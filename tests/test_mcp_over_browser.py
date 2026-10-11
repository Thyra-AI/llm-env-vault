"""A real MCP tool, end to end, through the browser dialogs.

``mcp_server._change_password_impl`` is driven by a simulated browser speaking HTTP to the
loopback server -- the closest a test can get to "an assistant calls a tool, the human types in
a page, the vault changes" without a real browser. tests/test_webui_flows.py and
test_webui_server.py cover the pieces; this proves they are wired together.
"""
import http.client
import json
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import TEST_PASSWORD, workspace  # noqa: E402

from thyra_vault import mcp_server  # noqa: E402
from thyra_vault import webui  # noqa: E402
from thyra_vault.vault import store
from thyra_vault.webui import server  # noqa: E402


@pytest.fixture()
def fake_assets(tmp_path, monkeypatch):
    root = tmp_path / "dist"
    root.mkdir()
    (root / "index.html").write_text("<!doctype html><div id=root></div>", "utf-8")
    monkeypatch.setenv("THYRA_VAULT_WEB_ASSETS", str(root))
    return root


def test_mcp_server_exposes_a_complete_dialog_module():
    for name in ["add_secret_dialog", "remove_secret_dialog", "retype_placeholders_dialog",
                 "install_dialog", "encrypt_file_dialog", "decrypt_file_dialog",
                 "confirm_abandon_files_dialog", "unlock_for_run_dialog", "change_password_dialog",
                 "show_recovery_key_dialog", "recover_dialog", "manage_vault_dialog"]:
        assert callable(getattr(mcp_server.gui, name)), name


# --------------------------------------------------------------------------
# A real tool, through the browser back-end, with a simulated browser
# --------------------------------------------------------------------------

class SimulatedBrowser(threading.Thread):
    """Plays the human: opens the launch URL, then answers each screen."""

    def __init__(self, url, answer):
        super().__init__(daemon=True)
        parts = urlsplit(url)
        self.port, self.code, self.answer = parts.port, parts.fragment[2:], answer
        self.seen = []
        self.error = None

    def call(self, method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(data))})
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        out = json.loads(resp.read() or b"{}")
        conn.close()
        return out

    def run(self):
        try:
            token = self.call("POST", "/api/exchange", {"code": self.code})["token"]
            view = self.call("GET", "/api/screen", token=token)
            while "screen" in view:
                screen = view["screen"]
                self.seen.append(screen["title"]["key"])
                action, values = self.answer(screen)
                view = self.call("POST", "/api/action",
                                 {"screen": screen["id"], "action": action, "values": values},
                                 token=token)
        except Exception as exc:  # noqa: BLE001
            self.error = exc


def run_tool_with_browser(tool, answer):
    """Call ``tool()`` (an MCP tool body) while a simulated browser answers."""
    holder = {}

    def on_ready(url, session):
        holder["browser"] = SimulatedBrowser(url, answer)
        holder["browser"].start()

    server._on_ready = on_ready
    server._open_url = lambda url: True
    try:
        return tool(), holder["browser"]
    finally:
        server._on_ready = None
        server._open_url = server._default_open
        holder["browser"].join(10)


def test_change_password_tool_end_to_end_through_the_browser_backend(monkeypatch, fake_assets):
    new_password = "A-brand-new-passphrase-7"
    with workspace():
        monkeypatch.setattr(mcp_server, "gui", webui)

        def answer(screen):
            if screen["title"]["key"] == "changePassword.title":
                return "change", {"old": TEST_PASSWORD, "new": new_password, "confirm": new_password}
            return "cancel", {}

        result, browser = run_tool_with_browser(mcp_server._change_password_impl, answer)
        assert browser.error is None
        assert browser.seen == ["changePassword.title"]
        assert result["applied"] is True
        # The vault really changed: the new password opens it, the old one does not.
        assert "API_TOKEN" in store.load_secrets(new_password)
        with pytest.raises(Exception):
            store.load_secrets(TEST_PASSWORD)


def test_change_password_tool_cancel_is_a_clean_noop(monkeypatch, fake_assets):
    with workspace():
        monkeypatch.setattr(mcp_server, "gui", webui)
        result, browser = run_tool_with_browser(mcp_server._change_password_impl,
                                                lambda screen: ("cancel", {}))
        assert result == {"applied": False, "message": "Cancelled by user."}
        assert "API_TOKEN" in store.load_secrets(TEST_PASSWORD)  # untouched


def test_change_password_tool_with_a_wrong_current_password_is_refused(monkeypatch, fake_assets):
    with workspace():
        monkeypatch.setattr(mcp_server, "gui", webui)
        result, _ = run_tool_with_browser(
            mcp_server._change_password_impl,
            lambda screen: ("change", {"old": "not-my-password", "new": "Another-Pa55word!",
                                       "confirm": "Another-Pa55word!"}))
        assert result["applied"] is False and "Incorrect" in result["error"]
        assert "API_TOKEN" in store.load_secrets(TEST_PASSWORD)


def test_nobody_opening_the_page_makes_the_tool_report_a_cancel(monkeypatch, fake_assets):
    with workspace():
        monkeypatch.setattr(mcp_server, "gui", webui)
        monkeypatch.setattr(webui, "LIMITS", server.Limits(launch_timeout=0.8))
        # Nobody ever opens the page: the dialog times out as a denial.
        server._open_url = lambda url: True
        try:
            result = mcp_server._change_password_impl()
        finally:
            server._open_url = server._default_open
        assert result == {"applied": False, "message": "Cancelled by user."}


def test_envvars_treats_an_empty_value_as_unset():
    from thyra_vault.vault import envvars
    assert envvars.get("X", "d", {"THYRA_VAULT_X": "", "LLM_ENV_VAULT_X": "old"}) == "old"
    assert envvars.get("X", "d", {}) == "d"
