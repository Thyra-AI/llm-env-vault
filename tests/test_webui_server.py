"""The browser dialogs' loopback server, tested over real HTTP.

Each test starts ``server.run_flow`` on a background thread with a tiny flow and
fake static assets, grabs the launch URL through the ``_on_ready`` seam (no real
browser is ever opened), then talks to it with http.client -- which, unlike a
browser or urllib, lets a test send any Host/Origin header it likes.

What is being proven is the security posture documented in
thyra_vault/webui/server.py: loopback only, DNS-rebinding and cross-site requests
refused, a single-use launch code, a bearer token for every API call,
JSON-only bodies, no CORS, no path traversal, and a server that goes away when
the human does.
"""
import http.client
import json
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from thyra_vault.webui import schema, server  # noqa: E402

PASSWORD = "Hunter2-Hunter2-Hunter2"


def tiny_flow(outcome):
    """Two screens: a password prompt, then a confirm. Records what it got."""
    error = None
    while True:
        act = yield schema.screen(
            "unlock.title", fields=[schema.password_field("password", "fields.masterPassword")],
            actions=[schema.action("cancel", "common.cancel"),
                     schema.action("go", "common.continue", variant="primary")],
            default_action="go", error=error)
        if act.id != "go":
            return
        if act.values.get("password") != PASSWORD:
            error = schema.msg("errors.emptyPassword")
            continue
        break
    act = yield schema.screen("confirmRemove.title", tone="danger",
                              actions=[schema.action("allow", "common.allow", variant="danger")])
    if act.id == "allow":
        outcome["approved"] = True


@pytest.fixture()
def assets(tmp_path, monkeypatch):
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>x</title><div id=root></div>", "utf-8")
    (root / "assets" / "app.js").write_text("console.log(1)", "utf-8")
    (root / "assets" / "font.woff2").write_bytes(b"wOF2")
    (tmp_path / "secret.txt").write_text("TOP SECRET", "utf-8")
    monkeypatch.setenv("THYRA_VAULT_WEB_ASSETS", str(root))
    return root


class Harness:
    """Runs run_flow on a thread and exposes a request helper."""

    def __init__(self, limits=None, flow=None):
        self.outcome = {"approved": False}
        self.url = None
        self.session = None
        self.token = ""
        self.ready = threading.Event()
        self.error = None
        self.limits = limits or server.Limits(launch_timeout=30, heartbeat_timeout=30,
                                              closing_grace=0.5)

        def on_ready(url, session):
            self.url, self.session = url, session
            self.ready.set()

        server._on_ready = on_ready
        server._open_url = lambda url: True  # never launch a real browser
        self.flow = flow or tiny_flow(self.outcome)

        def target():
            try:
                server.run_flow(self.flow, status_of=lambda: "approved" if self.outcome["approved"]
                                else "declined", limits=self.limits)
            except BaseException as exc:  # noqa: BLE001
                self.error = exc

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        assert self.ready.wait(5), "server did not start"
        parts = urlsplit(self.url)
        self.port = parts.port
        self.code = parts.fragment[len("c="):]

    def request(self, method, path, body=None, headers=None, host=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or f"127.0.0.1:{self.port}")
        payload = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        hdrs = dict(headers or {})
        if payload is not None:
            hdrs.setdefault("Content-Type", "application/json")
            hdrs["Content-Length"] = str(len(payload))
        for k, v in hdrs.items():
            conn.putheader(k, v)
        conn.endheaders(payload)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        try:
            parsed = json.loads(data)
        except ValueError:
            parsed = None
        return resp.status, parsed, data, resp

    def connect(self):
        status, body, _, _ = self.request("POST", "/api/exchange", {"code": self.code})
        assert status == 200, body
        self.token = body["token"]
        return self.token

    def api(self, method, path, body=None, **kw):
        headers = {"Authorization": f"Bearer {self.token}"}
        headers.update(kw.pop("headers", {}))
        return self.request(method, path, body, headers=headers, **kw)

    def screen(self):
        status, body, _, _ = self.api("GET", "/api/screen")
        assert status == 200
        return body

    def act(self, action_id, **values):
        sc = self.screen()["screen"]
        return self.api("POST", "/api/action", {"screen": sc["id"], "action": action_id,
                                                "values": values})

    def finish(self, timeout=8):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "run_flow did not return"
        if self.error:
            raise self.error


@pytest.fixture(autouse=True)
def _restore_seams():
    yield
    server._on_ready = None
    server._open_url = server._default_open


# --------------------------------------------------------------------------
# The happy path, over HTTP
# --------------------------------------------------------------------------

def test_full_dialog_over_http_and_server_goes_away(assets):
    h = Harness()
    h.connect()
    first = h.screen()["screen"]
    assert first["title"]["key"] == "unlock.title" and "id" in first
    status, body, _, _ = h.act("go", password="wrong")
    assert status == 200 and body["screen"]["error"]["key"] == "errors.emptyPassword"
    status, body, _, _ = h.act("go", password=PASSWORD)
    assert body["screen"]["title"]["key"] == "confirmRemove.title"
    status, body, _, _ = h.act("allow")
    assert body == {"done": True, "reason": "completed", "status": "approved"}
    h.finish()
    assert h.outcome["approved"] is True
    with pytest.raises(OSError):  # the port is closed again
        http.client.HTTPConnection("127.0.0.1", h.port, timeout=1).request("GET", "/")


def test_cancel_leaves_the_outcome_denied(assets):
    h = Harness()
    h.connect()
    status, body, _, _ = h.act("cancel")
    assert body["done"] and body["status"] == "declined"
    h.finish()
    assert h.outcome["approved"] is False


def test_password_is_never_echoed_back_or_stored_in_a_screen(assets):
    h = Harness()
    h.connect()
    _, _, raw, _ = h.act("go", password=PASSWORD)
    assert PASSWORD.encode() not in raw
    assert PASSWORD not in json.dumps(h.screen())
    h.act("cancel")
    h.finish()


# --------------------------------------------------------------------------
# Launch code and token
# --------------------------------------------------------------------------

def test_launch_code_is_single_use(assets):
    h = Harness()
    h.connect()
    status, body, _, _ = h.request("POST", "/api/exchange", {"code": h.code})
    assert status == 403 and body == {"error": "invalid_code"}
    h.act("cancel")
    h.finish()


def test_wrong_codes_are_refused_and_throttled_but_never_end_the_dialog(assets):
    h = Harness(server.Limits(launch_timeout=30, max_bad_codes=3, lockout_base=0.4, lockout_max=0.4))
    statuses = [h.request("POST", "/api/exchange", {"code": "guess"})[0] for _ in range(3)]
    assert statuses == [403, 403, 403]
    status, _, _, resp = h.request("POST", "/api/exchange", {"code": "guess"})
    assert status == 429 and resp.getheader("Retry-After")  # locked out, not cancelled
    assert h.thread.is_alive()
    time.sleep(0.5)
    h.connect()  # the real code still works once the lockout has passed
    h.act("cancel")
    h.finish()


def test_api_requires_the_bearer_token(assets):
    h = Harness()
    h.connect()
    assert h.request("GET", "/api/screen")[0] == 401
    assert h.request("GET", "/api/screen", headers={"Authorization": "Bearer nope"})[0] == 401
    assert h.request("GET", "/api/screen", headers={"Authorization": h.token})[0] == 401  # no scheme
    assert h.request("POST", "/api/action", {"screen": "x", "action": "go"})[0] == 401
    assert h.request("POST", "/api/ping", {})[0] == 401
    h.act("cancel")
    h.finish()


def test_token_is_not_issued_without_the_code(assets):
    h = Harness()
    status, body, _, _ = h.request("POST", "/api/exchange", {})
    assert status == 403 and "token" not in (body or {})
    h.connect()
    h.act("cancel")
    h.finish()


# --------------------------------------------------------------------------
# Cross-site and rebinding defences
# --------------------------------------------------------------------------

def test_wrong_host_header_is_refused_everywhere(assets):
    h = Harness()
    h.connect()
    for host in ("evil.example", "localhost:%d" % h.port, "127.0.0.1", "127.0.0.1:1"):
        assert h.request("GET", "/", host=host)[0] == 403, host
        assert h.request("GET", "/api/screen", host=host,
                         headers={"Authorization": f"Bearer {h.token}"})[0] == 403, host
        assert h.request("POST", "/api/exchange", {"code": "x"}, host=host)[0] == 403, host
    h.act("cancel")
    h.finish()


def test_foreign_origin_is_refused(assets):
    h = Harness()
    h.connect()
    for origin in ("http://evil.example", "http://localhost:%d" % h.port, "null"):
        status, _, _, _ = h.api("POST", "/api/action", {"screen": "x", "action": "go"},
                                headers={"Origin": origin})
        assert status == 403, origin
    status, _, _, _ = h.api("POST", "/api/ping", {}, headers={"Origin": f"http://127.0.0.1:{h.port}"})
    assert status == 200  # the page's own origin is fine
    h.act("cancel")
    h.finish()


def test_cross_site_fetch_metadata_is_refused(assets):
    h = Harness()
    h.connect()
    for site in ("cross-site", "same-site"):
        assert h.api("GET", "/api/screen", headers={"Sec-Fetch-Site": site})[0] == 403
    assert h.api("GET", "/api/screen", headers={"Sec-Fetch-Site": "same-origin"})[0] == 200
    h.act("cancel")
    h.finish()


def test_post_must_be_json(assets):
    h = Harness()
    h.connect()
    for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        status, _, _, _ = h.api("POST", "/api/ping", None, raw_body=b"{}",
                                headers={"Content-Type": ctype})
        assert status == 400, ctype
    h.act("cancel")
    h.finish()


def test_malformed_and_oversized_bodies_are_refused(assets):
    h = Harness()
    h.connect()
    assert h.api("POST", "/api/ping", None, raw_body=b"{not json")[0] == 400
    assert h.api("POST", "/api/ping", None, raw_body=b"[1,2]")[0] == 400  # not an object
    big = b'{"x":"' + b"a" * (server.MAX_BODY + 10) + b'"}'
    try:
        assert h.api("POST", "/api/ping", None, raw_body=big)[0] == 400
    except (ConnectionError, BrokenPipeError):
        # The server refuses an oversized body WITHOUT reading it and closes the connection;
        # depending on timing the client sees the 400 or a reset while still sending. Both
        # are a refusal.
        pass
    assert h.api("POST", "/api/action", {"screen": 1, "action": "go"})[0] == 400
    assert h.api("POST", "/api/action", {"screen": "x", "action": "go", "values": [1]})[0] == 400
    h.act("cancel")
    h.finish()


def test_no_cors_headers_and_options_is_refused(assets):
    h = Harness()
    h.connect()
    status, _, _, resp = h.request("OPTIONS", "/api/action",
                                   headers={"Origin": "http://evil.example",
                                            "Access-Control-Request-Method": "POST"})
    assert status == 405
    assert resp.getheader("Access-Control-Allow-Origin") is None
    for method in ("PUT", "DELETE", "PATCH"):
        assert h.request(method, "/api/action", {})[0] == 405
    status, _, _, resp = h.api("GET", "/api/screen")
    assert not [k for k, _v in resp.getheaders() if k.lower().startswith("access-control-")]
    h.act("cancel")
    h.finish()


def test_a_stale_screen_id_is_rejected_and_resyncs_the_page(assets):
    h = Harness()
    h.connect()
    old = h.screen()["screen"]["id"]
    h.act("go", password=PASSWORD)  # advances to the confirm screen
    status, body, _, _ = h.api("POST", "/api/action", {"screen": old, "action": "go", "values": {}})
    assert status == 409 and body["error"] == "stale"
    assert body["screen"]["title"]["key"] == "confirmRemove.title"  # told what is current now
    h.act("cancel")
    h.finish()


# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------

def test_static_files_and_spa_fallback(assets):
    h = Harness()
    status, _, data, resp = h.request("GET", "/")
    assert status == 200 and b"<div id=root>" in data
    assert resp.getheader("Content-Type").startswith("text/html")
    status, _, data, resp = h.request("GET", "/assets/app.js")
    assert status == 200 and resp.getheader("Content-Type").startswith("text/javascript")
    assert h.request("GET", "/assets/font.woff2")[3].getheader("Content-Type") == "font/woff2"
    status, _, data, _ = h.request("GET", "/some/route")  # no extension: SPA fallback
    assert status == 200 and b"<div id=root>" in data
    assert h.request("GET", "/assets/missing.js")[0] == 404
    assert h.request("HEAD", "/")[0] == 200
    h.connect()
    h.act("cancel")
    h.finish()


def test_path_traversal_cannot_leave_the_asset_root(assets, tmp_path):
    h = Harness()
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt",
                 "/assets/../../secret.txt", "/%2e%2e%2f%2e%2e%2fetc/passwd",
                 "/assets/..%5c..%5csecret.txt", "/%00/../secret.txt"):
        status, _, data, _ = h.request("GET", path)
        assert b"TOP SECRET" not in data, path
        assert status in (200, 400, 403, 404), path
        if status == 200:  # the only 200 allowed is the SPA shell
            assert b"<div id=root>" in data
    h.connect()
    h.act("cancel")
    h.finish()


def test_every_response_carries_the_hardening_headers(assets):
    h = Harness()
    h.connect()
    for path in ("/", "/assets/app.js", "/nope.js"):
        resp = h.request("GET", path)[3]
        assert resp.getheader("Cache-Control") == "no-store"
        assert resp.getheader("X-Content-Type-Options") == "nosniff"
        assert resp.getheader("Referrer-Policy") == "no-referrer"
        assert resp.getheader("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in resp.getheader("Content-Security-Policy")
        assert "frame-ancestors 'none'" in resp.getheader("Content-Security-Policy")
    resp = h.api("GET", "/api/screen")[3]
    assert resp.getheader("Cache-Control") == "no-store"
    h.act("cancel")
    h.finish()


def test_server_header_does_not_advertise_python(assets):
    h = Harness()
    resp = h.request("GET", "/")[3]
    assert "Python" not in (resp.getheader("Server") or "")
    h.connect()
    h.act("cancel")
    h.finish()


# --------------------------------------------------------------------------
# Leaving: closed tabs and timeouts
# --------------------------------------------------------------------------

def test_never_connecting_times_out_as_denied(assets):
    h = Harness(server.Limits(launch_timeout=0.6))
    h.finish(5)
    assert h.outcome["approved"] is False
    assert h.session.reason == "timeout"


def test_silent_tab_is_treated_as_closed(assets):
    h = Harness(server.Limits(launch_timeout=30, heartbeat_timeout=0.8))
    h.connect()
    h.finish(8)
    assert h.session.reason == "closed" and h.outcome["approved"] is False


def test_heartbeats_keep_the_dialog_alive(assets):
    h = Harness(server.Limits(launch_timeout=30, heartbeat_timeout=1.0))
    h.connect()
    for _ in range(6):
        assert h.api("POST", "/api/ping", {})[0] == 200
        time.sleep(0.3)
    assert not h.session.finished.is_set()
    h.act("cancel")
    h.finish()


def test_pagehide_beacon_closes_the_dialog_after_the_grace_period(assets):
    h = Harness(server.Limits(launch_timeout=30, heartbeat_timeout=30, closing_grace=0.5))
    h.connect()
    assert h.api("POST", "/api/closing", {})[0] == 200
    h.finish(8)
    assert h.session.reason == "closed"


def test_a_reload_after_pagehide_cancels_the_pending_close(assets):
    h = Harness(server.Limits(launch_timeout=30, heartbeat_timeout=30, closing_grace=1.0))
    h.connect()
    h.api("POST", "/api/closing", {})
    time.sleep(0.3)
    assert h.api("GET", "/api/screen")[0] == 200  # the reloaded page is back
    time.sleep(1.5)
    assert not h.session.finished.is_set()
    h.act("cancel")
    h.finish()


def test_a_flow_that_raises_is_reraised_to_the_caller(assets):
    def boom():
        yield schema.screen("unlock.title")
        raise RuntimeError("vault exploded")

    h = Harness(flow=boom())
    h.connect()
    status, body, _, _ = h.act("go")
    assert status == 200 and body["done"] and body["reason"] == "error"
    h.thread.join(8)
    assert isinstance(h.error, RuntimeError) and "vault exploded" in str(h.error)


def test_missing_assets_raise_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv("THYRA_VAULT_WEB_ASSETS", str(tmp_path / "nope"))
    with pytest.raises(server.WebUiUnavailable) as exc:
        server.run_flow(tiny_flow({}))
    assert "build:embed" in str(exc.value)


def test_binds_loopback_only(assets):
    h = Harness()
    h.connect()
    import socket
    probes = {a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith("127.")}
    for addr in probes:  # any non-loopback address of this machine must refuse
        with pytest.raises(OSError):
            socket.create_connection((addr, h.port), timeout=1).close()
    h.act("cancel")
    h.finish()


def test_the_throwaway_browser_profile_starts_without_password_or_analytics_prompts(tmp_path):
    """A fresh profile made Brave offer to save the master password and show its analytics notice."""
    import json
    from thyra_vault.webui import server
    server._seed_profile(str(tmp_path))
    prefs = json.loads((tmp_path / "Default" / "Preferences").read_text(encoding="utf-8"))
    assert prefs["credentials_enable_service"] is False
    assert prefs["profile"]["password_manager_enabled"] is False
    assert prefs["autofill"]["profile_enabled"] is False
    state = json.loads((tmp_path / "Local State").read_text(encoding="utf-8"))
    assert state["brave"]["p3a"]["notice_acknowledged"] is True
