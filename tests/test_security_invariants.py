"""Invariants that must hold for the product to mean what it claims.

Each of these is a property that could regress silently in a perfectly green suite, because the
behavioural tests exercise what happens, not how the code is shaped:

  * the recovery key can leave the screen only on paper (no save, print or download path in the
    page), and the one copy button is paired with an automatic wipe;
  * the page has no HTML-injection or link sink for text that comes from the vault;
  * no module quietly defines the same name twice (the later definition wins, the earlier one is
    dead code that still looks authoritative);
  * the standing agent instructions still contain every prohibition, since they are the only
    policy an MCP client ever receives;
  * the tool surface is exactly what we intend to expose.
"""
import ast
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_server  # noqa: E402
from thyra_vault import crypto, store, webui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
WEB_SRC = REPO / "web" / "apps" / "web" / "src"


def _page_sources():
    return {p: p.read_text(encoding="utf-8") for p in WEB_SRC.rglob("*.ts*")}


# ---------------------------------------------------------------------------
# The recovery key must be able to leave the screen only on paper
#
# The clipboard is readable by every process running as this user -- the assistant included -- and
# clipboard history can sync it off the machine. A save or print button writes it to disk or a
# spooler. The copy button exists on purpose (hand-typing 36 characters invites a slip that looks like
# "the key does not work"), so it is allowed, but only with a bounded, automatic wipe.
# ---------------------------------------------------------------------------

def test_the_recovery_key_copy_button_is_paired_with_an_automatic_wipe() -> None:
    source = (WEB_SRC / "components" / "molecules" / "CopyKeyButton.tsx").read_text(encoding="utf-8")
    assert "clearSeconds" in source and "setTimeout" in source and "writeText('')" in source, (
        "REGRESSION: the recovery-key copy button no longer wipes the clipboard on a timer.")


def test_the_page_never_offers_to_save_print_or_download() -> None:
    forbidden = ("showSaveFilePicker", "window.print", "createObjectURL", "download=", "navigator.share",
                 "FileSaver")
    offenders = [f"{p.relative_to(WEB_SRC)}: {bad}" for p, text in _page_sources().items()
                 for bad in forbidden if bad in text]
    assert not offenders, (
        f"REGRESSION: {offenders}. Writing a recovery key to a file or a print spooler defeats "
        f"the point of a paper-only key.")


def test_the_clipboard_wipe_window_is_bounded() -> None:
    from thyra_vault import uihelpers
    assert uihelpers._CLIPBOARD_CLEAR_SECONDS <= 60, (
        "REGRESSION: the clipboard holds a copied value for over a minute; it only needs to survive "
        "long enough to paste.")


def test_no_module_defines_the_same_name_twice() -> None:
    """A blocklist and its helpers were once defined twice in one file. Python binds top to bottom,
    so the later pair silently won and the earlier pair was dead code that looked authoritative --
    edit the wrong copy and the behaviour does not change while the diff says it should. For a
    security control that is a dangerous shape."""
    dupes = []
    for path in sorted(list((REPO / "thyra_vault").rglob("*.py")) + [REPO / "mcp_server.py"]):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        seen = set()
        for node in tree.body:
            names = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [node.name]
            elif isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            for name in names:
                if name in seen:
                    dupes.append(f"{path.name}:{name}")
                seen.add(name)
    assert not dupes, f"REGRESSION: defined more than once at module level: {dupes}"


# ---------------------------------------------------------------------------
# The standing agent policy
#
# _AGENT_INSTRUCTIONS is handed to every MCP client on connect and is the only
# policy the agent ever receives. Dropping a line here is invisible -- nothing
# fails, the agent simply stops being told not to do something.
# ---------------------------------------------------------------------------

def test_agent_instructions_keep_every_prohibition() -> None:
    required = {
        "vault.enc": "never read the vault ciphertext",
        "master password": "never ask for the master password in chat",
        "recovery key into the chat": "never ask for a recovery key in chat",
        "only_vars": "scope injection to what the command needs",
        "redacted before it reaches you": "explain that output is redacted",
        "thyra-vault-run-": "never read a live background run log",
        "materialize target": "never read a materialize target",
    }
    text = mcp_server._AGENT_INSTRUCTIONS
    for needle, why in required.items():
        assert needle in text, (
            f"REGRESSION: the standing agent instructions no longer {why} "
            f"(missing {needle!r}). This text is the only policy a client ever "
            f"receives; a dropped line silently removes the rule.")


def test_agent_instructions_are_honest_about_redaction_limits() -> None:
    """Overclaiming here is worse than saying nothing: an agent that believes
    redaction is a guarantee will echo output freely."""
    text = mcp_server._AGENT_INSTRUCTIONS
    assert "NOT a guarantee" in text or "not a guarantee" in text, (
        "REGRESSION: the instructions no longer state that redaction is "
        "best-effort rather than a guarantee")


# ---------------------------------------------------------------------------
# The exposed tool surface
#
# Every tool is a door into a vault the agent is not trusted to read. A new one
# appearing unnoticed -- or change_password/recover_vault silently vanishing --
# should fail loudly.
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    "add_secret", "change_password", "decrypt_file", "encrypt_file",
    "install_migrate", "manage_vault", "recover_vault", "remove_secret",
    "resync_targets", "retype_placeholders", "run_with_env", "sync_llm_env",
    "vault_status",
}


def test_tool_surface_is_exactly_what_we_intend() -> None:
    import re
    src_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp_server.py")
    with open(src_path, encoding="utf-8") as fh:
        src = fh.read()
    found = set(re.findall(r"@mcp\.tool\(\)\s*\ndef\s+([a-z_][a-z0-9_]*)", src))
    assert found == EXPECTED_TOOLS, (
        f"REGRESSION: the MCP tool surface changed.\n"
        f"  added:   {sorted(found - EXPECTED_TOOLS)}\n"
        f"  removed: {sorted(EXPECTED_TOOLS - found)}\n"
        f"Every tool is a door into the vault -- update EXPECTED_TOOLS "
        f"deliberately, not reflexively.")


def test_recovery_is_reachable_without_the_master_password() -> None:
    """The paper key only means something if there is a way to use it when the
    password is gone. Every other entry point authenticates with the password."""
    assert hasattr(mcp_server, "recover_vault"), (
        "REGRESSION: the recover_vault tool is gone. Without it a forgotten "
        "master password is unrecoverable even with a correct paper key, which "
        "makes the entire recovery feature decorative.")
    assert hasattr(webui, "recover_dialog"), "recover_dialog is gone"


# ---------------------------------------------------------------------------
# The server actually runs
#
# Importing mcp_server proves the module parses. It does not prove FastMCP
# accepts the tool signatures, that the stdio transport comes up, or that the
# standing instructions reach a client -- all of which fail at connect time,
# in front of a user, with the suite still green. This does a real handshake
# over stdio the way Claude Code does. It deliberately calls only initialize
# and tools/list, so it never touches the vault.
# ---------------------------------------------------------------------------

def test_server_starts_and_serves_its_tools_over_stdio() -> None:
    import json
    import subprocess

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python = os.path.join(repo, ".venv", "Scripts", "python.exe")
    if not os.path.exists(python):
        python = sys.executable

    proc = subprocess.Popen(
        [python, "mcp_server.py"], cwd=repo,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", bufsize=1)
    try:
        def send(obj):
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "regression", "version": "0"}}})
        init = json.loads(proc.stdout.readline())
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = json.loads(proc.stdout.readline())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()

    names = {t["name"] for t in listed["result"]["tools"]}
    assert names == EXPECTED_TOOLS, (
        f"REGRESSION: the server advertises a different tool set than the source "
        f"declares.\n  advertised but not expected: {sorted(names - EXPECTED_TOOLS)}"
        f"\n  expected but not advertised: {sorted(EXPECTED_TOOLS - names)}")

    instructions = init["result"].get("instructions") or ""
    assert "Never read vault.enc" in instructions, (
        "REGRESSION: the standing agent policy is not reaching connecting "
        "clients. The text can be perfect and still never be delivered.")


# ---------------------------------------------------------------------------
# Standalone runner -- CI runs both this and pytest, because the two collect
# differently and a test visible to only one is a real gap.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = []
    for test in tests:
        print(f"Running {test.__name__} ...")
        try:
            test()
            print("  PASS")
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL: {exc}")
            failures.append((test.__name__, exc))
    print(f"\nResults: {len(tests) - len(failures)}/{len(tests)} passed")
    if failures:
        for name, exc in failures:
            print(f"  FAILED {name}: {exc}")
        sys.exit(1)
    print("All tests passed.")
