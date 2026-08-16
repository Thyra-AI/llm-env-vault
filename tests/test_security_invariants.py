"""Invariants that must hold for the product to mean what it claims.

Everything here was verified by hand at some point during development and then
guarded by nothing. Each of these is a property that could regress silently in
a perfectly green suite, because the existing tests exercise behaviour rather
than structure:

  * the recovery-key dialog offers no way to copy, save, or print the key --
    the whole point is that it goes onto paper and nowhere else;
  * the ordinary unlock dialog never accepts a recovery key, so routine
    prompts cannot be turned into a harvesting surface;
  * the standing agent instructions still contain every prohibition, since
    they are the only policy an MCP client ever receives;
  * every dialog actually constructs -- no test had ever built a real Tk
    widget, so a layout or attribute error in a dialog would have shipped
    green and only failed in front of a human;
  * the tool surface is exactly what we intend to expose.

The Tk tests run a real Tk root. `mainloop()` is replaced so it snapshots the
widget tree and returns instead of blocking, which is what makes a dialog
inspectable without a human. They skip cleanly where Tk cannot open a display.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_server  # noqa: E402
from vault_lib import crypto, gui, store  # noqa: E402

_GUI_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vault_lib", "gui.py")
with open(_GUI_SRC_PATH, encoding="utf-8") as _fh:
    _GUI_SRC = _fh.read()




# ---------------------------------------------------------------------------
# The recovery key must be able to leave the screen only on paper
#
# A clipboard button would be the single worst addition to this dialog: the
# Windows clipboard is readable by every local process -- including the agent's
# own tooling -- and Clipboard History syncs it to the cloud. A save or print
# button writes it to disk or a spooler. None of these exist today; these tests
# exist so that stays true, because adding one would look like a usability win.
# ---------------------------------------------------------------------------

def test_clipboard_use_is_paired_with_an_automatic_wipe() -> None:
    """The copy button was originally refused outright, then added on purpose.

    The objection was real and still is: the Windows clipboard is readable by
    every process running as this user -- the agent included -- and Clipboard
    History can sync it off the machine. What overturned it was watching a
    human actually do the ceremony. Without a copy button they hand-type 36
    characters into the confirm field, and a slip there presents as "the key
    does not work". A confirmation step people abandon is a recovery path that
    silently does not exist, which is the exact failure this feature exists to
    prevent.

    So the clipboard is allowed, and the exposure is bounded instead. This test
    pins the bound: if the copy path ever loses its scheduled wipe, the key sits
    on the clipboard indefinitely and the trade-off we accepted quietly becomes
    a worse one than the one we argued about.
    """
    if "clipboard_append" not in _GUI_SRC:
        return  # no copy path at all is also acceptable
    assert "clipboard_clear" in _GUI_SRC, (
        "REGRESSION: gui.py puts the recovery key on the clipboard but never "
        "clears it.")
    assert "_CLIPBOARD_CLEAR_SECONDS" in _GUI_SRC, (
        "REGRESSION: the clipboard wipe is no longer on a bounded timer.")
    assert "_CLIPBOARD_CLEAR_SECONDS * 1000" in _GUI_SRC, (
        "REGRESSION: the clipboard wipe is no longer scheduled via after() -- "
        "a clear that is never scheduled never runs.")
    assert gui._CLIPBOARD_CLEAR_SECONDS <= 60, (
        f"REGRESSION: the clipboard holds the recovery key for "
        f"{gui._CLIPBOARD_CLEAR_SECONDS}s. It only needs to survive long enough "
        f"to paste into the field directly below it.")


def test_gui_never_offers_to_save_or_print() -> None:
    for api in ("filedialog", "asksaveasfilename", "asksaveasfile",
                "win32print", "os.startfile", "ShellExecute"):
        assert api not in _GUI_SRC, (
            f"REGRESSION: gui.py references {api}. Writing a recovery key to a "
            f"file or a print spooler defeats the point of a paper-only key.")






# ---------------------------------------------------------------------------
# Every dialog must at least build
#
# No test had ever constructed a real widget, so an f-string referencing a
# renamed variable, a grid() on a destroyed parent, or a missing colour
# constant would pass the entire suite and fail only in front of a human --
# at the exact moment they are trying to reach their secrets.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# A dialog opened from inside another dialog must not create a second Tk root
#
# Found by hand, not by any test: the recovery drill is invoked from inside
# add_secret_dialog's Allow handler, which is already running inside that
# dialog's mainloop. Creating a second tk.Tk() there produced a nested
# mainloop, and on Windows that meant the drill window opened BEHIND its
# parent (so it looked like nothing had happened) and destroy() failed to
# unwind the nested loop -- the human could tick the checkbox, click Confirm,
# and never leave the page. Recovery setup was impossible to complete.
#
# The fix is structural: only the first window is a Tk root; any window opened
# while one is alive is a Toplevel driven by wait_window. These tests pin that,
# because the natural way to write a new dialog is to copy an existing one --
# which would reintroduce tk.Tk() verbatim.
# ---------------------------------------------------------------------------

def test_no_dialog_calls_tk_Tk_directly() -> None:
    """Every dialog must go through the _new_window() helper."""
    import re
    # Strip the helper itself: it legitimately owns the one tk.Tk() call.
    helper_start = _GUI_SRC.index("def _new_window(")
    helper_end = _GUI_SRC.index("def _foreground(")
    without_helper = _GUI_SRC[:helper_start] + _GUI_SRC[helper_end:]
    offenders = re.findall(r"^\s*\w+\s*=\s*tk\.Tk\(\)", without_helper, re.M)
    assert not offenders, (
        f"REGRESSION: {len(offenders)} dialog(s) call tk.Tk() directly instead of "
        f"_new_window(). A dialog opened from inside another dialog's callback "
        f"then creates a second root with a nested mainloop, which on Windows "
        f"opens behind its parent and cannot be dismissed.")





def test_win32_foreground_helper_is_wired_in() -> None:
    """Guards the mechanism, so the OS-level test above cannot be satisfied by
    accident on a machine where we happened to be foreground already."""
    assert "AttachThreadInput" in _GUI_SRC, (
        "REGRESSION: the AttachThreadInput workaround is gone. Without it "
        "Windows silently refuses the foreground request from a background-"
        "launched process and the dialog opens without the keyboard.")
    assert "_win32_take_foreground" in _GUI_SRC


def test_passphrase_generator_is_gone() -> None:
    """It filled two masked fields, so the value it produced was never visible
    to the person who had to remember it -- a data-loss trap, not a feature."""
    for token in ("_WORDLIST", "gen_passphrase", "Generate passphrase"):
        assert token not in _GUI_SRC, (
            f"REGRESSION: {token!r} is back in gui.py. A generated password "
            f"written into a show='*' field cannot be read, written down, or "
            f"recovered -- it guarantees eventual loss of the vault.")



def test_no_shadowed_module_level_definitions() -> None:
    """No name may be defined twice at module level in gui.py.

    A blocklist and its two helpers were once defined twice in this file. Python
    binds top to bottom, so the later pair silently won and the earlier pair was
    dead code that looked completely authoritative -- edit the wrong copy, add
    an entry to the wrong set, and the behaviour does not change while the diff
    says it should. For a security control that is a genuinely dangerous shape.
    """
    import ast
    tree = ast.parse(_GUI_SRC)
    seen, dupes = set(), []
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for name in names:
            if name in seen:
                dupes.append(name)
            seen.add(name)
    assert not dupes, (
        f"REGRESSION: {sorted(set(dupes))} defined more than once at module "
        f"level in gui.py. The later definition wins and the earlier one is "
        f"dead code that still looks live.")


# ---------------------------------------------------------------------------
# Dialog checks, executed in a fresh interpreter
#
# These need real Tk windows -- nothing else catches a dialog that fails to
# build, or one that opens without owning the keyboard. But creating and
# destroying Tk roots repeatedly inside a single interpreter corrupts Tcl
# state: after a dozen or so, unrelated tests begin failing with "tk wasn't
# installed properly", and which ones fail depends on execution order. A flaky
# security test is worse than none, because it gets muted. So the whole sweep
# runs once in a subprocess. See tests/_tk_checks.py for the individual checks.
# ---------------------------------------------------------------------------

def test_dialog_checks_pass_in_a_clean_interpreter() -> None:
    import subprocess

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python = os.path.join(repo, ".venv", "Scripts", "python.exe")
    if not os.path.exists(python):
        python = sys.executable
    script = os.path.join(repo, "tests", "_tk_checks.py")

    proc = subprocess.run([python, script], cwd=repo, capture_output=True,
                          text=True, timeout=300)
    out = (proc.stdout or "") + (proc.stderr or "")

    if "tk wasn't installed properly" in out or "no display name" in out:
        return  # headless box -- nothing to assert

    failures = [ln for ln in out.splitlines() if ln.startswith("FAIL ")]
    assert proc.returncode == 0 and not failures, (
        "REGRESSION: dialog checks failed.\n" + out)
    assert "OK every_dialog_constructs" in out, (
        "the dialog-construction sweep did not run at all -- a dialog that "
        "cannot be built locks the human out of their own vault, so this must "
        "never silently skip.\n" + out)


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
        "llm-env-vault-run-": "never read a live background run log",
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
    "add_secret", "change_password", "install_migrate", "manage_vault",
    "recover_vault", "remove_secret", "resync_targets", "run_with_env",
    "sync_llm_env", "vault_status",
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
    assert hasattr(gui, "recover_dialog"), "recover_dialog is gone"


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
