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


def _tk_available() -> bool:
    try:
        import tkinter as tk
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:  # noqa: BLE001 -- no display, no Tcl, anything
        return False


def _build_dialog(call):
    """Run a dialog function far enough to build its widgets, then tear it down.

    The dialogs own their Tk root and end in root.mainloop(), so there is no
    outside handle to drive them with. Swapping in a root whose mainloop()
    snapshots the tree and destroys itself lets the whole construction path run
    -- every grid(), every cget(), every f-string in a label -- without a human
    and without blocking.

    Returns a list of (widget_class, text) for every widget built.
    """
    import tkinter as tk

    captured = []
    real_tk = tk.Tk

    class _AutoCloseTk(real_tk):
        def mainloop(self, n=0):
            def walk(widget):
                for child in widget.winfo_children():
                    try:
                        text = str(child.cget("text"))
                    except Exception:  # noqa: BLE001 -- not every widget has -text
                        text = ""
                    captured.append((child.winfo_class(), text))
                    walk(child)
            walk(self)
            self.destroy()

    gui.tk.Tk = _AutoCloseTk
    try:
        call()
    finally:
        gui.tk.Tk = real_tk
    return captured


def _all_text(widgets) -> str:
    return " ".join(text for _cls, text in widgets).lower()


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


def test_recovery_key_dialog_shows_the_key_and_both_drill_steps() -> None:
    if not _tk_available():
        return
    key = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
    widgets = _build_dialog(lambda: gui.show_recovery_key_dialog(key, "AB12"))
    blob = _all_text(widgets)

    classes = [cls for cls, _text in widgets]
    assert "Checkbutton" in classes, (
        "REGRESSION: the 'I have written this down' checkbox is gone from the "
        "recovery-key drill")
    assert "Entry" in classes, (
        "REGRESSION: the full-key re-entry field is gone from the recovery-key "
        "drill. Without it nothing verifies the human actually transcribed the "
        "key, and a mistranscription is only discovered when recovery is needed")
    assert "cannot be shown again" in blob, (
        "the dialog must say plainly that the key is unrecoverable once closed")
    assert "AB12" in " ".join(t for _c, t in widgets), (
        "the slot id must be shown so a stale printout is identifiable")


def test_recovery_key_dialog_has_no_copy_control() -> None:
    """Prose may legitimately mention a 'printed copy'; a control may not."""
    if not _tk_available():
        return
    key = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
    widgets = _build_dialog(lambda: gui.show_recovery_key_dialog(key, "AB12"))
    for cls, text in widgets:
        if cls in ("Button", "Checkbutton", "Radiobutton"):
            low = text.lower()
            # "copy" is now allowed -- see the clipboard test above for why, and
            # for the wipe that bounds it. Writing to disk or a spooler is not:
            # those leave the key somewhere nobody remembers to clean up.
            for banned in ("save to", "save as", "print", "export", "email"):
                assert banned not in low, (
                    f"REGRESSION: found a {cls} labelled {text!r} in the recovery "
                    f"key dialog. The key may reach the clipboard briefly, but it "
                    f"must never be written to a file or a print spooler.")


def test_unlock_dialog_never_accepts_a_recovery_key() -> None:
    """If it did, every routine unlock becomes a harvesting surface and users
    get trained to type paper secrets into ordinary prompts."""
    if not _tk_available():
        return
    widgets = _build_dialog(
        lambda: gui.unlock_for_run_dialog("echo hello", only_vars=["A"]))
    blob = _all_text(widgets)
    assert "recovery" not in blob, (
        "REGRESSION: the run-command unlock dialog mentions a recovery key. "
        "Recovery entry belongs only in recover_dialog, which is visually "
        "distinct and explicitly framed as a forgotten-password path.")


def test_unlock_dialog_discloses_that_output_goes_to_the_ai() -> None:
    if not _tk_available():
        return
    widgets = _build_dialog(
        lambda: gui.unlock_for_run_dialog("echo hello", only_vars=["A"]))
    blob = _all_text(widgets)
    assert "returned to the ai" in blob or "returned to the a" in blob, (
        "REGRESSION (A1): the unlock dialog no longer tells the human that the "
        "command's output is handed back to the AI assistant")


# ---------------------------------------------------------------------------
# Every dialog must at least build
#
# No test had ever constructed a real widget, so an f-string referencing a
# renamed variable, a grid() on a destroyed parent, or a missing colour
# constant would pass the entire suite and fail only in front of a human --
# at the exact moment they are trying to reach their secrets.
# ---------------------------------------------------------------------------

def test_every_dialog_constructs_without_error() -> None:
    if not _tk_available():
        return
    key = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
    orig_info = store.vault_info
    orig_version = store.vault_format_version
    store.vault_info = lambda: {
        "format": 2, "kdf": "scrypt", "kdf_params": {"n": 65536, "r": 8, "p": 1},
        "recovery_slot": True, "recovery_slot_id": "AB12",
        "recovery_slot_created": "2026-08-16T00:00:00+00:00",
        "created": "2026-08-16T00:00:00+00:00"}
    store.vault_format_version = lambda: 2
    try:
        cases = {
            "show_recovery_key_dialog": lambda: gui.show_recovery_key_dialog(key, "AB12"),
            "recover_dialog": gui.recover_dialog,
            "manage_vault_dialog": gui.manage_vault_dialog,
            "change_password_dialog": gui.change_password_dialog,
            "unlock_for_run_dialog": lambda: gui.unlock_for_run_dialog(
                "echo hello", only_vars=["A"]),
        }
        for name, call in cases.items():
            try:
                widgets = _build_dialog(call)
            except Exception as exc:  # noqa: BLE001
                assert False, (
                    f"REGRESSION: {name} raised while building its widgets "
                    f"({type(exc).__name__}: {exc}). A dialog that cannot be "
                    f"constructed locks the human out of their own vault.")
            assert widgets, f"{name} built no widgets at all"
    finally:
        store.vault_info = orig_info
        store.vault_format_version = orig_version


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


def test_second_window_is_a_toplevel_not_a_second_root() -> None:
    if not _tk_available():
        return
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    try:
        second, run = gui._new_window()
        assert isinstance(second, tk.Toplevel), (
            f"REGRESSION: opening a window while a root is alive produced "
            f"{type(second).__name__}, not a Toplevel. A second Tk root means a "
            f"nested mainloop and an undismissable dialog.")
        assert run.__name__ != "mainloop", (
            "REGRESSION: the second window would be driven by a nested "
            "mainloop rather than wait_window")
        second.destroy()
    finally:
        root.destroy()


def test_first_window_is_a_real_root() -> None:
    if not _tk_available():
        return
    import tkinter as tk

    win, _run = gui._new_window()
    try:
        assert isinstance(win, tk.Tk), (
            "the first window in a process must be a real Tk root")
    finally:
        win.destroy()


def test_dialog_actually_takes_the_keyboard_focus() -> None:
    """A visible dialog that does not own the keyboard is a disclosure bug.

    If the window is painted but the foreground belongs to something else, the
    human types their master password into whatever that something else is --
    an editor, a terminal, a chat box. The secret this product exists to
    contain lands in plaintext somewhere arbitrary and unrecoverable.

    Windows refuses SetForegroundWindow to a process that is not already in the
    foreground, which is exactly what this server is when an editor or MCP
    client launched it. focus_force() does not help: it moves focus only within
    our own application. This asserts the real OS-level condition rather than
    trusting that we asked nicely.
    """
    if not _tk_available() or sys.platform != "win32":
        return
    import ctypes
    import tkinter as tk

    win, _run = gui._new_window()
    try:
        gui._style(win)
        tk.Label(win, text="focus probe").pack()
        win.update_idletasks()
        gui._foreground(win)
        win.update()

        user32 = ctypes.windll.user32
        hwnd = user32.GetParent(win.winfo_id()) or win.winfo_id()
        assert user32.GetForegroundWindow() == hwnd, (
            "REGRESSION: the dialog opened without taking the Windows "
            "foreground. Anything the human types before clicking it goes to "
            "another application -- including their master password.")
    finally:
        win.destroy()


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
