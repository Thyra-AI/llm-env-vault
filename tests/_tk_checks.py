"""Tk-dependent dialog checks, run in a FRESH interpreter.

Not named test_* on purpose: pytest must not collect this directly.
tests/test_security_invariants.py runs it as a subprocess and asserts the
result.

Why a subprocess at all. These checks need real Tk windows -- that is the whole
point, since nothing else catches a dialog that fails to build or one that
opens without the keyboard. But creating and destroying Tk roots repeatedly
inside one interpreter corrupts Tcl state: after a dozen or so, unrelated tests
start failing with "tk wasn't installed properly", and which ones fail depends
on execution order. That is worse than no test, because a flaky security test
gets muted. One fresh process per full sweep makes it deterministic.

Prints one line per check: "OK <name>" or "FAIL <name>: <reason>".
Exit code is 0 only if every check passed.
"""
import os
import sys
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault_lib import crypto, gui, store  # noqa: E402

RESULTS = []


def check(name):
    def wrap(fn):
        try:
            fn()
            RESULTS.append((name, None))
        except AssertionError as exc:
            RESULTS.append((name, str(exc)))
        except Exception as exc:  # noqa: BLE001
            RESULTS.append((name, f"{type(exc).__name__}: {exc}"))
        return fn
    return wrap


def build_dialog(call):
    """Run a dialog far enough to build its widgets, then tear it down.

    Dialogs own their root and end in mainloop(), so there is no outside handle
    to drive them. Swapping in a root whose mainloop() snapshots the widget tree
    and destroys itself lets the entire construction path run -- every grid(),
    every cget(), every f-string in a label -- with no human and no blocking.
    """
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
        _drop_dead_root()
    return captured


def _drop_dead_root():
    """tkinter keeps the last root in _default_root and never clears it on
    destroy, so the next unparented widget attaches to a dead interpreter."""
    root = getattr(tk, "_default_root", None)
    if root is not None:
        try:
            root.winfo_exists()
        except Exception:  # noqa: BLE001 -- already destroyed
            tk._default_root = None


def all_text(widgets):
    return " ".join(t for _c, t in widgets).lower()


KEY = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))


@check("recovery_dialog_shows_key_and_both_drill_steps")
def _():
    widgets = build_dialog(lambda: gui.show_recovery_key_dialog(KEY, "AB12"))
    classes = [c for c, _t in widgets]
    blob = all_text(widgets)
    assert "Checkbutton" in classes, "the 'I wrote this down' checkbox is gone"
    assert "Entry" in classes, (
        "the full-key re-entry field is gone -- nothing then verifies the human "
        "transcribed the key, and a mistranscription surfaces only in an emergency")
    assert "cannot be shown again" in blob, (
        "the dialog no longer says the key is unrecoverable once closed")
    assert "AB12" in " ".join(t for _c, t in widgets), (
        "the slot id is gone, so a stale printout cannot be identified")


@check("recovery_dialog_offers_no_save_or_print")
def _():
    widgets = build_dialog(lambda: gui.show_recovery_key_dialog(KEY, "AB12"))
    for cls, text in widgets:
        if cls in ("Button", "Checkbutton", "Radiobutton"):
            low = text.lower()
            for banned in ("save to", "save as", "print", "export", "email"):
                assert banned not in low, (
                    f"{cls} labelled {text!r}: the key may reach the clipboard "
                    f"briefly, but never a file or a print spooler")


@check("unlock_dialog_never_accepts_a_recovery_key")
def _():
    widgets = build_dialog(
        lambda: gui.unlock_for_run_dialog("echo hello", only_vars=["A"]))
    assert "recovery" not in all_text(widgets), (
        "the run-command unlock dialog mentions a recovery key. Recovery entry "
        "belongs only in recover_dialog; otherwise every routine unlock prompt "
        "becomes a harvesting surface")


@check("unlock_dialog_discloses_output_goes_to_the_ai")
def _():
    widgets = build_dialog(
        lambda: gui.unlock_for_run_dialog("echo hello", only_vars=["A"]))
    assert "returned to the ai" in all_text(widgets), (
        "the unlock dialog no longer tells the human the command's output is "
        "handed back to the AI assistant")


@check("every_dialog_constructs")
def _():
    orig_info, orig_ver = store.vault_info, store.vault_format_version
    store.vault_info = lambda: {
        "format": 2, "kdf": "scrypt", "kdf_params": {"n": 65536, "r": 8, "p": 1},
        "recovery_slot": True, "recovery_slot_id": "AB12",
        "recovery_slot_created": "2026-08-16T00:00:00+00:00",
        "created": "2026-08-16T00:00:00+00:00"}
    store.vault_format_version = lambda: 2
    try:
        cases = {
            "show_recovery_key_dialog": lambda: gui.show_recovery_key_dialog(KEY, "AB12"),
            "recover_dialog": gui.recover_dialog,
            "manage_vault_dialog": gui.manage_vault_dialog,
            "change_password_dialog": gui.change_password_dialog,
            "unlock_for_run_dialog": lambda: gui.unlock_for_run_dialog(
                "echo hello", only_vars=["A"]),
        }
        for name, call in cases.items():
            widgets = build_dialog(call)
            assert widgets, f"{name} built no widgets at all"
    finally:
        store.vault_info, store.vault_format_version = orig_info, orig_ver


@check("first_window_is_a_real_root")
def _():
    _drop_dead_root()
    win, _run = gui._new_window()
    try:
        assert isinstance(win, tk.Tk), (
            "the first window in a process must be a real Tk root")
    finally:
        win.destroy()
        _drop_dead_root()


@check("second_window_is_a_toplevel")
def _():
    root = tk.Tk()
    root.withdraw()
    try:
        second, run = gui._new_window()
        assert isinstance(second, tk.Toplevel), (
            f"opening a window while a root is alive produced "
            f"{type(second).__name__}, not a Toplevel. A second Tk root means a "
            f"nested mainloop and an undismissable dialog")
        assert run.__name__ != "mainloop", (
            "the second window would be driven by a nested mainloop")
        second.destroy()
    finally:
        root.destroy()
        _drop_dead_root()


@check("dialog_takes_the_windows_foreground")
def _():
    if sys.platform != "win32":
        return
    import ctypes
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
            "the dialog opened without taking the Windows foreground. Anything "
            "typed before clicking it goes to another application -- including "
            "the master password")
    finally:
        win.destroy()
        _drop_dead_root()


if __name__ == "__main__":
    failed = 0
    for name, err in RESULTS:
        if err is None:
            print(f"OK {name}")
        else:
            print(f"FAIL {name}: {err}")
            failed += 1
    sys.exit(1 if failed else 0)
