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
import contextlib
import os
import pathlib
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


# Filled in by build_dialog with the root's key bindings at snapshot time, so
# a check can assert that a dangerous screen rebound <Return> to a no-op
# instead of leaving the previous step's handler live.
LAST_BINDINGS = {}


def build_dialog(call, typed=None, click=None):
    """Run a dialog far enough to build its widgets, then tear it down.

    Dialogs own their root and end in mainloop(), so there is no outside handle
    to drive them. Swapping in a root whose mainloop() snapshots the widget tree
    and destroys itself lets the entire construction path run -- every grid(),
    every cget(), every f-string in a label -- with no human and no blocking.

    *typed* and *click* drive a two-step dialog one step further: the text is
    put into the first Entry (a password box), then the Button with that label
    is invoked, and only then is the tree snapshotted. Without this, the only
    screen ever exercised is the unlock prompt -- and the screen that actually
    matters for consent, the one naming what is about to be destroyed, would
    never be built by any test.
    """
    captured = []
    real_tk = tk.Tk

    def _walk_into(widget, out):
        for child in widget.winfo_children():
            try:
                text = str(child.cget("text"))
            except Exception:  # noqa: BLE001 -- not every widget has -text
                text = ""
            out.append((child.winfo_class(), text, child))
            label = _button_label(child)
            if label is not None:
                # Buttons here are _RoundedButton, a Canvas whose label is a
                # canvas item rather than a -text option, so cget above returns
                # "" for every one of them. Without this, no check can see what
                # any button in this application is labelled.
                out.append(("Canvas", label, child))
            _walk_into(child, out)

    class _AutoCloseTk(real_tk):
        def mainloop(self, n=0):
            if typed is not None or click is not None:
                nodes = []
                _walk_into(self, nodes)
                if typed is not None:
                    for cls, _t, widget in nodes:
                        if cls == "Entry":
                            widget.insert("end", typed)
                            break
                if click is not None:
                    for _cls, _text, widget in nodes:
                        if _button_label(widget) == click:
                            widget._command()
                            break
                    else:
                        raise AssertionError(f"no button labelled {click!r} to click")
            nodes = []
            _walk_into(self, nodes)
            captured.extend((cls, text) for cls, text, _w in nodes)
            LAST_BINDINGS.clear()
            for seq in ("<Return>", "<Escape>"):
                try:
                    LAST_BINDINGS[seq] = self.bind(seq)
                except Exception:  # noqa: BLE001
                    LAST_BINDINGS[seq] = None
            self.destroy()

    gui.tk.Tk = _AutoCloseTk
    try:
        call()
    finally:
        gui.tk.Tk = real_tk
        _drop_dead_root()
    return captured


def _button_label(widget):
    """The label of a _RoundedButton, or None if this isn't one.

    Buttons in this application are Canvas subclasses that draw their own
    label as a canvas text item, so winfo_class() says "Canvas" and
    cget("text") raises. Reading the item back is the only way to know what a
    human sees on a button.
    """
    if not isinstance(widget, tk.Canvas) or not hasattr(widget, "_command"):
        return None
    try:
        for item in widget.find_all():
            if widget.type(item) == "text":
                return str(widget.itemcget(item, "text"))
    except Exception:  # noqa: BLE001
        return None
    return None


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

# Paths that never exist -- the dialogs are driven with store monkeypatched, so
# nothing here touches a real vault or a real file.
_FAKE_PLAINTEXT = os.path.join(os.path.dirname(__file__), "_never_exists", "server.pem")
_FAKE_SIDECAR = _FAKE_PLAINTEXT + ".levault"


@contextlib.contextmanager
def _fake_encrypt_vault():
    """Let encrypt_file_dialog reach step 2 without a vault or a real file."""
    originals = (store.load_secrets, store.precheck_encrypt, store._sidecar_matches)
    store.load_secrets = lambda pw: {"A": "a"}
    store.precheck_encrypt = lambda p: {
        "path": pathlib.Path(_FAKE_PLAINTEXT),
        "vault_path": pathlib.Path(_FAKE_SIDECAR),
        "size": 4096, "mode": "0600", "sidecar_exists": False}
    store._sidecar_matches = lambda *a, **k: False
    try:
        yield
    finally:
        (store.load_secrets, store.precheck_encrypt, store._sidecar_matches) = originals


@contextlib.contextmanager
def _fake_decrypt_vault():
    """Let decrypt_file_dialog reach step 2 without a vault or a real file."""
    originals = (store.precheck_decrypt, store.read_encrypted_file)
    store.precheck_decrypt = lambda vp, op=None: {
        "vault_path": pathlib.Path(_FAKE_SIDECAR),
        "output_path": pathlib.Path(_FAKE_PLAINTEXT),
        "envelope_size": 4200}
    store.read_encrypted_file = lambda vp, pw: (
        b"x" * 4096, {"name": "server.pem", "mode": "0600", "sha256": "0" * 64})
    try:
        yield
    finally:
        (store.precheck_decrypt, store.read_encrypted_file) = originals


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
        if cls in ("Button", "Canvas", "Checkbutton", "Radiobutton"):
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


@check("unlock_dialog_discloses_every_file_it_will_decrypt")
def _():
    """A files= run writes real private keys into the working directory. The
    human must see each destination path in full -- and must be told the
    contents are NOT redacted from the output, unlike variable values."""
    pairs = [(pathlib.Path(_FAKE_SIDECAR), pathlib.Path(_FAKE_PLAINTEXT))]
    widgets = build_dialog(lambda: gui.unlock_for_run_dialog(
        "echo hello", only_vars=["A"], files=pairs))
    blob = all_text(widgets)
    assert "decrypts 1 file" in blob, (
        "the unlock dialog no longer says how many files it will decrypt")
    assert "deleted the moment the command exits" in blob, (
        "the unlock dialog no longer says the decrypted files are cleaned up")
    assert "not redacted" in blob, (
        "the unlock dialog no longer warns that file contents reach the AI "
        "unredacted -- unlike variable values, which are masked")


@check("unlock_dialog_offers_no_trust_when_it_will_decrypt_files")
def _():
    """An 8-hour grant that re-decrypts a private key with no human present is
    a different risk from one that injects a token into an environment. The
    checkbox must not even be offered."""
    pairs = [(pathlib.Path(_FAKE_SIDECAR), pathlib.Path(_FAKE_PLAINTEXT))]
    with_files = build_dialog(lambda: gui.unlock_for_run_dialog(
        "echo hello", only_vars=["A"], files=pairs))
    assert "Checkbutton" not in [c for c, _t in with_files], (
        "the trust checkbox is still offered on a run that decrypts files to disk")
    assert "cannot be trusted" in all_text(with_files), (
        "the dialog hides the trust checkbox without saying why")

    without = build_dialog(lambda: gui.unlock_for_run_dialog(
        "echo hello", only_vars=["A"]))
    assert "Checkbutton" in [c for c, _t in without], (
        "the trust checkbox vanished from ordinary runs too -- the files check "
        "above would then pass for the wrong reason")


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
            "encrypt_file_dialog": lambda: gui.encrypt_file_dialog(
                _FAKE_PLAINTEXT),
            "decrypt_file_dialog": lambda: gui.decrypt_file_dialog(
                _FAKE_SIDECAR),
            "confirm_abandon_files_dialog": lambda: gui.confirm_abandon_files_dialog(
                {"OLDGEN01": ["abcdef0123456789"]}, {"abcdef0123456789": "server.pem"}),
        }
        for name, call in cases.items():
            widgets = build_dialog(call)
            assert widgets, f"{name} built no widgets at all"
    finally:
        store.vault_info, store.vault_format_version = orig_info, orig_ver


@check("encrypt_dialog_says_the_original_will_be_destroyed")
def _():
    """The single most consequential sentence in this entire feature. If it
    stops rendering, a human clicks Allow on a screen that never told them a
    file is about to be deleted."""
    with _fake_encrypt_vault():
        widgets = build_dialog(
            lambda: gui.encrypt_file_dialog(_FAKE_PLAINTEXT),
            typed="pw", click="Continue")
    blob = all_text(widgets)
    assert "will be destroyed" in blob, (
        "the encrypt dialog no longer warns that the original file is deleted")
    assert "overwritten with random bytes" in blob, (
        "the encrypt dialog no longer says how the original is destroyed")


@check("encrypt_dialog_keeps_the_best_effort_overwrite_caveat")
def _():
    """Promising a secure wipe we cannot deliver is worse than not promising
    one: the user skips rotating a credential that is still recoverable."""
    with _fake_encrypt_vault():
        widgets = build_dialog(
            lambda: gui.encrypt_file_dialog(_FAKE_PLAINTEXT),
            typed="pw", click="Continue")
    blob = all_text(widgets)
    assert "best-effort" in blob, "the overwrite caveat is gone"
    for needle in ("wear-levelling", "shadow copies", "rotate the credential"):
        assert needle in blob, f"the overwrite caveat no longer mentions {needle}"


@check("encrypt_dialog_warns_that_losing_the_vault_loses_the_file")
def _():
    """A .levault is meant to be committed, but the only key lives in
    vault.enc and the recovery key cannot open a file without it."""
    with _fake_encrypt_vault():
        widgets = build_dialog(
            lambda: gui.encrypt_file_dialog(_FAKE_PLAINTEXT),
            typed="pw", click="Continue")
    blob = all_text(widgets)
    assert "cannot be recovered" in blob and "recovery key alone is not enough" in blob, (
        "the encrypt dialog no longer warns that losing vault.enc loses the file")


@check("file_dialogs_rebind_return_away_from_allow")
def _():
    """A held or double-tapped Enter carried over from the password box must
    not fire Allow on a screen that destroys a file. Rebinding to a no-op is
    required, not merely omitting the binding: an unrebound handler stays live
    and fires against widgets step 2 already destroyed.

    Asserting the binding CHANGED between the two steps is what makes this
    real -- "some binding exists" is also true of the dangerous case."""
    for name, fake, call in (
        ("encrypt", _fake_encrypt_vault,
         lambda: gui.encrypt_file_dialog(_FAKE_PLAINTEXT)),
        ("decrypt", _fake_decrypt_vault,
         lambda: gui.decrypt_file_dialog(_FAKE_SIDECAR)),
    ):
        with fake():
            build_dialog(call)
            step1 = LAST_BINDINGS.get("<Return>")
            build_dialog(call, typed="pw", click="Continue")
            step2 = LAST_BINDINGS.get("<Return>")
        assert step1, f"{name} step 1 has no <Return> -> Continue binding"
        assert step2, (
            f"{name} step 2 left <Return> unbound entirely -- step 1's handler "
            f"is still live and will fire against destroyed widgets")
        assert step1 != step2, (
            f"{name} step 2 still carries step 1's <Return> handler; a carried-"
            f"over Enter would act on the confirmation screen")


@check("decrypt_dialog_says_the_secret_lands_on_disk_permanently")
def _():
    with _fake_decrypt_vault():
        widgets = build_dialog(
            lambda: gui.decrypt_file_dialog(_FAKE_SIDECAR),
            typed="pw", click="Continue")
    blob = all_text(widgets)
    assert "real secret to disk permanently" in blob, (
        "the decrypt dialog no longer says the secret is written permanently")
    assert "not enforced" in blob, (
        "the decrypt dialog no longer admits the AI's instruction not to read "
        "the file is unenforced")


@check("abandon_dialog_names_what_is_being_destroyed")
def _():
    """This dialog is the only way to deliberately make a file unreadable
    forever. It must say so, and it must list what is being given up rather
    than asking for a blanket confirmation."""
    widgets = build_dialog(lambda: gui.confirm_abandon_files_dialog(
        {"OLDGEN01": ["abcdef0123456789"]}, {"abcdef0123456789": "server.pem"}))
    blob = all_text(widgets)
    assert "permanently unreadable" in blob, (
        "the abandon dialog no longer says the files become unreadable forever")
    assert "gone forever" in blob, "the confirmation checkbox text is gone"
    assert "Checkbutton" in [c for c, _t in widgets], (
        "the abandon confirmation is no longer an explicit opt-in")


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
