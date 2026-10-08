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

Where the windows go. The sweep builds some fifty real Tk roots, and the
product deliberately grabs the Windows foreground for each of them, so run on
the user's own desktop it makes the PC unusable for the duration. The sweep
therefore switches this thread to a PRIVATE Win32 desktop, before tkinter is
imported, and every window lives and dies there: nothing is ever drawn on the
interactive desktop. If the private desktop cannot be created, entered and
verified, the sweep exits non-zero (EXIT_NO_DESKTOP) -- it never falls back to
the visible desktop and never passes silently. The one check that needs the
real foreground (GetForegroundWindow only works on the input desktop) is opt-in:
set LLM_ENV_VAULT_REAL_FOREGROUND=1 and the WHOLE sweep runs on the visible
desktop, deliberately, for a human who wants to watch.

Prints one line per check: "OK <name>", "SKIP <name>: <reason>" or
"FAIL <name>: <reason>". Exit code is 0 only if every check passed.
"""
import atexit
import contextlib
import os
import pathlib
import sys

EXIT_NO_DESKTOP = 3
REAL_FOREGROUND = os.environ.get("LLM_ENV_VAULT_REAL_FOREGROUND") == "1"


def _enter_private_desktop():
    """Create a private desktop, make this thread live on it, and PROVE it.

    Must run before the first window of the thread exists (SetThreadDesktop
    fails for a thread that already owns windows), so before `import tkinter`.
    Returns a teardown callable. Exits the process on any failure.
    """
    def fail(why):
        sys.stderr.write(
            "PRIVATE DESKTOP UNAVAILABLE: " + why + ". Refusing to run the Tk "
            "sweep on the interactive desktop (it would steal the user's "
            "focus).\n")
        sys.exit(EXIT_NO_DESKTOP)

    if sys.platform != "win32":
        fail("no private desktop on this platform")
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.CreateDesktopW.restype = wintypes.HANDLE
    user32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      wintypes.LPVOID, wintypes.DWORD,
                                      wintypes.DWORD, wintypes.LPVOID]
    user32.GetThreadDesktop.restype = wintypes.HANDLE
    user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
    user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.GetUserObjectInformationW.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    def desktop_name(handle):
        buf = ctypes.create_unicode_buffer(256)
        need = wintypes.DWORD()
        UOI_NAME = 2
        if not user32.GetUserObjectInformationW(
                handle, UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(need)):
            return None
        return buf.value

    original = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    name = f"llm_env_vault_tk_sweep_{os.getpid()}"
    GENERIC_ALL = 0x10000000
    private = user32.CreateDesktopW(name, None, None, 0, GENERIC_ALL, None)
    if not private:
        fail(f"CreateDesktopW failed (error {ctypes.get_last_error()})")
    if not user32.SetThreadDesktop(private):
        err = ctypes.get_last_error()
        user32.CloseDesktop(private)
        fail(f"SetThreadDesktop failed (error {err})")
    current = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    if desktop_name(current) != name:
        fail(f"the thread is on desktop {desktop_name(current)!r}, not {name!r}")

    def teardown():
        # CloseDesktop refuses while any thread of this process is still
        # assigned to the desktop, so step back to the original one first.
        if original:
            user32.SetThreadDesktop(original)
        user32.CloseDesktop(private)

    return teardown


if REAL_FOREGROUND:
    sys.stderr.write("LLM_ENV_VAULT_REAL_FOREGROUND=1: running the sweep on the "
                     "VISIBLE desktop (windows will appear and take focus).\n")
    os.environ.pop("LLM_ENV_VAULT_HEADLESS", None)
else:
    atexit.register(_enter_private_desktop())
    # Verified above: from here on, any window is on the private desktop, so
    # the process may build real Tk roots. Opt out of the headless refusal
    # explicitly; the parent test does the same for the environment it passes.
    os.environ.pop("LLM_ENV_VAULT_HEADLESS", None)
    os.environ["LLM_ENV_VAULT_PRIVATE_DESKTOP"] = "1"

import tkinter as tk  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault_lib import crypto, gui, store  # noqa: E402

RESULTS = []


class Skip(Exception):
    """Raised by a check that does not apply; reported as SKIP, not FAIL."""


def check(name):
    def wrap(fn):
        try:
            fn()
            RESULTS.append((name, None))
        except Skip as exc:
            RESULTS.append((name, ("SKIP", str(exc))))
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

# Likewise the text left in every Entry at snapshot time, in widget order, so a
# check can assert that a refused password is no longer sitting in its box.
LAST_ENTRIES = []


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
            LAST_ENTRIES[:] = [w.get() for cls, _t, w in nodes if cls == "Entry"]
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
    destroy, so the next unparented widget attaches to a dead interpreter.

    A root that is still ALIVE here is worse: a dialog raised during
    construction, before its mainloop ran, and the harness caught the
    exception. Left alone, the next dialog sees a live root, opens as a
    modal Toplevel and blocks in wait_window() -- a real window on the
    developer's desktop, waiting for a click nobody will make, until the
    outer test's timeout kills the process. Destroy it, so one broken
    dialog fails one check instead of hanging the whole sweep."""
    root = getattr(tk, "_default_root", None)
    if root is not None:
        try:
            if root.winfo_exists():
                root.destroy()
        except Exception:  # noqa: BLE001 -- already destroyed
            pass
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


@check("unlock_dialog_states_the_single_view_rule_for_materialize")
def _():
    """materialize= writes real values to a fresh path for the lifetime of
    one command -- the last standing exception to "no file an agent can read
    holds a real value" after swap= was retired in 2.0. The human must see
    the path, when the file goes away, and, under max_reads, that the revert
    is counted in opens by ANY program when the reader cannot be told apart.
    That last clause is the one that must not quietly soften."""
    widgets = build_dialog(lambda: gui.unlock_for_run_dialog(
        "docker run --env-file .env app", only_vars=["A", "B"],
        materialize_path=_FAKE_PLAINTEXT))
    blob = all_text(widgets)
    assert "deleted the moment the command exits" in blob, (
        "the unlock dialog no longer says when the materialized file goes away")
    assert "Checkbutton" in [c for c, _t in widgets], (
        "the trust checkbox vanished from materialize runs -- they are still trustable")
    single = build_dialog(lambda: gui.unlock_for_run_dialog(
        "docker compose up", only_vars=["A"], materialize_path=_FAKE_PLAINTEXT,
        timeout=3600, max_reads=2))
    blob = all_text(single)
    assert "after the first 2 open(s)" in blob and "any program" in blob, (
        "the unlock dialog no longer states the single-view rule honestly")


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
            "retype_placeholders_dialog": lambda: gui.retype_placeholders_dialog(
                ["SMTP_PORT", "SMTP_USE_SSL"]),
        }
        for name, call in cases.items():
            widgets = build_dialog(call)
            assert widgets, f"{name} built no widgets at all"
    finally:
        store.vault_info, store.vault_format_version = orig_info, orig_ver


@contextlib.contextmanager
def _refusing_vault(exc):
    """Make every password test fail with *exc* (WrongPassword, or the 2.2.0
    cool-down's TooManyAttempts), leaving the rest of the dialog's store calls
    harmless so the failed attempt is the only thing that can go wrong."""
    names = ["load_secrets", "vault_exists", "load_index", "precheck_encrypt",
             "precheck_decrypt", "read_encrypted_file"]
    originals = {n: getattr(store, n) for n in names}

    def _refuse(*a, **k):
        raise exc

    store.load_secrets = _refuse
    store.vault_exists = lambda: True
    store.load_index = lambda: {"A": 1}
    store.precheck_encrypt = lambda p: {
        "path": pathlib.Path(_FAKE_PLAINTEXT),
        "vault_path": pathlib.Path(_FAKE_SIDECAR),
        "size": 4096, "mode": "0600", "sidecar_exists": False}
    store.precheck_decrypt = lambda vp, op=None: {
        "vault_path": pathlib.Path(_FAKE_SIDECAR),
        "output_path": pathlib.Path(_FAKE_PLAINTEXT),
        "envelope_size": 4200}
    store.read_encrypted_file = _refuse
    try:
        yield
    finally:
        for n, fn in originals.items():
            setattr(store, n, fn)


@check("a_refused_password_is_cleared_and_the_field_refocused")
def _():
    """Every dialog that tests the typed master password in place must empty
    the box when the attempt is refused -- wrong password, or turned away by
    the unlock cool-down (TooManyAttempts, a WrongPassword subclass) -- keep
    the error message, and put the cursor back in the field. Leaving the
    wrong text there makes the human delete it by hand and leaves a wrong
    secret on screen."""
    cases = {
        "unlock_for_run_dialog": (
            lambda: gui.unlock_for_run_dialog("echo hello", only_vars=["A"]),
            "Unlock && Run"),
        "add_secret_dialog": (
            lambda: gui.add_secret_dialog("A", False, 1), "Continue"),
        "remove_secret_dialog": (
            lambda: gui.remove_secret_dialog("A", 1), "Continue"),
        "retype_placeholders_dialog": (
            lambda: gui.retype_placeholders_dialog(["A"]), "Continue"),
        "install_dialog": (
            lambda: gui.install_dialog(pathlib.Path(_FAKE_PLAINTEXT), [("A", "a")]),
            "Continue"),
        "encrypt_file_dialog": (
            lambda: gui.encrypt_file_dialog(_FAKE_PLAINTEXT), "Continue"),
        "decrypt_file_dialog": (
            lambda: gui.decrypt_file_dialog(_FAKE_SIDECAR), "Continue"),
    }
    for exc in (crypto.WrongPassword("Wrong password."),
                crypto.TooManyAttempts(30)):
        for name, (call, click) in cases.items():
            focused = []
            real_focus = tk.Entry.focus_force
            tk.Entry.focus_force = lambda self: focused.append(self.winfo_class())
            try:
                with _refusing_vault(exc):
                    widgets = build_dialog(call, typed="not-the-password", click=click)
            finally:
                tk.Entry.focus_force = real_focus
            where = f"{name} after {type(exc).__name__}"
            assert LAST_ENTRIES == [""], (
                f"{where}: the refused password is still in the entry box "
                f"(entries hold {LAST_ENTRIES!r})")
            assert str(exc) in [t for _c, t in widgets], (
                f"{where}: the error message {str(exc)!r} is no longer shown")
            assert len(focused) >= 2 and focused[-1] == "Entry", (
                f"{where}: focus was not put back in the password field "
                f"(focus_force calls: {focused!r}; the first is the dialog opening)")


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


@check("dialog_asks_for_the_windows_foreground")
def _():
    """Mocked, so it runs on the private desktop.

    Two halves. gui._foreground must hand THIS dialog's window to
    _win32_take_foreground; and _win32_take_foreground must aim
    SetForegroundWindow at that window's top-level HWND (the parent of Tk's
    client area), attaching to the foreground thread's input queue before the
    call and detaching after.
    """
    win, _run = gui._new_window()
    seen = []
    real = gui._win32_take_foreground
    gui._win32_take_foreground = seen.append
    try:
        gui._style(win)
        gui._foreground(win)
    finally:
        gui._win32_take_foreground = real
        win.destroy()
        _drop_dead_root()
    assert len(seen) == 1 and seen[0] is win, (
        f"_foreground did not ask for the foreground for the dialog window "
        f"(calls: {len(seen)})")

    if sys.platform != "win32":
        return
    import ctypes
    calls = []

    class _Fn:
        def __init__(self, label, result):
            self.label, self.result = label, result

        def __call__(self, *args):
            calls.append((self.label, tuple(args)))
            return self.result

    class _Lib:
        def __init__(self, **fns):
            self.__dict__.update(fns)

    TOP_LEVEL, CLIENT, OTHER_FG, FG_TID, OUR_TID = 4242, 100, 7, 55, 66
    fake_user32 = _Lib(
        GetParent=_Fn("GetParent", TOP_LEVEL),
        GetForegroundWindow=_Fn("GetForegroundWindow", OTHER_FG),
        GetWindowThreadProcessId=_Fn("GetWindowThreadProcessId", FG_TID),
        AttachThreadInput=_Fn("AttachThreadInput", 1),
        BringWindowToTop=_Fn("BringWindowToTop", 1),
        SetForegroundWindow=_Fn("SetForegroundWindow", 1),
        SetActiveWindow=_Fn("SetActiveWindow", 1))
    fake_kernel32 = _Lib(GetCurrentThreadId=_Fn("GetCurrentThreadId", OUR_TID))

    class _FakeWin:
        def winfo_id(self):
            return CLIENT

    real_windll = ctypes.windll
    ctypes.windll = _Lib(user32=fake_user32, kernel32=fake_kernel32)
    try:
        gui._win32_take_foreground(_FakeWin())
    finally:
        ctypes.windll = real_windll
    by_name = [c[0] for c in calls]
    assert ("SetForegroundWindow", (TOP_LEVEL,)) in calls, (
        f"SetForegroundWindow was not aimed at the dialog's top-level window "
        f"(calls: {calls})")
    assert ("AttachThreadInput", (FG_TID, OUR_TID, True)) in calls, (
        f"the foreground thread's input queue was not attached (calls: {calls})")
    assert ("AttachThreadInput", (FG_TID, OUR_TID, False)) in calls, (
        f"the foreground thread's input queue was never detached (calls: {calls})")
    assert by_name.index("AttachThreadInput") < by_name.index("SetForegroundWindow"), (
        "SetForegroundWindow ran before attaching to the foreground thread")


@check("dialog_takes_the_windows_foreground")
def _():
    """The real thing: GetForegroundWindow() must be the dialog. Foreground
    only exists on the input desktop, so this cannot run on the private one;
    it is opt-in (LLM_ENV_VAULT_REAL_FOREGROUND=1, which also puts the whole
    sweep on the visible desktop). Run it before a release."""
    if not REAL_FOREGROUND:
        raise Skip("needs the real input desktop; set "
                   "LLM_ENV_VAULT_REAL_FOREGROUND=1 to run it (windows will "
                   "appear and take focus)")
    if sys.platform != "win32":
        raise Skip("Windows-only")
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
        elif isinstance(err, tuple):
            print(f"SKIP {name}: {err[1]}")
        else:
            print(f"FAIL {name}: {err}")
            failed += 1
    sys.exit(1 if failed else 0)
