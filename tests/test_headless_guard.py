"""
Tests for the fail-closed headless guard in vault_lib/gui.py.

LLM_ENV_VAULT_HEADLESS exists so the test suite (and every subprocess it
starts) can never put a real window on the user's screen. Its only effect is
to make dialog creation RAISE. It must never become a way to skip a consent
dialog: no dialog may return, approve, or hand back a password or confirmation
while it is set.

Call convention: plain `def test_x() -> None:` functions, no fixtures, so the
file also runs standalone (python tests/test_headless_guard.py).
"""
import contextlib
import inspect
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vault_lib import gui  # noqa: E402


@contextlib.contextmanager
def _env(value):
    old = os.environ.get(gui.HEADLESS_ENV)
    if value is None:
        os.environ.pop(gui.HEADLESS_ENV, None)
    else:
        os.environ[gui.HEADLESS_ENV] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(gui.HEADLESS_ENV, None)
        else:
            os.environ[gui.HEADLESS_ENV] = old


@contextlib.contextmanager
def _window_tripwire():
    """Fail if anything gets as far as building a Tk widget. Independent of
    tests/conftest.py so the guarantee holds when run standalone too."""
    created = []

    def boom(*_a, **_k):
        created.append(1)
        raise AssertionError("a window was created")

    saved = (gui.tk.Tk, gui.tk.Toplevel)
    gui.tk.Tk = boom
    gui.tk.Toplevel = boom
    try:
        yield created
    finally:
        gui.tk.Tk, gui.tk.Toplevel = saved


# One valid-enough argument set per public entry point. The discovery test
# below fails when a dialog is added without a row here, so a new dialog can
# never skip the headless proof.
_ARGS = {
    "add_secret_dialog": (("API_KEY", False, 1), {}),
    "remove_secret_dialog": (("API_KEY", 1), {}),
    "retype_placeholders_dialog": ((["API_KEY"],), {}),
    "install_dialog": (("fake.env", [("API_KEY", "x")]), {}),
    "encrypt_file_dialog": (("fake.txt",), {}),
    "decrypt_file_dialog": (("fake.levault",), {}),
    "confirm_abandon_files_dialog": (({"g1": ["f1"]}, {"f1": "fake.txt"}), {}),
    "unlock_for_run_dialog": (("echo hi",), {}),
    "change_password_dialog": ((), {}),
    "show_recovery_key_dialog": (("KEY", "slot"), {}),
    "recover_dialog": ((), {}),
    "manage_vault_dialog": ((), {}),
    "run_recovery_drill": ((), {}),
}


def _public_dialogs() -> dict:
    found = {}
    for name, fn in inspect.getmembers(gui, inspect.isfunction):
        if name.startswith("_") or fn.__module__ != gui.__name__:
            continue
        if name.endswith("_dialog") or name == "run_recovery_drill":
            found[name] = fn
    return found


def test_every_public_dialog_has_a_headless_case() -> None:
    found = set(_public_dialogs())
    assert found == set(_ARGS), (
        f"REGRESSION: the set of gui dialog entry points changed. Add or "
        f"remove rows in _ARGS so each one is proven to refuse when headless. "
        f"Missing rows: {sorted(found - set(_ARGS))}; stale rows: "
        f"{sorted(set(_ARGS) - found)}")


def test_every_dialog_refuses_when_headless() -> None:
    with _env("1"), _window_tripwire() as created:
        for name, fn in sorted(_public_dialogs().items()):
            args, kwargs = _ARGS[name]
            try:
                result = fn(*args, **kwargs)
            except gui.HeadlessDialogRefused:
                continue
            raise AssertionError(
                f"REGRESSION: {name} did not refuse under {gui.HEADLESS_ENV}; "
                f"it returned {type(result).__name__}. A headless dialog must "
                f"fail closed -- never approve, never return a password or "
                f"confirmation.")
        assert not created, "a dialog built a Tk window while headless"
    assert getattr(gui.tk, "_default_root", None) is None, (
        "a dialog left a Tk root behind while headless")


def test_the_refusal_is_not_swallowed_by_foreground() -> None:
    # _foreground wraps its body in a catch-all; the headless refusal must sit
    # outside it or a window that slipped through would not be stopped there.
    with _env("1"):
        try:
            gui._foreground(object())
        except gui.HeadlessDialogRefused:
            return
    raise AssertionError("_foreground did not refuse when headless")


def test_the_refusal_is_a_plain_error_not_an_outcome() -> None:
    assert issubclass(gui.HeadlessDialogRefused, RuntimeError)
    with _env("1"):
        try:
            gui._new_window()
        except gui.HeadlessDialogRefused as exc:
            assert "no input was collected" in str(exc).lower() or \
                "nothing was approved" in str(exc).lower()
            return
    raise AssertionError("_new_window did not raise when headless")


def test_unset_or_zero_does_not_refuse() -> None:
    # Only the guard helper is called: actually opening a window is exactly
    # what this suite must never do.
    for value in (None, "", "0"):
        with _env(value):
            gui._refuse_if_headless("probe")  # must not raise
    for value in ("1", "true", "yes", "anything"):
        with _env(value):
            try:
                gui._refuse_if_headless("probe")
            except gui.HeadlessDialogRefused:
                continue
            raise AssertionError(f"{value!r} did not refuse")


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
        sys.exit(1)
    print("All tests passed.")
