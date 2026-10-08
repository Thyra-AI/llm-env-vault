"""Suite-wide guard: no test may put a real window on anyone's screen.

Before this file existed the only protection was that each test happened to
monkeypatch the dialog it called, and the one sweep that needs real Tk windows
(tests/_tk_checks.py) ran them on the interactive desktop, stealing focus for
the whole run. Two layers now:

1. LLM_ENV_VAULT_HEADLESS=1 is set at import time, so every subprocess a test
   starts inherits it too. vault_lib/gui.py then REFUSES to create any dialog
   (it raises; nothing is approved, no password or confirmation is returned --
   see gui._refuse_if_headless). The Tk sweep child is the single exception:
   test_security_invariants.py clears the variable for it, and the child moves
   itself to a private Win32 desktop (verified) before it imports tkinter.

2. An autouse tripwire makes creating a tkinter.Tk / Toplevel, or calling a
   ctypes MessageBox, fail the test loudly in THIS process, and counts every
   attempt. If a test swallows that failure the session still ends non-zero.

The tripwire only exists under pytest. CI also runs some files standalone
(python tests/test_x.py); that workflow step sets LLM_ENV_VAULT_HEADLESS itself.
"""
import os
import sys
import tkinter

import pytest

# Import time, not a fixture: subprocesses spawned during collection and by
# module-level code must inherit it as well.
os.environ["LLM_ENV_VAULT_HEADLESS"] = "1"

# One entry per attempted window, with what tried it. Empty means the suite
# created zero windows in this process.
ATTEMPTS: list = []


class WindowForbidden(AssertionError):
    """A test tried to open a real window or message box."""


def _record(what: str):
    ATTEMPTS.append(what)
    raise WindowForbidden(
        f"{what}: a test tried to open a real window. Patch the gui.*_dialog "
        f"function (or the code under test) instead; the suite must never "
        f"draw on the user's screen.")


def _forbid_init(cls):
    def init(self, *args, **kwargs):
        _record(f"tkinter.{cls.__name__}()")
    return init


@pytest.fixture(autouse=True)
def _no_real_windows(monkeypatch):
    monkeypatch.setattr(tkinter.Tk, "__init__", _forbid_init(tkinter.Tk))
    monkeypatch.setattr(tkinter.Toplevel, "__init__", _forbid_init(tkinter.Toplevel))
    if sys.platform == "win32":
        import ctypes
        user32 = ctypes.windll.user32
        for name in ("MessageBoxW", "MessageBoxA", "MessageBoxExW", "MessageBoxExA"):
            monkeypatch.setattr(
                user32, name,
                lambda *a, _n=name, **k: _record(f"ctypes user32.{_n}"),
                raising=False)
    yield


def pytest_sessionfinish(session, exitstatus):
    # A test that caught WindowForbidden would otherwise hide the leak.
    if ATTEMPTS and session.exitstatus == 0:
        session.exitstatus = 1


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(
        f"window tripwire: {len(ATTEMPTS)} Tk/MessageBox creation attempt(s) "
        f"in-process"
        + ("" if not ATTEMPTS else " -- " + "; ".join(ATTEMPTS[:5])))
