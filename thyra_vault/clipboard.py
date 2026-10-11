"""Put a value on the system clipboard from the server side, then wipe it.

The browser app copies a secret WITHOUT the value ever reaching the page: the
page asks for "copy item X", this module puts it on the clipboard, and it is
cleared again after a delay -- but only if the clipboard still holds what we put
there, so something the human copied in the meantime is left alone. The value
travels to the clipboard tool on stdin, never on a command line (a command line
is visible in the process list).

Honest limits: any program that can read the clipboard can read the value while
it is there, and Windows clipboard history / cloud clipboard may keep a copy
this module cannot erase. Short timeouts shrink the window; they do not close it.

``copy`` returns None on success or a short reason code the UI can translate:
``"unavailable"`` (no clipboard tool found) or ``"failed"``.
"""
import atexit
import os
import shutil
import signal
import subprocess
import sys
import threading
from typing import Callable, List, Optional, Tuple

_TIMEOUT = 5

# (copy command, paste command) pairs, tried in order.
_Backend = Tuple[List[str], Optional[List[str]]]


def _posix_backends(env) -> List[_Backend]:
    wayland: List[_Backend] = [(["wl-copy"], ["wl-paste", "--no-newline"])]
    x11: List[_Backend] = [(["xclip", "-selection", "clipboard", "-in"], ["xclip", "-selection", "clipboard", "-out"]),
           (["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"])]
    return wayland + x11 if env.get("WAYLAND_DISPLAY") else x11 + wayland


def backends(platform: str = sys.platform, env=os.environ, which=shutil.which) -> List[_Backend]:
    found: List[_Backend]
    if platform == "darwin":
        found = [(["pbcopy"], ["pbpaste"])]
    elif platform == "win32":
        ps = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        found = [(ps + ["[Console]::InputEncoding=[Text.Encoding]::UTF8; "
                        "Set-Clipboard -Value ([Console]::In.ReadToEnd())"],
                  ps + ["[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"])]
    else:
        found = _posix_backends(env)
    return [b for b in found if which(b[0][0])]


def _run_copy(cmd: List[str], text: str) -> bool:
    try:
        # DEVNULL on stdout/stderr: xclip and wl-copy stay alive to serve the
        # selection, and holding our pipes open would hang a capture.
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        assert proc.stdin is not None
        proc.stdin.write(text.encode("utf-8"))
        proc.stdin.close()
        try:
            return proc.wait(timeout=_TIMEOUT) == 0
        except subprocess.TimeoutExpired:
            # Still running: it is serving the selection. Treat as success.
            return proc.poll() is None
    except (OSError, ValueError):
        return False


def _run_paste(cmd: List[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def copy(text: str) -> Optional[str]:
    available = backends()
    if not available:
        return "unavailable"
    for cmd, _ in available:
        if _run_copy(cmd, text):
            return None
    return "failed"


def read() -> Optional[str]:
    for _, paste in backends():
        if paste:
            got = _run_paste(paste)
            if got is not None:
                return got
    return None


def clear_if_unchanged(value: str, *, reader: Callable[[], Optional[str]] = read,
                       writer: Callable[[str], Optional[str]] = copy) -> bool:
    """Empty the clipboard if it still holds ``value``. If it cannot be read,
    clear it anyway: leaving a secret behind is the worse failure."""
    current = reader()
    if current is not None and current.rstrip("\r\n") != value.rstrip("\r\n"):
        return False
    return writer(" ") is None  # some tools refuse an empty selection


# Wipes that are scheduled but have not fired yet, by value. A daemon timer dies
# with the process, so "copy, paste, close the app" used to leave the secret on
# the clipboard for good (and an X11 clipboard tool keeps serving it). wipe_now
# runs from the app's shutdown path and from atexit.
_pending: dict = {}
_pending_lock = threading.Lock()


def _fire(value: str) -> None:
    with _pending_lock:
        _pending.pop(value, None)
    clear_if_unchanged(value)


def clear_later(value: str, seconds: float) -> threading.Timer:
    """Wipe ``value`` after ``seconds`` -- once per value: a second copy of the
    same text restarts the clock instead of letting the first timer wipe early."""
    timer = threading.Timer(seconds, _fire, args=(value,))
    timer.daemon = True
    with _pending_lock:
        previous = _pending.get(value)
        if previous is not None:
            previous.cancel()
        _pending[value] = timer
    timer.start()
    return timer


def wipe_now() -> int:
    """Cancel every pending timer and wipe those values immediately. Returns how many."""
    with _pending_lock:
        waiting = list(_pending.items())
        _pending.clear()
    for value, timer in waiting:
        timer.cancel()
        try:
            clear_if_unchanged(value)
        except Exception:  # noqa: BLE001 -- shutting down: never raise from here
            pass
    return len(waiting)


atexit.register(wipe_now)


def _exit_signals() -> list:
    """The signals that end the process without running atexit: closing the
    terminal (SIGHUP) or a plain ``kill`` (SIGTERM; SIGBREAK on Windows)."""
    names = ("SIGTERM", "SIGBREAK") if sys.platform == "win32" else ("SIGTERM", "SIGHUP")
    return [getattr(signal, n) for n in names if hasattr(signal, n)]


def _on_exit_signal(signum, _frame) -> None:  # noqa: ARG001 -- signal handler signature
    wipe_now()
    raise SystemExit(128 + int(signum))  # unwinds the app's finally blocks


def install_signal_handlers() -> Callable[[], None]:
    """Wipe the clipboard when the process is told to stop, then exit cleanly.

    Main thread only (elsewhere this is a no-op). Returns a function that puts
    the previous handlers back.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous = {}
    for sig in _exit_signals():
        try:
            previous[sig] = signal.signal(sig, _on_exit_signal)
        except (ValueError, OSError):
            continue

    def restore() -> None:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler if handler is not None else signal.SIG_DFL)
            except (ValueError, OSError):
                pass
    return restore
