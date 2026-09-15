"""Process liveness for the swap journal.

The swap journal (see store.py) records which server process currently has
real values written into a project's .env. Deciding whether that process is
still alive is what separates "another chat is mid-run, leave the file
alone" from "that server died, restore the placeholders now". A wrong
answer in either direction is bad: recovering a live swap clobbers a file
another process is about to restore itself (and hands its hot-reloader
placeholders mid-run); trusting a dead one leaves real values on disk.

A bare pid is not enough for that decision. Windows recycles pids
aggressively, so a stale entry's pid can belong to an unrelated process
within minutes -- and a restarted server can even be handed its dead
predecessor's pid, which would make it treat that predecessor's abandoned
swap as its own live one forever. So every journal entry carries the pid
AND the process creation time, and liveness means "a process with that pid
exists and was started at that moment". A per-process random server id
covers the remaining case (same pid, creation time unavailable).

Everything here is best-effort and stdlib-only. When the platform cannot
report a creation time, liveness degrades to "pid exists", which is the
conservative direction: it can delay a recovery, never cause a clobber.
"""
import os
import sys
from typing import Optional

# Two processes are "the same" if their recorded start times agree within
# this many seconds. FILETIME is 100 ns resolution and /proc is in clock
# ticks, so a small tolerance absorbs the conversion noise without letting
# a pid reused minutes later slip through.
_START_TOLERANCE = 2.0


def _windows_start_time(pid: int) -> tuple:
    """Returns (exists, start_time_or_None).

    OpenProcess with the least privilege that still answers "does it
    exist". ERROR_ACCESS_DENIED means a process with that pid exists but
    is not ours to inspect (a different user's, or protected) -- that is
    "alive, start time unknown", not "dead". ERROR_INVALID_PARAMETER is the
    documented answer for a pid that is not in use.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Explicit signatures: without them a 64-bit HANDLE is truncated to a C
    # int on the way back, and CloseHandle later gets a mangled value.
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    ERROR_ACCESS_DENIED = 5
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED, None
    try:
        # A pid can be opened for a short while after the process exits
        # (handles keep the object alive). Exit code STILL_ACTIVE (259)
        # distinguishes "running" from "zombie handle".
        exit_code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) and \
                exit_code.value != 259:
            return False, None
        creation = wintypes.FILETIME()
        exit_t = wintypes.FILETIME()
        kernel_t = wintypes.FILETIME()
        user_t = wintypes.FILETIME()
        ok = kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_t),
                                      ctypes.byref(kernel_t), ctypes.byref(user_t))
        if not ok:
            return True, None
        # FILETIME: 100 ns intervals since 1601-01-01. Unix epoch offset is
        # 116444736000000000 of those intervals.
        ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return True, (ticks - 116444736000000000) / 10_000_000
    finally:
        kernel32.CloseHandle(handle)


def _posix_start_time(pid: int) -> tuple:
    """Returns (exists, start_time_or_None) using kill(0) and, on Linux,
    /proc/<pid>/stat field 22 (starttime in clock ticks since boot) plus
    /proc/stat's btime. Elsewhere on POSIX the start time is None."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False, None
    except PermissionError:
        pass  # exists, not ours
    except OSError:
        return True, None
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
            stat = f.read()
        # The comm field is in parentheses and may contain spaces; split
        # after the last ')' so field numbering is stable.
        fields = stat[stat.rindex(")") + 2:].split()
        start_ticks = int(fields[19])  # field 22 overall, index 19 after comm
        with open("/proc/stat", "r", encoding="utf-8", errors="replace") as f:
            btime = None
            for line in f:
                if line.startswith("btime "):
                    btime = int(line.split()[1])
                    break
        if btime is None:
            return True, None
        hz = os.sysconf("SC_CLK_TCK")
        return True, btime + start_ticks / hz
    except (OSError, ValueError, IndexError, AttributeError):
        return True, None


def process_start_time(pid: int) -> tuple:
    """(exists, start_time) for any pid. start_time is a Unix timestamp or
    None when the platform can't say."""
    try:
        if sys.platform == "win32":
            return _windows_start_time(pid)
        return _posix_start_time(pid)
    except Exception:  # noqa: BLE001 -- ctypes/proc oddities must never crash recovery
        return True, None


def own_start_time() -> Optional[float]:
    return process_start_time(os.getpid())[1]


def pid_alive(pid: int, recorded_start: Optional[float]) -> bool:
    """True if a process with `pid` exists AND, when both sides know a start
    time, it is the same process that recorded `recorded_start`.

    Unknown on either side degrades to "exists", deliberately: a delayed
    recovery costs minutes of exposure that the journal will still catch
    later; a false "dead" costs a live run its file.
    """
    exists, current_start = process_start_time(pid)
    if not exists:
        return False
    if recorded_start is None or current_start is None:
        return True
    return abs(current_start - recorded_start) <= _START_TOLERANCE
