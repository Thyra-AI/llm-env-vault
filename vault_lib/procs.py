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
import time
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


class RunResult:
    """What run_bound hands back: the pieces of subprocess.CompletedProcess
    run_with_env uses, plus whether the child was bound to this server's
    lifetime and whether it was killed on timeout."""
    __slots__ = ("returncode", "stdout", "stderr", "timed_out", "binding")

    def __init__(self, returncode, stdout, stderr, timed_out, binding):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.binding = binding


def _windows_job():
    """A Job object whose closing kills everything still in it. Returns
    (job_handle, assign_fn) or (None, None) if jobs are unavailable."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD)
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None, None, None
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                            ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        return None, None, None

    def assign(process_handle) -> bool:
        return bool(kernel32.AssignProcessToJobObject(job, process_handle))

    def terminate() -> None:
        kernel32.TerminateJobObject(job, 1)

    def close() -> None:
        kernel32.CloseHandle(job)

    return assign, terminate, close


def run_bound(argv, env, cwd, timeout: Optional[float]) -> RunResult:
    """subprocess.run(capture_output=True, text=True, stdin=DEVNULL) with the
    child bound to this server's lifetime.

    Windows: the child goes into a Job object with KILL_ON_JOB_CLOSE, so if
    this server dies -- TerminateProcess from the MCP host is how every
    Windows session ends -- the kernel closes the job handle and takes the
    whole process tree with it. That is what makes a swap recovery's
    inference "the owner is dead, rewrite the file" safe: a dead owner now
    implies a dead command, not an orphan still reading the file. On
    timeout the job is terminated (children included) BEFORE the caller's
    restore runs, so no orphan can hold .env open against os.replace. On
    normal exit the job is closed, which also ends any descendant the
    command left behind -- a foreground command's children do not outlive
    it (documented).

    POSIX: the child starts its own session; timeout and interrupt kill the
    whole process group. There is no kill-on-parent-death primitive in the
    stdlib, so a dead server can leave the group running there.

    The Job assignment happens right after Popen returns rather than on a
    suspended process (Popen does not expose the thread handle). A child
    that spawns a grandchild in that first millisecond escapes the job; the
    result's `binding` says "job" only when assignment succeeded, and
    "unavailable" (with the run proceeding unbound) when Windows refused it.
    """
    import subprocess

    # errors="replace": a child printing cp1252-hostile bytes must not turn
    # the whole run into a UnicodeDecodeError after the work is done.
    kwargs = dict(env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    terminate = close = None
    binding = "none"
    if sys.platform == "win32":
        try:
            assign, terminate, close = _windows_job()
        except Exception:  # noqa: BLE001 -- never let ctypes trouble block a run
            assign = None
        proc = subprocess.Popen(argv, **kwargs)
        if assign is not None:
            try:
                binding = "job" if assign(int(proc._handle)) else "unavailable"
            except Exception:  # noqa: BLE001
                binding = "unavailable"
        else:
            binding = "unavailable"
    else:
        proc = subprocess.Popen(argv, start_new_session=True, **kwargs)
        binding = "session"

    def _kill_tree() -> None:
        if terminate is not None:
            terminate()
        elif sys.platform != "win32":
            import signal
            # poll() first: once the leader is reaped its pgid could be
            # reused, and killpg would then hit an unrelated group.
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        try:
            proc.kill()
        except OSError:
            pass

    # communicate() returns only when the LAST holder of the output pipes
    # closes them. A descendant the command left behind (a dev server
    # started by an npm script) inherits those pipes, so without help the
    # tool would block until it exits -- with real values on disk the whole
    # time. The watchdog waits for the direct child, gives its descendants
    # a short grace to finish flushing, then ends the tree. It must not
    # drain the pipes itself: only communicate() may, or a chatty child
    # deadlocks on a full buffer.
    import threading

    def _watchdog() -> None:
        try:
            proc.wait()
        except Exception:  # noqa: BLE001
            return
        time.sleep(_DESCENDANT_GRACE_SECONDS)
        _kill_tree()

    threading.Thread(target=_watchdog, daemon=True).start()
    timed_out = False
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree()
            stdout, stderr = proc.communicate()
        except BaseException:
            _kill_tree()
            raise
    finally:
        if close is not None:
            close()
    return RunResult(None if timed_out else proc.returncode, stdout, stderr, timed_out, binding)


# How long a foreground command's descendants may outlive it before the
# tree is ended. Long enough for a wrapper's child to flush and exit on its
# own; short enough that a daemon holding the output pipe cannot hold the
# tool -- and the real values -- hostage.
_DESCENDANT_GRACE_SECONDS = 2.0


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
