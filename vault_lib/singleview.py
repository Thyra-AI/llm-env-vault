"""Single-view real values: revert the file as soon as the command has read it.

run_with_env(max_reads=N) shortens the window in which a swapped .env (or a
materialized file) holds real values from "until the command exits" to
"until the command's process tree has opened and closed the file N
times". A dotenv loader reads once at startup; after that the file goes
back to placeholders while the command keeps running with the values it
already loaded. This is Doppler's `--mount-max-reads 1`, built from what a
user-mode process on Windows has: oplocks and the Restart Manager.

How it works (every step verified by spike on this project's own machine):

  1. We hold ONE handle to the file for the whole run: GENERIC_READ|WRITE,
     share mode 0, FILE_FLAG_OVERLAPPED. Real values are written THROUGH it
     (a write by the oplock owner does not break its own RWH oplock), so
     "armed" and "real values on disk" are never two separate moments -- if
     the arm fails, nothing was exposed yet.
  2. We request a Read+Write+Handle oplock on that handle. Any other
     process's open would normally fail with a sharing violation; with the
     H oplock held the filesystem instead BREAKS our oplock (our pending
     DeviceIoControl completes) and holds their open until we close. So a
     break means "someone is opening the file". Attribute-only opens
     (os.stat, os.path.exists) do not conflict and do not break.
  3. On a break we close our handle -- their open proceeds, they read the
     real content -- and immediately loop on re-opening exclusively: it
     fails with ERROR_SHARING_VIOLATION while their handle is open and
     succeeds the instant it closes. That success IS the re-arm: we request
     the oplock again on the new handle at once, so the file is unwatched
     for microseconds, not milliseconds.
  4. Attribution: while the re-open is failing, the Restart Manager can name
     the holders (RmGetList, ~300 ms). A holder inside the command's Job
     object counts as the command's read. Named holders outside the job
     (an editor, an indexer, an antivirus deep scan) are foreign: reported,
     not counted, and the watch re-arms. A reader that opened and closed
     before anyone could look -- every dotenv loader, in practice -- cannot
     be attributed; it is counted IF the job has a live process at that
     moment, and labelled "unattributed". That default is deliberate:
     refusing to count fast readers would make the feature dead for
     exactly the loaders it exists for, and the failure it risks -- an
     early restore the command notices, reported in the result -- is a
     correctness failure the user sees, never a leak.
  5. When the count reaches N we restore through the handle we hold: read
     the current bytes, compute the placeholders with the same value-based
     logic the normal restore uses, write, truncate, flush, release the
     journal entry. Nobody else can hold the file at that moment (our open
     was exclusive), so the write cannot collide with a sharing violation.
     A memory-mapped view makes SetEndOfFile fail (ERROR_USER_MAPPED_FILE);
     then the bytes are overwritten in place, padded to the old length, and
     the exact restore is retried when the command exits.
  6. After the restore the watch stays armed in observe-only mode, so a
     read that arrives after the file has reverted -- the command asking a
     second time -- is reported as reads_after_restore instead of being
     invisible.

Windows only. There is no way to observe file opens from user mode on
macOS without an Endpoint Security entitlement, and Linux's answer
(fanotify FAN_OPEN, which names the opener) is a separate piece of work;
both platforms refuse max_reads before the dialog with a plain message.

What this is not: a security boundary against the agent. A concurrent
same-user reader (an agent's own Bash loop) is held, reads, and is
counted as an unattributed read. The result says so.
"""
import ctypes
import os
import sys
import threading
import time
from typing import Callable, Optional

from . import store

# --------------------------------------------------------------------------- Win32
if sys.platform == "win32":
    from ctypes import wintypes as wt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    try:
        _rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)
    except OSError:  # pragma: no cover -- not on any supported Windows
        _rstrtmgr = None

    GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
    OPEN_EXISTING, CREATE_NEW = 3, 1
    FILE_FLAG_OVERLAPPED = 0x40000000
    FILE_ATTRIBUTE_NORMAL = 0x80
    FSCTL_REQUEST_OPLOCK = 0x00090240
    OPLOCK_LEVEL_CACHE_READ, OPLOCK_LEVEL_CACHE_HANDLE, OPLOCK_LEVEL_CACHE_WRITE = 1, 2, 4
    REQUEST_OPLOCK_INPUT_FLAG_REQUEST = 1
    ERROR_IO_PENDING, ERROR_SHARING_VIOLATION, ERROR_FILE_NOT_FOUND = 997, 32, 2
    ERROR_USER_MAPPED_FILE, ERROR_ACCESS_DENIED = 1224, 5
    INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
    WAIT_OBJECT_0, WAIT_TIMEOUT = 0, 258
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    JobObjectBasicAccountingInformation = 1

    class _REQUEST_OPLOCK_INPUT_BUFFER(ctypes.Structure):
        _fields_ = [("StructureVersion", wt.WORD), ("StructureLength", wt.WORD),
                    ("RequestedOplockLevel", wt.DWORD), ("Flags", wt.DWORD)]

    class _REQUEST_OPLOCK_OUTPUT_BUFFER(ctypes.Structure):
        _fields_ = [("StructureVersion", wt.WORD), ("StructureLength", wt.WORD),
                    ("OriginalOplockLevel", wt.DWORD), ("NewOplockLevel", wt.DWORD),
                    ("Flags", wt.DWORD), ("AccessMode", wt.DWORD), ("ShareMode", wt.WORD)]

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD), ("hEvent", wt.HANDLE)]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wt.DWORD), ("TotalProcesses", wt.DWORD),
                    ("ActiveProcesses", wt.DWORD), ("TotalTerminatedProcesses", wt.DWORD)]

    _CCH_RM_MAX_APP_NAME, _CCH_RM_MAX_SVC_NAME, _CCH_RM_SESSION_KEY = 255, 63, 32
    _ERROR_MORE_DATA = 234

    class _RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [("dwProcessId", wt.DWORD), ("ProcessStartTime", wt.FILETIME)]

    class _RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [("Process", _RM_UNIQUE_PROCESS),
                    ("strAppName", wt.WCHAR * (_CCH_RM_MAX_APP_NAME + 1)),
                    ("strServiceShortName", wt.WCHAR * (_CCH_RM_MAX_SVC_NAME + 1)),
                    ("ApplicationType", wt.DWORD), ("AppStatus", wt.DWORD),
                    ("TSSessionId", wt.DWORD), ("bRestartable", wt.BOOL)]

    for _fn, _res, _args in (
        ("CreateFileW", wt.HANDLE, (wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                    wt.DWORD, wt.HANDLE)),
        ("DeviceIoControl", wt.BOOL, (wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                      ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                      ctypes.POINTER(_OVERLAPPED))),
        ("CreateEventW", wt.HANDLE, (ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR)),
        ("SetEvent", wt.BOOL, (wt.HANDLE,)),
        ("WaitForMultipleObjects", wt.DWORD, (wt.DWORD, ctypes.POINTER(wt.HANDLE), wt.BOOL,
                                              wt.DWORD)),
        ("WaitForSingleObject", wt.DWORD, (wt.HANDLE, wt.DWORD)),
        ("CloseHandle", wt.BOOL, (wt.HANDLE,)),
        ("WriteFile", wt.BOOL, (wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                ctypes.POINTER(_OVERLAPPED))),
        ("ReadFile", wt.BOOL, (wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                               ctypes.POINTER(_OVERLAPPED))),
        ("GetFileSizeEx", wt.BOOL, (wt.HANDLE, ctypes.POINTER(ctypes.c_longlong))),
        ("SetFilePointerEx", wt.BOOL, (wt.HANDLE, ctypes.c_longlong, ctypes.c_void_p, wt.DWORD)),
        ("SetEndOfFile", wt.BOOL, (wt.HANDLE,)),
        ("FlushFileBuffers", wt.BOOL, (wt.HANDLE,)),
        ("GetOverlappedResult", wt.BOOL, (wt.HANDLE, ctypes.POINTER(_OVERLAPPED),
                                          ctypes.POINTER(wt.DWORD), wt.BOOL)),
        ("IsProcessInJob", wt.BOOL, (wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.BOOL))),
        ("OpenProcess", wt.HANDLE, (wt.DWORD, wt.BOOL, wt.DWORD)),
        ("QueryInformationJobObject", wt.BOOL, (wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                wt.DWORD, ctypes.POINTER(wt.DWORD))),
    ):
        _f = getattr(_k32, _fn)
        _f.restype, _f.argtypes = _res, _args

    if _rstrtmgr is not None:
        _rstrtmgr.RmStartSession.argtypes = (ctypes.POINTER(wt.DWORD), wt.DWORD, wt.LPWSTR)
        _rstrtmgr.RmRegisterResources.argtypes = (wt.DWORD, wt.UINT, ctypes.POINTER(wt.LPCWSTR),
                                                  wt.UINT, ctypes.c_void_p, wt.UINT,
                                                  ctypes.c_void_p)
        _rstrtmgr.RmGetList.argtypes = (wt.DWORD, ctypes.POINTER(wt.UINT), ctypes.POINTER(wt.UINT),
                                        ctypes.c_void_p, ctypes.POINTER(wt.DWORD))
        _rstrtmgr.RmEndSession.argtypes = (wt.DWORD,)


def unsupported_reason() -> Optional[str]:
    """None when max_reads can work here; otherwise the sentence the caller
    shows before any dialog opens."""
    if sys.platform != "win32":
        return ("max_reads needs the operating system to report file opens to a user-mode "
                "process; that exists on Windows (oplocks). Linux support (fanotify) is not "
                "implemented yet and macOS has no such facility without an Endpoint Security "
                "entitlement.")
    if _rstrtmgr is None:
        return "max_reads needs the Restart Manager (rstrtmgr.dll), which this Windows lacks."
    return None


def holders(path: str) -> list:
    """Processes holding `path` open, as [(pid, app_name, start_filetime)],
    via the Restart Manager. Read-only: only Start/Register/GetList/End are
    ever called -- nothing here can shut down or restart anything."""
    if sys.platform != "win32" or _rstrtmgr is None:
        return []
    session = wt.DWORD()
    key = ctypes.create_unicode_buffer(_CCH_RM_SESSION_KEY + 1)
    if _rstrtmgr.RmStartSession(ctypes.byref(session), 0, key) != 0:
        return []
    try:
        files = (wt.LPCWSTR * 1)(path)
        if _rstrtmgr.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
            return []
        needed, got, reason = wt.UINT(0), wt.UINT(0), wt.DWORD()
        rc = _rstrtmgr.RmGetList(session, ctypes.byref(needed), ctypes.byref(got), None,
                                 ctypes.byref(reason))
        if rc not in (0, _ERROR_MORE_DATA) or needed.value == 0:
            return []
        arr = (_RM_PROCESS_INFO * needed.value)()
        got = wt.UINT(needed.value)
        if _rstrtmgr.RmGetList(session, ctypes.byref(needed), ctypes.byref(got), arr,
                               ctypes.byref(reason)) != 0:
            return []
        out = []
        for i in range(got.value):
            ft = arr[i].Process.ProcessStartTime
            out.append((int(arr[i].Process.dwProcessId), str(arr[i].strAppName),
                        (ft.dwHighDateTime << 32) | ft.dwLowDateTime))
        return out
    finally:
        _rstrtmgr.RmEndSession(session)


def pid_in_job(pid: int, job_handle) -> Optional[bool]:
    """True/False, or None when the process cannot be opened at all."""
    if sys.platform != "win32" or not job_handle:
        return None
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        inside = wt.BOOL()
        if not _k32.IsProcessInJob(h, job_handle, ctypes.byref(inside)):
            return None
        return bool(inside.value)
    finally:
        _k32.CloseHandle(h)


def job_active_processes(job_handle) -> int:
    if sys.platform != "win32" or not job_handle:
        return 0
    info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    if not _k32.QueryInformationJobObject(job_handle, JobObjectBasicAccountingInformation,
                                          ctypes.byref(info), ctypes.sizeof(info), None):
        return 0
    return int(info.ActiveProcesses)


# --------------------------------------------------------------------- the watcher
# How long the arm sits before the command starts, waiting for an editor,
# indexer or sync client to react to the write. A break in this window has
# no command to attribute to, so it is foreign by construction.
SETTLE_SECONDS = 0.15
SETTLE_MAX_SECONDS = 0.5
# Poll interval while waiting for a reader to close; measured re-arm
# latency is ~10 ms at this setting.
_REOPEN_POLL_SECONDS = 0.005


class Watcher:
    """One swapped or materialized file under single-view control.

    Life cycle, driven by run_with_env:
        w = Watcher(path, max_reads, on_restore)   # on_restore(handle_io) writes placeholders
        w.open(create=False)                       # exclusive handle; nothing written yet
        raw = w.read_all(); w.write_all(new_bytes) # real values, through the handle
        w.arm(); w.settle()                        # oplock up; editors' reactions absorbed
        ... Popen ...; w.set_job(job_handle)
        w.start()                                  # thread: breaks -> attribution -> restore
        ... command runs ...
        w.stop(); w.join()                         # releases the handle; restore if not yet
        w.report()

    `on_restore` receives this watcher (for read_all/write_all through the
    held handle) and returns the restore result dict; it runs on the
    watcher thread under the run's restore lock, exactly once.
    """

    def __init__(self, path, max_reads: int, on_restore: Callable, restore_lock: threading.Lock,
                 deadline: Optional[float] = None):
        self.path = str(path)
        self.max_reads = max_reads
        self.on_restore = on_restore
        self.lock = restore_lock
        self.deadline = deadline
        self.handle = None
        self._ov = None
        self._resp = None
        self._req = None
        self._stop = _k32.CreateEventW(None, True, False, None) if sys.platform == "win32" else None
        self._thread = None
        self._job = None
        self.reads = []          # [{"at", "attribution", "holders"}]
        self.foreign_opens = []  # [{"at", "apps"}]
        self.reads_after_restore = 0
        self.restored_early = False
        self.restore_result = None
        self.watch_gaps = []     # [(start, end)] seconds with no oplock armed
        self.missing = False
        self.error = None
        self.mapped_tail_pending = False

    # ----------------------------------------------------------- handle I/O
    def open(self, create: bool = False) -> None:
        disposition = CREATE_NEW if create else OPEN_EXISTING
        h = _k32.CreateFileW(self.path, GENERIC_READ | GENERIC_WRITE, 0, None, disposition,
                             FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, None)
        if h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise OSError(err, f"could not open {self.path} exclusively (Win32 error {err})")
        self.handle = h

    def _try_open(self) -> int:
        """0 on success (handle set), else the Win32 error."""
        h = _k32.CreateFileW(self.path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, None)
        if h == INVALID_HANDLE_VALUE:
            return ctypes.get_last_error()
        self.handle = h
        return 0

    def read_all(self) -> bytes:
        size = ctypes.c_longlong()
        if not _k32.GetFileSizeEx(self.handle, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "GetFileSizeEx")
        n = int(size.value)
        if n > store._MAX_ENV_BYTES:
            raise ValueError(f"{self.path} is {n} bytes -- larger than any .env this tool will "
                             f"parse")
        buf = ctypes.create_string_buffer(n or 1)
        got = wt.DWORD()
        ov = _OVERLAPPED()
        ov.hEvent = _k32.CreateEventW(None, True, False, None)
        try:
            ok = _k32.ReadFile(self.handle, buf, n, ctypes.byref(got), ctypes.byref(ov))
            if not ok:
                if ctypes.get_last_error() != ERROR_IO_PENDING:
                    raise OSError(ctypes.get_last_error(), "ReadFile")
                if not _k32.GetOverlappedResult(self.handle, ctypes.byref(ov), ctypes.byref(got),
                                                True):
                    raise OSError(ctypes.get_last_error(), "ReadFile (overlapped)")
        finally:
            _k32.CloseHandle(ov.hEvent)
        return buf.raw[:got.value]

    def write_all(self, data: bytes) -> None:
        """Overwrite the file through the held handle: write at offset 0,
        truncate to the new length, flush. On ERROR_USER_MAPPED_FILE the
        truncate is impossible (a reader still has a view mapped); the
        remainder is padded with newlines so no byte of the old content
        survives, and the exact-length restore is retried by the caller's
        normal end-of-run path."""
        got = wt.DWORD()
        ov = _OVERLAPPED()
        ov.hEvent = _k32.CreateEventW(None, True, False, None)
        try:
            ok = _k32.WriteFile(self.handle, data, len(data), ctypes.byref(got), ctypes.byref(ov))
            if not ok:
                if ctypes.get_last_error() != ERROR_IO_PENDING:
                    raise OSError(ctypes.get_last_error(), "WriteFile")
                if not _k32.GetOverlappedResult(self.handle, ctypes.byref(ov), ctypes.byref(got),
                                                True):
                    raise OSError(ctypes.get_last_error(), "WriteFile (overlapped)")
            if got.value != len(data):
                # A short write would leave the old bytes -- on the restore
                # path, the real value -- between the written prefix and the
                # truncation point. Refuse to pretend it succeeded.
                raise OSError(0, f"short write: {got.value} of {len(data)} bytes")
        finally:
            _k32.CloseHandle(ov.hEvent)
        if not _k32.SetFilePointerEx(self.handle, len(data), None, 0):
            raise OSError(ctypes.get_last_error(), "SetFilePointerEx")
        if not _k32.SetEndOfFile(self.handle):
            err = ctypes.get_last_error()
            if err != ERROR_USER_MAPPED_FILE:
                raise OSError(err, "SetEndOfFile")
            size = ctypes.c_longlong()
            _k32.GetFileSizeEx(self.handle, ctypes.byref(size))
            tail = int(size.value) - len(data)
            if tail > 0:
                pad = b"\n" * tail
                ov2 = _OVERLAPPED()
                ov2.Offset = len(data) & 0xFFFFFFFF
                ov2.OffsetHigh = len(data) >> 32
                ov2.hEvent = _k32.CreateEventW(None, True, False, None)
                try:
                    ok = _k32.WriteFile(self.handle, pad, len(pad), ctypes.byref(got),
                                        ctypes.byref(ov2))
                    if not ok and ctypes.get_last_error() == ERROR_IO_PENDING:
                        _k32.GetOverlappedResult(self.handle, ctypes.byref(ov2),
                                                 ctypes.byref(got), True)
                finally:
                    _k32.CloseHandle(ov2.hEvent)
            self.mapped_tail_pending = True
        _k32.FlushFileBuffers(self.handle)

    def close(self) -> None:
        """Release the handle -- and, if an oplock request is pending,
        drain its IRP first, or the OVERLAPPED buffer the kernel still
        references goes out of scope while it is in flight."""
        if self.handle is None:
            return
        h, self.handle = self.handle, None
        _k32.CloseHandle(h)
        if self._ov is not None:
            # Closing the handle releases the oplock, which completes the
            # pending FSCTL and signals its event. Wait for that signal
            # before dropping the OVERLAPPED the kernel is still writing to;
            # GetOverlappedResult on the closed handle would not wait.
            _k32.WaitForSingleObject(self._ov.hEvent, 5000)
            _k32.CloseHandle(self._ov.hEvent)
            self._ov = None

    # ------------------------------------------------------------- oplock
    def arm(self) -> None:
        self._req = _REQUEST_OPLOCK_INPUT_BUFFER(
            1, ctypes.sizeof(_REQUEST_OPLOCK_INPUT_BUFFER),
            OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE,
            REQUEST_OPLOCK_INPUT_FLAG_REQUEST)
        self._resp = _REQUEST_OPLOCK_OUTPUT_BUFFER()
        self._ov = _OVERLAPPED()
        self._ov.hEvent = _k32.CreateEventW(None, True, False, None)
        ret = wt.DWORD()
        ok = _k32.DeviceIoControl(self.handle, FSCTL_REQUEST_OPLOCK, ctypes.byref(self._req),
                                  ctypes.sizeof(self._req), ctypes.byref(self._resp),
                                  ctypes.sizeof(self._resp), ctypes.byref(ret),
                                  ctypes.byref(self._ov))
        err = ctypes.get_last_error()
        if ok or err != ERROR_IO_PENDING:
            _k32.CloseHandle(self._ov.hEvent)
            self._ov = None
            raise OSError(err, f"oplock not granted on {self.path} (Win32 error {err})")

    def _wait_break(self, timeout_ms: int) -> str:
        """'break', 'stop' or 'timeout'."""
        handles = (wt.HANDLE * 2)(self._ov.hEvent, self._stop)
        r = _k32.WaitForMultipleObjects(2, handles, False, timeout_ms)
        if r == WAIT_OBJECT_0:
            return "break"
        if r == WAIT_OBJECT_0 + 1:
            return "stop"
        return "timeout"

    def settle(self) -> None:
        """Absorb reactions to the write before the command exists: an
        editor tab reloading, an IDE's VFS refresh, an indexer. Each break
        here is foreign by construction (no job yet); re-arm and keep
        waiting until a quiet interval passes or the cap is reached."""
        started = time.monotonic()
        while True:
            outcome = self._wait_break(int(SETTLE_SECONDS * 1000))
            if outcome != "break":
                return
            self.foreign_opens.append({"at": time.time(), "apps": [], "phase": "settle"})
            self.close()
            self._reacquire(record_holders=False)
            if self.handle is None:
                return
            self.arm()
            if time.monotonic() - started > SETTLE_MAX_SECONDS:
                return

    def _reacquire(self, record_holders: bool) -> Optional[list]:
        """After a break: loop on the exclusive re-open until the reader has
        closed (or the deadline passes). Returns the holders the Restart
        Manager saw while the open was failing (None if it never failed --
        the reader was already gone)."""
        gap_start = time.monotonic()
        seen_holders = None
        # The opener whose CreateFile broke our oplock is still inside the
        # kernel, waiting for our close to finish. Reopening exclusively in
        # the same instant can win that race -- and then THEY get the
        # sharing violation, their read fails, and the feature has turned a
        # loader's open into an error. One poll interval is enough for the
        # pending open to complete; the file is unwatched for those 5 ms.
        time.sleep(_REOPEN_POLL_SECONDS)
        while True:
            err = self._try_open()
            if err == 0:
                return seen_holders
            if err == ERROR_FILE_NOT_FOUND:
                self.missing = True
                self.watch_gaps.append((gap_start, time.monotonic()))
                return seen_holders
            if err != ERROR_SHARING_VIOLATION:
                self.error = f"could not re-open {self.path}: Win32 error {err}"
                self.watch_gaps.append((gap_start, time.monotonic()))
                return seen_holders
            if seen_holders is None and record_holders:
                seen_holders = holders(self.path)
            if _k32.WaitForSingleObject(self._stop, 0) == WAIT_OBJECT_0 or \
                    (self.deadline is not None and time.time() > self.deadline):
                self.watch_gaps.append((gap_start, time.monotonic()))
                return seen_holders
            time.sleep(_REOPEN_POLL_SECONDS)

    # ------------------------------------------------------------- thread
    def set_job(self, job_handle) -> None:
        self._job = job_handle

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="single-view")
        self._thread.start()

    def stop(self) -> None:
        if self._stop is not None:
            _k32.SetEvent(self._stop)

    def join(self, timeout: float) -> bool:
        """True once the watcher thread is gone -- and only then may another
        thread touch the handle. A watcher that is still alive after the
        join owns the handle and will close it in its own finally."""
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        try:
            remaining = self.max_reads
            while True:
                outcome = self._wait_break(1000)
                if outcome == "stop":
                    return
                if outcome == "timeout":
                    continue
                broke_at = time.time()
                self.close()
                seen = self._reacquire(record_holders=True)
                if self.handle is None:
                    if not self.missing and not self.error:
                        # Stopped while a break was in flight: the command
                        # read and exited in the same breath (its last act).
                        # The open happened; tally it so the report is
                        # truthful, even though nobody can be named now.
                        if self.restored_early:
                            self.reads_after_restore += 1
                        else:
                            self.reads.append({"at": broke_at,
                                               "attribution": "unattributed-at-exit",
                                               "holders": []})
                    return  # missing, unrecoverable, or stopped; reported
                counted, attribution, apps = self._attribute(seen)
                if counted:
                    if self.restored_early:
                        self.reads_after_restore += 1
                    else:
                        remaining -= 1
                        self.reads.append({"at": broke_at, "attribution": attribution,
                                           "holders": apps})
                else:
                    self.foreign_opens.append({"at": broke_at, "apps": apps, "phase": "run"})
                if remaining == 0 and not self.restored_early:
                    with self.lock:
                        if self.restore_result is None:
                            try:
                                self.restore_result = self.on_restore(self)
                            except Exception as e:  # noqa: BLE001 -- must keep watching
                                self.restore_result = {"error": f"{type(e).__name__}: {e}"}
                            self.restored_early = self.restore_result.get("error") is None
                if _k32.WaitForSingleObject(self._stop, 0) == WAIT_OBJECT_0:
                    return
                self.arm()
        except Exception as e:  # noqa: BLE001 -- the thread must never die holding the handle
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.close()

    def _attribute(self, seen: Optional[list]) -> tuple:
        """(counted, attribution, app_names) for one break."""
        own = os.getpid()
        if seen:
            named = [(pid, app) for pid, app, _st in seen if pid != own]
            in_job = [app for pid, app in named if pid_in_job(pid, self._job) is True]
            if in_job:
                return True, "job", sorted(set(in_job))
            if named:
                return False, "foreign", sorted({app for _pid, app in named})
        # Nobody could be named: the reader opened and closed before the
        # Restart Manager could look (every dotenv loader). Count it if the
        # command is running, labelled so the user can tell.
        if self._job is not None and job_active_processes(self._job) > 0:
            return True, "unattributed", []
        return False, "foreign-unattributed", []

    def report(self) -> dict:
        out = {
            "max_reads": self.max_reads,
            "reads": len(self.reads),
            "attribution": [r["attribution"] for r in self.reads],
            "restored_early": self.restored_early,
            "reads_after_restore": self.reads_after_restore,
        }
        apps = sorted({a for f in self.foreign_opens for a in f["apps"]})
        if self.foreign_opens:
            out["foreign_opens"] = len(self.foreign_opens)
            out["foreign_apps"] = apps
        if self.watch_gaps:
            out["watch_gap_seconds"] = round(sum(e - s for s, e in self.watch_gaps), 3)
        if self.missing:
            out["file_disappeared"] = True
        if self.error:
            out["error"] = self.error
        if self.mapped_tail_pending:
            out["mapped_view_tail_padded"] = True
        return out


def self_test(path: str, timeout: float = 3.0) -> Optional[str]:
    """Prove, on this very file, that an oplock is granted with handle
    caching and that a foreign open is HELD until we release -- the two
    properties the feature rests on. Returns None on success or the reason
    to refuse. Runs before the dialog, on the placeholder file, touching
    nothing."""
    if unsupported_reason():
        return unsupported_reason()
    w = Watcher(path, 1, lambda _w: {}, threading.Lock())
    try:
        try:
            w.open()
        except OSError as e:
            return f"{path} could not be opened exclusively (another process holds it): {e}"
        try:
            w.arm()
        except OSError as e:
            return f"this filesystem did not grant an oplock on {path}: {e}"
        result = {"opened_at": None}

        def opener():
            try:
                with open(path, "rb"):
                    result["opened_at"] = time.monotonic()
            except OSError as e:
                result["error"] = str(e)

        t = threading.Thread(target=opener, daemon=True)
        t0 = time.monotonic()
        t.start()
        if w._wait_break(int(timeout * 1000)) != "break":
            return f"a test open of {path} did not break the oplock -- opens are not observable"
        time.sleep(0.2)
        if result["opened_at"] is not None or "error" in result:
            return (f"a test open of {path} was not held while the oplock was pending "
                    f"(handle caching not granted) -- opens could not be counted reliably")
        w.close()
        t.join(timeout)
        if result["opened_at"] is None:
            return f"a test open of {path} did not complete after release"
        return None
    finally:
        w.close()
