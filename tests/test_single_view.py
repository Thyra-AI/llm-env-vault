"""
1.7.0 single-view: run_with_env(max_reads=N) reverts the real values as soon
as the command has read them, not when it exits.

Every test here runs a REAL child process, in a REAL Job object, against a
REAL oplock on a real file -- there is no way to fake the kernel's answer to
"did someone open this file", and the whole feature is that answer. The
proof of the headline claim is the first test: the child reads the real
value, sleeps, reads again while still running, and gets the placeholder.

Windows only, like the feature. Runs under pytest or standalone.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from vault_lib import legacy_swap, procs, singleview, store, trust  # noqa: E402
from _vault_workspace import (INDEX, PLACEHOLDER_ENV, SECRETS, fake_dialog, stub_run,  # noqa: E402
                       workspace)

IS_WIN = sys.platform == "win32"
PYTHON = getattr(sys, "_base_executable", None) or sys.executable


def _skip(reason):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print(f"  SKIP: {reason}")
        return True


def _need_windows():
    if not IS_WIN:
        return _skip("single-view is Windows-only")


# Reads .env by line, prints the API_TOKEN line, sleeps, prints it again.
READ_TWICE = ("import sys,time\n"
              "def get():\n"
              "    for line in open('.env', encoding='utf-8'):\n"
              "        if line.startswith('export API_TOKEN='): return line.split('=',1)[1].strip()\n"
              "print(get(), flush=True)\n"
              "time.sleep(1.2)\n"
              "print(get(), flush=True)\n"
              "time.sleep(0.4)\n")










def test_materialize_with_max_reads_is_emptied_after_first_read() -> None:
    if _need_windows():
        return
    code = ("import time\n"
            "print(open('.env.runtime').read().strip(), flush=True)\n"
            "time.sleep(0.8)\n"
            "print(repr(open('.env.runtime').read()), flush=True)\n")
    with workspace() as (project, env_path):
        with fake_dialog():
            r = mcp_server._run_with_env_impl([PYTHON, "-c", code], ".env.runtime", False,
                                              str(project), ["PLAIN"], None, max_reads=1)
        lines = r["stdout"].splitlines()
        assert lines[0] == "PLAIN=[REDACTED:PLAIN]", lines
        assert lines[1] == "''", lines
        assert not (project / ".env.runtime").exists()
        assert r["single_read"][str(project / ".env.runtime")]["restored_early"] is True




def test_self_test_proves_holding_and_refuses_when_a_holder_exists() -> None:
    if _need_windows():
        return
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_bytes(b"A=1\n")
        assert singleview.self_test(str(p)) is None
        holder = subprocess.Popen([PYTHON, "-c",
                                   "import sys,time; f=open(sys.argv[1]); time.sleep(3)", str(p)])
        try:
            time.sleep(0.5)
            reason = singleview.self_test(str(p))
            assert reason and "exclusively" in reason, reason
        finally:
            holder.kill()
            holder.wait()






def test_short_write_is_refused() -> None:
    if _need_windows():
        return
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_bytes(b"A=1\n")
        w = singleview.Watcher(str(p), 1, lambda _w: {}, threading.Lock())
        w.open()
        try:
            # Which call reports the byte count depends on the storage stack.
            # A handle opened FILE_FLAG_OVERLAPPED may still complete the write
            # synchronously, and then WriteFile returns TRUE and fills the
            # count itself -- GetOverlappedResult is never reached. Patch both,
            # so the guard is exercised either way: patching only
            # GetOverlappedResult passes on a disk that goes async and silently
            # tests nothing on one that does not.
            real_wf = singleview._k32.WriteFile
            real_gor = singleview._k32.GetOverlappedResult
            shaved = {"n": 0}

            def shave(got):
                if hasattr(got, "_obj") and got._obj.value > 0:
                    got._obj.value -= 1
                    shaved["n"] += 1

            def short_wf(handle, buf, n, got, ov):
                ok = real_wf(handle, buf, n, got, ov)
                # Only a synchronous completion reports the count here; on the
                # pending path GetOverlappedResult overwrites it afterwards.
                if ok:
                    shave(got)
                return ok

            def short_gor(handle, ov, got, wait):
                ok = real_gor(handle, ov, got, wait)
                if ok:
                    shave(got)
                return ok

            singleview._k32.WriteFile = short_wf
            singleview._k32.GetOverlappedResult = short_gor
            try:
                try:
                    w.write_all(b"A=2\nB=3\n")
                except OSError as e:
                    assert "short write" in str(e)
                else:
                    raise AssertionError("a short write was accepted")
            finally:
                singleview._k32.WriteFile = real_wf
                singleview._k32.GetOverlappedResult = real_gor
            # Guard the guard: if neither patch fired, the branch above proved
            # nothing and the test would pass for the wrong reason.
            assert shaved["n"] == 1, f"byte count never shaved ({shaved['n']})"
        finally:
            w.close()


# Reads three times with pauses long enough for a restore between each.
READ_THRICE = ("import time\n"
               "def get():\n"
               "    for line in open('.env', encoding='utf-8'):\n"
               "        if line.startswith('export API_TOKEN='): return line.split('=',1)[1].strip()\n"
               "for i in range(3):\n"
               "    print(get(), flush=True)\n"
               "    time.sleep(0.9)\n")




def test_padded_tail_from_a_mapped_view_is_trimmed_after_release() -> None:
    """While a reader holds a memory-mapped view the truncate is refused
    (ERROR_USER_MAPPED_FILE); write_all pads with newlines so nothing of the
    old content survives, and once the handle is released the padding is
    cut so the file matches the write exactly."""
    if _need_windows():
        return
    import mmap
    import msvcrt
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_bytes(b"A=1\nB=22\n")
        w = singleview.Watcher(str(p), 1, lambda _w: {}, threading.Lock())
        w.open()
        # A view on our own handle: the only way to map a file nobody else
        # may open. Its CRT fd must not be closed -- it shares the handle.
        fd = msvcrt.open_osfhandle(w.handle, os.O_RDWR)
        view = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        try:
            w.write_all(b"A=1\n")
            assert w.mapped_tail_pending is True
            assert bytes(view[:]) == b"A=1\n" + b"\n" * 5  # no byte of B=22 survives
            assert w.trim_padded_tail() == "handle still held"
        finally:
            view.close()
            w.close()
        assert w.trim_padded_tail() is None
        assert p.read_bytes() == b"A=1\n"
        assert w.report().get("mapped_view_tail_trimmed") is True
        # A file someone changed after the padded write is left alone.
        w2 = singleview.Watcher(str(p), 1, lambda _w: {}, threading.Lock())
        w2.mapped_tail_pending, w2._last_written = True, b"A=1\n"
        p.write_bytes(b"A=1\n\nX=9\n")
        assert w2.trim_padded_tail() == "file changed since the padded write"
        assert p.read_bytes() == b"A=1\n\nX=9\n"
        assert w2.report().get("mapped_view_tail_error") == "file changed since the padded write"


def test_job_observer_is_told_before_the_job_handle_closes() -> None:
    """run_bound's on_start(None, pid) must arrive while the handle it hands
    out earlier is still valid, or a break processed meanwhile queries a
    closed (possibly recycled) handle."""
    if _need_windows():
        return
    import ctypes
    from ctypes import wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    seen = {}

    def on_start(job, pid):
        if job is not None:
            seen["job"] = job
        else:
            flags = wt.DWORD()
            seen["valid_at_close"] = bool(k32.GetHandleInformation(seen["job"],
                                                                   ctypes.byref(flags)))

    res = procs.run_bound([PYTHON, "-c", "print(1)"], dict(os.environ), None, 30,
                          on_start=on_start)
    assert res.returncode == 0
    assert seen.get("valid_at_close") is True, seen




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


# ---------------------------------------------------------------------------
# materialize + max_reads
# ---------------------------------------------------------------------------
# After swap= was retired in 2.0, materialize is the ONLY standing exception
# to "no file an agent can read holds a real value", and max_reads is its
# strongest mitigation -- a `docker run --env-file` reads once at client
# start, so an early revert cuts the window from the container's lifetime to
# milliseconds. In 1.7.x this mechanism was proven against swap targets: 13
# of the 14 tests in this file used one and materialize had exactly one.
# These port that coverage onto the mode that survived.

MATERIALIZED = ".env.runtime"
_M = repr(MATERIALIZED)


def _materialize_run(project, code, *, only_vars=("PLAIN",), max_reads=1):
    with fake_dialog():
        return mcp_server._run_with_env_impl([PYTHON, "-c", code], MATERIALIZED, False,
                                             str(project), list(only_vars), None,
                                             max_reads=max_reads)


def test_materialize_max_reads_two_serves_both_reads() -> None:
    if _need_windows():
        return
    code = ("import time\n"
            "print(open(" + _M + ").read().strip(), flush=True)\n"
            "time.sleep(0.6)\n"
            "print(open(" + _M + ").read().strip(), flush=True)\n"
            "time.sleep(0.4)\n")
    with workspace() as (project, _env_path):
        r = _materialize_run(project, code, max_reads=2)
        first, second = r["stdout"].splitlines()
        assert first == second == "PLAIN=[REDACTED:PLAIN]", r["stdout"]
        rep = r["single_read"][str(project / MATERIALIZED)]
        assert rep["reads"] == 2 and rep["restored_early"] is True
        assert "single_read_restored_early" not in r
        assert not (project / MATERIALIZED).exists()


def test_materialize_stat_only_is_not_a_read() -> None:
    """Opening is a read; asking the directory about the file is not. If
    stat counted, any watcher or indexer would burn the budget."""
    if _need_windows():
        return
    code = ("import os,time\n"
            "for _ in range(20):\n"
            "    os.stat(" + _M + "); os.path.isfile(" + _M + "); os.path.getsize(" + _M + ")\n"
            "time.sleep(0.3)\n")
    with workspace() as (project, _env_path):
        r = _materialize_run(project, code)
        rep = r["single_read"][str(project / MATERIALIZED)]
        assert rep["reads"] == 0 and rep["restored_early"] is False, rep
        assert not (project / MATERIALIZED).exists()


def test_materialize_run_that_never_reads_is_cleaned_up_and_reports_zero_reads() -> None:
    if _need_windows():
        return
    with workspace() as (project, _env_path):
        r = _materialize_run(project, "print('hi')")
        rep = r["single_read"][str(project / MATERIALIZED)]
        assert rep["reads"] == 0 and not rep["restored_early"]
        assert not (project / MATERIALIZED).exists()


def test_materialize_foreign_holder_is_reported_and_not_counted() -> None:
    """A program outside the job opening the file must not spend the budget
    -- otherwise an editor or AV scanner reverts it before the command has
    read it. It is still disclosed."""
    if _need_windows():
        return
    code = ("import time\n"
            "time.sleep(1.6)\n"
            "print(open(" + _M + ").read().count('PLAIN='), flush=True)\n"
            "time.sleep(0.4)\n")
    with workspace() as (project, _env_path):
        target = project / MATERIALIZED
        holder = {}
        original = mcp_server._run_command

        def wrapped(command, env, cwd, timeout, bind=True, on_start=None):
            def hooked(job, pid):
                on_start(job, pid)
                time.sleep(0.2)
                holder["p"] = subprocess.Popen(
                    [PYTHON, "-c",
                     "import sys,time; f=open(sys.argv[1]); time.sleep(1.0); f.close()",
                     str(target)])
            return original(command, env, cwd, timeout, bind=bind, on_start=hooked)

        mcp_server._run_command = wrapped
        try:
            r = _materialize_run(project, code)
        finally:
            mcp_server._run_command = original
            if "p" in holder:
                holder["p"].wait()
        rep = r["single_read"][str(target)]
        assert rep.get("foreign_opens", 0) >= 1 and "Python" in rep.get("foreign_apps", []), rep
        assert r["stdout"].strip() == "1", r
        assert rep["reads"] == 1 and rep["restored_early"] is True
        assert not target.exists()


def test_materialize_watcher_thread_is_gone_and_handle_released_after_the_run() -> None:
    if _need_windows():
        return
    with workspace() as (project, _env_path):
        before = threading.active_count()
        _materialize_run(project, "print(open(" + _M + ").read()[:1])")
        time.sleep(0.2)
        assert threading.active_count() <= before + 1  # run_bound's watchdog may linger 2 s
        probe = project / "probe.env"
        probe.write_bytes(b"A=1\n")
        w = singleview.Watcher(str(probe), 1, lambda _w: {}, threading.Lock())
        w.open()
        w.close()


def test_max_reads_refusals_happen_before_the_dialog() -> None:
    with workspace() as (project, _env_path):
        with fake_dialog() as calls:
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              max_reads=1)
            assert "only means something" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], MATERIALIZED, False, str(project), None,
                                              None, max_reads=0)
            assert "between 1 and" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], MATERIALIZED, False, str(project), None,
                                              None, max_reads=True)
            assert "between 1 and" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], MATERIALIZED, True, str(project), None,
                                              None, max_reads=1)
            assert "background" in r["error"]
            if IS_WIN:
                original = singleview.self_test
                singleview.self_test = lambda path, timeout=3.0: "simulated: no oplock here"
                try:
                    r = mcp_server._run_with_env_impl(["cmd"], MATERIALIZED, False,
                                                      str(project), None, None, max_reads=1)
                finally:
                    singleview.self_test = original
                assert "cannot be honoured" in r["error"] and "no oplock" in r["error"]
            else:
                r = mcp_server._run_with_env_impl(["cmd"], MATERIALIZED, False, str(project),
                                                  None, None, max_reads=1)
                assert "Windows" in r["error"]
        assert calls == []
        a = trust.make_signature(["c"], str(project), None, None, False, None, max_reads=1)
        b = trust.make_signature(["c"], str(project), None, None, False, None, max_reads=2)
        c = trust.make_signature(["c"], str(project), None, None, False, None)
        assert len({a, b, c}) == 3


def test_oplock_probe_is_removed_and_never_clobbers() -> None:
    """The probe self_test_for_new_file leaves beside the target must not
    survive the run, and must never overwrite something already there."""
    if _need_windows():
        return
    with workspace() as (project, _env_path):
        _materialize_run(project, "print('hi')")
        leftovers = [p.name for p in project.iterdir() if "oplock-probe" in p.name]
        assert leftovers == [], leftovers
        # An unrelated file beside the target is never touched.
        bystander = project / "keep.env"
        bystander.write_bytes(b"do not lose me\n")
        assert singleview.self_test_for_new_file(str(project / MATERIALIZED)) is None
        assert bystander.read_bytes() == b"do not lose me\n"


def test_a_probe_left_by_a_crash_does_not_disable_max_reads_forever() -> None:
    """The probe is unlinked in a `finally`, but a process killed before
    reaching it leaves the file behind. With a fixed probe name that turned
    one crash into a PERMANENT refusal of max_reads for that target: the
    exclusive-create hit the survivor on every later run. Shipped that way
    in 2.0.0 and caught by the push-time review. The name carries random
    bytes now, and older ones are swept."""
    if _need_windows():
        return
    with workspace() as (project, _env_path):
        target = project / MATERIALIZED
        for stale in ("." + MATERIALIZED + ".oplock-probe",            # the 2.0.0 shape
                      "." + MATERIALIZED + ".deadbeef.oplock-probe"):  # a 2.0.1 survivor
            (project / stale).write_bytes(b"# llm-env-vault oplock probe\n")
        # Backdate them: a sweep only removes probes old enough to be dead.
        old = time.time() - singleview._STALE_PROBE_SECONDS - 60
        for p in project.iterdir():
            if "oplock-probe" in p.name:
                os.utime(p, (old, old))
        assert singleview.self_test_for_new_file(str(target)) is None, "a crash disabled it"
        # And survivors are swept rather than accumulating.
        assert [p.name for p in project.iterdir() if "oplock-probe" in p.name] == []
        r = _materialize_run(project, "print('hi')")
        assert "error" not in r, r


def test_the_sweep_never_removes_another_servers_live_probe() -> None:
    """The sweep matches the same name shape the live probe uses, so an
    unconditional one would let a second server delete the first's probe
    mid-test -- and holding the file is not the protection it looks like,
    because the probe is closed after it is written and only re-opened by
    self_test. Only age makes a probe safe to remove."""
    if _need_windows():
        return
    with workspace() as (project, _env_path):
        target = project / MATERIALIZED
        live = project / ("." + MATERIALIZED + ".cafebabe.oplock-probe")
        live.write_bytes(b"# llm-env-vault oplock probe\n")   # another server, just now
        assert singleview.self_test_for_new_file(str(target)) is None
        assert live.exists(), "a concurrent server's live probe was swept"
        # The window is flat and absurdly generous rather than derived from
        # the timeout argument. Tying it to a parameter is what let 2.0.2 and
        # 2.0.3 each ship a version of this same bug; an hour is longer than
        # any self_test could run, whatever a caller passes.
        assert singleview._STALE_PROBE_SECONDS >= 3600
        assert singleview.self_test_for_new_file(str(target), timeout=60.0) is None
        assert live.exists(), "a long self_test would have had its own probe swept"
        live.unlink()


# ---------------------------------------------------------------------------
# materialize refuses a network location
# ---------------------------------------------------------------------------
# materialize writes REAL values to the path for the lifetime of the command.
# On a mapped drive or a UNC path those cross the wire and land on a server's
# storage -- backups, snapshots, another machine's disk -- where the unlink on
# exit cannot reach any copy it has already made. Until 2.0.4 only swap= was
# guarded this way; materialize inherited nothing when swap was removed.

def test_materialize_refuses_a_unc_path_before_resolving_it() -> None:
    """The string check runs BEFORE resolve(), because resolving is the
    dangerous step: it opens SMB with the user's credentials. On Windows an
    absolute segment also wins the join, so a UNC value would sail past the
    containment check if it were resolved first."""
    with workspace() as (project, _env_path):
        for bad in (r"\\evil-host\share\.env.runtime", "//evil-host/share/.env.runtime"):
            with fake_dialog() as calls:
                r = mcp_server._run_with_env_impl(["cmd"], bad, False, str(project),
                                                  None, None)
            assert "error" in r, r
            assert "UNC" in r["error"], r["error"]
            assert calls == [], "a refused path still opened the dialog"


def test_materialize_refuses_a_mapped_network_drive() -> None:
    """A mapped drive is a UNC path wearing a letter."""
    if not IS_WIN:
        return _skip("drive types are a Windows concept")
    with workspace() as (project, _env_path):
        original = mcp_server._drive_is_remote
        mcp_server._drive_is_remote = lambda path_str: True
        try:
            with fake_dialog() as calls:
                r = mcp_server._run_with_env_impl(["cmd"], ".env.runtime", False,
                                                  str(project), None, None)
        finally:
            mcp_server._drive_is_remote = original
        assert "error" in r and "mapped network drive" in r["error"], r
        assert "REAL values" in r["error"], "the refusal does not say why"
        assert calls == [], "a refused path still opened the dialog"


def test_materialize_refuses_a_junction_pointing_at_a_share() -> None:
    """Checked on the UNRESOLVED path: a junction whose target is UNC would
    make resolve() itself open the share."""
    if not IS_WIN:
        return _skip("junctions are a Windows concept")
    with workspace() as (project, _env_path):
        original = mcp_server._reparse_points_to_share
        mcp_server._reparse_points_to_share = lambda path_str: True
        try:
            with fake_dialog() as calls:
                r = mcp_server._run_with_env_impl(["cmd"], "sub/.env.runtime", False,
                                                  str(project), None, None)
        finally:
            mcp_server._reparse_points_to_share = original
        assert "error" in r and "junction" in r["error"], r
        assert calls == [], "a refused path still opened the dialog"


def test_an_ordinary_local_materialize_path_is_still_accepted() -> None:
    """The guards must not refuse the normal case."""
    with workspace() as (project, _env_path):
        resolved = mcp_server._resolve_materialize_path(".env.runtime", str(project))
        assert resolved == (project / ".env.runtime").resolve()


def test_a_chained_junction_to_a_share_is_refused() -> None:
    """One hop of indirection is not enough. `A -> C:\\local\\B` where B is
    itself a junction to `\\\\share` looks innocent when only A's own target
    is inspected, and the component walk never visits B because it only ever
    steps through components of the ORIGINAL path. Simulated rather than
    built from real junctions, so it runs without the privileges those need
    and pins the logic rather than the filesystem."""
    if not IS_WIN:
        return _skip("reparse points are a Windows concept")

    class _St:
        def __init__(self, tag):
            self.st_reparse_tag = tag

    # proj/link -> C:/staging/hop1 -> C:/staging/hop2 -> \\evil-host\share
    links = {
        r"C:\proj\link": r"C:\staging\hop1",
        r"C:\staging\hop1": r"C:\staging\hop2",
        r"C:\staging\hop2": r"\\evil-host\share\x",
    }
    real_lstat, real_readlink = mcp_server.os.lstat, mcp_server.os.readlink

    def fake_lstat(p):
        return _St(0xA000000C if str(p) in links else 0)

    def fake_readlink(p):
        return links[str(p)]

    mcp_server.os.lstat, mcp_server.os.readlink = fake_lstat, fake_readlink
    try:
        assert mcp_server._reparse_points_to_share(r"C:\proj\link\.env.runtime") is True
        # And the chain ending somewhere local is still allowed.
        links[r"C:\staging\hop2"] = r"C:\staging\final"
        assert mcp_server._reparse_points_to_share(r"C:\proj\link\.env.runtime") is False
        # A loop is refused rather than followed forever.
        links[r"C:\staging\hop2"] = r"C:\proj\link"
        assert mcp_server._reparse_points_to_share(r"C:\proj\link\.env.runtime") is True
    finally:
        mcp_server.os.lstat, mcp_server.os.readlink = real_lstat, real_readlink


def test_a_plain_local_path_has_no_reparse_points() -> None:
    with workspace() as (project, _env_path):
        assert mcp_server._reparse_points_to_share(str(project / ".env.runtime")) is False
