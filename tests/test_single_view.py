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
from test_swap import (INDEX, PLACEHOLDER_ENV, SECRETS, fake_dialog, stub_run,  # noqa: E402
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


def test_first_read_is_real_second_read_while_running_is_placeholder() -> None:
    if _need_windows():
        return
    with workspace(styles={"API_TOKEN": '"'}) as (project, env_path):
        with fake_dialog() as calls:
            r = mcp_server._run_with_env_impl([PYTHON, "-c", READ_TWICE], None, False,
                                              str(project), ["API_TOKEN"], None,
                                              swap=[".env"], max_reads=1)
        assert r["applied"] and r["exit_code"] == 0, r
        first, second = r["stdout"].splitlines()
        assert first == "[REDACTED:API_TOKEN (as written to .env)]", first
        assert second == '"value 1"', second
        rep = r["single_read"][str(env_path)]
        assert rep["restored_early"] is True and rep["reads"] == 1
        assert rep["reads_after_restore"] == 1
        assert r["single_read_restored_early"] == {str(env_path): 1}
        assert calls[0]["max_reads"] == 1
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert "swap_restore_conflicts" not in r and not legacy_swap._journal_path().exists()


def test_max_reads_two_serves_both_reads() -> None:
    if _need_windows():
        return
    with workspace(styles={"API_TOKEN": '"'}) as (project, env_path):
        with fake_dialog():
            r = mcp_server._run_with_env_impl([PYTHON, "-c", READ_TWICE], None, False,
                                              str(project), ["API_TOKEN"], None,
                                              swap=[".env"], max_reads=2)
        first, second = r["stdout"].splitlines()
        assert first == second == "[REDACTED:API_TOKEN (as written to .env)]", r["stdout"]
        rep = r["single_read"][str(env_path)]
        assert rep["reads"] == 2 and rep["restored_early"] is True
        assert "single_read_restored_early" not in r
        assert env_path.read_bytes() == PLACEHOLDER_ENV


def test_stat_only_is_not_a_read() -> None:
    if _need_windows():
        return
    code = ("import os,time\n"
            "for _ in range(20): os.stat('.env'); os.path.isfile('.env'); os.path.getsize('.env')\n"
            "time.sleep(0.3)\n")
    with workspace() as (project, env_path):
        with fake_dialog():
            r = mcp_server._run_with_env_impl([PYTHON, "-c", code], None, False, str(project),
                                              ["API_TOKEN"], None, swap=[".env"], max_reads=1)
        rep = r["single_read"][str(env_path)]
        assert rep["reads"] == 0 and rep["restored_early"] is False, rep
        assert env_path.read_bytes() == PLACEHOLDER_ENV  # restored at exit as usual


def test_foreign_holder_is_reported_and_not_counted() -> None:
    if _need_windows():
        return
    with workspace(styles={"API_TOKEN": '"'}) as (project, env_path):
        # The command waits 0.5 s, then reads once. Meanwhile a process OUTSIDE
        # the job opens the file and holds it for 1 s.
        code = ("import time\n"
                "time.sleep(1.6)\n"
                "print(open('.env', encoding='utf-8').read().count('tok-'), flush=True)\n"
                "time.sleep(0.4)\n")
        holder = {}

        def start_holder(*_a):
            holder["p"] = subprocess.Popen(
                [PYTHON, "-c", "import sys,time; f=open(sys.argv[1]); time.sleep(1.0); f.close()",
                 str(env_path)])

        original = mcp_server._run_command

        def wrapped(command, env, cwd, timeout, bind=True, on_start=None):
            def hooked(job, pid):
                on_start(job, pid)
                time.sleep(0.2)
                start_holder()
            return original(command, env, cwd, timeout, bind=bind, on_start=hooked)

        mcp_server._run_command = wrapped
        try:
            with fake_dialog():
                r = mcp_server._run_with_env_impl([PYTHON, "-c", code], None, False,
                                                  str(project), ["API_TOKEN"], None,
                                                  swap=[".env"], max_reads=1)
        finally:
            mcp_server._run_command = original
            if "p" in holder:
                holder["p"].wait()
        rep = r["single_read"][str(env_path)]
        assert rep.get("foreign_opens", 0) >= 1 and "Python" in rep.get("foreign_apps", []), rep
        # The command's own read still got the real value and was counted.
        assert r["stdout"].strip() == "1", r
        assert rep["reads"] == 1 and rep["restored_early"] is True
        assert env_path.read_bytes() == PLACEHOLDER_ENV


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


def test_refusals_before_the_dialog() -> None:
    with workspace() as (project, env_path):
        with fake_dialog() as calls:
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              max_reads=1)
            assert "only means something" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"], max_reads=0)
            assert "between 1 and" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"], max_reads=True)
            assert "between 1 and" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], None, True, str(project), None, None,
                                              swap=[".env"], max_reads=1)
            assert "background" in r["error"]
            if IS_WIN:
                original = singleview.self_test
                singleview.self_test = lambda path, timeout=3.0: "simulated: no oplock here"
                try:
                    r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                      None, swap=[".env"], max_reads=1)
                finally:
                    singleview.self_test = original
                assert "cannot be honoured" in r["error"] and "no oplock" in r["error"]
            else:
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"], max_reads=1)
                assert "Windows" in r["error"]
        assert calls == []
        a = trust.make_signature(["c"], str(project), None, None, False, None, max_reads=1)
        b = trust.make_signature(["c"], str(project), None, None, False, None, max_reads=2)
        c = trust.make_signature(["c"], str(project), None, None, False, None)
        assert len({a, b, c}) == 3


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


def test_a_run_that_never_reads_restores_at_exit_and_reports_zero_reads() -> None:
    if _need_windows():
        return
    with workspace() as (project, env_path):
        with fake_dialog():
            r = mcp_server._run_with_env_impl([PYTHON, "-c", "print('hi')"], None, False,
                                              str(project), ["PLAIN"], None, swap=[".env"],
                                              max_reads=1)
        rep = r["single_read"][str(env_path)]
        assert rep["reads"] == 0 and not rep["restored_early"]
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert not legacy_swap._journal_path().exists()


def test_failure_on_a_later_target_rolls_back_an_armed_earlier_one() -> None:
    """Two swap targets, max_reads set. The first is armed (exclusive handle
    held, real values written through it) when the second fails. The
    rollback must release the first watcher's handle before the file-based
    restore, or the restore cannot even open the file."""
    if _need_windows():
        return
    with workspace() as (project, env_path):
        second = project / ".env.second"
        second.write_bytes(b'PLAIN="value 3"\n')
        store.add_target(str(second), ["PLAIN"])
        original = mcp_server._swap_through_watcher
        calls = {"n": 0}

        def failing_second(key, *a, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise ValueError("simulated failure on the second target")
            return original(key, *a, **k)

        mcp_server._swap_through_watcher = failing_second
        try:
            with fake_dialog():
                r = mcp_server._run_with_env_impl([PYTHON, "-c", "pass"], None, False,
                                                  str(project), ["PLAIN"], None,
                                                  swap=[".env", ".env.second"], max_reads=1)
        finally:
            mcp_server._swap_through_watcher = original
        assert r["applied"] is False and "simulated" in r["error"], r
        assert env_path.read_bytes() == PLACEHOLDER_ENV, "first target not rolled back"
        assert b"justletters123" not in second.read_bytes()
        assert "swap_restore_failed" not in r
        assert not legacy_swap._journal_path().exists()
        # And nothing of ours is left holding either file.
        for p in (env_path, second):
            w = singleview.Watcher(str(p), 1, lambda _w: {}, threading.Lock())
            w.open()
            w.close()


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


def test_a_failed_early_restore_is_retried_on_the_next_read() -> None:
    """A transient failure while reverting must not leave the real values
    on disk for the rest of the run: the next counted open retries."""
    if _need_windows():
        return
    real = store.compute_unswap_bytes
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(0, "simulated transient failure")
        return real(*args, **kwargs)

    store.compute_unswap_bytes = flaky
    try:
        with workspace(styles={"API_TOKEN": '"'}) as (project, env_path):
            with fake_dialog():
                r = mcp_server._run_with_env_impl([PYTHON, "-c", READ_THRICE], None, False,
                                                  str(project), ["API_TOKEN"], None,
                                                  swap=[".env"], max_reads=1)
            assert r["applied"] and r["exit_code"] == 0, r
            first, second, third = r["stdout"].splitlines()
            assert first == "[REDACTED:API_TOKEN (as written to .env)]", first
            # The second read still saw the real value (the failed attempt);
            # the third proves the retry happened.
            assert second == "[REDACTED:API_TOKEN (as written to .env)]", second
            assert third == '"value 1"', third
            rep = r["single_read"][str(env_path)]
            assert rep["restored_early"] is True, rep
            assert rep["restore_attempts"] == 2 and "restore_error" not in rep, rep
            assert rep["reads"] == 2 and rep["reads_after_restore"] == 1, rep
            assert env_path.read_bytes() == PLACEHOLDER_ENV
            assert "swap_restore_conflicts" not in r and not legacy_swap._journal_path().exists()
    finally:
        store.compute_unswap_bytes = real


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


def test_watcher_thread_is_gone_and_handle_released_after_the_run() -> None:
    if _need_windows():
        return
    with workspace() as (project, env_path):
        before = threading.active_count()
        with fake_dialog():
            mcp_server._run_with_env_impl([PYTHON, "-c", "print(open('.env').read()[:1])"],
                                          None, False, str(project), ["PLAIN"], None,
                                          swap=[".env"], max_reads=1)
        time.sleep(0.2)
        assert threading.active_count() <= before + 1  # run_bound's watchdog may linger 2 s
        # An exclusive open must succeed: no handle of ours is left on the file.
        w = singleview.Watcher(str(env_path), 1, lambda _w: {}, threading.Lock())
        w.open()
        w.close()


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
