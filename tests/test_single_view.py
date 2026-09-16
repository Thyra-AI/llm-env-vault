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
from vault_lib import procs, singleview, store, trust  # noqa: E402
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
        assert "swap_restore_conflicts" not in r and not store._journal_path().exists()


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
        assert not store._journal_path().exists()


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
        assert not store._journal_path().exists()
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
            # The byte count of an overlapped write is reported by
            # GetOverlappedResult, not by WriteFile itself.
            real_gor = singleview._k32.GetOverlappedResult

            def short(handle, ov, got, wait):
                ok = real_gor(handle, ov, got, wait)
                if hasattr(got, "_obj") and got._obj.value > 0:
                    got._obj.value -= 1
                return ok

            singleview._k32.GetOverlappedResult = short
            try:
                try:
                    w.write_all(b"A=2\nB=3\n")
                except OSError as e:
                    assert "short write" in str(e)
                else:
                    raise AssertionError("a short write was accepted")
            finally:
                singleview._k32.GetOverlappedResult = real_gor
        finally:
            w.close()


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
