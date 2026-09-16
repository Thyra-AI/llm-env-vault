"""
1.6.1 hardening -- the findings of the post-1.6.0 security review, one test
each, so none of them can quietly come back.

  WP1  the git probe cannot execute repo-controlled code, cannot be
       redirected to a share, and resolves git from PATH only; every path
       recovery or swap= acts on is a registered local file, checked
       before anything on disk is touched
  WP2  a secret re-quoted by a formatter during the run is still restored;
       a secret copied under another name is reported by line number; the
       restore can write in place when os.replace is blocked; an
       unreadable index yields the `value ?` marker that resync finishes
  WP3  a swap run is bounded in time and its process tree dies with it;
       a REAL TerminateProcess of a swapping server is recovered
  WP4  vault_status sees real values without the journal; --force exists
  WP5  a git command is refused; a cloud-synced folder is disclosed

Runs under pytest or standalone (`python tests/test_hardening_161.py`).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from vault_lib import procs, store, trust  # noqa: E402
from test_swap import (INDEX, PLACEHOLDER_ENV, SECRETS, TEST_PASSWORD, _read_journal,  # noqa: E402
                       fake_dialog, stub_run, workspace)

IS_WIN = os.name == "nt"


def _skip(reason: str):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print(f"  SKIP: {reason}")
        return True


# ---------------------------------------------------------------------------
# WP1.1 -- git probe
# ---------------------------------------------------------------------------

def test_git_is_resolved_from_path_only_never_from_cwd_or_below() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp).resolve()
        planted = tmp / "git.exe" if IS_WIN else tmp / "git"
        planted.write_bytes(b"MZ not really")
        (tmp / "sub").mkdir()
        old_cwd, old_path = os.getcwd(), os.environ.get("PATH", "")
        try:
            os.chdir(tmp)
            # cwd first on PATH, then a subdirectory of cwd, then a relative entry.
            os.environ["PATH"] = os.pathsep.join([str(tmp), str(tmp / "sub"), "relative",
                                                  old_path])
            found = mcp_server._find_on_path("git")
        finally:
            os.chdir(old_cwd)
            os.environ["PATH"] = old_path
        assert found is None or not os.path.normcase(found).startswith(
            os.path.normcase(str(tmp))), found
        if IS_WIN:
            assert found is None or found.lower().endswith((".exe", ".com")), found


def test_git_probe_does_not_execute_repo_fsmonitor() -> None:
    if mcp_server._GIT_EXE is None:
        return _skip("git not on PATH")
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp).resolve()
        subprocess.run([mcp_server._GIT_EXE, "init", "-q", str(repo)], check=True,
                       capture_output=True)
        sentinel = repo / "SENTINEL"
        hook = repo / "hook.py"
        hook.write_text(f"open({str(sentinel)!r}, 'w').write('ran')\n", encoding="utf-8")
        cfg = repo / ".git" / "config"
        cfg.write_text(cfg.read_text(encoding="utf-8") +
                       f'[core]\n\tfsmonitor = "{sys.executable} {hook}"\n'
                       f'\thooksPath = {repo / "hooks"}\n', encoding="utf-8")
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        for _ in range(2):
            mcp_server._git_tracks(repo / ".env")
            mcp_server._git_ignores(repo / ".env")
        assert not sentinel.exists(), "repo-level core.fsmonitor executed during the probe"


def test_git_probe_refuses_a_gitdir_file_pointing_at_a_share() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp).resolve()
        (repo / ".git").write_text("gitdir: //evil-host/share/repo.git\n", encoding="utf-8")
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        assert mcp_server._gitdir_is_suspicious(repo) is True
        assert mcp_server._git_tracks(repo / ".env") is None


def test_git_env_disables_every_program_naming_config() -> None:
    env = mcp_server._git_env()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_KEY_0"] == "core.fsmonitor" and env["GIT_CONFIG_VALUE_0"] == "false"
    assert env["GIT_CONFIG_KEY_1"] == "core.hooksPath"
    assert "GIT_DIR" not in env and "GIT_WORK_TREE" not in env


# ---------------------------------------------------------------------------
# WP1.2 -- path validation
# ---------------------------------------------------------------------------

def test_journal_entries_off_the_registry_are_quarantined_not_acted_on() -> None:
    with workspace() as (project, env_path):
        outside = project / "victim.txt"
        outside.write_text("API_TOKEN=keep-me\n", encoding="utf-8")
        entries = {
            str(outside): {"names": ["API_TOKEN"], "pid": 4000000, "pid_start": None,
                           "server_id": "x", "started": 1.0, "state": "active"},
            r"\\evil\share\.env": {"names": ["API_TOKEN"], "pid": 4000000, "pid_start": None,
                                    "server_id": "x", "started": 1.0, "state": "active"},
            str(env_path): {"names": ["NOT_REGISTERED"], "pid": 4000000, "pid_start": None,
                            "server_id": "x", "started": 1.0, "state": "active"},
        }
        store._journal_path().write_text(json.dumps({"version": 1, "entries": entries}),
                                         encoding="utf-8")
        original_exists = Path.exists
        touched = []

        def spy(self):
            if str(self).startswith("\\\\"):
                touched.append(str(self))
            return original_exists(self)

        Path.exists = spy
        try:
            reports = store.recover_stale_swaps()
        finally:
            Path.exists = original_exists
        assert touched == [], "a UNC journal path was stat'ed"
        assert all(r["rejected"] for r in reports) and len(reports) == 3
        assert outside.read_text(encoding="utf-8") == "API_TOKEN=keep-me\n"
        # Quarantined: still there, still reported, on the next call too.
        assert len(_read_journal()) == 3
        assert len(store.recover_stale_swaps()) == 3
        # Only the human's explicit CLI switch clears them.
        store.recover_stale_swaps(drop_rejected=True)
        assert not store._journal_path().exists()


def test_swap_argument_unc_and_remote_are_refused_before_resolve() -> None:
    with workspace() as (project, env_path):
        original_resolve = Path.resolve
        resolved = []

        def spy(self, *a, **k):
            resolved.append(str(self))
            return original_resolve(self, *a, **k)

        Path.resolve = spy
        try:
            with fake_dialog() as calls:
                for bad in (r"\\evil\share\.env", "//evil/share/.env", r"\\?\C:\x\.env"):
                    r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                      None, swap=[bad])
                    assert "refused" in r["error"] or "UNC" in r["error"], r
                r = mcp_server._run_with_env_impl(["cmd"], None, False, r"\\evil\share", None,
                                                  None, swap=[".env"])
                assert "UNC" in r["error"]
                r = mcp_server._run_with_env_impl([r"\\evil\share\tool.exe"], None, False,
                                                  str(project), None, None)
                assert "UNC" in r["error"]
        finally:
            Path.resolve = original_resolve
        assert not any(p.startswith(("\\\\", "//")) for p in resolved), resolved
        assert calls == []


def test_journal_add_validates_names_against_the_registry() -> None:
    with workspace() as (project, env_path):
        try:
            store.journal_add(str(env_path), ["NOT_REGISTERED"])
        except ValueError as e:
            assert "not registered" in str(e)
        else:
            raise AssertionError("journal_add accepted a name outside the registry")
        assert not store._journal_path().exists()


# ---------------------------------------------------------------------------
# WP2 -- restore correctness
# ---------------------------------------------------------------------------

def test_requoted_secret_during_run_is_restored_not_treated_as_edit() -> None:
    with workspace(styles={"API_TOKEN": '"'}) as (project, env_path):
        def formatter(env, cwd):
            data = env_path.read_bytes().replace(b'export API_TOKEN="tok-abcdefgh-123456"',
                                                 b"export API_TOKEN=tok-abcdefgh-123456")
            env_path.write_bytes(data)
            return ""

        with fake_dialog(), stub_run(observer=formatter):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["API_TOKEN"], None, swap=[".env"])
        assert "swap_restore_conflicts" not in r, r
        assert "swap_verify_failed" not in r
        assert b'export API_TOKEN="value 1"\r\n' in env_path.read_bytes()
        assert not store._journal_path().exists()


def test_secret_copied_under_another_name_is_reported_by_line_number() -> None:
    with workspace() as (project, env_path):
        def copier(env, cwd):
            env_path.write_bytes(env_path.read_bytes() + b"BACKUP_TOKEN=tok-abcdefgh-123456\r\n")
            return ""

        with fake_dialog(), stub_run(observer=copier):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["API_TOKEN"], None, swap=[".env"])
        seen = r["swap_secret_seen_elsewhere"]
        assert seen == [{"line": 6, "name": "API_TOKEN", "path": str(env_path)}], seen
        assert "line 6" in r["swap_warning"]
        assert "tok-abcdefgh" not in json.dumps(r)
        assert b'export API_TOKEN="value 1"\r\n' in env_path.read_bytes()


def test_restore_writes_in_place_when_replace_is_blocked() -> None:
    if not IS_WIN:
        return _skip("os.replace sharing violation is Windows-specific")
    with workspace() as (project, env_path):
        record = store.swap_target_file(env_path, ["PLAIN"], SECRETS, {})
        # The base interpreter, not the venv launcher: the launcher's real
        # python is a grandchild, and killing the launcher would leave it
        # holding the file through the temp dir's cleanup.
        python = getattr(sys, "_base_executable", None) or sys.executable
        holder = subprocess.Popen([python, "-c",
                                   "import sys,time; f=open(sys.argv[1]); time.sleep(20)",
                                   str(env_path)])
        try:
            time.sleep(0.8)
            res = store.unswap_target_file(env_path, record, INDEX)
            assert res["error"] is None and res["restored"] == ["PLAIN"], res
            assert b'PLAIN="value 3"' in env_path.read_bytes()
        finally:
            holder.kill()
            holder.wait()


def test_unreadable_index_during_recovery_yields_pending_marker_then_resync_numbers_it() -> None:
    with workspace() as (project, env_path):
        store.swap_target_file(env_path, ["API_TOKEN", "PLAIN"], SECRETS, {})
        store.journal_add(str(env_path), ["API_TOKEN", "PLAIN"])
        j = json.loads(store._journal_path().read_text(encoding="utf-8"))
        j["entries"][str(env_path)].update({"pid": 4000000, "server_id": "gone"})
        store._journal_path().write_text(json.dumps(j), encoding="utf-8")
        store.INDEX_FILE.write_text("{corrupt", encoding="utf-8")
        old_sleep = store.time.sleep
        store.time.sleep = lambda s: None  # skip the 2 s retry wait
        try:
            reports = store.recover_stale_swaps()
        finally:
            store.time.sleep = old_sleep
        assert reports[0]["cleared"] == ["API_TOKEN", "PLAIN"] and "pending_index" in reports[0]
        after = env_path.read_bytes()
        assert b'export API_TOKEN="value ?"\r\n' in after and b"tok-abcdefgh" not in after
        # vault_status shows the pending lines; a repaired index + resync numbers them.
        store.save_index(dict(INDEX))
        status = mcp_server._vault_status_impl()
        assert status["targets_with_pending_placeholders"] == {str(env_path): ["API_TOKEN", "PLAIN"]}
        res = mcp_server._resync_targets_impl()
        assert res[str(env_path)]["status"] == "ok"
        assert b'export API_TOKEN="value 1"\r\n' in env_path.read_bytes()


def test_transient_index_lock_is_retried() -> None:
    with workspace() as (project, env_path):
        store.swap_target_file(env_path, ["PLAIN"], SECRETS, {})
        store.journal_add(str(env_path), ["PLAIN"])
        j = json.loads(store._journal_path().read_text(encoding="utf-8"))
        j["entries"][str(env_path)].update({"pid": 4000000, "server_id": "gone"})
        store._journal_path().write_text(json.dumps(j), encoding="utf-8")
        original = store.load_index
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("locked")
            return original()

        store.load_index = flaky
        old_sleep = store.time.sleep
        store.time.sleep = lambda s: None
        try:
            reports = store.recover_stale_swaps()
        finally:
            store.load_index = original
            store.time.sleep = old_sleep
        assert reports[0]["restored"] == ["PLAIN"] and "pending_index" not in reports[0]


def test_dotenv_decode_reads_single_backslash_escapes() -> None:
    assert store._dotenv_decode('"a\\nb"') == "a\nb"
    assert store._dotenv_decode('"a\\\\b"') == "a\\b"
    assert store._dotenv_decode('"q\\"x"') == 'q"x'
    assert store._dotenv_decode("'lit\\n'") == "lit\\n"
    # A formatter that re-escaped a secret containing a backslash: still ours.
    entry = {"secret": "a\\b", "rendered_value": '"a\\b"'}
    assert store._carries_value('"a\\\\b"', entry) is True


def test_a_registered_target_that_became_a_link_is_refused_everywhere() -> None:
    with workspace() as (project, env_path):
        victim = project / "victim.env"
        victim.write_bytes(b'PLAIN="value 3"\n')
        real = project / "real.env"
        env_path.rename(real)
        try:
            os.symlink(victim, env_path)
        except (OSError, NotImplementedError):
            real.rename(env_path)
            return _skip("symlink creation not permitted here")
        try:
            assert store._is_link(env_path)
            with fake_dialog() as calls:
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
            assert "link" in r["error"] and calls == []
            for fn in (lambda: store.preview_swap(env_path, ["PLAIN"]),
                       lambda: store.swap_target_file(env_path, ["PLAIN"], SECRETS, {}),
                       lambda: store.recover_swap_file(env_path, ["PLAIN"], INDEX, 0)):
                try:
                    out = fn()
                except ValueError as e:
                    assert "link" in str(e)
                else:
                    assert isinstance(out, dict) and out.get("error") and "link" in out["error"]
            assert victim.read_bytes() == b'PLAIN="value 3"\n'
        finally:
            env_path.unlink()
            real.rename(env_path)


def test_trailing_backslash_never_renders_unterminated() -> None:
    text, note = store.render_swap_value("abc\\", '"')
    assert text == "'abc\\'" and note
    text, note = store.render_swap_value("a'b\\", '"')
    assert text == '"a\'b\\\\"' and note
    assert store.render_swap_value("abc\\\\", '"') == ('"abc\\\\"', None)


def test_temp_file_sweep_ignores_age() -> None:
    with workspace() as (project, env_path):
        leftover = project / "..env.old.tmp"
        leftover.write_bytes(b"PLAIN=justletters123\n")
        os.utime(leftover, (0, 0))  # epoch-old
        report = store.recover_swap_file(env_path, ["PLAIN"], INDEX, started=time.time())
        assert not leftover.exists() and report["temp_files_removed"]


def test_own_pid_leftover_entry_is_cleared_when_file_already_restored() -> None:
    with workspace() as (project, env_path):
        store.journal_add(str(env_path), ["PLAIN"])  # file still holds placeholders
        reports = store.recover_stale_swaps()
        assert reports and reports[0].get("leftover_entry_removed") is True
        assert not store._journal_path().exists()


# ---------------------------------------------------------------------------
# WP3 -- time bound, process binding, the real kill
# ---------------------------------------------------------------------------

def test_swap_run_has_a_default_timeout_and_it_is_in_the_signature() -> None:
    with workspace() as (project, env_path):
        with fake_dialog() as calls, stub_run():
            mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                          swap=[".env"])
            assert calls[0]["timeout"] == mcp_server.SWAP_DEFAULT_TIMEOUT_SECONDS
            mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None)
            assert calls[1]["timeout"] is None
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              timeout=True)
            assert "timeout must be" in r["error"]
            r = mcp_server._run_with_env_impl(["cmd"], None, True, str(project), None, None,
                                              timeout=5)
            assert "background" in r["error"]
        a = trust.make_signature(["cmd"], str(project), None, None, False, None, timeout=3600)
        b = trust.make_signature(["cmd"], str(project), None, None, False, None, timeout=60)
        c = trust.make_signature(["cmd"], str(project), None, None, False, None)
        assert len({a, b, c}) == 3


def test_timed_out_swap_run_kills_the_tree_and_restores() -> None:
    with workspace() as (project, env_path):
        code = ("import subprocess,sys,time\n"
                "g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
                "print('grandchild', g.pid, flush=True)\n"
                "time.sleep(60)\n")
        t = time.time()
        with fake_dialog():
            r = mcp_server._run_with_env_impl([sys.executable, "-c", code], None, False,
                                              str(project), ["PLAIN"], None, swap=[".env"],
                                              timeout=2)
        assert r["timed_out"] is True and r["exit_code"] is None, r
        assert time.time() - t < 15
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        gpid = int(r["stdout"].split()[1])
        time.sleep(0.5)
        if r.get("process_binding") is None:  # bound: the grandchild must be gone
            assert procs.process_start_time(gpid)[0] is False


def test_plain_runs_are_not_bound_but_swap_runs_are() -> None:
    with workspace() as (project, env_path):
        seen = []
        original = mcp_server._run_command

        def spy(command, env, cwd, timeout, bind=True, on_start=None):
            seen.append(bind)
            return procs.RunResult(0, "", "", False, "job" if bind else "none")

        mcp_server._run_command = spy
        try:
            with fake_dialog():
                mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None)
                mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"])
                mcp_server._run_with_env_impl(["cmd"], ".env.runtime", False, str(project),
                                              None, None)
        finally:
            mcp_server._run_command = original
        assert seen == [False, True, True]


def test_watchdog_never_touches_a_closed_job_and_ends_lingering_descendants() -> None:
    """The main thread closes the Job the moment communicate() returns; the
    watchdog wakes up two seconds later. Its terminate must be a no-op on a
    closed job (a reused handle value could be an unrelated object), and a
    descendant the command left behind must still be gone -- on Windows via
    the job close, on POSIX via the watchdog's killpg after the leader was
    reaped (which a poll() guard used to make unreachable)."""
    # Many fast runs: the watchdog fires after close every single time.
    for _ in range(8):
        r = procs.run_bound([sys.executable, "-c", "print(1)"], os.environ.copy(), None, 10)
        assert r.returncode == 0 and r.stdout.strip() == "1"
    # A command that leaves a grandchild holding the output pipe and exits.
    code = ("import subprocess,sys\n"
            "g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            "print('grandchild', g.pid, flush=True)\n")
    t = time.time()
    r = procs.run_bound([sys.executable, "-c", code], os.environ.copy(), None, 30)
    elapsed = time.time() - t
    gpid = int(r.stdout.split()[1])
    assert r.returncode == 0 and not r.timed_out
    assert elapsed < 15, f"tool blocked on the orphan's pipe for {elapsed:.0f}s"
    time.sleep(procs._DESCENDANT_GRACE_SECONDS + 1)
    if r.binding in ("job", "session"):
        assert procs.process_start_time(gpid)[0] is False, "descendant outlived the command"


_CHILD_SWAPPER = r"""
import sys, time, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from vault_lib import store
store.ROOT = Path(sys.argv[2])
for attr, name in (("INDEX_FILE", "vault_index.json"), ("TARGETS_FILE", "targets.json"),
                   ("TARGETS_LOCK_FILE", "targets.json.lock")):
    setattr(store, attr, store.ROOT / name)
env_path = Path(sys.argv[3])
secrets = json.loads(sys.argv[4])
store.journal_add(str(env_path), sorted(secrets))
store.swap_target_file(env_path, sorted(secrets), secrets, {})
print("swapped", flush=True)
time.sleep(60)
"""


def _spawn_swapping_server(project, env_path):
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_SWAPPER, str(Path(__file__).parent.parent),
         str(store.ROOT), str(env_path), json.dumps({"PLAIN": SECRETS["PLAIN"]})],
        stdout=subprocess.PIPE, text=True)
    line = child.stdout.readline()
    assert line.strip() == "swapped", line
    return child


def test_real_terminateprocess_of_a_swapping_server_is_recovered() -> None:
    """The path every Windows session actually exits through: the host
    TerminateProcess-es the server mid-swap. No finally block runs. The
    next tool call in another process must put the placeholders back."""
    with workspace() as (project, env_path):
        child = _spawn_swapping_server(project, env_path)
        try:
            assert b"justletters123" in env_path.read_bytes()
            assert store.live_swaps(), "the child's entry should be live"
            assert store.recover_stale_swaps() == []  # live: untouched
            assert b"justletters123" in env_path.read_bytes()
            child.kill()  # TerminateProcess
            child.wait()
        finally:
            if child.poll() is None:
                child.kill()
        reports = mcp_server._recover_swaps()
        assert reports and reports[0]["restored"] == ["PLAIN"], reports
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert not store._journal_path().exists()


def test_force_recovers_a_live_entry_and_needs_no_password() -> None:
    with workspace() as (project, env_path):
        child = _spawn_swapping_server(project, env_path)
        try:
            reports = store.recover_stale_swaps(force=True)
            assert reports and reports[0]["reason"] == "forced"
            assert env_path.read_bytes() == PLACEHOLDER_ENV
        finally:
            child.kill()
            child.wait()


# ---------------------------------------------------------------------------
# WP4 -- journal-independent visibility
# ---------------------------------------------------------------------------

def test_vault_status_reports_managed_lines_holding_real_values_without_a_journal() -> None:
    with workspace() as (project, env_path):
        store.swap_target_file(env_path, ["PLAIN"], SECRETS, {})
        status = mcp_server._vault_status_impl()
        assert status["targets_holding_non_placeholders"] == {str(env_path): ["PLAIN"]}
        assert "justletters123" not in json.dumps(status)


# ---------------------------------------------------------------------------
# WP5 -- refusals and disclosure
# ---------------------------------------------------------------------------

def test_git_command_is_refused_for_swap() -> None:
    with workspace() as (project, env_path):
        with fake_dialog() as calls:
            for argv0 in ("git", "GIT.EXE", r"C:\Program Files\Git\cmd\git.exe"):
                r = mcp_server._run_with_env_impl([argv0, "add", "-A"], None, False,
                                                  str(project), None, None, swap=[".env"])
                assert "git" in r["error"], r
        assert calls == []


def test_cloud_synced_folder_is_disclosed_to_the_dialog() -> None:
    with workspace() as (project, env_path):
        old = os.environ.get("OneDrive")
        os.environ["OneDrive"] = str(project.parent)
        try:
            with fake_dialog() as calls, stub_run():
                mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"])
        finally:
            if old is None:
                os.environ.pop("OneDrive", None)
            else:
                os.environ["OneDrive"] = old
        assert calls[0]["swap"][0]["cloud"] == "OneDrive"


def test_file_that_became_tracked_during_the_run_is_reported() -> None:
    if mcp_server._GIT_EXE is None:
        return _skip("git not on PATH")
    with workspace() as (project, env_path):
        subprocess.run([mcp_server._GIT_EXE, "init", "-q", str(project)], check=True,
                       capture_output=True)

        def commit_during_run(env, cwd):
            subprocess.run([mcp_server._GIT_EXE, "-C", str(project), "add", "-A"],
                           check=True, capture_output=True)
            return ""

        with fake_dialog(), stub_run(observer=commit_during_run):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), ["PLAIN"],
                                              None, swap=[".env"])
        assert r["swap_target_committed"] == [str(env_path)]
        assert "Rotate" in r["swap_warning"]


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
