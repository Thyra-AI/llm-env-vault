"""
Suite for run_with_env's swap= parameter -- real values written INTO a
registered .env for the lifetime of one foreground command.

This is materialize at the canonical path, and it inherits materialize's
failure modes plus three of its own, which drive the tests here:

  1. REAL VALUES LEFT BEHIND. The restore runs in a finally block, retries
     its write, verifies from disk, and a journal written before the first
     byte lands lets any later tool call in any server finish the job if
     this one dies. Every one of those layers is exercised, including the
     journal's liveness logic (a dead pid, a reused pid, another live
     server).

  2. THE RESTORE DESTROYS AN EDIT. Only a line that still carries exactly
     what the swap wrote is put back; a line someone changed during the run
     is left alone and reported. Byte-exactness matters too: trust hashes
     `.env` for docker/compose commands, so a restore that lost a BOM or a
     CRLF would silently revoke a trusted command on every run.

  3. TRUST WIDENS. targets.json is agent-writable, so a signature keyed on
     the swap PATH alone would let a grant for "swap 2 values" auto-allow
     "swap 20" after the registry grew. The signature binds the names that
     would actually be swapped, and the swap file is drift-hashed.

gui.unlock_for_run_dialog is monkeypatched throughout; no window opens.
Runs under pytest or standalone (`python tests/test_swap.py`).
"""
import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, procs, store, trust  # noqa: E402

TEST_PASSWORD = "swap-suite-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
SECRETS = {
    "API_TOKEN": "tok-abcdefgh-123456",
    "DB_PASSWORD": "p$ss w#rd 'quoted' \"dq\"",
    "PLAIN": "justletters123",
}
INDEX = {"API_TOKEN": 1, "DB_PASSWORD": 2, "PLAIN": 3}


def _isolate(tmp_dir: Path) -> dict:
    names = ("SALT_FILE", "SECRETS_FILE", "INDEX_FILE", "ENV_FILE", "BAK_FILE",
             "FORMAT_FILE", "VAULT_LOCK_FILE", "FILES_FILE", "FILES_LOCK_FILE",
             "TARGETS_FILE", "TARGETS_LOCK_FILE", "ROOT")
    originals = {n: getattr(store, n) for n in names}
    vault_dir = tmp_dir / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    store.ROOT = vault_dir
    for attr, name in (("SALT_FILE", "vault.salt"), ("SECRETS_FILE", "vault.enc"),
                       ("INDEX_FILE", "vault_index.json"), ("ENV_FILE", "llm.env"),
                       ("BAK_FILE", "vault.enc.bak"), ("FORMAT_FILE", "vault.format.txt"),
                       ("VAULT_LOCK_FILE", "vault.enc.lock"), ("FILES_FILE", "files.json"),
                       ("FILES_LOCK_FILE", "files.json.lock"),
                       ("TARGETS_FILE", "targets.json"),
                       ("TARGETS_LOCK_FILE", "targets.json.lock")):
        setattr(store, attr, vault_dir / name)
    return originals


def _reset_trust() -> None:
    trust._trusted.clear()
    trust._cached_secrets.clear()
    trust._cache_keys.clear()
    trust._cached_vault_fingerprint = None


PLACEHOLDER_ENV = (b"# project config\r\n"
                   b"export API_TOKEN=\"value 1\"\r\n"
                   b"  DB_PASSWORD=\"value 2\"  \r\n"
                   b"PLAIN=\"value 3\"\r\n"
                   b"OTHER=untouched\r\n")


@contextlib.contextmanager
def workspace(env_bytes=PLACEHOLDER_ENV, styles=None, register=True):
    """A v2 vault holding SECRETS plus a project dir whose .env is a
    registered target already rewritten with placeholders."""
    with tempfile.TemporaryDirectory(prefix="llm_swap_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        _reset_trust()
        project = tmp_path / "project"
        project.mkdir()
        env_path = project / ".env"
        env_path.write_bytes(env_bytes)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(SECRETS))
            store.save_index(dict(INDEX))
            if register:
                store.add_target(str(env_path), sorted(SECRETS))
                if styles:
                    store.record_target_styles(str(env_path), styles)
            yield project, env_path
        finally:
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


@contextlib.contextmanager
def fake_dialog(approve=True, trust_it=False):
    original = gui.unlock_for_run_dialog
    calls = []

    def wrapper(command_str, materialize_path=None, only_vars=None, trust_note=None,
                files=None, swap=None, timeout=None, **kwargs):
        calls.append({"command_str": command_str, "only_vars": only_vars,
                      "trust_note": trust_note, "files": files, "swap": swap,
                      "materialize_path": materialize_path, "timeout": timeout, **kwargs})
        if not approve:
            return {"secrets": None, "trust": False}
        secrets = store.load_secrets(TEST_PASSWORD)
        if only_vars is not None:
            secrets = {k: v for k, v in secrets.items() if k in only_vars}
        return {"secrets": secrets, "trust": trust_it}

    gui.unlock_for_run_dialog = wrapper
    try:
        yield calls
    finally:
        gui.unlock_for_run_dialog = original


@contextlib.contextmanager
def stub_run(observer=None, returncode=0, raise_exc=None):
    """Replace subprocess.run inside mcp_server. `observer(env, cwd)` is
    called at the moment the command would run -- i.e. while the swap is
    in effect -- and may return text to use as stdout."""
    original = mcp_server._run_command

    def fake(command, env, cwd, timeout, bind=True, on_start=None):
        out = observer(env, cwd) if observer else ""
        if raise_exc is not None:
            raise raise_exc
        return procs.RunResult(returncode, out or "", "", False, "job")

    mcp_server._run_command = fake
    try:
        yield
    finally:
        mcp_server._run_command = original


def _read_journal() -> dict:
    p = store._journal_path()
    return json.loads(p.read_text(encoding="utf-8"))["entries"] if p.exists() else {}


# ---------------------------------------------------------------------------
# Rendering and style capture
# ---------------------------------------------------------------------------

def test_render_faithful_styles_are_exact_inverses_of_unquote() -> None:
    # Double-quoted: only the quote is re-escaped; a literal backslash-n the
    # user wrote stays two characters, exactly as their loader always saw.
    assert store.render_swap_value('a"b\\n', '"') == ('"a\\"b\\n"', None)
    assert store.render_swap_value("it's", "'") == ("'it\\'s'", None)
    assert store.render_swap_value("p$ss word", "") == ("p$ss word", None)


def test_render_unquoted_style_falls_back_when_value_would_misparse() -> None:
    # A leading space or an inline-comment sequence cannot be raw.
    text, _ = store.render_swap_value(" lead", "")
    assert text == "' lead'"
    text, _ = store.render_swap_value("x #y", "")
    assert text == "'x #y'"


def test_render_unknown_style_policy() -> None:
    assert store.render_swap_value("tok-abc_123", None) == ("tok-abc_123", None)
    text, note = store.render_swap_value("p$ss w#rd", None)
    assert text == "'p$ss w#rd'" and "single-quoted" in note
    text, note = store.render_swap_value("it's \"q\"", None)
    assert text == '"it\'s \\"q\\""' and "node" in note


def test_render_refuses_newlines() -> None:
    for style in ('"', "'", "", None):
        try:
            store.render_swap_value("a\nb", style)
        except ValueError:
            continue
        raise AssertionError(f"newline accepted for style {style!r}")


def test_parse_env_file_with_styles_reports_each_lines_quoting() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_text('A="x"\nB=\'y\'\nC=z\nD="unterminated\n', encoding="utf-8")
        parsed, styles = store.parse_env_file_with_styles(p)
        assert styles == {"A": '"', "B": "'", "C": ""}
        # The plain accessor is unchanged in shape for every existing caller.
        assert store.parse_env_file(p) == parsed
        assert all(len(item) in (2, 3) for item in parsed)


def test_target_styles_round_trip_and_validation() -> None:
    with workspace() as (project, env_path):
        store.record_target_styles(str(env_path), {"API_TOKEN": '"', "PLAIN": ""})
        store.record_target_styles(str(env_path), {"DB_PASSWORD": "'"})
        assert store.load_target_styles()[str(env_path)] == {
            "API_TOKEN": '"', "PLAIN": "", "DB_PASSWORD": "'"}
        # Malformed entries are dropped, never raised: a bad styles file
        # costs fidelity, not a run.
        store._styles_path().write_text(json.dumps({
            str(env_path): {"API_TOKEN": "```", "bad name": '"', "PLAIN": ""},
            "junk": "not a dict", 7: {}}), encoding="utf-8")
        assert store.load_target_styles() == {str(env_path): {"PLAIN": ""}}
        store._styles_path().write_text("{not json", encoding="utf-8")
        assert store.load_target_styles() == {}


# ---------------------------------------------------------------------------
# store: swap / unswap / preview / recover
# ---------------------------------------------------------------------------

def test_preview_classifies_names_without_secrets() -> None:
    with workspace() as (project, env_path):
        env_path.write_bytes(PLACEHOLDER_ENV + b"PLAIN=real-now\r\n")
        preview = store.preview_swap(env_path, ["API_TOKEN", "PLAIN", "MISSING", "OTHER"])
        assert preview["swappable"] == ["API_TOKEN", "PLAIN"]
        assert preview["not_in_file"] == ["MISSING"]
        assert preview["not_placeholder"] == ["OTHER"]
        assert preview["duplicates"] == ["PLAIN"]


def test_swap_and_unswap_are_byte_exact_with_bom_crlf_indent_and_export() -> None:
    original = b"\xef\xbb\xbf" + PLACEHOLDER_ENV.replace(b"OTHER=untouched\r\n",
                                                          b"OTHER=untouched")  # no final EOL
    with workspace(env_bytes=original) as (project, env_path):
        record = store.swap_target_file(env_path, sorted(SECRETS), SECRETS,
                                        {"API_TOKEN": '"', "DB_PASSWORD": '"', "PLAIN": ""})
        after = env_path.read_bytes()
        assert after.startswith(b"\xef\xbb\xbf# project config\r\n")
        assert b'export API_TOKEN="tok-abcdefgh-123456"\r\n' in after
        assert b'  DB_PASSWORD="p$ss w#rd \'quoted\' \\"dq\\""\r\n' in after
        assert b"PLAIN=justletters123\r\n" in after
        assert after.endswith(b"OTHER=untouched")
        assert record["swapped"] == ["API_TOKEN", "DB_PASSWORD", "PLAIN"]
        res = store.unswap_target_file(env_path, record, INDEX)
        assert res == {"restored": ["API_TOKEN", "DB_PASSWORD", "PLAIN"], "conflicts": [],
                       "verify_failed": [], "error": None, "secret_seen_elsewhere": []}
        assert env_path.read_bytes() == original


def test_swap_skips_non_placeholder_and_missing_lines_and_never_appends() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\nPLAIN=hand-typed\n') as (project, env_path):
        record = store.swap_target_file(env_path, ["API_TOKEN", "PLAIN", "DB_PASSWORD"],
                                        SECRETS, {})
        assert record["swapped"] == ["API_TOKEN"]
        assert record["skipped"] == {"PLAIN": "current value is not a vault placeholder",
                                     "DB_PASSWORD": "no line for this name in the file"}
        text = env_path.read_text(encoding="utf-8")
        assert "PLAIN=hand-typed" in text and "DB_PASSWORD" not in text


def test_unswap_tier_two_handles_reindented_line_and_removed_var() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\nPLAIN="value 3"\n') as (project, env_path):
        record = store.swap_target_file(env_path, ["API_TOKEN", "PLAIN"], SECRETS, {})
        # An editor re-indented and re-terminated the API_TOKEN line and
        # moved it; PLAIN's variable was removed from the vault meanwhile.
        env_path.write_bytes(b'PLAIN=justletters123\r\n    API_TOKEN=tok-abcdefgh-123456\r\n')
        res = store.unswap_target_file(env_path, record, {"API_TOKEN": 1})
        assert res["restored"] == ["API_TOKEN", "PLAIN"] and not res["conflicts"]
        after = env_path.read_bytes()
        assert b'    API_TOKEN="value 1"\r\n' in after
        # A name that left the vault gets the pending marker -- a line, not
        # a comment, so the next resync finishes the job by itself.
        assert b'PLAIN="value ?"\r\n' in after
        assert b"justletters123" not in after


def test_unswap_leaves_user_edited_line_alone_and_reports_conflict() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\nPLAIN="value 3"\n') as (project, env_path):
        record = store.swap_target_file(env_path, ["API_TOKEN", "PLAIN"], SECRETS, {})
        env_path.write_bytes(b'API_TOKEN=user-typed-something\nPLAIN=justletters123\n')
        res = store.unswap_target_file(env_path, record, INDEX)
        assert res["conflicts"] == ["API_TOKEN"]
        assert res["restored"] == ["PLAIN"]
        after = env_path.read_bytes()
        assert b"API_TOKEN=user-typed-something" in after
        assert b'PLAIN="value 3"' in after


def test_unswap_verify_catches_write_back_after_restore() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\n') as (project, env_path):
        record = store.swap_target_file(env_path, ["API_TOKEN"], SECRETS, {})
        original_write = store._write_with_retries

        def sabotaged(path, data, mode, **kw):
            # Something (an editor saving a stale buffer) writes the real
            # value back right after our restore.
            err = original_write(path, data, mode, **kw)
            path.write_bytes(b"API_TOKEN=tok-abcdefgh-123456\n")
            return err

        store._write_with_retries = sabotaged
        try:
            res = store.unswap_target_file(env_path, record, INDEX)
        finally:
            store._write_with_retries = original_write
        assert res["verify_failed"] == ["API_TOKEN"]


def test_unswap_reports_error_when_write_keeps_failing() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\n') as (project, env_path):
        record = store.swap_target_file(env_path, ["API_TOKEN"], SECRETS, {})
        original_write = store._write_with_retries
        store._write_with_retries = lambda path, data, mode, **kw: "simulated lock"
        try:
            res = store.unswap_target_file(env_path, record, INDEX)
        finally:
            store._write_with_retries = original_write
        assert res["error"] == "simulated lock" and res["restored"] == []


def test_recover_swap_file_rewrites_unconditionally_and_sweeps_temp_files() -> None:
    with workspace(env_bytes=b'API_TOKEN="value 1"\nPLAIN=real\nOTHER=x\n') as (project, env_path):
        store.swap_target_file(env_path, ["API_TOKEN"], SECRETS, {})
        # A temp file _atomic_write_bytes could have left mid-rename.
        # _atomic_write_bytes names its temp files ".<name>.<random>.tmp".
        leftover = project / "..env.abc123.tmp"
        leftover.write_bytes(b"API_TOKEN=tok-abcdefgh-123456\n")
        report = store.recover_swap_file(env_path, ["API_TOKEN", "PLAIN"], INDEX, started=0)
        assert report["restored"] == ["API_TOKEN", "PLAIN"]
        assert [Path(p).name for p in report["temp_files_removed"]] == ["..env.abc123.tmp"]
        assert not leftover.exists()
        after = env_path.read_text(encoding="utf-8")
        assert 'API_TOKEN="value 1"' in after and 'PLAIN="value 3"' in after
        assert "OTHER=x" in after


# ---------------------------------------------------------------------------
# Journal and liveness
# ---------------------------------------------------------------------------

def test_journal_add_refuses_live_entry_and_replaces_stale_one() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        store.journal_add(key, ["API_TOKEN"])
        entry = _read_journal()[key]
        assert entry["pid"] == os.getpid() and entry["server_id"] == store.SERVER_ID
        assert entry["state"] == "active"
        # Same process, same server id -> live -> refused.
        try:
            store.journal_add(key, ["PLAIN"])
        except store.SwapInProgress:
            pass
        else:
            raise AssertionError("second swap of a live file was not refused")
        # Same pid, different server id: a dead predecessor that was handed
        # our pid. Stale, replaced.
        j = json.loads(store._journal_path().read_text(encoding="utf-8"))
        j["entries"][key]["server_id"] = "someone-else"
        store._journal_path().write_text(json.dumps(j), encoding="utf-8")
        store.journal_add(key, ["PLAIN"])
        assert _read_journal()[key]["names"] == ["PLAIN"]
        store.journal_remove(key)
        assert not store._journal_path().exists()


def test_liveness_uses_pid_start_time_not_pid_alone() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        store.journal_add(key, ["API_TOKEN"])
        j = json.loads(store._journal_path().read_text(encoding="utf-8"))
        e = j["entries"][key]
        # A different, currently-running process (this interpreter's parent
        # is not reliably known, so spawn a child and use its pid) whose
        # recorded start time is wrong -> the pid was reused -> stale.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            e["pid"], e["server_id"], e["pid_start"] = child.pid, "other", 1.0
            store._journal_path().write_text(json.dumps(j), encoding="utf-8")
            assert store.live_swaps() == {}
            # Correct start time -> live.
            e["pid_start"] = procs.process_start_time(child.pid)[1]
            store._journal_path().write_text(json.dumps(j), encoding="utf-8")
            if e["pid_start"] is not None:
                assert key in store.live_swaps()
        finally:
            child.kill()
            child.wait()
        store.journal_remove(key)


def test_recover_stale_swaps_restores_dead_owner_and_leaves_live_alone() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        store.swap_target_file(env_path, ["API_TOKEN"], SECRETS, {})
        store.journal_add(key, ["API_TOKEN"])
        assert store.recover_stale_swaps() == []  # our own live entry
        assert b"tok-abcdefgh-123456" in env_path.read_bytes()
        j = json.loads(store._journal_path().read_text(encoding="utf-8"))
        j["entries"][key].update({"pid": 4000000, "server_id": "gone", "pid_start": None})
        store._journal_path().write_text(json.dumps(j), encoding="utf-8")
        reports = store.recover_stale_swaps()
        assert len(reports) == 1 and reports[0]["restored"] == ["API_TOKEN"]
        assert "no longer running" in reports[0]["reason"]
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert not store._journal_path().exists()


def test_recover_stale_swaps_handles_restore_failed_state_regardless_of_pid() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        store.swap_target_file(env_path, ["PLAIN"], SECRETS, {})
        store.journal_add(key, ["PLAIN"])
        store.journal_mark_restore_failed(key)
        reports = store.recover_stale_swaps()
        assert reports and reports[0]["restored"] == ["PLAIN"]
        assert "restore had failed" in reports[0]["reason"]
        assert env_path.read_bytes() == PLACEHOLDER_ENV


def test_corrupted_journal_is_reported_not_swallowed() -> None:
    with workspace() as (project, env_path):
        store._journal_path().write_text("{oops", encoding="utf-8")
        try:
            store.recover_stale_swaps()
        except ValueError as e:
            assert "corrupted" in str(e)
        else:
            raise AssertionError("corrupted journal did not raise")
        # And the tool-level wrapper turns that into a report entry.
        reports = mcp_server._recover_swaps()
        assert reports and "swap.journal.json" in reports[0]["error"]


# ---------------------------------------------------------------------------
# run_with_env wiring
# ---------------------------------------------------------------------------

def test_refusals_happen_before_the_dialog() -> None:
    with workspace() as (project, env_path):
        with fake_dialog() as calls:
            r = mcp_server._run_with_env_impl(["x"], None, True, str(project), None, None,
                                              swap=[".env"])
            assert "background" in r["error"]
            r = mcp_server._run_with_env_impl(["x"], None, False, str(project), None, None,
                                              swap=[".env.other"])
            assert "not a registered" in r["error"]
            r = mcp_server._run_with_env_impl(["x"], None, False, str(project), ["OTHER_X"],
                                              None, swap=[".env"])
            assert "Unknown variable" in r["error"]
            # only_vars names a registered variable that is not swappable
            # here -> a contradiction, refused.
            env_path.write_bytes(b'API_TOKEN=typed\nPLAIN="value 3"\n')
            r = mcp_server._run_with_env_impl(["x"], None, False, str(project), ["API_TOKEN"],
                                              None, swap=[".env"])
            assert "cannot be swapped" in r["error"]
            # Nothing swappable at all -> refused.
            env_path.write_bytes(b"# empty\n")
            r = mcp_server._run_with_env_impl(["x"], None, False, str(project), None, None,
                                              swap=[".env"])
            assert "nothing in" in r["error"]
            assert calls == []


def test_swap_end_to_end_child_with_scrubbed_env_reads_real_value_from_file() -> None:
    """Mechanism B-when-scrubbed: the child builds its environment from an
    allowlist (no vault vars survive) and parses .env from disk. Without
    swap it can only ever see the placeholder."""
    with workspace(styles={"API_TOKEN": '"', "DB_PASSWORD": '"', "PLAIN": ""}) as (project, env_path):
        script = (
            "import os,sys,subprocess\n"
            "child_env={k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','TEMP','TMP')}\n"
            "code='''\n"
            "import re\n"
            "vals={}\n"
            "for line in open('.env',encoding='utf-8'):\n"
            "    m=re.match(r'\\\\s*(?:export\\\\s+)?(\\\\w+)\\\\s*=\\\\s*(.*)',line)\n"
            "    if m: vals[m.group(1)]=m.group(2).strip()\n"
            "print(vals['API_TOKEN']); print(vals['PLAIN'])\n"
            "'''\n"
            "r=subprocess.run([sys.executable,'-c',code],env=child_env,capture_output=True,text=True)\n"
            "print(r.stdout,end='')\n"
        )
        with fake_dialog() as calls:
            r = mcp_server._run_with_env_impl([sys.executable, "-c", script], None, False,
                                              str(project), ["API_TOKEN", "PLAIN"], None,
                                              swap=[".env"])
        assert r["applied"] is True and r["exit_code"] == 0, r
        lines = r["stdout"].splitlines()
        # Redacted on the way back -- in its as-written (quoted) form, which
        # the redactor learned from the swap -- and that is itself proof the
        # real value reached the child through the file.
        assert lines[0] == "[REDACTED:API_TOKEN (as written to .env)]"
        assert lines[1] == "[REDACTED:PLAIN]"
        assert r["swapped"] == {str(env_path): ["API_TOKEN", "PLAIN"]}
        assert "swap_restore_conflicts" not in r
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert not store._journal_path().exists()
        # The dialog was told exactly what would be written where.
        shown = calls[0]["swap"][0]
        assert (shown["path"], shown["names"], shown["skipped"]) == (
            str(env_path), ["API_TOKEN", "PLAIN"], {})
        assert shown["git_tracked"] in (None, False)


def test_swap_restores_on_command_failure_launch_error_and_interrupt() -> None:
    with workspace() as (project, env_path):
        for kwargs in ({"returncode": 3}, {"raise_exc": OSError("no such exe")},
                       {"raise_exc": mcp_server._Terminated()}):
            seen = {}

            def observe(env, cwd):
                seen["bytes"] = env_path.read_bytes()
                seen["journal"] = _read_journal()
                return ""

            with fake_dialog(), stub_run(observer=observe, **kwargs):
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
            assert b"tok-abcdefgh-123456" in seen["bytes"]
            assert str(env_path) in seen["journal"]
            assert env_path.read_bytes() == PLACEHOLDER_ENV, kwargs
            assert not store._journal_path().exists(), kwargs
            assert r["swapped"] == {str(env_path): ["API_TOKEN", "DB_PASSWORD", "PLAIN"]}


def test_swap_only_vars_scopes_the_lines_touched() -> None:
    with workspace() as (project, env_path):
        seen = {}

        def observe(env, cwd):
            seen["text"] = env_path.read_text(encoding="utf-8")
            return ""

        with fake_dialog(), stub_run(observer=observe):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), ["PLAIN"],
                                              None, swap=[".env"])
        assert "PLAIN=justletters123" in seen["text"]
        assert 'API_TOKEN="value 1"' in seen["text"]
        assert r["swapped"] == {str(env_path): ["PLAIN"]}


def test_swap_reports_restore_conflict_when_line_changed_during_run() -> None:
    with workspace() as (project, env_path):
        def observe(env, cwd):
            data = env_path.read_bytes().replace(b"PLAIN=justletters123", b"PLAIN=edited")
            env_path.write_bytes(data)
            return ""

        with fake_dialog(), stub_run(observer=observe):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"])
        assert r["swap_restore_conflicts"] == {str(env_path): ["PLAIN"]}
        assert "PLAIN" in r["swap_warning"]
        after = env_path.read_bytes()
        assert b"PLAIN=edited" in after and b'API_TOKEN="value 1"' in after
        assert not store._journal_path().exists()


def test_swap_restore_failure_keeps_journal_entry_and_next_call_recovers() -> None:
    with workspace() as (project, env_path):
        original_write = store._write_with_retries
        calls = {"n": 0}

        def failing(path, data, mode, **kw):
            calls["n"] += 1
            if calls["n"] == 1:  # the restore write (the swap itself does not retry)
                return "simulated AV lock"
            return original_write(path, data, mode, **kw)

        store._write_with_retries = failing
        try:
            with fake_dialog(), stub_run():
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
        finally:
            store._write_with_retries = original_write
        assert r["swap_restore_failed"] == {str(env_path): "simulated AV lock"}
        assert "REAL values" in r["swap_warning"]
        assert _read_journal()[str(env_path)]["state"] == "restore_failed"
        assert b"tok-abcdefgh-123456" in env_path.read_bytes()
        # Any later tool call -- here vault_status -- finishes the job.
        status = mcp_server._vault_status_impl()
        assert status["swap_recovered"][0]["restored"] == ["API_TOKEN", "DB_PASSWORD", "PLAIN"]
        # Crash recovery writes the canonical placeholder (it has no record
        # of the original line), so trailing whitespace on a line is not
        # preserved -- compare content, not bytes.
        after = env_path.read_bytes()
        for value in SECRETS.values():
            assert value.encode("utf-8") not in after
        assert b'export API_TOKEN="value 1"\r\n' in after
        assert b'  DB_PASSWORD="value 2"\r\n' in after
        assert b'PLAIN="value 3"\r\n' in after
        assert not store._journal_path().exists()


def test_verify_failed_keeps_journal_entry_so_recovery_retries() -> None:
    """The restore write succeeded but a swapped value is still in the file
    afterwards (an editor re-saved a stale buffer). That is a confirmed
    secret on disk: the journal entry must survive so the next tool call
    rewrites it -- unlike a conflict, which is a user edit and is not."""
    with workspace() as (project, env_path):
        original_write = store._write_with_retries

        def write_then_stale_editor_save(path, data, mode, **kw):
            err = original_write(path, data, mode, **kw)
            if err is None and b"value 3" in data:  # the restore write
                # Stale buffer with the real value lands after the restore.
                path.write_bytes(data.replace(b'PLAIN="value 3"', b"PLAIN=justletters123"))
            return err

        store._write_with_retries = write_then_stale_editor_save
        try:
            with fake_dialog(), stub_run():
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
        finally:
            store._write_with_retries = original_write
        assert r["swap_verify_failed"] == {str(env_path): ["PLAIN"]}
        assert "swap_restore_failed" not in r
        assert _read_journal()[str(env_path)]["state"] == "restore_failed"
        status = mcp_server._vault_status_impl()
        assert status["swap_recovered"][0]["restored"] == ["PLAIN"]
        assert b"justletters123" not in env_path.read_bytes()
        assert not store._journal_path().exists()


def test_conflict_only_releases_journal_and_preserves_user_edit() -> None:
    with workspace() as (project, env_path):
        def observe(env, cwd):
            env_path.write_bytes(env_path.read_bytes().replace(
                b"PLAIN=justletters123", b"PLAIN=user-edit"))
            return ""

        with fake_dialog(), stub_run(observer=observe):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"])
        assert r["swap_restore_conflicts"] == {str(env_path): ["PLAIN"]}
        assert not store._journal_path().exists()
        # A later recovery must NOT rewrite the user's edit.
        assert mcp_server._vault_status_impl().get("swap_recovered") is None
        assert b"PLAIN=user-edit" in env_path.read_bytes()


def test_journal_bookkeeping_failure_is_reported_separately_from_a_leak() -> None:
    with workspace() as (project, env_path):
        original_remove = store.journal_remove
        store.journal_remove = lambda key: (_ for _ in ()).throw(RuntimeError("lock stuck"))
        try:
            with fake_dialog(), stub_run():
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
        finally:
            store.journal_remove = original_remove
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert "swap_restore_failed" not in r and "swap_warning" not in r
        assert "lock stuck" in r["swap_journal_warning"]
        store.journal_remove(str(env_path))


def test_unreadable_journal_fails_closed_for_migrate_and_resync() -> None:
    with workspace() as (project, env_path):
        store._journal_path().write_text("{not json", encoding="utf-8")
        r = mcp_server._install_migrate_impl(str(env_path))
        assert "cannot tell whether" in r["error"]
        r = mcp_server._resync_targets_core()
        assert "cannot tell which targets" in r["error"]
        status = mcp_server._vault_status_impl()
        assert "swap.journal.json" in status["swap_journal_error"]
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        store._journal_path().unlink()


def test_startup_recovery_report_is_delivered_in_first_result() -> None:
    with workspace() as (project, env_path):
        mcp_server._startup_recovery.append({"path": "x", "restored": ["Y"]})
        with fake_dialog(), stub_run():
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None)
        assert r["swap_recovered"] == [{"path": "x", "restored": ["Y"]}]
        assert mcp_server._startup_recovery == []


def test_rendered_form_is_redacted_from_output() -> None:
    with workspace(styles={"DB_PASSWORD": '"'}) as (project, env_path):
        def observe(env, cwd):
            return env_path.read_text(encoding="utf-8")

        with fake_dialog(), stub_run(observer=observe):
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["DB_PASSWORD"], None, swap=[".env"])
        assert SECRETS["DB_PASSWORD"] not in r["stdout"]
        assert '\\"dq\\"' not in r["stdout"]
        assert "[REDACTED:DB_PASSWORD" in r["stdout"]


def test_resync_and_migrate_refuse_a_live_swapped_file() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        store.swap_target_file(env_path, ["API_TOKEN"], SECRETS, {})
        store.journal_add(key, ["API_TOKEN"])
        try:
            res = mcp_server._resync_targets_impl()
            assert res[key]["status"] == "swap_in_progress"
            assert b"tok-abcdefgh-123456" in env_path.read_bytes()
            res = mcp_server._install_migrate_impl(key)
            assert "swapped into it" in res["error"]
            status = mcp_server._vault_status_impl()
            assert status["swaps_in_progress"][0]["names"] == ["API_TOKEN"]
        finally:
            store.journal_remove(key)


def test_trust_signature_binds_swapped_names_and_drift_hashes_the_file() -> None:
    with workspace() as (project, env_path):
        with fake_dialog(trust_it=True) as calls, stub_run():
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["PLAIN"], None, swap=[".env"])
            assert r["applied"] and len(calls) == 1
            # Identical call auto-allows: the file was restored byte-exact,
            # so the drift hash of .env still matches.
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["PLAIN"], None, swap=[".env"])
            assert r.get("auto_allowed") is True and len(calls) == 1
            # A wider only_vars is a different signature -> dialog again.
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              ["PLAIN", "API_TOKEN"], None, swap=[".env"])
            assert not r.get("auto_allowed") and len(calls) == 2
        # Trust was granted for names=[PLAIN]. The agent appends a line for
        # a registered name that was absent, hoping the grant covers it: the
        # swappable set changes -> new signature -> no auto-allow. And the
        # file itself changed -> drift.
        with fake_dialog(trust_it=False) as calls, stub_run():
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project),
                                              None, None, swap=[".env"])
            assert not r.get("auto_allowed") and len(calls) == 1
        sig_a = trust.make_signature(["cmd"], str(project), None, None, False, None,
                                     swap=[(str(env_path), ["PLAIN"])])
        sig_b = trust.make_signature(["cmd"], str(project), None, None, False, None,
                                     swap=[(str(env_path), ["PLAIN", "API_TOKEN"])])
        sig_none = trust.make_signature(["cmd"], str(project), None, None, False, None)
        sig_empty = trust.make_signature(["cmd"], str(project), None, None, False, None, swap=[])
        assert len({sig_a, sig_b, sig_none, sig_empty}) == 4


def test_trusted_swap_run_is_revoked_when_the_env_file_changes() -> None:
    with workspace() as (project, env_path):
        with fake_dialog(trust_it=True) as calls, stub_run():
            mcp_server._run_with_env_impl(["cmd"], None, False, str(project), ["PLAIN"],
                                          None, swap=[".env"])
            env_path.write_bytes(PLACEHOLDER_ENV + b"# a harmless comment\r\n")
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), ["PLAIN"],
                                              None, swap=[".env"])
            assert len(calls) == 2
            assert "revoked" in r["trust_note"] and ".env" in r["trust_note"]


def test_swap_combined_with_materialize_cleans_both() -> None:
    with workspace() as (project, env_path):
        seen = {}

        def observe(env, cwd):
            seen["mat"] = (project / ".env.runtime").read_text(encoding="utf-8")
            seen["swap"] = env_path.read_bytes()
            return ""

        with fake_dialog(), stub_run(observer=observe):
            r = mcp_server._run_with_env_impl(["cmd"], ".env.runtime", False, str(project),
                                              ["PLAIN"], None, swap=[".env"])
        assert "PLAIN=justletters123" in seen["mat"]
        assert b"PLAIN=justletters123" in seen["swap"]
        assert not (project / ".env.runtime").exists()
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert r["applied"] is True


def test_denied_dialog_touches_nothing() -> None:
    with workspace() as (project, env_path):
        with fake_dialog(approve=False), stub_run():
            r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None, None,
                                              swap=[".env"])
        assert r == {"applied": False, "message": "Denied by user."}
        assert env_path.read_bytes() == PLACEHOLDER_ENV
        assert not store._journal_path().exists()


def test_second_server_swapping_same_file_is_refused_and_first_is_untouched() -> None:
    with workspace() as (project, env_path):
        key = str(env_path)
        # Simulate another live server's active entry (a child process).
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            store.journal_add(key, ["API_TOKEN"])
            j = json.loads(store._journal_path().read_text(encoding="utf-8"))
            j["entries"][key].update({"pid": child.pid, "server_id": "other",
                                      "pid_start": procs.process_start_time(child.pid)[1]})
            store._journal_path().write_text(json.dumps(j), encoding="utf-8")
            with fake_dialog(), stub_run():
                r = mcp_server._run_with_env_impl(["cmd"], None, False, str(project), None,
                                                  None, swap=[".env"])
            assert "another llm-env-vault session" in r["error"]
            assert env_path.read_bytes() == PLACEHOLDER_ENV
            assert _read_journal()[key]["pid"] == child.pid
        finally:
            child.kill()
            child.wait()
            store.journal_remove(key)


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

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
