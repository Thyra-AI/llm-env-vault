"""
Recovery of swaps written by 1.6.0-1.7.x, after `swap=` itself is gone.

`run_with_env(swap=)` is retired in 2.0.0. Its recovery half is not: a user
can upgrade while a .env on their disk still holds real values, because a
1.6-1.7 server crashed mid-swap or because one is STILL RUNNING a command
in another session right now. Those two cases pull in opposite directions
and both have to hold:

  dead owner  -> rewrite the file unconditionally. Nothing can now tell a
                 value the vault wrote from one the user typed, and leaving
                 a secret on disk is the worse error.
  live owner  -> do not touch it. Another chat's command is reading that
                 file; restoring under it corrupts the run.

The 1.7.1 suite covered all of this, but it built its state by CALLING the
writers (`store.swap_target_file`, `store.journal_add`). Those are deleted
in 2.0, so this suite builds the same state from frozen golden bytes in
tests/fixtures/legacy_swap/ instead -- see that directory's README. Nothing
here may call a swap writer; that is the property that keeps this file
alive after the removal.

Runs under pytest or standalone (`python tests/test_legacy_swap_recovery.py`).
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
from vault_lib import gui, procs, store  # noqa: E402

TEST_PASSWORD = "legacy-recovery-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_swap"
PLACEHOLDER_ENV = (FIXTURES / "placeholder.env").read_bytes()
SWAPPED_ENV = (FIXTURES / "swapped.env").read_bytes()

# The values frozen into swapped.env, and the index that maps them back to
# placeholders. Kept in sync with the fixture README, not with any writer.
SECRETS = {
    "API_TOKEN": "tok-abcdefgh-123456",
    "DB_PASSWORD": "p$ss w#rd 'quoted' \"dq\"",
    "PLAIN": "justletters123",
}
INDEX = {"API_TOKEN": 1, "DB_PASSWORD": 2, "PLAIN": 3}
NAMES = sorted(SECRETS)

DEAD_PID = 4000000  # far above any live pid; paired with server_id "gone"


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


@contextlib.contextmanager
def workspace(env_bytes=SWAPPED_ENV, register=True):
    """A v2 vault plus a project whose registered .env is mid-swap."""
    with tempfile.TemporaryDirectory(prefix="llm_legacy_swap_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        project = tmp_path / "project"
        project.mkdir()
        env_path = project / ".env"
        env_path.write_bytes(env_bytes)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(SECRETS))
            store.save_index(dict(INDEX))
            if register:
                store.add_target(str(env_path), NAMES)
            yield project, env_path
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def _write_journal(env_path: Path, *, state="active", pid=DEAD_PID,
                   server_id="gone", pid_start=None, names=None) -> None:
    """Install a journal built from the golden fixture, with the path key
    substituted and the liveness fields set for this scenario.

    Deliberately not `journal_add`: that writer is gone in 2.0, and a test
    that needed it would not survive the removal it exists to guard.
    """
    source = "journal_restore_failed.json" if state == "restore_failed" else "journal_active.json"
    doc = json.loads((FIXTURES / source).read_text(encoding="utf-8"))
    entry = dict(doc["entries"]["__ENV_PATH__"])
    entry.update({"pid": pid, "server_id": server_id, "pid_start": pid_start})
    if names is not None:
        entry["names"] = sorted(names)
    assert entry["state"] == state, f"fixture {source} is not state={state}"
    doc["entries"] = {str(env_path): entry}
    store._journal_path().write_text(json.dumps(doc), encoding="utf-8")


def _journal_entries() -> dict:
    p = store._journal_path()
    return json.loads(p.read_text(encoding="utf-8"))["entries"] if p.exists() else {}


def _norm(blob: bytes) -> bytes:
    """Drop trailing horizontal whitespace from every line.

    Crash recovery re-derives each managed line from the index
    (`_placeholder_line` -> `{indent}{export}NAME="value N"`) because,
    unlike the normal-exit restore, it has no record of what the line
    looked like. Indent, `export `, terminator, comments and unmanaged
    lines survive byte-exactly; trailing spaces do not. See
    test_crash_recovery_normalizes_trailing_whitespace.
    """
    return b"\n".join(line.rstrip(b" \t") for line in blob.replace(b"\r\n", b"\n").split(b"\n"))


def _assert_fully_restored(env_path: Path) -> None:
    """Every property a caller actually depends on after recovery."""
    after = env_path.read_bytes()
    for value in SECRETS.values():
        assert value.encode("utf-8") not in after, f"{value!r} survived recovery"
    for name, number in INDEX.items():
        assert f'{name}="value {number}"'.encode("utf-8") in after
    assert _norm(after) == _norm(PLACEHOLDER_ENV)
    # Traits recovery does preserve exactly.
    assert after.count(b"\r\n") == PLACEHOLDER_ENV.count(b"\r\n")
    assert b"export API_TOKEN=" in after
    assert b'\n  DB_PASSWORD=' in after.replace(b"\r\n", b"\n")
    assert b"# project config" in after and b"OTHER=untouched" in after


@contextlib.contextmanager
def _stub_install_dialog(approve=False):
    """Capture what install_migrate would show a human, without a window."""
    original = gui.install_dialog
    seen = {}

    def fake(target, to_migrate, other_owner, also_register=None, sensitive_names=None):
        seen["to_migrate"] = list(to_migrate)
        seen["also_register"] = list(also_register or [])
        return {"approved": approve, "partial_failure": None}

    gui.install_dialog = fake
    try:
        yield seen
    finally:
        gui.install_dialog = original


# ---------------------------------------------------------------------------
# The fixture itself
# ---------------------------------------------------------------------------

def test_fixture_is_a_real_swap_not_a_transcription() -> None:
    """Guards the fixture, not the code: if these stop holding, the golden
    bytes were edited by hand and no longer represent what 1.7.x wrote."""
    assert b'API_TOKEN="value 1"' in PLACEHOLDER_ENV
    for value in SECRETS.values():
        assert value.encode("utf-8") in SWAPPED_ENV or value.split()[0].encode() in SWAPPED_ENV
    # Byte-level traits the restore has to preserve.
    assert b"\r\n" in PLACEHOLDER_ENV and b"export " in PLACEHOLDER_ENV
    assert b"OTHER=untouched" in PLACEHOLDER_ENV and b"OTHER=untouched" in SWAPPED_ENV
    assert PLACEHOLDER_ENV != SWAPPED_ENV
    doc = json.loads((FIXTURES / "journal_active.json").read_text(encoding="utf-8"))
    assert doc["version"] == 1, "journal format version is part of what this pins"
    entry = doc["entries"]["__ENV_PATH__"]
    assert set(entry) == {"names", "pid", "pid_start", "server_id", "started", "state"}


# ---------------------------------------------------------------------------
# Dead owner: restore
# ---------------------------------------------------------------------------

def test_dead_owner_is_restored_byte_exactly() -> None:
    with workspace() as (project, env_path):
        _write_journal(env_path)
        reports = store.recover_stale_swaps()
        assert len(reports) == 1
        assert reports[0]["restored"] == NAMES
        assert "no longer running" in reports[0]["reason"]
        _assert_fully_restored(env_path)
        assert not store._journal_path().exists()


def test_crash_recovery_normalizes_trailing_whitespace() -> None:
    """A documented limit of CRASH recovery, distinct from the normal-exit
    restore: `compute_unswap_bytes` puts back the line it recorded, but
    `recover_swap_file` has no record and rebuilds the line from the index,
    so trailing spaces are lost. The fixture's DB_PASSWORD line ends in two
    spaces precisely to hold this.

    Consequence: trust drift-hashes `.env`, so a trusted docker/compose
    command is revoked after a crash recovery and the human re-approves it.
    That fails safe, which is why this is pinned rather than fixed. Do not
    "fix" it by making recovery preserve the bytes it never captured.
    """
    assert b'"value 2"  \r\n' in PLACEHOLDER_ENV, "fixture lost its trailing-space line"
    with workspace() as (project, env_path):
        _write_journal(env_path)
        store.recover_stale_swaps()
        after = env_path.read_bytes()
        assert b'"value 2"\r\n' in after          # trailing spaces gone
        assert b'"value 2"  \r\n' not in after
        assert after != PLACEHOLDER_ENV           # so: not byte-exact
        assert _norm(after) == _norm(PLACEHOLDER_ENV)  # but identical otherwise


def test_restore_sweeps_the_atomic_write_temp_file() -> None:
    """A crash between _atomic_write_bytes' write and its rename leaves a
    temp file holding the same real values."""
    with workspace() as (project, env_path):
        leftover = project / "..env.abc123.tmp"
        leftover.write_bytes(SWAPPED_ENV)
        _write_journal(env_path)
        reports = store.recover_stale_swaps()
        assert [Path(p).name for p in reports[0]["temp_files_removed"]] == ["..env.abc123.tmp"]
        assert not leftover.exists()


def test_no_secret_survives_recovery_anywhere_in_the_project() -> None:
    """The property that actually matters, asserted over the whole tree."""
    with workspace() as (project, env_path):
        (project / "..env.xyz.tmp").write_bytes(SWAPPED_ENV)
        _write_journal(env_path)
        store.recover_stale_swaps()
        for path in project.rglob("*"):
            if path.is_file():
                blob = path.read_bytes()
                for value in SECRETS.values():
                    assert value.encode("utf-8") not in blob, f"{value!r} left in {path}"


# ---------------------------------------------------------------------------
# Live owner: hands off
# ---------------------------------------------------------------------------

def test_live_owner_is_left_alone_and_reported() -> None:
    """The case a naive removal gets wrong. Our own pid with our own
    server_id is by definition a live owner."""
    with workspace() as (project, env_path):
        _write_journal(env_path, pid=os.getpid(), server_id=store.SERVER_ID,
                       pid_start=procs.own_start_time())
        assert store.recover_stale_swaps() == []
        assert env_path.read_bytes() == SWAPPED_ENV  # untouched, still holding real values
        assert str(env_path) in _journal_entries()
        assert str(env_path) in {str(k) for k in store.live_swaps()}


def test_liveness_uses_pid_start_time_so_a_reused_pid_is_stale() -> None:
    with workspace() as (project, env_path):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            # Right pid, wrong start time -> the pid was recycled -> stale.
            _write_journal(env_path, pid=child.pid, server_id="other", pid_start=1.0)
            assert store.live_swaps() == {}
            # Right pid, right start time -> genuinely live.
            actual_start = procs.process_start_time(child.pid)[1]
            if actual_start is not None:
                _write_journal(env_path, pid=child.pid, server_id="other",
                               pid_start=actual_start)
                assert str(env_path) in {str(k) for k in store.live_swaps()}
        finally:
            child.kill()
            child.wait()


def test_force_overrides_a_live_owner() -> None:
    """`--recover --force` is the human's exit when a pid exists but cannot
    be inspected. Worst case is clobbering a live run -- never a leak."""
    with workspace() as (project, env_path):
        _write_journal(env_path, pid=os.getpid(), server_id=store.SERVER_ID,
                       pid_start=procs.own_start_time())
        reports = store.recover_stale_swaps(force=True)
        assert len(reports) == 1 and reports[0]["restored"] == NAMES
        assert reports[0]["reason"] == "forced"
        _assert_fully_restored(env_path)


# ---------------------------------------------------------------------------
# restore_failed: act regardless of pid
# ---------------------------------------------------------------------------

def test_restore_failed_is_recovered_even_though_the_owner_is_alive() -> None:
    with workspace() as (project, env_path):
        _write_journal(env_path, state="restore_failed", pid=os.getpid(),
                       server_id=store.SERVER_ID, pid_start=procs.own_start_time())
        reports = store.recover_stale_swaps()
        assert reports and reports[0]["restored"] == NAMES
        assert "restore had failed" in reports[0]["reason"]
        _assert_fully_restored(env_path)


# ---------------------------------------------------------------------------
# Degraded inputs
# ---------------------------------------------------------------------------

def test_corrupted_journal_is_reported_not_swallowed() -> None:
    with workspace() as (project, env_path):
        store._journal_path().write_text("{oops", encoding="utf-8")
        try:
            store.recover_stale_swaps()
        except ValueError as e:
            assert "corrupted" in str(e)
        else:
            raise AssertionError("corrupted journal did not raise")
        reports = mcp_server._recover_swaps()
        assert reports and "swap.journal.json" in reports[0]["error"]
        # A file that may be mid-swap with nobody watching must not be
        # reported as "nothing is swapped".
        live, error = mcp_server._live_swap_paths()
        assert live == {} and error


def test_unreadable_index_writes_the_pending_marker_rather_than_leaking() -> None:
    with workspace() as (project, env_path):
        store.INDEX_FILE.write_text("{ not json", encoding="utf-8")
        _write_journal(env_path)
        reports = store.recover_stale_swaps()
        assert reports and reports[0].get("pending_index")
        after = env_path.read_bytes()
        for value in SECRETS.values():
            assert value.encode("utf-8") not in after
        assert b'"value ?"' in after


def test_missing_target_file_is_reported_not_fatal() -> None:
    with workspace() as (project, env_path):
        _write_journal(env_path)
        env_path.unlink()
        reports = store.recover_stale_swaps()
        assert reports and reports[0]["missing"] is True


# ---------------------------------------------------------------------------
# No journal at all: the last-resort path
# ---------------------------------------------------------------------------

def test_without_a_journal_migrate_treats_real_values_as_secrets_to_revault() -> None:
    """Journal deleted or never written, .env still full of real values.
    Nothing can restore it automatically -- re-running install_migrate is
    the documented recovery, so it must classify those lines as real
    secrets rather than skipping them as placeholders."""
    with workspace(register=False) as (project, env_path):
        assert not store._journal_path().exists()
        with _stub_install_dialog(approve=False) as seen:
            mcp_server._install_migrate_impl(str(env_path))
        migrated = dict(seen["to_migrate"])
        for name in NAMES:
            assert name in migrated, f"{name} would have been left on disk"
            assert migrated[name] == SECRETS[name]


def test_placeholder_file_is_not_mistaken_for_real_secrets() -> None:
    """The converse guard: a healthy placeholder-only file must never have
    its placeholders re-vaulted, or migrate would store the literal string
    `value 1` as API_TOKEN's secret. This is the guard at mcp_server.py:834,
    and the one that typed placeholders must not break in C5.

    `OTHER=untouched` is an ordinary unmanaged line and IS legitimately
    offered for migration -- that is migrate doing its job, not a leak.
    """
    with workspace(env_bytes=PLACEHOLDER_ENV, register=False) as (project, env_path):
        with _stub_install_dialog(approve=False) as seen:
            mcp_server._install_migrate_impl(str(env_path))
        offered = dict(seen["to_migrate"])
        for name in NAMES:
            assert name not in offered, f"{name}'s placeholder would be vaulted as its value"
        assert offered == {"OTHER": "untouched"}


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
