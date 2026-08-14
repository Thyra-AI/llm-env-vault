"""
Regression suite for vault_lib/trust.py and the trust-cache wiring inside
mcp_server._run_with_env_impl.

Covers, end to end, every finding from the adversarial code review of the
"trust this command" feature:

  B1 - only_vars=[] and only_vars=None hashed to the same signature,
       letting a zero-secret grant auto-allow a full-vault run.
  B2 - `background` wasn't part of the signature, letting a trusted
       foreground run be replayed detached.
  B3 - cached secrets were never checked against the vault itself, so a
       rotated/added/removed secret kept serving stale cached values.
  B4 - referenced-file hashes were taken *after* the human clicked
       Allow, not before the dialog opened, so trust could bind to
       content nobody actually reviewed.
  B5 - a relative command argument was checked against this *server
       process's* cwd as a fallback, not just the `cwd` the command
       actually runs in.
  N1 - the tool result silently dropped the "trust was just revoked"
       explanation when the human re-approved in the same dialog,
       showing only the fresh-grant note.

Plus permanent coverage for the drift-detection core (check()'s math,
_candidate_paths' dedup) that the review verified clean, and for the two
new unmonitored-file warnings (oversized/unreadable files, the
_MAX_HASHED_FILES cap) added alongside the fixes.

Every test runs against an isolated, throwaway vault created under a
temp directory -- store.SALT_FILE / SECRETS_FILE / INDEX_FILE / ENV_FILE
are redirected there for the duration of each test and restored
afterward, so nothing here ever reads or writes this repo's real
vault.enc / vault.salt / vault_index.json / llm.env. gui.unlock_for_run_dialog
is monkeypatched per-test so no real Tkinter window ever opens.

Runs under pytest (`pytest test_trust.py -q`) or standalone
(`python test_trust.py`), matching test_install_migrate_robustness.py.
"""
import contextlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from vault_lib import gui, store, trust  # noqa: E402
REPO_ROOT = Path(__file__).parent  # noqa: E402

TEST_PASSWORD = "regression-test-password-123"
BASE_SECRETS = {"DOCKER_TEST_TOKEN": "tok-abc-123", "OTHER_SECRET": "other-xyz-789"}


# ---------------------------------------------------------------------------
# Isolation helpers
# ---------------------------------------------------------------------------

def _isolate_store_paths(tmp_dir: Path) -> dict:
    originals = {
        "SALT_FILE": store.SALT_FILE,
        "SECRETS_FILE": store.SECRETS_FILE,
        "INDEX_FILE": store.INDEX_FILE,
        "ENV_FILE": store.ENV_FILE,
    }
    store.SALT_FILE = tmp_dir / "vault.salt"
    store.SECRETS_FILE = tmp_dir / "vault.enc"
    store.INDEX_FILE = tmp_dir / "vault_index.json"
    store.ENV_FILE = tmp_dir / "llm.env"
    return originals


def _restore_store_paths(originals: dict) -> None:
    for name, value in originals.items():
        setattr(store, name, value)


def _reset_trust_state() -> None:
    trust._trusted.clear()
    trust._cached_secrets.clear()
    trust._cache_keys.clear()
    trust._cached_vault_fingerprint = None


@contextlib.contextmanager
def isolated_vault(secrets=None):
    """Redirects the vault's on-disk files into a fresh temp dir, creates
    a real (small) vault there with the given secrets (BASE_SECRETS by
    default), and resets the trust module's global state before and
    after -- so tests never leak state into each other or into the real
    repo vault."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_test_") as tmp:
        tmp_path = Path(tmp)
        originals = _isolate_store_paths(tmp_path)
        _reset_trust_state()
        try:
            store.create_secrets_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, secrets)
            store.save_index({name: i + 1 for i, name in enumerate(sorted(secrets))})
            yield tmp_path
        finally:
            _reset_trust_state()
            _restore_store_paths(originals)


@contextlib.contextmanager
def fake_dialog(respond):
    """Monkeypatches gui.unlock_for_run_dialog for the duration of the
    block. `respond(command_str, materialize_path, only_vars, trust_note)`
    must return the outcome dict {"secrets": ..., "trust": ...}. Yields
    the list of calls made (each a dict of the kwargs received), so tests
    can assert exactly how many times -- and with what -- the dialog was
    invoked."""
    original = gui.unlock_for_run_dialog
    calls = []

    def wrapper(command_str, materialize_path=None, only_vars=None, trust_note=None):
        calls.append({"command_str": command_str, "materialize_path": materialize_path,
                       "only_vars": only_vars, "trust_note": trust_note})
        return respond(command_str, materialize_path, only_vars, trust_note)

    gui.unlock_for_run_dialog = wrapper
    try:
        yield calls
    finally:
        gui.unlock_for_run_dialog = original


def _allow(trust_it=True, secrets=None):
    """A fake_dialog `respond` that always allows, optionally checking
    the trust checkbox."""
    def respond(command_str, materialize_path, only_vars, trust_note):
        return {"secrets": dict(secrets) if secrets is not None else dict(BASE_SECRETS),
                "trust": trust_it}
    return respond


def _deny():
    def respond(command_str, materialize_path, only_vars, trust_note):
        return {"secrets": None, "trust": False}
    return respond


def _py(*extra_args) -> list:
    return [sys.executable, "-c", "print('ok')", *extra_args]


def _fake_cmd(*extra_args) -> list:
    """A command that is never actually executed -- only fed to trust's
    hashing helpers directly. Unlike _py(), command[0] here does NOT
    resolve to a real file, so tests using this can assert on the exact
    set of tracked files without sys.executable (a real, absolute,
    always-present file) showing up as an incidental extra entry."""
    return ["definitely-not-a-real-executable-xyzzy", *extra_args]


# ---------------------------------------------------------------------------
# Core drift-detection logic (verified clean by review; locked in here)
# ---------------------------------------------------------------------------

def test_check_never_trusted_falls_back_with_no_reason() -> None:
    with isolated_vault():
        sig = trust.make_signature(_py(), None, None, None, False)
        ok, reason = trust.check(sig, _py(), None)
        assert ok is False and reason is None


def test_check_true_for_unchanged_trusted_signature() -> None:
    with isolated_vault():
        sig = trust.make_signature(_py(), None, None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(_py(), None))
        trust.cache_secrets(sig, dict(BASE_SECRETS))
        ok, reason = trust.check(sig, _py(), None)
        assert ok is True and reason is None


def test_check_detects_content_change() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "ref.txt"
        ref.write_text("v1")
        cmd = _py(str(ref))
        sig = trust.make_signature(cmd, str(tmp), None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(cmd, str(tmp)))
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        ref.write_text("v2 -- different content")
        ok, reason = trust.check(sig, cmd, str(tmp))
        assert ok is False
        assert reason is not None and str(ref) in reason and "changed" in reason.lower()
        # Revocation is one-shot: the entry is gone, not just "currently mismatched".
        assert sig not in trust._trusted


def test_check_detects_disappearance() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "ref.txt"
        ref.write_text("v1")
        cmd = _py(str(ref))
        sig = trust.make_signature(cmd, str(tmp), None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(cmd, str(tmp)))
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        ref.unlink()
        ok, reason = trust.check(sig, cmd, str(tmp))
        assert ok is False and reason is not None and str(ref) in reason


def test_check_detects_new_file_appearing() -> None:
    with isolated_vault() as tmp:
        # Argument names a file that does NOT exist at approval time --
        # referenced_file_hashes simply won't track it (is_file() is False).
        ref = tmp / "appears_later.txt"
        cmd = _fake_cmd(str(ref))
        sig = trust.make_signature(cmd, str(tmp), None, None, False)
        approved_hashes = trust.referenced_file_hashes(cmd, str(tmp))
        assert approved_hashes == {}, "file shouldn't be tracked before it exists"
        trust.trust(sig, approved_hashes)
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        ref.write_text("now it exists")
        ok, reason = trust.check(sig, cmd, str(tmp))
        assert ok is False and reason is not None and str(ref) in reason


def test_check_message_lists_all_changed_files_for_multi_file_command() -> None:
    with isolated_vault() as tmp:
        a, b = tmp / "a.txt", tmp / "b.txt"
        a.write_text("a1")
        b.write_text("b1")
        cmd = _py(str(a), str(b))
        sig = trust.make_signature(cmd, str(tmp), None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(cmd, str(tmp)))
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        a.write_text("a2")  # only `a` changes; `b` stays identical
        ok, reason = trust.check(sig, cmd, str(tmp))
        assert ok is False
        assert str(a) in reason and str(b) not in reason, (
            "only the file that actually changed should be named", reason)


def test_candidate_paths_dedups_same_file_referenced_twice() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "dup.txt"
        ref.write_text("content")
        # Same file named twice: absolute, and relative to cwd.
        cmd = _fake_cmd(str(ref), "dup.txt")
        hashes = trust.referenced_file_hashes(cmd, str(tmp))
        assert len(hashes) == 1, f"expected exactly one entry, got {hashes}"


# ---------------------------------------------------------------------------
# Executable-planting: the program itself (argv[0]), not just its arguments,
# must be resolved (PATH/PATHEXT-aware) and drift-monitored -- otherwise a
# bare command name like "python" is invisible to _candidate_paths and a
# decoy binary planted at that name after trust is granted goes undetected.
# ---------------------------------------------------------------------------

def test_argv0_resolved_via_path_is_hashed_and_monitored() -> None:
    with isolated_vault() as tmp:
        exe = tmp / "fakepy_test_tool.exe"
        exe.write_bytes(b"not a real executable, just bytes to hash")
        cmd = ["fakepy_test_tool", "some", "args"]
        hashes = trust.referenced_file_hashes(cmd, str(tmp))
        assert str(exe.resolve()) in hashes, (
            f"REGRESSION: argv0 resolved via PATH/PATHEXT was not hashed/monitored, "
            f"got {hashes}")


def test_argv0_content_change_revokes_trust() -> None:
    with isolated_vault() as tmp:
        exe = tmp / "fakepy_test_tool.exe"
        exe.write_bytes(b"version 1")
        cmd = ["fakepy_test_tool"]
        sig = trust.make_signature(cmd, str(tmp), None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(cmd, str(tmp)))
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        exe.write_bytes(b"version 2 -- a planted decoy binary")
        ok, reason = trust.check(sig, cmd, str(tmp))
        assert ok is False, (
            "REGRESSION: planting a decoy at the resolved argv0 path did not "
            "revoke trust")
        assert reason is not None and "changed" in reason.lower()


def test_unresolvable_argv0_flagged_in_unmonitored_warning() -> None:
    with isolated_vault() as tmp:
        cmd = _fake_cmd()  # "definitely-not-a-real-executable-xyzzy" -- guaranteed unresolvable
        warning = trust.unmonitored_file_warning(cmd, str(tmp))
        assert warning is not None, (
            "REGRESSION: an argv0 that can't be resolved to a file should be "
            "disclosed, not silently unflagged")
        assert "xyzzy" in warning and "not" in warning.lower() and "drift-monitored" in warning.lower()


# ---------------------------------------------------------------------------
# B1: only_vars=[] vs only_vars=None must NOT share a signature
# ---------------------------------------------------------------------------

def test_b1_signature_level_empty_list_differs_from_none() -> None:
    sig_none = trust.make_signature(_py(), None, None, None, False)
    sig_empty = trust.make_signature(_py(), None, [], None, False)
    assert sig_none != sig_empty


def test_b1_integration_zero_secret_grant_does_not_auto_allow_full_vault_run() -> None:
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_allow(trust_it=True)) as calls:
            r_empty = mcp_server._run_with_env_impl(list(cmd), None, False, None, [])
            assert r_empty.get("applied") is True
            assert len(calls) == 1

            r_full = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert len(calls) == 2, (
                "REGRESSION (B1): only_vars=None auto-allowed off an only_vars=[] "
                "grant without re-prompting")
            assert not r_full.get("auto_allowed")


def test_b1_duplicate_only_vars_entries_normalize_the_same_as_deduped() -> None:
    sig_dup = trust.make_signature(_py(), None, ["A", "A", "B"], None, False)
    sig_clean = trust.make_signature(_py(), None, ["B", "A"], None, False)
    assert sig_dup == sig_clean


# ---------------------------------------------------------------------------
# B2: background must be part of the signature
# ---------------------------------------------------------------------------

def test_b2_signature_level_background_differs() -> None:
    sig_fg = trust.make_signature(_py(), None, None, None, False)
    sig_bg = trust.make_signature(_py(), None, None, None, True)
    assert sig_fg != sig_bg


def test_b2_integration_foreground_grant_does_not_auto_allow_background_run() -> None:
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_allow(trust_it=True)) as calls:
            r_fg = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert r_fg.get("applied") is True
            assert len(calls) == 1

            r_bg = mcp_server._run_with_env_impl(list(cmd), None, True, None, None)
            assert len(calls) == 2, (
                "REGRESSION (B2): background=True auto-allowed off a foreground "
                "grant without re-prompting")
            assert not r_bg.get("auto_allowed")
            assert r_bg.get("started") is True  # background run still actually worked


# ---------------------------------------------------------------------------
# B3: a vault change must invalidate the whole cache, not serve stale secrets
# ---------------------------------------------------------------------------

def test_b3_vault_change_drops_entire_cache_and_reprompts() -> None:
    with isolated_vault() as tmp:
        cmd1 = _py()
        cmd2 = _py("--second-command-marker")
        with fake_dialog(_allow(trust_it=True)) as calls:
            mcp_server._run_with_env_impl(list(cmd1), None, False, None, None)
            mcp_server._run_with_env_impl(list(cmd2), None, False, None, None)
            assert len(calls) == 2
            assert trust.has_cached_secrets()

            # Rotate a secret through the real store API (not a raw file
            # mutation) -- this is exactly what add_secret/remove_secret do.
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "NEW_ONE": "rotated"})

            r1 = mcp_server._run_with_env_impl(list(cmd1), None, False, None, None)
            assert len(calls) == 3, (
                "REGRESSION (B3): a rotated vault still served a cached, "
                "pre-rotation secret set")
            assert not r1.get("auto_allowed")
            assert "vault changed" in (r1.get("trust_note") or "").lower()

            # The *other* previously-trusted command must also need
            # re-approval now -- the whole cache was stale, not just cmd1.
            r2 = mcp_server._run_with_env_impl(list(cmd2), None, False, None, None)
            assert len(calls) == 4, (
                "REGRESSION (B3): only the touched command's trust was revoked, "
                "not the whole (now-stale) cache")


# ---------------------------------------------------------------------------
# B4: referenced-file hashes must be taken before the dialog opens
# ---------------------------------------------------------------------------

def test_b4_hash_taken_before_dialog_not_after_allow_click() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "compose.yml"
        ref.write_text("version-1-content")
        cmd = _py(str(ref))

        def respond_and_mutate(command_str, materialize_path, only_vars, trust_note):
            # Simulates the file changing while the dialog sits open on
            # screen, *before* the human clicks Allow.
            ref.write_text("version-2-content -- changed while dialog was open")
            return {"secrets": dict(BASE_SECRETS), "trust": True}

        with fake_dialog(respond_and_mutate) as calls:
            r1 = mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)
            assert r1.get("applied") is True
            assert len(calls) == 1

            # File is now at "version-2" and hasn't changed again since.
            # If trust bound to "version-2" (hashed after Allow), this
            # would incorrectly auto-allow. It must instead detect that
            # "version-2" != the "version-1" hash taken before the dialog
            # opened, and fall back to the dialog again.
            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)
            assert len(calls) == 2, (
                "REGRESSION (B4): trust bound to file content read AFTER the "
                "dialog closed, not before it opened")
            assert not r2.get("auto_allowed")
            assert "revoked" in (r2.get("trust_note") or "").lower()


# ---------------------------------------------------------------------------
# B5: relative args must resolve against the given cwd, not the server's own
# ---------------------------------------------------------------------------

def test_b5_relative_arg_ignores_servers_own_cwd() -> None:
    with isolated_vault() as tmp, tempfile.TemporaryDirectory(prefix="fake_server_cwd_") as fake_server_cwd:
        # A file that exists relative to THIS PROCESS's own cwd, which we
        # deliberately point somewhere OTHER than `tmp` -- the cwd the
        # command is claimed to actually run in.
        bogus_name = "only_here_in_fake_server_cwd.txt"
        (Path(fake_server_cwd) / bogus_name).write_text("should never be tracked")
        assert not (tmp / bogus_name).is_file()

        original_cwd = os.getcwd()
        os.chdir(fake_server_cwd)
        try:
            cmd = _fake_cmd(bogus_name)
            hashes = trust.referenced_file_hashes(cmd, str(tmp))
        finally:
            os.chdir(original_cwd)
        assert hashes == {}, (
            f"REGRESSION (B5): relative arg resolved against the server's own "
            f"cwd instead of the given cwd -- got {hashes}")


def test_b5_relative_arg_still_resolves_against_the_given_cwd() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "in_project.txt"
        ref.write_text("hi")
        cmd = _fake_cmd("in_project.txt")
        hashes = trust.referenced_file_hashes(cmd, str(tmp))
        assert len(hashes) == 1 and str(ref.resolve()) in hashes


def test_b5_absolute_arg_still_works_regardless_of_cwd() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "abs.txt"
        ref.write_text("hi")
        cmd = _fake_cmd(str(ref))
        hashes = trust.referenced_file_hashes(cmd, None)  # cwd=None (server default)
        assert len(hashes) == 1 and str(ref.resolve()) in hashes


# ---------------------------------------------------------------------------
# N1: the "trust was revoked" reason must survive into the tool result,
# not just the (now-closed) dialog, when the human re-grants trust.
# ---------------------------------------------------------------------------

def test_n1_result_mentions_both_revocation_and_fresh_grant() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "ref.txt"
        ref.write_text("v1")
        cmd = _py(str(ref))
        with fake_dialog(_allow(trust_it=True)) as calls:
            mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)

            ref.write_text("v2")
            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)
            note = r2.get("trust_note", "")
            assert "revoked" in note.lower(), (
                "REGRESSION (N1): the tool result dropped the revocation "
                f"explanation, only the dialog saw it. Got: {note!r}")
            assert "now trusted" in note.lower(), (
                f"result should also confirm the fresh grant. Got: {note!r}")
            # And the dialog itself was shown the revocation note too.
            assert calls[-1]["trust_note"] is not None and "revoked" in calls[-1]["trust_note"].lower()


def test_n1_denial_after_revocation_still_surfaces_the_reason() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "ref.txt"
        ref.write_text("v1")
        cmd = _py(str(ref))
        with fake_dialog(_allow(trust_it=True)):
            mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)

        ref.write_text("v2")
        with fake_dialog(_deny()):
            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)
            assert r2.get("applied") is False
            assert "revoked" in (r2.get("trust_note") or "").lower()


# ---------------------------------------------------------------------------
# Disclosure/injection desync: unlock_for_run_dialog's "Will expose N
# variable(s)" list (built from vault_index.json) must not silently
# under-report what run_with_env actually injects (built from vault.enc),
# if the two have ever diverged. _disclosure_mismatch is pure/Tkinter-free,
# so it's tested directly here rather than through a real dialog.
# ---------------------------------------------------------------------------

def test_disclosure_matches_when_index_and_vault_agree() -> None:
    assert gui._disclosure_mismatch(["A", "B"], ["A", "B"]) is None
    assert gui._disclosure_mismatch([], []) is None


def test_disclosure_mismatch_detects_undisclosed_extra_secret() -> None:
    msg = gui._disclosure_mismatch(["A"], ["A", "UNDISCLOSED"])
    assert msg is not None and "UNDISCLOSED" in msg


def test_disclosure_mismatch_detects_disclosed_but_missing_secret() -> None:
    msg = gui._disclosure_mismatch(["A", "GHOST"], ["A"])
    assert msg is not None and "GHOST" in msg


# ---------------------------------------------------------------------------
# Unmonitored-file warnings (new alongside the fixes)
# ---------------------------------------------------------------------------

def test_oversized_file_produces_unmonitored_warning() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "big.bin"
        ref.write_bytes(b"x" * 100)
        cmd = _py(str(ref))
        original_cap = trust._MAX_HASH_BYTES
        trust._MAX_HASH_BYTES = 10  # pretend 100 bytes is "too large"
        try:
            hashes = trust.referenced_file_hashes(cmd, str(tmp))
            assert hashes == {}, "oversized file must not be hashed"
            warning = trust.unmonitored_file_warning(cmd, str(tmp))
            assert warning is not None and str(ref) in warning and "large" in warning.lower()
        finally:
            trust._MAX_HASH_BYTES = original_cap


def test_file_count_over_cap_produces_truncation_warning() -> None:
    with isolated_vault() as tmp:
        files = []
        for i in range(4):
            f = tmp / f"f{i}.txt"
            f.write_text(str(i))
            files.append(str(f))
        cmd = _py(*files)
        original_cap = trust._MAX_HASHED_FILES
        trust._MAX_HASHED_FILES = 2
        try:
            hashes = trust.referenced_file_hashes(cmd, str(tmp))
            assert len(hashes) == 2
            warning = trust.unmonitored_file_warning(cmd, str(tmp))
            assert warning is not None and "more than 2" in warning.lower()
        finally:
            trust._MAX_HASHED_FILES = original_cap


def test_no_warning_when_nothing_is_unmonitored() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "small.txt"
        ref.write_text("fine")
        cmd = _py(str(ref))
        assert trust.unmonitored_file_warning(cmd, str(tmp)) is None


def test_trust_note_includes_unmonitored_warning_on_grant() -> None:
    with isolated_vault() as tmp:
        ref = tmp / "big.bin"
        ref.write_bytes(b"x" * 100)
        cmd = _py(str(ref))
        original_cap = trust._MAX_HASH_BYTES
        trust._MAX_HASH_BYTES = 10
        try:
            with fake_dialog(_allow(trust_it=True)):
                r = mcp_server._run_with_env_impl(list(cmd), None, False, str(tmp), None)
                note = r.get("trust_note", "")
                assert "unreadable to monitor" in note.lower() or "large" in note.lower(), note
        finally:
            trust._MAX_HASH_BYTES = original_cap


# ---------------------------------------------------------------------------
# General integration sanity: auto-allow really skips the dialog, denial
# leaves no trace, only_vars filtering still applies on the auto-allow path.
# ---------------------------------------------------------------------------

def test_auto_allow_skips_dialog_call_entirely() -> None:
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_allow(trust_it=True)) as calls:
            mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert len(calls) == 1
            for _ in range(3):
                r = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
                assert r.get("auto_allowed") is True
            assert len(calls) == 1, "dialog must not be invoked again once trusted"


def test_denial_does_not_cache_or_trust_anything() -> None:
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_deny()):
            r = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert r == {"applied": False, "message": "Denied by user."}
        assert not trust.has_cached_secrets()
        sig = trust.make_signature(cmd, None, None, None, False)
        assert sig not in trust._trusted


def test_allow_without_checking_trust_does_not_grant_trust() -> None:
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_allow(trust_it=False)) as calls:
            r1 = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert r1.get("applied") is True
            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
            assert len(calls) == 2, "no trust was granted, so the dialog must reappear"
            assert not r2.get("auto_allowed")


def test_auto_allow_still_respects_only_vars_filtering() -> None:
    """The cache holds only the subset scoped to each signature's own
    only_vars -- not the full decrypted vault -- so this locks in both
    that the cache itself never holds more than was approved, and that
    the injection-time filter still applies on the cached path (belt and
    suspenders alongside the cache already being pre-scoped)."""
    with isolated_vault():
        cmd = [sys.executable, "-c",
               "import os; print('HAS_TOKEN=' + str('DOCKER_TEST_TOKEN' in os.environ)); "
               "print('HAS_OTHER=' + str('OTHER_SECRET' in os.environ))"]
        with fake_dialog(_allow(trust_it=True)) as calls:
            r1 = mcp_server._run_with_env_impl(list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
            assert "HAS_TOKEN=True" in r1["stdout"]
            assert "HAS_OTHER=False" in r1["stdout"]

            sig = trust.make_signature(cmd, None, ["DOCKER_TEST_TOKEN"], None, False)
            cached = trust.cached_secrets(sig)
            assert cached is not None and set(cached) == {"DOCKER_TEST_TOKEN"}, (
                "REGRESSION: the trust cache holds more than what was approved "
                f"for this signature, got {cached and set(cached)}")

            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
            assert len(calls) == 1 and r2.get("auto_allowed") is True
            assert "HAS_TOKEN=True" in r2["stdout"]
            assert "HAS_OTHER=False" in r2["stdout"], (
                "auto-allowed run leaked a secret outside its approved only_vars")


def test_cached_secret_is_obfuscated_not_plaintext_in_the_cache_dict() -> None:
    """Cached values must not sit as recognizable plaintext bytes in
    _cached_secrets -- proves the XOR obfuscation actually runs (not
    present-but-unused), while cached_secrets() still round-trips to the
    real value via the matching key in _cache_keys."""
    with isolated_vault():
        cmd = _py()
        with fake_dialog(_allow(trust_it=True)):
            mcp_server._run_with_env_impl(list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])

        sig = trust.make_signature(cmd, None, ["DOCKER_TEST_TOKEN"], None, False)
        stored = trust._cached_secrets[sig]["DOCKER_TEST_TOKEN"]
        plaintext_bytes = BASE_SECRETS["DOCKER_TEST_TOKEN"].encode("utf-8")
        assert stored != plaintext_bytes, (
            "REGRESSION: cached secret is stored as raw plaintext bytes")
        assert trust.cached_secrets(sig)["DOCKER_TEST_TOKEN"] == BASE_SECRETS["DOCKER_TEST_TOKEN"]


def test_real_docker_test_token_value_is_actually_injected() -> None:
    """End-to-end (no Docker needed): confirms the real secret VALUE, not
    just its presence, reaches the child process on both the fresh-unlock
    and the auto-allowed path."""
    with isolated_vault():
        cmd = [sys.executable, "-c", "import os; print(os.environ.get('DOCKER_TEST_TOKEN', ''))"]
        with fake_dialog(_allow(trust_it=True)):
            r1 = mcp_server._run_with_env_impl(list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
            assert r1["stdout"].strip() == BASE_SECRETS["DOCKER_TEST_TOKEN"]
            r2 = mcp_server._run_with_env_impl(list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
            assert r2.get("auto_allowed") is True
            assert r2["stdout"].strip() == BASE_SECRETS["DOCKER_TEST_TOKEN"]


# ---------------------------------------------------------------------------
# NEW-1: when installed as a plugin, the vault must live under
# CLAUDE_PLUGIN_DATA (the one directory Claude Code documents as surviving
# `claude plugin update`) instead of next to the module -- a red-team audit
# found the old behavior silently orphans vault.enc/vault.salt in a
# version-scoped plugin cache directory on a routine update, with no
# warning and no recovery. Run in a real subprocess (not importlib.reload
# in-process) so this exercises exactly what a fresh plugin_launcher.py ->
# mcp_server.py process actually sees, and so it can't perturb the
# already-imported `store` module the rest of this suite depends on.
# ---------------------------------------------------------------------------

def test_root_uses_plugin_data_dir_when_set() -> None:
    with tempfile.TemporaryDirectory(prefix="fake_plugin_data_") as data_dir:
        env = {**os.environ, "CLAUDE_PLUGIN_DATA": data_dir}
        proc = subprocess.run(
            [sys.executable, "-c", "from vault_lib import store; print(store.ROOT)"],
            cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, check=True)
        root = proc.stdout.strip()
        expected = str(Path(data_dir).resolve() / "vault")
        assert root == expected, (
            f"REGRESSION (NEW-1): with CLAUDE_PLUGIN_DATA set, store.ROOT should "
            f"live under it, got {root!r}, expected {expected!r}")
        assert Path(root).is_dir(), "store.py must create ROOT if it doesn't exist yet"


def test_root_falls_back_to_module_location_without_plugin_data_dir() -> None:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_DATA"}
    proc = subprocess.run(
        [sys.executable, "-c", "from vault_lib import store; print(store.ROOT)"],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, check=True)
    root = proc.stdout.strip()
    assert root == str(REPO_ROOT.resolve()), (
        f"REGRESSION: manual/dev install (no CLAUDE_PLUGIN_DATA) must keep "
        f"the old next-to-the-module vault location, got {root!r}")


# ---------------------------------------------------------------------------
# NEW-3: two variable names sharing one placeholder number must be rejected
# on load, not silently accepted -- a duplicate number makes llm.env's
# VAR="value N" lines ambiguous between the two names.
# ---------------------------------------------------------------------------

def test_load_index_rejects_duplicate_placeholder_numbers() -> None:
    with isolated_vault():
        store.INDEX_FILE.write_text('{"NAME_A": 1, "NAME_B": 1}')
        try:
            store.load_index()
            raised = False
        except ValueError as e:
            raised = True
            msg = str(e)
        assert raised, "REGRESSION (NEW-3): duplicate placeholder numbers were accepted"
        assert "NAME_A" in msg and "NAME_B" in msg and "1" in msg


# ---------------------------------------------------------------------------
# Ciphertext-length padding: vault.enc's length used to reveal the
# aggregate byte size of every real secret value combined. save_secrets
# now pads to a block multiple before encrypting; load_secrets must still
# read an OLDER, unpadded vault.enc correctly (no format version flag
# exists, so this is the only thing standing between this fix and
# corrupting every vault that predates it).
# ---------------------------------------------------------------------------

def test_save_then_load_round_trips_through_padding() -> None:
    with isolated_vault(secrets={}):
        secrets = {"A": "short", "B": "a considerably longer value than the other one"}
        store.save_secrets(TEST_PASSWORD, secrets)
        assert store.load_secrets(TEST_PASSWORD) == secrets


def test_saved_ciphertext_length_is_coarsened_across_different_value_sizes() -> None:
    """Two secrets dicts of noticeably different byte size should be able
    to land in the same padded-length bucket -- proves padding is actually
    applied, not merely present as unused code."""
    with isolated_vault(secrets={}):
        store.save_secrets(TEST_PASSWORD, {"A": "x"})
        short_len = store.SECRETS_FILE.stat().st_size
        store.save_secrets(TEST_PASSWORD, {"A": "x" * 10})
        long_len = store.SECRETS_FILE.stat().st_size
        assert short_len == long_len, (
            f"REGRESSION: a 9-byte difference in real value length changed the "
            f"ciphertext length ({short_len} vs {long_len}) -- padding isn't "
            f"coarsening it")


def test_load_secrets_still_reads_an_older_unpadded_vault() -> None:
    """Simulates a vault.enc written by the pre-padding code -- crypto.encrypt
    called directly on unpadded JSON, exactly what save_secrets used to do."""
    with isolated_vault(secrets={}):
        import json
        from vault_lib import crypto
        legacy_secrets = {"OLD_STYLE": "still-must-load-correctly"}
        salt = store.SALT_FILE.read_bytes()
        unpadded_token = crypto.encrypt(
            TEST_PASSWORD, salt, json.dumps(legacy_secrets).encode("utf-8"))
        store.SECRETS_FILE.write_bytes(unpadded_token)
        assert store.load_secrets(TEST_PASSWORD) == legacy_secrets, (
            "REGRESSION: an older, unpadded vault.enc failed to load")


# ---------------------------------------------------------------------------
# Stale background-run log cleanup: opportunistic, best-effort deletion of
# old llm-env-vault-run-*.log files from a prior session's background=True
# calls -- previously never cleaned up at all (documented limitation).
# ---------------------------------------------------------------------------

def test_cleanup_stale_run_logs_removes_old_ones_keeps_recent_ones() -> None:
    with tempfile.TemporaryDirectory() as fake_temp:
        old_path = Path(fake_temp) / "llm-env-vault-run-old.log"
        recent_path = Path(fake_temp) / "llm-env-vault-run-recent.log"
        unrelated_path = Path(fake_temp) / "some-other-file.log"
        for p in (old_path, recent_path, unrelated_path):
            p.write_text("x")
        old_cutoff = time.time() - (mcp_server._STALE_RUN_LOG_AGE_SECONDS + 3600)
        os.utime(old_path, (old_cutoff, old_cutoff))

        original_gettempdir = tempfile.gettempdir
        tempfile.gettempdir = lambda: fake_temp
        try:
            mcp_server._cleanup_stale_run_logs()
        finally:
            tempfile.gettempdir = original_gettempdir

        assert not old_path.exists(), "REGRESSION: a stale run log was not cleaned up"
        assert recent_path.exists(), "REGRESSION: a recent run log was incorrectly deleted"
        assert unrelated_path.exists(), "REGRESSION: a non-matching file was incorrectly deleted"


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches
# test_install_migrate_robustness.py's convention)
# ---------------------------------------------------------------------------

def _run(fn) -> bool:
    print(f"Running {fn.__name__} ...")
    try:
        fn()
        print("  PASS")
        return True
    except Exception as exc:
        import traceback
        print(f"  FAIL: {exc}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]

    passed = [t for t in tests if _run(t)]
    failed = [t for t in tests if t not in passed]

    print()
    print(f"Results: {len(passed)}/{len(tests)} passed")
    if failed:
        print(f"FAILED: {[f.__name__ for f in failed]}")
        sys.exit(1)
    else:
        print("All tests passed.")
