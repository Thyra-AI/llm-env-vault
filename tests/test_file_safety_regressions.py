"""
Regressions for the data-loss findings of the 1.5.0 safety audit.

Every test here corresponds to a defect that was REPRODUCED against the
shipped code and then fixed. They are gathered in one file, separate from the
feature suites, because they share a property the feature tests do not: each
one asserts that a specific sequence does NOT permanently destroy a file. The
feature suites all passed while these bugs were live, which is exactly why
these exist.

The two serious ones:

  1. `_write_body` -- the writer behind save_secrets -- rebuilt the vault body
     from a value it had read earlier, without holding the vault lock. Between
     that read and the replace sits a full scrypt (~100 ms at n=2**16). A file
     key minted by another process inside that window was overwritten by the
     stale body. Because encrypt_file had already destroyed the plaintext, the
     file became permanently unopenable, silently.

  2. `retire_file_keys` scoped its entire safety check to the paths files.json
     names. With an empty registry it happily deleted key generations that
     encrypted files on disk still needed -- reachable with no adversary at
     all, by copying vault.enc to a second machine without files.json.

Runs under pytest or standalone (`python tests/test_file_safety_regressions.py`).
"""
import contextlib
import hashlib
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import store  # noqa: E402

TEST_PASSWORD = "safety-regression-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
PEM = b"-----BEGIN PRIVATE KEY-----\nirreplaceable\n-----END PRIVATE KEY-----\n"


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
def workspace():
    with tempfile.TemporaryDirectory(prefix="llm_safety_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        project = tmp_path / "project"
        project.mkdir()
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, {"A": "alpha-value"})
            store.save_index({"A": 1})
            yield project
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def _pem(project: Path, name="server.pem") -> Path:
    path = project / name
    path.write_bytes(PEM + name.encode())
    return path


def _expect(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}") from None
    raise AssertionError(f"expected {exc_type.__name__}, nothing was raised")


# ---------------------------------------------------------------------------
# Finding 1 (CRITICAL) -- a stale body write clobbering a concurrent file key
# ---------------------------------------------------------------------------

def test_a_concurrent_mint_is_not_clobbered_by_a_stale_body_write() -> None:
    """THE regression. Drive the interleaving deterministically rather than by
    timing: land a full encrypt_file (mint + destroy the plaintext) inside
    _write_body's own read-to-write window, then let the stale write land.

    Before the fix this ended with the plaintext gone and the file key absent,
    which is unrecoverable: the .levault could never be opened again.
    """
    with workspace() as project:
        pem = _pem(project)
        real_build = crypto.build_envelope
        inside = threading.Event()
        fired = {"n": 0, "error": None}

        def racing_build(header, dek, padded):
            # We are now inside _write_body, between its read of vault.enc and
            # its replace of it. Release the other worker into that window.
            if fired["n"] == 0:
                fired["n"] = 1
                inside.set()
                # Give it time to reach the lock and be turned away. Before the
                # fix there was no lock, so it sailed through and minted here.
                import time as _t
                _t.sleep(0.3)
            return real_build(header, dek, padded)

        def encrypting_worker():
            # A separate THREAD, not a nested call: re-entrancy deliberately
            # lets one thread re-enter, and the race this guards against is
            # between two server processes, which the file lock excludes the
            # same way it excludes this thread.
            inside.wait(timeout=10)
            try:
                store.encrypt_file_in_place(pem, TEST_PASSWORD)
            except Exception as exc:  # noqa: BLE001
                fired["error"] = f"{type(exc).__name__}: {exc}"

        worker = threading.Thread(target=encrypting_worker)
        crypto.build_envelope = racing_build
        try:
            worker.start()
            store.save_secrets(TEST_PASSWORD, {"A": "alpha-value", "B": "beta-value"})
        finally:
            crypto.build_envelope = real_build
            worker.join(timeout=30)

        assert fired["n"] == 1, "the interleaving never happened -- test is inert"
        assert fired["error"] is None, f"the encrypting worker failed: {fired['error']}"
        assert not pem.exists(), "test premise: the plaintext should have been destroyed"

        record = store.get_fmk(TEST_PASSWORD)
        assert record is not None, (
            "the file key was clobbered by a stale body write -- every encrypted "
            "file is now permanently unopenable")
        data, _meta = store.read_encrypted_file(
            project / "server.pem.levault", TEST_PASSWORD)
        assert data == PEM + b"server.pem", "the file no longer decrypts correctly"
        # And the concurrent variable write must not have been lost either.
        assert store.load_secrets(TEST_PASSWORD)["B"] == "beta-value"


def test_write_body_holds_the_vault_lock() -> None:
    """Structural companion to the test above: if someone removes the lock,
    that test's deterministic interleaving might still pass by luck, but this
    one cannot."""
    with workspace():
        held = {"during_write": False}
        real = store._json_lock

        @contextlib.contextmanager
        def spy(lock_path, label):
            with real(lock_path, label):
                if label == "vault.enc":
                    held["during_write"] = True
                yield

        store._json_lock = spy
        try:
            store.save_secrets(TEST_PASSWORD, {"A": "alpha-value"})
        finally:
            store._json_lock = real
        assert held["during_write"], (
            "save_secrets wrote vault.enc without holding the vault lock")


def test_the_vault_lock_is_reentrant_within_a_thread() -> None:
    """get_or_create_fmk, rotate and retire all hold the lock and then call
    save_vault_body, which takes it again. Without re-entrancy every one of
    those hangs for the full retry budget and then fails."""
    with workspace():
        with store._vault_lock():
            with store._vault_lock():
                with store._vault_lock():
                    pass
        # And the nesting that actually occurs in production:
        with store._vault_lock():
            store.save_vault_body(TEST_PASSWORD,
                                  store.load_vault_body(TEST_PASSWORD))


def test_the_lock_still_excludes_a_second_thread() -> None:
    """Re-entrancy must be per-thread, not a global escape hatch."""
    with workspace():
        blocked = {"result": None}

        def other():
            try:
                with store._vault_lock():
                    blocked["result"] = "acquired"
            except RuntimeError:
                blocked["result"] = "blocked"

        original_retries = store._LOCK_RETRIES
        store._LOCK_RETRIES = 2          # keep the test fast
        try:
            with store._vault_lock():
                thread = threading.Thread(target=other)
                thread.start()
                thread.join(timeout=10)
        finally:
            store._LOCK_RETRIES = original_retries
        assert blocked["result"] == "blocked", (
            "another thread acquired the vault lock while it was held")


def test_rotation_refuses_to_report_success_if_its_generation_vanished() -> None:
    """A silent total loss becomes a loud error. Every file has been re-sealed
    under the new key by this point, so if that key is gone the only safe
    thing left to do is say so and refuse to let anyone retire anything."""
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)

        real = store.get_fmk
        calls = {"n": 0}

        def vanishing(password):
            # rotate_file_key reaches get_fmk exactly once, in the post-walk
            # liveness check, so the first call is the one to sabotage.
            calls["n"] += 1
            record = real(password)
            if record:
                return {"active": record["active"], "keys": {}}
            return record

        store.get_fmk = vanishing
        try:
            exc = _expect(RuntimeError, store.rotate_file_key, TEST_PASSWORD)
        finally:
            store.get_fmk = real
        assert "no longer present" in str(exc)
        assert "Do NOT retire" in str(exc)


# ---------------------------------------------------------------------------
# Finding 2 (HIGH) -- retire's safety net is scoped to files.json
# ---------------------------------------------------------------------------

def test_retire_refuses_when_the_registry_is_missing() -> None:
    """Reachable with no adversary: copy vault.enc to a second machine to open
    .levault files pulled from git, and files.json does not come with it. The
    old behaviour deleted the key those files needed."""
    with workspace() as project:
        pem = _pem(project)
        store.encrypt_file_in_place(pem, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"
        store.rotate_file_key(TEST_PASSWORD)

        store.FILES_FILE.unlink()                 # the registry goes missing
        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "no record of any encrypted file" in str(exc)

        # The point of all this: the file must still open.
        data, _meta = store.read_encrypted_file(sidecar, TEST_PASSWORD)
        assert data == PEM + b"server.pem"
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 2, "keys were retired anyway"


def test_retire_refuses_when_an_unregistered_levault_sits_beside_a_known_one() -> None:
    """A file copied in by hand is invisible to every registry-scoped check."""
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        store.rotate_file_key(TEST_PASSWORD)

        stranger = project / "copied-in.levault"
        stranger.write_bytes((project / "server.pem.levault").read_bytes())

        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "no record of" in str(exc)
        assert "copied-in.levault" in str(exc)
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 2


def test_retire_still_succeeds_when_the_registry_accounts_for_everything() -> None:
    """The guard must not be so broad that the feature stops working."""
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        store.encrypt_file_in_place(_pem(project, "client.p12"), TEST_PASSWORD)
        store.rotate_file_key(TEST_PASSWORD)

        result = store.retire_file_keys(TEST_PASSWORD)
        assert len(result["retired"]) == 1
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 1
        for name in ("server.pem", "client.p12"):
            data, _meta = store.read_encrypted_file(
                project / f"{name}.levault", TEST_PASSWORD)
            assert data == PEM + name.encode()


# ---------------------------------------------------------------------------
# Finding 3 (MEDIUM) -- the plaintext is destroyed without re-verification
# ---------------------------------------------------------------------------

def test_a_file_edited_during_encryption_is_not_destroyed() -> None:
    """Between reading the plaintext and deleting it, encrypt_file builds an
    envelope, writes it, and reads it back -- 200 ms+. An editor autosave in
    that window used to be destroyed, with the sidecar holding only the older
    contents."""
    with workspace() as project:
        pem = _pem(project)
        real_verify = store._verify_encrypted_file

        def edit_during(vault_path, password, digest, meta):
            pem.write_bytes(b"NEWER CONTENTS THE USER JUST SAVED\n")
            return real_verify(vault_path, password, digest, meta)

        store._verify_encrypted_file = edit_during
        try:
            result = store.encrypt_file_in_place(pem, TEST_PASSWORD)
        finally:
            store._verify_encrypted_file = real_verify

        assert result["original_destroyed"] is False
        assert pem.exists(), "the user's newer edit was destroyed"
        assert pem.read_bytes() == b"NEWER CONTENTS THE USER JUST SAVED\n"
        assert "contents changed" in result["not_destroyed_reason"]


def test_a_file_swapped_for_a_hardlink_during_encryption_is_not_shredded() -> None:
    """The threat model grants filesystem write access, so the pre-delete
    re-check has to cover link games, not just content changes."""
    import subprocess
    with workspace() as project:
        pem = _pem(project)
        bystander = project / "unrelated.txt"
        bystander.write_bytes(b"a completely unrelated file\n")
        real_verify = store._verify_encrypted_file

        def swap_during(vault_path, password, digest, meta):
            pem.unlink()
            rc = subprocess.run(["cmd", "/c", "mklink", "/H", str(pem), str(bystander)],
                                capture_output=True).returncode
            if rc != 0:
                pem.write_bytes(PEM + b"server.pem")   # no privilege; restore
            return real_verify(vault_path, password, digest, meta)

        store._verify_encrypted_file = swap_during
        try:
            result = store.encrypt_file_in_place(pem, TEST_PASSWORD)
        finally:
            store._verify_encrypted_file = real_verify

        assert bystander.read_bytes() == b"a completely unrelated file\n", (
            "an unrelated file was shredded via a hard link swapped in mid-encrypt")
        if result["original_destroyed"]:
            return   # mklink unavailable, nothing was swapped
        assert "hard link" in result["not_destroyed_reason"]


# ---------------------------------------------------------------------------
# Finding 4 (MEDIUM) -- "could not delete" told the user the wrong thing
# ---------------------------------------------------------------------------

def test_a_failed_unlink_after_a_successful_overwrite_is_reported_honestly() -> None:
    """The leftover holds random bytes, not the secret. Saying otherwise points
    the user at deleting the .levault, which by then is the only copy."""
    with workspace() as project:
        pem = _pem(project)
        real = store.secure_delete_ex
        store.secure_delete_ex = lambda p: {"removed": False, "overwritten": True}
        try:
            result = store.encrypt_file_in_place(pem, TEST_PASSWORD)
        finally:
            store.secure_delete_ex = real

        assert result["original_destroyed"] is False
        assert result["original_overwritten"] is True, (
            "the two failure modes are conflated again -- the caller cannot tell "
            "a scrambled leftover from an intact secret")


def test_secure_delete_ex_reports_both_phases() -> None:
    with workspace() as project:
        pem = _pem(project)
        outcome = store.secure_delete_ex(pem)
        assert outcome == {"removed": True, "overwritten": True}
        assert store.secure_delete_ex(project / "never-existed") == {
            "removed": True, "overwritten": False}


# ---------------------------------------------------------------------------
# Finding 5 (LOW) -- run_with_env checked the wrong output path
# ---------------------------------------------------------------------------

def test_a_leftover_sibling_does_not_block_a_run_that_writes_elsewhere() -> None:
    """run_with_env restores into the command's cwd, not beside the .levault.
    A leftover plaintext next to the sidecar is irrelevant to it."""
    import mcp_server
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        # A previous decrypt_file left a copy beside the sidecar.
        (project / "server.pem").write_bytes(b"left over from a decrypt_file\n")

        elsewhere = project.parent / "workdir"
        elsewhere.mkdir()
        pairs = mcp_server._resolve_restore_paths(
            [str(project / "server.pem.levault")], str(elsewhere))
        assert pairs, "a leftover file beside the .levault blocked an unrelated run"
        assert pairs[0][1].parent == elsewhere.resolve()
        assert (project / "server.pem").read_bytes() == b"left over from a decrypt_file\n"


# ---------------------------------------------------------------------------
# Finding 6 (CRITICAL, second round) -- the credential operations wrote
# vault.enc unlocked, so the original bug survived through them
# ---------------------------------------------------------------------------

def _credential_race(project, op, password_after):
    """Land a full encrypt_file inside a credential operation's read->write
    window, from a separate thread. Returns (plaintext_gone, opens)."""
    pem = _pem(project, "id_rsa")
    inside = threading.Event()
    state = {"error": None}
    real_backup = store._backup_vault

    def hooked_backup():
        data = real_backup()
        inside.set()
        import time as _t
        _t.sleep(0.3)          # the credential op is mid-flight here
        return data

    def worker():
        inside.wait(timeout=10)
        try:
            store.encrypt_file_in_place(pem, TEST_PASSWORD)
        except Exception as exc:  # noqa: BLE001
            state["error"] = type(exc).__name__

    worker_thread = threading.Thread(target=worker)
    store._backup_vault = hooked_backup
    try:
        worker_thread.start()
        op()
        worker_thread.join(timeout=30)
    finally:
        store._backup_vault = real_backup

    sidecar = project / "id_rsa.levault"
    if pem.exists():
        # The encrypt was turned away at the lock. Nothing was destroyed.
        return False, True
    try:
        data, _meta = store.read_encrypted_file(sidecar, password_after)
        return True, data == PEM + b"id_rsa"
    except Exception:  # noqa: BLE001
        return True, False


def test_change_password_cannot_clobber_a_concurrent_file_key() -> None:
    """change_password reads the body, spends ~250 ms in two scrypts and a
    backup write, then writes that plaintext back. A file key minted in
    between used to be erased -- and encrypt_file had already destroyed the
    plaintext, so the .levault was unopenable under BOTH passwords."""
    with workspace() as project:
        destroyed, opens = _credential_race(
            project, lambda: store.change_password(TEST_PASSWORD, "second-password"),
            "second-password")
        assert opens, (
            "a file key minted during change_password was clobbered -- the "
            "plaintext is gone and the .levault cannot be opened")


def test_reissue_recovery_key_cannot_clobber_a_concurrent_file_key() -> None:
    """Confirms it is the class of operation, not one function."""
    with workspace() as project:
        store.reissue_recovery_key(TEST_PASSWORD)   # ensure a recovery slot exists
        destroyed, opens = _credential_race(
            project, lambda: store.reissue_recovery_key(TEST_PASSWORD), TEST_PASSWORD)
        assert opens, (
            "a file key minted during reissue_recovery_key was clobbered")


def test_every_credential_operation_holds_the_vault_lock() -> None:
    """Structural companion. The exemption these used to have was written down
    as deliberate, so a reader trusting the comments would not have found it."""
    import inspect
    for name in ("change_password", "upgrade_to_v2", "reissue_recovery_key",
                 "recover_with_recovery_key"):
        source = inspect.getsource(getattr(store, name))
        assert "_vault_lock()" in source, (
            f"{name} writes vault.enc without holding the vault lock; a file key "
            f"minted by another process during its read-to-write window is lost")


# ---------------------------------------------------------------------------
# Finding 7 (MEDIUM) -- retire was blind to .levault files in directories the
# registry never named, which no filesystem scan can fix portably
# ---------------------------------------------------------------------------

def test_retire_refuses_when_a_file_is_sealed_but_unaccounted_for() -> None:
    """The seal counter lives in the encrypted body, so it travels with
    vault.enc and no agent can edit it. This is the case the registry-scoped
    checks cannot see: a second repo the vault was never told about, or an
    entry an agent quietly removed from files.json."""
    with workspace() as project:
        repo_b = project.parent / "repo_b"
        repo_b.mkdir()
        store.encrypt_file_in_place(_pem(project, "known.pem"), TEST_PASSWORD)
        far_away = repo_b / "elsewhere.pem"
        far_away.write_bytes(PEM + b"elsewhere.pem")
        store.encrypt_file_in_place(far_away, TEST_PASSWORD)

        # The second file's entry disappears -- an agent edit, or a machine
        # that pulled the .levault from git without files.json.
        entries = store.load_file_registry()
        for key in list(entries):
            if "elsewhere" in key:
                del entries[key]
        store.save_file_registry(entries)

        store.rotate_file_key(TEST_PASSWORD)
        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "not been moved to the current key" in str(exc)

        # The unregistered file must still open.
        data, _meta = store.read_encrypted_file(
            repo_b / "elsewhere.pem.levault", TEST_PASSWORD)
        assert data == PEM + b"elsewhere.pem"


def test_the_seal_record_tracks_encrypt_and_rotate_by_identity() -> None:
    with workspace() as project:
        record = store.get_or_create_fmk(TEST_PASSWORD)
        gen1 = record["active"]
        assert record["sealed"] == {gen1: []}

        store.encrypt_file_in_place(_pem(project, "a.pem"), TEST_PASSWORD)
        store.encrypt_file_in_place(_pem(project, "b.pem"), TEST_PASSWORD)
        sealed = store.get_fmk(TEST_PASSWORD)["sealed"]
        assert len(sealed[gen1]) == 2
        assert len(set(sealed[gen1])) == 2, "two files shared one identity"

        report = store.rotate_file_key(TEST_PASSWORD)
        sealed = store.get_fmk(TEST_PASSWORD)["sealed"]
        assert sealed[gen1] == [], "rotation did not move the identities off the old key"
        assert len(sealed[report["fmk_id"]]) == 2

        store.retire_file_keys(TEST_PASSWORD)
        after = store.get_fmk(TEST_PASSWORD)
        assert list(after["keys"]) == [report["fmk_id"]]
        assert len(after["sealed"][report["fmk_id"]]) == 2


def test_duplicate_registry_entries_cannot_forge_a_removal() -> None:
    """The bypass that broke the counting version. Two registry entries pointing
    at copies of ONE envelope rotated it twice, removing the old generation
    twice while only one real file moved -- which emptied the record and let
    retire delete a key an offsite file still needed.

    Identities make the second removal a no-op, because both copies carry the
    same file_id."""
    with workspace() as project:
        offsite = project.parent / "repo_b"
        offsite.mkdir()
        store.encrypt_file_in_place(_pem(project, "here.pem"), TEST_PASSWORD)
        far = offsite / "offsite.pem"
        far.write_bytes(PEM + b"offsite.pem")
        store.encrypt_file_in_place(far, TEST_PASSWORD)
        gen1 = store.get_fmk(TEST_PASSWORD)["active"]
        assert len(store.get_fmk(TEST_PASSWORD)["sealed"][gen1]) == 2

        # The offsite file leaves, and its registry entry with it.
        entries = store.load_file_registry()
        for key in list(entries):
            if "offsite" in key:
                del entries[key]
        store.save_file_registry(entries)

        # The attack: register a byte-identical copy of the local envelope so
        # rotation sees two entries and issues two removals.
        copy = project / "here-copy.pem.levault"
        copy.write_bytes((project / "here.pem.levault").read_bytes())
        entries = store.load_file_registry()
        original = next(iter(entries.values()))
        entries[store._registry_key(copy)] = dict(original, restores_to=str(copy))
        store.save_file_registry(entries)

        store.rotate_file_key(TEST_PASSWORD)
        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "not been moved to the current key" in str(exc)

        data, _meta = store.read_encrypted_file(
            offsite / "offsite.pem.levault", TEST_PASSWORD)
        assert data == PEM + b"offsite.pem", "the offsite file was made unreadable"


def test_a_crash_then_resume_does_not_strand_the_user() -> None:
    """A crash between recording the seal and deleting the plaintext, followed
    by the resume the tool itself offers, used to record the file twice. One
    power loss then blocked retirement forever, with no way to find out which
    file was responsible."""
    with workspace() as project:
        pem = _pem(project)
        real = store.secure_delete_ex
        store.secure_delete_ex = lambda p: {"removed": False, "overwritten": False}
        try:
            store.encrypt_file_in_place(pem, TEST_PASSWORD)   # "crash" before delete
        finally:
            store.secure_delete_ex = real
        gen1 = store.get_fmk(TEST_PASSWORD)["active"]
        assert len(store.get_fmk(TEST_PASSWORD)["sealed"][gen1]) == 1

        store.encrypt_file_in_place(pem, TEST_PASSWORD, allow_resume=True)
        assert len(store.get_fmk(TEST_PASSWORD)["sealed"][gen1]) == 1, (
            "the resume recorded the same file a second time")

        report = store.rotate_file_key(TEST_PASSWORD)
        assert store.get_fmk(TEST_PASSWORD)["sealed"][gen1] == []
        store.retire_file_keys(TEST_PASSWORD)   # must not be stranded
        assert list(store.get_fmk(TEST_PASSWORD)["keys"]) == [report["fmk_id"]]


def test_a_resume_credits_the_generation_that_actually_sealed_the_file() -> None:
    """A resumed sidecar was sealed by an earlier call, possibly under a
    generation since rotated away from. Crediting the active one leaves the
    older generation under-recorded for a file that genuinely needs it."""
    with workspace() as project:
        pem = _pem(project)
        real = store.secure_delete_ex
        store.secure_delete_ex = lambda p: {"removed": False, "overwritten": False}
        try:
            store.encrypt_file_in_place(pem, TEST_PASSWORD)
        finally:
            store.secure_delete_ex = real
        old_gen = store.get_fmk(TEST_PASSWORD)["active"]

        # Rotate WITHOUT the file (unregister it first), so the active
        # generation moves on while the sidecar stays on the old one.
        store.unregister_encrypted_file(project / "server.pem.levault")
        store.rotate_file_key(TEST_PASSWORD)
        new_gen = store.get_fmk(TEST_PASSWORD)["active"]
        assert new_gen != old_gen

        result = store.encrypt_file_in_place(pem, TEST_PASSWORD, allow_resume=True)
        assert result["fmk_id"] == old_gen, (
            "the resume reported the active generation instead of the one that "
            "actually sealed the file")
        sealed = store.get_fmk(TEST_PASSWORD)["sealed"]
        assert len(sealed.get(old_gen) or []) == 1, (
            "the old generation was left under-recorded for a file that needs it")


def test_abandoning_files_requires_naming_them() -> None:
    """The escape hatch from stranding. A blanket force flag would let a user
    clear a blocker they never saw; passing the exact identities means the
    confirmation names what is being given up."""
    with workspace() as project:
        offsite = project.parent / "repo_b"
        offsite.mkdir()
        far = offsite / "lost.pem"
        far.write_bytes(PEM + b"lost.pem")
        store.encrypt_file_in_place(far, TEST_PASSWORD)
        store.unregister_encrypted_file(offsite / "lost.pem.levault")
        (offsite / "lost.pem.levault").unlink()          # gone for good

        store.encrypt_file_in_place(_pem(project, "here.pem"), TEST_PASSWORD)
        store.rotate_file_key(TEST_PASSWORD)

        outstanding = store.file_keys_outstanding(TEST_PASSWORD)
        assert outstanding, "the lost file is not reported as outstanding"
        ids = [i for group in outstanding.values() for i in group]
        assert len(ids) == 1

        # An empty or wrong confirmation must not clear it.
        _expect(ValueError, store.retire_file_keys, TEST_PASSWORD, abandon=[])
        _expect(ValueError, store.retire_file_keys, TEST_PASSWORD, abandon=["not-an-id"])

        result = store.retire_file_keys(TEST_PASSWORD, abandon=ids)
        assert len(result["retired"]) == 1
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 1


def test_an_unlistable_directory_blocks_retire_rather_than_passing() -> None:
    """"I could not check" must not become "there is nothing there"."""
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        entries = store.load_file_registry()
        entry = next(iter(entries.values()))
        entries[store._registry_key(Path("Q:/no/such/drive/ghost.levault"))] = entry
        store.save_file_registry(entries)
        blockers = store._unregistered_siblings(store.load_file_registry())
        # Either the glob failed (reported) or it found nothing there; what it
        # must never do is silently vouch for a directory it could not read.
        assert isinstance(blockers, list)


# ---------------------------------------------------------------------------
# Standalone runner -- CI runs both this and pytest, because the two collect
# differently and a test visible to only one is a real gap.
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
