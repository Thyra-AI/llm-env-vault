"""
Store-layer suite for whole-file encryption: encrypt/decrypt, the refusal
rules, the registry, and secure_delete.

The stakes here are different from the rest of the vault. encrypt_file destroys
the original after writing the sidecar, so a bug in the ORDERING -- not in the
crypto, which test_file_vault_crypto.py covers -- costs the user a file that
may exist nowhere else. Most of what follows is therefore about what happens
when a step fails partway, and about the long list of things that must be
refused before anything is written at all.

Two invariants get their own tests because they are easy to regress and
expensive to get wrong:

  * The registry is never authoritative and never parameterises a write. It is
    plaintext and agent-writable, so a mode of "0777" or a redirected
    restores_to in files.json must not reach the filesystem.
  * A failed read-back leaves the original's ACTUAL BYTES untouched -- not
    merely "the file still exists".

Runs under pytest (`pytest tests/test_file_store.py -q`) or standalone
(`python tests/test_file_store.py`).
"""
import contextlib
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import store  # noqa: E402

TEST_PASSWORD = "file-store-test-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)

PEM = (b"-----BEGIN PRIVATE KEY-----\n"
       b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
       b"-----END PRIVATE KEY-----\n")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _isolate_store_paths(tmp_dir: Path) -> dict:
    names = ("SALT_FILE", "SECRETS_FILE", "INDEX_FILE", "ENV_FILE", "BAK_FILE",
             "FORMAT_FILE", "VAULT_LOCK_FILE", "FILES_FILE", "FILES_LOCK_FILE",
             "TARGETS_FILE", "TARGETS_LOCK_FILE", "ROOT")
    originals = {n: getattr(store, n) for n in names}
    vault_dir = tmp_dir / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    store.ROOT = vault_dir
    store.SALT_FILE = vault_dir / "vault.salt"
    store.SECRETS_FILE = vault_dir / "vault.enc"
    store.INDEX_FILE = vault_dir / "vault_index.json"
    store.ENV_FILE = vault_dir / "llm.env"
    store.BAK_FILE = vault_dir / "vault.enc.bak"
    store.FORMAT_FILE = vault_dir / "vault.format.txt"
    store.VAULT_LOCK_FILE = vault_dir / "vault.enc.lock"
    store.FILES_FILE = vault_dir / "files.json"
    store.FILES_LOCK_FILE = vault_dir / "files.json.lock"
    # TARGETS_FILE is isolated here on purpose. test_trust's fixture does not,
    # and its tests write the repo's real targets.json as a side effect. Do
    # not copy that.
    store.TARGETS_FILE = vault_dir / "targets.json"
    store.TARGETS_LOCK_FILE = vault_dir / "targets.json.lock"
    return originals


@contextlib.contextmanager
def workspace(*, v2=True):
    """A throwaway vault plus a separate project directory to encrypt files in.

    Yields the project dir -- deliberately NOT inside the vault ROOT, since
    encrypting anything under ROOT is one of the things being refused.
    """
    with tempfile.TemporaryDirectory(prefix="llm_filestore_test_") as tmp:
        tmp_path = Path(tmp).resolve()  # 8.3 short paths on Windows, see test_trust
        originals = _isolate_store_paths(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        project = tmp_path / "project"
        project.mkdir()
        try:
            if v2:
                store.create_v2_vault(TEST_PASSWORD)
            else:
                store.create_secrets_vault(TEST_PASSWORD)
            yield project
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def _pem(project: Path, name="server.pem", data=PEM) -> Path:
    path = project / name
    path.write_bytes(data)
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
# The happy path
# ---------------------------------------------------------------------------

def test_encrypt_then_decrypt_round_trips_the_bytes() -> None:
    with workspace() as project:
        src = _pem(project)
        result = store.encrypt_file_in_place(src, TEST_PASSWORD)

        sidecar = project / "server.pem.levault"
        assert sidecar.exists()
        assert not src.exists(), "the original was not destroyed"
        assert result["original_destroyed"] is True
        assert crypto.is_file_envelope(sidecar.read_bytes())

        out = store.decrypt_file_to(sidecar, TEST_PASSWORD)
        assert Path(out["output_path"]) == src
        assert src.read_bytes() == PEM
        assert sidecar.exists(), "decrypt must leave the .levault in place"


def test_encrypt_registers_the_file_with_non_secret_facts_only() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)

        entries = store.load_file_registry()
        assert len(entries) == 1
        entry = next(iter(entries.values()))
        assert entry["original_name"] == "server.pem"
        assert entry["restores_to"] == str(src)
        assert entry["plaintext_size"] == len(PEM)
        assert entry["mode"].startswith("0")

        # Nothing derived from the plaintext contents may be in here:
        # files.json is world-readable and a hash of a low-entropy file is a
        # confirmation oracle.
        blob = json.dumps(entries)
        assert hashlib.sha256(PEM).hexdigest() not in blob
        assert "BEGIN PRIVATE KEY" not in blob


def test_binary_files_round_trip() -> None:
    with workspace() as project:
        blob = bytes(range(256)) * 64
        src = _pem(project, "client.p12", blob)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        store.decrypt_file_to(project / "client.p12.levault", TEST_PASSWORD)
        assert src.read_bytes() == blob


def test_decrypt_works_on_an_unregistered_file() -> None:
    """The envelope is self-describing; the registry is a convenience. Losing
    files.json must lose visibility and nothing else."""
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        store.FILES_FILE.unlink()

        store.decrypt_file_to(project / "server.pem.levault", TEST_PASSWORD)
        assert src.read_bytes() == PEM


def test_the_file_survives_a_password_change() -> None:
    """The reason the FMK exists at all. change_password rotates the vault DEK;
    if files rode on that, every .levault would die here."""
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        store.change_password(TEST_PASSWORD, "a-completely-different-password")

        store.decrypt_file_to(project / "server.pem.levault",
                              "a-completely-different-password")
        assert src.read_bytes() == PEM


def test_decrypt_to_an_explicit_output_path() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        out = store.decrypt_file_to(project / "server.pem.levault",
                                    TEST_PASSWORD, output_path="restored.pem")
        assert Path(out["output_path"]).name == "restored.pem"
        assert (project / "restored.pem").read_bytes() == PEM
        # A rename is legitimate, but it must be reported.
        assert out["warnings"] and "server.pem" in out["warnings"][0]


# ---------------------------------------------------------------------------
# Rollback and crash limbo
#
# Failure mode: the original is destroyed on the strength of a sidecar that
# cannot actually be opened.
# ---------------------------------------------------------------------------

def test_a_failed_read_back_leaves_the_original_bytes_untouched() -> None:
    with workspace() as project:
        src = _pem(project)
        original = src.read_bytes()

        broken = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        real = store._verify_encrypted_file
        store._verify_encrypted_file = broken
        try:
            _expect(RuntimeError, store.encrypt_file_in_place, src, TEST_PASSWORD)
        finally:
            store._verify_encrypted_file = real

        assert src.exists(), "the original was destroyed after a failed read-back"
        assert src.read_bytes() == original, "the original's BYTES were modified"
        assert not (project / "server.pem.levault").exists(), \
            "the unusable sidecar was left behind"
        assert store.load_file_registry() == {}


def test_an_existing_sidecar_is_never_silently_overwritten() -> None:
    with workspace() as project:
        src = _pem(project)
        (project / "server.pem.levault").write_bytes(b"something precious")
        exc = _expect(ValueError, store.encrypt_file_in_place, src, TEST_PASSWORD)
        assert "already exists" in str(exc)
        assert (project / "server.pem.levault").read_bytes() == b"something precious"
        assert src.exists()


def test_resume_finishes_a_crash_between_write_and_delete() -> None:
    """A crash after the sidecar is verified but before the original is
    destroyed wedges both tools. allow_resume is the documented way out."""
    with workspace() as project:
        src = _pem(project)
        real = store.secure_delete_ex
        # Simulate dying in the window between a verified sidecar and the
        # deletion. encrypt_file_in_place goes through secure_delete_ex so it
        # can tell "overwritten but not unlinked" from "untouched".
        store.secure_delete_ex = lambda p: {"removed": False, "overwritten": False}
        try:
            store.encrypt_file_in_place(src, TEST_PASSWORD)
        finally:
            store.secure_delete_ex = real

        assert src.exists() and (project / "server.pem.levault").exists()
        # Without resume it stays wedged, on purpose.
        _expect(ValueError, store.encrypt_file_in_place, src, TEST_PASSWORD)

        result = store.encrypt_file_in_place(src, TEST_PASSWORD, allow_resume=True)
        assert result["resumed"] is True
        assert not src.exists()
        store.decrypt_file_to(project / "server.pem.levault", TEST_PASSWORD)
        assert src.read_bytes() == PEM


def test_resume_refuses_when_the_sidecar_holds_something_else() -> None:
    """Genuinely ambiguous: one of the two files is not what the user thinks.
    Refusing is the only honest answer."""
    with workspace() as project:
        src = _pem(project)
        other = _pem(project, "other.pem", b"different contents entirely\n")
        store.encrypt_file_in_place(other, TEST_PASSWORD)
        (project / "other.pem.levault").rename(project / "server.pem.levault")

        exc = _expect(ValueError, store.encrypt_file_in_place, src,
                      TEST_PASSWORD, allow_resume=True)
        assert "does NOT contain" in str(exc)
        assert src.read_bytes() == PEM


def test_a_decrypt_that_fails_verification_leaves_nothing_behind() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"

        real = store.write_restored_file
        store.write_restored_file = lambda p, b, m: p.write_bytes(b"wrong bytes")
        try:
            _expect(RuntimeError, store.decrypt_file_to, sidecar, TEST_PASSWORD)
        finally:
            store.write_restored_file = real

        assert not src.exists(), "a file failing verification was left on disk"


# ---------------------------------------------------------------------------
# Encrypt refusals -- everything that must be caught before a byte is written
# ---------------------------------------------------------------------------

def test_refuses_a_missing_file() -> None:
    with workspace() as project:
        _expect(ValueError, store.precheck_encrypt, project / "nope.pem")


def test_refuses_a_directory() -> None:
    with workspace() as project:
        (project / "subdir").mkdir()
        _expect(ValueError, store.precheck_encrypt, project / "subdir")


def test_refuses_an_empty_file() -> None:
    with workspace() as project:
        exc = _expect(ValueError, store.precheck_encrypt, _pem(project, "empty.pem", b""))
        assert "empty" in str(exc)


def test_refuses_an_oversized_file() -> None:
    with workspace() as project:
        src = project / "huge.bin"
        with open(src, "wb") as handle:
            handle.seek(crypto.MAX_FILE_PLAINTEXT_BYTES)
            handle.write(b"\x00")
        exc = _expect(ValueError, store.precheck_encrypt, src)
        assert "limit" in str(exc)


def test_refuses_a_file_already_named_levault() -> None:
    with workspace() as project:
        exc = _expect(ValueError, store.precheck_encrypt,
                      _pem(project, "a.pem.levault", b"x"))
        assert "already an encrypted" in str(exc)


def test_refuses_a_renamed_envelope_by_its_magic_bytes() -> None:
    """The mistake people actually make: re-encrypting ciphertext because it
    got renamed. The suffix check alone would miss it."""
    with workspace() as project:
        for magic in (crypto.FILE_MAGIC, crypto.VAULT_MAGIC):
            src = _pem(project, "innocent.pem", magic + b"padding" * 20)
            exc = _expect(ValueError, store.precheck_encrypt, src)
            assert "already an encrypted" in str(exc)
            src.unlink()


def test_refuses_anything_inside_the_vault_root() -> None:
    with workspace():
        for name in ("vault.enc", "vault_index.json", "files.json", "llm.env"):
            target = store.ROOT / name
            if not target.exists():
                target.write_bytes(b"placeholder contents")
            exc = _expect(ValueError, store.precheck_encrypt, target)
            assert "vault's own directory" in str(exc)


def test_refuses_a_symlink() -> None:
    with workspace() as project:
        src = _pem(project)
        link = project / "link.pem"
        rc = subprocess.run(["cmd", "/c", "mklink", str(link), str(src)],
                            capture_output=True).returncode
        if rc != 0:
            return  # no symlink privilege on this machine; nothing to assert
        exc = _expect(ValueError, store.precheck_encrypt, link)
        assert "symbolic link" in str(exc)
        assert src.exists()


def test_refuses_a_hard_link() -> None:
    """Destroying one name of a hard-linked file leaves the contents readable
    under the other, while reporting success."""
    with workspace() as project:
        src = _pem(project)
        link = project / "hard.pem"
        rc = subprocess.run(["cmd", "/c", "mklink", "/H", str(link), str(src)],
                            capture_output=True).returncode
        if rc != 0:
            return
        exc = _expect(ValueError, store.precheck_encrypt, src)
        assert "hard link" in str(exc)


def test_refuses_on_a_v1_vault_and_says_how_to_fix_it() -> None:
    with workspace(v2=False) as project:
        exc = _expect(ValueError, store.precheck_encrypt, _pem(project))
        assert "v2 vault" in str(exc) and "upgrade_v2" in str(exc)


def test_v1_gating_reads_the_magic_bytes_not_the_format_file() -> None:
    """vault.format.txt has a never-read invariant precisely so it cannot
    become an agent-writable downgrade lever. Writing a lie into it must not
    change the answer."""
    with workspace() as project:
        store.FORMAT_FILE.write_text("format_version=1\n", encoding="utf-8")
        info = store.precheck_encrypt(_pem(project))  # must still succeed
        assert info["size"] == len(PEM)


# ---------------------------------------------------------------------------
# Decrypt refusals
# ---------------------------------------------------------------------------

def test_refuses_to_overwrite_an_existing_output() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        src.write_bytes(b"a newer file the user made")

        exc = _expect(ValueError, store.decrypt_file_to,
                      project / "server.pem.levault", TEST_PASSWORD)
        assert "already exists" in str(exc)
        assert src.read_bytes() == b"a newer file the user made"


def test_refuses_an_output_whose_parent_does_not_exist() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        exc = _expect(ValueError, store.decrypt_file_to,
                      project / "server.pem.levault", TEST_PASSWORD,
                      output_path="no/such/dir/out.pem")
        assert "does not exist" in str(exc)


def test_refuses_an_output_inside_the_vault_root() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        exc = _expect(ValueError, store.decrypt_file_to,
                      project / "server.pem.levault", TEST_PASSWORD,
                      output_path=str(store.ROOT / "leaked.pem"))
        assert "vault's own directory" in str(exc)


def test_refuses_a_non_levault_name_with_no_explicit_output() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        (project / "server.pem.levault").rename(project / "mystery.bin")
        exc = _expect(ValueError, store.decrypt_file_to,
                      project / "mystery.bin", TEST_PASSWORD)
        assert "explicitly" in str(exc)


def test_refuses_a_file_that_is_not_an_envelope() -> None:
    with workspace() as project:
        bogus = _pem(project, "fake.levault", b"not an envelope at all")
        _expect(ValueError, store.precheck_decrypt, bogus)


def test_refuses_an_absurdly_large_envelope_without_reading_it() -> None:
    with workspace() as project:
        huge = project / "huge.levault"
        with open(huge, "wb") as handle:
            handle.write(crypto.FILE_MAGIC)
            handle.seek(crypto.MAX_FILE_ENVELOPE_BYTES + 1)
            handle.write(b"\x00")
        exc = _expect(ValueError, store.precheck_decrypt, huge)
        assert "Refusing to read" in str(exc)


def test_a_tampered_envelope_never_blames_the_password() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"
        data = bytearray(sidecar.read_bytes())
        data[-5] ^= 0x01
        sidecar.write_bytes(bytes(data))

        exc = _expect(crypto.FileEnvelopeTampered, store.decrypt_file_to,
                      sidecar, TEST_PASSWORD)
        assert "password" not in str(exc).lower()
        assert not src.exists(), "a failed decrypt left a file behind"


def test_a_file_from_another_vault_is_refused_by_generation() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"

        # Replace this vault's FMK with a different generation entirely.
        body = store.load_vault_body(TEST_PASSWORD)
        other_id = crypto.new_fmk_id()
        body[store.FMK_KEY] = {
            "active": other_id,
            "keys": {other_id: store._b64u(bytes(crypto.new_fmk()))},
        }
        store.save_vault_body(TEST_PASSWORD, body)

        exc = _expect(ValueError, store.decrypt_file_to, sidecar, TEST_PASSWORD)
        assert "retired" in str(exc) or "different vault" in str(exc)


# ---------------------------------------------------------------------------
# The registry is never authoritative and never parameterises a write
# ---------------------------------------------------------------------------

def test_a_malicious_mode_in_the_registry_is_not_applied() -> None:
    """files.json is agent-writable. If the restored mode came from there,
    an agent could make a private key world-readable by editing a text file."""
    with workspace() as project:
        src = _pem(project)
        os.chmod(src, 0o600)
        store.encrypt_file_in_place(src, TEST_PASSWORD)

        entries = store.load_file_registry()
        key = next(iter(entries))
        entries[key]["mode"] = "0777"
        store.save_file_registry(entries)

        store.decrypt_file_to(project / "server.pem.levault", TEST_PASSWORD)
        assert stat.S_IMODE(src.stat().st_mode) != 0o777


def test_a_redirected_restores_to_does_not_move_the_output() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)

        entries = store.load_file_registry()
        key = next(iter(entries))
        entries[key]["restores_to"] = str(project / "attacker-chosen.pem")
        store.save_file_registry(entries)

        out = store.decrypt_file_to(project / "server.pem.levault", TEST_PASSWORD)
        assert Path(out["output_path"]) == src
        assert not (project / "attacker-chosen.pem").exists()


def test_a_malformed_registry_raises_valueerror_not_keyerror() -> None:
    with workspace():
        store.FILES_FILE.write_text("{ not json", encoding="utf-8")
        _expect(ValueError, store.load_file_registry)

        store.FILES_FILE.write_text('{"version": 99, "files": {}}', encoding="utf-8")
        _expect(ValueError, store.load_file_registry)

        store.FILES_FILE.write_text(
            '{"version": 1, "files": {"a": {"mode": "0999"}}}', encoding="utf-8")
        _expect(ValueError, store.load_file_registry)

        store.FILES_FILE.write_text(
            '{"version": 1, "files": {"a": "not an object"}}', encoding="utf-8")
        _expect(ValueError, store.load_file_registry)


def test_registry_keys_are_case_normalised() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"

        entries = store.load_file_registry()
        assert store._registry_key(sidecar) in entries
        assert store._registry_key(Path(str(sidecar).upper())) in entries


# ---------------------------------------------------------------------------
# Registry status reporting
# ---------------------------------------------------------------------------

def test_status_reports_ok_missing_modified_and_plaintext_present() -> None:
    with workspace() as project:
        src = _pem(project)
        store.encrypt_file_in_place(src, TEST_PASSWORD)
        sidecar = project / "server.pem.levault"

        assert [r["status"] for r in store.file_registry_status()] == ["ok"]

        # plaintext_present: the secret is in the clear beside its ciphertext.
        store.decrypt_file_to(sidecar, TEST_PASSWORD)
        assert [r["status"] for r in store.file_registry_status()] == ["plaintext_present"]
        src.unlink()

        # modified: re-encrypted elsewhere and pulled in. Reported, never healed.
        entries = store.load_file_registry()
        entries[next(iter(entries))]["envelope_sha256"] = "0" * 64
        store.save_file_registry(entries)
        assert [r["status"] for r in store.file_registry_status()] == ["modified"]
        assert store.load_file_registry()[store._registry_key(sidecar)][
            "envelope_sha256"] == "0" * 64, "status must not heal the registry"

        sidecar.unlink()
        assert [r["status"] for r in store.file_registry_status()] == ["missing"]


def test_status_never_reveals_contents() -> None:
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        blob = json.dumps(store.file_registry_status())
        assert "BEGIN PRIVATE KEY" not in blob
        assert hashlib.sha256(PEM).hexdigest() not in blob


def test_unregister_drops_the_entry_and_leaves_the_file() -> None:
    with workspace() as project:
        store.encrypt_file_in_place(_pem(project), TEST_PASSWORD)
        sidecar = project / "server.pem.levault"
        assert store.unregister_encrypted_file(sidecar) is True
        assert store.load_file_registry() == {}
        assert sidecar.exists()
        assert store.unregister_encrypted_file(sidecar) is False


# ---------------------------------------------------------------------------
# secure_delete and locking
# ---------------------------------------------------------------------------

def test_secure_delete_removes_the_file_and_reports_true() -> None:
    with workspace() as project:
        src = _pem(project)
        assert store.secure_delete(src) is True
        assert not src.exists()


def test_secure_delete_never_raises_on_a_locked_file() -> None:
    """It runs in cleanup paths where a raise would mask the real error."""
    with workspace() as project:
        src = _pem(project)
        with open(src, "rb"):
            result = store.secure_delete(src)   # may or may not succeed
        assert isinstance(result, bool)
        store.secure_delete(src)


def test_secure_delete_on_a_missing_file_is_true_not_an_error() -> None:
    with workspace() as project:
        assert store.secure_delete(project / "never-existed") is True


def test_the_files_lock_and_targets_lock_are_independent() -> None:
    """Sharing one lock file would serialise unrelated operations and couple
    two independent failure modes."""
    with workspace():
        assert store.FILES_LOCK_FILE != store.TARGETS_LOCK_FILE
        with store._files_lock():
            with store._targets_lock():
                pass


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
