"""
Regression suite for the v2 storage layer additions to vault_lib/store.py.

Covers the v2 AES-256-GCM/scrypt vault format introduced in 1.4.0:

  - v1 vaults still load and save via the legacy PBKDF2/Fernet path.
  - v2 vaults round-trip through create → load → save → load correctly.
  - Creating over an existing vault raises and leaves bytes byte-identical
    (prevents "Create Vault" over a populated vault from wiping secrets).
  - vault_exists() is True for a v2 vault even with no vault.salt present.
  - Upgrading v1→v2 preserves every secret and leaves vault.salt on disk
    (a surviving v1 backup is undecryptable without its salt).
  - change_password on v2 rotates the DEK (old wrapped DEK is gone) and
    issues a fresh recovery key with a new slot id.
  - The old recovery key is invalid after a password change.
  - recover_with_recovery_key restores access and sets a new password.
  - Read-back failure after a credential write rolls back the original bytes.
  - compare-and-swap (expect_fingerprint) rejects a stale fingerprint.
  - A below-SCRYPT_FLOOR password-slot header is silently upgraded on save.
  - vault.enc.bak is deleted after a successful credential change.
  - PKCS7 padding length-coarsening holds for v2 just as for v1.

Monkeypatches crypto.SCRYPT_DEFAULT to n=2**12 (~6 ms per derivation) for
the entire module so the suite runs in seconds rather than minutes.

Every test creates an isolated temp directory and redirects all store path
globals into it -- the developer's real vault.enc / vault.salt / vault.format.txt
/ vault.enc.bak are never read or written.

Runs under pytest (``pytest tests/test_store_v2.py -q``) or standalone
(``python tests/test_store_v2.py``), matching test_store_hardening.py.
"""
import base64
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib import crypto, store  # noqa: E402

# ---------------------------------------------------------------------------
# Monkeypatch SCRYPT_DEFAULT to n=2**12 for the entire module (speed).
# Wrap in try/finally so the original value is always restored even if import
# fails -- but since this is module-level, it runs once at import time and
# stays in effect for all tests in this module.
# ---------------------------------------------------------------------------
_ORIG_SCRYPT_DEFAULT = crypto.SCRYPT_DEFAULT
crypto.SCRYPT_DEFAULT = crypto.ScryptParams(n=2 ** 12, r=8, p=1)

TEST_PASSWORD = "regression-test-password-v2-123"
NEW_PASSWORD = "brand-new-v2-password-456"
BASE_SECRETS = {"DOCKER_TEST_TOKEN": "tok-abc-123", "OTHER_SECRET": "other-xyz-789"}


# ---------------------------------------------------------------------------
# Isolation helpers
# ---------------------------------------------------------------------------

def _isolate_store_paths(tmp_dir: Path) -> dict:
    """Redirect every store path global to *tmp_dir* and return originals."""
    originals = {
        "SALT_FILE": store.SALT_FILE,
        "SECRETS_FILE": store.SECRETS_FILE,
        "INDEX_FILE": store.INDEX_FILE,
        "ENV_FILE": store.ENV_FILE,
        "BAK_FILE": store.BAK_FILE,
        "FORMAT_FILE": store.FORMAT_FILE,
    }
    store.SALT_FILE = tmp_dir / "vault.salt"
    store.SECRETS_FILE = tmp_dir / "vault.enc"
    store.INDEX_FILE = tmp_dir / "vault_index.json"
    store.ENV_FILE = tmp_dir / "llm.env"
    store.BAK_FILE = tmp_dir / "vault.enc.bak"
    store.FORMAT_FILE = tmp_dir / "vault.format.txt"
    return originals


def _restore_store_paths(originals: dict) -> None:
    for name, value in originals.items():
        setattr(store, name, value)


@contextlib.contextmanager
def isolated_v1_vault(secrets=None):
    """Temp dir with a real v1 vault (TEST_PASSWORD, BASE_SECRETS by default)."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_secrets_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, secrets)
            yield tmp_path
        finally:
            _restore_store_paths(originals)


@contextlib.contextmanager
def isolated_v2_vault(secrets=None, recovery=False):
    """Temp dir with a real v2 vault (TEST_PASSWORD, BASE_SECRETS by default)."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            recovery_raw = bytes(crypto.new_recovery_key()) if recovery else None
            rk_text = store.create_v2_vault(TEST_PASSWORD, recovery_raw=recovery_raw)
            store.save_secrets(TEST_PASSWORD, secrets)
            yield tmp_path, rk_text
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# v1 compatibility
#
# The v1 path (PBKDF2/Fernet) must be entirely unaffected by the v2 changes.
# If these tests regress, every existing 1.3.0 vault in the wild breaks.
# ---------------------------------------------------------------------------

def test_v1_vault_loads_and_saves_unchanged() -> None:
    """v1 vault round-trips correctly; save does not change the format to v2."""
    with isolated_v1_vault() as tmp:
        loaded = store.load_secrets(TEST_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: v1 load returned {loaded!r}, expected {BASE_SECRETS!r}"
        )
        # save and reload
        new_secrets = dict(BASE_SECRETS)
        new_secrets["EXTRA"] = "extra-value"
        store.save_secrets(TEST_PASSWORD, new_secrets)
        reloaded = store.load_secrets(TEST_PASSWORD)
        assert reloaded == new_secrets, (
            f"REGRESSION: v1 save/load round-trip failed -- got {reloaded!r}"
        )
        # Must still be v1 on disk (save must not silently promote format)
        data = store.SECRETS_FILE.read_bytes()
        assert not crypto.is_v2(data), (
            "REGRESSION: save_secrets promoted a v1 vault to v2 silently"
        )


def test_v1_change_password_still_works() -> None:
    """The legacy v1 change_password path returns None and round-trips."""
    with isolated_v1_vault() as tmp:
        result = store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert result is None, (
            f"REGRESSION: v1 change_password returned {result!r}, expected None"
        )
        loaded = store.load_secrets(NEW_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: v1 change_password corrupted secrets -- got {loaded!r}"
        )


# ---------------------------------------------------------------------------
# v2 create / load / save round-trip
#
# Validates the full happy path: create an empty v2 vault, populate it, save,
# reload.  Exercises all three of _pkcs7_pad, build_v2_vault, open_v2_with_password,
# and _pkcs7_unpad_strict in sequence.
# ---------------------------------------------------------------------------

def test_v2_create_load_save_round_trip() -> None:
    """v2 vault create → save secrets → load secrets round-trip."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            # vault.enc must be v2
            data = store.SECRETS_FILE.read_bytes()
            assert crypto.is_v2(data), "create_v2_vault did not write a v2 envelope"

            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)
            loaded = store.load_secrets(TEST_PASSWORD)
            assert loaded == BASE_SECRETS, (
                f"REGRESSION: v2 round-trip failed -- got {loaded!r}"
            )

            # Second save/load cycle
            updated = dict(BASE_SECRETS)
            updated["NEW_KEY"] = "new-value"
            store.save_secrets(TEST_PASSWORD, updated)
            loaded2 = store.load_secrets(TEST_PASSWORD)
            assert loaded2 == updated, (
                f"REGRESSION: v2 second round-trip failed -- got {loaded2!r}"
            )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# Create-over-existing vault guard
#
# This is the highest data-loss risk in the whole project.  A v2 vault has no
# vault.salt, so vault_exists() returned False before this patch.  If the GUI
# offered "Create Vault" over a populated vault.enc, the only defence was the
# vault.salt guard -- which no longer exists for v2.
#
# Both create_secrets_vault and create_v2_vault must refuse outright and leave
# the existing bytes byte-identical.
# ---------------------------------------------------------------------------

def test_create_v2_vault_refuses_if_secrets_file_exists() -> None:
    """create_v2_vault raises and leaves vault.enc bytes identical."""
    with isolated_v2_vault() as (tmp, _rk):
        before = store.SECRETS_FILE.read_bytes()
        try:
            store.create_v2_vault(TEST_PASSWORD)
        except RuntimeError:
            pass  # expected
        else:
            raise AssertionError(
                "REGRESSION: create_v2_vault did not raise when vault.enc exists"
            )
        after = store.SECRETS_FILE.read_bytes()
        assert before == after, (
            "REGRESSION: create_v2_vault modified vault.enc even though it raised"
        )


def test_create_secrets_vault_refuses_if_secrets_file_exists() -> None:
    """create_secrets_vault raises when vault.enc already exists (regardless of format)."""
    with isolated_v2_vault() as (tmp, _rk):
        before = store.SECRETS_FILE.read_bytes()
        try:
            store.create_secrets_vault(TEST_PASSWORD)
        except RuntimeError:
            pass  # expected
        else:
            raise AssertionError(
                "REGRESSION: create_secrets_vault did not raise when vault.enc exists"
            )
        after = store.SECRETS_FILE.read_bytes()
        assert before == after, (
            "REGRESSION: create_secrets_vault modified vault.enc even though it raised"
        )


# ---------------------------------------------------------------------------
# vault_exists for v2
#
# vault_exists() must return True even when vault.salt is absent, so the GUI
# does not offer "Create Vault" over an existing populated v2 vault.
# ---------------------------------------------------------------------------

def test_vault_exists_true_for_v2_without_salt_file() -> None:
    """vault_exists() returns True for a v2 vault when vault.salt is absent."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            # Confirm no salt file was created
            assert not store.SALT_FILE.exists(), (
                "create_v2_vault should not write vault.salt"
            )
            assert store.vault_exists(), (
                "REGRESSION: vault_exists() returned False for a v2 vault with no salt file"
            )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# Upgrade v1 → v2
#
# Upgrading must preserve every secret and -- critically -- must NOT delete
# vault.salt.  A surviving v1 backup (vault.enc.bak or a user copy) needs
# its salt to decrypt; deleting 16 bytes to tidy up silently destroys every
# v1 backup the user holds.
# ---------------------------------------------------------------------------

def test_upgrade_v1_to_v2_preserves_secrets_and_keeps_salt() -> None:
    """upgrade_to_v2 keeps every secret and leaves vault.salt on disk."""
    with isolated_v1_vault() as tmp:
        assert store.SALT_FILE.exists(), "Test precondition: vault.salt must exist for v1"
        rk_text = store.upgrade_to_v2(TEST_PASSWORD, recovery=True)

        assert rk_text is not None, "upgrade_to_v2(recovery=True) must return a key string"
        assert rk_text.startswith("RK1 "), (
            f"REGRESSION: returned key has unexpected prefix: {rk_text!r}"
        )
        # vault.salt must survive -- see function docstring
        assert store.SALT_FILE.exists(), (
            "REGRESSION: upgrade_to_v2 deleted vault.salt -- "
            "v1 backups are now permanently undecryptable"
        )
        # vault must now be v2
        data = store.SECRETS_FILE.read_bytes()
        assert crypto.is_v2(data), "vault.enc is not v2 after upgrade"

        # All secrets preserved
        loaded = store.load_secrets(TEST_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: upgrade_to_v2 lost secrets -- got {loaded!r}"
        )

        # Recovery key works too
        plaintext, _dek, _hdr = crypto.open_v2_with_recovery(data, rk_text)
        recovered = json.loads(store._pkcs7_unpad_strict(plaintext))
        assert recovered == BASE_SECRETS, (
            f"REGRESSION: recovery key cannot read secrets after upgrade -- got {recovered!r}"
        )


def test_upgrade_v2_raises_if_already_v2() -> None:
    """upgrade_to_v2 raises RuntimeError when the vault is already v2."""
    with isolated_v2_vault() as (tmp, _rk):
        try:
            store.upgrade_to_v2(TEST_PASSWORD, recovery=False)
        except RuntimeError:
            pass  # expected
        else:
            raise AssertionError(
                "REGRESSION: upgrade_to_v2 did not raise on an already-v2 vault"
            )


# ---------------------------------------------------------------------------
# change_password on v2 -- DEK rotation and recovery key rotation
#
# The core security property: rotating the password must also rotate the DEK
# so that a future leak of the old password cannot decrypt future ciphertext.
# When a recovery slot exists, a new recovery key is issued (old printout
# invalidated) so the caller can hand the user a fresh one.
# ---------------------------------------------------------------------------

def test_change_password_v2_rotates_dek_and_issues_new_recovery_key() -> None:
    """change_password on v2 replaces the wrapped DEK bytes and returns a new key."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            # Create v2 vault with a recovery slot
            orig_rk_raw = bytes(crypto.new_recovery_key())
            store.create_v2_vault(TEST_PASSWORD, recovery_raw=orig_rk_raw)
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            # Capture wrapped DEK bytes from the original password slot
            data_before = store.SECRETS_FILE.read_bytes()
            hdr_before, _, _ = crypto.parse_envelope(data_before)
            pw_slot_before = next(
                s for s in hdr_before["slots"] if s["type"] == "password"
            )
            rk_slot_before = next(
                s for s in hdr_before["slots"] if s["type"] == "recovery"
            )
            wrapped_dek_before = pw_slot_before["wrapped_dek"]
            slot_id_before = rk_slot_before["id"]

            # Change password
            new_rk_text = store.change_password(TEST_PASSWORD, NEW_PASSWORD)

            assert new_rk_text is not None, (
                "REGRESSION: change_password on a v2 vault with recovery slot returned None"
            )
            assert new_rk_text.startswith("RK1 "), (
                f"REGRESSION: new recovery key has bad prefix: {new_rk_text!r}"
            )

            data_after = store.SECRETS_FILE.read_bytes()
            hdr_after, _, _ = crypto.parse_envelope(data_after)
            pw_slot_after = next(
                s for s in hdr_after["slots"] if s["type"] == "password"
            )
            rk_slot_after = next(
                s for s in hdr_after["slots"] if s["type"] == "recovery"
            )
            wrapped_dek_after = pw_slot_after["wrapped_dek"]
            slot_id_after = rk_slot_after["id"]

            # Wrapped DEK bytes MUST change (DEK rotated)
            assert wrapped_dek_before != wrapped_dek_after, (
                "REGRESSION: change_password did not rotate the DEK -- "
                "wrapped_dek bytes are identical before and after"
            )
            # Recovery slot id MUST change (new recovery key)
            assert slot_id_before != slot_id_after, (
                "REGRESSION: change_password did not replace the recovery slot id"
            )

            # New password works
            loaded = store.load_secrets(NEW_PASSWORD)
            assert loaded == BASE_SECRETS, (
                f"REGRESSION: secrets lost after change_password -- got {loaded!r}"
            )

            # New recovery key works
            plaintext, _dek, _hdr = crypto.open_v2_with_recovery(
                store.SECRETS_FILE.read_bytes(), new_rk_text
            )
            recovered = json.loads(store._pkcs7_unpad_strict(plaintext))
            assert recovered == BASE_SECRETS, (
                f"REGRESSION: new recovery key cannot read secrets after change_password"
            )
        finally:
            _restore_store_paths(originals)


def test_change_password_v2_no_recovery_slot_returns_none() -> None:
    """change_password on v2 vault without recovery slot returns None."""
    with isolated_v2_vault() as (tmp, _rk):  # no recovery_raw in isolated_v2_vault default
        result = store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert result is None, (
            f"REGRESSION: change_password returned {result!r} instead of None "
            "when no recovery slot exists"
        )
        loaded = store.load_secrets(NEW_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: secrets lost after change_password without recovery -- got {loaded!r}"
        )


# ---------------------------------------------------------------------------
# Old recovery key invalid after password change
#
# After change_password, the old recovery printout must no longer open the
# vault -- the new key was issued, the old one is dead.
# ---------------------------------------------------------------------------

def test_old_recovery_key_invalid_after_password_change() -> None:
    """The old recovery key raises after change_password rotates the slot."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            orig_rk_raw = bytes(crypto.new_recovery_key())
            orig_rk_text = crypto.format_recovery_key(orig_rk_raw)
            store.create_v2_vault(TEST_PASSWORD, recovery_raw=orig_rk_raw)
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            store.change_password(TEST_PASSWORD, NEW_PASSWORD)

            data = store.SECRETS_FILE.read_bytes()
            try:
                crypto.open_v2_with_recovery(data, orig_rk_text)
            except (crypto.WrongRecoveryKey, crypto.VaultTampered):
                pass  # expected
            else:
                raise AssertionError(
                    "REGRESSION: old recovery key still opened vault after change_password -- "
                    "recovery slot rotation did not take effect"
                )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# recover_with_recovery_key
#
# Validates the full disaster-recovery flow: open with the recovery key,
# set a new password, get a new recovery key back.
# ---------------------------------------------------------------------------

def test_recover_with_recovery_key_restores_access() -> None:
    """recover_with_recovery_key sets a new password and returns a new key."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            orig_rk_raw = bytes(crypto.new_recovery_key())
            orig_rk_text = crypto.format_recovery_key(orig_rk_raw)
            store.create_v2_vault(TEST_PASSWORD, recovery_raw=orig_rk_raw)
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            RECOVERY_PASSWORD = "recovered-password-789"
            new_rk_text = store.recover_with_recovery_key(orig_rk_text, RECOVERY_PASSWORD)

            assert new_rk_text is not None, (
                "REGRESSION: recover_with_recovery_key returned None"
            )
            assert new_rk_text.startswith("RK1 "), (
                f"REGRESSION: returned key has unexpected prefix: {new_rk_text!r}"
            )

            # New password must work
            loaded = store.load_secrets(RECOVERY_PASSWORD)
            assert loaded == BASE_SECRETS, (
                f"REGRESSION: recover_with_recovery_key lost secrets -- got {loaded!r}"
            )

            # Old recovery key must not work
            data = store.SECRETS_FILE.read_bytes()
            try:
                crypto.open_v2_with_recovery(data, orig_rk_text)
            except (crypto.WrongRecoveryKey, crypto.VaultTampered):
                pass  # expected
            else:
                raise AssertionError(
                    "REGRESSION: old recovery key still works after recover_with_recovery_key"
                )

            # New recovery key must work
            plaintext, _dek, _hdr = crypto.open_v2_with_recovery(data, new_rk_text)
            recovered = json.loads(store._pkcs7_unpad_strict(plaintext))
            assert recovered == BASE_SECRETS, (
                f"REGRESSION: new recovery key cannot read secrets after recovery -- "
                f"got {recovered!r}"
            )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# Read-back failure rolls back
#
# If _verify_v2_slots raises after the file is written, the original bytes
# must be restored atomically and a RuntimeError raised.  The user's vault
# must remain openable.
# ---------------------------------------------------------------------------

def test_readback_failure_rolls_back_original_bytes() -> None:
    """A simulated read-back failure restores the original vault bytes."""
    with isolated_v2_vault() as (tmp, _rk):
        before = store.SECRETS_FILE.read_bytes()

        # Monkeypatch _verify_v2_slots to always raise
        orig_verify = store._verify_v2_slots
        def _always_fail(data, password, new_recovery_raw=None):
            raise RuntimeError("Simulated read-back failure")
        store._verify_v2_slots = _always_fail
        try:
            try:
                store.change_password(TEST_PASSWORD, NEW_PASSWORD)
            except RuntimeError:
                pass  # expected
            else:
                raise AssertionError(
                    "REGRESSION: change_password did not raise when read-back failed"
                )
        finally:
            store._verify_v2_slots = orig_verify

        after = store.SECRETS_FILE.read_bytes()
        assert before == after, (
            "REGRESSION: read-back failure did not restore original vault bytes"
        )
        # Original password must still work
        loaded = store.load_secrets(TEST_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: vault was left unopenable after failed read-back -- got {loaded!r}"
        )


# ---------------------------------------------------------------------------
# Compare-and-swap (expect_fingerprint)
#
# Two writers competing for the same vault (GUI + MCP server) must not
# silently overwrite each other.  The second writer must get an honest error.
# ---------------------------------------------------------------------------

def test_cas_rejects_stale_fingerprint() -> None:
    """save_secrets raises RuntimeError when expect_fingerprint doesn't match current bytes."""
    with isolated_v2_vault() as (tmp, _rk):
        # Read once to get fingerprint
        _secrets, _env, fp = store.load_secrets_ex(TEST_PASSWORD)

        # Simulate a concurrent write that changes the file
        store.save_secrets(TEST_PASSWORD, {"CONCURRENT": "write"})

        # Original fingerprint is now stale -- must be rejected
        try:
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS, expect_fingerprint=fp)
        except RuntimeError as exc:
            assert "compare-and-swap" in str(exc).lower() or "changed" in str(exc).lower(), (
                f"REGRESSION: CAS error message is unhelpful: {exc}"
            )
        else:
            raise AssertionError(
                "REGRESSION: save_secrets accepted a stale expect_fingerprint"
            )


def test_cas_accepts_current_fingerprint() -> None:
    """save_secrets with a fresh fingerprint succeeds normally."""
    with isolated_v2_vault() as (tmp, _rk):
        _secrets, _env, fp = store.load_secrets_ex(TEST_PASSWORD)
        # This must NOT raise
        store.save_secrets(TEST_PASSWORD, BASE_SECRETS, expect_fingerprint=fp)
        loaded = store.load_secrets(TEST_PASSWORD)
        assert loaded == BASE_SECRETS


# ---------------------------------------------------------------------------
# Below-SCRYPT_FLOOR header upgraded on save
#
# An attacker who downgrades the password-slot header to n=2**10 and writes
# it back gets that weakness persisted on the next legitimate save -- unless
# the store layer enforces a floor and rewrites at SCRYPT_DEFAULT.
# ---------------------------------------------------------------------------

def test_below_floor_header_silently_upgraded_on_save() -> None:
    """A below-floor scrypt n in the header is rewritten to SCRYPT_DEFAULT on save.

    To exercise the floor path we must actually re-wrap the DEK under the
    sub-floor params so the vault remains openable (a tampered-header-only file
    would be unreadable since the KEK would be derived with the wrong n).
    """
    sub_floor_n = 2 ** 10   # below SCRYPT_FLOOR.n == 2**14; within validate_scrypt_params range
    sub_floor_params = crypto.ScryptParams(n=sub_floor_n, r=8, p=1)

    # The module-level monkeypatch sets SCRYPT_DEFAULT to n=2**12 which is itself
    # below SCRYPT_FLOOR (n=2**14).  Restore the real default so that the upgrade
    # target is actually above the floor -- this test does exactly one extra
    # KDF derivation at n=2**16 (~1 s), which is acceptable.
    saved_default = crypto.SCRYPT_DEFAULT
    crypto.SCRYPT_DEFAULT = _ORIG_SCRYPT_DEFAULT  # real production n=2**16

    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            # Open the vault to get the DEK and vault_id.
            data = store.SECRETS_FILE.read_bytes()
            plaintext_bytes, dek, header = crypto.open_v2_with_password(data, TEST_PASSWORD)
            vault_id = base64.urlsafe_b64decode(header["vault_id"] + "==")

            # Build a new password slot that uses sub-floor params but wraps the SAME DEK.
            weak_pw_salt = os.urandom(16)
            weak_kek = crypto.derive_password_kek(TEST_PASSWORD, weak_pw_salt, sub_floor_params)
            weak_aad = crypto.slot_aad(vault_id, "password")
            weak_nonce, weak_wrapped = crypto.wrap_dek(weak_kek, bytes(dek), weak_aad)
            weak_pw_slot = {
                "type": "password",
                "kdf": {
                    "name": "scrypt",
                    "n": sub_floor_n,
                    "r": 8,
                    "p": 1,
                    "salt": base64.urlsafe_b64encode(weak_pw_salt).decode("ascii"),
                },
                "nonce": base64.urlsafe_b64encode(weak_nonce).decode("ascii"),
                "wrapped_dek": base64.urlsafe_b64encode(weak_wrapped).decode("ascii"),
            }
            tampered_header = dict(header)
            tampered_header["slots"] = [weak_pw_slot] + [
                s for s in header["slots"] if s.get("type") != "password"
            ]

            # Build the tampered envelope; vault is now openable with the sub-floor KEK.
            tampered_data = crypto.build_envelope(tampered_header, bytes(dek), plaintext_bytes)
            store.SECRETS_FILE.write_bytes(tampered_data)

            # Confirm the tampered header has sub-floor n and the vault opens.
            hdr_check, _, _ = crypto.parse_envelope(store.SECRETS_FILE.read_bytes())
            pw_check = next(s for s in hdr_check["slots"] if s["type"] == "password")
            assert pw_check["kdf"]["n"] == sub_floor_n, "Test setup failed: n not written"
            _ = store.load_secrets(TEST_PASSWORD)  # must open

            # Now trigger save_secrets -- the floor enforcement must kick in.
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            data_after = store.SECRETS_FILE.read_bytes()
            hdr_after, _, _ = crypto.parse_envelope(data_after)
            pw_after = next(s for s in hdr_after["slots"] if s["type"] == "password")
            assert pw_after["kdf"]["n"] >= crypto.SCRYPT_FLOOR.n, (
                f"REGRESSION: below-floor n={sub_floor_n} was not upgraded on save; "
                f"got n={pw_after['kdf']['n']}"
            )

            loaded = store.load_secrets(TEST_PASSWORD)
            assert loaded == BASE_SECRETS, (
                f"REGRESSION: floor upgrade lost secrets -- got {loaded!r}"
            )
        finally:
            _restore_store_paths(originals)
    # Restore the test-speed monkeypatch regardless of test outcome.
    crypto.SCRYPT_DEFAULT = saved_default


# ---------------------------------------------------------------------------
# vault.enc.bak lifecycle
#
# The backup is written before every credential-changing write and deleted
# after a successful read-back.  Leaving it behind keeps the old password
# slot alive on disk.
# ---------------------------------------------------------------------------

def test_bak_file_deleted_after_successful_credential_change() -> None:
    """vault.enc.bak is gone after change_password succeeds."""
    with isolated_v2_vault() as (tmp, _rk):
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert not store.BAK_FILE.exists(), (
            "REGRESSION: vault.enc.bak was not deleted after a successful change_password -- "
            "the old password slot is still alive on disk"
        )


def test_bak_file_preserved_on_rollback_then_cleaned() -> None:
    """After a failed credential change that rolls back, the bak file is also cleaned up."""
    with isolated_v2_vault() as (tmp, _rk):
        orig_verify = store._verify_v2_slots
        def _always_fail(data, password, new_recovery_raw=None):
            raise RuntimeError("Simulated failure")
        store._verify_v2_slots = _always_fail
        try:
            try:
                store.change_password(TEST_PASSWORD, NEW_PASSWORD)
            except RuntimeError:
                pass
        finally:
            store._verify_v2_slots = orig_verify

        assert not store.BAK_FILE.exists(), (
            "REGRESSION: vault.enc.bak was not cleaned up after a rolled-back credential change"
        )


# ---------------------------------------------------------------------------
# PKCS7 padding length-coarsening for v2
#
# GCM is CTR-based: ciphertext length == plaintext length exactly.  Without
# padding the ciphertext length leaks the aggregate byte size of all secret
# values, which is worse than Fernet's 16-byte CBC coarsening.  Padding must
# coarsen v2 output into _PAD_BLOCK (64-byte) buckets.
# ---------------------------------------------------------------------------

def test_v2_padding_length_coarsening() -> None:
    """v2 vault file sizes for small vs. slightly-larger secrets must be identical."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_v2_vault(TEST_PASSWORD)

            store.save_secrets(TEST_PASSWORD, {"A": "x"})
            short_len = store.SECRETS_FILE.stat().st_size

            # 9-byte difference in real value -- same padded bucket
            store.save_secrets(TEST_PASSWORD, {"A": "x" * 10})
            long_len = store.SECRETS_FILE.stat().st_size

            assert short_len == long_len, (
                f"REGRESSION: v2 padding not coarsening output -- "
                f"9-byte value difference changed file size ({short_len} vs {long_len})"
            )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# vault_format_version and vault_info
#
# vault_format_version() detects the format from on-disk bytes only --
# vault.format.txt is never read.  vault_info() returns the expected keys.
# ---------------------------------------------------------------------------

def test_vault_format_version_v1() -> None:
    """vault_format_version returns 1 for a v1 vault."""
    with isolated_v1_vault():
        assert store.vault_format_version() == 1, (
            f"REGRESSION: vault_format_version returned {store.vault_format_version()!r} "
            "for a v1 vault, expected 1"
        )


def test_vault_format_version_v2() -> None:
    """vault_format_version returns 2 for a v2 vault."""
    with isolated_v2_vault() as (tmp, _rk):
        assert store.vault_format_version() == 2, (
            f"REGRESSION: vault_format_version returned {store.vault_format_version()!r} "
            "for a v2 vault, expected 2"
        )


def test_vault_format_version_none_when_no_vault() -> None:
    """vault_format_version returns None when vault.enc does not exist."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            assert store.vault_format_version() is None
        finally:
            _restore_store_paths(originals)


def test_vault_info_v2_shape() -> None:
    """vault_info returns expected keys for a v2 vault with a recovery slot."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            rk_raw = bytes(crypto.new_recovery_key())
            store.create_v2_vault(TEST_PASSWORD, recovery_raw=rk_raw)
            info = store.vault_info()

            assert info.get("format") == 2, f"Expected format=2, got {info!r}"
            assert info.get("kdf") == "scrypt", f"Expected kdf=scrypt, got {info!r}"
            assert info.get("recovery_slot") is True, (
                f"Expected recovery_slot=True, got {info!r}"
            )
            assert "kdf_params" in info, f"kdf_params missing from vault_info: {info!r}"
            assert info["kdf_params"].get("n") is not None, "kdf_params.n missing"
            assert "vault_id" in info, "vault_id missing"
            assert "created" in info, "created missing"
            assert "recovery_slot_id" in info, "recovery_slot_id missing"
            assert "recovery_slot_created" in info, "recovery_slot_created missing"
        finally:
            _restore_store_paths(originals)


def test_vault_info_v2_no_recovery_slot() -> None:
    """vault_info reports recovery_slot=False when no recovery slot exists."""
    with isolated_v2_vault() as (tmp, _rk):  # default: no recovery_raw
        info = store.vault_info()
        assert info.get("recovery_slot") is False, (
            f"Expected recovery_slot=False, got {info!r}"
        )
        assert "recovery_slot_id" not in info, "recovery_slot_id should be absent"


# ---------------------------------------------------------------------------
# vault.format.txt is never read by any code path
#
# The FORMAT_FILE is purely informational.  If any code path branched on it,
# it would become an agent-writable downgrade lever.  This test writes a
# deliberately wrong version into vault.format.txt and verifies that no
# store operation reads it.
# ---------------------------------------------------------------------------

def test_vault_format_txt_never_read() -> None:
    """Writing a wrong version into vault.format.txt does not affect any operation."""
    with isolated_v2_vault() as (tmp, _rk):
        # Write garbage into FORMAT_FILE
        store.FORMAT_FILE.write_text("format_version=999\ndate=1970-01-01\n")

        # Every code path that could branch on it -- these must all work correctly
        assert store.vault_format_version() == 2, (
            "REGRESSION: vault_format_version read vault.format.txt (got wrong version)"
        )
        assert store.vault_exists() is True
        loaded = store.load_secrets(TEST_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: load_secrets produced wrong result after format file poisoning"
        )
        info = store.vault_info()
        assert info.get("format") == 2, (
            f"REGRESSION: vault_info read vault.format.txt: {info!r}"
        )


# ---------------------------------------------------------------------------
# reissue_recovery_key
# ---------------------------------------------------------------------------

def test_reissue_recovery_key_invalidates_old_and_issues_new() -> None:
    """reissue_recovery_key gives back a new formatted key; old key stops working."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_v2_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            orig_rk_raw = bytes(crypto.new_recovery_key())
            orig_rk_text = crypto.format_recovery_key(orig_rk_raw)
            store.create_v2_vault(TEST_PASSWORD, recovery_raw=orig_rk_raw)
            store.save_secrets(TEST_PASSWORD, BASE_SECRETS)

            new_rk_text = store.reissue_recovery_key(TEST_PASSWORD)
            assert new_rk_text != orig_rk_text, "New recovery key must differ from the old one"
            assert new_rk_text.startswith("RK1 "), (
                f"REGRESSION: reissued key has bad prefix: {new_rk_text!r}"
            )

            data = store.SECRETS_FILE.read_bytes()

            # Old key must not work
            try:
                crypto.open_v2_with_recovery(data, orig_rk_text)
            except (crypto.WrongRecoveryKey, crypto.VaultTampered):
                pass
            else:
                raise AssertionError(
                    "REGRESSION: old recovery key still works after reissue_recovery_key"
                )

            # New key must work
            plaintext, _dek, _hdr = crypto.open_v2_with_recovery(data, new_rk_text)
            recovered = json.loads(store._pkcs7_unpad_strict(plaintext))
            assert recovered == BASE_SECRETS, (
                f"REGRESSION: new recovery key cannot read secrets -- got {recovered!r}"
            )
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# load_secrets_ex -- (secrets, envelope_or_None, fingerprint) contract
# ---------------------------------------------------------------------------

def test_load_secrets_ex_v2_returns_envelope_and_fingerprint() -> None:
    """load_secrets_ex for v2 returns (secrets, envelope_bytes, fingerprint)."""
    with isolated_v2_vault() as (tmp, _rk):
        secrets, envelope, fp = store.load_secrets_ex(TEST_PASSWORD)
        assert secrets == BASE_SECRETS, f"secrets mismatch: {secrets!r}"
        assert envelope is not None, "envelope should not be None for v2"
        assert crypto.is_v2(envelope), "envelope should be v2 bytes"
        assert isinstance(fp, str) and len(fp) == 64, f"fingerprint bad: {fp!r}"


def test_load_secrets_ex_v1_returns_none_envelope() -> None:
    """load_secrets_ex for v1 returns (secrets, None, fingerprint)."""
    with isolated_v1_vault():
        secrets, envelope, fp = store.load_secrets_ex(TEST_PASSWORD)
        assert secrets == BASE_SECRETS
        assert envelope is None, "envelope should be None for v1"
        assert isinstance(fp, str) and len(fp) == 64


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches test_store_hardening.py)
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
    # Restore original SCRYPT_DEFAULT on exit so the process isn't polluted.
    try:
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
    finally:
        crypto.SCRYPT_DEFAULT = _ORIG_SCRYPT_DEFAULT
