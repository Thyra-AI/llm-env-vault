"""Regression tests for the store hardening fixes: reissue rotates the DEK,
secure_delete_ex refuses links, vault reads are bounded, stale .bak files go."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from thyra_vault import crypto, store  # noqa: E402

PW = "hardening-test-password-1"


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "SCRYPT_DEFAULT", crypto.ScryptParams(n=2 ** 12, r=8, p=1))
    for name, fname in (("SALT_FILE", "vault.salt"), ("SECRETS_FILE", "vault.enc"),
                        ("INDEX_FILE", "vault_index.json"), ("ENV_FILE", "llm.env"),
                        ("BAK_FILE", "vault.enc.bak"), ("FORMAT_FILE", "vault.format.txt"),
                        ("VAULT_LOCK_FILE", "vault.enc.lock")):
        monkeypatch.setattr(store, name, tmp_path / fname)
    monkeypatch.setattr(store, "ROOT", tmp_path)
    rk = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
    store.create_v2_vault(PW, recovery_raw=crypto.parse_recovery_key(rk))
    store.save_secrets(PW, {"A_TOKEN": "value-1"})
    return tmp_path, rk


# --- 1. reissue rotates the DEK -------------------------------------------------

def test_reissue_rotates_dek_so_old_recovery_key_and_dek_are_dead(vault):
    tmp, old_rk = vault
    snapshot = store.SECRETS_FILE.read_bytes()
    _pt, old_dek, _h = crypto.open_v2_with_recovery(snapshot, old_rk)

    new_rk = store.reissue_recovery_key(PW)
    new_data = store.SECRETS_FILE.read_bytes()

    with pytest.raises((crypto.WrongRecoveryKey, crypto.VaultTampered)):
        crypto.open_v2_with_recovery(new_data, old_rk)
    header, aad, body = crypto.parse_envelope(new_data)
    with pytest.raises(crypto.VaultTampered):
        crypto.open_body(bytes(old_dek), body, aad)
    crypto.open_body(bytes(crypto.open_v2_with_password(new_data, PW)[1]), body, aad)
    crypto.open_v2_with_recovery(new_data, new_rk)
    assert store.load_secrets(PW)["A_TOKEN"] == "value-1"
    assert not store.BAK_FILE.exists()


# --- 2. secure_delete_ex refuses links ------------------------------------------

def test_secure_delete_does_not_write_through_a_symlink(tmp_path):
    target = tmp_path / "precious"
    target.write_bytes(b"keep me" * 10)
    link = tmp_path / "link"
    link.symlink_to(target)
    out = store.secure_delete_ex(link)
    assert target.read_bytes() == b"keep me" * 10
    assert out["overwritten"] is False


def test_secure_delete_refuses_a_different_inode_or_hard_link(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"x" * 100)
    st = f.stat()
    assert store.secure_delete_ex(f, expected_id=(st.st_dev, st.st_ino + 1)) == {
        "removed": False, "overwritten": False}
    assert f.read_bytes() == b"x" * 100
    os.link(f, tmp_path / "g")
    assert store.secure_delete_ex(f, expected_id=(st.st_dev, st.st_ino))["removed"] is False
    assert (tmp_path / "g").read_bytes() == b"x" * 100


def test_secure_delete_still_shreds_a_plain_file(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"secret")
    st = f.stat()
    assert store.secure_delete_ex(f, expected_id=(st.st_dev, st.st_ino)) == {
        "removed": True, "overwritten": True}
    assert not f.exists()


# --- 3. bounded vault reads ------------------------------------------------------

def test_a_fifo_vault_does_not_hang(tmp_path, monkeypatch):
    fifo = tmp_path / "vault.enc"
    os.mkfifo(fifo)
    monkeypatch.setattr(store, "SECRETS_FILE", fifo)
    assert store.vault_exists() is False
    with pytest.raises(OSError):
        store._read_secrets_file()


def test_a_symlinked_or_oversized_vault_is_refused(tmp_path, monkeypatch):
    link = tmp_path / "vault.enc"
    link.symlink_to("/dev/zero")
    monkeypatch.setattr(store, "SECRETS_FILE", link)
    assert store.vault_exists() is False
    with pytest.raises(OSError):
        store._read_secrets_file()
    big = tmp_path / "big"
    big.write_bytes(b"\0" * 1024)
    monkeypatch.setattr(store, "_MAX_VAULT_BYTES", 512)
    with pytest.raises(OSError):
        store._read_vault_file(big)


def test_vault_exists_reads_only_the_magic(vault, monkeypatch):
    seen = []
    real = store._read_vault_file
    monkeypatch.setattr(store, "_read_vault_file",
                        lambda p, limit=None: seen.append(limit) or real(p, limit))
    assert store.vault_exists() is True
    assert seen == [len(crypto.VAULT_MAGIC)]


# --- 4. stale .bak ----------------------------------------------------------------

def test_backup_is_removed_when_the_write_dies_midway(vault, monkeypatch):
    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(store, "_verify_v2_slots", boom)
    with pytest.raises(KeyboardInterrupt):
        store.reissue_recovery_key(PW)
    assert not store.BAK_FILE.exists()


def test_change_password_removes_backup_on_oserror(vault, monkeypatch):
    real = store._atomic_write_bytes

    def flaky(path, data, *a, **k):
        if path == store.SECRETS_FILE:
            raise OSError("disk full")
        return real(path, data, *a, **k)
    monkeypatch.setattr(store, "_atomic_write_bytes", flaky)
    with pytest.raises(OSError):
        store.change_password(PW, "another-password-2")
    assert not store.BAK_FILE.exists()


def test_stale_backup_swept_only_when_vault_is_structurally_sound(vault):
    tmp, _rk = vault
    store.BAK_FILE.write_bytes(b"old")
    with store._vault_lock():
        pass
    assert not store.BAK_FILE.exists()

    good = store.SECRETS_FILE.read_bytes()
    store.BAK_FILE.write_bytes(good)
    store.SECRETS_FILE.write_bytes(good[:20])          # damaged vault.enc
    with store._vault_lock():
        pass
    assert store.BAK_FILE.read_bytes() == good          # may be the only good copy

    store.SECRETS_FILE.unlink()                         # missing vault.enc
    with store._vault_lock():
        pass
    assert store.BAK_FILE.read_bytes() == good
