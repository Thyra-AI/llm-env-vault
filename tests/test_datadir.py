"""Where the vault lives: THYRA_VAULT_HOME > CLAUDE_PLUGIN_DATA > checkout > user data dir."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from thyra_vault import datadir  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
HOME = Path("/home/ana")
CHECKOUT_MODULE = REPO_ROOT / "thyra_vault" / "store.py"
SITE_MODULE = Path("/home/ana/.cache/uv/archive-v0/x/lib/python3.12/site-packages/thyra_vault/store.py")


def resolve(env, module=CHECKOUT_MODULE, frozen=False, platform="linux"):
    return datadir.resolve_root(env, module, frozen=frozen, platform=platform, home=HOME)


def test_explicit_home_beats_everything(tmp_path):
    env = {"THYRA_VAULT_HOME": str(tmp_path / "mine"), "CLAUDE_PLUGIN_DATA": "/x"}
    assert resolve(env, SITE_MODULE, frozen=True) == (tmp_path / "mine").resolve()


def test_plugin_data_comes_second(tmp_path):
    env = {"CLAUDE_PLUGIN_DATA": str(tmp_path)}
    assert resolve(env, SITE_MODULE) == tmp_path.resolve() / "vault"


def test_blank_explicit_home_is_ignored(tmp_path):
    env = {"THYRA_VAULT_HOME": "   ", "CLAUDE_PLUGIN_DATA": str(tmp_path)}
    assert resolve(env) == tmp_path.resolve() / "vault"
    assert datadir.explicit_location_given({"THYRA_VAULT_HOME": "  "}) is False


def test_a_source_checkout_keeps_the_old_location():
    assert resolve({}) == REPO_ROOT


@pytest.mark.parametrize("module,frozen", [(SITE_MODULE, False), (CHECKOUT_MODULE, True),
                                           (Path("/usr/lib/python3/dist-packages/thyra_vault/store.py"), False)])
def test_package_and_frozen_installs_use_the_user_data_dir(module, frozen):
    assert resolve({}, module, frozen) == HOME / ".local" / "share" / "thyra-vault"


def test_xdg_data_home_is_honoured_only_when_absolute():
    assert resolve({"XDG_DATA_HOME": "/data/xdg"}, SITE_MODULE) == Path("/data/xdg/thyra-vault")
    assert resolve({"XDG_DATA_HOME": "relative/dir"}, SITE_MODULE) == HOME / ".local/share/thyra-vault"


def test_macos_location():
    assert resolve({}, SITE_MODULE, platform="darwin") == HOME / "Library/Application Support/Thyra Vault"


def test_windows_location():
    got = datadir.user_data_dir("win32", {"LOCALAPPDATA": "C:/Users/Ana/AppData/Local"}, HOME)
    assert got.name == "Thyra Vault" and got.parent.name == "Local"
    assert datadir.user_data_dir("win32", {}, HOME) == HOME / "AppData" / "Local" / "Thyra Vault"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_new_directory_is_owner_only(tmp_path):
    target = tmp_path / "a" / "vault"
    datadir.make_private_dir(target)
    assert (target.stat().st_mode & 0o777) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_existing_directory_permissions_are_left_alone(tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    os.chmod(target, 0o750)
    datadir.make_private_dir(target)
    assert (target.stat().st_mode & 0o777) == 0o750


def test_store_honours_thyra_vault_home_in_a_fresh_process():
    with tempfile.TemporaryDirectory(prefix="thyra_home_") as home:
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_DATA"}
        env["THYRA_VAULT_HOME"] = home
        out = subprocess.run([sys.executable, "-c", "from thyra_vault import store; print(store.ROOT)"],
                             cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, check=True)
        assert out.stdout.strip() == str(Path(home).resolve())


def test_explicit_home_disarms_the_plugin_cache_refusal():
    """A copy under plugins/cache is fine when the user pinned the vault dir."""
    with tempfile.TemporaryDirectory(prefix="fake_repo_") as fake, \
            tempfile.TemporaryDirectory(prefix="thyra_home_") as home:
        plugin = Path(fake) / "plugins" / "cache" / "thyra-vault" / "1.0.0"
        lib = plugin / "thyra_vault"
        lib.mkdir(parents=True)
        for name in ("__init__.py", "store.py", "crypto.py", "procs.py", "datadir.py"):
            (lib / name).write_bytes((REPO_ROOT / "thyra_vault" / name).read_bytes())
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_DATA"}
        env["THYRA_VAULT_HOME"] = home
        proc = subprocess.run(
            [sys.executable, "-c",
             "from thyra_vault import store; store.create_secrets_vault('a-long-enough-pass'); print('ok')"],
            cwd=str(plugin), env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


# --- adopting a vault left by the old plugin id (llm-env-vault) ---------------

def _legacy(parent, name="llm-env-vault-llm-env-vault", files=None, mtime=None):
    vault = parent / name / "vault"
    vault.mkdir(parents=True)
    for fname, content in (files or {"vault.enc": b"ENC", "vault.salt": b"SALT", "vault_index.json": b"{}",
                                     "vault.enc.lock": b"", "vault.attempts.json.lock": b""}).items():
        (vault / fname).write_bytes(content)
    if mtime:
        os.utime(vault / "vault.enc", (mtime, mtime))
    return vault


def test_the_old_vault_is_copied_into_the_new_plugin_data_dir(tmp_path):
    old = _legacy(tmp_path)
    new_data = tmp_path / "thyra-vault-thyra-vault"
    root = new_data / "vault"
    root.mkdir(parents=True)
    assert datadir.adopt_legacy_vault(root, str(new_data)) == old
    assert (root / "vault.enc").read_bytes() == b"ENC" and (root / "vault.salt").read_bytes() == b"SALT"
    assert (root / "vault_index.json").exists()
    assert not (root / "vault.enc.lock").exists()           # locks are not copied
    assert (root / datadir.ADOPTED_NOTE).exists()
    assert not (root / ".adopting").exists()                 # staging area cleaned up
    assert (old / "vault.enc").read_bytes() == b"ENC"        # the original is untouched
    assert (old / "vault.salt").exists()


def test_adoption_happens_once_and_never_overwrites_a_vault(tmp_path):
    _legacy(tmp_path)
    new_data = tmp_path / "thyra-vault-thyra-vault"
    root = new_data / "vault"
    root.mkdir(parents=True)
    (root / "vault.enc").write_bytes(b"MINE")
    assert datadir.adopt_legacy_vault(root, str(new_data)) is None
    assert (root / "vault.enc").read_bytes() == b"MINE"
    (root / "vault.enc").unlink()
    assert datadir.adopt_legacy_vault(root, str(new_data)) is not None
    (root / "vault.enc").write_bytes(b"CHANGED")
    assert datadir.adopt_legacy_vault(root, str(new_data)) is None   # the note says it already happened
    assert (root / "vault.enc").read_bytes() == b"CHANGED"


def test_the_newest_legacy_vault_wins(tmp_path):
    _legacy(tmp_path, "llm-env-vault-marketplace-a", {"vault.enc": b"OLD"}, mtime=1_000_000)
    _legacy(tmp_path, "llm-env-vault-marketplace-b", {"vault.enc": b"NEW"}, mtime=2_000_000)
    new_data = tmp_path / "thyra-vault-thyra-vault"
    root = new_data / "vault"
    root.mkdir(parents=True)
    datadir.adopt_legacy_vault(root, str(new_data))
    assert (root / "vault.enc").read_bytes() == b"NEW"


def test_unrelated_plugins_and_missing_vaults_are_ignored(tmp_path):
    _legacy(tmp_path, "some-other-plugin")
    (tmp_path / "llm-env-vault-empty" / "vault").mkdir(parents=True)
    new_data = tmp_path / "thyra-vault-thyra-vault"
    root = new_data / "vault"
    root.mkdir(parents=True)
    assert datadir.adopt_legacy_vault(root, str(new_data)) is None
    assert not (root / "vault.enc").exists()
    assert datadir.adopt_legacy_vault(root, None) is None


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_links_in_the_old_vault_are_not_followed(tmp_path):
    old = _legacy(tmp_path)
    secret = tmp_path / "elsewhere.txt"
    secret.write_text("not part of the vault")
    (old / "linked.txt").symlink_to(secret)
    new_data = tmp_path / "thyra-vault-thyra-vault"
    root = new_data / "vault"
    root.mkdir(parents=True)
    datadir.adopt_legacy_vault(root, str(new_data))
    assert not (root / "linked.txt").exists()


def test_an_explicit_home_disables_adoption():
    assert datadir.explicit_home_given({"THYRA_VAULT_HOME": "/x"}) is True
    assert datadir.explicit_home_given({"CLAUDE_PLUGIN_DATA": "/x"}) is False


def test_a_real_vault_made_under_the_old_plugin_id_opens_under_the_new_one():
    """End to end, in fresh processes exactly as Claude Code would start them."""
    code_make = ("from thyra_vault import store, crypto\n"
                 "crypto.SCRYPT_DEFAULT = crypto.ScryptParams(n=2**12, r=8, p=1)\n"
                 "store.create_v2_vault('a-long-enough-pass')\n"
                 "store.save_secrets('a-long-enough-pass', {'API_TOKEN': 'tok-123'})\n"
                 "store.save_index({'API_TOKEN': 1})\n")
    code_open = ("from thyra_vault import store\n"
                 "print(store.load_secrets('a-long-enough-pass')['API_TOKEN'], store.load_index())\n")
    with tempfile.TemporaryDirectory(prefix="adopt_e2e_") as tmp:
        base = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "THYRA_VAULT_HOME")}
        old = Path(tmp) / "llm-env-vault-llm-env-vault"
        new = Path(tmp) / "thyra-vault-thyra-vault"
        subprocess.run([sys.executable, "-c", code_make], cwd=str(REPO_ROOT), check=True,
                       env={**base, "CLAUDE_PLUGIN_DATA": str(old)}, capture_output=True, text=True)
        out = subprocess.run([sys.executable, "-c", code_open], cwd=str(REPO_ROOT), check=True,
                             env={**base, "CLAUDE_PLUGIN_DATA": str(new)}, capture_output=True, text=True)
        assert out.stdout.strip() == "tok-123 {'API_TOKEN': 1}"
        assert "copied your existing vault" in out.stderr
        assert (old / "vault" / "vault.enc").exists()      # the original is still there
