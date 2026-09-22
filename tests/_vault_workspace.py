"""
Shared test fixtures: an isolated v2 vault plus a project whose .env is a
registered, placeholder-only target.

These lived in the 1.7.1 swap suite because swap was the first thing that
needed a registered target with known contents. They are not swap-specific
-- single-view, the 1.6.1 hardening suite and the consumption matrix all
build on them -- so they moved here when that suite was deleted rather than
being re-implemented three times.

`workspace()` yields (project_dir, env_path). `fake_dialog()` replaces the
Tk unlock dialog so no window opens; `stub_run()` replaces the subprocess
call so a test can observe the environment a command would have seen.
"""
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, legacy_swap, procs, store, trust  # noqa: E402

TEST_PASSWORD = "swap-suite-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
SECRETS = {
    "API_TOKEN": "tok-abcdefgh-123456",
    "DB_PASSWORD": "p$ss w#rd 'quoted' \"dq\"",
    "PLAIN": "justletters123",
}
INDEX = {"API_TOKEN": 1, "DB_PASSWORD": 2, "PLAIN": 3}

PLACEHOLDER_ENV = (b"# project config\r\n"
                   b"export API_TOKEN=\"value 1\"\r\n"
                   b"  DB_PASSWORD=\"value 2\"  \r\n"
                   b"PLAIN=\"value 3\"\r\n"
                   b"OTHER=untouched\r\n")


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
    p = legacy_swap._journal_path()
    return json.loads(p.read_text(encoding="utf-8"))["entries"] if p.exists() else {}