"""
MCP-tool suite for encrypt_file / decrypt_file and vault_status's file list.

These tests drive the _impl functions directly with gui.encrypt_file_dialog and
gui.decrypt_file_dialog monkeypatched, which is the same shape every other tool
suite here uses: the dialog is the consent boundary, and no test may ever open
a real Tk window.

What matters at this layer, as opposed to the store layer below it:

  * The tool contract. Never raise; {"applied": bool} plus exactly one of
    "error"/"message"; denial is literally "Denied by user."
  * Fast-fail. Every refusal must be reachable WITHOUT a dialog opening, so a
    hopeless request does not put a modal window in front of a human.
  * vault_status must report encrypted files by name and never by content.
  * The git warnings, which are the difference between "encrypted" and
    "actually protected" for a file that was already committed.

Runs under pytest (`pytest tests/test_file_tools.py -q`) or standalone
(`python tests/test_file_tools.py`).
"""
import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, store  # noqa: E402

TEST_PASSWORD = "file-tools-test-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
PEM = b"-----BEGIN PRIVATE KEY-----\nfake key material here\n-----END PRIVATE KEY-----\n"


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
def workspace(*, v2=True):
    with tempfile.TemporaryDirectory(prefix="llm_filetools_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        project = tmp_path / "project"
        project.mkdir()
        try:
            if v2:
                store.create_v2_vault(TEST_PASSWORD)
            else:
                store.create_secrets_vault(TEST_PASSWORD)
            store.save_index({})
            yield project
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


@contextlib.contextmanager
def fake_encrypt_dialog(approve=True, partial=None):
    """Monkeypatch gui.encrypt_file_dialog. Yields the list of calls made, so a
    test can assert a dialog did NOT open for a request that should fast-fail."""
    original = gui.encrypt_file_dialog
    calls = []

    def wrapper(path):
        calls.append(Path(path))
        if partial is not None:
            return {"approved": False, "partial_failure": partial, "result": None}
        if not approve:
            return {"approved": False, "partial_failure": None, "result": None}
        result = store.encrypt_file_in_place(Path(path), TEST_PASSWORD)
        return {"approved": True, "partial_failure": None, "result": result}

    gui.encrypt_file_dialog = wrapper
    try:
        yield calls
    finally:
        gui.encrypt_file_dialog = original


@contextlib.contextmanager
def fake_decrypt_dialog(approve=True):
    original = gui.decrypt_file_dialog
    calls = []

    def wrapper(vault_path, output_path=None):
        calls.append((Path(vault_path), output_path))
        if not approve:
            return {"approved": False, "partial_failure": None, "result": None}
        result = store.decrypt_file_to(Path(vault_path), TEST_PASSWORD,
                                       output_path=output_path)
        return {"approved": True, "partial_failure": None, "result": result}

    gui.decrypt_file_dialog = wrapper
    try:
        yield calls
    finally:
        gui.decrypt_file_dialog = original


def _pem(project: Path, name="server.pem", data=PEM) -> Path:
    path = project / name
    path.write_bytes(data)
    return path


def _assert_tool_contract(result: dict) -> None:
    """Mutating tools: {"applied": bool} plus exactly one of error/message."""
    assert "applied" in result, f"no 'applied' key: {result}"
    has_error, has_message = "error" in result, "message" in result
    assert has_error != has_message, (
        f"a tool result must carry exactly one of 'error'/'message': {result}")


# ---------------------------------------------------------------------------
# The happy path and the tool contract
# ---------------------------------------------------------------------------

def test_encrypt_then_decrypt_through_the_tools() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog():
            result = mcp_server._encrypt_file_impl(str(src))
        _assert_tool_contract(result)
        assert result["applied"] is True
        assert not src.exists()
        assert Path(result["vault_path"]).exists()

        with fake_decrypt_dialog():
            result = mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))
        _assert_tool_contract(result)
        assert result["applied"] is True
        assert src.read_bytes() == PEM


def test_neither_tool_ever_returns_file_contents() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog():
            enc = mcp_server._encrypt_file_impl(str(src))
        with fake_decrypt_dialog():
            dec = mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))
        for result in (enc, dec):
            blob = json.dumps(result)
            assert "BEGIN PRIVATE KEY" not in blob
            assert "fake key material" not in blob


def test_denial_uses_the_exact_shared_wording() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog(approve=False):
            result = mcp_server._encrypt_file_impl(str(src))
        assert result == {"applied": False, "message": "Denied by user."}
        assert src.exists(), "a denied encrypt must leave the file alone"

        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))
        with fake_decrypt_dialog(approve=False):
            result = mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))
        assert result == {"applied": False, "message": "Denied by user."}


def test_a_partial_failure_is_reported_as_an_error_not_a_denial() -> None:
    """The ciphertext exists but the original could not be deleted. Calling
    that "denied" would tell the user nothing happened, when in fact a real
    secret is still sitting on disk next to its encrypted copy."""
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog(partial="could not delete the original"):
            result = mcp_server._encrypt_file_impl(str(src))
        _assert_tool_contract(result)
        assert result["applied"] is False
        assert "could not delete" in result["error"]


def test_the_tools_never_raise_on_a_broken_vault() -> None:
    with workspace() as project:
        src = _pem(project)
        store.SECRETS_FILE.unlink()
        result = mcp_server._encrypt_file_impl(str(src))
        _assert_tool_contract(result)
        assert result["applied"] is False


# ---------------------------------------------------------------------------
# Fast-fail -- no modal window for a request that cannot succeed
# ---------------------------------------------------------------------------

def test_every_encrypt_refusal_happens_before_a_dialog_opens() -> None:
    """A hopeless request must not put a window in front of a human. Each of
    these is refused by precheck, which runs before gui.encrypt_file_dialog."""
    with workspace() as project:
        (project / "adir").mkdir()
        _pem(project, "empty.pem", b"")
        _pem(project, "already.pem.levault", b"x")
        good = _pem(project, "good.pem")
        with fake_encrypt_dialog() as calls:
            store.encrypt_file_in_place(good, TEST_PASSWORD)
        calls.clear()

        cases = [
            project / "missing.pem",
            project / "adir",
            project / "empty.pem",
            project / "already.pem.levault",
            store.SECRETS_FILE,
            project / "good.pem",           # sidecar already exists
        ]
        with fake_encrypt_dialog() as calls:
            for path in cases:
                result = mcp_server._encrypt_file_impl(str(path))
                _assert_tool_contract(result)
                assert result["applied"] is False, f"{path} was not refused"
                assert "error" in result
        assert calls == [], f"a dialog opened for a doomed request: {calls}"


def test_every_decrypt_refusal_happens_before_a_dialog_opens() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))
        sidecar = project / "server.pem.levault"
        _pem(project, "notenvelope.levault", b"definitely not an envelope")

        with fake_decrypt_dialog() as calls:
            for args in (
                (str(project / "missing.levault"), None),
                (str(project / "notenvelope.levault"), None),
                (str(sidecar), str(store.ROOT / "leak.pem")),        # inside ROOT
                (str(sidecar), "no/such/dir/out.pem"),               # missing parent
            ):
                result = mcp_server._decrypt_file_impl(*args)
                _assert_tool_contract(result)
                assert result["applied"] is False, f"{args} was not refused"
        assert calls == [], f"a dialog opened for a doomed request: {calls}"

        # And the output-already-exists case.
        src.write_bytes(b"a file the user made since")
        with fake_decrypt_dialog() as calls:
            result = mcp_server._decrypt_file_impl(str(sidecar))
        assert result["applied"] is False and calls == []
        assert src.read_bytes() == b"a file the user made since"


def test_a_v1_vault_is_refused_with_the_upgrade_instruction() -> None:
    with workspace(v2=False) as project:
        with fake_encrypt_dialog() as calls:
            result = mcp_server._encrypt_file_impl(str(_pem(project)))
        assert result["applied"] is False
        assert "upgrade_v2" in result["error"]
        assert calls == []


# ---------------------------------------------------------------------------
# vault_status
# ---------------------------------------------------------------------------

def test_vault_status_lists_encrypted_files_by_name_never_by_content() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))

        status = mcp_server._vault_status_impl()
        assert "files" in status, "vault_status no longer reports encrypted files"
        assert len(status["files"]) == 1
        row = status["files"][0]
        assert row["original_name"] == "server.pem"
        assert row["status"] == "ok"
        assert row["plaintext_size"] == len(PEM)
        assert row["encrypted_at"]

        blob = json.dumps(status)
        assert "BEGIN PRIVATE KEY" not in blob and "fake key material" not in blob


def test_vault_status_needs_no_password_and_reports_an_empty_list() -> None:
    with workspace():
        status = mcp_server._vault_status_impl()
        assert status["files"] == []
        assert "error" not in status


def test_vault_status_surfaces_a_malformed_registry_as_an_error() -> None:
    with workspace():
        store.FILES_FILE.write_text("{ not json", encoding="utf-8")
        status = mcp_server._vault_status_impl()
        assert "error" in status, "a malformed files.json was silently ignored"


def test_vault_status_reports_a_forgotten_decrypted_copy() -> None:
    with workspace() as project:
        src = _pem(project)
        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))
        with fake_decrypt_dialog():
            mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))

        status = mcp_server._vault_status_impl()
        assert status["files"][0]["status"] == "plaintext_present", (
            "a decrypted secret sitting beside its ciphertext is not surfaced")


# ---------------------------------------------------------------------------
# The git warnings -- the difference between "encrypted" and "protected"
# ---------------------------------------------------------------------------

def _git_init(project: Path) -> bool:
    try:
        for args in (["init"], ["config", "user.email", "t@example.com"],
                     ["config", "user.name", "t"]):
            subprocess.run(["git"] + args, cwd=str(project),
                           capture_output=True, timeout=20, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def test_encrypting_a_committed_file_warns_that_history_still_has_it() -> None:
    """Encrypting a secret that is already in git history protects nothing.
    Saying so is the whole value of the warning."""
    with workspace() as project:
        if not _git_init(project):
            return
        src = _pem(project)
        subprocess.run(["git", "add", "server.pem"], cwd=str(project),
                       capture_output=True, timeout=20)
        subprocess.run(["git", "commit", "-m", "oops"], cwd=str(project),
                       capture_output=True, timeout=20)

        with fake_encrypt_dialog():
            result = mcp_server._encrypt_file_impl(str(src))
        assert result["applied"] is True
        warnings = " ".join(result.get("warnings", []))
        assert "repository history" in warnings
        assert "rotated" in warnings, "the warning must say to rotate the credential"


def test_encrypting_an_untracked_file_produces_no_history_warning() -> None:
    with workspace() as project:
        if not _git_init(project):
            return
        with fake_encrypt_dialog():
            result = mcp_server._encrypt_file_impl(str(_pem(project)))
        assert "repository history" not in " ".join(result.get("warnings", []))


def test_decrypting_into_a_repo_warns_when_nothing_would_ignore_it() -> None:
    with workspace() as project:
        if not _git_init(project):
            return
        src = _pem(project)
        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))
        with fake_decrypt_dialog():
            result = mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))
        warnings = " ".join(result.get("warnings", []))
        assert "gitignore" in warnings.lower(), (
            "a real secret was restored into a working tree with no rule to keep "
            "it out of the next commit, and nothing said so")


def test_decrypting_a_gitignored_path_produces_no_warning() -> None:
    with workspace() as project:
        if not _git_init(project):
            return
        (project / ".gitignore").write_text("*.pem\n", encoding="utf-8")
        src = _pem(project)
        with fake_encrypt_dialog():
            mcp_server._encrypt_file_impl(str(src))
        with fake_decrypt_dialog():
            result = mcp_server._decrypt_file_impl(str(project / "server.pem.levault"))
        assert "gitignore" not in " ".join(result.get("warnings", [])).lower()


def test_the_git_helpers_never_raise_outside_a_repo() -> None:
    with workspace() as project:
        src = _pem(project)
        assert mcp_server._git_tracks(src) in (True, False, None)
        assert mcp_server._git_ignores(src) in (True, False, None)


# ---------------------------------------------------------------------------
# Agent instructions
# ---------------------------------------------------------------------------

def test_agent_instructions_cover_the_file_tools() -> None:
    """The standing policy is the only thing telling the agent not to read a
    decrypted private key. It ships in the server's instructions, so it applies
    without any skill needing to fire."""
    text = mcp_server._AGENT_INSTRUCTIONS
    for needle, why in (
        ("Never read a file this server decrypts", "never read a decrypted file"),
        ("write-only", "treat a decrypt target as write-only"),
        (".levault file is pure ciphertext", "a .levault is safe but useless to it"),
        ("destroys the original", "encrypt_file is destructive"),
    ):
        assert needle in text, f"the agent instructions no longer say to {why}"


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
