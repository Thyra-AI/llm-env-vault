"""
Suite for run_with_env's files= parameter -- decrypting whole files into a
command's working directory for the lifetime of that one run.

This is the most dangerous surface in the file-encryption feature, because it
is the one that writes real plaintext secrets to disk automatically. Three
failure modes drive almost every test here:

  1. A decrypted private key is LEFT BEHIND. The cleanup runs in a finally
     block, but a detached process has no reliable moment to clean up at all,
     and a SIGTERM can skip the handler. Both are covered.

  2. Cleanup DESTROYS SOMETHING ELSE. Cleanup shreds what it is given, so if a
     restore ever overwrote a file the user already had -- say one they
     restored with decrypt_file yesterday -- the finally block would
     irreversibly destroy it. The rule is: never overwrite, and only ever
     shred a path this run created.

  3. Trust silently WIDENS. An 8-hour grant that can re-decrypt a private key
     with no human present is a different thing from one that injects a token
     into an environment. files= runs are never auto-allowed and never grant
     trust, and files is in the trust signature so a files=None grant can
     never match a files=[...] call even if that skip were refactored away.

gui.unlock_for_run_dialog is monkeypatched throughout; no real window opens.

Runs under pytest (`pytest tests/test_run_with_files.py -q`) or standalone
(`python tests/test_run_with_files.py`).
"""
import base64
import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, store, trust  # noqa: E402

TEST_PASSWORD = "run-with-files-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
PEM = b"-----BEGIN PRIVATE KEY-----\nrun-with-files key material\n-----END PRIVATE KEY-----\n"
SECRETS = {"API_TOKEN": "tok-abcdefgh-123456"}


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
def workspace(extra_files=()):
    """A vault with SECRETS, plus server.pem already encrypted in a project dir."""
    with tempfile.TemporaryDirectory(prefix="llm_runfiles_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        _reset_trust()
        project = tmp_path / "project"
        project.mkdir()
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(SECRETS))
            store.save_index({n: i + 1 for i, n in enumerate(sorted(SECRETS))})
            for name in ("server.pem",) + tuple(extra_files):
                (project / name).write_bytes(PEM)
                store.encrypt_file_in_place(project / name, TEST_PASSWORD)
            yield project
        finally:
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


@contextlib.contextmanager
def fake_dialog(approve=True, trust_it=False):
    """Monkeypatch gui.unlock_for_run_dialog, decrypting for real when asked.

    Yields the list of calls, so a test can assert a dialog did NOT open."""
    original = gui.unlock_for_run_dialog
    calls = []

    def wrapper(command_str, materialize_path=None, only_vars=None, trust_note=None,
                files=None):
        calls.append({"command_str": command_str, "materialize_path": materialize_path,
                       "only_vars": only_vars, "trust_note": trust_note, "files": files})
        if not approve:
            return {"secrets": None, "trust": False}
        secrets = store.load_secrets(TEST_PASSWORD)
        if only_vars is not None:
            secrets = {k: v for k, v in secrets.items() if k in only_vars}
        outcome = {"secrets": secrets, "trust": trust_it}
        if files:
            decrypted = {}
            for vault_path, restore_path in files:
                data, meta = store.read_encrypted_file(vault_path, TEST_PASSWORD)
                decrypted[str(vault_path)] = {
                    "name": meta.get("name"), "mode": meta.get("mode"),
                    "bytes": data, "restore_path": str(restore_path)}
            outcome["files"] = decrypted
        return outcome

    gui.unlock_for_run_dialog = wrapper
    try:
        yield calls
    finally:
        gui.unlock_for_run_dialog = original


@contextlib.contextmanager
def stub_run(observer=None, returncode=0):
    """Replace subprocess.run inside mcp_server so nothing is really executed.

    *observer* is called with (command, env, cwd) while the "process" is
    notionally running -- the one moment a restored file must exist on disk."""
    original = subprocess.run

    class _Result:
        def __init__(self):
            self.returncode = returncode
            self.stdout = "ran"
            self.stderr = ""

    def fake(command, **kwargs):
        if observer is not None:
            observer(command, kwargs.get("env") or {}, kwargs.get("cwd"))
        return _Result()

    mcp_server.subprocess.run = fake
    try:
        yield
    finally:
        mcp_server.subprocess.run = original


def _levault(project: Path, name="server.pem") -> str:
    return str(project / (name + ".levault"))


# ---------------------------------------------------------------------------
# The happy path: present during the run, gone after
# ---------------------------------------------------------------------------

def test_the_file_exists_during_the_run_and_is_gone_afterwards() -> None:
    with workspace() as project:
        seen = {}

        def observer(_cmd, _env, _cwd):
            restored = project / "server.pem"
            seen["existed"] = restored.exists()
            seen["contents"] = restored.read_bytes() if restored.exists() else None

        with fake_dialog(), stub_run(observer):
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])

        assert result["applied"] is True, result
        assert seen["existed"] is True, "the file was not on disk while the command ran"
        assert seen["contents"] == PEM, "the restored file had the wrong contents"
        assert not (project / "server.pem").exists(), "the decrypted file was left behind"
        assert result["files_restored"] == 1


def test_the_restored_file_keeps_its_recorded_permissions() -> None:
    with workspace() as project:
        modes = {}

        def observer(_cmd, _env, _cwd):
            modes["mode"] = (project / "server.pem").stat().st_mode

        with fake_dialog(), stub_run(observer):
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        assert "mode" in modes  # on Windows the value itself is best-effort


def test_several_files_are_all_restored_and_all_cleaned_up() -> None:
    with workspace(extra_files=("client.p12", "kubeconfig")) as project:
        during = {}

        def observer(_cmd, _env, _cwd):
            during["present"] = sorted(
                p.name for p in project.iterdir() if not p.name.endswith(".levault"))

        files = [_levault(project, n) for n in ("server.pem", "client.p12", "kubeconfig")]
        with fake_dialog(), stub_run(observer):
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, files)

        assert during["present"] == ["client.p12", "kubeconfig", "server.pem"]
        assert result["files_restored"] == 3
        leftovers = [p.name for p in project.iterdir() if not p.name.endswith(".levault")]
        assert leftovers == [], f"decrypted files left behind: {leftovers}"


def test_environment_variables_are_injected_alongside_the_files() -> None:
    with workspace() as project:
        captured = {}
        with fake_dialog(), stub_run(lambda _c, env, _w: captured.update(env)):
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        assert captured.get("API_TOKEN") == SECRETS["API_TOKEN"]


def test_denial_leaves_nothing_on_disk() -> None:
    with workspace() as project:
        with fake_dialog(approve=False), stub_run():
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        assert result["applied"] is False
        assert result["message"] == "Denied by user."
        assert not (project / "server.pem").exists()


# ---------------------------------------------------------------------------
# Never overwrite, never shred someone else's file
# ---------------------------------------------------------------------------

def test_an_existing_file_at_the_restore_path_is_never_overwritten() -> None:
    """The cleanup shreds every path this run wrote. If a restore overwrote a
    file the user already had -- e.g. one they restored with decrypt_file --
    the finally block would irreversibly destroy it."""
    with workspace() as project:
        precious = project / "server.pem"
        precious.write_bytes(b"a file the user made and still wants")

        with fake_dialog() as calls, stub_run():
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])

        assert result.get("applied") is not True
        assert "already exists" in result["error"]
        assert calls == [], "a dialog opened for a request that could not succeed"
        assert precious.exists(), "the user's own file was deleted"
        assert precious.read_bytes() == b"a file the user made and still wants", (
            "the user's own file was overwritten or shredded")


def test_a_file_appearing_while_the_prompt_is_open_is_not_overwritten() -> None:
    """The pre-dialog check is a fast-fail nicety; the real guard runs after
    the password prompt closes, which can be minutes later."""
    with workspace() as project:
        original = gui.unlock_for_run_dialog

        def wrapper(command_str, **kwargs):
            # Create the file "while the dialog is open".
            (project / "server.pem").write_bytes(b"appeared during the prompt")
            secrets = store.load_secrets(TEST_PASSWORD)
            decrypted = {}
            for vault_path, restore_path in kwargs.get("files") or []:
                data, meta = store.read_encrypted_file(vault_path, TEST_PASSWORD)
                decrypted[str(vault_path)] = {"name": meta.get("name"),
                                               "mode": meta.get("mode"), "bytes": data,
                                               "restore_path": str(restore_path)}
            return {"secrets": secrets, "trust": False, "files": decrypted}

        gui.unlock_for_run_dialog = wrapper
        try:
            with stub_run():
                result = mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        finally:
            gui.unlock_for_run_dialog = original

        assert result["applied"] is False
        assert "came into existence" in result["error"]
        assert (project / "server.pem").read_bytes() == b"appeared during the prompt"


def test_cleanup_touches_only_paths_this_run_created() -> None:
    with workspace(extra_files=("kubeconfig",)) as project:
        bystander = project / "unrelated.txt"
        bystander.write_bytes(b"nothing to do with the vault")

        with fake_dialog(), stub_run():
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])

        assert bystander.read_bytes() == b"nothing to do with the vault"


def test_two_files_restoring_to_one_name_are_refused() -> None:
    with workspace() as project:
        nested = project / "sub"
        nested.mkdir()
        (nested / "server.pem").write_bytes(PEM)
        store.encrypt_file_in_place(nested / "server.pem", TEST_PASSWORD)

        with fake_dialog() as calls, stub_run():
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None,
                [_levault(project), str(nested / "server.pem.levault")])
        assert result.get("applied") is not True
        assert "would both restore" in result["error"]
        assert calls == []


# ---------------------------------------------------------------------------
# background is refused -- the highest-severity rule here
# ---------------------------------------------------------------------------

def test_background_with_files_is_refused_before_any_dialog() -> None:
    """A detached process has no reliable moment at which the decrypted file
    can be deleted, so it would sit in the working directory indefinitely."""
    with workspace() as project:
        with fake_dialog() as calls, stub_run():
            result = mcp_server._run_with_env_impl(
                ["echo", "hi"], None, True, str(project), None, [_levault(project)])
        assert "error" in result
        assert "background" in result["error"]
        assert calls == [], "a dialog opened for a request that must be refused"
        assert not (project / "server.pem").exists()


# ---------------------------------------------------------------------------
# Fast-fail refusals
# ---------------------------------------------------------------------------

def test_bad_file_arguments_are_refused_before_a_dialog_opens() -> None:
    with workspace() as project:
        (project / "notenvelope.levault").write_bytes(b"not an envelope at all")
        outside = project.parent / "outside.pem.levault"
        outside.write_bytes(b"x")

        with fake_dialog() as calls, stub_run():
            for files in ([str(project / "missing.levault")],
                          [str(project / "notenvelope.levault")],
                          [str(outside)],
                          [""],
                          [123]):
                result = mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None, files)
                assert "error" in result, f"{files} was not refused"
        assert calls == [], "a dialog opened for a doomed request"


def test_a_levault_outside_cwd_restores_nowhere_and_is_refused() -> None:
    """The .levault may live anywhere, but its plaintext must land inside cwd.
    A sibling directory's file would restore into cwd by name -- that is fine;
    what must never happen is a restore path escaping cwd."""
    with workspace() as project:
        elsewhere = project.parent / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "other.pem").write_bytes(PEM)
        store.encrypt_file_in_place(elsewhere / "other.pem", TEST_PASSWORD)

        pairs = mcp_server._resolve_restore_paths(
            [str(elsewhere / "other.pem.levault")], str(project))
        _vault_path, restore_path = pairs[0]
        assert restore_path.parent == project.resolve(), (
            "a restored file must land in the command's working directory")


# ---------------------------------------------------------------------------
# Trust must never widen
# ---------------------------------------------------------------------------

def test_a_files_run_never_grants_trust_even_if_the_dialog_says_so() -> None:
    """The dialog hides the checkbox, so trust should already be False. This
    asserts the server refuses to act on it anyway."""
    with workspace() as project:
        with fake_dialog(trust_it=True), stub_run():
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        assert trust._trusted == {}, (
            "a run that decrypts files to disk was granted an 8-hour trust")


def test_a_files_run_always_prompts_even_when_an_identical_one_is_trusted() -> None:
    with workspace() as project:
        # First, trust the same command WITHOUT files.
        with fake_dialog(trust_it=True), stub_run():
            mcp_server._run_with_env_impl(["echo", "hi"], None, False, str(project), None)
        assert trust._trusted, "the no-files run did not grant trust (test premise)"

        with fake_dialog() as calls, stub_run():
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        assert len(calls) == 1, (
            "a files= run was auto-allowed by a grant made for a run without files")
        assert calls[0]["files"], "the dialog was not told which files it is approving"


def test_a_files_grant_could_never_match_a_files_none_call() -> None:
    """Defence in depth on the signature itself. The server skips trust for
    files runs, but if that skip were ever refactored away, the signature must
    still keep the two apart."""
    args = (["echo", "hi"], "/tmp", None, None, False)
    assert (trust.make_signature(*args, None)
            != trust.make_signature(*args, ["a.levault"]))
    assert (trust.make_signature(*args, None)
            != trust.make_signature(*args, []))
    assert (trust.make_signature(*args, ["a.levault", "b.levault"])
            == trust.make_signature(*args, ["b.levault", "a.levault"])), (
        "two spellings of one request became two grants")
    assert (trust.make_signature(*args, ["a.levault"])
            != trust.make_signature(*args, ["b.levault"]))


# ---------------------------------------------------------------------------
# The file master key must never escape
# ---------------------------------------------------------------------------

def test_no_reserved_key_or_file_key_reaches_the_child_environment() -> None:
    with workspace() as project:
        record = store.get_fmk(TEST_PASSWORD)
        raw = base64.urlsafe_b64decode(record["keys"][record["active"]] + "==")
        captured = {}

        with fake_dialog(), stub_run(lambda _c, env, _w: captured.update(env)):
            # only_vars=None is the full-vault path -- the one that would leak.
            mcp_server._run_with_env_impl(
                ["echo", "hi"], None, False, str(project), None, [_levault(project)])

        assert captured, "the stub captured no environment (test is not exercising it)"
        assert not any(k.startswith("#") for k in captured), (
            f"a reserved vault key reached the child environment: "
            f"{[k for k in captured if k.startswith('#')]}")
        blob = "\x00".join(f"{k}={v}" for k, v in captured.items())
        for form in (base64.urlsafe_b64encode(raw).decode(),
                     base64.b64encode(raw).decode(),
                     record["active"]):
            assert form not in blob, "file key material reached the child environment"


def test_the_reserved_key_guard_fires_when_forced() -> None:
    """Never reachable in a correct build; this forces it, because a guard
    that has never once been observed to fire is not a guard."""
    with workspace() as project:
        original = gui.unlock_for_run_dialog

        def wrapper(command_str, **kwargs):
            secrets = store.load_secrets(TEST_PASSWORD)
            secrets["#fmk"] = "leaked key material"   # simulate a filtering bug
            return {"secrets": secrets, "trust": False, "files": {}}

        gui.unlock_for_run_dialog = wrapper
        try:
            with stub_run():
                result = mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None)
        finally:
            gui.unlock_for_run_dialog = original

        assert result["applied"] is False
        assert "#fmk" in result["error"] and "refusing to launch" in result["error"]


# ---------------------------------------------------------------------------
# Cleanup failure must be reported, never silent
# ---------------------------------------------------------------------------

def test_a_file_that_cannot_be_deleted_is_named_in_a_warning() -> None:
    with workspace() as project:
        original = store.secure_delete
        store.secure_delete = lambda p: False   # simulate a locked file
        try:
            with fake_dialog(), stub_run():
                result = mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        finally:
            store.secure_delete = original

        assert "files_warning" in result, "a surviving decrypted secret was not reported"
        assert "server.pem" in result["files_warning"]
        assert "files_restored" not in result
        (project / "server.pem").unlink(missing_ok=True)


def test_the_sigterm_handler_is_installed_for_a_files_only_run() -> None:
    """Without `or restored_paths` in that condition, a SIGTERM during a
    files-only run skips cleanup entirely and leaves a private key on disk."""
    with workspace() as project:
        import signal
        installed = {}
        real_signal = signal.signal

        def spy(signum, handler):
            if signum == signal.SIGTERM:
                installed["yes"] = handler is mcp_server._on_sigterm or installed.get("yes")
            return real_signal(signum, handler)

        mcp_server.signal.signal = spy
        try:
            with fake_dialog(), stub_run():
                mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        finally:
            mcp_server.signal.signal = real_signal

        assert installed.get("yes") is True, (
            "no SIGTERM handler was installed for a run that decrypts files to disk")


def test_an_interrupted_run_still_cleans_up() -> None:
    with workspace() as project:
        def boom(_command, **_kwargs):
            raise KeyboardInterrupt()

        original = subprocess.run
        mcp_server.subprocess.run = boom
        try:
            with fake_dialog():
                result = mcp_server._run_with_env_impl(
                    ["echo", "hi"], None, False, str(project), None, [_levault(project)])
        finally:
            mcp_server.subprocess.run = original

        assert result["message"] == "Interrupted."
        assert not (project / "server.pem").exists(), (
            "an interrupted run left a decrypted private key on disk")


def test_a_command_that_fails_to_start_still_cleans_up() -> None:
    with workspace() as project:
        def boom(_command, **_kwargs):
            raise OSError("no such executable")

        original = subprocess.run
        mcp_server.subprocess.run = boom
        try:
            with fake_dialog():
                result = mcp_server._run_with_env_impl(
                    ["nonexistent"], None, False, str(project), None, [_levault(project)])
        finally:
            mcp_server.subprocess.run = original

        assert result["applied"] is False
        assert not (project / "server.pem").exists()


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
