"""
Suite for file key rotation and retirement.

The file master key deliberately survives a password change -- that is why a
.levault committed to git last year still opens today. The price is that a
leaked file key is total and retroactive, and rotation is the answer. It has to
work while being honest about a fact it cannot change: the files it is rotating
may not all be reachable from this machine.

That produces the generation model, and these tests exist to hold its two
dangerous edges down:

  * PARTIAL rotation must be safe. A file on another laptop, or one not yet
    pulled from git, keeps working under the retained old key. Rotation reports
    what it skipped rather than pretending it finished.

  * RETIREMENT must not destroy a key something still needs, and its
    precondition must be read from ENVELOPE HEADERS rather than from
    files.json. The registry records what rotation believed; the headers record
    what is actually on disk, and they diverge in a case that really happens --
    a user restoring an older .levault from git history after rotating. A
    registry-driven check would pass and permanently destroy that file.

Runs under pytest (`pytest tests/test_fmk_rotation.py -q`) or standalone
(`python tests/test_fmk_rotation.py`).
"""
import contextlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, store  # noqa: E402

TEST_PASSWORD = "rotation-test-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
PEM = b"-----BEGIN PRIVATE KEY-----\nrotation key material\n-----END PRIVATE KEY-----\n"


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
def workspace(names=("server.pem",)):
    with tempfile.TemporaryDirectory(prefix="llm_rotate_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        project = tmp_path / "project"
        project.mkdir()
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_index({})
            for name in names:
                (project / name).write_bytes(PEM + name.encode())
                store.encrypt_file_in_place(project / name, TEST_PASSWORD)
            yield project
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def _gen_of(path: Path) -> str:
    return crypto.file_envelope_info(path.read_bytes())["fmk_id"]


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
# Rotation
# ---------------------------------------------------------------------------

def test_rotation_re_encrypts_every_reachable_file_and_it_still_opens() -> None:
    with workspace(("server.pem", "client.p12")) as project:
        before = {n: _gen_of(project / f"{n}.levault") for n in ("server.pem", "client.p12")}
        assert len(set(before.values())) == 1, "the fixture should start on one generation"

        report = store.rotate_file_key(TEST_PASSWORD)
        assert report["rotated"] == 2
        assert all(r["status"] == "ok" for r in report["results"])

        for name in ("server.pem", "client.p12"):
            sidecar = project / f"{name}.levault"
            assert _gen_of(sidecar) == report["fmk_id"], f"{name} was not rotated"
            assert _gen_of(sidecar) != before[name]
            data, meta = store.read_encrypted_file(sidecar, TEST_PASSWORD)
            assert data == PEM + name.encode(), f"{name} decrypts to the wrong bytes"
            assert meta["name"] == name


def test_a_file_encrypted_before_rotation_still_opens_after() -> None:
    """The single most important property. If this fails, rotation is a
    data-destruction tool."""
    with workspace() as project:
        sidecar = project / "server.pem.levault"
        store.rotate_file_key(TEST_PASSWORD)
        store.decrypt_file_to(sidecar, TEST_PASSWORD)
        assert (project / "server.pem").read_bytes() == PEM + b"server.pem"


def test_rotation_mints_a_fresh_file_dek_not_just_a_new_wrapping() -> None:
    """Never re-seal under a reused DEK, even with a fresh nonce."""
    with workspace() as project:
        sidecar = project / "server.pem.levault"
        _hdr_before, _aad, _body = crypto.parse_file_envelope(sidecar.read_bytes())
        store.rotate_file_key(TEST_PASSWORD)
        hdr_after, _aad2, _body2 = crypto.parse_file_envelope(sidecar.read_bytes())
        assert hdr_after["wrapped_dek"] != _hdr_before["wrapped_dek"]
        assert hdr_after["file_id"] != _hdr_before["file_id"]
        assert hdr_after["kdf"]["salt"] != _hdr_before["kdf"]["salt"]


def test_the_old_key_is_retained_so_an_unreachable_file_keeps_working() -> None:
    """A file on another machine, or not yet pulled from git, must not be
    collateral damage."""
    with workspace(("server.pem", "remote.pem")) as project:
        remote = project / "remote.pem.levault"
        stashed = remote.read_bytes()
        remote.unlink()                       # "on another laptop"

        report = store.rotate_file_key(TEST_PASSWORD)
        assert report["rotated"] == 1
        statuses = {r["original_name"]: r["status"] for r in report["results"]}
        assert statuses["remote.pem"] == "missing"

        remote.write_bytes(stashed)           # it comes back later
        data, _meta = store.read_encrypted_file(remote, TEST_PASSWORD)
        assert data == PEM + b"remote.pem", "the retained old key no longer opens the file"


def test_rotation_is_resumable_and_picks_up_what_reappears() -> None:
    with workspace(("server.pem", "remote.pem")) as project:
        remote = project / "remote.pem.levault"
        stashed = remote.read_bytes()
        remote.unlink()
        first = store.rotate_file_key(TEST_PASSWORD)

        remote.write_bytes(stashed)
        second = store.rotate_file_key(TEST_PASSWORD)
        assert second["rotated"] == 2
        assert _gen_of(remote) == second["fmk_id"]
        assert second["fmk_id"] != first["fmk_id"]


def test_one_bad_file_does_not_abort_the_whole_rotation() -> None:
    """Stopping at the first unreachable file would leave every other file
    exposed on a key the user just decided to stop trusting."""
    with workspace(("a.pem", "b.pem", "c.pem")) as project:
        (project / "b.pem.levault").write_bytes(b"corrupted beyond recognition")

        report = store.rotate_file_key(TEST_PASSWORD)
        statuses = {r["original_name"]: r["status"] for r in report["results"]}
        assert statuses["b.pem"] == "error"
        assert statuses["a.pem"] == "ok" and statuses["c.pem"] == "ok"
        assert report["rotated"] == 2


def test_a_failed_re_encrypt_restores_the_original_ciphertext_exactly() -> None:
    """A half-rotated file is a destroyed file."""
    with workspace() as project:
        sidecar = project / "server.pem.levault"
        original = sidecar.read_bytes()

        real = crypto.open_file_envelope
        calls = {"n": 0}

        def flaky(fmk, data):
            calls["n"] += 1
            if calls["n"] == 2:          # the read-back verification
                raise RuntimeError("boom")
            return real(fmk, data)

        crypto.open_file_envelope = flaky
        try:
            report = store.rotate_file_key(TEST_PASSWORD)
        finally:
            crypto.open_file_envelope = real

        assert report["results"][0]["status"] == "error"
        assert sidecar.read_bytes() == original, (
            "a failed rotation left the file in a different state than it found it")
        data, _meta = store.read_encrypted_file(sidecar, TEST_PASSWORD)
        assert data == PEM + b"server.pem"


def test_rotation_updates_the_registry_but_the_headers_are_authoritative() -> None:
    with workspace() as project:
        report = store.rotate_file_key(TEST_PASSWORD)
        entry = next(iter(store.load_file_registry().values()))
        assert entry["fmk_id"] == report["fmk_id"]
        assert entry["envelope_sha256"] == store._file_fingerprint(
            project / "server.pem.levault")
        assert store.file_registry_status()[0]["status"] == "ok"


def test_rotation_needs_a_vault_that_has_encrypted_something() -> None:
    with workspace(names=()):
        exc = _expect(ValueError, store.rotate_file_key, TEST_PASSWORD)
        assert "never encrypted" in str(exc)


def test_rotation_rejects_a_wrong_password() -> None:
    with workspace():
        _expect(crypto.WrongPassword, store.rotate_file_key, "not-the-password")


def test_the_new_generation_survives_a_password_change() -> None:
    with workspace() as project:
        report = store.rotate_file_key(TEST_PASSWORD)
        store.change_password(TEST_PASSWORD, "a-brand-new-password")
        record = store.get_fmk("a-brand-new-password")
        assert record["active"] == report["fmk_id"]
        data, _meta = store.read_encrypted_file(
            project / "server.pem.levault", "a-brand-new-password")
        assert data == PEM + b"server.pem"


# ---------------------------------------------------------------------------
# Retirement -- the irreversible half
# ---------------------------------------------------------------------------

def test_retire_drops_old_keys_once_everything_is_rotated() -> None:
    with workspace(("server.pem", "client.p12")) as project:
        report = store.rotate_file_key(TEST_PASSWORD)
        before = store.get_fmk(TEST_PASSWORD)
        assert len(before["keys"]) == 2, "the old generation should still be held"

        result = store.retire_file_keys(TEST_PASSWORD)
        assert len(result["retired"]) == 1

        after = store.get_fmk(TEST_PASSWORD)
        assert list(after["keys"]) == [report["fmk_id"]]
        # And every file still opens on the surviving key.
        for name in ("server.pem", "client.p12"):
            data, _meta = store.read_encrypted_file(
                project / f"{name}.levault", TEST_PASSWORD)
            assert data == PEM + name.encode()


def test_retire_refuses_while_a_file_is_still_on_an_old_generation() -> None:
    with workspace(("server.pem", "remote.pem")) as project:
        remote = project / "remote.pem.levault"
        stashed = remote.read_bytes()
        remote.unlink()
        store.rotate_file_key(TEST_PASSWORD)
        remote.write_bytes(stashed)          # comes back, still on the old key

        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        # Assert the OUTCOME, not which guard caught it. Retire has several
        # independent checks and the first to fire is an implementation
        # detail; what must never change is that it refuses and says to
        # rotate again.
        assert "rotation again" in str(exc).lower()
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 2, "keys were retired anyway"
        data, _meta = store.read_encrypted_file(remote, TEST_PASSWORD)
        assert data == PEM + b"remote.pem"


def test_retire_reads_generations_from_headers_not_from_the_registry() -> None:
    """THE regression this test file exists for. After rotating, a user
    restores an older .levault from git history. files.json still says the file
    is on the current generation; the bytes on disk say otherwise. A
    registry-driven precondition would pass here and destroy the only key that
    opens it."""
    with workspace() as project:
        sidecar = project / "server.pem.levault"
        old_bytes = sidecar.read_bytes()
        old_gen = _gen_of(sidecar)

        store.rotate_file_key(TEST_PASSWORD)
        assert _gen_of(sidecar) != old_gen

        # "git checkout HEAD~5 -- certs/server.pem.levault"
        sidecar.write_bytes(old_bytes)
        # Registry still claims the new generation, and even the hash guard is
        # neutralised, so ONLY the header can reveal the truth.
        entries = store.load_file_registry()
        key = next(iter(entries))
        entries[key]["envelope_sha256"] = store._file_fingerprint(sidecar)
        store.save_file_registry(entries)
        assert store.file_registry_status()[0]["status"] == "ok"

        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "rotation again" in str(exc).lower()
        data, _meta = store.read_encrypted_file(sidecar, TEST_PASSWORD)
        assert data == PEM + b"server.pem", "the restored older file was made unreadable"


def test_retire_refuses_when_a_registered_file_is_missing_or_damaged() -> None:
    with workspace(("server.pem", "gone.pem")) as project:
        store.rotate_file_key(TEST_PASSWORD)

        (project / "gone.pem.levault").unlink()
        exc = _expect(ValueError, store.retire_file_keys, TEST_PASSWORD)
        assert "could not be verified" in str(exc)
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 2


def test_retire_with_nothing_to_retire_is_a_clean_no_op() -> None:
    with workspace():
        result = store.retire_file_keys(TEST_PASSWORD)
        assert result["retired"] == []
        assert "nothing to retire" in result["message"]
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 1


def test_file_generations_reports_from_headers_without_a_password() -> None:
    with workspace(("a.pem", "b.pem")) as project:
        gens = store.file_generations()
        assert sum(gens["generations"].values()) == 2
        assert len(gens["generations"]) == 1
        assert gens["unreadable"] == []

        (project / "b.pem.levault").write_bytes(b"garbage")
        gens = store.file_generations()
        assert gens["unreadable"] == [store._registry_key(project / "b.pem.levault")]


# ---------------------------------------------------------------------------
# The manage_vault wiring
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def fake_manage_dialog(response, abandon=None):
    """Stub manage_vault_dialog, and the abandonment confirm it can chain to.

    Both must be stubbed. retire_file_keys refusing over unaccounted-for files
    now opens a second dialog, and a test that leaves it real would put a
    modal window on a human's screen with nothing able to answer it."""
    originals = (gui.manage_vault_dialog, gui.confirm_abandon_files_dialog)
    gui.manage_vault_dialog = lambda: response
    gui.confirm_abandon_files_dialog = lambda outstanding, names: abandon
    try:
        yield
    finally:
        gui.manage_vault_dialog, gui.confirm_abandon_files_dialog = originals


def test_rotate_through_manage_vault_reports_what_it_skipped() -> None:
    with workspace(("server.pem", "remote.pem")) as project:
        (project / "remote.pem.levault").unlink()

        with fake_manage_dialog({"action": "rotate_file_key", "password": TEST_PASSWORD}):
            result = mcp_server._manage_vault_impl()

        assert result["applied"] is True
        assert result["rotated"] == 1
        assert "warning" in result, "a file that did not rotate was not reported"
        assert "remote.pem" in result["warning"]
        assert "old key" in result["warning"]


def test_retire_through_manage_vault_is_refused_with_a_reason() -> None:
    with workspace(("server.pem", "remote.pem")) as project:
        stashed = (project / "remote.pem.levault").read_bytes()
        (project / "remote.pem.levault").unlink()
        store.rotate_file_key(TEST_PASSWORD)
        (project / "remote.pem.levault").write_bytes(stashed)

        # abandon=None: the human cancels the abandonment confirm, so the
        # refusal stands and nothing is retired.
        with fake_manage_dialog({"action": "retire_file_keys", "password": TEST_PASSWORD}):
            result = mcp_server._manage_vault_impl()
        assert result["applied"] is False
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 2, "keys were retired anyway"


def test_retire_offers_abandonment_and_honours_the_confirmation() -> None:
    """Refusing forever is its own failure: a file that genuinely no longer
    exists would otherwise block retiring a key the user believes is
    compromised. The confirm names the exact identities being given up."""
    with workspace(("server.pem", "remote.pem")) as project:
        stashed = (project / "remote.pem.levault").read_bytes()
        (project / "remote.pem.levault").unlink()
        store.unregister_encrypted_file(project / "remote.pem.levault")
        store.rotate_file_key(TEST_PASSWORD)

        seen = {}

        def capture(outstanding, names):
            seen["outstanding"] = outstanding
            seen["names"] = names
            return [fid for group in outstanding.values() for fid in group]

        original = gui.confirm_abandon_files_dialog
        gui.confirm_abandon_files_dialog = capture
        try:
            with fake_manage_dialog(
                    {"action": "retire_file_keys", "password": TEST_PASSWORD}):
                gui.confirm_abandon_files_dialog = capture   # fake_manage_dialog reset it
                result = mcp_server._manage_vault_impl()
        finally:
            gui.confirm_abandon_files_dialog = original

        assert seen["outstanding"], "the human was not shown what would be abandoned"
        assert result["applied"] is True
        assert len(store.get_fmk(TEST_PASSWORD)["keys"]) == 1


def test_manage_vault_reports_a_wrong_password_without_leaking_detail() -> None:
    with workspace():
        with fake_manage_dialog({"action": "rotate_file_key", "password": "wrong"}):
            result = mcp_server._manage_vault_impl()
        assert result["applied"] is False
        assert result["error"] == "Incorrect master password."


def test_the_file_actions_are_offered_only_when_files_exist() -> None:
    info = {"format": 2, "recovery_slot": True}
    with_files = gui._applicable_manage_actions(info, 3)
    assert "rotate_file_key" in with_files and "retire_file_keys" in with_files
    without = gui._applicable_manage_actions(info, 0)
    assert "rotate_file_key" not in without and "retire_file_keys" not in without
    # A v1 vault cannot encrypt files at all, so it must never offer either.
    v1 = gui._applicable_manage_actions({"format": 1}, 3)
    assert "rotate_file_key" not in v1 and "retire_file_keys" not in v1


def test_both_file_actions_declare_the_password_result_key() -> None:
    for action in ("rotate_file_key", "retire_file_keys"):
        assert gui._manage_action_result_keys(action) == frozenset({"action", "password"})


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
