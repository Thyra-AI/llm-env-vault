"""
Tests for the unlock-listener registry and the ``#generation`` counter in
vault_lib/store.py (2.4.0 "always allow", core).

Listeners are called as ``fn(body, fingerprint, method)`` with method one of
"password" (a successful password unlock), "write", "change_password",
"reissue", or "recovery" (a write/credential operation that ran inside a
recovery-key-authenticated session).  A recovery-key unlock by itself never
notifies, and a listener that raises never breaks the operation it observed.

Every test runs against a throwaway vault in a temp dir (the store paths are
redirected for the duration and restored afterward) with fast scrypt
parameters; nothing here opens a window.

Runs under pytest or standalone (``python tests/test_unlock_listeners.py``).
"""
import contextlib
import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib import crypto, store  # noqa: E402

TEST_PASSWORD = "listener-test-password-123"
NEW_PASSWORD = "listener-test-new-password-456"
BASE_SECRETS = {"API_TOKEN": "tok-abc-123", "OTHER_SECRET": "other-xyz-789"}
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextlib.contextmanager
def _vault(version: int = 2, recovery: bool = False):
    """Isolated vault with BASE_SECRETS already saved.  Yields the recovery
    key text (v2 with recovery=True) or None."""
    names = ("SALT_FILE", "SECRETS_FILE", "INDEX_FILE", "ENV_FILE", "BAK_FILE",
             "FORMAT_FILE", "VAULT_LOCK_FILE", "FILES_FILE", "FILES_LOCK_FILE",
             "TARGETS_FILE", "TARGETS_LOCK_FILE", "ROOT")
    originals = {n: getattr(store, n) for n in names}
    saved_listeners = list(store._unlock_listeners)
    old_params = crypto.SCRYPT_DEFAULT
    with tempfile.TemporaryDirectory(prefix="llm_listener_test_") as tmp:
        root = Path(tmp).resolve()
        store.ROOT = root
        for attr, name in (("SALT_FILE", "vault.salt"), ("SECRETS_FILE", "vault.enc"),
                           ("INDEX_FILE", "vault_index.json"), ("ENV_FILE", "llm.env"),
                           ("BAK_FILE", "vault.enc.bak"), ("FORMAT_FILE", "vault.format.txt"),
                           ("VAULT_LOCK_FILE", "vault.enc.lock"),
                           ("FILES_FILE", "files.json"), ("FILES_LOCK_FILE", "files.json.lock"),
                           ("TARGETS_FILE", "targets.json"),
                           ("TARGETS_LOCK_FILE", "targets.json.lock")):
            setattr(store, attr, root / name)
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        del store._unlock_listeners[:]
        try:
            rk_text = None
            if version == 2:
                raw = bytes(crypto.new_recovery_key()) if recovery else None
                rk_text = store.create_v2_vault(TEST_PASSWORD, recovery_raw=raw)
            else:
                store.create_secrets_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))
            yield rk_text
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            store._unlock_listeners[:] = saved_listeners
            for n, v in originals.items():
                setattr(store, n, v)


class Recorder:
    def __init__(self):
        self.events = []

    def __call__(self, body, fingerprint, method):
        self.events.append((method, body, fingerprint))

    @property
    def methods(self):
        return [m for m, _b, _f in self.events]


def _recorder() -> Recorder:
    rec = Recorder()
    store.register_unlock_listener(rec)
    return rec


# ---------------------------------------------------------------------------
# Password unlocks
# ---------------------------------------------------------------------------

def test_password_unlock_notifies_on_v2() -> None:
    with _vault(2):
        rec = _recorder()
        assert store.load_secrets(TEST_PASSWORD) == BASE_SECRETS
        assert rec.methods == ["password"]
        _m, body, fp = rec.events[0]
        assert fp == _sha(store.SECRETS_FILE)
        assert {k: v for k, v in body.items() if not k.startswith("#")} == BASE_SECRETS
        assert store.body_generation(body) == 1


def test_password_unlock_notifies_on_v1() -> None:
    with _vault(1):
        assert crypto.is_v2(store.SECRETS_FILE.read_bytes()) is False
        rec = _recorder()
        assert store.load_secrets(TEST_PASSWORD) == BASE_SECRETS
        assert rec.methods == ["password"]
        _m, body, fp = rec.events[0]
        assert fp == _sha(store.SECRETS_FILE)
        assert body["API_TOKEN"] == "tok-abc-123"
        assert store.body_generation(body) == 2  # create (1) + save (2)


def test_every_password_read_entry_point_notifies() -> None:
    for version in (2, 1):
        with _vault(version):
            rec = _recorder()
            store.load_secrets(TEST_PASSWORD)
            store.load_secrets_ex(TEST_PASSWORD)
            store.load_vault_body(TEST_PASSWORD)
            body, _env, fp = store.load_vault_body_ex(TEST_PASSWORD)
            assert rec.methods == ["password"] * 4
            assert rec.events[-1][2] == fp == _sha(store.SECRETS_FILE)
            assert store.GENERATION_KEY in body


def test_wrong_password_does_not_notify() -> None:
    for version in (2, 1):
        with _vault(version):
            rec = _recorder()
            try:
                store.load_secrets("not-the-password")
            except crypto.WrongPassword:
                pass
            else:
                raise AssertionError("wrong password was accepted")
            assert rec.events == []


def test_listener_receives_a_copy_not_the_callers_body() -> None:
    with _vault(2):
        def vandal(body, fingerprint, method):
            body.clear()
            body["API_TOKEN"] = "poisoned"
        store.register_unlock_listener(vandal)
        assert store.load_secrets(TEST_PASSWORD) == BASE_SECRETS
        body = store.load_vault_body(TEST_PASSWORD)
        assert body["API_TOKEN"] == "tok-abc-123"


# ---------------------------------------------------------------------------
# Writes, credential changes, reissue
# ---------------------------------------------------------------------------

def test_writes_notify_with_the_written_body_and_new_fingerprint() -> None:
    for version in (2, 1):
        with _vault(version):
            rec = _recorder()
            before = store.body_generation(store.load_vault_body(TEST_PASSWORD))
            rec.events.clear()

            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "ADDED": "v-added-1"})
            assert rec.methods == ["write"]
            _m, body, fp = rec.events[0]
            assert fp == _sha(store.SECRETS_FILE)
            assert body["ADDED"] == "v-added-1"
            assert store.body_generation(body) == before + 1

            rec.events.clear()
            raw = store.load_vault_body(TEST_PASSWORD)
            raw["#always_allow"] = [{"id": "x"}]
            rec.events.clear()
            store.save_vault_body(TEST_PASSWORD, raw)
            assert rec.methods == ["write"]
            _m, body, fp = rec.events[0]
            assert fp == _sha(store.SECRETS_FILE)
            assert body["#always_allow"] == [{"id": "x"}]
            assert store.body_generation(body) == before + 2


def test_failed_write_does_not_notify_or_bump() -> None:
    with _vault(2):
        rec = _recorder()
        body, _env, fp = store.load_vault_body_ex(TEST_PASSWORD)
        store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "N": "v-n-1234"})
        rec.events.clear()
        gen = store.body_generation(store.load_vault_body(TEST_PASSWORD))
        rec.events.clear()
        try:
            store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS), expect_fingerprint=fp)
        except RuntimeError:
            pass
        else:
            raise AssertionError("stale fingerprint accepted")
        assert rec.events == []
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == gen


def test_change_password_notifies_once_on_v2_and_v1() -> None:
    for version in (2, 1):
        with _vault(version):
            gen = store.body_generation(store.load_vault_body(TEST_PASSWORD))
            rec = _recorder()
            store.change_password(TEST_PASSWORD, NEW_PASSWORD)
            assert rec.methods == ["change_password"], rec.methods
            _m, body, fp = rec.events[0]
            assert fp == _sha(store.SECRETS_FILE)
            assert body["API_TOKEN"] == "tok-abc-123"
            # a credential change raises the generation too: a pre-change
            # vault.enc must read as older
            assert store.body_generation(body) == gen + 1
            assert store.load_secrets(NEW_PASSWORD) == BASE_SECRETS


def test_reissue_recovery_key_notifies_once() -> None:
    with _vault(2, recovery=True):
        gen = store.body_generation(store.load_vault_body(TEST_PASSWORD))
        rec = _recorder()
        store.reissue_recovery_key(TEST_PASSWORD)
        assert rec.methods == ["reissue"]
        _m, body, fp = rec.events[0]
        assert fp == _sha(store.SECRETS_FILE)
        assert body["OTHER_SECRET"] == "other-xyz-789"
        assert store.body_generation(body) == gen + 1


# ---------------------------------------------------------------------------
# Recovery key
# ---------------------------------------------------------------------------

def test_recovery_key_unlock_does_not_notify_and_new_password_does() -> None:
    with _vault(2, recovery=True) as rk_text:
        rec = _recorder()
        assert store.recover_with_recovery_key(rk_text, NEW_PASSWORD) is None
        assert rec.events == [], "a recovery-key unlock must never notify"
        # the human then using the NEW password is an ordinary password unlock
        assert store.load_secrets(NEW_PASSWORD) == BASE_SECRETS
        assert rec.methods == ["password"]


def test_writes_inside_a_recovery_session_are_tagged_recovery() -> None:
    with _vault(2, recovery=True):
        rec = _recorder()
        with store.recovery_session():
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "R": "v-recov-1"})
            store.reissue_recovery_key(TEST_PASSWORD)
            store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert rec.methods == ["recovery", "recovery", "recovery"]
        rec.events.clear()
        # the tag does not leak out of the session
        store.save_secrets(NEW_PASSWORD, dict(BASE_SECRETS))
        assert rec.methods == ["write"]


def test_recovery_session_is_per_thread() -> None:
    import threading
    with _vault(2):
        rec = _recorder()
        done = []

        def other():
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "T": "v-thread-1"})
            done.append(True)

        with store.recovery_session():
            t = threading.Thread(target=other)
            t.start()
            t.join()
        assert done and rec.methods == ["write"]


# ---------------------------------------------------------------------------
# Listener robustness and registry
# ---------------------------------------------------------------------------

def test_listener_exceptions_never_break_unlocks_writes_or_credential_ops() -> None:
    for version in (2, 1):
        with _vault(version, recovery=(version == 2)):
            calls = []

            def boom(body, fingerprint, method):
                calls.append(method)
                raise RuntimeError("listener exploded")

            store.register_unlock_listener(boom)
            good = _recorder()
            assert store.load_secrets(TEST_PASSWORD) == BASE_SECRETS
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "Z": "v-z-123456"})
            store.change_password(TEST_PASSWORD, NEW_PASSWORD)
            if version == 2:
                store.reissue_recovery_key(NEW_PASSWORD)
            assert store.load_secrets(NEW_PASSWORD)["Z"] == "v-z-123456"
            # the failing listener was still called every time, and a later
            # listener still got every event
            assert calls[:3] == ["password", "write", "change_password"]
            assert good.methods[:3] == ["password", "write", "change_password"]


def test_register_is_idempotent_and_unregister_works() -> None:
    with _vault(2):
        rec = Recorder()
        store.register_unlock_listener(rec)
        store.register_unlock_listener(rec)
        store.load_secrets(TEST_PASSWORD)
        assert rec.methods == ["password"]
        store.unregister_unlock_listener(rec)
        store.unregister_unlock_listener(rec)  # unknown: ignored
        store.load_secrets(TEST_PASSWORD)
        assert rec.methods == ["password"]


# ---------------------------------------------------------------------------
# #generation
# ---------------------------------------------------------------------------

def test_body_generation_helper_is_tolerant() -> None:
    g = store.body_generation
    assert g({}) == 0
    assert g({"#generation": 7}) == 7
    for bad in (None, "5", 1.5, -3, True, [], {}):
        assert g({"#generation": bad}) == 0, bad
    assert g(None) == 0
    assert store.GENERATION_KEY == "#generation" and store.is_reserved_key(store.GENERATION_KEY)


def test_generation_increments_on_every_write_and_survives_save_secrets() -> None:
    with _vault(2):
        # create_v2_vault wrote no counter; the setup save_secrets made it 1
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 1
        for expected in (2, 3, 4):
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, "K": f"v-{expected}-xxxx"})
            assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == expected
        # variables-only views never expose it
        assert all(not k.startswith("#") for k in store.load_secrets(TEST_PASSWORD))


def test_generation_survives_save_vault_body_and_is_never_lowered() -> None:
    with _vault(2):
        body = store.load_vault_body(TEST_PASSWORD)          # generation 1
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))  # now 2
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))  # now 3
        # a stale raw body carrying generation 1 must not roll the counter back
        store.save_vault_body(TEST_PASSWORD, body)
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 4
        # a body that carries a HIGHER number than disk is respected
        body = store.load_vault_body(TEST_PASSWORD)
        body[store.GENERATION_KEY] = 50
        store.save_vault_body(TEST_PASSWORD, body)
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 51
        # a body with no counter at all picks up from disk
        bare = {k: v for k, v in store.load_vault_body(TEST_PASSWORD).items()
                if k != store.GENERATION_KEY}
        store.save_vault_body(TEST_PASSWORD, bare)
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 52


def test_generation_on_v1_save_vault_body_is_never_lowered() -> None:
    with _vault(1):
        body = store.load_vault_body(TEST_PASSWORD)          # an older generation
        stale = store.body_generation(body)
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))
        on_disk = store.body_generation(store.load_vault_body(TEST_PASSWORD))
        assert on_disk >= stale + 2
        # a stale raw body (no merge) must not move the counter backwards
        store.save_vault_body(TEST_PASSWORD, body)
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == on_disk + 1


def test_generation_does_not_mutate_the_callers_body() -> None:
    with _vault(2):
        body = store.load_vault_body(TEST_PASSWORD)
        snapshot = dict(body)
        store.save_vault_body(TEST_PASSWORD, body)
        assert body == snapshot


def test_generation_on_v1_and_across_change_password_and_other_reserved_keys() -> None:
    with _vault(1):
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 2
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 3
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert store.body_generation(store.load_vault_body(NEW_PASSWORD)) == 4

    with _vault(2):
        store.get_or_create_fmk(TEST_PASSWORD)  # another reserved key; also a write
        body = store.load_vault_body(TEST_PASSWORD)
        assert store.FMK_KEY in body and store.body_generation(body) == 2
        store.save_secrets(TEST_PASSWORD, dict(BASE_SECRETS))
        body = store.load_vault_body(TEST_PASSWORD)
        assert store.FMK_KEY in body and store.body_generation(body) == 3


def test_save_secrets_still_refuses_a_smuggled_generation() -> None:
    with _vault(2):
        try:
            store.save_secrets(TEST_PASSWORD, {**BASE_SECRETS, store.GENERATION_KEY: 99})
        except ValueError:
            pass
        else:
            raise AssertionError("save_secrets accepted a reserved key")
        assert store.body_generation(store.load_vault_body(TEST_PASSWORD)) == 1


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches test_trust.py)
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
    print("All tests passed.")
