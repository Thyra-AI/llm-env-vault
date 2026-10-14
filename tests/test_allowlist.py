"""
Tests for vault_lib/allowlist.py and vault_lib/profiles/__init__.py (2.4.0
"always allow", core): storage in the vault body, arming from the unlock
listener, the rollback guard, matching, eligibility, the denial cool-down and
the profile registry.

Everything is headless: a throwaway v2 vault in a temp dir (store paths
redirected and restored), fast scrypt parameters, a fake profile registered
through profiles.register_profile, and the rollback sidecar redirected to a
temp directory by the autouse fixture in tests/conftest.py. No dialog exists
at this layer.

Runs under pytest only (the conftest fixture isolates the sidecar).
"""
import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib import allowlist, crypto, profiles, store, trust  # noqa: E402
from vault_lib.profiles import Request, Verdict  # noqa: E402
from vault_lib.profiles import _common as profile_common  # noqa: E402

PW = "allowlist-test-password-123"
NEW_PW = "allowlist-test-new-password-456"
SECRETS = {"API_TOKEN": "tok-abcdefgh-123456", "DB_PASSWORD": "db-pass-value-789",
           "PLAIN": "justletters123"}
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

class FakeProfile:
    """A profile claiming every command whose argv0 is 'fake'."""
    kind = "fake"

    def __init__(self):
        self.snapshot_result = (True, None)
        self.snapshot_raises = False
        self.drift = None           # reason string -> verify says "drifted"
        self.verify_calls = 0

    def match(self, req):
        if req.command and req.command[0] == "fake":
            return {"argv": list(req.command)}
        return None

    def snapshot(self, req, candidate):
        return {"state": "approved", "hash": "abc123def456"}

    def describe(self, req, candidate):
        return "fake " + " ".join(req.command[1:]) + "\nfindings: none"

    def check_snapshot(self, entry):
        if self.snapshot_raises:
            raise RuntimeError("probe exploded")
        return self.snapshot_result

    def verify(self, entry, req):
        self.verify_calls += 1
        if entry["shape"] != self.match(req):
            return Verdict(ok=False, reason=None)
        if self.drift:
            return Verdict(ok=False, reason=self.drift)
        return Verdict(ok=True, argv=list(req.command), env=None)


def _reset_trust() -> None:
    trust._trusted.clear()
    trust._cached_secrets.clear()
    trust._cache_keys.clear()
    trust._cached_vault_fingerprint = None


class Env:
    def __init__(self, root, recovery_key):
        self.root = root
        self.cwd = allowlist.canonical_cwd(str(root))
        self.recovery_key = recovery_key
        self.fake = FakeProfile()
        profiles.register_profile("fake", self.fake)

    def req(self, *command, only=("API_TOKEN",), cwd=None, timeout=None):
        return Request(command or ("fake", "go"), cwd or self.cwd, tuple(only), timeout)

    def approve(self, *command, only=("API_TOKEN",)):
        offer = allowlist.make_offer(self.req(*command, only=only))
        assert offer is not None
        return offer.commit(PW)

    def copy_vault(self) -> bytes:
        return store.SECRETS_FILE.read_bytes()

    def restore_vault(self, data: bytes) -> None:
        store.SECRETS_FILE.write_bytes(data)

    def unlock(self, password=PW):
        return store.load_secrets(password)


@contextlib.contextmanager
def _env(recovery=False, install=True):
    names = ("SALT_FILE", "SECRETS_FILE", "INDEX_FILE", "ENV_FILE", "BAK_FILE",
             "FORMAT_FILE", "VAULT_LOCK_FILE", "FILES_FILE", "FILES_LOCK_FILE",
             "TARGETS_FILE", "TARGETS_LOCK_FILE", "ROOT")
    originals = {n: getattr(store, n) for n in names}
    saved_listeners = list(store._unlock_listeners)
    old_params = crypto.SCRYPT_DEFAULT
    with tempfile.TemporaryDirectory(prefix="llm_allowlist_test_") as tmp:
        root = Path(tmp).resolve()
        vault_dir = root / "vault"
        vault_dir.mkdir()
        store.ROOT = vault_dir
        for attr, name in (("SALT_FILE", "vault.salt"), ("SECRETS_FILE", "vault.enc"),
                           ("INDEX_FILE", "vault_index.json"), ("ENV_FILE", "llm.env"),
                           ("BAK_FILE", "vault.enc.bak"), ("FORMAT_FILE", "vault.format.txt"),
                           ("VAULT_LOCK_FILE", "vault.enc.lock"),
                           ("FILES_FILE", "files.json"), ("FILES_LOCK_FILE", "files.json.lock"),
                           ("TARGETS_FILE", "targets.json"),
                           ("TARGETS_LOCK_FILE", "targets.json.lock")):
            setattr(store, attr, vault_dir / name)
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        del store._unlock_listeners[:]
        _reset_trust()
        project = root / "project"
        project.mkdir()
        try:
            raw = bytes(crypto.new_recovery_key()) if recovery else None
            rk = store.create_v2_vault(PW, recovery_raw=raw)
            store.save_secrets(PW, dict(SECRETS))
            if install:
                allowlist.install()
            yield Env(project, rk)
        finally:
            allowlist.reset()
            allowlist.uninstall()
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            store._unlock_listeners[:] = saved_listeners
            for n, v in originals.items():
                setattr(store, n, v)


def _body() -> dict:
    return store.load_vault_body(PW)


def _native_copy(e, monkeypatch, name="sometool") -> str:
    """A copy of a system native executable in the project directory, with the
    exe-directory-writable check relaxed (a temp dir is user-writable): the
    exact profile pins its argv0, so it needs a real program to resolve."""
    monkeypatch.setattr(profile_common.RELAXATIONS, "skip_exe_dir_writable_check", True)
    if os.name == "nt":
        source = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                              "hostname.exe")
        dest = e.root / (name + ".exe")
    else:
        source = shutil.which("true") or "/bin/true"
        dest = e.root / name
    shutil.copy(source, dest)
    return str(dest.resolve())


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def test_storage_round_trip_and_upsert() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        raw = _body()[allowlist.ALLOW_KEY]
        assert len(raw) == 1
        entry = raw[0]
        assert entry["id"] == eid == allowlist.entry_id(
            "fake", e.cwd, ["API_TOKEN"], {"argv": ["fake", "go"]})
        assert (entry["kind"], entry["cwd"], entry["only_vars"]) == ("fake", e.cwd, ["API_TOKEN"])
        assert entry["shape"] == {"argv": ["fake", "go"]}
        assert entry["snapshot"] == {"state": "approved", "hash": "abc123def456"}
        assert entry["label"].startswith("fake")
        created = entry["created"]
        assert created.endswith("+00:00")

        # Re-approval upserts: same id, one entry, created kept, snapshot refreshed.
        e.fake.snapshot = lambda req, cand: {"state": "re-approved"}
        assert e.approve("fake", "go") == eid
        raw = _body()[allowlist.ALLOW_KEY]
        assert len(raw) == 1 and raw[0]["created"] == created
        assert raw[0]["snapshot"] == {"state": "re-approved"}


def test_id_depends_on_vars_cwd_shape_not_order() -> None:
    a = allowlist.entry_id("fake", "/c", ["B", "A"], {"x": 1})
    assert a == allowlist.entry_id("fake", "/c", ["A", "B"], {"x": 1})
    assert a != allowlist.entry_id("fake", "/c", ["A"], {"x": 1})
    assert a != allowlist.entry_id("fake", "/d", ["A", "B"], {"x": 1})
    assert a != allowlist.entry_id("fake", "/c", ["A", "B"], {"x": 2})
    assert len(a) == 12


def test_reserved_keys_survive_add_and_remove() -> None:
    with _env() as e:
        fmk = store.get_or_create_fmk(PW)
        body = _body()
        body["#custom_reserved"] = {"keep": "me"}
        store.save_vault_body(PW, body)
        gen_before = store.body_generation(_body())

        eid = e.approve("fake", "go")
        after_add = _body()
        assert after_add[store.FMK_KEY] == fmk
        assert after_add["#custom_reserved"] == {"keep": "me"}
        assert store.body_generation(after_add) > gen_before
        for name, value in SECRETS.items():
            assert after_add[name] == value

        assert allowlist.remove_entry(PW, eid) is True
        after_rm = _body()
        assert after_rm[store.FMK_KEY] == fmk
        assert after_rm["#custom_reserved"] == {"keep": "me"}
        assert after_rm[allowlist.ALLOW_KEY] == []
        assert store.body_generation(after_rm) > store.body_generation(after_add)
        assert allowlist.remove_entry(PW, eid) is False      # unknown id: no write


def test_add_entry_validations() -> None:
    with _env() as e:
        with pytest.raises(ValueError):
            allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=[], shape={}, snapshot={}, label="x")
        with pytest.raises(ValueError):                       # not in the vault
            allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=["NOPE"], shape={}, snapshot={}, label="x")
        with pytest.raises(ValueError):                       # reserved key
            allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=["#fmk"], shape={}, snapshot={}, label="x")
        with pytest.raises(ValueError):                       # unknown kind
            allowlist.add_entry(PW, kind="nonesuch", cwd=e.cwd, only_vars=["PLAIN"], shape={}, snapshot={}, label="x")
        with pytest.raises(crypto.WrongPassword):
            allowlist.add_entry("wrong-password", kind="fake", cwd=e.cwd, only_vars=["PLAIN"],
                                shape={}, snapshot={}, label="x")
        assert _body().get(allowlist.ALLOW_KEY, []) == []


def test_cas_retry_on_concurrent_write() -> None:
    with _env() as e:
        real = store.save_vault_body
        calls = []

        def racing(password, body, expect_fingerprint=None):
            calls.append(expect_fingerprint)
            if len(calls) == 1:
                # Someone else writes first: the CAS check must fail once.
                store.save_secrets(PW, {**SECRETS, "ADDED": "added-value-1"})
            return real(password, body, expect_fingerprint=expect_fingerprint)

        store.save_vault_body = racing
        try:
            eid = e.approve("fake", "go")
        finally:
            store.save_vault_body = real
        assert len(calls) == 2
        body = _body()
        assert body["ADDED"] == "added-value-1"               # the racer's write kept
        assert [x["id"] for x in body[allowlist.ALLOW_KEY]] == [eid]


def test_cas_gives_up_after_one_retry() -> None:
    with _env() as e:
        real = store.save_vault_body

        def always_racing(password, body, expect_fingerprint=None):
            store.save_secrets(PW, {**SECRETS, "N": f"n-{hashlib.sha256(body.__repr__().encode()).hexdigest()[:8]}"})
            return real(password, body, expect_fingerprint=expect_fingerprint)

        store.save_vault_body = always_racing
        try:
            with pytest.raises(RuntimeError, match="compare-and-swap"):
                e.approve("fake", "go")
        finally:
            store.save_vault_body = real


def test_tampered_vault_raises_vault_tampered() -> None:
    with _env() as e:
        e.approve("fake", "go")
        data = bytearray(e.copy_vault())
        data[-5] ^= 0x01                                      # inside the AEAD ciphertext/tag
        e.restore_vault(bytes(data))
        with pytest.raises(crypto.VaultTampered):
            allowlist.list_entries(PW)
        with pytest.raises(crypto.VaultTampered):
            allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=["PLAIN"],
                                shape={"argv": ["fake", "x"]}, snapshot={}, label="x")


def test_list_lives_inside_the_ciphertext() -> None:
    with _env() as e:
        e.approve("fake", "go")
        raw = e.copy_vault()
        assert b"always_allow" not in raw and b"abc123def456" not in raw


# ---------------------------------------------------------------------------
# Arming
# ---------------------------------------------------------------------------

def test_arms_on_password_unlock_and_loads_only_entry_vars() -> None:
    with _env() as e:
        e.approve("fake", "go", only=("API_TOKEN", "DB_PASSWORD"))
        allowlist.reset()                                     # "restart": nothing armed
        assert allowlist.describe_state()["armed"] == 0
        assert allowlist.find_match(e.req("fake", "go", only=("API_TOKEN",))) is None

        e.unlock()
        state = allowlist.describe_state()
        assert state["installed"] and state["entries"] == 1 and state["armed"] == 1
        report = allowlist.last_arm_report()
        assert report["method"] == "password" and len(report["armed"]) == 1
        assert report["armed"][0]["only_vars"] == ["API_TOKEN", "DB_PASSWORD"]
        assert report["disarmed"] == []
        eid = report["armed"][0]["id"]
        cached = trust.cached_secrets(("always_allow", eid))
        assert cached == {"API_TOKEN": SECRETS["API_TOKEN"], "DB_PASSWORD": SECRETS["DB_PASSWORD"]}
        assert "PLAIN" not in cached


def test_add_arms_immediately_from_post_write_body() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        assert allowlist.describe_state()["status"][eid]["armed"] is True
        m = allowlist.find_match(e.req("fake", "go"))
        assert m is not None and m.id == eid and m.secrets == {"API_TOKEN": SECRETS["API_TOKEN"]}
        assert m.verdict.ok and m.verdict.argv == ["fake", "go"]
        m.close()
        assert m.secrets == {}


def test_install_is_idempotent_and_uninstall_stops_arming() -> None:
    with _env() as e:
        allowlist.install()
        allowlist.install()
        assert store._unlock_listeners.count(allowlist._on_unlock) == 1
        e.approve("fake", "go")
        allowlist.uninstall()
        allowlist.reset()
        e.unlock()
        assert allowlist.describe_state()["armed"] == 0


def test_recovery_method_never_arms() -> None:
    with _env(recovery=True) as e:
        e.approve("fake", "go")
        allowlist.reset()
        # Direct listener call and a real recovery-key reset: neither arms.
        body, _env_bytes, fp = store.load_vault_body_ex(PW)    # arms (password)
        assert allowlist.describe_state()["armed"] == 1
        allowlist.reset()
        allowlist._on_unlock(body, fp, "recovery")
        state = allowlist.describe_state()
        assert state["armed"] == 0 and state["entries"] == 0
        store.recover_with_recovery_key(e.recovery_key, NEW_PW)
        assert allowlist.describe_state()["armed"] == 0
        assert allowlist.find_match(e.req("fake", "go")) is None
        # Password unlock on the new credentials arms again.
        store.load_secrets(NEW_PW)
        assert allowlist.describe_state()["armed"] == 1


def test_recovery_write_drops_what_was_armed() -> None:
    with _env(recovery=True) as e:
        e.approve("fake", "go")
        assert allowlist.find_match(e.req("fake", "go")) is not None
        store.recover_with_recovery_key(e.recovery_key, NEW_PW)
        match, reason = allowlist.lookup(e.req("fake", "go"))
        assert match is None and reason                         # vault changed under us
        assert allowlist.describe_state()["armed"] == 0


def test_exact_offer_label_is_short_and_server_made(monkeypatch) -> None:
    with _env() as e:
        exe = _native_copy(e, monkeypatch, "some-tool")
        offer = allowlist.make_offer(e.req(exe, "--flag", "x" * 300))
        assert offer.label.startswith("exact: ") and "some-tool" in offer.label
        assert len(offer.label) <= 100 and "\n" not in offer.label


def test_recovery_session_writes_never_arm() -> None:
    with _env(recovery=True) as e:
        allowlist.reset()
        with store.recovery_session():
            body = _body_noarm()
            body[allowlist.ALLOW_KEY] = [{"id": "x"}]
            store.save_vault_body(PW, body)
        assert allowlist.describe_state()["entries"] == 0


def _body_noarm() -> dict:
    with store._quiet_notifications():
        return store.load_vault_body(PW)


def test_removal_disarms_synchronously() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        other = e.approve("fake", "other")
        assert allowlist.find_match(e.req("fake", "go")) is not None
        assert allowlist.remove_entry(PW, eid) is True
        assert allowlist.find_match(e.req("fake", "go")) is None
        assert trust.cached_secrets(("always_allow", eid)) is None
        assert trust.check_armed(("always_allow", eid)) == (False, None)
        state = allowlist.describe_state()
        assert eid not in state["status"] and state["armed"] == 1
        assert allowlist.find_match(e.req("fake", "other")) is not None
        assert other in state["status"]


def test_removal_is_not_undone_by_a_later_unlock() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        allowlist.remove_entry(PW, eid)
        e.unlock()
        assert allowlist.describe_state()["armed"] == 0
        assert allowlist.entries_to_arm() == []


def test_rebuild_failure_while_arming_still_disarms_removed_entries(monkeypatch) -> None:
    with _env() as e:
        gone = e.approve("fake", "go")
        kept = e.approve("fake", "other")
        assert trust.cached_secrets(("always_allow", gone)) is not None
        real_arm = trust.arm

        def flaky_arm(key, *a, **k):
            if key == ("always_allow", kept):
                raise RuntimeError("cache unavailable")
            return real_arm(key, *a, **k)

        monkeypatch.setattr(trust, "arm", flaky_arm)

        def mutate(body, entries):
            return [i for i in entries if i.get("id") != gone], True

        allowlist._modify(PW, mutate)               # another writer drops `gone`
        assert trust.cached_secrets(("always_allow", gone)) is None
        assert trust.check_armed(("always_allow", gone)) == (False, None)
        state = allowlist.describe_state()
        assert gone not in state["status"]
        assert state["status"][kept]["armed"] is False
        assert "cache unavailable" in state["status"][kept]["reason"]
        assert gone not in {i["id"] for i in allowlist.entries_to_arm()}


def test_missing_variable_disarms_with_reason() -> None:
    with _env() as e:
        eid = e.approve("fake", "go", only=("PLAIN",))
        remaining = {k: v for k, v in SECRETS.items() if k != "PLAIN"}
        store.save_secrets(PW, remaining)
        status = allowlist.describe_state()["status"][eid]
        assert status["armed"] is False and "PLAIN" in status["reason"]
        report = allowlist.last_arm_report()
        assert report["disarmed"][0]["id"] == eid and "PLAIN" in report["disarmed"][0]["reason"]
        assert allowlist.find_match(e.req("fake", "go", only=("PLAIN",))) is None
        assert trust.cached_secrets(("always_allow", eid)) is None
        assert [x["id"] for x in allowlist.entries_to_arm()] == [eid]


def test_unknown_kind_and_missing_module_disarm_without_crash(monkeypatch) -> None:
    with _env() as e:
        e.fake.kind = "fake"
        eid = e.approve("fake", "go")
        profiles.unregister_profile("fake")                   # kind now unknown
        e.unlock()
        status = allowlist.describe_state()["status"][eid]
        assert status["armed"] is False and "unknown" in status["reason"]
        assert allowlist.find_match(e.req("fake", "go")) is None

        # A kind in the registry whose module does not exist.
        monkeypatch.setitem(profiles.REGISTRY, "ghost", "vault_lib.profiles.ghost_not_written")
        profiles.register_profile("ghost", e.fake)
        gid = allowlist.add_entry(PW, kind="ghost", cwd=e.cwd, only_vars=["PLAIN"],
                                  shape={"argv": ["g"]}, snapshot={}, label="ghost: g")
        profiles.unregister_profile("ghost")
        profiles.reset_cache()
        e.unlock()
        status = allowlist.describe_state()["status"][gid]
        assert status["armed"] is False and "not available" in status["reason"]
        # Other entries are unaffected by the missing module.
        profiles.register_profile("fake", e.fake)
        e.unlock()
        assert allowlist.describe_state()["status"][eid]["armed"] is True


def test_check_snapshot_failure_and_exception_disarm() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        e.fake.snapshot_result = (False, "the remote URL changed")
        e.unlock()
        status = allowlist.describe_state()["status"][eid]
        assert status == {"kind": "fake", "label": status["label"], "armed": False,
                          "reason": "the remote URL changed"}
        assert allowlist.last_arm_report()["disarmed"][0]["reason"] == "the remote URL changed"
        assert allowlist.find_match(e.req("fake", "go")) is None

        e.fake.snapshot_result = (False, None)
        e.unlock()
        assert allowlist.describe_state()["status"][eid]["reason"]    # non-empty default

        e.fake.snapshot_raises = True
        e.unlock()
        reason = allowlist.describe_state()["status"][eid]["reason"]
        assert "probe exploded" in reason

        e.fake.snapshot_raises = False
        e.fake.snapshot_result = (True, None)
        e.unlock()
        assert allowlist.describe_state()["status"][eid]["armed"] is True


def test_tool_control_names_are_refused_when_the_store_defines_them(monkeypatch) -> None:
    with _env() as e:
        monkeypatch.setattr(store, "is_tool_control_name",
                            lambda n: n.upper().startswith("GIT_"), raising=False)
        store.save_secrets(PW, {**SECRETS, "GIT_ASKPASS": "askpass-value-1"})
        with pytest.raises(ValueError, match="tool-control"):
            allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=["GIT_ASKPASS"],
                                shape={"argv": ["fake"]}, snapshot={}, label="x")
        monkeypatch.setattr(store, "is_tool_control_name", lambda n: False, raising=False)
        eid = allowlist.add_entry(PW, kind="fake", cwd=e.cwd, only_vars=["GIT_ASKPASS"],
                                  shape={"argv": ["fake"]}, snapshot={}, label="x")
        monkeypatch.setattr(store, "is_tool_control_name",
                            lambda n: n.upper().startswith("GIT_"), raising=False)
        e.unlock()
        status = allowlist.describe_state()["status"][eid]
        assert status["armed"] is False and "tool-control" in status["reason"]


def test_malformed_entries_are_ignored_not_fatal() -> None:
    with _env() as e:
        good = e.approve("fake", "go")
        body = _body_noarm()
        body[allowlist.ALLOW_KEY] = body[allowlist.ALLOW_KEY] + [
            "junk", 7, {"id": "bad1"},
            {**body[allowlist.ALLOW_KEY][0], "id": "000000000000"}]   # id does not match contents
        store.save_vault_body(PW, body)
        state = allowlist.describe_state()
        assert state["entries"] == 1 and state["armed"] == 1
        assert state["status"][good]["armed"] is True
        assert state["status"]["bad1"]["armed"] is False
        assert state["status"]["000000000000"]["armed"] is False
        assert allowlist.find_match(e.req("fake", "go")) is not None


# ---------------------------------------------------------------------------
# Rollback guard
# ---------------------------------------------------------------------------

def test_rollback_to_older_copy_refuses_arming() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        old = e.copy_vault()
        store.save_secrets(PW, {**SECRETS, "NEWER": "newer-value-1"})     # generation moves on
        assert allowlist.rollback_warning() is None
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE
        state = allowlist.describe_state()
        assert state["armed"] == 0 and state["rollback_warning"]
        assert state["status"][eid]["reason"] == allowlist.ROLLBACK_MESSAGE
        assert allowlist.find_match(e.req("fake", "go")) is None
        assert allowlist.last_arm_report()["warning"] == allowlist.ROLLBACK_MESSAGE
        # The vault itself still opens, and it stays refused on every later unlock.
        assert e.unlock() == SECRETS
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE
        assert trust.cached_secrets(("always_allow", eid)) is None


def test_restoring_the_newest_copy_clears_the_refusal() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        old = e.copy_vault()
        store.save_secrets(PW, {**SECRETS, "NEWER": "newer-value-1"})
        newest = e.copy_vault()
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning()
        e.restore_vault(newest)
        e.unlock()
        assert allowlist.rollback_warning() is None
        assert allowlist.describe_state()["status"][eid]["armed"] is True


def test_sidecar_survives_restart_and_lives_outside_the_vault_dir() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        old = e.copy_vault()
        store.save_secrets(PW, {**SECRETS, "NEWER": "newer-value-1"})
        side_dir = Path(allowlist.SIDECAR_DIR)
        files = list(side_dir.glob("*.json"))
        assert len(files) == 1
        record = json.loads(files[0].read_text(encoding="utf-8"))
        assert set(record) == {"vault_id", "generation"}
        assert record["generation"] == store.body_generation(_body_noarm())
        assert store.ROOT not in files[0].parents

        allowlist.reset()                                     # "restart": memory gone, sidecar stays
        assert files[0].exists() and not allowlist._seen_mem
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE
        assert allowlist.describe_state()["armed"] == 0 and eid is not None


def test_rollback_detected_from_memory_when_sidecar_is_deleted() -> None:
    with _env() as e:
        e.approve("fake", "go")
        old = e.copy_vault()
        store.save_secrets(PW, {**SECRETS, "NEWER": "newer-value-1"})
        for f in Path(allowlist.SIDECAR_DIR).glob("*.json"):
            f.unlink()
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE


def test_sidecar_is_never_lowered() -> None:
    with _env() as e:
        e.approve("fake", "go")
        old = e.copy_vault()
        store.save_secrets(PW, {**SECRETS, "NEWER": "newer-value-1"})
        high = store.body_generation(_body_noarm())
        e.restore_vault(old)
        e.unlock()                                             # refused: nothing recorded
        side = next(Path(allowlist.SIDECAR_DIR).glob("*.json"))
        assert json.loads(side.read_text(encoding="utf-8"))["generation"] == high


def test_missing_sidecar_is_accepted_with_a_note() -> None:
    with _env() as e:
        e.approve("fake", "go")
        for f in Path(allowlist.SIDECAR_DIR).glob("*.json"):
            f.unlink()
        allowlist.reset()
        e.unlock()
        assert allowlist.rollback_warning() is None
        assert allowlist.describe_state()["armed"] == 1
        assert allowlist.NO_SIDECAR_NOTE in allowlist.describe_state()["notes"]
        assert list(Path(allowlist.SIDECAR_DIR).glob("*.json"))     # recreated


def test_change_password_bump_makes_older_copy_read_as_rollback() -> None:
    with _env() as e:
        e.approve("fake", "go")
        old = e.copy_vault()
        gen = store.body_generation(_body_noarm())
        store.change_password(PW, NEW_PW)
        assert allowlist.describe_state()["armed"] == 1
        with store._quiet_notifications():
            assert store.body_generation(store.load_vault_body(NEW_PW)) > gen
        e.restore_vault(old)
        store.load_secrets(PW)                                 # the old copy opens with the old password
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE
        assert allowlist.describe_state()["armed"] == 0


def test_reissue_bump_makes_older_copy_read_as_rollback() -> None:
    with _env(recovery=True) as e:
        e.approve("fake", "go")
        old = e.copy_vault()
        store.reissue_recovery_key(PW)
        assert allowlist.rollback_warning() is None
        assert allowlist.describe_state()["armed"] == 1
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE


def test_recover_bump_makes_older_copy_read_as_rollback() -> None:
    with _env(recovery=True) as e:
        e.approve("fake", "go")
        old = e.copy_vault()
        store.recover_with_recovery_key(e.recovery_key, NEW_PW)
        store.load_secrets(NEW_PW)
        e.restore_vault(old)
        e.unlock()
        assert allowlist.rollback_warning() == allowlist.ROLLBACK_MESSAGE


def test_stale_notification_is_ignored() -> None:
    with _env() as e:
        e.approve("fake", "go")
        body, _env_bytes, fp = store.load_vault_body_ex(PW)
        allowlist.reset()
        allowlist._on_unlock(body, "0" * 64, "password")       # fingerprint of some other write
        assert allowlist.describe_state()["entries"] == 0
        allowlist._on_unlock(body, fp, "password")
        assert allowlist.describe_state()["armed"] == 1


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def test_request_vars_must_be_a_subset_of_entry_vars() -> None:
    with _env() as e:
        e.approve("fake", "go", only=("API_TOKEN", "DB_PASSWORD"))
        m = allowlist.find_match(e.req("fake", "go", only=("API_TOKEN",)))
        assert m is not None and m.secrets == {"API_TOKEN": SECRETS["API_TOKEN"]}   # only the subset
        m2 = allowlist.find_match(e.req("fake", "go", only=("API_TOKEN", "DB_PASSWORD")))
        assert m2 is not None and set(m2.secrets) == {"API_TOKEN", "DB_PASSWORD"}
        assert allowlist.find_match(e.req("fake", "go", only=("API_TOKEN", "PLAIN"))) is None
        assert allowlist.find_match(e.req("fake", "go", only=("PLAIN",))) is None


def test_other_command_cwd_do_not_match(tmp_path) -> None:
    with _env() as e:
        e.approve("fake", "go")
        assert allowlist.find_match(e.req("fake", "different")) is None
        assert allowlist.find_match(e.req("fake", "go", cwd=str(tmp_path))) is None
        # Another spelling of the same directory matches.
        assert allowlist.find_match(e.req("fake", "go", cwd=str(e.root / "." / ".."/ e.root.name))) is not None


def test_ineligible_request_never_reaches_a_profile() -> None:
    with _env() as e:
        e.approve("fake", "go")
        calls = e.fake.verify_calls
        assert allowlist.lookup(Request(("fake", "go"), e.cwd, ())) == (None, None)   # empty only_vars
        assert allowlist.find_match(e.req("bash", "-c", "x")) is None
        assert e.fake.verify_calls == calls


def test_verify_drift_disarms_with_reason() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        e.fake.drift = "the remote now points elsewhere"
        match, reason = allowlist.lookup(e.req("fake", "go"))
        assert match is None and reason == "the remote now points elsewhere"
        status = allowlist.describe_state()["status"][eid]
        assert status["armed"] is False and status["reason"] == reason
        assert trust.cached_secrets(("always_allow", eid)) is None
        # Even after the drift is gone it stays disarmed until the next unlock.
        e.fake.drift = None
        assert allowlist.find_match(e.req("fake", "go")) is None
        e.unlock()
        assert allowlist.find_match(e.req("fake", "go")) is not None


def test_recheck_drift_disarms_and_clears_secrets() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        m = allowlist.find_match(e.req("fake", "go"))
        assert m is not None and m.recheck().ok
        e.fake.drift = "hook added"
        verdict = m.recheck()
        assert not verdict.ok and verdict.reason == "hook added"
        assert m.secrets == {}
        assert allowlist.describe_state()["status"][eid] == {
            "kind": "fake", "label": m.label, "armed": False, "reason": "hook added"}
        assert allowlist.find_match(e.req("fake", "go")) is None


def test_verify_exception_is_drift() -> None:
    with _env() as e:
        e.approve("fake", "go")

        def boom(entry, req):
            raise RuntimeError("kaboom")
        e.fake.verify = boom
        match, reason = allowlist.lookup(e.req("fake", "go"))
        assert match is None and "kaboom" in reason


def test_vault_change_behind_our_back_invalidates_matches() -> None:
    with _env() as e:
        e.approve("fake", "go")
        # A write by someone who did not notify us (listeners cleared).
        saved = list(store._unlock_listeners)
        del store._unlock_listeners[:]
        try:
            store.save_secrets(PW, {**SECRETS, "ELSEWHERE": "elsewhere-value-1"})
        finally:
            store._unlock_listeners[:] = saved
        match, reason = allowlist.lookup(e.req("fake", "go"))
        assert match is None and reason                         # explains: vault changed
        assert allowlist.describe_state()["armed"] == 0


# ---------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------

def test_eligible_accepts_a_plain_command() -> None:
    assert allowlist.eligible(["git", "push"], only_vars=["A"], cwd="/tmp") == (True, None)
    assert allowlist.eligible(["git", "push"]) == (True, None)


@pytest.mark.parametrize("kwargs", [
    {"files": ["secret.bin"]},
    {"all_vars": True},
    {"background": True},
    {"max_reads": 1},
    {"materialize": "/tmp/x.env"},
    {"only_vars": []},
])
def test_eligible_refuses_modes(kwargs) -> None:
    ok, reason = allowlist.eligible(["git", "push"], **kwargs)
    assert ok is False and reason


@pytest.mark.parametrize("argv0", [
    "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh", "py", "node", "perl", "ruby", "wsl",
    "python", "python3", "python3.12", "Python.EXE", "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "/usr/bin/bash", "BASH.EXE",
    "x/pwsh.ps1",
])
def test_eligible_refuses_shells_and_interpreters_by_basename(argv0) -> None:
    ok, reason = allowlist.eligible([argv0, "-c", "x"])
    assert ok is False and "shell/interpreter" in reason


@pytest.mark.parametrize("argv0", [
    "env", "/usr/bin/env", "xargs", "timeout", "nice", "nohup", "pypy", "pypy3",
    "php", "lua", "deno", "bun", "java", "mshta.exe", "rundll32.exe",
])
def test_eligible_refuses_wrappers_and_other_interpreters(argv0) -> None:
    ok, reason = allowlist.eligible([argv0, "sh", "-c", "x"])
    assert ok is False and "shell/interpreter" in reason


def test_eligible_refuses_malformed_and_unprintable() -> None:
    assert allowlist.eligible([])[0] is False
    assert allowlist.eligible(["git", 5])[0] is False
    assert allowlist.eligible(["git", "pu\u202esh"])[0] is False          # bidi override
    assert allowlist.eligible(["git", "pu\u200bsh"])[0] is False          # zero width
    assert allowlist.eligible(["git", "a\nb"])[0] is False
    assert allowlist.eligible(["git", "a\u2028b"])[0] is False
    assert allowlist.eligible(["git", "a\x00b"])[0] is False
    assert allowlist.eligible(["git", "ok"], cwd="/tmp/\u202e")[0] is False


def test_make_offer_refuses_ineligible_requests() -> None:
    with _env() as e:
        assert allowlist.make_offer(e.req("bash", "-c", "x")) is None
        assert allowlist.make_offer(Request(("fake", "go"), e.cwd, ())) is None
        assert allowlist.make_offer(e.req("fake", "pu\u202esh")) is None


# ---------------------------------------------------------------------------
# Offers, labels, cool-down
# ---------------------------------------------------------------------------

def test_offer_fields_and_commit() -> None:
    with _env() as e:
        offer = allowlist.make_offer(e.req("fake", "go", only=("DB_PASSWORD", "API_TOKEN")))
        assert offer.kind == "fake" and offer.pattern.splitlines()[0] == "fake go"
        assert offer.cwd == e.cwd and offer.only_vars == ("API_TOKEN", "DB_PASSWORD")
        assert offer.shape == {"argv": ["fake", "go"]}
        assert offer.label.startswith("fake")
        eid = offer.commit(PW)
        assert allowlist.describe_state()["status"][eid]["armed"] is True


def test_offer_falls_through_to_exact_last(monkeypatch) -> None:
    with _env() as e:
        exe = _native_copy(e, monkeypatch, "some-tool")
        offer = allowlist.make_offer(e.req(exe, "--flag"))
        assert offer is not None and offer.kind == "exact"
        assert "Exact command" in offer.pattern
        # The injected fake claims its own commands before exact.
        assert allowlist.make_offer(e.req("fake", "x")).kind == "fake"


def test_offer_is_none_when_profile_cannot_snapshot() -> None:
    with _env() as e:
        def boom(req, cand):
            raise RuntimeError("no snapshot")
        e.fake.snapshot = boom
        assert allowlist.make_offer(e.req("fake", "go")) is None


def test_cooldown_after_three_denials(monkeypatch) -> None:
    with _env() as e:
        clock = [1000.0]
        monkeypatch.setattr(allowlist, "_now", lambda: clock[0])
        req = e.req("fake", "go")
        assert allowlist.cooldown_remaining(req) == 0
        allowlist.record_denial(req)
        clock[0] += 60
        allowlist.record_denial(req)
        assert allowlist.make_offer(req) is not None
        clock[0] += 60
        allowlist.record_denial(req)                          # third inside 30 min
        assert allowlist.make_offer(req) is None
        assert allowlist.cooldown_remaining(req) == pytest.approx(30 * 60)
        # A different signature is unaffected.
        assert allowlist.make_offer(e.req("fake", "other")) is not None
        clock[0] += 29 * 60
        assert allowlist.make_offer(req) is None
        clock[0] += 2 * 60
        assert allowlist.cooldown_remaining(req) == 0
        assert allowlist.make_offer(req) is not None
        # The counter restarted: two more denials do not hide it again.
        allowlist.record_denial(req)
        allowlist.record_denial(req)
        assert allowlist.make_offer(req) is not None


def test_denials_outside_the_window_do_not_add_up(monkeypatch) -> None:
    with _env() as e:
        clock = [0.0]
        monkeypatch.setattr(allowlist, "_now", lambda: clock[0])
        req = e.req("fake", "go")
        allowlist.record_denial(req)
        clock[0] += 31 * 60
        allowlist.record_denial(req)
        clock[0] += 31 * 60
        allowlist.record_denial(req)
        assert allowlist.cooldown_remaining(req) == 0
        assert allowlist.make_offer(req) is not None


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def test_list_entries_exposes_only_safe_fields() -> None:
    with _env() as e:
        eid = e.approve("fake", "go")
        bad = e.approve("fake", "other")
        e.fake.snapshot_result = (False, "drifted")
        e.unlock()
        listing = allowlist.list_entries(PW)
        assert len(listing) == 2
        for row in listing:
            assert set(row) == {"id", "kind", "cwd", "shape", "label", "armed", "reason"}
        dumped = json.dumps(listing)
        assert "abc123def456" not in dumped and "approved" not in dumped      # no snapshot content
        assert {r["id"] for r in listing} == {eid, bad}
        assert all(r["armed"] is False and r["reason"] == "drifted" for r in listing)
        with pytest.raises(crypto.WrongPassword):
            allowlist.list_entries("wrong-password")


def test_list_entries_when_empty() -> None:
    with _env():
        assert allowlist.list_entries(PW) == []


def test_describe_state_and_reports_hold_no_secret_values() -> None:
    with _env() as e:
        e.approve("fake", "go", only=("API_TOKEN",))
        blob = json.dumps([allowlist.describe_state(), allowlist.last_arm_report(),
                           allowlist.entries_to_arm()])
        for value in SECRETS.values():
            assert value not in blob


# ---------------------------------------------------------------------------
# Profile registry
# ---------------------------------------------------------------------------

def test_registry_order_has_exact_last() -> None:
    assert list(profiles.REGISTRY)[-1] == "exact"
    assert {"git", "docker", "kubectl", "exact"} <= set(profiles.REGISTRY)


def test_lazy_import_and_unavailable_reason(monkeypatch) -> None:
    import importlib
    imported = []
    real = importlib.import_module

    def spy(name, *a, **k):
        imported.append(name)
        return real(name, *a, **k)

    monkeypatch.setattr(profiles.importlib, "import_module", spy)
    profiles.reset_cache()
    assert imported == []                                      # nothing imported by reset/registry
    assert profiles.get_profile("exact").kind == "exact"
    assert imported == ["vault_lib.profiles.exact"]
    profiles.get_profile("exact")
    assert imported == ["vault_lib.profiles.exact"]            # cached

    monkeypatch.setitem(profiles.REGISTRY, "ghost", "vault_lib.profiles.ghost_not_written")
    assert profiles.get_profile("ghost") is None               # no crash
    assert "not available" in profiles.unavailable_reason("ghost")
    assert profiles.unavailable_reason("exact") == ""
    assert "unknown" in profiles.unavailable_reason("nonesuch")
    assert profiles.get_profile("nonesuch") is None
    assert profiles.get_profile(None) is None and profiles.get_profile(5) is None
    n = len(imported)
    profiles.get_profile("ghost")
    assert len(imported) == n                                  # failure is remembered


def test_broken_module_is_unavailable_not_fatal(monkeypatch) -> None:
    def explode(name, *a, **k):
        raise RuntimeError("syntax mess")
    monkeypatch.setitem(profiles.REGISTRY, "broken", "vault_lib.profiles.broken")
    monkeypatch.setattr(profiles.importlib, "import_module", explode)
    assert profiles.get_profile("broken") is None
    assert "failed to load" in profiles.unavailable_reason("broken")
    assert list(profiles.iter_profiles()) == []                # everything "fails", nothing raises


def test_nested_import_error_is_reported_as_load_failure(monkeypatch) -> None:
    import importlib

    def nested(name, *a, **k):
        raise ModuleNotFoundError("No module named 'dependency'", name="dependency")
    monkeypatch.setitem(profiles.REGISTRY, "nested", "vault_lib.profiles.nested")
    monkeypatch.setattr(profiles.importlib, "import_module", nested)
    assert profiles.get_profile("nested") is None
    assert "failed to load" in profiles.unavailable_reason("nested")
    del importlib


def test_iter_profiles_order_injected_first_exact_last() -> None:
    profiles.register_profile("fake", FakeProfile())
    kinds = [k for k, _p in profiles.iter_profiles()]
    assert kinds[0] == "fake" and kinds[-1] == "exact"
    assert kinds.count("exact") == 1
    other = FakeProfile()
    profiles.register_profile("fake", other)                   # replace
    assert dict(profiles.iter_profiles())["fake"] is other
    profiles.unregister_profile("fake")
    assert "fake" not in [k for k, _p in profiles.iter_profiles()]
    assert profiles.get_profile("fake") is None


def test_register_over_a_registry_kind_wins_then_unregister_restores() -> None:
    sentinel = FakeProfile()
    sentinel.kind = "exact"
    profiles.register_profile("exact", sentinel)
    assert profiles.get_profile("exact") is sentinel
    assert [k for k, _p in profiles.iter_profiles()][0] == "exact"
    profiles.unregister_profile("exact")
    restored = profiles.get_profile("exact")
    assert restored is not sentinel and restored.__name__ == "vault_lib.profiles.exact"


def test_request_and_verdict_value_types() -> None:
    r = Request(["a", "b"], "/c", ["Z", "A", "A"], 5)
    assert r.command == ("a", "b") and r.only_vars == ("A", "Z")
    with pytest.raises(Exception):
        r.cwd = "/other"                                        # frozen
    assert hash(r) == hash(Request(("a", "b"), "/c", ("A", "Z"), 5))
    v = Verdict(ok=False)
    assert v.reason is None and v.argv is None and v.env is None and v.replace_env is False


# ---------------------------------------------------------------------------
# Exact placeholder profile through the allowlist
# ---------------------------------------------------------------------------

def test_exact_profile_round_trip_with_file_drift(monkeypatch) -> None:
    with _env() as e:
        exe = _native_copy(e, monkeypatch)
        script = e.root / "tool.txt"
        script.write_text("v1", encoding="utf-8")
        req = e.req(exe, str(script))
        offer = allowlist.make_offer(req)
        assert offer.kind == "exact"
        eid = offer.commit(PW)
        assert allowlist.find_match(req) is not None
        assert allowlist.find_match(e.req(exe, "other")) is None
        script.write_text("v2", encoding="utf-8")
        match, reason = allowlist.lookup(req)
        assert match is None and "changed" in reason
        assert allowlist.describe_state()["status"][eid]["armed"] is False
        e.unlock()                                              # check_snapshot at arm time sees drift
        assert "changed" in allowlist.describe_state()["status"][eid]["reason"]
