"""
Regression suite for the File Master Key and the reserved-body-key accessors.

The FMK is the stable root for whole-file encryption. It lives INSIDE the
encrypted vault body rather than in a v2 header slot, because every credential
operation rotates the DEK but carries the body plaintext through verbatim --
so a key in the body survives all of them for free, while a key in a header
slot would have to be rebuilt correctly in four separate places.

That design buys its safety entirely from two properties, and this file exists
to hold both of them down:

  1. THE SURVIVAL MATRIX. Every credential path must carry the body across
     unchanged. Five paths do this by carrying `plaintext_bytes` verbatim
     (change_password v2, reissue_recovery_key, recover_with_recovery_key) or
     by going through the raw accessors on purpose (change_password v1,
     upgrade_to_v2). If any future refactor re-serialises the body from a
     variables-only dict, every .levault file ever written becomes permanently
     unopenable -- with no error at the time, and the failure surfacing weeks
     later on a file whose plaintext was already destroyed. These tests are the
     tripwire for that.

  2. THE NAMESPACE SPLIT. load_secrets/save_secrets are the safe door:
     variables only on the way out, reserved keys merged back in on the way in.
     Raw access is load_vault_body/save_vault_body, named to read as a warning
     at the call site. A caller who pairs a filtering read with a
     non-preserving write is the bug this split exists to make impossible.

Every test runs against an isolated throwaway vault under a temp directory;
nothing here reads or writes the repo's real vault files.

Runs under pytest (`pytest tests/test_fmk.py -q`) or standalone
(`python tests/test_fmk.py`).
"""
import base64
import contextlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import store  # noqa: E402

TEST_PASSWORD = "fmk-regression-password-123"
NEW_PASSWORD = "fmk-regression-password-456"
BASE_SECRETS = {"ALPHA": "alpha-value-111", "BETA": "beta-value-222"}

# scrypt at the real n=2**16 costs 64 MiB and ~100 ms per call; several tests
# here run three or four credential operations back to back.
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)


# ---------------------------------------------------------------------------
# Isolation helpers
# ---------------------------------------------------------------------------

def _isolate_store_paths(tmp_dir: Path) -> dict:
    originals = {
        "SALT_FILE": store.SALT_FILE,
        "SECRETS_FILE": store.SECRETS_FILE,
        "INDEX_FILE": store.INDEX_FILE,
        "ENV_FILE": store.ENV_FILE,
        "BAK_FILE": store.BAK_FILE,
        "FORMAT_FILE": store.FORMAT_FILE,
        "VAULT_LOCK_FILE": store.VAULT_LOCK_FILE,
    }
    store.SALT_FILE = tmp_dir / "vault.salt"
    store.SECRETS_FILE = tmp_dir / "vault.enc"
    store.INDEX_FILE = tmp_dir / "vault_index.json"
    store.ENV_FILE = tmp_dir / "llm.env"
    store.BAK_FILE = tmp_dir / "vault.enc.bak"
    store.FORMAT_FILE = tmp_dir / "vault.format.txt"
    store.VAULT_LOCK_FILE = tmp_dir / "vault.enc.lock"
    return originals


@contextlib.contextmanager
def isolated_vault(secrets=None, *, v2=True, recovery=False):
    """A throwaway vault in a temp dir, with scrypt turned down for speed.

    *v2* False creates the legacy v1 (PBKDF2/Fernet) vault instead, which the
    v1-specific paths need. *recovery* adds a recovery slot and yields its
    formatted key alongside the temp path.
    """
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_fmk_test_") as tmp:
        # .resolve() matters on Windows: mkdtemp hands back the 8.3 short form
        # when the username is over 8 characters. Same reasoning as test_trust.
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        try:
            if v2:
                rk = store.create_v2_vault(
                    TEST_PASSWORD,
                    recovery_raw=bytes(crypto.new_recovery_key()) if recovery else None,
                )
            else:
                store.create_secrets_vault(TEST_PASSWORD)
                rk = None
            store.save_secrets(TEST_PASSWORD, secrets)
            store.save_index({n: i + 1 for i, n in enumerate(sorted(secrets))})
            yield tmp_path, rk
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def _plant_fmk(password: str = TEST_PASSWORD) -> dict:
    """Mint an FMK the normal way and return the record."""
    return store.get_or_create_fmk(password)


def _fmk_of(password: str = TEST_PASSWORD):
    return store.get_fmk(password)


# ---------------------------------------------------------------------------
# 1. The namespace split
#
# Failure mode: a reserved key escapes into the variables dict and reaches
# env.update / render_env_text / _disclosure_mismatch, or a variables-only
# dict is written back over a body that held reserved state.
# ---------------------------------------------------------------------------

def test_is_reserved_key_and_validate_var_name_are_disjoint() -> None:
    assert store.is_reserved_key("#fmk")
    assert store.is_reserved_key(store.FMK_KEY)
    assert not store.is_reserved_key("FMK")
    assert not store.is_reserved_key("ALPHA")
    assert not store.is_reserved_key(None)
    assert not store.is_reserved_key(123)

    # The whole collision argument: validate_var_name can never produce a name
    # that is_reserved_key would accept.
    for bad in ("#fmk", "#anything", "#"):
        try:
            store.validate_var_name(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"validate_var_name accepted {bad!r}")


def test_save_index_rejects_a_reserved_key() -> None:
    with isolated_vault():
        try:
            store.save_index({"#fmk": 1})
        except ValueError:
            pass
        else:
            raise AssertionError("save_index accepted a reserved key")


def test_load_secrets_filters_reserved_keys_but_load_vault_body_does_not() -> None:
    with isolated_vault():
        record = _plant_fmk()
        assert record["active"] in record["keys"]

        variables = store.load_secrets(TEST_PASSWORD)
        assert variables == BASE_SECRETS
        assert not any(store.is_reserved_key(k) for k in variables)

        body = store.load_vault_body(TEST_PASSWORD)
        assert store.FMK_KEY in body
        assert body[store.FMK_KEY] == record


def test_load_secrets_ex_filters_reserved_keys_too() -> None:
    with isolated_vault():
        _plant_fmk()
        variables, envelope, fingerprint = store.load_secrets_ex(TEST_PASSWORD)
        assert variables == BASE_SECRETS
        assert not any(store.is_reserved_key(k) for k in variables)
        assert envelope is not None  # v2
        assert len(fingerprint) == 64


def test_save_secrets_refuses_a_smuggled_reserved_key() -> None:
    with isolated_vault():
        try:
            store.save_secrets(TEST_PASSWORD, {"ALPHA": "a", "#fmk": "smuggled"})
        except ValueError as exc:
            assert "#fmk" in str(exc)
            assert "save_vault_body" in str(exc)
        else:
            raise AssertionError("save_secrets accepted a reserved key")


def test_the_catastrophe_a_plain_load_save_round_trip_never_drops_the_fmk() -> None:
    """THE test. Every mutation in this codebase is load -> mutate -> save.
    If that cycle drops the FMK, every encrypted file dies silently."""
    with isolated_vault():
        record = _plant_fmk()

        secrets = store.load_secrets(TEST_PASSWORD)
        secrets["GAMMA"] = "gamma-value-333"
        store.save_secrets(TEST_PASSWORD, secrets)

        assert _fmk_of() == record, "the load -> mutate -> save cycle dropped the FMK"
        assert store.load_secrets(TEST_PASSWORD)["GAMMA"] == "gamma-value-333"


def test_reserved_keys_survive_a_removal_round_trip() -> None:
    with isolated_vault():
        record = _plant_fmk()
        secrets = store.load_secrets(TEST_PASSWORD)
        secrets.pop("BETA")
        store.save_secrets(TEST_PASSWORD, secrets)

        assert _fmk_of() == record
        assert "BETA" not in store.load_secrets(TEST_PASSWORD)


def test_disk_wins_the_merge_a_stale_caller_cannot_revive_an_old_fmk() -> None:
    """A caller holding a body read before a rotation must not write its stale
    reserved state back over the current one."""
    with isolated_vault():
        first = _plant_fmk()
        secrets = store.load_secrets(TEST_PASSWORD)

        # Something else rotates the reserved state behind this caller's back.
        body = store.load_vault_body(TEST_PASSWORD)
        body[store.FMK_KEY] = {"active": "NEWGEN00", "keys": {"NEWGEN00": "AAAA"}}
        store.save_vault_body(TEST_PASSWORD, body)

        # The stale caller saves its variables. Disk's reserved state must win.
        store.save_secrets(TEST_PASSWORD, secrets)
        assert _fmk_of()["active"] == "NEWGEN00"
        assert _fmk_of() != first


def test_save_vault_body_writes_reserved_state_verbatim() -> None:
    with isolated_vault():
        body = store.load_vault_body(TEST_PASSWORD)
        body["#custom"] = {"anything": 1}
        store.save_vault_body(TEST_PASSWORD, body)

        assert store.load_vault_body(TEST_PASSWORD)["#custom"] == {"anything": 1}
        assert "#custom" not in store.load_secrets(TEST_PASSWORD)


def test_split_body_and_merge_reserved_are_pure() -> None:
    variables, reserved = store._split_body({"A": "1", "#fmk": "k", "B": "2"})
    assert variables == {"A": "1", "B": "2"}
    assert reserved == {"#fmk": "k"}

    merged = store._merge_reserved({"#fmk": "k", "OLD": "gone"}, {"A": "1"})
    assert merged == {"A": "1", "#fmk": "k"}, "reserved carried, old variables not"

    try:
        store._merge_reserved({}, {"#fmk": "x"})
    except ValueError:
        pass
    else:
        raise AssertionError("_merge_reserved accepted a smuggled reserved key")


def test_render_env_text_refuses_a_reserved_key() -> None:
    """This function writes real values to a real file -- a reserved key
    reaching it would put key material on disk in plaintext."""
    try:
        store.render_env_text({"ALPHA": "a-value", "#fmk": "keymaterial"})
    except ValueError as exc:
        assert "#fmk" in str(exc)
    else:
        raise AssertionError("render_env_text wrote a reserved key")


# ---------------------------------------------------------------------------
# 2. get_or_create_fmk
#
# Failure mode: two mints produce two different keys, and whichever loses the
# race orphans every file encrypted under it.
# ---------------------------------------------------------------------------

def test_get_fmk_is_none_before_first_use_and_never_mints() -> None:
    with isolated_vault():
        assert store.get_fmk(TEST_PASSWORD) is None
        assert store.get_fmk(TEST_PASSWORD) is None, "get_fmk minted a key"
        assert store.FMK_KEY not in store.load_vault_body(TEST_PASSWORD)


def test_get_or_create_fmk_is_idempotent() -> None:
    with isolated_vault():
        first = store.get_or_create_fmk(TEST_PASSWORD)
        second = store.get_or_create_fmk(TEST_PASSWORD)
        assert first == second
        assert store.get_fmk(TEST_PASSWORD) == first


def test_minted_fmk_is_well_formed() -> None:
    with isolated_vault():
        record = _plant_fmk()
        assert set(record) == {"active", "keys", "sealed"}
        assert record["active"] in record["keys"]
        assert len(record["keys"]) == 1
        # The seal record starts empty and is what retire_file_keys trusts
        # instead of the agent-writable registry. It holds file IDENTITIES,
        # not counts, so every update is idempotent.
        assert record["sealed"] == {record["active"]: []}
        raw = base64.urlsafe_b64decode(record["keys"][record["active"]] + "==")
        assert len(raw) == crypto.FMK_BYTES == 32


def test_two_mints_produce_different_keys() -> None:
    """Sanity check on the generator itself -- if new_fmk were deterministic,
    every other test here would still pass."""
    a = bytes(crypto.new_fmk())
    b = bytes(crypto.new_fmk())
    assert a != b
    assert len(a) == 32
    assert crypto.new_fmk_id() != crypto.new_fmk_id()


def test_concurrent_mint_adopts_rather_than_clobbers() -> None:
    """Simulates the lost-mint race: another process writes an FMK between our
    read and our write. The loser must ADOPT the winner's key, never overwrite
    it -- overwriting orphans whatever the winner already encrypted."""
    with isolated_vault():
        rival = {"active": "RIVAL000", "keys": {"RIVAL000": "cml2YWwta2V5LWJ5dGVz"}}

        original_save = store.save_vault_body
        state = {"fired": False}

        def racing_save(password, body, expect_fingerprint=None):
            if not state["fired"] and store.FMK_KEY in body:
                state["fired"] = True
                # The rival lands first, invalidating our fingerprint, so our
                # own write below must fail the compare-and-swap.
                rival_body = store.load_vault_body(password)
                rival_body[store.FMK_KEY] = rival
                original_save(password, rival_body)
            return original_save(password, body, expect_fingerprint)

        store.save_vault_body = racing_save
        try:
            got = store.get_or_create_fmk(TEST_PASSWORD)
        finally:
            store.save_vault_body = original_save

        assert state["fired"], "the race never triggered -- test is not exercising it"
        assert got == rival, "the loser clobbered the winner's FMK instead of adopting it"
        assert store.get_fmk(TEST_PASSWORD) == rival


def test_save_secrets_on_a_brand_new_vault_does_not_error() -> None:
    """create_secrets_vault writes vault.salt then calls save_secrets with no
    vault.enc on disk yet. The merge must no-op rather than fail on the
    missing file."""
    with tempfile.TemporaryDirectory(prefix="llm_fmk_test_") as tmp:
        originals = _isolate_store_paths(Path(tmp).resolve())
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        try:
            store.create_secrets_vault(TEST_PASSWORD)
            assert store.load_secrets(TEST_PASSWORD) == {}
            store.save_secrets(TEST_PASSWORD, {"ALPHA": "a"})
            assert store.load_secrets(TEST_PASSWORD) == {"ALPHA": "a"}
        finally:
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


# ---------------------------------------------------------------------------
# 3. THE SURVIVAL MATRIX
#
# Failure mode: a credential operation re-serialises the body from a
# variables-only dict, silently deleting the FMK. Every encrypted file dies,
# and nothing errors until someone tries to open one.
# ---------------------------------------------------------------------------

def test_fmk_survives_change_password_v2() -> None:
    with isolated_vault():
        before = _plant_fmk()
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)

        after = store.get_fmk(NEW_PASSWORD)
        assert after == before, "change_password (v2) dropped or changed the FMK"
        assert store.load_secrets(NEW_PASSWORD) == BASE_SECRETS


def test_fmk_survives_change_password_v1() -> None:
    with isolated_vault(v2=False):
        before = _plant_fmk()
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)

        after = store.get_fmk(NEW_PASSWORD)
        assert after == before, "change_password (v1) dropped or changed the FMK"
        assert store.load_secrets(NEW_PASSWORD) == BASE_SECRETS


def test_fmk_survives_reissue_recovery_key() -> None:
    with isolated_vault(recovery=True):
        before = _plant_fmk()
        new_rk = store.reissue_recovery_key(TEST_PASSWORD)

        assert store.get_fmk(TEST_PASSWORD) == before, \
            "reissue_recovery_key dropped or changed the FMK"
        # And the brand-new recovery key still reaches it.
        plaintext, _dek, _hdr = crypto.open_v2_with_recovery(
            store.SECRETS_FILE.read_bytes(), new_rk)
        body = json.loads(store._pkcs7_unpad_strict(plaintext).decode("utf-8"))
        assert body[store.FMK_KEY] == before


def test_fmk_survives_recover_with_recovery_key() -> None:
    with isolated_vault(recovery=True) as (_tmp, rk):
        before = _plant_fmk()
        store.recover_with_recovery_key(rk, NEW_PASSWORD)

        assert store.get_fmk(NEW_PASSWORD) == before, \
            "recover_with_recovery_key dropped or changed the FMK"
        assert store.load_secrets(NEW_PASSWORD) == BASE_SECRETS


def test_fmk_survives_upgrade_to_v2() -> None:
    with isolated_vault(v2=False):
        before = _plant_fmk()
        store.upgrade_to_v2(TEST_PASSWORD, recovery=False)

        assert crypto.is_v2(store.SECRETS_FILE.read_bytes())
        assert store.get_fmk(TEST_PASSWORD) == before, \
            "upgrade_to_v2 dropped or changed the FMK"
        assert store.load_secrets(TEST_PASSWORD) == BASE_SECRETS


def test_fmk_survives_the_below_floor_scrypt_upgrade_on_save() -> None:
    """save_secrets silently rebuilds the password slot when the header's
    scrypt params are below SCRYPT_FLOOR. That branch takes a different route
    through the writer, so it needs its own check."""
    with isolated_vault():
        before = _plant_fmk()
        # The fixture's n=2**12 is already below SCRYPT_FLOOR (n=2**14), so an
        # ordinary save takes the upgrade branch. Confirm the premise first.
        data = store.SECRETS_FILE.read_bytes()
        header, _aad, _body = crypto.parse_envelope(data)
        pw_slot = next(s for s in header["slots"] if s["type"] == "password")
        assert int(pw_slot["kdf"]["n"]) < crypto.SCRYPT_FLOOR.n

        secrets = store.load_secrets(TEST_PASSWORD)
        secrets["DELTA"] = "delta-value-444"
        store.save_secrets(TEST_PASSWORD, secrets)

        assert store.get_fmk(TEST_PASSWORD) == before, \
            "the below-floor scrypt upgrade dropped the FMK"


def test_fmk_survives_a_full_credential_gauntlet() -> None:
    """Chain every operation a real vault goes through in its lifetime. Each
    step alone is covered above; this catches an interaction between them."""
    with isolated_vault(recovery=True) as (_tmp, rk):
        before = _plant_fmk()

        store.reissue_recovery_key(TEST_PASSWORD)
        secrets = store.load_secrets(TEST_PASSWORD)
        secrets["GAMMA"] = "gamma-value-333"
        store.save_secrets(TEST_PASSWORD, secrets)
        new_rk = store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert new_rk is not None, "a vault with a recovery slot must reissue one"
        store.recover_with_recovery_key(new_rk, TEST_PASSWORD)

        assert store.get_fmk(TEST_PASSWORD) == before, \
            "the FMK did not survive the full credential gauntlet"
        assert store.load_secrets(TEST_PASSWORD)["GAMMA"] == "gamma-value-333"


def test_change_password_rotates_the_dek_but_not_the_fmk() -> None:
    """The premise the whole design rests on: the DEK is deliberately rotated
    (so an old password cannot open future bodies) while the FMK is
    deliberately not (so committed ciphertext keeps working)."""
    with isolated_vault():
        before = _plant_fmk()
        _pt, old_dek, _hdr = crypto.open_v2_with_password(
            store.SECRETS_FILE.read_bytes(), TEST_PASSWORD)

        store.change_password(TEST_PASSWORD, NEW_PASSWORD)

        _pt2, new_dek, _hdr2 = crypto.open_v2_with_password(
            store.SECRETS_FILE.read_bytes(), NEW_PASSWORD)
        assert bytes(new_dek) != bytes(old_dek), "the DEK was not rotated"
        assert store.get_fmk(NEW_PASSWORD) == before, "the FMK was rotated"


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
