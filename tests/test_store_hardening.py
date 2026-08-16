"""
Regression suite for the security-hardening additions to vault_lib/store.py.

Covers two findings from the adversarial code review:

  B4 - validate_var_name had no upper-bound on name length.  A syntactically
       valid multi-thousand-character name gets interpolated into fixed-size Tk
       labels, pushing the Allow/Deny consent buttons off the non-resizable
       window.  That is an attack on the consent mechanism, not a cosmetic
       issue.  MAX_VAR_NAME_LEN = 128 is now enforced.

  C2 - There was no way to change the master password; a user who suspected
       compromise had no supported path except deleting the vault and
       re-migrating everything.  change_password() is now implemented with a
       rollback snapshot and read-back verification so a failed write can never
       leave the vault in an unopenable state.

Every test runs against an isolated, throwaway vault created under a temp
directory -- store.SALT_FILE / SECRETS_FILE / INDEX_FILE / ENV_FILE are
redirected there for the duration of each test and restored afterward, so
nothing here ever reads or writes this repo's real vault.enc / vault.salt /
vault_index.json / llm.env.

Runs under pytest (`pytest tests/test_store_hardening.py -q`) or standalone
(`python tests/test_store_hardening.py`), matching test_trust.py's convention.
"""
import contextlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib import crypto, store  # noqa: E402

TEST_PASSWORD = "regression-test-password-123"
NEW_PASSWORD = "brand-new-password-456"
BASE_SECRETS = {"DOCKER_TEST_TOKEN": "tok-abc-123", "OTHER_SECRET": "other-xyz-789"}


# ---------------------------------------------------------------------------
# Isolation helpers (replicated minimally from test_trust.py; tests/ has no
# __init__.py so cross-file import would require importlib gymnastics)
# ---------------------------------------------------------------------------

def _isolate_store_paths(tmp_dir: Path) -> dict:
    originals = {
        "SALT_FILE": store.SALT_FILE,
        "SECRETS_FILE": store.SECRETS_FILE,
        "INDEX_FILE": store.INDEX_FILE,
        "ENV_FILE": store.ENV_FILE,
    }
    store.SALT_FILE = tmp_dir / "vault.salt"
    store.SECRETS_FILE = tmp_dir / "vault.enc"
    store.INDEX_FILE = tmp_dir / "vault_index.json"
    store.ENV_FILE = tmp_dir / "llm.env"
    return originals


def _restore_store_paths(originals: dict) -> None:
    for name, value in originals.items():
        setattr(store, name, value)


@contextlib.contextmanager
def isolated_vault(secrets=None):
    """Redirects the vault's on-disk files into a fresh temp dir, creates a
    real (small) vault there with the given secrets (BASE_SECRETS by default),
    so tests never leak state into each other or into the real repo vault."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_store_test_") as tmp:
        # .resolve() matters: on Windows, mkdtemp hands back the 8.3 short form
        # when the username is over 8 characters (a CI runner's
        # C:\Users\RUNNER~1\... vs C:\Users\runneradmin\...).
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            store.create_secrets_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, secrets)
            yield tmp_path
        finally:
            _restore_store_paths(originals)


# ---------------------------------------------------------------------------
# B4 -- Variable-name length cap
#
# Without MAX_VAR_NAME_LEN, a syntactically valid but thousands-of-characters-
# long name gets interpolated into fixed-size Tk labels.  _label wraps at
# 480 px and _center never clamps to screen height, so the Allow/Deny buttons
# get pushed off the non-resizable window -- an attack on the consent
# mechanism, not a cosmetic issue.  The 128-character ceiling matches
# Windows environment-block limits and nothing legitimate needs more.
# ---------------------------------------------------------------------------

def test_var_name_128_chars_valid() -> None:
    """A name at exactly the boundary must be accepted."""
    name = "A" * 128
    result = store.validate_var_name(name)
    assert result == name, (
        "REGRESSION (B4): a 128-char name (the exact boundary) was rejected -- "
        "MAX_VAR_NAME_LEN should be an inclusive upper bound"
    )


def test_var_name_129_chars_raises_value_error() -> None:
    """A name one character over the limit must raise ValueError."""
    name = "A" * 129
    try:
        store.validate_var_name(name)
    except ValueError:
        return  # correct
    raise AssertionError(
        "REGRESSION (B4): a 129-char name was accepted without error -- "
        "MAX_VAR_NAME_LEN = 128 is not being enforced"
    )


def test_existing_pattern_rules_still_apply() -> None:
    """Adding the length check must not break pre-existing pattern rejections."""
    bad_names = [
        "1starts_with_digit",
        "has space",
        "has-hyphen",
        "has.dot",
        "",                  # empty string
        "has\nnewline",
    ]
    for bad in bad_names:
        try:
            store.validate_var_name(bad)
        except ValueError:
            continue  # correct: pattern rule still fires
        raise AssertionError(
            f"REGRESSION (B4): existing pattern rule no longer rejects {bad!r} -- "
            "the length-check addition broke the pattern check"
        )


# ---------------------------------------------------------------------------
# C2 -- change_password
#
# There was no supported way to change the master password; a user who
# suspected compromise had no path except deleting the vault and
# re-migrating every secret from scratch.  change_password() implements the
# re-encryption on the existing vetted crypto path, with a rollback snapshot
# so a failure during the write can never leave the vault in an unopenable
# state.
# ---------------------------------------------------------------------------

def test_change_password_round_trip() -> None:
    """Secrets loaded under the new password must equal what was saved."""
    with isolated_vault(secrets=dict(BASE_SECRETS)):
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        loaded = store.load_secrets(NEW_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION (C2): secrets did not survive a password change -- "
            f"got {loaded!r}, expected {BASE_SECRETS!r}"
        )


def test_change_password_old_password_no_longer_works() -> None:
    """After change_password the old password must raise WrongPassword."""
    with isolated_vault(secrets=dict(BASE_SECRETS)):
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        try:
            store.load_secrets(TEST_PASSWORD)
        except crypto.WrongPassword:
            return  # correct
        raise AssertionError(
            "REGRESSION (C2): the old password still opened the vault after "
            "change_password -- the re-encryption did not take effect"
        )


def test_change_password_wrong_old_password_raises_wrong_password() -> None:
    """A bad old_password must raise crypto.WrongPassword."""
    with isolated_vault(secrets=dict(BASE_SECRETS)):
        try:
            store.change_password("definitely-wrong-password", NEW_PASSWORD)
        except crypto.WrongPassword:
            return  # correct
        raise AssertionError(
            "REGRESSION (C2): a wrong old_password did not raise WrongPassword -- "
            "change_password must propagate the exception from load_secrets"
        )


def test_change_password_wrong_old_password_leaves_vault_intact() -> None:
    """A bad old_password must leave vault.enc byte-identical -- no partial write."""
    with isolated_vault(secrets=dict(BASE_SECRETS)):
        before = store.SECRETS_FILE.read_bytes()
        try:
            store.change_password("definitely-wrong-password", NEW_PASSWORD)
        except crypto.WrongPassword:
            pass  # expected
        after = store.SECRETS_FILE.read_bytes()
        assert before == after, (
            "REGRESSION (C2): vault.enc was modified despite a wrong old_password -- "
            "change_password must not write anything when the old password is wrong"
        )


def test_change_password_empty_vault() -> None:
    """change_password on a vault with zero secrets must succeed."""
    with isolated_vault(secrets={}):
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        loaded = store.load_secrets(NEW_PASSWORD)
        assert loaded == {}, (
            f"REGRESSION (C2): change_password failed on an empty-secrets vault -- "
            f"got {loaded!r} instead of {{}}"
        )


def test_change_password_preserves_padding_behaviour() -> None:
    """After a password change, padding must still coarsen ciphertext length.
    Two secrets dicts of noticeably different byte size should be able to land
    in the same padded-length bucket -- proves the re-encrypted vault is still
    going through _pkcs7_pad, not writing a bare unpadded payload."""
    with isolated_vault(secrets={}):
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        # Write a short dict under the new password and measure.
        store.save_secrets(NEW_PASSWORD, {"A": "x"})
        short_len = store.SECRETS_FILE.stat().st_size
        # Write a longer dict (9 bytes more of real value) under the same password.
        store.save_secrets(NEW_PASSWORD, {"A": "x" * 10})
        long_len = store.SECRETS_FILE.stat().st_size
        assert short_len == long_len, (
            f"REGRESSION (C2): a 9-byte difference in real value length changed "
            f"the ciphertext length ({short_len} vs {long_len}) after change_password "
            f"-- padding is no longer coarsening the output"
        )


def test_change_password_no_vault_raises() -> None:
    """change_password on a missing vault must raise FileNotFoundError."""
    with tempfile.TemporaryDirectory(prefix="llm_vault_store_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_store_paths(tmp_path)
        try:
            # No vault created -- SALT_FILE and SECRETS_FILE do not exist.
            store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        except FileNotFoundError:
            pass  # correct
        except Exception as exc:
            raise AssertionError(
                f"REGRESSION (C2): change_password on a missing vault raised "
                f"{type(exc).__name__} instead of FileNotFoundError"
            ) from exc
        else:
            raise AssertionError(
                "REGRESSION (C2): change_password on a missing vault raised nothing -- "
                "it must raise FileNotFoundError when no vault exists"
            )
        finally:
            _restore_store_paths(originals)


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
    else:
        print("All tests passed.")
