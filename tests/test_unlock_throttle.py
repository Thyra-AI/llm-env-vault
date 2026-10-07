"""
The failed-unlock throttle: a handful of free attempts, then a doubling
cool-down during which the credential is not even tried.

Time is faked by patching time.time, so no test actually waits.
"""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import TEST_PASSWORD, SECRETS, workspace  # noqa: E402
from vault_lib import crypto, store  # noqa: E402


class _Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(time, "time", c)
    return c


def _fail(n=1):
    for _ in range(n):
        with pytest.raises(crypto.WrongPassword) as exc:
            store.load_secrets("not-the-password")
        assert not isinstance(exc.value, crypto.TooManyAttempts)


def test_free_attempts_then_lockout(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        with pytest.raises(crypto.TooManyAttempts) as exc:
            store.load_secrets(TEST_PASSWORD)
        assert exc.value.retry_after == store._BASE_LOCKOUT_SECONDS
        assert "Try again in 30 seconds" in str(exc.value)


def test_correct_password_refused_during_lockout_then_accepted(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        clock.now += store._BASE_LOCKOUT_SECONDS - 1
        with pytest.raises(crypto.TooManyAttempts):
            store.load_secrets(TEST_PASSWORD)
        clock.now += 1
        assert store.load_secrets(TEST_PASSWORD) == SECRETS
        # Success wipes the record entirely.
        assert not store._attempts_file().exists()


def test_lockout_doubles_and_caps(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        expected = store._BASE_LOCKOUT_SECONDS
        for _ in range(8):
            clock.now += expected
            _fail()
            expected = min(expected * 2, store._MAX_LOCKOUT_SECONDS)
            with pytest.raises(crypto.TooManyAttempts) as exc:
                store.load_secrets(TEST_PASSWORD)
            assert exc.value.retry_after == expected
        assert expected == store._MAX_LOCKOUT_SECONDS


def test_attempts_during_lockout_are_not_counted(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        for _ in range(20):
            with pytest.raises(crypto.TooManyAttempts):
                store.load_secrets("not-the-password")
        assert store._read_attempts()["password"]["failures"] == store._FREE_ATTEMPTS


def test_failures_forgotten_after_a_quiet_day(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS - 1)
        clock.now += store._FORGET_FAILURES_SECONDS + 1
        _fail()  # would have been the locking failure; counts as the first instead
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_clock_moved_backwards_does_not_lock_forever(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        clock.now -= 7 * 24 * 3600
        with pytest.raises(crypto.TooManyAttempts) as exc:
            store.load_secrets(TEST_PASSWORD)
        assert exc.value.retry_after == store._BASE_LOCKOUT_SECONDS
        clock.now += store._BASE_LOCKOUT_SECONDS
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_change_password_is_throttled(clock):
    with workspace(register=False):
        for _ in range(store._FREE_ATTEMPTS):
            with pytest.raises(crypto.WrongPassword):
                store.change_password("not-the-password", "new-password-123")
        with pytest.raises(crypto.TooManyAttempts):
            store.change_password(TEST_PASSWORD, "new-password-123")


def test_recovery_budget_is_separate(clock):
    with workspace(register=False):
        paper_key = store.reissue_recovery_key(TEST_PASSWORD)
        _fail(store._FREE_ATTEMPTS)
        # Locked out of the password, the paper key still works at once.
        store.recover_with_recovery_key(paper_key, "new-password-123")
        assert store.load_secrets("new-password-123") == SECRETS


def test_wrong_recovery_keys_are_throttled(clock):
    with workspace(register=False):
        store.reissue_recovery_key(TEST_PASSWORD)
        wrong = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
        for _ in range(store._FREE_ATTEMPTS):
            with pytest.raises(crypto.WrongRecoveryKey):
                store.recover_with_recovery_key(wrong, "new-password-123")
        with pytest.raises(crypto.TooManyAttempts):
            store.recover_with_recovery_key(wrong, "new-password-123")
        # ...and the password budget is untouched.
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_junk_attempts_file_reads_as_empty(clock):
    with workspace(register=False):
        store._attempts_file().write_text(
            json.dumps({"password": {"failures": "lots", "last": None}}),
            encoding="utf-8")
        assert store.load_secrets(TEST_PASSWORD) == SECRETS
        store._attempts_file().write_text("not json", encoding="utf-8")
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_concurrent_attempts_count_before_the_kdf_finishes(clock):
    with workspace(register=False):
        # Attempts begun but not yet settled -- as if all were mid-scrypt at
        # once -- already use up the budget, so one more is refused.
        for _ in range(store._FREE_ATTEMPTS):
            store._begin_unlock_attempt("password")
        with pytest.raises(crypto.TooManyAttempts):
            store._begin_unlock_attempt("password")


def test_non_credential_errors_are_not_counted(clock):
    with workspace(register=False):
        for _ in range(store._FREE_ATTEMPTS + 3):
            with pytest.raises(OSError):
                with store._unlock_attempt():
                    raise OSError("disk went away")
        assert not store._attempts_file().exists()
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_refused_attempts_do_not_rewrite_the_file(clock):
    with workspace(register=False):
        _fail(store._FREE_ATTEMPTS)
        stamp = store._attempts_file().stat().st_mtime_ns
        for _ in range(3):
            with pytest.raises(crypto.TooManyAttempts):
                store.load_secrets(TEST_PASSWORD)
        assert store._attempts_file().stat().st_mtime_ns == stamp


def test_unknown_outcome_is_rejected(clock):
    with workspace(register=False):
        with pytest.raises(ValueError):
            store._finish_unlock_attempt("password", "okay")
