"""
Adversarial test suite for the v2 LEVAULT envelope format (vault_lib/crypto.py).

Lane 7 — written independently of the implementer.  The threat model is an
attacker with filesystem write access to vault.enc who tries to weaken,
confuse, or downgrade the vault, or cause a crash that is worse than a clean
error.

Conventions (match test_crypto_v2.py exactly):
  - Plain ``def test_x() -> None:``; no pytest fixtures; no conftest.
  - SCRYPT_DEFAULT is monkeypatched to n=2**12 inside try/finally for anything
    that derives a key.
  - 75-dash section banners with a prose paragraph explaining the attack.
  - Standalone runner block at the bottom sweeping globals() for test_* and
    printing ``Results: N/N passed``.

Findings are marked with ``# FINDING`` comments and summarised in the report.
A "FINDING" test still passes (the vault did not open), but the exception class
that escaped is incorrect: the code surfaces a raw KeyError / ValueError instead
of VaultCorrupted.  That is a low-severity robustness flaw, not a full break.

Runs under:
  ``python tests/test_vault_format.py``   (standalone)
  ``pytest tests/test_vault_format.py``   (pytest)
"""

import base64
import binascii
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib.crypto import (  # noqa: E402
    FORMAT_VERSION,
    MalformedRecoveryKey,
    NoRecoverySlot,
    RECOVERY_KEY_BYTES,
    SCRYPT_DEFAULT,
    VAULT_MAGIC,
    ScryptParams,
    VaultCorrupted,
    VaultTampered,
    WrongPassword,
    WrongRecoveryKey,
    build_v2_vault,
    decrypt as v1_decrypt,
    format_recovery_key,
    new_dek,
    new_recovery_key,
    open_v2_with_password,
    open_v2_with_recovery,
    parse_envelope,
    parse_recovery_key,
    slot_aad,
    validate_scrypt_params,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAST_PARAMS = ScryptParams(n=2 ** 12, r=8, p=1)
_PASSWORD = "adversarial-test-password-lane7"
_PLAINTEXT = b"adversarial-plaintext-32b" + b"\x07" * 7  # 32 bytes

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "v1_vault"

# Exception types that represent "clean" API failures
_CLEAN = (VaultCorrupted, VaultTampered, WrongPassword, WrongRecoveryKey,
          NoRecoverySlot, MalformedRecoveryKey)

# Exception types that are raw internal leaks (always findings if they escape)
_RAW = (KeyError, IndexError, binascii.Error, UnicodeDecodeError,
        struct.error, TypeError)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vault(with_recovery: bool = False) -> tuple:
    """Build a valid v2 envelope using fast scrypt.

    Returns ``(envelope, dek, vault_id_bytes, rk_raw_or_None)``.
    """
    old = crypto.SCRYPT_DEFAULT
    crypto.SCRYPT_DEFAULT = _FAST_PARAMS
    try:
        rk_raw = bytes(new_recovery_key()) if with_recovery else None
        envelope, dek, vault_id = build_v2_vault(
            _PASSWORD, _PLAINTEXT, recovery_raw=rk_raw, params=_FAST_PARAMS,
        )
        return envelope, dek, vault_id, rk_raw
    finally:
        crypto.SCRYPT_DEFAULT = old


def _parse_header(envelope: bytes) -> tuple:
    """Return ``(header_dict, hdr_len)``."""
    hdr_len = struct.unpack(">I", envelope[9:13])[0]
    return json.loads(envelope[13:13 + hdr_len]), hdr_len


def _rebuild_with_header(envelope: bytes, new_header: dict) -> bytes:
    """Rebuild the envelope prefix with a mutated header; keep body unchanged.

    Note: the body AAD will differ from the original (the header bytes are
    the AAD), so body decryption will fail even if the slot opens cleanly.
    """
    _, old_hdr_len = _parse_header(envelope)
    body = envelope[13 + old_hdr_len:]
    new_hdr_bytes = json.dumps(
        new_header, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return (
        VAULT_MAGIC
        + bytes([FORMAT_VERSION])
        + struct.pack(">I", len(new_hdr_bytes))
        + new_hdr_bytes
        + body
    )


def _set_hdr_len(envelope: bytes, new_len: int) -> bytes:
    """Overwrite only the 4-byte hdr_len field; leave everything else as-is."""
    return envelope[:9] + struct.pack(">I", new_len) + envelope[13:]


def _assert_vault_did_not_open(call_result_fn) -> None:
    """Assert that calling fn() did NOT return plaintext successfully.

    If it raises ANY exception, the vault did not open — that is the security
    guarantee.  If it returns without exception, the vault opened — fail hard.
    """
    try:
        call_result_fn()
        raise AssertionError("Vault opened without authentication — security failure!")
    except AssertionError:
        raise
    except Exception:
        pass  # any exception = vault did not open = OK


# ===========================================================================
# Cross-vault slot transplant
# ===========================================================================
# An attacker builds two vaults (A and B) with the same password, then moves
# the wrapped DEK from vault A into vault B.  The slot AAD binds each wrapped
# DEK to a specific vault_id and slot type, so the transplant must fail.  We
# also test the sophisticated variant where the attacker copies vault_id_A into
# vault_B's header — this must still fail because the body AAD covers the full
# header (including vault_id), so changing the vault_id changes the body's AAD
# and body decryption fails even if the slot unwraps cleanly.

def test_cross_vault_simple_transplant_fails() -> None:
    """Moving a password slot from vault A into vault B must raise WrongPassword.

    The slot_aad function embeds vault_id, so the wrapped DEK from vault A
    was sealed under slot_aad(vault_id_A, 'password'), which differs from
    slot_aad(vault_id_B, 'password').  Unwrapping must fail.
    """
    env_A, _, _, _ = _make_vault()
    env_B, _, _, _ = _make_vault()
    hdr_A, _ = _parse_header(env_A)
    hdr_B, _ = _parse_header(env_B)
    # Transplant vault A's password slot into vault B's header (keep B's vault_id)
    hdr_B["slots"][0] = hdr_A["slots"][0]
    bad_B = _rebuild_with_header(env_B, hdr_B)
    # Must not open with vault B's password
    try:
        open_v2_with_password(bad_B, _PASSWORD)
        assert False, "SECURITY FAILURE: cross-vault transplant opened the vault"
    except WrongPassword:
        pass  # correct — slot AAD binds the wrapped DEK to the originating vault
    except (VaultCorrupted, VaultTampered):
        pass  # also acceptable — body decryption also fails


def test_cross_vault_transplant_with_vault_id_copy_fails() -> None:
    """Even copying vault_id_A into vault_B's header must not open vault B.

    With vault_id_A in the header, the slot from vault A opens correctly —
    the attacker recovers DEK_A.  But the body of vault B was sealed with
    vault_B's header bytes as AAD.  Swapping vault_id changes those bytes,
    so body decryption fails with VaultTampered regardless.
    """
    env_A, _, _, _ = _make_vault()
    env_B, _, _, _ = _make_vault()
    hdr_A, _ = _parse_header(env_A)
    hdr_B, _ = _parse_header(env_B)
    # Copy both the slot AND the vault_id from vault A
    hdr_B["slots"][0] = hdr_A["slots"][0]
    hdr_B["vault_id"] = hdr_A["vault_id"]
    bad_B = _rebuild_with_header(env_B, hdr_B)
    try:
        open_v2_with_password(bad_B, _PASSWORD)
        assert False, "SECURITY FAILURE: transplant with vault_id copy opened the vault"
    except (WrongPassword, VaultTampered, VaultCorrupted):
        pass  # the body AAD changed — body decryption must fail


def test_cross_vault_recovery_slot_transplant_fails() -> None:
    """A recovery slot from vault A transplanted into vault B must not open.

    The recovery slot AAD also binds vault_id, so the transplanted wrapped
    DEK cannot be authenticated under vault B's vault_id.
    """
    rk = bytes(new_recovery_key())
    env_A, _, _, _ = _make_vault()  # no recovery slot
    env_B, _, _, rk_B = _make_vault(with_recovery=True)
    hdr_A, _ = _parse_header(env_A)
    hdr_B, _ = _parse_header(env_B)
    # Find recovery slot from vault B, transplant it into vault A
    rk_slot_B = next(s for s in hdr_B["slots"] if s["type"] == "recovery")
    # Rebuild vault A with this transplanted recovery slot
    hdr_A["slots"].append(rk_slot_B)
    bad_A = _rebuild_with_header(env_A, hdr_A)
    rk_str = format_recovery_key(rk_B)
    try:
        open_v2_with_recovery(bad_A, rk_str)
        assert False, "SECURITY FAILURE: cross-vault recovery transplant succeeded"
    except (WrongRecoveryKey, VaultTampered, VaultCorrupted):
        pass  # slot AAD binds to vault_id — vault B's slot cannot open vault A


# ===========================================================================
# Slot-type confusion
# ===========================================================================
# The slot type is embedded in the slot AAD, so a wrapped DEK cannot be
# moved between slot types without failing authentication.  We also test
# edge cases: empty slot lists, unknown slot types, missing slot structures,
# and duplicate slots.  Every case must fail with a clean, named exception.
# The recovery-slot-relabeled-as-password case currently surfaces a raw
# KeyError (finding) because the recovery KDF has no n/r/p fields.

def test_password_slot_relabeled_as_recovery_raises_no_recovery_slot() -> None:
    """Changing the password slot's type to 'recovery' must deny all access.

    The only slot now claims to be a recovery slot, so open_v2_with_password
    must report no password slot.  Attempting recovery with any key must
    fail authentication because the DEK was wrapped under the password AAD.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["type"] = "recovery"
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted (no password slot)"
    except (VaultCorrupted,):
        pass  # correct — no password slot found

    # Recovery open should fail (DEK was wrapped under password AAD, not recovery)
    rk_str = format_recovery_key(bytes(new_recovery_key()))
    try:
        open_v2_with_recovery(bad, rk_str)
        assert False, "Expected WrongRecoveryKey or NoRecoverySlot"
    except (WrongRecoveryKey, VaultCorrupted, VaultTampered, MalformedRecoveryKey,
            NoRecoverySlot):
        pass


def test_recovery_slot_relabeled_as_password_raises_clean_exception() -> None:
    """A recovery slot (no n/r/p KDF) relabeled as 'password' must not open.

    FINDING: the code raises a raw KeyError because it accesses kdf['n']
    without a try/except, and the recovery KDF has no 'n' field.  The vault
    does not open, but the exception type should be VaultCorrupted.
    """
    env, _, _, rk_raw = _make_vault(with_recovery=True)
    hdr, _ = _parse_header(env)
    # Remove the real password slot; keep only the recovery slot, relabeled
    hdr["slots"] = [s for s in hdr["slots"] if s["type"] == "recovery"]
    hdr["slots"][0]["type"] = "password"
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted — vault must not open"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError escapes — kdf['n'] missing from recovery KDF")


def test_empty_slots_list_raises_vault_corrupted() -> None:
    """An empty 'slots' list must raise VaultCorrupted, not open the vault."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"] = []
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_missing_slots_key_raises_vault_corrupted() -> None:
    """Missing 'slots' key in header must raise VaultCorrupted."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_unknown_slot_type_only_raises_vault_corrupted() -> None:
    """A single slot of unknown type must raise VaultCorrupted, not open."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["type"] = "hardware-key"
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_duplicate_password_slot_does_not_open_vault() -> None:
    """Duplicating the password slot should not open the vault (body AAD changes)."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    import copy
    hdr["slots"].append(copy.deepcopy(hdr["slots"][0]))
    bad = _rebuild_with_header(env, hdr)
    # The header changed, so body AAD is different → body decryption fails
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultTampered (body AAD changed)"
    except (VaultTampered, WrongPassword, VaultCorrupted):
        pass


# ===========================================================================
# Header field abuse
# ===========================================================================
# The hdr_len field and the header JSON are both attacker-controlled bytes.
# Discrepancies between hdr_len and the actual header length, non-UTF-8 bytes
# in the header region, JSON structural tricks (duplicate keys, extreme nesting),
# and missing top-level fields all probe the parser's robustness.  Every case
# must raise a clean exception from the VaultCorrupted family.  One case below
# (missing vault_id) currently surfaces a raw KeyError — see FINDING comment.

def test_hdr_len_one_too_large_never_opens() -> None:
    """hdr_len = actual + 1 must not yield a usable vault.

    Asserting that parse_envelope RAISES is not quite right, and was flaky at
    about 1 run in 60: the extra byte is borrowed from the body, whose first
    bytes are a random nonce, and json.loads accepts a trailing whitespace
    byte -- 4 of the 256 possible values. The parser is deliberately
    structural, so the guarantee that actually holds is end-to-end: the header
    slice is the AAD, so moving the boundary means the body no longer
    authenticates. Assert that instead of the incidental parse failure.
    """
    env, _, _, _ = _make_vault()
    _, actual_hdr_len = _parse_header(env)
    bad = _set_hdr_len(env, actual_hdr_len + 1)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected the vault not to open"
    except VaultCorrupted:
        pass


def test_hdr_len_one_too_small_raises_vault_corrupted() -> None:
    """hdr_len = actual - 1 must raise VaultCorrupted (truncated JSON)."""
    env, _, _, _ = _make_vault()
    _, actual_hdr_len = _parse_header(env)
    bad = _set_hdr_len(env, actual_hdr_len - 1)
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_hdr_len_zero_raises_vault_corrupted() -> None:
    """hdr_len = 0 must raise VaultCorrupted (empty JSON is invalid)."""
    env, _, _, _ = _make_vault()
    bad = _set_hdr_len(env, 0)
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_hdr_len_past_eof_raises_vault_corrupted() -> None:
    """hdr_len pointing past EOF must raise VaultCorrupted (truncation check)."""
    env, _, _, _ = _make_vault()
    # Set hdr_len to a value that would extend well past the end of the file
    bad = _set_hdr_len(env, len(env) * 2)
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_hdr_len_at_cap_raises_vault_corrupted() -> None:
    """hdr_len = 65537 (exceeds 65536 cap) must raise VaultCorrupted."""
    env, _, _, _ = _make_vault()
    bad = _set_hdr_len(env, 65537)
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_non_utf8_header_bytes_raises_vault_corrupted() -> None:
    """Non-UTF-8 bytes injected into the header region must raise VaultCorrupted."""
    env, _, _, _ = _make_vault()
    _, hdr_len = _parse_header(env)
    # Overwrite two bytes inside the header with invalid UTF-8 (0xFF 0xFE)
    offset = 13 + 2  # past magic+version+hdr_len, a few bytes into the header
    bad = env[:offset] + b"\xff\xfe" + env[offset + 2:]
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_duplicate_json_slots_key_raises_vault_corrupted() -> None:
    """Duplicate 'slots' key in JSON (empty override wins) must deny access.

    Python's json.loads uses last-wins for duplicate keys, so a crafted header
    with 'slots': [...valid...], 'slots': [] resolves to an empty list and
    must raise VaultCorrupted (no password slot found).
    """
    env, _, _, _ = _make_vault()
    _, hdr_len = _parse_header(env)
    hdr_bytes = env[13:13 + hdr_len]
    # Append ', "slots": []' before the closing brace — last-wins semantics
    dup_hdr_bytes = hdr_bytes[:-1] + b', "slots": []}'
    bad = (
        VAULT_MAGIC
        + bytes([FORMAT_VERSION])
        + struct.pack(">I", len(dup_hdr_bytes))
        + dup_hdr_bytes
        + env[13 + hdr_len:]
    )
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted (no password slot)"
    except (VaultCorrupted, VaultTampered, WrongPassword):
        pass  # vault did not open — correct


def test_missing_vault_id_field_raises_clean_exception() -> None:
    """Missing 'vault_id' in header must raise VaultCorrupted, not KeyError.

    FINDING: the code does ``base64.urlsafe_b64decode(header['vault_id'] + '==')``
    without a try/except, so a missing vault_id field raises a raw KeyError
    instead of VaultCorrupted.  The vault does not open in either case.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["vault_id"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted — vault must not open"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError escapes — header['vault_id'] not wrapped")


def test_deeply_nested_json_within_cap_does_not_hang() -> None:
    """Deeply nested JSON within the 65536-byte header cap must not hang or crash.

    Verifies that parse_envelope finishes quickly (Python's json module handles
    this without hitting Python's recursion limit) and raises VaultCorrupted
    (not VaultTampered or success) because the header lacks required fields.
    """
    # Craft a deeply nested but valid JSON that fits within 65536 bytes
    # Each level uses 5 bytes '{"a":' and 1 byte '}'; 1000 levels ≈ 7000 bytes
    depth = 1000
    nested_json = ('{"a":' * depth + '"v"' + '}' * depth).encode("utf-8")
    assert len(nested_json) <= 65536, "Test setup error: nested JSON too large"
    # Pad to have a minimal valid body (nonce + tag)
    body = b"\x00" * (12 + 16)
    bad = (
        VAULT_MAGIC
        + bytes([FORMAT_VERSION])
        + struct.pack(">I", len(nested_json))
        + nested_json
        + body
    )
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except _CLEAN:
        pass  # clean exception — didn't hang, didn't crash


# ===========================================================================
# KDF descriptor abuse
# ===========================================================================
# The KDF descriptor inside each slot is attacker-controlled JSON.  Missing
# fields, wrong types, and extreme values must all be caught before any key
# derivation runs.  The DoS gate (validate_scrypt_params) must run before
# derive_password_kek for every code path.  Several cases below surface raw
# exceptions (KeyError, ValueError) instead of VaultCorrupted — these are
# findings: the field-access code is not wrapped in a general try/except.

def test_missing_kdf_field_n_raises_clean_exception() -> None:
    """Missing kdf['n'] must raise VaultCorrupted, not a raw KeyError.

    FINDING: ``int(kdf['n'])`` raises KeyError when 'n' is absent from the
    password slot's KDF descriptor.  The vault does not open, but the
    exception type leaks an internal detail.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["kdf"]["n"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing kdf['n']")


def test_missing_kdf_field_salt_raises_clean_exception() -> None:
    """Missing kdf['salt'] must raise VaultCorrupted, not a raw KeyError.

    FINDING: same class of issue as missing 'n' — the field access is unguarded.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["kdf"]["salt"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing kdf['salt']")


def test_missing_kdf_entirely_raises_clean_exception() -> None:
    """Missing 'kdf' key in the password slot must raise VaultCorrupted.

    FINDING: ``pw_slot['kdf']`` raises KeyError when the field is absent.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["kdf"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing slot['kdf']")


def test_missing_slot_nonce_raises_clean_exception() -> None:
    """Missing 'nonce' in the password slot must raise VaultCorrupted.

    FINDING: ``pw_slot['nonce']`` raises KeyError when absent.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["nonce"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing slot['nonce']")


def test_missing_wrapped_dek_raises_clean_exception() -> None:
    """Missing 'wrapped_dek' in the password slot must raise VaultCorrupted.

    FINDING: ``pw_slot['wrapped_dek']`` raises KeyError when absent.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["wrapped_dek"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing slot['wrapped_dek']")


def test_non_numeric_kdf_n_raises_clean_exception() -> None:
    """kdf['n'] = 'large' (non-numeric string) must raise VaultCorrupted.

    FINDING: ``int('large')`` raises a raw ValueError instead of VaultCorrupted.
    The vault does not open — no scrypt allocation occurs — but the exception
    type exposes an internal detail.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["kdf"]["n"] = "large"
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except ValueError as exc:
        assert False, (
            "REGRESSION: a raw ValueError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw ValueError from int('large')")


def test_kdf_n_as_float_json_value() -> None:
    """kdf['n'] as JSON float (e.g. 1e10) must be caught by validate_scrypt_params.

    JSON floats like 1e10 are represented as Python floats; int(1e10) succeeds
    and produces a huge integer.  validate_scrypt_params must reject it before
    any scrypt allocation.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    # 1e10 as a float in JSON; int(1e10) = 10000000000, which is way above 2**20
    hdr["slots"][0]["kdf"]["n"] = 1e10
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted (n too large)"
    except (VaultCorrupted, WrongPassword):
        pass  # validate_scrypt_params caught it before allocation


def test_validate_scrypt_params_boundary_n_min_accepted() -> None:
    """n=2**10 (minimum boundary) must be accepted by validate_scrypt_params."""
    # Should not raise — 2**10 is the documented minimum
    validate_scrypt_params(2 ** 10, 8, 1)


def test_validate_scrypt_params_boundary_n_below_min_rejected() -> None:
    """n=2**9 (one step below minimum) must raise VaultCorrupted."""
    try:
        validate_scrypt_params(2 ** 9, 8, 1)
        assert False, "Expected VaultCorrupted for n=2**9"
    except VaultCorrupted:
        pass


def test_validate_scrypt_params_boundary_256mib_accepted() -> None:
    """n=2**18, r=8, p=1 uses exactly 256 MiB — at the cap boundary, accepted.

    The check is ``mem > _MAX_SCRYPT_MEM`` (strict greater-than), so exactly
    256 MiB is permitted.  This is documented boundary behaviour, not a bug.
    An attacker who embeds these params triggers a real 256 MiB allocation on
    unlock — acceptable under the threat model (they already have write access).
    """
    # 128 * 2**18 * 8 * 1 = 268,435,456 bytes = 256 MiB exactly — not rejected
    validate_scrypt_params(2 ** 18, 8, 1)  # must not raise


def test_validate_scrypt_params_boundary_n_max_rejected() -> None:
    """n=2**20 with r=8, p=1 requires 1 GiB — must raise VaultCorrupted."""
    try:
        validate_scrypt_params(2 ** 20, 8, 1)
        assert False, "Expected VaultCorrupted (1 GiB > 256 MiB)"
    except VaultCorrupted:
        pass


def test_negative_scrypt_n_raises_vault_corrupted() -> None:
    """Negative n in KDF params must raise VaultCorrupted."""
    try:
        validate_scrypt_params(-1, 8, 1)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_recovery_slot_missing_kdf_salt_raises_clean_exception() -> None:
    """Missing kdf['salt'] in a recovery slot must raise VaultCorrupted.

    FINDING: ``base64.urlsafe_b64decode(kdf['salt'] + '==')`` raises a raw
    KeyError when 'salt' is absent from the recovery KDF.
    """
    env, _, _, rk_raw = _make_vault(with_recovery=True)
    hdr, _ = _parse_header(env)
    for s in hdr["slots"]:
        if s["type"] == "recovery":
            del s["kdf"]["salt"]
    bad = _rebuild_with_header(env, hdr)
    rk_str = format_recovery_key(rk_raw)
    try:
        open_v2_with_recovery(bad, rk_str)
        assert False, "Expected VaultCorrupted"
    except (VaultCorrupted, WrongRecoveryKey, VaultTampered):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError for missing recovery kdf['salt']")


# ===========================================================================
# Base64 field abuse
# ===========================================================================
# Every base64-encoded field (vault_id, kdf.salt, slot nonce, wrapped_dek) is
# attacker-controlled.  Python's base64.urlsafe_b64decode silently drops
# non-alphabet characters by default, so truly malformed base64 may not raise
# binascii.Error — instead it produces garbage bytes that then fail downstream
# AES-GCM authentication.  We verify both that no exception surfaces from the
# guts AND that the vault never opens.  We also test fields of the wrong decoded
# length (short nonce, short wrapped DEK) to confirm they are safely rejected.

def test_invalid_base64_vault_id_does_not_open_vault() -> None:
    """Garbage in vault_id base64 must not open the vault.

    urlsafe_b64decode is lenient (drops invalid chars), so this produces
    wrong bytes rather than raising.  The slot AAD won't match → WrongPassword.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["vault_id"] = "!!!!!!!!!!!!!!!!!!!!!!!!"  # all invalid chars → decoded as empty-ish
    bad = _rebuild_with_header(env, hdr)
    _assert_vault_did_not_open(lambda: open_v2_with_password(bad, _PASSWORD))


def test_invalid_base64_slot_nonce_does_not_open_vault() -> None:
    """Garbage in slot nonce base64 must not open the vault."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["nonce"] = "!!!!!!"
    bad = _rebuild_with_header(env, hdr)
    _assert_vault_did_not_open(lambda: open_v2_with_password(bad, _PASSWORD))


def test_invalid_base64_wrapped_dek_does_not_open_vault() -> None:
    """Garbage in wrapped_dek base64 must not open the vault."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["wrapped_dek"] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    bad = _rebuild_with_header(env, hdr)
    _assert_vault_did_not_open(lambda: open_v2_with_password(bad, _PASSWORD))


def test_short_nonce_11_bytes_does_not_open_vault() -> None:
    """An 11-byte nonce (wrong length) must not open the vault.

    AESGCM requires 12 bytes; a wrong-length nonce is caught inside
    unwrap_dek's except-block and re-raised as VaultTampered → WrongPassword.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    short_nonce = base64.urlsafe_b64encode(b"\xab" * 11).decode("ascii")
    hdr["slots"][0]["nonce"] = short_nonce
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected WrongPassword (short nonce)"
    except (WrongPassword, VaultCorrupted, VaultTampered):
        pass


def test_short_wrapped_dek_47_bytes_does_not_open_vault() -> None:
    """A 47-byte wrapped_dek (one byte short of 32+tag) must not open the vault.

    AESGCM decryption with a truncated ciphertext fails authentication →
    VaultTampered → WrongPassword.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    short_wrapped = base64.urlsafe_b64encode(b"\xab" * 47).decode("ascii")
    hdr["slots"][0]["wrapped_dek"] = short_wrapped
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected WrongPassword (short wrapped_dek)"
    except (WrongPassword, VaultCorrupted, VaultTampered):
        pass


def test_long_nonce_13_bytes_does_not_open_vault() -> None:
    """A 13-byte nonce (one byte too long) must not open the vault."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    long_nonce = base64.urlsafe_b64encode(b"\xab" * 13).decode("ascii")
    hdr["slots"][0]["nonce"] = long_nonce
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected WrongPassword (long nonce)"
    except (WrongPassword, VaultCorrupted, VaultTampered):
        pass


def test_long_wrapped_dek_49_bytes_does_not_open_vault() -> None:
    """A 49-byte wrapped_dek (one byte too long) must not open the vault."""
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    long_wrapped = base64.urlsafe_b64encode(b"\xab" * 49).decode("ascii")
    hdr["slots"][0]["wrapped_dek"] = long_wrapped
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected WrongPassword (long wrapped_dek)"
    except (WrongPassword, VaultCorrupted, VaultTampered):
        pass


# ===========================================================================
# Recovery-key parsing — adversarial input
# ===========================================================================
# parse_recovery_key runs before any KDF and must reject malformed input
# efficiently (no computation).  Adversarial inputs include empty strings,
# absurdly long strings, Unicode lookalikes that might bypass the alphabet
# check, and keys with transposed groups that the checksum must catch.
# We also verify that the O/I/L normalisation cannot be abused to make two
# printed keys with different visual appearances decode to the same bytes and
# pass the checksum — since the checksum is over the decoded bytes, and
# decoding is many-to-one by design (O,o,0 all map to '0'), this is expected
# behaviour; the test confirms no unexpected collision exists.

def test_empty_recovery_key_raises_malformed() -> None:
    """An empty string must raise MalformedRecoveryKey immediately."""
    try:
        parse_recovery_key("")
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


def test_absurdly_long_recovery_key_raises_malformed_quickly() -> None:
    """A 10 000-character string must raise MalformedRecoveryKey, not hang."""
    long_key = "A" * 10_000
    try:
        parse_recovery_key(long_key)
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


def test_valid_chars_but_35_chars_raises_malformed() -> None:
    """35 valid Crockford chars (one short) must raise MalformedRecoveryKey."""
    # 35 chars after prefix strip = wrong length (need exactly 36)
    key = "RK1 " + "ABCD-" * 7 + "ABC"  # 3 + 1 + 7*5 + 3 = 7+35 = 42 visible, strip to 35 data
    try:
        parse_recovery_key(key)
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


def test_valid_chars_but_37_chars_raises_malformed() -> None:
    """37 valid Crockford chars (one too many) must raise MalformedRecoveryKey."""
    raw = bytes(new_recovery_key())
    formatted = format_recovery_key(raw)
    # Add one extra Crockford char at the end
    extra = formatted + "A"
    try:
        parse_recovery_key(extra)
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


def test_transposed_groups_caught_by_checksum() -> None:
    """Swapping two 4-char groups in a valid key must raise MalformedRecoveryKey.

    The checksum covers the raw decoded bytes; transposing groups changes
    those bytes and must produce a checksum mismatch.
    """
    raw = bytes(new_recovery_key())
    formatted = format_recovery_key(raw)
    # "RK1 AAAA-BBBB-...-CHK" — swap group 0 and group 1
    # format: "RK1 " + groups[0] + "-" + groups[1] + ... + "-" + chk
    parts = formatted[4:].split("-")  # 8 data groups + 1 chk = 9 parts
    assert len(parts) == 9
    parts[0], parts[1] = parts[1], parts[0]  # transpose first two groups
    transposed = "RK1 " + "-".join(parts)
    try:
        result = parse_recovery_key(transposed)
        # Only OK if transposing happened to produce the original bytes (astronomically unlikely)
        assert bytes(result) == raw, "Transposition silently produced different bytes and passed!"
    except MalformedRecoveryKey:
        pass  # correct — checksum caught the transposition


def test_unicode_lookalikes_raise_malformed() -> None:
    """Unicode look-alike characters must raise MalformedRecoveryKey.

    Fullwidth digits (U+FF10, U+FF11) look like '0' and '1' but are outside
    the ASCII Crockford alphabet and must not pass the character-validation loop.
    We craft the input directly (rather than using format_recovery_key output)
    to guarantee the fullwidth character is always present regardless of which
    random bytes the key contains.
    """
    # After stripping "RK1" prefix and the space: 31 ASCII-A + fullwidth-zero + ABCD = 36 chars.
    # The character-validation loop must reject the fullwidth zero before attempting decode.
    crafted_0 = "RK1 " + "A" * 31 + "０" + "ABCD"  # U+FF10 fullwidth '０'
    try:
        parse_recovery_key(crafted_0)
        assert False, "Expected MalformedRecoveryKey for fullwidth '０' (U+FF10)"
    except MalformedRecoveryKey:
        pass  # correct

    crafted_1 = "RK1 " + "B" * 31 + "１" + "BCDE"  # U+FF11 fullwidth '１'
    try:
        parse_recovery_key(crafted_1)
        assert False, "Expected MalformedRecoveryKey for fullwidth '１' (U+FF11)"
    except MalformedRecoveryKey:
        pass  # correct


def test_oli_normalisation_does_not_create_collision() -> None:
    """Two distinct valid recovery keys must decode to distinct byte sequences.

    The O/I/L normalisation is many-to-one on the printed string ('O', 'o',
    '0' all normalise to '0') but one-to-one on the raw bytes: every valid
    raw produces a unique formatted key.  This test generates two different
    raw keys, formats them, and verifies their parsed bytes remain distinct.
    """
    for _ in range(20):
        raw_a = bytes(new_recovery_key())
        raw_b = bytes(new_recovery_key())
        if raw_a == raw_b:
            continue  # astronomically unlikely collision; skip iteration
        fmt_a = format_recovery_key(raw_a)
        fmt_b = format_recovery_key(raw_b)
        parsed_a = bytes(parse_recovery_key(fmt_a))
        parsed_b = bytes(parse_recovery_key(fmt_b))
        assert parsed_a != parsed_b, (
            f"Distinct raws produced same parsed bytes after normalisation: "
            f"{raw_a.hex()} vs {raw_b.hex()}"
        )
        assert parsed_a == raw_a, "parse(format(raw_a)) != raw_a"
        assert parsed_b == raw_b, "parse(format(raw_b)) != raw_b"


def test_recovery_key_without_rk1_prefix_is_lenient() -> None:
    """parse_recovery_key accepts keys without the RK1 prefix — documents leniency.

    FINDING: the prefix check is ``if t.startswith('RK1'): t = t[3:]`` — the
    prefix is stripped only when present, not required.  A 36-character string
    of valid Crockford chars + correct checksum is accepted verbatim.  This
    means a user who copies only the data+checksum portion (36 chars, no prefix)
    gets a successful parse returning the correct raw bytes.  Not a security
    issue (the checksum still validates), but it contradicts the documented
    format ("RK1 prefix required") and could allow two different printed strings
    to refer to the same key without user confusion being surfaced as an error.
    """
    raw = bytes(new_recovery_key())
    formatted = format_recovery_key(raw)
    # Strip "RK1 " (4 chars) — what remains is 36 chars (32 data + 4 checksum)
    no_prefix = formatted[4:]
    try:
        result = parse_recovery_key(no_prefix)
        # FINDING: this succeeds and returns the correct raw bytes.
        # The prefix is optional in the current implementation.
        assert bytes(result) == raw, (
            "Parsing without prefix returned wrong bytes — unexpected inconsistency"
        )
    except MalformedRecoveryKey:
        pass  # would be correct if the implementation ever requires the prefix


# ===========================================================================
# Resource exhaustion / DoS gate
# ===========================================================================
# The primary DoS vector is embedding a huge scrypt n in vault.enc.  Without
# validate_scrypt_params, n=2**30 causes a >100 GiB allocation and crashes the
# MCP server.  We verify three things: (1) validate runs before derive for
# large n, (2) an attacker who supplies a non-numeric n gets a clean rejection
# before any allocation, and (3) an attacker who supplies n just inside the
# memory cap (n=2**18, r=8) triggers validation without a MemoryError on the
# validation call itself — the actual scrypt call is not made in these tests.

def test_dos_large_n_in_header_raises_vault_corrupted_not_memory_error() -> None:
    """n=2**30 in the header must raise VaultCorrupted, never MemoryError.

    This is the primary DoS regression: validate_scrypt_params must gate the
    call before derive_password_kek ever touches the Scrypt constructor.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    hdr["slots"][0]["kdf"]["n"] = 2 ** 30
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass
    except MemoryError:
        assert False, "CRITICAL: MemoryError escaped — DoS gate failed"
    except (WrongPassword,):
        # The header was mutated so body AAD changed; if the slot also opened
        # before VaultCorrupted was raised for memory, that's also suspicious
        assert False, "Unexpected WrongPassword — validate_scrypt_params may not have run"


def test_dos_missing_n_no_scrypt_allocation() -> None:
    """Missing kdf['n'] must fail before any scrypt allocation.

    FINDING: raises raw KeyError instead of VaultCorrupted.  The DoS gate
    is not bypassed (no allocation occurs), but the exception is wrong.
    """
    env, _, _, _ = _make_vault()
    hdr, _ = _parse_header(env)
    del hdr["slots"][0]["kdf"]["n"]
    bad = _rebuild_with_header(env, hdr)
    try:
        open_v2_with_password(bad, _PASSWORD)
        assert False, "Expected VaultCorrupted — no allocation should occur"
    except MemoryError:
        assert False, "CRITICAL: MemoryError — DoS gate bypassed"
    except (VaultCorrupted, WrongPassword):
        pass  # ideal
    except KeyError as exc:
        assert False, (
            "REGRESSION: a raw KeyError escaped instead of VaultCorrupted -- "
            "an attacker-controlled header field is being read unguarded "
            f"again ({type(exc).__name__}: {exc}). Was: raw KeyError, but no allocation occurred — acceptable as DoS defence")


def test_dos_validate_runs_before_derive_for_exact_memory_cap() -> None:
    """validate_scrypt_params must not raise MemoryError for n=2**18, r=8, p=1.

    At exactly 256 MiB the gate accepts the params (> not >=).  Confirming
    the gate itself doesn't allocate is the point: the test calls validate
    directly, not derive_password_kek.
    """
    # Must complete instantly — no allocation, just arithmetic
    try:
        validate_scrypt_params(2 ** 18, 8, 1)
        # Accepted — 256 MiB is the documented boundary
    except VaultCorrupted:
        pass  # also fine if implementation tightens the boundary


# ===========================================================================
# v1 golden fixture — byte-frozen tripwire
# ===========================================================================
# test_trust.py builds a v1 vault at runtime, which means it would silently
# track any change to the v1 code path.  This section uses byte-frozen fixture
# files (tests/fixtures/v1_vault/v1_vault.enc and v1_vault.salt) generated
# once with a known password and known secret values.  If either of the frozen
# v1 functions (crypto.decrypt, _derive_key, PBKDF2_ITERATIONS = 480_000)
# is ever changed, this test will fail — which is the intended behaviour.
#
# Fixture password : "v1-fixture-password-do-not-change"
# Fixture plaintext: JSON of
#     {"FIXTURE_API_KEY": "sk-fixture-0000-not-a-real-key",
#      "FIXTURE_SECRET":  "fixture-value-do-not-use"}
# Salt (hex): deadbeefcafebabe0102030405060708
#
# The files are named v1_vault.enc / v1_vault.salt (not vault.enc / vault.salt)
# to avoid being silently excluded by the root .gitignore patterns (which use
# bare filenames that git matches in every subdirectory).  If someone renames
# them to vault.enc / vault.salt, git will silently stop tracking them and CI
# will fail with FileNotFoundError — reported to Lane 8 (gitignore owner).

_V1_PASSWORD = "v1-fixture-password-do-not-change"
_V1_EXPECTED_PLAINTEXT = (
    b'{"FIXTURE_API_KEY": "sk-fixture-0000-not-a-real-key",'
    b' "FIXTURE_SECRET": "fixture-value-do-not-use"}'
)


def test_v1_fixture_decrypts_correctly() -> None:
    """The frozen v1 fixture must decrypt to the exact expected plaintext.

    If this test fails, the v1 frozen code path (decrypt / _derive_key /
    PBKDF2_ITERATIONS) was modified — which is explicitly forbidden by the
    crypto.py module docstring.
    """
    salt_file = FIXTURES_DIR / "v1_vault.salt"
    enc_file = FIXTURES_DIR / "v1_vault.enc"
    assert salt_file.exists(), f"Fixture missing: {salt_file}"
    assert enc_file.exists(), f"Fixture missing: {enc_file}"
    salt = salt_file.read_bytes()
    token = enc_file.read_bytes()
    assert len(salt) == 16, f"Fixture salt must be 16 bytes, got {len(salt)}"
    recovered = v1_decrypt(_V1_PASSWORD, salt, token)
    assert recovered == _V1_EXPECTED_PLAINTEXT, (
        f"v1 fixture decryption produced wrong plaintext.\n"
        f"Expected: {_V1_EXPECTED_PLAINTEXT!r}\n"
        f"Got:      {recovered!r}\n"
        f"REGRESSION: the frozen v1 code path was changed."
    )


def test_v1_fixture_wrong_password_raises_wrong_password() -> None:
    """Wrong password on the frozen fixture must raise WrongPassword."""
    salt = (FIXTURES_DIR / "v1_vault.salt").read_bytes()
    token = (FIXTURES_DIR / "v1_vault.enc").read_bytes()
    from vault_lib.crypto import WrongPassword as WP
    try:
        v1_decrypt("definitely-wrong-password", salt, token)
        assert False, "Expected WrongPassword"
    except WP:
        pass


# ---------------------------------------------------------------------------
# Standalone test runner
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
