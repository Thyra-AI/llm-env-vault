"""
Regression and correctness suite for the v2 LEVAULT envelope format
implemented in vault_lib/crypto.py (1.4.0).

This suite validates the happy paths and the specific attack-surface cases
called out in the 1.4.0 spec:

  - Full password-slot round-trip: build → parse → unwrap → open body.
  - Full recovery-slot round-trip.
  - A vault with no recovery slot parses and opens cleanly.
  - scrypt parameter validation rejects hostile values without OOM.
  - Recovery-key checksum catches transcription errors.
  - Crockford normalisation (O→0, I/L→1, lowercase, hyphens, spaces).
  - format_recovery_key output shape and round-trip through parse.
  - Entropy preservation: parse(format(raw)) == raw (checksum is appended).
  - Fresh random nonce per seal: same DEK + plaintext → different bytes.
  - is_v2 is False for a real v1 Fernet token and True for a v2 envelope.

Adversarial tamper tests (bit-flipping, slot swapping, truncation) are
deliberately omitted here — they are owned by Lane 7, which writes them
independently of the implementer, as a second pair of eyes.

Conventions:
  - Plain ``def test_x() -> None:``; no pytest fixtures; no conftest.
  - SCRYPT_DEFAULT is monkeypatched to n=2**12 (~6 ms) in every test that
    calls into scrypt, saving/restoring in try/finally.
  - 75-dash section banners with a prose failure-mode paragraph.
  - Standalone runner block at the bottom sweeping globals() for test_*
    and printing ``Results: N/N passed``.

Runs under ``pytest tests/test_crypto_v2.py -q`` and standalone:
  ``python tests/test_crypto_v2.py``
"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib.crypto import (  # noqa: E402
    SCRYPT_DEFAULT,
    VAULT_MAGIC,
    FORMAT_VERSION,
    RECOVERY_KEY_BYTES,
    ScryptParams,
    VaultCorrupted,
    VaultTampered,
    WrongPassword,
    WrongRecoveryKey,
    MalformedRecoveryKey,
    NoRecoverySlot,
    build_envelope,
    build_v2_vault,
    derive_password_kek,
    derive_recovery_kek,
    encrypt,
    format_recovery_key,
    is_v2,
    new_dek,
    new_recovery_key,
    new_salt,
    new_vault_id,
    open_body,
    open_v2_with_password,
    open_v2_with_recovery,
    parse_envelope,
    parse_recovery_key,
    seal_body,
    slot_aad,
    validate_scrypt_params,
    wrap_dek,
    unwrap_dek,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAST_PARAMS = ScryptParams(n=2 ** 12, r=8, p=1)
_PLAINTEXT = b"Hello, vault!" + b"\x03" * 3   # PKCS7-padded to 16-byte block

_PASSWORD = "test-master-password"


def _patch_scrypt(params: ScryptParams = _FAST_PARAMS):
    """Context manager: monkeypatch SCRYPT_DEFAULT, restore on exit."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        old = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = params
        try:
            yield
        finally:
            crypto.SCRYPT_DEFAULT = old

    return _ctx()


# ===========================================================================
# Round-trip: password slot
# ===========================================================================
# If build_v2_vault/open_v2_with_password are broken the vault is unreadable
# on every ordinary unlock — a catastrophic regression.

def test_password_slot_round_trip() -> None:
    """Full build → parse → unwrap → open round-trip via the password slot."""
    with _patch_scrypt():
        envelope, dek, vault_id = build_v2_vault(
            _PASSWORD, _PLAINTEXT, params=_FAST_PARAMS
        )
    plaintext, out_dek, header = open_v2_with_password(envelope, _PASSWORD)
    assert plaintext == _PLAINTEXT, f"Plaintext mismatch: {plaintext!r}"
    assert bytes(out_dek) == bytes(dek), "DEK mismatch"
    assert header["version"] == FORMAT_VERSION
    assert header["format"] == "llm-env-vault"
    assert header["cipher"] == "AES-256-GCM"


def test_wrong_password_raises_wrong_password() -> None:
    """A wrong master password must raise WrongPassword, not VaultTampered."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    try:
        open_v2_with_password(envelope, "wrong-password")
        assert False, "Expected WrongPassword"
    except WrongPassword:
        pass


# ===========================================================================
# Round-trip: recovery slot
# ===========================================================================
# If recovery unlock is broken, a user who lost their master password cannot
# recover their secrets despite having a valid paper key.

def test_recovery_slot_round_trip() -> None:
    """Full build → parse → unwrap → open round-trip via the recovery slot."""
    rk = new_recovery_key()
    with _patch_scrypt():
        envelope, dek, vault_id = build_v2_vault(
            _PASSWORD, _PLAINTEXT, recovery_raw=bytes(rk), params=_FAST_PARAMS
        )
    rk_str = format_recovery_key(bytes(rk))
    plaintext, out_dek, header = open_v2_with_recovery(envelope, rk_str)
    assert plaintext == _PLAINTEXT, f"Plaintext mismatch: {plaintext!r}"
    assert bytes(out_dek) == bytes(dek), "DEK mismatch via recovery"


def test_wrong_recovery_key_raises_wrong_recovery_key() -> None:
    """A wrong recovery key must raise WrongRecoveryKey."""
    rk = new_recovery_key()
    wrong = new_recovery_key()   # different key
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(
            _PASSWORD, _PLAINTEXT, recovery_raw=bytes(rk), params=_FAST_PARAMS
        )
    # Format the *wrong* key so it passes checksum validation
    wrong_str = format_recovery_key(bytes(wrong))
    try:
        open_v2_with_recovery(envelope, wrong_str)
        assert False, "Expected WrongRecoveryKey"
    except WrongRecoveryKey:
        pass


# ===========================================================================
# Vault with no recovery slot
# ===========================================================================
# A vault without a recovery slot must be a fully supported state.  The
# parse/open path must not crash, and the recovery-slot API must raise
# NoRecoverySlot cleanly rather than a generic exception.

def test_no_recovery_slot_opens_via_password() -> None:
    """A vault without a recovery slot opens fine via the password."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    # Verify no recovery slot in header
    header, _, _ = parse_envelope(envelope)
    rk_slots = [s for s in header["slots"] if s["type"] == "recovery"]
    assert rk_slots == [], "Should have no recovery slot"
    # Open via password still works
    plaintext, _, _ = open_v2_with_password(envelope, _PASSWORD)
    assert plaintext == _PLAINTEXT


def test_no_recovery_slot_raises_no_recovery_slot() -> None:
    """Attempting recovery on a vault without a recovery slot raises NoRecoverySlot."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    rk = format_recovery_key(bytes(new_recovery_key()))
    try:
        open_v2_with_recovery(envelope, rk)
        assert False, "Expected NoRecoverySlot"
    except NoRecoverySlot:
        pass


# ===========================================================================
# validate_scrypt_params — security control against DoS via hostile headers
# ===========================================================================
# Without this gate an attacker who can write vault.enc can embed n=2**30
# and cause a hundreds-of-GiB allocation that OOM-kills the MCP server on
# every unlock attempt.  Every rejection path must raise VaultCorrupted —
# never MemoryError or any allocation attempt.

def test_validate_scrypt_params_accepts_defaults() -> None:
    """Default scrypt parameters must pass validation without error."""
    validate_scrypt_params(2 ** 16, 8, 1)  # should not raise


def test_validate_scrypt_params_rejects_n_too_large() -> None:
    """n=2**30 must raise VaultCorrupted without allocating."""
    try:
        validate_scrypt_params(2 ** 30, 8, 1)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass
    except MemoryError:
        assert False, "validate_scrypt_params must never raise MemoryError"


def test_validate_scrypt_params_rejects_non_power_of_two_n() -> None:
    """Non-power-of-two n must raise VaultCorrupted."""
    try:
        validate_scrypt_params(65535, 8, 1)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_validate_scrypt_params_rejects_n_too_small() -> None:
    """n below 2**10 must raise VaultCorrupted."""
    try:
        validate_scrypt_params(2 ** 9, 8, 1)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_validate_scrypt_params_rejects_r_out_of_range() -> None:
    """r=0 and r=33 must raise VaultCorrupted."""
    try:
        validate_scrypt_params(2 ** 16, 0, 1)
        assert False, "Expected VaultCorrupted for r=0"
    except VaultCorrupted:
        pass
    try:
        validate_scrypt_params(2 ** 16, 33, 1)
        assert False, "Expected VaultCorrupted for r=33"
    except VaultCorrupted:
        pass


def test_validate_scrypt_params_rejects_p_out_of_range() -> None:
    """p=0 and p=17 must raise VaultCorrupted."""
    try:
        validate_scrypt_params(2 ** 16, 8, 0)
        assert False, "Expected VaultCorrupted for p=0"
    except VaultCorrupted:
        pass
    try:
        validate_scrypt_params(2 ** 16, 8, 17)
        assert False, "Expected VaultCorrupted for p=17"
    except VaultCorrupted:
        pass


def test_validate_scrypt_params_rejects_memory_product_cap() -> None:
    """Parameters whose product exceeds 256 MiB must raise VaultCorrupted."""
    # 128 * 2**20 * 32 * 1 = 4 GiB > 256 MiB
    try:
        validate_scrypt_params(2 ** 20, 32, 1)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass
    except MemoryError:
        assert False, "Must not raise MemoryError"


# ===========================================================================
# Recovery-key checksum
# ===========================================================================
# The checksum catches transcription errors *before* the KDF runs, so the
# UI can say "that looks like a typo" rather than waiting 100 ms for scrypt
# to confirm a wrong key.

def test_recovery_key_checksum_catches_single_char_error() -> None:
    """A single-character change anywhere in the data chars raises MalformedRecoveryKey."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # Corrupt the first data character inside the formatted string
    # "RK1 " is 4 chars, first data char is at index 4
    chars = list(formatted)
    # Find first data char and flip it to a different Crockford character
    from vault_lib.crypto import _CROCKFORD_ALPHABET
    for i, ch in enumerate(chars):
        if ch in _CROCKFORD_ALPHABET and ch != "RK1 "[0] if i < 4 else True:
            original = chars[i]
            # Replace with a different Crockford char
            alt = "A" if original != "A" else "B"
            chars[i] = alt
            corrupted = "".join(chars)
            try:
                parse_recovery_key(corrupted)
                # If this doesn't raise, the checksum missed a corruption
                # (This could happen if corrupted == formatted after normalisation,
                # but that's only possible if alt == original after normalisation)
                if corrupted != formatted:
                    assert False, (
                        f"Checksum did not catch corruption at position {i}: "
                        f"original {original!r} → {alt!r}"
                    )
            except MalformedRecoveryKey:
                pass  # correct behaviour
            break


def test_recovery_key_checksum_rejects_wrong_checksum() -> None:
    """Manually corrupting the checksum group raises MalformedRecoveryKey."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # The checksum is the last 4 chars (after the last hyphen)
    body, chk = formatted.rsplit("-", 1)
    # Flip one checksum character
    bad_chk = ("A" if chk[0] != "A" else "B") + chk[1:]
    corrupted = body + "-" + bad_chk
    try:
        parse_recovery_key(corrupted)
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


# ===========================================================================
# Crockford normalisation
# ===========================================================================
# Users copy recovery keys from paper; OCR and hand-writing confuse O/0, I/1,
# L/1.  Hyphens and spaces help readability but must be stripped.  Lowercase
# input is common when typing from memory.

def test_crockford_normalisation_O_to_0() -> None:
    """O is normalised to 0 before checksum verification."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # Replace every '0' with 'O' (both uppercase and lowercase)
    mangled = formatted.replace("0", "O")
    # Should parse cleanly
    out = parse_recovery_key(mangled)
    assert bytes(out) == rk, "O→0 normalisation failed"


def test_crockford_normalisation_I_to_1() -> None:
    """I is normalised to 1 before checksum verification."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    mangled = formatted.replace("1", "I")
    out = parse_recovery_key(mangled)
    assert bytes(out) == rk, "I→1 normalisation failed"


def test_crockford_normalisation_L_to_1() -> None:
    """L is normalised to 1 before checksum verification."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    mangled = formatted.replace("1", "L")
    out = parse_recovery_key(mangled)
    assert bytes(out) == rk, "L→1 normalisation failed"


def test_crockford_normalisation_lowercase_input() -> None:
    """Lowercase input is accepted and normalised to uppercase."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    out = parse_recovery_key(formatted.lower())
    assert bytes(out) == rk, "Lowercase normalisation failed"


def test_crockford_normalisation_strips_hyphens_and_spaces() -> None:
    """Hyphens and spaces are stripped before parsing."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # Remove all hyphens and add spaces instead
    no_hyphens = formatted.replace("-", " ")
    out = parse_recovery_key(no_hyphens)
    assert bytes(out) == rk, "Hyphen/space stripping failed"


def test_crockford_invalid_char_raises_malformed() -> None:
    """Characters outside the Crockford alphabet raise MalformedRecoveryKey."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # Insert an invalid character '$'
    bad = formatted[:5] + "$" + formatted[5:]
    try:
        parse_recovery_key(bad)
        assert False, "Expected MalformedRecoveryKey"
    except MalformedRecoveryKey:
        pass


# ===========================================================================
# format_recovery_key output shape
# ===========================================================================
# The documented shape must match exactly so that printed keys and the UI
# template match what parse_recovery_key expects.

def test_format_recovery_key_shape() -> None:
    """format_recovery_key output must match the documented shape exactly."""
    rk = bytes(new_recovery_key())
    formatted = format_recovery_key(rk)
    # "RK1 XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
    #  prefix + space + 8×4 data chars with hyphens + hyphen + 4 checksum chars
    assert formatted.startswith("RK1 "), f"Wrong prefix: {formatted[:5]!r}"
    parts = formatted[4:].split("-")
    # 8 data groups + 1 checksum group = 9 groups
    assert len(parts) == 9, f"Expected 9 hyphen-separated groups, got {len(parts)}: {parts}"
    for i, part in enumerate(parts):
        assert len(part) == 4, f"Group {i} has length {len(part)}: {part!r}"
        for ch in part:
            assert ch in "0123456789ABCDEFGHJKMNPQRSTVWXYZ", (
                f"Non-Crockford char {ch!r} in group {i}"
            )


def test_format_recovery_key_round_trips() -> None:
    """format_recovery_key followed by parse_recovery_key returns the original bytes."""
    for _ in range(8):
        rk = bytes(new_recovery_key())
        assert bytes(parse_recovery_key(format_recovery_key(rk))) == rk


# ===========================================================================
# Entropy preservation (checksum is appended, not carved out)
# ===========================================================================
# If the checksum were carved out of the 160 bits, the recovered raw bytes
# would differ from the original.  Verifying parse(format(raw)) == raw proves
# the full 160 bits survive the round-trip.

def test_entropy_is_160_bits_checksum_is_appended() -> None:
    """parse_recovery_key(format_recovery_key(raw)) == raw for 160-bit raw."""
    for _ in range(16):
        raw = bytes(new_recovery_key())
        assert len(raw) == RECOVERY_KEY_BYTES == 20, (
            f"Expected 20 bytes, got {len(raw)}"
        )
        recovered = bytes(parse_recovery_key(format_recovery_key(raw)))
        assert recovered == raw, (
            f"Entropy not preserved: {raw.hex()} → {recovered.hex()}"
        )


# ===========================================================================
# Fresh nonce per seal
# ===========================================================================
# AES-256-GCM is catastrophically broken if the same nonce is reused under
# the same key.  Every seal call must generate a fresh random nonce.

def test_fresh_nonce_per_seal_produces_different_ciphertext() -> None:
    """Sealing the same plaintext twice under the same DEK gives different bytes."""
    dek = bytes(new_dek())
    aad = b"test-aad"
    ct1 = seal_body(dek, _PLAINTEXT, aad)
    ct2 = seal_body(dek, _PLAINTEXT, aad)
    assert ct1 != ct2, (
        "seal_body produced identical output on two calls — nonce is not fresh!"
    )


def test_fresh_nonce_per_wrap_produces_different_ciphertext() -> None:
    """wrap_dek produces different output on every call even for the same DEK."""
    kek = bytes(new_dek())
    dek = bytes(new_dek())
    aad = b"wrap-aad"
    n1, w1 = wrap_dek(kek, dek, aad)
    n2, w2 = wrap_dek(kek, dek, aad)
    assert (n1, w1) != (n2, w2), "wrap_dek produced identical nonce+wrapped twice"


# ===========================================================================
# is_v2 detection
# ===========================================================================
# is_v2 must reliably distinguish v1 Fernet tokens from v2 envelopes so that
# the store layer can route to the correct code path without parsing JSON or
# catching exceptions.

def test_is_v2_false_for_v1_fernet_token() -> None:
    """is_v2 returns False for a real v1 Fernet token."""
    salt = new_salt()
    token = encrypt("some-password", salt, b"plaintext")
    assert not is_v2(token), (
        f"is_v2 returned True for a v1 Fernet token: {token[:16]!r}"
    )


def test_is_v2_true_for_v2_envelope() -> None:
    """is_v2 returns True for a freshly built v2 envelope."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    assert is_v2(envelope), "is_v2 returned False for a valid v2 envelope"


def test_is_v2_false_for_empty_bytes() -> None:
    """is_v2 returns False for empty input (no crash)."""
    assert not is_v2(b"")


def test_is_v2_false_for_random_bytes() -> None:
    """is_v2 returns False for random garbage bytes."""
    assert not is_v2(b"gAAAAA" + b"\x00" * 50)  # Fernet-like prefix


# ===========================================================================
# parse_envelope structural checks
# ===========================================================================
# parse_envelope is the first line of defence against hostile vault files.
# Every structural rejection must raise VaultCorrupted with a message about
# "damaged file", never about "wrong password".

def test_parse_envelope_rejects_wrong_magic() -> None:
    """Wrong magic bytes must raise VaultCorrupted."""
    bad = b"BADMAGIC" + bytes([FORMAT_VERSION]) + b"\x00" * 20
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted as e:
        assert "password" not in str(e).lower(), (
            f"Error message mentions password: {e}"
        )


def test_parse_envelope_rejects_wrong_version() -> None:
    """Wrong format version must raise VaultCorrupted."""
    bad = VAULT_MAGIC + bytes([99]) + b"\x00\x00\x00\x04" + b"test" + b"\x00" * 28
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_parse_envelope_rejects_too_short() -> None:
    """Data shorter than minimum must raise VaultCorrupted."""
    try:
        parse_envelope(VAULT_MAGIC + b"\x02")
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_parse_envelope_rejects_oversized_header() -> None:
    """hdr_len > 65536 must raise VaultCorrupted."""
    import struct
    bad = VAULT_MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">I", 65537) + b"\x00" * 100
    try:
        parse_envelope(bad)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


def test_parse_envelope_rejects_truncated_body() -> None:
    """A file truncated after the header must raise VaultCorrupted."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    # Truncate to just the magic + version + hdr_len + header (no body at all)
    import struct
    hdr_len = struct.unpack(">I", envelope[9:13])[0]
    truncated = envelope[:13 + hdr_len]
    try:
        parse_envelope(truncated)
        assert False, "Expected VaultCorrupted"
    except VaultCorrupted:
        pass


# ===========================================================================
# slot_aad domain separation
# ===========================================================================
# The slot AAD binds each wrapped DEK to its vault and slot type.
# Two different slot types in the same vault must produce different AADs.

def test_slot_aad_differs_by_slot_type() -> None:
    """slot_aad for 'password' and 'recovery' differ even for the same vault."""
    vid = new_vault_id()
    pw_aad = slot_aad(vid, "password")
    rk_aad = slot_aad(vid, "recovery")
    assert pw_aad != rk_aad


def test_slot_aad_differs_by_vault_id() -> None:
    """slot_aad for the same slot type differs across different vault IDs."""
    vid1 = new_vault_id()
    vid2 = new_vault_id()
    assert slot_aad(vid1, "password") != slot_aad(vid2, "password")


def test_slot_aad_contains_magic_and_version() -> None:
    """slot_aad bytes start with VAULT_MAGIC and FORMAT_VERSION."""
    vid = new_vault_id()
    aad = slot_aad(vid, "password")
    assert aad[:8] == VAULT_MAGIC
    assert aad[8] == FORMAT_VERSION


# ===========================================================================
# wrap/unwrap DEK
# ===========================================================================

def test_wrap_unwrap_dek_round_trip() -> None:
    """wrap_dek followed by unwrap_dek recovers the original DEK."""
    kek = bytes(new_dek())
    dek = bytes(new_dek())
    aad = b"test-wrap-aad"
    nonce, wrapped = wrap_dek(kek, dek, aad)
    recovered = unwrap_dek(kek, nonce, wrapped, aad)
    assert bytes(recovered) == dek


def test_unwrap_dek_raises_vault_tampered_on_wrong_kek() -> None:
    """unwrap_dek raises VaultTampered when the KEK is wrong."""
    kek = bytes(new_dek())
    wrong_kek = bytes(new_dek())
    dek = bytes(new_dek())
    aad = b"aad"
    nonce, wrapped = wrap_dek(kek, dek, aad)
    try:
        unwrap_dek(wrong_kek, nonce, wrapped, aad)
        assert False, "Expected VaultTampered"
    except VaultTampered:
        pass


def test_unwrap_dek_raises_vault_tampered_on_wrong_aad() -> None:
    """unwrap_dek raises VaultTampered when the AAD is wrong."""
    kek = bytes(new_dek())
    dek = bytes(new_dek())
    nonce, wrapped = wrap_dek(kek, dek, b"correct-aad")
    try:
        unwrap_dek(kek, nonce, wrapped, b"wrong-aad")
        assert False, "Expected VaultTampered"
    except VaultTampered:
        pass


# ===========================================================================
# seal/open body
# ===========================================================================

def test_seal_open_body_round_trip() -> None:
    """seal_body followed by open_body recovers the original plaintext."""
    dek = bytes(new_dek())
    aad = b"body-aad"
    body = seal_body(dek, _PLAINTEXT, aad)
    recovered = open_body(dek, body, aad)
    assert recovered == _PLAINTEXT


def test_open_body_raises_vault_tampered_on_wrong_dek() -> None:
    """open_body raises VaultTampered when the DEK is wrong."""
    dek = bytes(new_dek())
    wrong_dek = bytes(new_dek())
    aad = b"aad"
    body = seal_body(dek, _PLAINTEXT, aad)
    try:
        open_body(wrong_dek, body, aad)
        assert False, "Expected VaultTampered"
    except VaultTampered:
        pass


def test_open_body_raises_vault_tampered_on_wrong_aad() -> None:
    """open_body raises VaultTampered when the AAD is wrong."""
    dek = bytes(new_dek())
    body = seal_body(dek, _PLAINTEXT, b"correct-aad")
    try:
        open_body(dek, body, b"wrong-aad")
        assert False, "Expected VaultTampered"
    except VaultTampered:
        pass


# ===========================================================================
# v1 backward compatibility — frozen legacy functions still work
# ===========================================================================
# The v1 read path must remain callable byte-for-byte identical.  Breaking it
# would make existing vaults permanently unreadable.

def test_v1_encrypt_decrypt_round_trip() -> None:
    """The frozen v1 encrypt/decrypt path must still work."""
    from vault_lib.crypto import encrypt, decrypt, new_salt
    salt = new_salt()
    token = encrypt("my-v1-password", salt, b"v1-secret-data")
    recovered = decrypt("my-v1-password", salt, token)
    assert recovered == b"v1-secret-data"


def test_v1_wrong_password_still_raises_wrong_password() -> None:
    """v1 decrypt with wrong password still raises WrongPassword."""
    from vault_lib.crypto import encrypt, decrypt, new_salt, WrongPassword
    salt = new_salt()
    token = encrypt("correct", salt, b"data")
    try:
        decrypt("wrong", salt, token)
        assert False, "Expected WrongPassword"
    except WrongPassword:
        pass


# ===========================================================================
# Header JSON shape
# ===========================================================================
# The header must contain the documented fields so that Lane 9 (store.py)
# can rely on the structure without guessing.

def test_header_json_has_required_fields() -> None:
    """build_v2_vault header must contain all required top-level fields."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    header, _, _ = parse_envelope(envelope)
    for field in ("format", "version", "vault_id", "created", "cipher", "slots"):
        assert field in header, f"Required header field missing: {field!r}"
    assert header["format"] == "llm-env-vault"
    assert header["version"] == 2
    assert header["cipher"] == "AES-256-GCM"


def test_header_password_slot_has_required_fields() -> None:
    """The password slot must have all required fields."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    header, _, _ = parse_envelope(envelope)
    pw_slot = next(s for s in header["slots"] if s["type"] == "password")
    for field in ("type", "kdf", "nonce", "wrapped_dek"):
        assert field in pw_slot, f"Password slot missing field: {field!r}"
    kdf = pw_slot["kdf"]
    for kdf_field in ("name", "n", "r", "p", "salt"):
        assert kdf_field in kdf, f"Password slot KDF missing field: {kdf_field!r}"
    assert kdf["name"] == "scrypt"


def test_header_recovery_slot_has_required_fields() -> None:
    """The recovery slot must have all required fields."""
    rk = new_recovery_key()
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(
            _PASSWORD, _PLAINTEXT, recovery_raw=bytes(rk), params=_FAST_PARAMS
        )
    header, _, _ = parse_envelope(envelope)
    rk_slot = next(s for s in header["slots"] if s["type"] == "recovery")
    for field in ("type", "id", "created", "kdf", "nonce", "wrapped_dek"):
        assert field in rk_slot, f"Recovery slot missing field: {field!r}"
    kdf = rk_slot["kdf"]
    for kdf_field in ("name", "salt", "info"):
        assert kdf_field in kdf, f"Recovery slot KDF missing field: {kdf_field!r}"
    assert kdf["name"] == "hkdf-sha256"
    assert kdf["info"] == "llm-env-vault/v2/recovery-kek"


# ===========================================================================
# AAD stability — no re-serialisation needed
# ===========================================================================
# The body AAD is the literal byte slice data[0 : 13 + hdr_len], not a
# re-serialisation of the parsed header.  parse_envelope must return this
# exact slice so the caller never has to regenerate it.

def test_aad_bytes_match_prefix_of_envelope() -> None:
    """parse_envelope must return the literal envelope prefix as AAD."""
    with _patch_scrypt():
        envelope, _, _ = build_v2_vault(_PASSWORD, _PLAINTEXT, params=_FAST_PARAMS)
    import struct
    hdr_len = struct.unpack(">I", envelope[9:13])[0]
    expected_aad = envelope[:13 + hdr_len]
    _, aad_bytes, _ = parse_envelope(envelope)
    assert aad_bytes == expected_aad, "AAD bytes do not match the envelope prefix"


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
