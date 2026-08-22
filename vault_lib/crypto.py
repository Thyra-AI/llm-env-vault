"""Password-based encryption for the secret vault.

The master password never touches disk and is never passed as a CLI
argument or environment variable — it only ever exists inside the GUI
process's memory for the duration of a single dialog.

v1 LEGACY (frozen):
    The functions ``new_salt``, ``_derive_key``, ``encrypt``, ``decrypt``,
    and the constant ``PBKDF2_ITERATIONS``, together with ``WrongPassword``,
    form the **v1 read path**.  Existing ``vault.enc`` files on disk depend on
    their exact byte-for-byte behaviour.  Do NOT edit, rename, inline, or
    "improve" any of them.  They must remain callable forever so that
    ``store.py`` can decrypt v1 vaults during migration.

v2 ENVELOPE (new in 1.4.0):
    The remainder of this module implements the versioned, self-describing
    LEVAULT\x00 binary envelope format with AES-256-GCM body encryption and
    scrypt-derived key-encryption keys.
"""
import base64
import functools
import hashlib
import json
import os
import struct
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ===========================================================================
# v1 LEGACY — FROZEN, DO NOT EDIT
# (existing vault.enc files depend on these exact byte-level behaviours)
# ===========================================================================

PBKDF2_ITERATIONS = 480_000


class WrongPassword(Exception):
    pass


def new_salt() -> bytes:
    """Return 16 fresh random bytes for use as a v1 KDF salt. FROZEN LEGACY."""
    return os.urandom(16)


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key via PBKDF2-HMAC-SHA256.  FROZEN LEGACY."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt(password: str, salt: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with the v1 Fernet envelope.  FROZEN LEGACY."""
    return Fernet(_derive_key(password, salt)).encrypt(plaintext)


def decrypt(password: str, salt: bytes, token: bytes) -> bytes:
    """Decrypt a v1 Fernet token.  FROZEN LEGACY."""
    try:
        return Fernet(_derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise WrongPassword(
            "Incorrect master password (or the vault file is corrupted)."
        ) from None


# ===========================================================================
# v2 ENVELOPE — new in 1.4.0
# ===========================================================================

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class WrongRecoveryKey(Exception):
    """Raised when a recovery key fails authentication (bad checksum passes but
    AESGCM unwrap fails — i.e. the key is wrong, not merely malformed)."""


class VaultCorrupted(Exception):
    """Raised for structurally invalid vault files (truncated, bad magic,
    illegal header, out-of-range scrypt params).  Not a wrong-password error.
    Never expose internal details that could aid an attacker."""


class VaultTampered(VaultCorrupted):
    """Raised when AESGCM authentication fails for the body or a slot, which
    means the ciphertext or AAD was modified after sealing."""


class NoRecoverySlot(Exception):
    """Raised when a recovery-slot operation is requested but none exists."""


class MalformedRecoveryKey(ValueError):
    """Raised by ``parse_recovery_key`` for structurally invalid input (bad
    alphabet, wrong length, checksum mismatch).  Not a wrong-key error."""


# ---------------------------------------------------------------------------
# Constants and defaults
# ---------------------------------------------------------------------------

VAULT_MAGIC: bytes = b"LEVAULT\x00"
FORMAT_VERSION: int = 2
FMK_BYTES: int = 32
RECOVERY_KEY_BYTES: int = 20  # 160 bits → 32 Crockford base32 chars, no padding

# Crockford base32: excludes I L O U (uppercase only on output; normalise on input)
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE: dict = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}


@dataclass(frozen=True)
class ScryptParams:
    n: int = 2 ** 16
    r: int = 8
    p: int = 1


# Monkeypatch this in tests to avoid 64 MiB scrypt runs.
SCRYPT_DEFAULT = ScryptParams()

# Save-time minimum: a vault should never be written with parameters weaker
# than these (enforced by the store layer, not by this module directly).
SCRYPT_FLOOR = ScryptParams(n=2 ** 14, r=8, p=1)


# ---------------------------------------------------------------------------
# Parameter validation — security control, not sanity check
# ---------------------------------------------------------------------------

_MAX_SCRYPT_MEM = 256 * 1024 * 1024  # 256 MiB


def validate_scrypt_params(n: int, r: int, p: int) -> None:
    """Validate scrypt parameters from a (potentially attacker-written) header.

    An unchecked ``n=2**30`` would cause Python's scrypt to attempt a
    hundreds-of-GiB allocation and OOM-kill the MCP server — a trivial
    denial-of-service via filesystem write.  Raise ``VaultCorrupted`` for any
    out-of-range combination; never let a ``MemoryError`` escape.
    """
    # n must be a power of two in [2**10, 2**20]
    if not (isinstance(n, int) and n >= 2 ** 10 and n <= 2 ** 20 and (n & (n - 1)) == 0):
        raise VaultCorrupted(
            f"Invalid scrypt n={n!r}: must be a power of two in [2**10, 2**20]."
        )
    if not (isinstance(r, int) and 1 <= r <= 32):
        raise VaultCorrupted(f"Invalid scrypt r={r!r}: must be in [1, 32].")
    if not (isinstance(p, int) and 1 <= p <= 16):
        raise VaultCorrupted(f"Invalid scrypt p={p!r}: must be in [1, 16].")
    mem = 128 * n * r * p
    if mem > _MAX_SCRYPT_MEM:
        raise VaultCorrupted(
            f"scrypt params (n={n}, r={r}, p={p}) would require "
            f"{mem // (1024*1024)} MiB > 256 MiB limit."
        )


# ---------------------------------------------------------------------------
# KDF functions
# ---------------------------------------------------------------------------

def derive_password_kek(password: str, salt: bytes, params: ScryptParams) -> bytes:
    """Derive a 32-byte key-encryption key from *password* using scrypt.

    Always call ``validate_scrypt_params`` before calling this function when
    the params come from an untrusted source (``parse_envelope`` does this
    automatically).
    """
    kdf = Scrypt(salt=salt, length=32, n=params.n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))


def derive_recovery_kek(recovery_key: bytes, salt: bytes, vault_id: bytes) -> bytes:
    """Derive a 32-byte KEK from *recovery_key* via HKDF-SHA256.

    HKDF (not scrypt) is sound here because the input is 160 bits of
    machine-generated entropy — there is no dictionary to grind.  If a
    future version ever allows a human-chosen recovery phrase, that slot
    MUST switch to scrypt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"llm-env-vault/v2/recovery-kek/" + vault_id,
    )
    return hkdf.derive(recovery_key)


# ---------------------------------------------------------------------------
# Recovery-key encoding (Crockford base32, 160-bit, with 20-bit checksum)
# ---------------------------------------------------------------------------

def _crockford_encode(data: bytes) -> str:
    """Encode *data* as Crockford base32 (uppercase, no padding)."""
    # Convert bytes to a big integer
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0 or not chars:
        chars.append(_CROCKFORD_ALPHABET[n & 0x1F])
        n >>= 5
    # Pad to the expected length: ceil(len(data)*8/5) characters
    expected = (len(data) * 8 + 4) // 5
    while len(chars) < expected:
        chars.append(_CROCKFORD_ALPHABET[0])
    return "".join(reversed(chars))


def _crockford_decode_str(text: str) -> bytes:
    """Decode a Crockford base32 string to bytes (no checksum logic here)."""
    n = 0
    for ch in text:
        if ch not in _CROCKFORD_DECODE:
            raise MalformedRecoveryKey(f"Invalid Crockford character: {ch!r}")
        n = (n << 5) | _CROCKFORD_DECODE[ch]
    # The number of output bytes
    num_bits = len(text) * 5
    num_bytes = num_bits // 8
    return n.to_bytes(num_bytes, "big")


def _rk_checksum(raw: bytes) -> bytes:
    """Return the 20-bit (3-byte, top-4-bits ignored) checksum for *raw*.

    Checksum = first 20 bits of SHA-256(b"llm-env-vault/v2/rk-check" || raw).
    Encoded as 4 Crockford characters (4*5 = 20 bits exactly).
    """
    digest = hashlib.sha256(b"llm-env-vault/v2/rk-check" + raw).digest()
    # Take the first 20 bits: top byte, second byte, top nibble of third byte
    # Pack as a 3-byte big-endian value but only use the top 20 bits
    val = ((digest[0] << 12) | (digest[1] << 4) | (digest[2] >> 4)) & 0xFFFFF
    # Encode as 4 Crockford chars (4 * 5 = 20 bits)
    chars = []
    v = val
    for _ in range(4):
        chars.append(_CROCKFORD_ALPHABET[v & 0x1F])
        v >>= 5
    return "".join(reversed(chars))


def new_recovery_key() -> bytearray:
    """Generate 20 bytes (160 bits) of random recovery key material."""
    return bytearray(os.urandom(RECOVERY_KEY_BYTES))


def format_recovery_key(raw: bytes) -> str:
    """Encode *raw* (20 bytes) as a human-readable recovery key string.

    Output shape: ``RK1 ABCD-EFGH-IJKL-MNPQ-RSTU-VWXY-Z012-3456-CHK9``
    That is: prefix ``RK1``, space, 8 groups of 4 data characters joined by
    hyphens, hyphen, then 4 checksum characters.  Total data: 32 Crockford
    chars (160 bits); total checksum: 4 Crockford chars (20 bits appended,
    not carved out).
    """
    if len(raw) != RECOVERY_KEY_BYTES:
        raise ValueError(f"Expected {RECOVERY_KEY_BYTES} bytes, got {len(raw)}")
    data_str = _crockford_encode(raw)  # 32 chars for 20 bytes
    chk = _rk_checksum(raw)           # 4 chars
    # Split data_str into 8 groups of 4
    groups = [data_str[i:i+4] for i in range(0, 32, 4)]
    return "RK1 " + "-".join(groups) + "-" + chk


def parse_recovery_key(text: str) -> bytearray:
    """Normalize and decode a recovery key string, verifying its checksum.

    Normalization order: strip hyphens/spaces/whitespace, uppercase, map
    ``O``→``0`` / ``I``/``L``→``1`` (Crockford), then strip the ``RK1``
    prefix.  Normalisation happens *before* the prefix check so that a user
    who typed ``RKI`` (I instead of 1) is still accepted.  Raises
    ``MalformedRecoveryKey`` on bad alphabet, wrong length, or checksum
    mismatch — so the UI can say "looks like a typo" before any KDF runs.
    """
    # Strip hyphens, spaces, and all whitespace first
    t = text.replace("-", "").replace(" ", "")
    t = "".join(t.split())  # handles tabs, newlines, etc.
    # Uppercase
    t = t.upper()
    # Crockford normalisation — must happen before prefix check so that
    # "RKI ..." (I typed instead of 1) is correctly detected as "RK1 ..."
    t = t.replace("O", "0").replace("I", "1").replace("L", "1")
    # Strip "RK1" prefix (already normalised)
    if t.startswith("RK1"):
        t = t[3:]
    # Validate: expect 32 data chars + 4 checksum chars = 36 total
    if len(t) != 36:
        raise MalformedRecoveryKey(
            f"Recovery key must be 36 Crockford characters (got {len(t)})."
        )
    data_str = t[:32]
    chk_str = t[32:]
    # Decode the 32 data chars to 20 bytes
    # Validate each character individually first
    for ch in t:
        if ch not in _CROCKFORD_DECODE:
            raise MalformedRecoveryKey(f"Invalid Crockford character: {ch!r}")
    raw = _crockford_decode_str(data_str)
    # Verify checksum
    expected_chk = _rk_checksum(raw)
    if chk_str != expected_chk:
        raise MalformedRecoveryKey(
            "Recovery key checksum mismatch — possible transcription error."
        )
    return bytearray(raw)


# ---------------------------------------------------------------------------
# Slot ID
# ---------------------------------------------------------------------------

def new_slot_id() -> str:
    """Return 4 random Crockford base32 characters as a slot label.

    This is a display label only — it is NOT derived from the key.  Deriving
    it would create an oracle that could correlate a printed recovery key with
    a vault file without knowing the actual key.
    """
    rand = os.urandom(3)  # 24 bits → 4 * 5-bit groups with 4 bits spare
    n = int.from_bytes(rand, "big")
    chars = [_CROCKFORD_ALPHABET[(n >> (5 * i)) & 0x1F] for i in range(3, -1, -1)]
    return "".join(chars)


# ---------------------------------------------------------------------------
# DEK / vault-id helpers
# ---------------------------------------------------------------------------

def new_dek() -> bytearray:
    """Return a fresh 32-byte data-encryption key."""
    return bytearray(os.urandom(32))


def new_vault_id() -> bytes:
    """Return 16 random bytes to identify this vault instance."""
    return os.urandom(16)


def new_fmk() -> bytearray:
    """Return a fresh 32-byte File Master Key.

    The FMK is the stable root for whole-file encryption.  It lives inside the
    vault BODY rather than in a header slot, so that it survives the DEK
    rotation every credential operation performs -- see store.py's reserved-key
    section for why that matters.
    """
    return bytearray(os.urandom(FMK_BYTES))


def new_fmk_id() -> str:
    """Return 8 random Crockford base32 characters labelling an FMK generation.

    A label only, never derived from the key.  It goes in the PLAINTEXT header
    of every encrypted file so that rotation can tell generations apart without
    trial-unwrapping.  That makes it a correlation tag across artifacts the
    user may well publish -- accepted deliberately, and documented, because the
    alternative turns every open into a guess-and-check loop and blurs the one
    question rotation depends on.
    """
    return "".join(_CROCKFORD_ALPHABET[b & 0x1F] for b in os.urandom(8))


# ---------------------------------------------------------------------------
# Slot AAD domain separation
# ---------------------------------------------------------------------------

def slot_aad(vault_id: bytes, slot_type: str) -> bytes:
    """Return the AAD bytes for a wrapped-DEK slot.

    ``VAULT_MAGIC || version_byte || vault_id || b"|" || slot_type``

    This domain-separates slots so a wrapped DEK cannot be transplanted
    between slot types or between different vaults.
    """
    return VAULT_MAGIC + bytes([FORMAT_VERSION]) + vault_id + b"|" + slot_type.encode()


# ---------------------------------------------------------------------------
# Wrap / unwrap DEK (AES-256-GCM)
# ---------------------------------------------------------------------------

def wrap_dek(kek: bytes, dek: bytes, aad: bytes) -> tuple:
    """Wrap *dek* under *kek* with AES-256-GCM and *aad*.

    Returns ``(nonce, wrapped)`` where *nonce* is 12 bytes and *wrapped* is
    48 bytes (32 plaintext + 16 GCM tag).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(kek)
    wrapped = aesgcm.encrypt(nonce, dek, aad)  # returns ct || tag
    return nonce, wrapped


def unwrap_dek(kek: bytes, nonce: bytes, wrapped: bytes, aad: bytes) -> bytearray:
    """Unwrap a DEK.  Raises ``VaultTampered`` if authentication fails."""
    aesgcm = AESGCM(kek)
    try:
        return bytearray(aesgcm.decrypt(nonce, wrapped, aad))
    except Exception:
        raise VaultTampered(
            "DEK slot authentication failed — file may have been tampered with."
        ) from None


# ---------------------------------------------------------------------------
# Body seal / open (AES-256-GCM)
# ---------------------------------------------------------------------------

def seal_body(dek: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM under *dek*.

    Returns ``nonce || ciphertext || tag`` (12 + len(plaintext) + 16 bytes).
    A fresh random nonce is chosen on every call.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct_and_tag


def open_body(dek: bytes, body: bytes, aad: bytes) -> bytes:
    """Decrypt the output of ``seal_body``.  Raises ``VaultTampered`` on failure."""
    if len(body) < 12 + 16:
        raise VaultCorrupted("Body too short to contain nonce and GCM tag.")
    nonce = body[:12]
    ct_and_tag = body[12:]
    aesgcm = AESGCM(dek)
    try:
        return aesgcm.decrypt(nonce, ct_and_tag, aad)
    except Exception:
        raise VaultTampered(
            "Body authentication failed — file may have been tampered with."
        ) from None


# ---------------------------------------------------------------------------
# Envelope build / parse
# ---------------------------------------------------------------------------

def build_envelope(header: dict, dek: bytes, padded_plaintext: bytes) -> bytes:
    """Assemble a complete v2 LEVAULT envelope.

    ``header`` must be the dict that will be serialised into the envelope —
    it must already contain the slot entries (including nonce/wrapped_dek for
    each slot).  The caller is responsible for building the slots before
    calling this.

    Layout::

        offset 0   8 bytes  VAULT_MAGIC
        offset 8   1 byte   FORMAT_VERSION (0x02)
        offset 9   4 bytes  hdr_len (uint32 big-endian)
        offset 13  hdr_len  UTF-8 JSON (these exact bytes are the AAD)
        +          12 bytes nonce
        +          rest     ciphertext || 16-byte GCM tag
    """
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    hdr_len = len(header_bytes)
    if hdr_len > 65536:
        raise VaultCorrupted(f"Header too large: {hdr_len} bytes > 65536 limit.")
    prefix = VAULT_MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">I", hdr_len) + header_bytes
    # AAD for the body is the entire prefix (magic + version + hdr_len + header)
    aad = prefix
    body = seal_body(dek, padded_plaintext, aad)
    return prefix + body


def parse_envelope(data: bytes) -> tuple:
    """Parse a v2 LEVAULT envelope into ``(header_dict, aad_bytes, body_bytes)``.

    *aad_bytes* is the literal byte slice ``data[0 : 13 + hdr_len]`` — the
    caller MUST pass this verbatim to ``open_body``; never re-serialise the
    parsed header to reconstruct it.

    Raises ``VaultCorrupted`` for any structural problem.  Error messages are
    deliberately about "damaged file", never about wrong passwords.
    """
    if len(data) < 13:
        raise VaultCorrupted("Vault file is too short to be valid.")
    magic = data[:8]
    if magic != VAULT_MAGIC:
        raise VaultCorrupted(
            "Vault file has an unrecognised magic header — it may be corrupted "
            "or this is not a LEVAULT v2 file."
        )
    version = data[8]
    if version != FORMAT_VERSION:
        raise VaultCorrupted(
            f"Unsupported vault format version {version}; expected {FORMAT_VERSION}."
        )
    (hdr_len,) = struct.unpack(">I", data[9:13])
    if hdr_len > 65536:
        raise VaultCorrupted(
            f"Header length field {hdr_len} exceeds the 65536-byte hard cap."
        )
    # Minimum viable body: 12-byte nonce + 16-byte GCM tag
    min_total = 13 + hdr_len + 12 + 16
    if len(data) < min_total:
        raise VaultCorrupted(
            f"Vault file is truncated (need at least {min_total} bytes, have {len(data)})."
        )
    header_bytes = data[13 : 13 + hdr_len]
    aad_bytes = data[0 : 13 + hdr_len]  # the canonical AAD
    body_bytes = data[13 + hdr_len :]
    try:
        header_dict = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise VaultCorrupted(f"Vault header JSON is malformed: {exc}") from None
    return header_dict, aad_bytes, body_bytes


def is_v2(data: bytes) -> bool:
    """Return True iff *data* starts with the LEVAULT v2 magic bytes.

    Detection is a ``startswith`` check — never a JSON parse attempt.
    A v1 Fernet token is base64url-encoded and always starts with ``gAAAAA``,
    so the magic is unambiguous and cheap.
    """
    return data.startswith(VAULT_MAGIC)


# ---------------------------------------------------------------------------
# High-level helpers for building a complete v2 vault
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    """Standard base64 (URL-safe, no padding stripped — just regular b64url)."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def build_v2_vault(
    password: str,
    padded_plaintext: bytes,
    recovery_raw: Optional[bytes] = None,
    *,
    params: Optional[ScryptParams] = None,
) -> tuple:
    """Build a complete v2 envelope from scratch.

    Returns ``(envelope_bytes, dek, vault_id_bytes)``.

    If *recovery_raw* is given (20 bytes from ``new_recovery_key()``), a
    recovery slot is added.  If *params* is None, ``SCRYPT_DEFAULT`` is used.

    This function is a convenience for tests and for the store layer; the
    store layer (Lane 9) calls this during first-time creation or
    password-change flows.
    """
    if params is None:
        params = SCRYPT_DEFAULT
    validate_scrypt_params(params.n, params.r, params.p)

    vault_id = new_vault_id()
    vault_id_b64 = _b64(vault_id)
    dek = new_dek()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # --- password slot ---
    pw_salt = os.urandom(16)
    pw_kek = derive_password_kek(password, pw_salt, params)
    pw_aad = slot_aad(vault_id, "password")
    pw_nonce, pw_wrapped = wrap_dek(pw_kek, bytes(dek), pw_aad)

    slots = [
        {
            "type": "password",
            "kdf": {
                "name": "scrypt",
                "n": params.n,
                "r": params.r,
                "p": params.p,
                "salt": _b64(pw_salt),
            },
            "nonce": _b64(pw_nonce),
            "wrapped_dek": _b64(pw_wrapped),
        }
    ]

    # --- optional recovery slot ---
    if recovery_raw is not None:
        rk_salt = os.urandom(16)
        rk_kek = derive_recovery_kek(bytes(recovery_raw), rk_salt, vault_id)
        rk_aad = slot_aad(vault_id, "recovery")
        rk_nonce, rk_wrapped = wrap_dek(rk_kek, bytes(dek), rk_aad)
        slot_id = new_slot_id()
        slots.append(
            {
                "type": "recovery",
                "id": slot_id,
                "created": now,
                "kdf": {
                    "name": "hkdf-sha256",
                    "salt": _b64(rk_salt),
                    "info": "llm-env-vault/v2/recovery-kek",
                },
                "nonce": _b64(rk_nonce),
                "wrapped_dek": _b64(rk_wrapped),
            }
        )

    header = {
        "format": "llm-env-vault",
        "version": FORMAT_VERSION,
        "vault_id": vault_id_b64,
        "created": now,
        "cipher": "AES-256-GCM",
        "slots": slots,
    }

    envelope = build_envelope(header, bytes(dek), padded_plaintext)
    return envelope, dek, vault_id


def _structural_errors_are_corruption(func):
    """Turn a malformed header's raw KeyError/TypeError/ValueError into
    VaultCorrupted.

    Everything the open_* functions read out of `header` is attacker-controlled
    JSON -- this project's threat model explicitly grants filesystem write
    access, so a hostile or damaged file can omit any field, retype an int as a
    string, or hand back base64 that decodes to the wrong length. The vault
    stayed shut in every one of those cases even before this wrapper (the GCM
    tags see to that), so this is not a confidentiality fix. It is about not
    leaking a KeyError from the library's internals when the honest answer is
    "this file is damaged" -- an exception type that says the code trusted
    attacker-supplied structure and got surprised.

    Domain exceptions pass through untouched, including MalformedRecoveryKey,
    which subclasses ValueError and would otherwise be swallowed here.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (WrongPassword, WrongRecoveryKey, NoRecoverySlot,
                MalformedRecoveryKey, VaultCorrupted):
            raise  # VaultTampered arrives here too -- it subclasses VaultCorrupted
        except (KeyError, TypeError, IndexError, ValueError, AttributeError) as exc:
            raise VaultCorrupted(
                f"Vault header is malformed or incomplete "
                f"({type(exc).__name__}: {exc}). The file is damaged, or was "
                f"written by a different tool."
            ) from exc
    return wrapper


@_structural_errors_are_corruption
def open_v2_with_password(
    data: bytes,
    password: str,
) -> tuple:
    """Open a v2 envelope using the master password.

    Returns ``(plaintext_bytes, dek_bytes, header_dict)``.
    Raises ``WrongPassword``, ``VaultCorrupted``, or ``VaultTampered``.
    """
    header, aad, body = parse_envelope(data)
    vault_id = base64.urlsafe_b64decode(header["vault_id"] + "==")

    pw_slot = next(
        (s for s in header.get("slots", []) if s.get("type") == "password"),
        None,
    )
    if pw_slot is None:
        raise VaultCorrupted("Vault has no password slot.")

    kdf = pw_slot["kdf"]
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    validate_scrypt_params(n, r, p)
    pw_salt = base64.urlsafe_b64decode(kdf["salt"] + "==")
    params = ScryptParams(n=n, r=r, p=p)

    try:
        pw_kek = derive_password_kek(password, pw_salt, params)
    except Exception as exc:
        raise VaultCorrupted(f"KDF failure: {exc}") from exc

    pw_aad = slot_aad(vault_id, "password")
    nonce = base64.urlsafe_b64decode(pw_slot["nonce"] + "==")
    wrapped = base64.urlsafe_b64decode(pw_slot["wrapped_dek"] + "==")

    try:
        dek = unwrap_dek(pw_kek, nonce, wrapped, pw_aad)
    except VaultTampered:
        raise WrongPassword(
            "Incorrect master password (or the vault file is corrupted)."
        ) from None

    plaintext = open_body(bytes(dek), body, aad)
    return plaintext, dek, header


@_structural_errors_are_corruption
def open_v2_with_recovery(
    data: bytes,
    recovery_text: str,
) -> tuple:
    """Open a v2 envelope using the recovery key.

    Returns ``(plaintext_bytes, dek_bytes, header_dict)``.
    Raises ``MalformedRecoveryKey``, ``NoRecoverySlot``, ``WrongRecoveryKey``,
    ``VaultCorrupted``, or ``VaultTampered``.
    """
    recovery_raw = parse_recovery_key(recovery_text)  # validates checksum

    header, aad, body = parse_envelope(data)
    vault_id = base64.urlsafe_b64decode(header["vault_id"] + "==")

    rk_slot = next(
        (s for s in header.get("slots", []) if s.get("type") == "recovery"),
        None,
    )
    if rk_slot is None:
        raise NoRecoverySlot("This vault has no recovery slot.")

    kdf = rk_slot["kdf"]
    rk_salt = base64.urlsafe_b64decode(kdf["salt"] + "==")
    rk_kek = derive_recovery_kek(bytes(recovery_raw), rk_salt, vault_id)

    rk_aad = slot_aad(vault_id, "recovery")
    nonce = base64.urlsafe_b64decode(rk_slot["nonce"] + "==")
    wrapped = base64.urlsafe_b64decode(rk_slot["wrapped_dek"] + "==")

    try:
        dek = unwrap_dek(rk_kek, nonce, wrapped, rk_aad)
    except VaultTampered:
        raise WrongRecoveryKey(
            "Recovery key authentication failed."
        ) from None

    plaintext = open_body(bytes(dek), body, aad)
    return plaintext, dek, header


# ---------------------------------------------------------------------------
# File envelope (LEVFILE) — whole-file encryption
# ---------------------------------------------------------------------------
#
# Deliberately a PARALLEL implementation rather than a `magic=` parameter on
# build_envelope/parse_envelope. Those two encode vault semantics — the 64 KiB
# header cap, the slots array, the version byte that means "v2 vault" — and a
# caller passing the wrong constant would let a file envelope be parsed as a
# vault. Forty-odd lines of near-duplicate structure is cheaper than a
# parameter a bug can set wrong. What IS shared is everything below the
# framing: seal_body, open_body, wrap_dek, unwrap_dek are all magic-agnostic
# and already correct.
#
# slot_aad is NOT reused — it hardcodes VAULT_MAGIC. Files get their domain
# separation from the HKDF info string instead, which additionally binds the
# key-encryption key to the file's own id, so a wrapped DEK cannot be
# transplanted between two files sealed under the same FMK.
#
#   off  0           8       FILE_MAGIC
#   off  8           1       FILE_FORMAT_VERSION
#   off  9           4       hdr_len, uint32 big-endian, capped
#   off 13           hdr_len UTF-8 JSON header
#                            AAD = data[0 : 13 + hdr_len], the literal byte
#                            slice, passed verbatim to open_body and never
#                            re-serialised from the parsed dict
#   off 13+hdr_len   12      body nonce
#   +                N+16    ciphertext || GCM tag
#
# Inside the sealed body, so that the metadata is CONFIDENTIAL and not merely
# authenticated:
#
#   4 bytes   meta_len, uint32 big-endian, capped
#   meta_len  UTF-8 JSON meta
#   rest      the original file bytes, verbatim, unpadded
#
# No PKCS7 padding here. The vault body pads because Fernet's CBC leaked
# length in v1 and it was free to keep; a file's size is already visible from
# the length of the .levault itself, so padding would be a lie rather than a
# defence.

FILE_MAGIC: bytes = b"LEVFILE\x00"
FILE_FORMAT_VERSION: int = 1

# Header/meta caps. Both are checked BEFORE any allocation keyed off them:
# this project's threat model explicitly grants filesystem write access, so a
# hostile length field must not be able to OOM the MCP server. Same reasoning
# as validate_scrypt_params.
FILE_HDR_CAP: int = 8192
FILE_META_CAP: int = 4096

# AESGCM is one-shot — there is no streaming API — so an N-byte file costs
# roughly 4N transient bytes to encrypt (read, inner-frame concat, ciphertext,
# prefix concat) and ~3N more across verified read-back. At 16 MiB that peaks
# around 64 MiB, the same order as one scrypt run at n=2**16 which this server
# already does routinely; at 64 MiB it would be ~256 MiB in a long-lived
# process, which is not acceptable.
#
# Chunking was considered and rejected: a correct segmented AEAD needs
# counter-derived per-segment nonces, a final-segment marker to defeat
# truncation, and cross-file splice resistance, which is the most bug-prone
# code in the whole feature — and every artifact this exists for (.pem, .p12,
# kubeconfig, service-account JSON) is under 100 KiB. Capping rather than
# streaming is also what this module already does elsewhere.
MAX_FILE_PLAINTEXT_BYTES: int = 16 * 1024 * 1024
# Envelope overhead is 13 + hdr_len + 12 + 16 + 4 + meta_len; 64 KiB is a
# generous ceiling on all of it. INVARIANT: this must stay below
# trust._MAX_HASH_BYTES so that every .levault is always hashable and trust's
# drift detection never has a silent gap. Asserted in the test suite.
MAX_FILE_ENVELOPE_BYTES: int = MAX_FILE_PLAINTEXT_BYTES + 64 * 1024

_FILE_KEK_INFO: str = "llm-env-vault/file/v1/kek"


class FileEnvelopeCorrupted(VaultCorrupted):
    """Structurally invalid .levault file (bad magic, truncated, illegal
    header). Subclasses VaultCorrupted so existing handlers still catch it."""


class FileEnvelopeTampered(VaultTampered):
    """AESGCM authentication failed for a .levault's body or wrapped DEK.

    Note what this must NEVER be reported as: a wrong password. The password
    is not what opens a file envelope — the file master key is — so "wrong
    password" would send the user to fix something that isn't broken. The
    honest statement is that the file does not belong to this vault, or was
    modified after it was written."""


def _file_structural_errors_are_corruption(func):
    """File-envelope twin of _structural_errors_are_corruption.

    Everything read out of a file header is attacker-controlled JSON. The
    envelope stays shut regardless (the GCM tags see to that), so this is not
    a confidentiality fix — it is about not leaking a KeyError from this
    module's internals when the honest answer is "this file is damaged".
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except VaultCorrupted:
            raise  # FileEnvelopeCorrupted/Tampered arrive here too
        except (KeyError, TypeError, IndexError, ValueError, AttributeError) as exc:
            raise FileEnvelopeCorrupted(
                f"Encrypted file header is malformed or incomplete "
                f"({type(exc).__name__}: {exc}). The file is damaged, or was "
                f"written by a different tool."
            ) from exc
    return wrapper


def new_file_id() -> bytes:
    """Return 16 random bytes identifying one encrypted file."""
    return os.urandom(16)


def derive_file_kek(fmk: bytes, salt: bytes, file_id: bytes) -> bytes:
    """Derive a 32-byte key-encryption key for one file from the FMK.

    HKDF-SHA256, not scrypt, for exactly the reason given at
    derive_recovery_kek: the input is 256 bits of machine-generated entropy,
    so there is no dictionary to grind and a slow KDF would buy nothing.

    The file's own id goes into the info string, which binds the KEK to that
    one file: copying a wrapped_dek from one envelope into another under the
    same FMK produces a KEK that cannot unwrap it.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=(_FILE_KEK_INFO + "/").encode("ascii") + file_id,
    )
    return hkdf.derive(fmk)


def _frame_inner(meta: dict, plaintext: bytes) -> bytes:
    """``meta_len || meta JSON || file bytes`` — the sealed inner layout."""
    meta_bytes = json.dumps(meta, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(meta_bytes) > FILE_META_CAP:
        raise FileEnvelopeCorrupted(
            f"File metadata is {len(meta_bytes)} bytes > {FILE_META_CAP} limit."
        )
    return struct.pack(">I", len(meta_bytes)) + meta_bytes + plaintext


def _unframe_inner(inner: bytes) -> tuple:
    """Split the sealed inner layout into ``(meta_dict, file_bytes)``."""
    if len(inner) < 4:
        raise FileEnvelopeCorrupted("Encrypted file contents are truncated.")
    (meta_len,) = struct.unpack(">I", inner[:4])
    if meta_len > FILE_META_CAP:
        raise FileEnvelopeCorrupted(
            f"File metadata length {meta_len} exceeds the {FILE_META_CAP}-byte cap."
        )
    if 4 + meta_len > len(inner):
        raise FileEnvelopeCorrupted(
            "File metadata length runs past the end of the decrypted contents."
        )
    try:
        meta = json.loads(inner[4:4 + meta_len].decode("utf-8"))
    except Exception as exc:
        raise FileEnvelopeCorrupted(f"File metadata JSON is malformed: {exc}") from None
    if not isinstance(meta, dict):
        raise FileEnvelopeCorrupted("File metadata is not a JSON object.")
    return meta, inner[4 + meta_len:]


def build_file_envelope(fmk: bytes, fmk_id: str, plaintext: bytes, meta: dict) -> bytes:
    """Seal *plaintext* and *meta* into a complete LEVFILE envelope.

    A fresh file DEK is minted on every call — never reuse one across two
    seals, even with fresh nonces. Callers who re-encrypt an existing file
    (rotation) get a new DEK for free by going through here.
    """
    if len(plaintext) > MAX_FILE_PLAINTEXT_BYTES:
        raise FileEnvelopeCorrupted(
            f"File is {len(plaintext)} bytes, over the "
            f"{MAX_FILE_PLAINTEXT_BYTES} byte limit for vault encryption."
        )

    file_id = new_file_id()
    salt = os.urandom(16)
    dek = new_dek()
    kek = derive_file_kek(fmk, salt, file_id)
    wrap_nonce, wrapped = wrap_dek(kek, bytes(dek), _file_wrap_aad(file_id, fmk_id))

    header = {
        "format": "llm-env-vault-file",
        "version": FILE_FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "file_id": _b64(file_id),
        "fmk_id": fmk_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kdf": {"name": "hkdf-sha256", "salt": _b64(salt), "info": _FILE_KEK_INFO},
        # wrap_nonce, not nonce: there are two nonces in this format and the
        # other one lives in the body at 13+hdr_len. Naming them apart is the
        # cheapest way to stop someone eventually swapping them.
        "wrap_nonce": _b64(wrap_nonce),
        "wrapped_dek": _b64(wrapped),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(header_bytes) > FILE_HDR_CAP:
        raise FileEnvelopeCorrupted(
            f"File header is {len(header_bytes)} bytes > {FILE_HDR_CAP} limit."
        )

    prefix = (FILE_MAGIC + bytes([FILE_FORMAT_VERSION])
              + struct.pack(">I", len(header_bytes)) + header_bytes)
    body = seal_body(bytes(dek), _frame_inner(meta, plaintext), prefix)
    return prefix + body


def _file_wrap_aad(file_id: bytes, fmk_id: str) -> bytes:
    """AAD for a file's wrapped DEK.

    ``FILE_MAGIC || version || file_id || b"|" || fmk_id``

    Binds the wrapped DEK to this file AND this key generation, so neither a
    cross-file transplant nor a header that lies about which generation sealed
    it can survive. The header's own bytes separately cover the body via the
    envelope AAD.
    """
    return (FILE_MAGIC + bytes([FILE_FORMAT_VERSION]) + file_id + b"|"
            + fmk_id.encode("utf-8"))


def parse_file_envelope(data: bytes) -> tuple:
    """Parse a LEVFILE envelope into ``(header_dict, aad_bytes, body_bytes)``.

    Structural only — no key material involved, nothing decrypted. *aad_bytes*
    is the literal slice ``data[0 : 13 + hdr_len]``; callers MUST pass it to
    open_body verbatim and never re-serialise the parsed header to rebuild it.
    """
    if len(data) > MAX_FILE_ENVELOPE_BYTES:
        raise FileEnvelopeCorrupted(
            f"Encrypted file is {len(data)} bytes, over the "
            f"{MAX_FILE_ENVELOPE_BYTES} byte limit."
        )
    if len(data) < 13:
        raise FileEnvelopeCorrupted("Encrypted file is too short to be valid.")
    if data[:8] != FILE_MAGIC:
        raise FileEnvelopeCorrupted(
            "This file is not a llm-env-vault encrypted file (unrecognised header)."
        )
    version = data[8]
    if version != FILE_FORMAT_VERSION:
        raise FileEnvelopeCorrupted(
            f"Unsupported encrypted-file format version {version}; "
            f"expected {FILE_FORMAT_VERSION}. A newer llm-env-vault wrote this file."
        )
    (hdr_len,) = struct.unpack(">I", data[9:13])
    if hdr_len > FILE_HDR_CAP:
        raise FileEnvelopeCorrupted(
            f"Header length field {hdr_len} exceeds the {FILE_HDR_CAP}-byte hard cap."
        )
    min_total = 13 + hdr_len + 12 + 16  # nonce + GCM tag
    if len(data) < min_total:
        raise FileEnvelopeCorrupted(
            f"Encrypted file is truncated (need at least {min_total} bytes, "
            f"have {len(data)})."
        )
    try:
        header = json.loads(data[13:13 + hdr_len].decode("utf-8"))
    except Exception as exc:
        raise FileEnvelopeCorrupted(f"File header JSON is malformed: {exc}") from None
    if not isinstance(header, dict):
        raise FileEnvelopeCorrupted("File header is not a JSON object.")
    return header, data[0:13 + hdr_len], data[13 + hdr_len:]


def _b64d_exact(text, expected_len: int, what: str) -> bytes:
    """Decode a header base64 field and require an exact byte length."""
    if not isinstance(text, str):
        raise FileEnvelopeCorrupted(f"File header field {what} is not a string.")
    try:
        raw = base64.urlsafe_b64decode(text + "==")
    except Exception:
        raise FileEnvelopeCorrupted(f"File header field {what} is not valid base64.") from None
    if len(raw) != expected_len:
        raise FileEnvelopeCorrupted(
            f"File header field {what} is {len(raw)} bytes, expected {expected_len}."
        )
    return raw


def _validate_file_header(header: dict) -> tuple:
    """Check every attacker-controlled header field before it is used.

    Returns ``(file_id, fmk_id, salt, wrap_nonce, wrapped_dek)``.

    In particular the KDF name and info are compared against hardcoded
    constants rather than trusted: feeding an arbitrary header string into
    HKDF as the info parameter would let a crafted file steer key derivation.
    """
    kdf = header.get("kdf")
    if not isinstance(kdf, dict):
        raise FileEnvelopeCorrupted("File header has no kdf section.")
    if kdf.get("name") != "hkdf-sha256":
        raise FileEnvelopeCorrupted(
            f"Unsupported file KDF {kdf.get('name')!r}; expected hkdf-sha256."
        )
    if kdf.get("info") != _FILE_KEK_INFO:
        raise FileEnvelopeCorrupted("File header declares an unexpected KDF info string.")

    fmk_id = header.get("fmk_id")
    if not isinstance(fmk_id, str) or not fmk_id:
        raise FileEnvelopeCorrupted("File header has no usable fmk_id.")

    return (
        _b64d_exact(header.get("file_id"), 16, "file_id"),
        fmk_id,
        _b64d_exact(kdf.get("salt"), 16, "kdf.salt"),
        _b64d_exact(header.get("wrap_nonce"), 12, "wrap_nonce"),
        _b64d_exact(header.get("wrapped_dek"), 48, "wrapped_dek"),
    )


@_file_structural_errors_are_corruption
def open_file_envelope(fmk: bytes, data: bytes) -> tuple:
    """Open a LEVFILE envelope. Returns ``(file_bytes, meta_dict, header)``.

    *fmk* is the raw 32-byte key for the generation the header names — the
    caller resolves the generation, because the shape of the stored key record
    is the store layer's business, not this module's.

    Raises FileEnvelopeCorrupted for a structurally bad file and
    FileEnvelopeTampered when authentication fails.
    """
    header, aad, body = parse_file_envelope(data)
    file_id, fmk_id, salt, wrap_nonce, wrapped = _validate_file_header(header)

    kek = derive_file_kek(fmk, salt, file_id)
    try:
        dek = unwrap_dek(kek, wrap_nonce, wrapped, _file_wrap_aad(file_id, fmk_id))
    except VaultTampered:
        raise FileEnvelopeTampered(
            "This encrypted file does not belong to this vault, or has been "
            "modified since it was written."
        ) from None

    try:
        inner = open_body(bytes(dek), body, aad)
    except VaultTampered:
        raise FileEnvelopeTampered(
            "This encrypted file has been modified since it was written."
        ) from None

    meta, file_bytes = _unframe_inner(inner)
    return file_bytes, meta, header


def is_file_envelope(data: bytes) -> bool:
    """True iff *data* starts with the LEVFILE magic bytes.

    A startswith check, never a JSON parse — the same discipline as is_v2, and
    the reason the two formats can never be confused for one another.
    """
    return data.startswith(FILE_MAGIC)


@_file_structural_errors_are_corruption
def file_envelope_info(data: bytes) -> dict:
    """Non-secret facts about a .levault file. Decrypts nothing.

    Note that the plaintext size is NOT recoverable exactly: meta_len lives
    inside the ciphertext, so all this can offer is an upper bound. That is
    deliberate — an authoritative size field in the header would be a second
    source of truth to keep consistent, for a number the caller can get from
    the registry or by opening the file.
    """
    header, aad, body = parse_file_envelope(data)
    file_id, fmk_id, _salt, _nonce, _wrapped = _validate_file_header(header)
    return {
        "version": header.get("version"),
        "file_id": _b64(file_id),
        "fmk_id": fmk_id,
        "created": header.get("created"),
        "envelope_size": len(data),
        # body is nonce(12) || ct || tag(16); ct covers meta_len(4) + meta + file
        "max_plaintext_size": max(0, len(body) - 12 - 16 - 4),
    }
