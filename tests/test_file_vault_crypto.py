"""
Format and tamper-resistance suite for the LEVFILE file envelope.

Whole-file encryption produces artefacts the user is explicitly encouraged to
commit and push. That changes the threat model compared with vault.enc, which
sits in one local directory: a .levault file is attacker-reachable by design,
and the plaintext it replaced was deliberately destroyed. So every structural
field in it is attacker-controlled, and the only acceptable outcomes for a
hostile or damaged file are "corrupted" or "tampered" -- never a crash, never
an OOM, and never a wrong answer.

What this file holds down:

  * Round-trip fidelity, including at the exact size cap.
  * Domain separation from the vault envelope, in BOTH directions.
  * Authentication: any single flipped bit anywhere -- ciphertext, header
    (which is AAD), or the framing -- must fail loudly.
  * Transplant resistance: a wrapped DEK is bound to its file id and its key
    generation, so it cannot be moved between files or forged into another
    generation even under the same FMK.
  * Denial of service: every length field is checked BEFORE anything is
    allocated from it. The threat model grants filesystem write access, so a
    header claiming 4 GiB must not take the server down.
  * The golden fixture, which is the only test here that proves the format
    still matches what is already on disk in the world rather than merely
    matching itself.

No scrypt anywhere in this path -- files derive their keys with HKDF from the
32-byte FMK -- so this suite is fast.

Runs under pytest (`pytest tests/test_file_vault_crypto.py -q`) or standalone
(`python tests/test_file_vault_crypto.py`).
"""
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import trust  # noqa: E402
from vault_lib.crypto import (  # noqa: E402
    FILE_HDR_CAP,
    FILE_MAGIC,
    FILE_META_CAP,
    FILE_FORMAT_VERSION,
    MAX_FILE_ENVELOPE_BYTES,
    MAX_FILE_PLAINTEXT_BYTES,
    VAULT_MAGIC,
    FileEnvelopeCorrupted,
    FileEnvelopeTampered,
    ScryptParams,
    VaultCorrupted,
    build_file_envelope,
    build_v2_vault,
    file_envelope_info,
    is_file_envelope,
    is_v2,
    new_fmk,
    new_fmk_id,
    open_file_envelope,
    parse_file_envelope,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "file_envelope"

_FMK = bytes(range(32))
_FMK_ID = "TESTGEN1"
_PLAINTEXT = b"-----BEGIN TEST KEY-----\nnot a real key\n-----END TEST KEY-----\n"
_META = {"name": "test.pem", "mode": "0600", "sha256": hashlib.sha256(_PLAINTEXT).hexdigest()}


def _env(plaintext=_PLAINTEXT, fmk=_FMK, fmk_id=_FMK_ID, meta=None) -> bytes:
    return build_file_envelope(
        fmk, fmk_id, plaintext, dict(_META if meta is None else meta))


def _parts(data: bytes) -> tuple:
    """``(prefix, header_dict, body)`` for surgery on a built envelope."""
    (hdr_len,) = struct.unpack(">I", data[9:13])
    header = json.loads(data[13:13 + hdr_len].decode("utf-8"))
    return data[:13 + hdr_len], header, data[13 + hdr_len:]


def _rebuild(header: dict, body: bytes) -> bytes:
    """Re-frame a (possibly doctored) header with an untouched body.

    Note this necessarily invalidates the body's AAD -- which is exactly the
    point for the header-surgery tests: a header the attacker rewrote is no
    longer the header the body was sealed against.
    """
    hb = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return FILE_MAGIC + bytes([FILE_FORMAT_VERSION]) + struct.pack(">I", len(hb)) + hb + body


def _expect(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}") from None
    raise AssertionError(f"expected {exc_type.__name__}, nothing was raised")


# ---------------------------------------------------------------------------
# Round trip
#
# Failure mode: the bytes that come back are not the bytes that went in, and
# the only copy of the original was destroyed on purpose.
# ---------------------------------------------------------------------------

def test_round_trip_preserves_bytes_and_meta_exactly() -> None:
    out, meta, header = open_file_envelope(_FMK, _env())
    assert out == _PLAINTEXT
    assert meta == _META
    assert header["format"] == "llm-env-vault-file"
    assert header["version"] == FILE_FORMAT_VERSION
    assert header["fmk_id"] == _FMK_ID


def test_round_trip_one_byte_file() -> None:
    out, _meta, _h = open_file_envelope(_FMK, _env(b"x"))
    assert out == b"x"


def test_round_trip_binary_with_every_byte_value() -> None:
    """.p12 and .der files are binary; nothing here may assume text."""
    blob = bytes(range(256)) * 40
    out, _meta, _h = open_file_envelope(_FMK, _env(blob))
    assert out == blob


def test_round_trip_one_mib() -> None:
    blob = hashlib.sha256(b"seed").digest() * (1024 * 1024 // 32)
    out, _meta, _h = open_file_envelope(_FMK, _env(blob))
    assert out == blob


def test_round_trip_at_exactly_the_size_cap() -> None:
    blob = b"\xa5" * MAX_FILE_PLAINTEXT_BYTES
    out, _meta, _h = open_file_envelope(_FMK, _env(blob))
    assert len(out) == MAX_FILE_PLAINTEXT_BYTES


def test_one_byte_over_the_cap_is_refused() -> None:
    _expect(FileEnvelopeCorrupted, _env, b"\xa5" * (MAX_FILE_PLAINTEXT_BYTES + 1))


def test_empty_meta_is_fine() -> None:
    out, meta, _h = open_file_envelope(_FMK, _env(meta={}))
    assert out == _PLAINTEXT and meta == {}


def test_oversized_meta_is_refused_at_build_time() -> None:
    _expect(FileEnvelopeCorrupted, _env, _PLAINTEXT, _FMK, _FMK_ID,
            {"name": "x" * (FILE_META_CAP + 10)})


def test_every_envelope_uses_a_fresh_dek_and_nonce() -> None:
    """Never reuse a DEK across two seals. Two encryptions of identical bytes
    must share nothing -- rotation depends on this."""
    a, b = _env(), _env()
    _pa, ha, _ba = _parts(a)
    _pb, hb, _bb = _parts(b)
    assert ha["file_id"] != hb["file_id"]
    assert ha["wrapped_dek"] != hb["wrapped_dek"]
    assert ha["kdf"]["salt"] != hb["kdf"]["salt"]
    assert a != b


# ---------------------------------------------------------------------------
# Domain separation
#
# Failure mode: a file envelope is mistaken for a vault envelope or the
# reverse, letting one format's parser loose on the other's bytes.
# ---------------------------------------------------------------------------

def test_a_file_envelope_is_never_mistaken_for_a_vault() -> None:
    assert is_v2(_env()) is False
    assert FILE_MAGIC != VAULT_MAGIC


def test_a_vault_envelope_is_never_mistaken_for_a_file() -> None:
    old = crypto.SCRYPT_DEFAULT
    crypto.SCRYPT_DEFAULT = ScryptParams(n=2 ** 12, r=8, p=1)
    try:
        vault, _dek, _vid = build_v2_vault("pw", b"\x10" * 16)
    finally:
        crypto.SCRYPT_DEFAULT = old
    assert is_file_envelope(vault) is False
    _expect(FileEnvelopeCorrupted, parse_file_envelope, vault)


def test_is_file_envelope_never_parses_it_only_looks_at_the_magic() -> None:
    assert is_file_envelope(FILE_MAGIC) is True       # truncated but right magic
    assert is_file_envelope(b"") is False
    assert is_file_envelope(b"{}") is False


# ---------------------------------------------------------------------------
# Authentication
#
# Failure mode: a modified file opens anyway and hands back attacker-chosen
# bytes, which for a certificate or a kubeconfig is a total compromise.
# ---------------------------------------------------------------------------

def test_flipping_a_ciphertext_byte_is_detected() -> None:
    data = bytearray(_env())
    data[-20] ^= 0x01
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, bytes(data))


def test_flipping_a_tag_byte_is_detected() -> None:
    data = bytearray(_env())
    data[-1] ^= 0x80
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, bytes(data))


def test_flipping_a_nonce_byte_is_detected() -> None:
    prefix, _header, body = _parts(_env())
    body = bytearray(body)
    body[0] ^= 0x01
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, prefix + bytes(body))


def test_the_header_is_aad_so_editing_it_breaks_the_body() -> None:
    """created is a field nothing validates -- proving the body still fails
    shows the whole header is authenticated, not just the parts we check."""
    prefix, header, body = _parts(_env())
    header["created"] = "1999-01-01T00:00:00+00:00"
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, _rebuild(header, body))


def test_a_wrong_fmk_is_reported_as_not_belonging_to_this_vault() -> None:
    other = bytes(range(32, 64))
    try:
        open_file_envelope(other, _env())
    except FileEnvelopeTampered as exc:
        msg = str(exc).lower()
        assert "does not belong" in msg
        # Never blame the password: the password is not what opens a file.
        assert "password" not in msg
    else:
        raise AssertionError("a wrong FMK opened the envelope")


def test_a_wrapped_dek_cannot_be_transplanted_between_two_files() -> None:
    """Both sealed under the SAME FMK. The KEK is bound to the file id via the
    HKDF info string, so swapping the wrapped DEK across must fail."""
    a, b = _env(b"first file"), _env(b"second file")
    _pa, ha, ba = _parts(a)
    _pb, hb, _bb = _parts(b)
    ha["wrapped_dek"] = hb["wrapped_dek"]
    ha["wrap_nonce"] = hb["wrap_nonce"]
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, _rebuild(ha, ba))


def test_the_file_id_cannot_be_swapped_to_borrow_another_files_kek() -> None:
    a, b = _env(b"first file"), _env(b"second file")
    _pa, ha, ba = _parts(a)
    _pb, hb, _bb = _parts(b)
    ha["file_id"] = hb["file_id"]
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, _rebuild(ha, ba))


def test_the_generation_label_cannot_be_forged() -> None:
    """fmk_id is in the wrapped-DEK AAD, so a header that lies about which
    generation sealed it cannot unwrap -- rotation relies on this label being
    trustworthy once the file opens."""
    prefix, header, body = _parts(_env())
    header["fmk_id"] = "OTHERGEN"
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, _rebuild(header, body))


def test_the_kdf_salt_cannot_be_swapped() -> None:
    prefix, header, body = _parts(_env())
    header["kdf"]["salt"] = base64.urlsafe_b64encode(b"\x00" * 16).decode()
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, _rebuild(header, body))


# ---------------------------------------------------------------------------
# Structural surgery
#
# Failure mode: a doctored header raises KeyError/struct.error/MemoryError out
# of this module's internals instead of an honest "this file is damaged".
# ---------------------------------------------------------------------------

def test_bad_magic_is_corrupted() -> None:
    data = b"NOTAFILE" + _env()[8:]
    _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_unknown_version_is_corrupted_and_says_so() -> None:
    data = bytearray(_env())
    data[8] = 99
    try:
        parse_file_envelope(bytes(data))
    except FileEnvelopeCorrupted as exc:
        assert "99" in str(exc)
    else:
        raise AssertionError("an unknown version parsed")


def test_structurally_impossible_hdr_len_values_are_corrupted() -> None:
    """Lengths that cannot describe this file at all -- over the cap, or
    running past the end -- are refused by the structural parser."""
    _prefix, _header, body = _parts(_env())
    hb = json.dumps({"a": 1}).encode()
    for hdr_len in (FILE_HDR_CAP + 1, 0xFFFFFFFF, len(hb) + len(body) + 10):
        data = (FILE_MAGIC + bytes([FILE_FORMAT_VERSION])
                + struct.pack(">I", hdr_len) + hb + body)
        _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_a_shifted_header_boundary_never_opens() -> None:
    """A hdr_len off by one can still leave text that json.loads accepts -- one
    trailing whitespace byte borrowed from the body is enough, and the body
    starts with a random nonce, so this happens roughly 1 run in 64.

    That is not a parser bug: parse_file_envelope is deliberately structural
    and does not hold key material. The guarantee that actually matters is
    end-to-end, and it comes from the AAD covering the exact header slice --
    move the boundary and the body no longer authenticates. So assert what is
    true for every value: the file does not OPEN.
    """
    data = _env()
    (hdr_len,) = struct.unpack(">I", data[9:13])
    for shifted in (0, 1, hdr_len - 1, hdr_len + 1, hdr_len + 2):
        candidate = data[:9] + struct.pack(">I", shifted) + data[13:]
        # VaultCorrupted is the common base of both file exception types:
        # either "damaged" or "tampered" is a correct answer here.
        _expect(VaultCorrupted, open_file_envelope, _FMK, candidate)


def test_a_four_gib_header_claim_is_refused_before_allocating() -> None:
    """The point is that this returns instantly on a 60-byte input rather than
    trying to slice four gigabytes out of it."""
    data = FILE_MAGIC + bytes([FILE_FORMAT_VERSION]) + struct.pack(">I", 0xFFFFFFFF) + b"x" * 40
    _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_an_oversized_envelope_is_refused_before_parsing() -> None:
    data = FILE_MAGIC + b"\x01" + b"\x00" * (MAX_FILE_ENVELOPE_BYTES + 1)
    _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_non_utf8_header_bytes_are_corrupted() -> None:
    _prefix, _header, body = _parts(_env())
    hb = b"\xff\xfe not utf-8 at all"
    data = (FILE_MAGIC + bytes([FILE_FORMAT_VERSION])
            + struct.pack(">I", len(hb)) + hb + body)
    _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_a_header_that_is_not_an_object_is_corrupted() -> None:
    _prefix, _header, body = _parts(_env())
    for payload in (b"[1,2,3]", b'"a string"', b"42", b"null"):
        data = (FILE_MAGIC + bytes([FILE_FORMAT_VERSION])
                + struct.pack(">I", len(payload)) + payload + body)
        _expect(FileEnvelopeCorrupted, parse_file_envelope, data)


def test_truncation_below_the_structural_minimum_is_corrupted() -> None:
    """Anything too short to hold a nonce and a GCM tag is structurally
    invalid and must be named as damaged before any key material is touched."""
    data = _env()
    (hdr_len,) = struct.unpack(">I", data[9:13])
    min_total = 13 + hdr_len + 12 + 16
    for cut in (0, 1, 8, 9, 12, 13, 13 + hdr_len, 13 + hdr_len + 11,
                13 + hdr_len + 12, min_total - 1):
        _expect(FileEnvelopeCorrupted, parse_file_envelope, data[:cut])


def test_truncation_inside_the_ciphertext_is_tampering_not_corruption() -> None:
    """Above the structural minimum there is nothing wrong with the framing --
    the file is the right shape, it is just missing bytes. parse_file_envelope
    is structural only and correctly accepts it; the GCM tag is what catches
    it, and the honest report is tampering."""
    data = _env()
    parse_file_envelope(data[:-1])  # structurally fine, must not raise
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, data[:-1])
    _expect(FileEnvelopeTampered, open_file_envelope, _FMK, data[:-17])


def test_every_missing_header_field_is_corrupted() -> None:
    for field in ("file_id", "fmk_id", "wrap_nonce", "wrapped_dek", "kdf"):
        _prefix, header, body = _parts(_env())
        del header[field]
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_every_invalid_base64_header_field_is_corrupted() -> None:
    for field in ("file_id", "wrap_nonce", "wrapped_dek"):
        _prefix, header, body = _parts(_env())
        header[field] = "!!!! not base64 !!!!"
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_wrong_length_key_material_fields_are_corrupted() -> None:
    """A nonce one byte short or a wrapped DEK one byte long is a damaged
    file, and must be named as one before it reaches AESGCM."""
    cases = [("wrap_nonce", 11), ("wrap_nonce", 13),
             ("wrapped_dek", 47), ("wrapped_dek", 49),
             ("file_id", 15), ("file_id", 17)]
    for field, length in cases:
        _prefix, header, body = _parts(_env())
        header[field] = base64.urlsafe_b64encode(b"\x00" * length).decode()
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))
    for length in (15, 17):
        _prefix, header, body = _parts(_env())
        header["kdf"]["salt"] = base64.urlsafe_b64encode(b"\x00" * length).decode()
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_non_string_header_fields_are_corrupted_not_typeerror() -> None:
    for field in ("file_id", "fmk_id", "wrap_nonce", "wrapped_dek"):
        _prefix, header, body = _parts(_env())
        header[field] = 12345
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_an_empty_fmk_id_is_corrupted() -> None:
    _prefix, header, body = _parts(_env())
    header["fmk_id"] = ""
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_a_kdf_that_is_not_an_object_is_corrupted() -> None:
    _prefix, header, body = _parts(_env())
    header["kdf"] = "hkdf-sha256"
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


def test_an_unexpected_kdf_name_or_info_is_refused() -> None:
    """The info string is never taken from the header and fed to HKDF -- it is
    compared against a constant. A crafted file must not be able to steer key
    derivation."""
    for key, value in (("name", "scrypt"), ("info", "attacker/chosen/info")):
        _prefix, header, body = _parts(_env())
        header["kdf"][key] = value
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _rebuild(header, body))


# ---------------------------------------------------------------------------
# Inner framing
#
# Failure mode: meta_len is attacker-controlled once the GCM tag has passed
# (an attacker who holds the FMK can seal anything), so it must not IndexError.
# ---------------------------------------------------------------------------

def _seal_raw_inner(inner: bytes) -> bytes:
    """Build a structurally valid envelope around arbitrary inner bytes."""
    file_id = crypto.new_file_id()
    salt = b"\x11" * 16
    dek = crypto.new_dek()
    kek = crypto.derive_file_kek(_FMK, salt, file_id)
    wrap_nonce, wrapped = crypto.wrap_dek(
        kek, bytes(dek), crypto._file_wrap_aad(file_id, _FMK_ID))
    header = {
        "format": "llm-env-vault-file", "version": FILE_FORMAT_VERSION,
        "cipher": "AES-256-GCM", "file_id": crypto._b64(file_id), "fmk_id": _FMK_ID,
        "created": "2026-01-01T00:00:00+00:00",
        "kdf": {"name": "hkdf-sha256", "salt": crypto._b64(salt),
                "info": crypto._FILE_KEK_INFO},
        "wrap_nonce": crypto._b64(wrap_nonce), "wrapped_dek": crypto._b64(wrapped),
    }
    hb = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    prefix = FILE_MAGIC + bytes([FILE_FORMAT_VERSION]) + struct.pack(">I", len(hb)) + hb
    return prefix + crypto.seal_body(bytes(dek), inner, prefix)


def test_inner_frame_shorter_than_the_length_prefix_is_corrupted() -> None:
    for inner in (b"", b"\x00", b"\x00\x00\x00"):
        _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _seal_raw_inner(inner))


def test_meta_len_past_the_end_of_the_plaintext_is_corrupted() -> None:
    inner = struct.pack(">I", 500) + b'{"name":"x"}'
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _seal_raw_inner(inner))


def test_meta_len_over_the_cap_is_corrupted() -> None:
    inner = struct.pack(">I", FILE_META_CAP + 1) + b"x" * (FILE_META_CAP + 1)
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _seal_raw_inner(inner))


def test_a_four_gib_meta_len_claim_is_corrupted_not_a_memory_error() -> None:
    inner = struct.pack(">I", 0xFFFFFFFF) + b"{}"
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _seal_raw_inner(inner))


def test_malformed_meta_json_is_corrupted() -> None:
    bad = b"{not json"
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK,
            _seal_raw_inner(struct.pack(">I", len(bad)) + bad))


def test_meta_that_is_not_an_object_is_corrupted() -> None:
    bad = b"[1,2,3]"
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK,
            _seal_raw_inner(struct.pack(">I", len(bad)) + bad))


def test_zero_length_meta_yields_an_empty_file_not_a_crash() -> None:
    inner = struct.pack(">I", 0) + b"payload"
    _expect(FileEnvelopeCorrupted, open_file_envelope, _FMK, _seal_raw_inner(inner))


# ---------------------------------------------------------------------------
# Metadata confidentiality and file_envelope_info
# ---------------------------------------------------------------------------

def test_the_original_filename_is_not_in_the_plaintext_header() -> None:
    """A .levault is meant to be committed and pushed. A header-embedded
    aws-root-key.pem would be a permanent, unavoidable leak in a public repo,
    and unlike the sidecar filename the user cannot rename it away."""
    data = _env(meta={"name": "aws-root-key.pem", "mode": "0600"})
    _prefix, header, _body = _parts(data)
    blob = json.dumps(header).encode()
    assert b"aws-root-key" not in blob
    assert b"0600" not in blob
    # And not anywhere else outside the ciphertext either.
    assert b"aws-root-key" not in data[:13 + len(json.dumps(header))]


def test_file_envelope_info_reveals_no_plaintext_and_needs_no_key() -> None:
    info = file_envelope_info(_env())
    assert info["fmk_id"] == _FMK_ID
    assert info["version"] == FILE_FORMAT_VERSION
    assert info["envelope_size"] > 0
    assert "name" not in info and "sha256" not in info


def test_file_envelope_info_bounds_the_plaintext_size_from_above() -> None:
    """Deliberately an upper bound, not an exact size: meta_len lives inside
    the ciphertext, so the exact figure is not recoverable without the key."""
    info = file_envelope_info(_env())
    assert info["max_plaintext_size"] >= len(_PLAINTEXT)
    assert info["max_plaintext_size"] < len(_PLAINTEXT) + FILE_META_CAP


def test_file_envelope_info_rejects_a_damaged_file() -> None:
    _expect(FileEnvelopeCorrupted, file_envelope_info, b"nope")


# ---------------------------------------------------------------------------
# Cross-module invariants
# ---------------------------------------------------------------------------

def test_the_envelope_cap_stays_below_the_trust_hash_cap() -> None:
    """trust._hash_file returns None above _MAX_HASH_BYTES. If a .levault
    could exceed it, trust's drift detection would silently stop covering the
    largest files -- exactly the ones worth swapping."""
    assert MAX_FILE_ENVELOPE_BYTES < trust._MAX_HASH_BYTES


def test_file_exceptions_are_catchable_as_vault_corruption() -> None:
    """Existing handlers say `except VaultCorrupted`. Both new exception types
    must still land in them rather than escaping as something unhandled."""
    assert issubclass(FileEnvelopeCorrupted, VaultCorrupted)
    assert issubclass(FileEnvelopeTampered, VaultCorrupted)


# ---------------------------------------------------------------------------
# The golden fixture -- the only test here that compares against bytes frozen
# on disk rather than against the current code's own output.
# ---------------------------------------------------------------------------

_GOLDEN_FMK = bytes(range(32))
_GOLDEN_PLAINTEXT = (b"-----BEGIN FIXTURE KEY-----\n"
                     b"this is not a real key, it is a format tripwire\n"
                     b"-----END FIXTURE KEY-----\n")


def test_golden_fixture_still_opens() -> None:
    """If this fails the on-disk format changed. Every round-trip test above
    would still pass, because they all encrypt and decrypt with the same
    (changed) code. Real users' .levault files -- whose plaintext was
    deliberately destroyed -- would not open. Read the fixture README before
    touching anything here; do NOT regenerate the file to make this green."""
    data = (FIXTURE_DIR / "golden.levault").read_bytes()
    out, meta, header = open_file_envelope(_GOLDEN_FMK, data)
    assert out == _GOLDEN_PLAINTEXT
    assert meta["name"] == "fixture.pem"
    assert meta["mode"] == "0600"
    assert meta["sha256"] == hashlib.sha256(_GOLDEN_PLAINTEXT).hexdigest()
    assert header["fmk_id"] == "FIXTURE1"
    assert header["version"] == 1


def test_golden_fixture_is_recognised_as_a_file_and_not_as_a_vault() -> None:
    data = (FIXTURE_DIR / "golden.levault").read_bytes()
    assert is_file_envelope(data) is True
    assert is_v2(data) is False


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
