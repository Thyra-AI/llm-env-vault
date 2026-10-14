"""Strict redaction + output cap for runs auto-allowed by an always-allow entry
(plan 2.4.0 section 4): mcp_server._redact_secrets(..., strict=True)."""
import base64
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_server  # noqa: E402

VALUE = "Tok/en+Secret 9=x"          # exercises '/', '+', ' ', '=' in b64 and URL forms
NAME = "API_TOKEN"
MARK = f"[REDACTED:{NAME}]"
SECRETS = {NAME: VALUE}


def _forms(value):
    raw = value.encode("utf-8")
    return {
        "raw": value,
        "b64": base64.b64encode(raw).decode(),
        "b64_nopad": base64.b64encode(raw).decode().rstrip("="),
        "b64url": base64.urlsafe_b64encode(raw).decode(),
        "b64url_nopad": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "hex_lower": raw.hex(),
        "hex_upper": raw.hex().upper(),
        "quote": urllib.parse.quote(value, safe=""),
        "quote_plus": urllib.parse.quote_plus(value, safe=""),
    }


def test_strict_redacts_every_encoding() -> None:
    for label, form in _forms(VALUE).items():
        out, skipped = mcp_server._redact_secrets(f"before {form} after", SECRETS, strict=True)
        assert form not in out, label
        assert out == f"before {MARK} after", label
        assert skipped == []


def test_strict_redacts_case_variants_and_their_encodings() -> None:
    for variant in (VALUE.upper(), VALUE.lower()):
        for label, form in _forms(variant).items():
            out, _ = mcp_server._redact_secrets(f"x {form} y", SECRETS, strict=True)
            assert form not in out, (variant, label)
            assert MARK in out


def test_strict_redacts_lowercase_percent_escapes() -> None:
    quoted = urllib.parse.quote(VALUE, safe="")
    low = re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), quoted)
    assert low != quoted
    out, _ = mcp_server._redact_secrets(f"a {low} b", SECRETS, strict=True)
    assert low not in out and MARK in out


def test_non_strict_is_unchanged_and_misses_the_extra_forms() -> None:
    forms = _forms(VALUE)
    for label in ("hex_lower", "hex_upper", "b64url_nopad"):
        out, _ = mcp_server._redact_secrets(f"x {forms[label]} y", SECRETS)
        assert forms[label] in out, label
    out, _ = mcp_server._redact_secrets(f"{VALUE} {forms['b64']} {forms['quote']}", SECRETS)
    assert out == f"{MARK} {MARK} {MARK}"


def test_strict_keeps_min_length_rule_and_reports_skipped() -> None:
    secrets = {"SHORT_ONE": "abc123", NAME: VALUE}
    out, skipped = mcp_server._redact_secrets("abc123 and " + VALUE, secrets, strict=True)
    assert out == f"abc123 and {MARK}"
    assert skipped == ["SHORT_ONE"]


def test_strict_does_not_cap_small_output_and_adds_no_note() -> None:
    out, _ = mcp_server._redact_secrets("hello world", SECRETS, strict=True)
    assert out == "hello world"


def test_strict_caps_each_stream_and_keeps_tail_with_note() -> None:
    cap = mcp_server.STRICT_OUTPUT_CAP_BYTES
    assert cap == 256 * 1024
    text = "A" * (cap + 5000) + "THE-END"
    out, _ = mcp_server._redact_secrets(text, SECRETS, strict=True)
    assert out.startswith(mcp_server.STRICT_TRUNCATION_PREFIX)
    note, _, kept = out.partition("\n")
    assert str(cap) in note and str(len(text)) in note
    assert len(kept.encode("utf-8")) <= cap
    assert kept.endswith("THE-END")


def test_cap_counts_bytes_not_characters() -> None:
    cap = mcp_server.STRICT_OUTPUT_CAP_BYTES
    out, _ = mcp_server._redact_secrets("é" * cap, SECRETS, strict=True)   # 2 bytes each
    _, _, kept = out.partition("\n")
    assert out.startswith(mcp_server.STRICT_TRUNCATION_PREFIX)
    assert len(kept.encode("utf-8")) <= cap


def test_value_at_the_cap_boundary_is_redacted_before_cutting() -> None:
    cap = mcp_server.STRICT_OUTPUT_CAP_BYTES
    text = "B" * 100 + VALUE + "C" * (cap - 3)
    out, _ = mcp_server._redact_secrets(text, SECRETS, strict=True)
    assert VALUE not in out and VALUE[:6] not in out


def test_non_strict_has_no_cap() -> None:
    cap = mcp_server.STRICT_OUTPUT_CAP_BYTES
    out, _ = mcp_server._redact_secrets("A" * (cap * 2), SECRETS)
    assert len(out) == cap * 2
