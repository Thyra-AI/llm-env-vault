"""
Regression suite for run_with_env output redaction (A1) and the B1 grant-note
improvement added in release 1.3.0.

A1 (SHIP GATE) -- run_with_env previously returned stdout/stderr verbatim, so
  a command that prints its own environment (e.g. a misconfigured server that
  dumps its config on startup) put real secret values directly into the model's
  context and the session transcript.  _redact_secrets() now replaces every
  vault value with [REDACTED:VAR_NAME] -- including its base64 and URL-percent-
  encoded forms -- before returning the result.  Values shorter than
  REDACT_MIN_VALUE_LEN=8 are skipped to avoid destroying the output (e.g. a
  value of "1" or "no" would replace every occurrence of that substring), and
  the skipped names are surfaced in the result so the omission is visible rather
  than silent.  Redaction runs BEFORE the [-4000:] slice so a value straddling
  the cut point is still caught.

B1 (SHIP GATE) -- for "docker compose up"-shaped commands, the grant note
  previously told the user they had file-coverage they did not have: the
  docker-compose.yml is never named on the command line, so the only monitored
  file was the executable binary itself.  trust.monitored_summary() now tells
  mcp_server which files are actually monitored, and the grant note enumerates
  them.  When is_executable_only=True, both the dialog trust_note and the tool-
  result trust_note say so explicitly so the human understands the limitation
  BEFORE ticking the trust checkbox.

Every test runs with an isolated, throwaway vault -- store paths are redirected
into a temp dir and trust state is reset, same as test_trust.py.  No real
vault.enc / vault.salt / vault_index.json is ever read or written.

Runs under pytest (`pytest tests/test_redaction.py -q`) or standalone
(`python tests/test_redaction.py`), matching test_trust.py's convention.
"""
import base64
import json
import sys
import urllib.parse
from pathlib import Path

# Project root must be on sys.path so vault_lib and mcp_server are importable.
sys.path.insert(0, str(Path(__file__).parent.parent))
# tests/ dir must be on sys.path so we can borrow helpers from test_trust.
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from test_trust import (  # noqa: E402
    isolated_vault,
    fake_dialog,
    _allow,
    _py,
    BASE_SECRETS,
    TEST_PASSWORD,
)

# The long secret from the shared fixture -- 11 chars, well above the floor.
_TOKEN = BASE_SECRETS["DOCKER_TEST_TOKEN"]   # "tok-abc-123"
_TOKEN_B64 = base64.b64encode(_TOKEN.encode("utf-8")).decode("ascii")
_TOKEN_URL = urllib.parse.quote(_TOKEN, safe="")

# A version of the fixture where DOCKER_TEST_TOKEN has a short value that must
# be skipped by _redact_secrets.  "short" is 5 characters -- safely below 8.
_SHORT_SECRETS = {"DOCKER_TEST_TOKEN": "short", "OTHER_SECRET": "other-xyz-789"}
assert len(_SHORT_SECRETS["DOCKER_TEST_TOKEN"]) < mcp_server.REDACT_MIN_VALUE_LEN, (
    "Test fixture requires DOCKER_TEST_TOKEN value shorter than REDACT_MIN_VALUE_LEN")


# ---------------------------------------------------------------------------
# A1 -- _redact_secrets unit tests: the public helper itself, tested directly.
#
# The length floor (REDACT_MIN_VALUE_LEN = 8) is load-bearing: a value of
# "1" or "true" would otherwise replace every occurrence of that character in
# the output and destroy it.  Values below the floor are skipped and their
# names are returned in the second tuple element so the caller (and ultimately
# the human) can see the omission rather than silently assume full coverage.
# Base64 and URL-encoded forms must also be caught -- they are the two most
# common ways a secret leaks into HTTP log lines or connection-string dumps
# without appearing as the literal secret value.
# ---------------------------------------------------------------------------

def test_redact_secrets_replaces_exact_value() -> None:
    text = f"command output contains {_TOKEN} and some other data"
    redacted, skipped = mcp_server._redact_secrets(text, {"DOCKER_TEST_TOKEN": _TOKEN})
    assert _TOKEN not in redacted, (
        f"REGRESSION (A1): raw value still present after _redact_secrets, "
        f"got: {redacted!r}")
    assert "[REDACTED:DOCKER_TEST_TOKEN]" in redacted, (
        f"REGRESSION (A1): redaction marker not in output, got: {redacted!r}")
    assert skipped == [], f"no values should be skipped here, got: {skipped!r}"


def test_redact_secrets_catches_base64_form() -> None:
    """A base64-encoded secret (e.g. in an HTTP Authorization: Basic header or
    a JWT payload) must also be redacted -- many frameworks log headers verbatim
    on connection errors, so the literal value may never appear but its base64
    form does."""
    text = f"Authorization: Basic {_TOKEN_B64} (connection log)"
    redacted, skipped = mcp_server._redact_secrets(text, {"DOCKER_TEST_TOKEN": _TOKEN})
    assert _TOKEN_B64 not in redacted, (
        f"REGRESSION (A1): base64 form of the secret not redacted, got: {redacted!r}")
    assert "[REDACTED:DOCKER_TEST_TOKEN]" in redacted, (
        f"REGRESSION (A1): redaction marker not present after base64 replacement, "
        f"got: {redacted!r}")
    assert skipped == []


def test_redact_secrets_short_value_is_left_alone_and_reported() -> None:
    """Values shorter than REDACT_MIN_VALUE_LEN must be left untouched AND
    their names must appear in the returned skipped list so the omission is
    visible to the caller -- 'short' (5 chars) is below the 8-char floor.

    The old broken behaviour would either (a) replace every occurrence of a
    common substring like '1' or 'no' and destroy the output, or (b) silently
    skip without disclosure, making the caller think redaction was complete
    when it was not."""
    short_val = "short"
    assert len(short_val) < mcp_server.REDACT_MIN_VALUE_LEN
    text = f"the value appears here: {short_val} and more output follows"
    redacted, skipped = mcp_server._redact_secrets(
        text, {"DOCKER_TEST_TOKEN": short_val})
    # Value must still be present -- we must NOT replace it.
    assert short_val in redacted, (
        f"REGRESSION (A1): short value was incorrectly redacted (would destroy "
        f"common substrings in output), got: {redacted!r}")
    # But the variable name MUST appear in the skipped list.
    assert "DOCKER_TEST_TOKEN" in skipped, (
        f"REGRESSION (A1): skipped list did not include the short-value variable "
        f"(old: omission was silent, giving false sense of full redaction), "
        f"got: {skipped!r}")


def test_redact_secrets_straddling_boundary_caught_with_redact_first() -> None:
    """Redact BEFORE slicing: a secret that straddles the -4000-character cut
    point must be caught by _redact_secrets even though only its tail appears
    in the final slice.

    Scenario with "tok-abc-123" (11 chars):
      text = "X"*5 + "tok-abc-123" + "Y"*3994   (4010 chars total)
      The [-4000:] cut is at index 10 -- inside the value (spans index 5..15).

      OLD behaviour (slice first, then redact):
        text[-4000:] starts with "bc-123" + "Y"*3994.  Searching for the full
        value "tok-abc-123" finds nothing; "bc-123" leaks.

      CORRECT behaviour (redact first, then slice):
        The full value is replaced before slicing, so the raw value is gone
        even though the [-4000:] marker might clip the [REDACTED:...] token.
    """
    val = _TOKEN  # "tok-abc-123", 11 chars
    prefix_len = 5
    suffix_len = 3994
    total_len = prefix_len + len(val) + suffix_len  # 4010
    cut = total_len - 4000  # 10 -- inside the value (5..15)
    assert prefix_len < cut < prefix_len + len(val), (
        "Test setup error: value must straddle the cut point")

    text = "X" * prefix_len + val + "Y" * suffix_len
    secrets = {"DOCKER_TEST_TOKEN": val}

    # Demonstrate that slice-first would leave the tail in the output:
    sliced_first = text[-4000:]
    assert val not in sliced_first, "full value not in bad slice (setup ok)"
    # The tail of the value IS in the slice (the bug):
    tail = val[cut - prefix_len:]  # "bc-123"
    assert sliced_first.startswith(tail), (
        f"Test setup error: expected tail {tail!r} at start of bad slice, "
        f"got {sliced_first[:20]!r}")

    # The correct way: redact first, then slice.
    redacted, _ = mcp_server._redact_secrets(text, secrets)
    correct_slice = redacted[-4000:]
    assert val not in correct_slice, (
        f"REGRESSION (A1): raw value found in the correct (redact-first) slice "
        f"-- this means _redact_secrets is not being called before the slice, "
        f"got slice start: {correct_slice[:40]!r}")


# ---------------------------------------------------------------------------
# A1 -- integration: _run_with_env_impl redacts stdout, stderr, and every
# field of the result dict, before truncating to the last 4000 characters.
#
# Key property: the raw value must not appear ANYWHERE in the serialised
# result -- not in stdout, not in stderr, not in trust_note, nowhere.  Assert
# on json.dumps(r) to catch every field at once.
# ---------------------------------------------------------------------------

def test_integration_echoed_value_is_fully_redacted_in_result() -> None:
    """A command that echoes an injected vault variable must produce
    [REDACTED:VAR_NAME] in stdout, and the raw value must not appear in any
    field of the serialised result -- not just stdout.

    Old broken behaviour: the raw value was returned verbatim in stdout,
    putting it directly into the model's context and the session transcript."""
    with isolated_vault():
        cmd = [sys.executable, "-c",
               "import os; print(os.environ.get('DOCKER_TEST_TOKEN', ''))"]
        with fake_dialog(_allow(trust_it=True)):
            r = mcp_server._run_with_env_impl(
                list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
        assert r.get("applied") is True
        # Redaction marker must be in stdout.
        assert "[REDACTED:DOCKER_TEST_TOKEN]" in r.get("stdout", ""), (
            f"REGRESSION (A1): redaction marker not in stdout, "
            f"got stdout: {r.get('stdout', '')!r}")
        # The raw value must not appear anywhere in the full serialised result.
        result_str = json.dumps(r)
        assert _TOKEN not in result_str, (
            f"REGRESSION (A1): raw secret value appears somewhere in the "
            f"serialised result (old: value was in the model's context), "
            f"got: {result_str!r}")


def test_integration_base64_form_in_output_is_caught() -> None:
    """A command that prints the base64-encoded form of a secret (common in
    HTTP client debug logs, e.g. `requests` with DEBUG logging) must be
    caught -- the base64 form must not appear in the returned result."""
    with isolated_vault():
        cmd = [sys.executable, "-c",
               "import os, base64; "
               "v = os.environ.get('DOCKER_TEST_TOKEN', ''); "
               "print(base64.b64encode(v.encode()).decode())"]
        with fake_dialog(_allow(trust_it=True)):
            r = mcp_server._run_with_env_impl(
                list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
        result_str = json.dumps(r)
        assert _TOKEN_B64 not in result_str, (
            f"REGRESSION (A1): base64-encoded secret value found in result "
            f"(old: base64 forms were not checked), got: {result_str!r}")


def test_integration_short_value_skipped_and_disclosed_in_result() -> None:
    """When a vault variable's value is shorter than REDACT_MIN_VALUE_LEN, it
    is NOT redacted from output (to avoid destroying common substrings), but
    its name appears in 'redaction_skipped' in the result dict so the human
    knows the omission is there rather than assuming full coverage."""
    with isolated_vault(secrets=_SHORT_SECRETS):
        cmd = [sys.executable, "-c",
               "import os; print(os.environ.get('DOCKER_TEST_TOKEN', ''))"]
        with fake_dialog(_allow(trust_it=True, secrets=_SHORT_SECRETS)):
            r = mcp_server._run_with_env_impl(
                list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
        assert "redaction_skipped" in r, (
            f"REGRESSION (A1): 'redaction_skipped' field missing from result "
            f"when a short-value variable was present, got: {r!r}")
        assert "DOCKER_TEST_TOKEN" in r["redaction_skipped"], (
            f"REGRESSION (A1): short-value variable not named in "
            f"'redaction_skipped', got: {r['redaction_skipped']!r}")


def test_integration_straddling_boundary_is_redacted() -> None:
    """End-to-end: a secret that straddles the -4000-character cut must be
    redacted in the result -- this verifies that _run_with_env_impl calls
    _redact_secrets BEFORE applying the [-4000:] slice.

    The command emits "X"*5 + secret + "Y"*3994 (4010 chars total).  The cut
    at index 10 falls inside the value (which spans 5..15).  If the slice ran
    first, the tail "bc-123" would appear in stdout without the head -- the
    simple string replacement in _redact_secrets would miss it."""
    val = _TOKEN  # 11 chars
    prefix_len = 5
    suffix_len = 3994
    total_len = prefix_len + len(val) + suffix_len  # 4010
    cut = total_len - 4000  # 10 -- inside the value
    assert prefix_len < cut < prefix_len + len(val), "setup check"

    with isolated_vault():
        cmd = [sys.executable, "-c",
               f"import sys, os; "
               f"v = os.environ.get('DOCKER_TEST_TOKEN', ''); "
               f"sys.stdout.write('X'*{prefix_len} + v + 'Y'*{suffix_len})"]
        with fake_dialog(_allow(trust_it=True)):
            r = mcp_server._run_with_env_impl(
                list(cmd), None, False, None, ["DOCKER_TEST_TOKEN"])
        stdout = r.get("stdout", "")
        assert val not in stdout, (
            f"REGRESSION (A1): raw value found in stdout after straddling "
            f"the -4000 cut point -- redaction must run before the slice; "
            f"got stdout start: {stdout[:50]!r}")


# ---------------------------------------------------------------------------
# B1 -- grant note: when trust is granted, the note must enumerate which files
# are actually drift-monitored rather than asserting generic coverage.
#
# Old broken behaviour: for "docker compose up", the note said "its referenced
# file(s) stay unchanged" without specifying what those files are.  The compose
# file is never named on the command line, so the monitored set was ONLY the
# executable binary -- the human was told they had file-coverage they did not
# have, and the agent could then rewrite docker-compose.yml while every later
# run auto-allowed.
#
# The fix: trust.monitored_summary() returns (monitored_paths, is_executable_only);
# when is_executable_only=True, both the dialog trust_note (seen BEFORE ticking
# the checkbox) and the tool-result trust_note say so explicitly.
# ---------------------------------------------------------------------------

def test_b1_executable_only_grant_note_names_binary_and_warns() -> None:
    """A 'docker compose up'-shaped command -- argv0 resolves but the remaining
    args ('compose', 'up') are not real files -- must produce a grant note that
    (a) names the resolved executable path and (b) explicitly warns that no
    config files are monitored and that changes to compose files or scripts will
    NOT revoke trust.  Uses sys.executable so the test is not Docker-dependent.

    Old broken behaviour: the note claimed 'its referenced file(s) stay
    unchanged' without specifying what those were, implying compose-file coverage
    the grant did not actually provide."""
    with isolated_vault():
        cmd = [sys.executable, "compose", "up"]
        with fake_dialog(_allow(trust_it=True)) as calls:
            r = mcp_server._run_with_env_impl(list(cmd), None, False, None, None)
        note = r.get("trust_note", "")
        exe_resolved = str(Path(sys.executable).resolve())
        assert exe_resolved in note, (
            f"REGRESSION (B1): grant note does not name the monitored executable "
            f"path -- human cannot see what is actually drift-monitored, "
            f"got: {note!r}")
        assert ("no config files" in note.lower()
                or "only the executable" in note.lower()), (
            f"REGRESSION (B1): grant note does not warn that no config files are "
            f"monitored -- user is told they have coverage they don't have, "
            f"got: {note!r}")
        # The dialog itself must have received the executable-only warning via
        # trust_note BEFORE the human ticked the checkbox.
        dialog_note = calls[-1].get("trust_note") or ""
        assert ("no config files" in dialog_note.lower()
                or "only the executable" in dialog_note.lower()
                or "not revoke trust" in dialog_note.lower()), (
            f"REGRESSION (B1): executable-only warning was not passed to the "
            f"dialog trust_note -- human never saw it before consenting, "
            f"got dialog note: {dialog_note!r}")


def test_b1_file_arg_grant_note_enumerates_file_and_not_executable_only() -> None:
    """When a real file IS explicitly named on the command line (e.g.
    'docker compose -f myapp.yml up'), the grant note must list it AND must
    NOT claim executable-only coverage.

    This locks in the complementary case to the test above: a command that
    does provide file-level drift-coverage must be reported accurately too."""
    with isolated_vault() as tmp:
        ref = tmp / "compose.yml"
        ref.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")
        cmd = [sys.executable, "-c", "print('ok')", str(ref)]
        with fake_dialog(_allow(trust_it=True)):
            r = mcp_server._run_with_env_impl(
                list(cmd), None, False, str(tmp), None)
        note = r.get("trust_note", "")
        ref_resolved = str(ref.resolve())
        assert ref_resolved in note, (
            f"REGRESSION (B1): grant note does not enumerate the explicitly-"
            f"named file argument -- human cannot see what is drift-monitored, "
            f"got: {note!r}")
        assert "no config files are named" not in note.lower(), (
            f"REGRESSION (B1): grant note falsely claimed no config files when "
            f"one was explicitly named on the command line, got: {note!r}")


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches test_trust.py and
# test_trust_hardening.py's standalone runner convention)
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
