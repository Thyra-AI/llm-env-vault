"""
Regression suite for the three security-hardening items applied to
vault_lib/trust.py in release 1.3.0:

  B1 - monitored_summary() data function: returns (monitored_paths,
       is_executable_only) so callers can warn the user when a bare command
       like "docker compose up" has its ONLY drift-monitored file be the
       executable binary -- not the compose file, which is never named on
       the command line.

  B2 - 8-hour dual-clock trust TTL: _trusted entries now carry both a
       wall-clock and a monotonic timestamp; check() expires the grant if
       EITHER deadline passes.  Dual-clock is deliberate -- monotonic alone
       pauses during system sleep (Friday-evening grant survives to Monday),
       wall-clock alone can be set backward.

  E2 - POSIX argv0 resolution: _resolve_argv0 previously prepended cwd to
       the PATH search unconditionally, matching Windows CreateProcess
       semantics but not POSIX exec -- on macOS/Linux a decoy file in cwd
       would be hashed while the real PATH binary executed.  cwd is now
       prepended only on win32.

Every test runs with an isolated, throwaway trust state -- no real vault
files are touched.  The vault-fingerprint regression test (B2 shape change)
uses isolated_vault from test_trust.py for a real (throwaway) vault.

Runs under pytest (`pytest tests/test_trust_hardening.py -q`) or standalone
(`python tests/test_trust_hardening.py`), matching test_trust.py's convention.
"""
import contextlib
import os
import sys
import tempfile
import time
from pathlib import Path

# Project root must be in sys.path so vault_lib is importable as a package.
sys.path.insert(0, str(Path(__file__).parent.parent))
# Tests dir must be in sys.path so we can borrow helpers from test_trust.
sys.path.insert(0, str(Path(__file__).parent))

from vault_lib import store, trust  # noqa: E402

# Borrow isolation helpers from the existing suite rather than duplicating them.
# isolated_vault handles store-path redirection, vault creation, and trust-state
# reset in a temp dir -- keeping these tests consistent with the 55-test suite.
from test_trust import (  # noqa: E402
    isolated_vault,
    BASE_SECRETS,
    TEST_PASSWORD,
    _reset_trust_state,
    _py,
)


# ---------------------------------------------------------------------------
# B1 — monitored_summary: data function that lets mcp_server decide whether
# to show an amber "only the executable binary is drift-monitored" warning.
#
# Bug being tested: for "docker compose up" the monitored set is only the
# resolved docker binary -- not docker-compose.yml, which is never named on
# the command line.  Without monitored_summary, mcp_server can't distinguish
# this from a command that really does reference a file explicitly (e.g.
# "docker compose -f myapp.yml up"), so it silently implies coverage it
# doesn't provide.  is_executable_only=True flags the gap; is_executable_only
# must be False (not True) when paths==[] (nothing monitored), so an
# unresolvable argv0 doesn't accidentally trigger the amber-warning branch.
# ---------------------------------------------------------------------------

def test_monitored_summary_executable_only_for_argless_command() -> None:
    """A bare-executable command with no file args ("docker compose up" shape)
    must return is_executable_only=True.  We use sys.executable so the test
    does not depend on Docker being installed."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        # Simulate the "docker compose up" shape: argv0 (sys.executable here)
        # resolves, but "compose" and "up" are not files.  A docker-compose.yml
        # sits in cwd but is NOT named on the command line.
        (tmp_path / "docker-compose.yml").write_text("version: '3'\n")
        cmd = [sys.executable, "compose", "up"]
        paths, is_exe_only = trust.monitored_summary(cmd, str(tmp_path))
        assert is_exe_only is True, (
            "REGRESSION (B1): is_executable_only was False for a bare-executable "
            "command -- the amber warning for 'only the binary is monitored' would "
            "be suppressed, leaving the user with a false sense of coverage"
        )
        # The resolved executable must appear in the monitored set.
        exe_resolved = str(Path(sys.executable).resolve())
        assert exe_resolved in paths, (
            f"REGRESSION (B1): sys.executable ({exe_resolved!r}) not in monitored "
            f"paths {paths!r}"
        )
        # The compose file must NOT appear -- it was never named on the command line.
        compose_str = str(tmp_path / "docker-compose.yml")
        assert compose_str not in paths, (
            "REGRESSION (B1): docker-compose.yml appeared in monitored paths even "
            "though it was not named on the command line"
        )


def test_monitored_summary_not_executable_only_when_file_arg_present() -> None:
    """When a real file IS explicitly named on the command line,
    is_executable_only must be False."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        config = tmp_path / "config.txt"
        config.write_text("key=value\n")
        # config.txt is named directly as an argument -- it must be monitored.
        cmd = [sys.executable, "-c", "print()", str(config)]
        paths, is_exe_only = trust.monitored_summary(cmd, str(tmp_path))
        assert is_exe_only is False, (
            "REGRESSION (B1): is_executable_only was True even though a real "
            "file argument was present on the command line"
        )
        assert str(config.resolve()) in paths, (
            f"REGRESSION (B1): the explicit file arg {config!r} was not in "
            f"monitored paths {paths!r}"
        )


def test_monitored_summary_empty_returns_false_not_executable_only() -> None:
    """Empty monitored set (unresolvable argv0 + no file args) must return
    is_executable_only=False -- that is a distinct condition from
    executable-only, and Lane 4 must NOT take the amber-warning branch."""
    # "definitely-not-a-real-executable-xyzzy" never resolves via PATH.
    cmd = ["definitely-not-a-real-executable-xyzzy-hardening"]
    with tempfile.TemporaryDirectory() as tmp:
        paths, is_exe_only = trust.monitored_summary(cmd, tmp)
        assert paths == [], (
            f"REGRESSION (B1): expected empty paths for unresolvable argv0, "
            f"got {paths!r}"
        )
        assert is_exe_only is False, (
            "REGRESSION (B1): is_executable_only was True for an empty monitored "
            "set -- Lane 4 would incorrectly show the amber warning for an "
            "unresolvable argv0, which is already covered by unmonitored_file_warning"
        )


# ---------------------------------------------------------------------------
# B2 — 8-hour dual-clock TTL: trust grants now carry both a wall-clock
# (time.time()) and a monotonic (time.monotonic()) timestamp.  check() expires
# the grant if EITHER clock shows >= _TRUST_TTL_SECONDS elapsed.
#
# The two failure modes this covers:
#   * Monotonic-only: CLOCK_MONOTONIC / mach_absolute_time stops advancing
#     during system sleep on Linux/macOS.  A grant at 6 pm Friday, with the
#     machine sleeping over the weekend, would survive until Monday morning.
#   * Wall-clock-only: the system clock can be set backward, allowing a user
#     or attacker to extend a grant indefinitely.
#
# The shape of _trusted entries changed from {path: hash} to
# {"hashes": {path: hash}, "granted_wall": float, "granted_mono": float}.
# The regression test at the bottom of this section pins the vault-fingerprint
# invalidation path, which clears the whole cache: after the shape change, the
# code that reads entry["hashes"] must still work when the fingerprint check
# fires, not crash with a KeyError or silently skip the clear.
# ---------------------------------------------------------------------------

def test_trust_ttl_expires_by_wall_clock() -> None:
    """Wall-clock expiry must fire even when the monotonic clock is still
    fresh -- simulates a clock-set-backward attack or a grant with a stale
    wall timestamp."""
    _reset_trust_state()
    try:
        cmd = _py()
        sig = trust.make_signature(cmd, None, None, None, False)
        hashes = trust.referenced_file_hashes(cmd, None)
        # Backdate granted_wall to 8h+1s ago; monotonic is current (fresh).
        trust._trusted[sig] = {
            "hashes": hashes,
            "granted_wall": time.time() - trust._TRUST_TTL_SECONDS - 1,
            "granted_mono": time.monotonic(),
        }
        trust.cache_secrets(sig, {"K": "V"})

        ok, reason = trust.check(sig, cmd, None)
        assert ok is False, (
            "REGRESSION (B2): wall-clock expiry did not fire even though "
            "granted_wall was 8h+ ago (monotonic was still fresh)"
        )
        assert reason is not None, (
            "REGRESSION (B2): expiry returned reason=None instead of an "
            "explanation string"
        )
        assert "expired" in reason.lower(), (
            f"REGRESSION (B2): expiry reason missing 'expired': {reason!r}"
        )
        assert "8" in reason, (
            f"REGRESSION (B2): expiry reason does not mention '8 hours': {reason!r}"
        )
        assert sig not in trust._trusted, (
            "REGRESSION (B2): expired _trusted entry was not removed"
        )
    finally:
        _reset_trust_state()


def test_trust_ttl_expires_by_monotonic() -> None:
    """Monotonic expiry must fire even when the wall clock is still fresh --
    simulates a post-sleep grant where wall time advanced but monotonic did
    not (the sleep-survivability failure mode this item fixes)."""
    _reset_trust_state()
    try:
        cmd = _py()
        sig = trust.make_signature(cmd, None, None, None, False)
        hashes = trust.referenced_file_hashes(cmd, None)
        # granted_wall is current (fresh); backdate granted_mono by 8h+1s.
        trust._trusted[sig] = {
            "hashes": hashes,
            "granted_wall": time.time(),
            "granted_mono": time.monotonic() - trust._TRUST_TTL_SECONDS - 1,
        }
        trust.cache_secrets(sig, {"K": "V"})

        ok, reason = trust.check(sig, cmd, None)
        assert ok is False, (
            "REGRESSION (B2): monotonic expiry did not fire even though "
            "granted_mono was 8h+ ago (wall clock was still fresh)"
        )
        assert reason is not None and "expired" in reason.lower(), (
            f"REGRESSION (B2): monotonic expiry reason wrong: {reason!r}"
        )
        assert "8" in reason, (
            f"REGRESSION (B2): expiry reason does not mention '8 hours': {reason!r}"
        )
        assert sig not in trust._trusted, (
            "REGRESSION (B2): expired _trusted entry was not removed after "
            "monotonic expiry"
        )
    finally:
        _reset_trust_state()


def test_trust_ttl_fresh_grant_still_allowed() -> None:
    """A freshly-granted trust entry (both clocks at 'now') must still
    auto-allow -- the TTL check must not fire spuriously."""
    _reset_trust_state()
    try:
        cmd = _py()
        sig = trust.make_signature(cmd, None, None, None, False)
        hashes = trust.referenced_file_hashes(cmd, None)
        trust.trust(sig, hashes)
        trust.cache_secrets(sig, {"K": "V"})

        ok, reason = trust.check(sig, cmd, None)
        assert ok is True, (
            f"REGRESSION (B2): a fresh trust grant was incorrectly expired: "
            f"reason={reason!r}"
        )
        assert reason is None, (
            f"REGRESSION (B2): ok=True but reason is not None: {reason!r}"
        )
    finally:
        _reset_trust_state()


def test_vault_fingerprint_invalidation_still_works_after_shape_change() -> None:
    """The vault-fingerprint cache-clear path must still work correctly after
    the _trusted entry shape changed from a bare dict to the
    {"hashes", "granted_wall", "granted_mono"} shape.

    Regression being guarded: if check() reads entry["hashes"] directly for
    the fingerprint branch instead of going through entry, a KeyError would
    crash; if the clear logic is broken, _trusted stays populated with stale
    entries that reference a vault snapshot that no longer exists."""
    with isolated_vault() as _tmp:
        cmd = _py()
        sig = trust.make_signature(cmd, None, None, None, False)
        trust.trust(sig, trust.referenced_file_hashes(cmd, None))
        trust.cache_secrets(sig, dict(BASE_SECRETS))

        # Sanity: must be trusted right after granting.
        ok, _ = trust.check(sig, cmd, None)
        assert ok is True, "test setup: expected ok=True immediately after grant"

        # Rotate the vault -- changes vault.enc on disk.
        store.save_secrets(TEST_PASSWORD, {"ROTATED_SECRET": "new-value"})

        # check() must detect the vault change, clear ALL caches, and report.
        ok, reason = trust.check(sig, cmd, None)
        assert ok is False, (
            "REGRESSION (B2 shape): vault-fingerprint check did not invalidate "
            "trust after the _trusted entry shape changed"
        )
        assert reason is not None and "vault" in reason.lower(), (
            f"REGRESSION (B2 shape): vault-change reason missing 'vault': {reason!r}"
        )
        assert not trust._trusted, (
            "REGRESSION (B2 shape): _trusted was not fully cleared on vault change"
        )
        assert not trust._cached_secrets, (
            "REGRESSION (B2 shape): _cached_secrets was not fully cleared on vault change"
        )


# ---------------------------------------------------------------------------
# E2 — POSIX argv0 resolution: _resolve_argv0 must NOT prepend cwd to the
# PATH search on POSIX, because POSIX exec() never searches cwd.
#
# The bug: before the fix, cwd was always prepended to search_path, matching
# Windows CreateProcess semantics but not POSIX exec.  On macOS/Linux, a
# malicious "docker" file planted in cwd after trust was granted would be
# hashed by _resolve_argv0 while the real /usr/bin/docker executed -- drift
# detection would bind to the decoy, not the binary, so a later swap of the
# decoy would not revoke trust.
#
# Each test is gated on sys.platform and returns early on the wrong OS,
# following the convention in test_install_migrate_robustness.py.
# ---------------------------------------------------------------------------

def test_posix_argv0_does_not_prepend_cwd() -> None:
    """On POSIX, _resolve_argv0 must NOT find an executable that lives only
    in cwd (and not in PATH)."""
    if sys.platform == "win32":
        return  # Windows intentionally prepends cwd; this test is POSIX-only.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        # Create a file that is only in tmp_path (not in PATH).
        decoy_name = "_llm_vault_trust_e2_posix_test"
        decoy = tmp_path / decoy_name
        decoy.write_text("#!/bin/sh\necho decoy\n")
        decoy.chmod(0o755)

        result = trust._resolve_argv0([decoy_name], str(tmp_path))
        assert result is None, (
            f"REGRESSION (E2): _resolve_argv0 resolved {decoy_name!r} via cwd "
            f"on POSIX ({result!r}) -- cwd must not be prepended to PATH on POSIX, "
            f"as POSIX exec() never searches cwd"
        )


def test_win32_argv0_prepends_cwd() -> None:
    """On Windows, _resolve_argv0 MUST find an executable that lives only in
    cwd (before PATH), matching CreateProcess semantics."""
    if sys.platform != "win32":
        return  # POSIX does not prepend cwd; this test is win32-only.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp).resolve()
        decoy_name = "_llm_vault_trust_e2_win32_test"
        decoy = tmp_path / (decoy_name + ".exe")
        decoy.write_bytes(b"MZ")  # minimal stub; only needs to pass is_file()

        result = trust._resolve_argv0([decoy_name], str(tmp_path))
        assert result is not None and result == decoy.resolve(), (
            f"REGRESSION (E2): _resolve_argv0 did not find {decoy_name!r} via "
            f"cwd on win32 (got {result!r}) -- cwd must be prepended to PATH on "
            f"Windows to match CreateProcess search order"
        )


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches test_trust.py's
# and test_install_migrate_robustness.py's convention)
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
