"""
Regression tests for the OSError robustness fix in _install_migrate_impl
(and the analogous fix in _run_with_env_impl).

Before the fix, calling _install_migrate_impl with an unreachable UNC path or a
Windows device special file would raise an uncaught OSError from Path.resolve() or
.exists()/.is_file() because those calls sat before the function's try/except block.
After the fix, all OSError-family exceptions from path-resolution/existence probing
are caught and turned into the same clean {"applied": False, "error": ...} shape
that every other bad-path case in the function already returned.
"""
import os
import sys
import tempfile
from pathlib import Path

# Make sure the worktree root is importable regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server
from vault_lib import store


def _write_temp_env(content: str) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".env", delete=False, prefix="llm_vault_test_"
    ) as fh:
        fh.write(content)
        return fh.name


def test_unreachable_unc_path_does_not_raise() -> None:
    """Unreachable UNC path must return a clean error dict, not raise."""
    result = mcp_server._install_migrate_impl(r"\\nonexistent-server-xyz123\share\file.env")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert result.get("applied") is False, f"Expected applied=False, got: {result}"
    assert "error" in result, f"Expected 'error' key in result: {result}"
    print(f"  error text: {result['error']!r}")


def test_nonexistent_normal_path_returns_does_not_exist() -> None:
    """A regular path that doesn't exist should return the 'does not exist' message."""
    result = mcp_server._install_migrate_impl(r"C:\this\path\cannot\exist\file.env")
    assert isinstance(result, dict)
    assert result.get("applied") is False
    assert "error" in result
    assert "does not exist" in result["error"], (
        f"Expected 'does not exist' in error message, got: {result['error']!r}"
    )
    print(f"  error text: {result['error']!r}")


def test_real_file_passes_preamble() -> None:
    """An existing .env file passes the preamble checks without crashing.

    We use a file containing only a comment and an empty variable so there is
    nothing to migrate and the function returns without ever opening the GUI.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".env", delete=False, prefix="llm_vault_test_"
    ) as fh:
        fh.write("# temporary test file -- no real secrets\nEMPTY_VAR=\n")
        tmp_path = fh.name

    try:
        result = mcp_server._install_migrate_impl(tmp_path)
        assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
        # The preamble checks must have succeeded, so these specific errors must NOT appear.
        assert "does not exist" not in result.get("error", ""), (
            f"Preamble wrongly rejected existing file: {result}"
        )
        assert "is not a file" not in result.get("error", ""), (
            f"Preamble wrongly rejected a regular file: {result}"
        )
        print(f"  result: {result}")
    finally:
        os.unlink(tmp_path)


def test_physical_drive_does_not_raise() -> None:
    r"""\\.\PhysicalDrive0 must return a clean dict, not raise.

    On some Windows configurations this raises PermissionError from .exists();
    on others it might behave differently.  Either way it must not propagate
    an unhandled exception -- the test just asserts a dict comes back.
    """
    if sys.platform != "win32":
        print("  SKIP (not on Windows)")
        return
    result = mcp_server._install_migrate_impl(r"\\.\PhysicalDrive0")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}: {result!r}"
    assert result.get("applied") is False, f"Expected applied=False, got: {result}"
    print(f"  result: {result}")


# ---------------------------------------------------------------------------
# sync_target_file mass-removal guard: a genuine remove_secret call takes
# out one variable at a time, so a resync legitimately comments out one
# previously-live managed line at most. If a vault/index gets replaced or
# corrupted out from under a registered target (confirmed via a real
# red-team exercise against this tool), the old code would silently
# comment out EVERY managed line in that file in one no-password call.
# ---------------------------------------------------------------------------

def test_sync_target_file_refuses_to_wipe_every_managed_line_at_once() -> None:
    content = 'STRIPE_SECRET_KEY="value 2"\nDATABASE_PASSWORD="value 3"\n'
    tmp_path = _write_temp_env(content)
    try:
        # Neither name is in this index -- simulates the index having been
        # replaced/corrupted out from under a target that still references
        # both of its previously-live variables.
        try:
            store.sync_target_file(Path(tmp_path), index={}, managed_names={
                "STRIPE_SECRET_KEY", "DATABASE_PASSWORD"})
            raised = False
        except ValueError as e:
            raised = True
            msg = str(e)
        assert raised, "expected sync_target_file to refuse a total wipeout"
        assert "STRIPE_SECRET_KEY" in msg and "DATABASE_PASSWORD" in msg
        # Refusal must mean nothing was written -- file stays exactly as it was.
        assert Path(tmp_path).read_text() == content, (
            "REGRESSION: file was rewritten despite the refusal")
    finally:
        os.unlink(tmp_path)


def test_sync_target_file_refuses_majority_removal_even_with_one_survivor() -> None:
    """A red-team audit defeated the original all-or-nothing guard: an
    index that happened to still share ONE overlapping name with a
    target's managed set let 3 of 4 previously-live lines be wiped with no
    refusal at all. The guard must fire on a majority removal, not only a
    complete one."""
    content = (
        'STRIPE_SECRET_KEY="value 2"\n'
        'DATABASE_PASSWORD="value 3"\n'
        'OPENAI_API_KEY="value 4"\n'
        'LOG_LEVEL="value 5"\n'
    )
    tmp_path = _write_temp_env(content)
    try:
        # Only LOG_LEVEL survives in the index -- 3 of 4 would be wiped.
        try:
            store.sync_target_file(
                Path(tmp_path), index={"LOG_LEVEL": 5},
                managed_names={"STRIPE_SECRET_KEY", "DATABASE_PASSWORD",
                                "OPENAI_API_KEY", "LOG_LEVEL"})
            raised = False
        except ValueError:
            raised = True
        assert raised, (
            "REGRESSION (NEW-2): a majority removal (3 of 4) with one "
            "surviving overlapping name was not refused")
        assert Path(tmp_path).read_text() == content, (
            "REGRESSION: file was rewritten despite the refusal")
    finally:
        os.unlink(tmp_path)


def test_sync_target_file_still_removes_a_single_variable_normally() -> None:
    """Regression guard: the mass-removal refusal must not block the
    ordinary, legitimate one-at-a-time removal this behavior exists for."""
    content = 'STRIPE_SECRET_KEY="value 2"\nDATABASE_PASSWORD="value 3"\n'
    tmp_path = _write_temp_env(content)
    try:
        # Only STRIPE_SECRET_KEY is missing from the index -- a normal,
        # single remove_secret -- DATABASE_PASSWORD stays live.
        conflicts = store.sync_target_file(
            Path(tmp_path), index={"DATABASE_PASSWORD": 3},
            managed_names={"STRIPE_SECRET_KEY", "DATABASE_PASSWORD"})
        assert conflicts == []
        result = Path(tmp_path).read_text()
        assert "STRIPE_SECRET_KEY was removed from the vault" in result
        assert 'DATABASE_PASSWORD="value 3"' in result
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Residual secret leak in unrecognized_name/swallowed warnings: everything
# before the first '=' on a line was carried verbatim with no check that
# it's actually a plausible name -- for a swallowed URL-with-credentials
# continuation line, that "name" can itself BE the secret.
# ---------------------------------------------------------------------------

def test_swallowed_credential_shaped_line_is_redacted_not_leaked() -> None:
    """A URL-with-credentials line swallowed inside an unterminated-quote
    continuation must not leak the credential into the parsed tuple."""
    content = 'SECRET="unterminated value\nhttps://user:secretpass@host/path?a=b\nend"\n'
    tmp_path = _write_temp_env(content)
    try:
        parsed = store.parse_env_file(Path(tmp_path))
        swallowed = [item for item in parsed if item[0] == "swallowed"]
        assert swallowed, f"expected a 'swallowed' entry, got: {parsed}"
        for _, key in swallowed:
            assert "secretpass" not in key, (
                f"REGRESSION: credential leaked into swallowed key: {key!r}")
            assert key.startswith("(line ") and "withheld" in key, (
                f"expected a withheld placeholder, got: {key!r}")
    finally:
        os.unlink(tmp_path)


def test_unrecognized_hyphenated_name_still_shown_unredacted() -> None:
    """Regression guard against over-redaction: a top-level hyphenated
    name is exactly the kind of non-identifier-but-plausible-name text
    unrecognized_name exists to surface unredacted, for the human to fix."""
    content = "MY-VAR=somevalue\n"
    tmp_path = _write_temp_env(content)
    try:
        parsed = store.parse_env_file(Path(tmp_path))
        assert ("unrecognized_name", "MY-VAR") in parsed, (
            f"expected unredacted 'MY-VAR', got: {parsed}")
    finally:
        os.unlink(tmp_path)


def test_install_migrate_warnings_never_contain_leaked_credential_text() -> None:
    """End-to-end: _install_migrate_impl's returned warnings must not
    contain the leaked credential for the same crafted repro file."""
    content = (
        "MY-VAR=somevalue\n"
        'SECRET="unterminated value\n'
        "https://user:secretpass@host/path?a=b\n"
        'end"\n'
    )
    tmp_path = _write_temp_env(content)
    try:
        result = mcp_server._install_migrate_impl(tmp_path)
        joined = " ".join(result.get("warnings", []))
        assert "secretpass" not in joined, (
            f"REGRESSION: credential leaked into install_migrate warnings: {joined!r}")
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required)
# ---------------------------------------------------------------------------

def _run(fn) -> bool:
    name = fn.__name__
    print(f"Running {name} ...")
    try:
        fn()
        print(f"  PASS")
        return True
    except Exception as exc:
        import traceback
        print(f"  FAIL: {exc}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    tests = [
        test_unreachable_unc_path_does_not_raise,
        test_nonexistent_normal_path_returns_does_not_exist,
        test_real_file_passes_preamble,
        test_physical_drive_does_not_raise,
        test_sync_target_file_refuses_to_wipe_every_managed_line_at_once,
        test_sync_target_file_refuses_majority_removal_even_with_one_survivor,
        test_sync_target_file_still_removes_a_single_variable_normally,
        test_swallowed_credential_shaped_line_is_redacted_not_leaked,
        test_unrecognized_hyphenated_name_still_shown_unredacted,
        test_install_migrate_warnings_never_contain_leaked_credential_text,
    ]

    passed = [t for t in tests if _run(t)]
    failed = [t for t in tests if t not in passed]

    print()
    print(f"Results: {len(passed)}/{len(tests)} passed")
    if failed:
        print(f"FAILED: {[f.__name__ for f in failed]}")
        sys.exit(1)
    else:
        print("All tests passed.")
