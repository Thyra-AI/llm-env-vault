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
