"""
Regression suite for the manage_vault MCP tool, the vault_status extension,
and the _change_password_impl recovery-key fix introduced in release 1.4.0.

----------------------------------------------------------------------------
CRITICAL BUG COVERED
----------------------------------------------------------------------------
In 1.3.0, store.change_password() changed from returning None to returning
Optional[str] -- the newly issued recovery key -- because every password
change on a v2 vault with a recovery slot now rotates the data encryption key
and re-wraps a fresh recovery key.  _change_password_impl() captured that
return value but immediately discarded it: the human's old printed recovery
key was silently invalidated and the new one was never shown.  A user who
changed their password would then find their only disaster-recovery path gone
the next time they actually needed it, with no warning.

The fix: the returned key is routed through gui.show_recovery_key_dialog so
the human sees it in a native dialog, and the key NEVER appears in the tool
result -- MCP tool results reach the agent's context window and session logs.
If the human closes the dialog without confirming, the result says so honestly;
the password has already changed and the old printout is invalid.

----------------------------------------------------------------------------
Conventions (match test_trust.py / test_redaction.py)
----------------------------------------------------------------------------
- Plain ``def test_x() -> None:``; no pytest fixtures or conftest.
- 75-dash section banners with a prose failure-mode paragraph.
- "REGRESSION: ..." assertion messages.
- gui.* dialogs monkeypatched per-test; no real Tkinter windows open.
- Standalone runner block at the bottom sweeping globals() for test_*.
  Prints ``Results: N/N passed`` -- CI runs this AND pytest.

Runs under ``pytest tests/test_manage_vault.py -q`` and standalone:
  ``python tests/test_manage_vault.py``
"""
import contextlib
import json
import sys
import tempfile
from pathlib import Path

# Project root and tests dir must both be on sys.path.
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from vault_lib import crypto, gui, store  # noqa: E402

TEST_PASSWORD = "regression-mgmt-test-password-123"
NEW_PASSWORD = "brand-new-mgmt-password-456"
BASE_SECRETS = {"DOCKER_TEST_TOKEN": "tok-abc-123", "OTHER_SECRET": "other-xyz-789"}


# ---------------------------------------------------------------------------
# Isolation helpers -- redirect every store path global into a temp dir so no
# test ever touches the developer's real vault files.
# ---------------------------------------------------------------------------

def _isolate_all_store_paths(tmp_dir: Path) -> dict:
    """Redirect all store path globals (including BAK_FILE, FORMAT_FILE)."""
    originals = {
        "SALT_FILE": store.SALT_FILE,
        "SECRETS_FILE": store.SECRETS_FILE,
        "INDEX_FILE": store.INDEX_FILE,
        "ENV_FILE": store.ENV_FILE,
        "BAK_FILE": store.BAK_FILE,
        "FORMAT_FILE": store.FORMAT_FILE,
    }
    store.SALT_FILE = tmp_dir / "vault.salt"
    store.SECRETS_FILE = tmp_dir / "vault.enc"
    store.INDEX_FILE = tmp_dir / "vault_index.json"
    store.ENV_FILE = tmp_dir / "llm.env"
    store.BAK_FILE = tmp_dir / "vault.enc.bak"
    store.FORMAT_FILE = tmp_dir / "vault.format.txt"
    return originals


def _restore_all_store_paths(originals: dict) -> None:
    for name, value in originals.items():
        setattr(store, name, value)


# Fast scrypt params for testing (n=2**12 ~= 6 ms vs n=2**16 ~= 100 ms).
# Patched locally inside each isolation context so that the module-level
# _ORIG_SCRYPT_DEFAULT saved by test_store_v2.py (which restores it inside
# test_below_floor_header_silently_upgraded_on_save) is never clobbered.
_FAST_SCRYPT = crypto.ScryptParams(n=2 ** 12, r=8, p=1)


@contextlib.contextmanager
def _fast_scrypt():
    """Temporarily replace crypto.SCRYPT_DEFAULT with n=2**12 for speed."""
    original = crypto.SCRYPT_DEFAULT
    crypto.SCRYPT_DEFAULT = _FAST_SCRYPT
    try:
        yield
    finally:
        crypto.SCRYPT_DEFAULT = original


@contextlib.contextmanager
def isolated_v1_vault(secrets=None):
    """Temp dir with a real v1 vault (TEST_PASSWORD, BASE_SECRETS by default).
    Uses fast scrypt params locally so the module-level default is not changed."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_mgmt_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_all_store_paths(tmp_path)
        with _fast_scrypt():
            try:
                store.create_secrets_vault(TEST_PASSWORD)
                store.save_secrets(TEST_PASSWORD, secrets)
                store.save_index({name: i + 1 for i, name in enumerate(sorted(secrets))})
                yield tmp_path
            finally:
                _restore_all_store_paths(originals)


@contextlib.contextmanager
def isolated_v2_vault_with_recovery(secrets=None):
    """Temp dir with a real v2 vault that has a recovery slot."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_mgmt_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_all_store_paths(tmp_path)
        with _fast_scrypt():
            try:
                recovery_raw = bytes(crypto.new_recovery_key())
                store.create_v2_vault(TEST_PASSWORD, recovery_raw=recovery_raw)
                store.save_secrets(TEST_PASSWORD, secrets)
                store.save_index({name: i + 1 for i, name in enumerate(sorted(secrets))})
                yield tmp_path
            finally:
                _restore_all_store_paths(originals)


@contextlib.contextmanager
def isolated_v2_vault_no_recovery(secrets=None):
    """Temp dir with a real v2 vault that has NO recovery slot."""
    secrets = dict(secrets) if secrets is not None else dict(BASE_SECRETS)
    with tempfile.TemporaryDirectory(prefix="llm_vault_mgmt_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate_all_store_paths(tmp_path)
        with _fast_scrypt():
            try:
                store.create_v2_vault(TEST_PASSWORD)
                store.save_secrets(TEST_PASSWORD, secrets)
                store.save_index({name: i + 1 for i, name in enumerate(sorted(secrets))})
                yield tmp_path
            finally:
                _restore_all_store_paths(originals)


# ---------------------------------------------------------------------------
# Dialog monkeypatching helpers -- save original, substitute, restore.
# Pattern matches fake_dialog in test_trust.py (lines 116-136).
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def fake_change_password_dialog(old=TEST_PASSWORD, new=NEW_PASSWORD):
    """Patch gui.change_password_dialog to return fixed passwords."""
    original = gui.change_password_dialog
    def wrapper():
        return {"old": old, "new": new}
    gui.change_password_dialog = wrapper
    try:
        yield
    finally:
        gui.change_password_dialog = original


@contextlib.contextmanager
def fake_change_password_dialog_cancelled():
    """Patch gui.change_password_dialog to simulate user cancellation."""
    original = gui.change_password_dialog
    def wrapper():
        return {"old": None, "new": None}
    gui.change_password_dialog = wrapper
    try:
        yield
    finally:
        gui.change_password_dialog = original


@contextlib.contextmanager
def fake_show_recovery_key_dialog(return_value=True):
    """Patch gui.show_recovery_key_dialog to capture calls and return a fixed value.

    The function may not exist yet in gui (Lane 10 builds it); getattr/setattr
    handles both the existing-function and add-attribute cases cleanly.
    Yields the call log list so tests can assert on it."""
    original = getattr(gui, "show_recovery_key_dialog", _SENTINEL)
    calls = []

    def wrapper(key_text, slot_id):
        calls.append({"key_text": key_text, "slot_id": slot_id})
        return return_value

    gui.show_recovery_key_dialog = wrapper
    try:
        yield calls
    finally:
        if original is _SENTINEL:
            try:
                delattr(gui, "show_recovery_key_dialog")
            except AttributeError:
                pass
        else:
            gui.show_recovery_key_dialog = original


@contextlib.contextmanager
def fake_manage_vault_dialog(response: dict):
    """Patch gui.manage_vault_dialog to return a fixed response dict."""
    original = getattr(gui, "manage_vault_dialog", _SENTINEL)
    calls = []

    def wrapper():
        calls.append({})
        return response

    gui.manage_vault_dialog = wrapper
    try:
        yield calls
    finally:
        if original is _SENTINEL:
            try:
                delattr(gui, "manage_vault_dialog")
            except AttributeError:
                pass
        else:
            gui.manage_vault_dialog = original


# Sentinel for "attribute did not exist before patching".
class _Sentinel:
    pass
_SENTINEL = _Sentinel()


# ---------------------------------------------------------------------------
# THE CRITICAL BUG -- _change_password_impl drops the recovery key
#
# When a v2 vault has a recovery slot and the user changes the password,
# store.change_password() rotates the DEK and returns a NEW recovery key.
# The old code silently discarded that return value with:
#   store.change_password(outcome["old"], outcome["new"])   # return ignored
# The human's printed recovery key was permanently invalidated, no replacement
# shown, no warning given.  The fix: capture the key, route it through
# gui.show_recovery_key_dialog, and NEVER put it in the tool result.
#
# This test verifies:
#   (a) gui.show_recovery_key_dialog is called with a non-empty key_text.
#   (b) The key does not appear anywhere in json.dumps(result) -- checking
#       a single field is not enough; the assertion covers every field at once.
# ---------------------------------------------------------------------------

def test_change_password_v2_with_recovery_routes_key_to_dialog_not_result() -> None:
    """On a v2 vault with a recovery slot, _change_password_impl must call
    gui.show_recovery_key_dialog with the new recovery key AND must not let
    the key appear anywhere in the serialised tool result.

    Old broken behaviour: store.change_password() returned a new recovery key
    that the implementation silently discarded.  The human's old printout was
    permanently invalidated without any warning or replacement shown."""
    with isolated_v2_vault_with_recovery():
        with fake_change_password_dialog():
            with fake_show_recovery_key_dialog(return_value=True) as rk_calls:
                result = mcp_server._change_password_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: password change was not applied on a v2 vault with recovery, "
            f"got: {result!r}")
        assert len(rk_calls) == 1, (
            f"REGRESSION: show_recovery_key_dialog must be called exactly once when "
            f"store.change_password returns a new key; called {len(rk_calls)} time(s). "
            f"Old broken behaviour: the return value was discarded and the dialog never opened.")
        new_key = rk_calls[0]["key_text"]
        assert new_key, (
            f"REGRESSION: show_recovery_key_dialog was called but key_text was empty, "
            f"got: {rk_calls[0]!r}")
        # The recovery key must not appear anywhere in the serialised result.
        # Asserting json.dumps catches every field at once -- the old bug is exactly
        # this kind of "it's not in the obvious field" leak.
        result_str = json.dumps(result)
        assert new_key not in result_str, (
            f"REGRESSION: new recovery key appears somewhere in the serialised tool "
            f"result -- MCP results reach the agent's context window and session logs; "
            f"the key must only pass through gui.show_recovery_key_dialog. "
            f"Result (first 200 chars): {result_str[:200]!r}")


def test_change_password_v2_with_recovery_key_dialog_abandoned() -> None:
    """When the human closes the recovery key dialog without confirming, the
    result must honestly report that the password changed AND the key is
    unrecoverable.  It must NOT claim success without the warning, and it
    must NOT claim the password was not changed (it was).

    Old broken behaviour: the implementation didn't call the dialog at all,
    so this partial-success state was never surfaced -- the user got a clean
    'success' with a silently gone recovery path."""
    with isolated_v2_vault_with_recovery():
        with fake_change_password_dialog():
            with fake_show_recovery_key_dialog(return_value=False) as rk_calls:
                result = mcp_server._change_password_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: result must say applied=True because the password DID change "
            f"(the change is irreversible regardless of what happened to the key display), "
            f"got: {result!r}")
        warning = result.get("warning", "")
        assert warning, (
            f"REGRESSION: result must carry a 'warning' field when the recovery key "
            f"dialog was dismissed -- the human must be told the key is unrecoverable, "
            f"got: {result!r}")
        assert "cannot be recovered" in warning.lower() or "unrecoverable" in warning.lower(), (
            f"REGRESSION: warning must explicitly state the key is unrecoverable, "
            f"got warning: {warning!r}")
        assert len(rk_calls) == 1, (
            f"REGRESSION: show_recovery_key_dialog must still be called exactly once "
            f"even though the human dismissed it, got {len(rk_calls)} call(s)")


def test_change_password_v2_no_recovery_slot_no_key_dialog() -> None:
    """On a v2 vault that has NO recovery slot, store.change_password returns
    None -- there is no key to show.  gui.show_recovery_key_dialog must NOT
    be called in this case (there is nothing to display)."""
    with isolated_v2_vault_no_recovery():
        with fake_change_password_dialog():
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._change_password_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: password change on v2 vault without recovery failed, "
            f"got: {result!r}")
        assert len(rk_calls) == 0, (
            f"REGRESSION: show_recovery_key_dialog must not be called when the vault "
            f"has no recovery slot (there is no key to display), "
            f"got {len(rk_calls)} call(s)")
        # No warning field on a clean success.
        assert "warning" not in result, (
            f"REGRESSION: unexpected 'warning' key in result for no-recovery-slot case, "
            f"got: {result!r}")


# ---------------------------------------------------------------------------
# Wrong-password and cancel paths for _change_password_impl
#
# These paths must produce fixed, non-secret error messages and must not
# forward raw exception text from the store or crypto layers -- one careless
# str(e) is how internal state escapes into the agent's context.
# ---------------------------------------------------------------------------

def test_change_password_wrong_password_returns_fixed_message() -> None:
    """A wrong current password must produce a fixed error string, not a raw
    exception message.  The vault bytes must be unchanged after the failed attempt
    (change_password raises before writing anything on a WrongPassword).

    Old broken behaviour: this specific path was already handled, but the
    test locks in the message shape and the no-side-effect contract."""
    with isolated_v2_vault_no_recovery():
        before_bytes = store.SECRETS_FILE.read_bytes()
        with fake_change_password_dialog(old="definitely-wrong-password", new=NEW_PASSWORD):
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._change_password_impl()

        assert result.get("applied") is False, (
            f"REGRESSION: change_password with wrong password must return applied=False, "
            f"got: {result!r}")
        error = result.get("error", "")
        assert "incorrect" in error.lower() or "wrong" in error.lower(), (
            f"REGRESSION: error message for wrong password must say 'incorrect' or 'wrong', "
            f"got: {error!r}")
        # Error must not include raw exception text from the crypto layer.
        assert "Exception" not in error and "Traceback" not in error, (
            f"REGRESSION: raw exception text found in error message -- "
            f"crypto layer internals must not escape into results, got: {error!r}")
        assert len(rk_calls) == 0, (
            f"REGRESSION: show_recovery_key_dialog must not be called on a wrong-password "
            f"failure, got {len(rk_calls)} call(s)")
        after_bytes = store.SECRETS_FILE.read_bytes()
        assert before_bytes == after_bytes, (
            f"REGRESSION: vault bytes changed after a wrong-password attempt -- "
            f"a failed change must leave vault.enc byte-identical")


def test_change_password_cancelled_is_clean_noop() -> None:
    """A cancelled change_password_dialog must return applied=False with no
    side effects -- the vault must be completely unchanged."""
    with isolated_v2_vault_no_recovery():
        before_bytes = store.SECRETS_FILE.read_bytes()
        with fake_change_password_dialog_cancelled():
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._change_password_impl()

        assert result.get("applied") is False, (
            f"REGRESSION: a cancelled dialog must return applied=False, got: {result!r}")
        assert "error" not in result, (
            f"REGRESSION: a cancelled dialog must not set an error key -- it is a "
            f"clean no-op, got: {result!r}")
        assert len(rk_calls) == 0, (
            f"REGRESSION: show_recovery_key_dialog must not be called after a cancel, "
            f"got {len(rk_calls)} call(s)")
        after_bytes = store.SECRETS_FILE.read_bytes()
        assert before_bytes == after_bytes, (
            f"REGRESSION: vault bytes changed after a cancelled dialog -- must be a no-op")


# ---------------------------------------------------------------------------
# vault_status: format_version and recovery_key fields
#
# vault_status was extended in 1.4.0 to include the vault format version and
# non-secret recovery-slot metadata.  This lets the agent surface "you have
# no recovery slot" or "you are still on v1" without ever touching key material.
# vault_id is deliberately excluded (random internal identifier; no agent use
# case; could enable tracking across backups).
# ---------------------------------------------------------------------------

def test_vault_status_reports_format_version_v1() -> None:
    """vault_status must report format_version=1 for a v1 (PBKDF2/Fernet) vault
    and must not leak secret material in any field.

    This test locks in the shape so a refactor cannot silently drop the field."""
    with isolated_v1_vault():
        result = mcp_server._vault_status_impl()

    assert "format_version" in result, (
        f"REGRESSION: 'format_version' field missing from vault_status result, "
        f"got keys: {list(result.keys())!r}")
    assert result["format_version"] == 1, (
        f"REGRESSION: format_version must be 1 for a v1 vault, "
        f"got: {result['format_version']!r}")
    # No secret material anywhere in the serialised result.
    result_str = json.dumps(result)
    for name, value in BASE_SECRETS.items():
        assert value not in result_str, (
            f"REGRESSION: secret value for {name!r} found in vault_status result -- "
            f"vault_status must never return secret values, got result: {result_str[:300]!r}")


def test_vault_status_reports_format_version_v2() -> None:
    """vault_status must report format_version=2 for a v2 vault and must include
    a 'recovery_key' field showing whether a slot exists."""
    with isolated_v2_vault_with_recovery():
        result = mcp_server._vault_status_impl()

    assert result.get("format_version") == 2, (
        f"REGRESSION: format_version must be 2 for a v2 vault, "
        f"got: {result.get('format_version')!r}")
    assert "recovery_key" in result, (
        f"REGRESSION: 'recovery_key' field missing from vault_status result for a v2 vault, "
        f"got keys: {list(result.keys())!r}")
    rk = result["recovery_key"]
    assert rk.get("present") is True, (
        f"REGRESSION: recovery_key.present must be True for a vault with a recovery slot, "
        f"got: {rk!r}")
    assert "id" in rk, (
        f"REGRESSION: recovery_key.id field missing, got: {rk!r}")
    assert "created" in rk, (
        f"REGRESSION: recovery_key.created field missing, got: {rk!r}")


def test_vault_status_recovery_key_absent_for_v2_no_slot() -> None:
    """For a v2 vault without a recovery slot, vault_status must report
    recovery_key.present=False."""
    with isolated_v2_vault_no_recovery():
        result = mcp_server._vault_status_impl()

    assert result.get("format_version") == 2, (
        f"REGRESSION: format_version must be 2, got: {result.get('format_version')!r}")
    rk = result.get("recovery_key", {})
    assert rk.get("present") is False, (
        f"REGRESSION: recovery_key.present must be False for a v2 vault with no recovery "
        f"slot, got: {rk!r}")


def test_vault_status_never_leaks_secret_values() -> None:
    """vault_status must not expose secret values in any field regardless of
    vault format.  Checks every field of the serialised result."""
    with isolated_v2_vault_with_recovery():
        result = mcp_server._vault_status_impl()
    result_str = json.dumps(result)
    for name, value in BASE_SECRETS.items():
        assert value not in result_str, (
            f"REGRESSION: secret value for {name!r} appears in vault_status result -- "
            f"vault_status must not decrypt or return any secret material, "
            f"got result: {result_str[:400]!r}")


def test_vault_status_no_vault_id_in_result() -> None:
    """vault_id is an internal vault identifier that serves no agent use case
    and could enable tracking vault files across backups.  It must not appear
    in vault_status output."""
    with isolated_v2_vault_with_recovery():
        info = store.vault_info()  # get the real vault_id directly
        vault_id = info.get("vault_id")
        assert vault_id, "setup: vault_id must be non-empty to test its exclusion"

        result = mcp_server._vault_status_impl()
        result_str = json.dumps(result)
        assert vault_id not in result_str, (
            f"REGRESSION: vault_id ({vault_id!r}) appeared in vault_status result -- "
            f"it is a random internal identifier with no agent use case and must be "
            f"excluded to prevent cross-backup tracking.")


# ---------------------------------------------------------------------------
# manage_vault: action dispatch
#
# _manage_vault_impl opens gui.manage_vault_dialog() and dispatches to the
# matching store function.  Each test fakes the dialog with a specific action
# response and asserts the right store function was called with the right args.
# ---------------------------------------------------------------------------

def test_manage_vault_cancelled_is_clean_noop() -> None:
    """A None action from manage_vault_dialog is a clean cancellation -- no
    store function is called and the result is applied=False with no error."""
    with isolated_v2_vault_no_recovery():
        with fake_manage_vault_dialog({"action": None}) as calls:
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._manage_vault_impl()

    assert result.get("applied") is False, (
        f"REGRESSION: cancelled manage_vault dialog must return applied=False, "
        f"got: {result!r}")
    assert "error" not in result, (
        f"REGRESSION: a cancelled dialog must not set an error key, got: {result!r}")
    assert len(rk_calls) == 0, (
        f"REGRESSION: show_recovery_key_dialog must not be called on cancel, "
        f"got {len(rk_calls)} call(s)")


def test_manage_vault_change_password_action_dispatches_correctly() -> None:
    """The change_password action must call store.change_password with the
    passwords from the dialog and return applied=True on success.
    manage_vault_dialog uses 'old_password' and 'new_password' as the key names
    (not 'old'/'new' like change_password_dialog -- they are separate dialogs)."""
    with isolated_v2_vault_no_recovery():
        dialog_response = {
            "action": "change_password",
            "old_password": TEST_PASSWORD,
            "new_password": NEW_PASSWORD,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog():
                result = mcp_server._manage_vault_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: manage_vault change_password must return applied=True on success, "
            f"got: {result!r}")
        assert result.get("action") == "change_password", (
            f"REGRESSION: result must echo the action field, got: {result!r}")
        # Verify the vault actually changed by loading with the new password.
        # (Must be done inside the isolation context so store paths point at the temp vault.)
        loaded = store.load_secrets(NEW_PASSWORD)
        assert loaded == BASE_SECRETS, (
            f"REGRESSION: secrets after manage_vault change_password do not match -- "
            f"store.change_password may not have been called, got: {loaded!r}")


def test_manage_vault_change_password_with_recovery_calls_key_dialog() -> None:
    """For a v2 vault with a recovery slot, the change_password action must
    route the new recovery key through show_recovery_key_dialog and must not
    put the key in the result."""
    with isolated_v2_vault_with_recovery():
        dialog_response = {
            "action": "change_password",
            "old_password": TEST_PASSWORD,
            "new_password": NEW_PASSWORD,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog(return_value=True) as rk_calls:
                result = mcp_server._manage_vault_impl()

    assert result.get("applied") is True, (
        f"REGRESSION: manage_vault change_password on v2-with-recovery must succeed, "
        f"got: {result!r}")
    assert len(rk_calls) == 1, (
        f"REGRESSION: show_recovery_key_dialog must be called exactly once for "
        f"change_password on a v2 vault with a recovery slot, "
        f"got {len(rk_calls)} call(s)")
    new_key = rk_calls[0]["key_text"]
    result_str = json.dumps(result)
    assert new_key not in result_str, (
        f"REGRESSION: new recovery key appears in the manage_vault result -- "
        f"it must only pass through show_recovery_key_dialog, never into the result dict")


def test_manage_vault_setup_recovery_dispatches_to_reissue_recovery_key() -> None:
    """The setup_recovery action must call store.reissue_recovery_key (which
    adds a recovery slot if none exists) and show the key via show_recovery_key_dialog."""
    with isolated_v2_vault_no_recovery():
        dialog_response = {
            "action": "setup_recovery",
            "password": TEST_PASSWORD,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog(return_value=True) as rk_calls:
                result = mcp_server._manage_vault_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: setup_recovery must succeed on a v2 vault, got: {result!r}")
        assert result.get("action") == "setup_recovery", (
            f"REGRESSION: result must echo the action field, got: {result!r}")
        assert len(rk_calls) == 1, (
            f"REGRESSION: show_recovery_key_dialog must be called once for setup_recovery, "
            f"got {len(rk_calls)} call(s)")
        new_key = rk_calls[0]["key_text"]
        result_str = json.dumps(result)
        assert new_key not in result_str, (
            f"REGRESSION: recovery key found in manage_vault result for setup_recovery -- "
            f"must only appear in the native dialog")
        # Verify the vault now has a recovery slot.
        # (Must be inside the isolation context so vault_info reads the temp vault.)
        info = store.vault_info()
        assert info.get("recovery_slot") is True, (
            f"REGRESSION: vault does not have a recovery slot after setup_recovery, "
            f"vault_info: {info!r}")


def test_manage_vault_reissue_recovery_dispatches_correctly() -> None:
    """The reissue_recovery action must call store.reissue_recovery_key and
    show the new key via show_recovery_key_dialog without putting it in the result."""
    with isolated_v2_vault_with_recovery():
        old_info = store.vault_info()
        old_slot_id = old_info.get("recovery_slot_id")

        dialog_response = {
            "action": "reissue_recovery",
            "password": TEST_PASSWORD,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog(return_value=True) as rk_calls:
                result = mcp_server._manage_vault_impl()

    assert result.get("applied") is True, (
        f"REGRESSION: reissue_recovery must succeed on a v2 vault with a slot, "
        f"got: {result!r}")
    assert len(rk_calls) == 1, (
        f"REGRESSION: show_recovery_key_dialog must be called once for reissue_recovery, "
        f"got {len(rk_calls)} call(s)")
    new_key = rk_calls[0]["key_text"]
    result_str = json.dumps(result)
    assert new_key not in result_str, (
        f"REGRESSION: new recovery key found in reissue_recovery result -- "
        f"must only appear in the native dialog")
    # Verify the slot_id changed (old key is invalidated, new slot was issued).
    new_info = store.vault_info()
    assert new_info.get("recovery_slot_id") != old_slot_id, (
        f"REGRESSION: recovery_slot_id did not change after reissue_recovery -- "
        f"the old slot may still be valid, old: {old_slot_id!r}, new: {new_info.get('recovery_slot_id')!r}")


def test_manage_vault_upgrade_v2_dispatches_correctly() -> None:
    """The upgrade_v2 action must call store.upgrade_to_v2 and the vault must
    be readable as v2 afterward."""
    with isolated_v1_vault():
        dialog_response = {
            "action": "upgrade_v2",
            "password": TEST_PASSWORD,
            "recovery": False,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._manage_vault_impl()

        assert result.get("applied") is True, (
            f"REGRESSION: upgrade_v2 must succeed on a v1 vault, got: {result!r}")
        assert result.get("action") == "upgrade_v2", (
            f"REGRESSION: result must echo the action field, got: {result!r}")
        assert len(rk_calls) == 0, (
            f"REGRESSION: show_recovery_key_dialog must not be called when recovery=False, "
            f"got {len(rk_calls)} call(s)")
        # Verify the vault is now v2 on disk.
        # (Must be inside the isolation context so store.SECRETS_FILE points at the temp vault.)
        data = store.SECRETS_FILE.read_bytes()
        assert crypto.is_v2(data), (
            f"REGRESSION: vault is not v2 after upgrade_v2 -- "
            f"store.upgrade_to_v2 may not have been called")


def test_manage_vault_upgrade_v2_with_recovery_shows_key_dialog() -> None:
    """The upgrade_v2 action with recovery=True must call show_recovery_key_dialog
    and never put the key in the result."""
    with isolated_v1_vault():
        dialog_response = {
            "action": "upgrade_v2",
            "password": TEST_PASSWORD,
            "recovery": True,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog(return_value=True) as rk_calls:
                result = mcp_server._manage_vault_impl()

    assert result.get("applied") is True, (
        f"REGRESSION: upgrade_v2 with recovery=True must succeed, got: {result!r}")
    assert len(rk_calls) == 1, (
        f"REGRESSION: show_recovery_key_dialog must be called once for upgrade_v2 "
        f"with recovery=True, got {len(rk_calls)} call(s)")
    new_key = rk_calls[0]["key_text"]
    result_str = json.dumps(result)
    assert new_key not in result_str, (
        f"REGRESSION: recovery key found in upgrade_v2 result -- "
        f"must only appear in the native dialog")


def test_manage_vault_wrong_password_returns_fixed_message() -> None:
    """Any manage_vault action with a wrong password must produce a fixed error
    string.  Raw crypto exception text must not appear in the result."""
    with isolated_v2_vault_no_recovery():
        dialog_response = {
            "action": "change_password",
            "old_password": "completely-wrong-password",
            "new_password": NEW_PASSWORD,
        }
        with fake_manage_vault_dialog(dialog_response):
            with fake_show_recovery_key_dialog() as rk_calls:
                result = mcp_server._manage_vault_impl()

    assert result.get("applied") is False, (
        f"REGRESSION: wrong password must return applied=False, got: {result!r}")
    error = result.get("error", "")
    assert "incorrect" in error.lower() or "wrong" in error.lower(), (
        f"REGRESSION: wrong-password error must say 'incorrect' or 'wrong', "
        f"got: {error!r}")
    assert "Exception" not in error and "Traceback" not in error, (
        f"REGRESSION: raw exception text must not appear in the error message, "
        f"got: {error!r}")
    assert len(rk_calls) == 0, (
        f"REGRESSION: show_recovery_key_dialog must not be called on wrong password")


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required)
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
