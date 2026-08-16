"""Cross-lane integration tests for the 1.4.0 vault work.

These cover two behaviours that no single lane owned, and that were both
introduced during integration:

  * the first-run recovery drill runs BEFORE the recovery slot is committed,
    so cancelling it cannot leave a vault advertising a recovery key nobody
    holds;
  * the recover_vault MCP tool exists at all, and actually recovers a vault
    whose master password has been forgotten.

Both are the same underlying worry: a recovery key that silently does not
work is worse than having none, because nothing in normal operation ever
exercises it. The failure surfaces years later, at the one moment it matters.
"""
import contextlib
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_server  # noqa: E402
from vault_lib import crypto, gui, store  # noqa: E402

_STORE_PATHS = {
    "SALT_FILE": "vault.salt",
    "SECRETS_FILE": "vault.enc",
    "INDEX_FILE": "vault_index.json",
    "ENV_FILE": "llm.env",
    "BAK_FILE": "vault.enc.bak",
    "FORMAT_FILE": "vault.format.txt",
}


class _FakeLabel:
    """Stands in for the Tk status label _create_v2_with_drill writes to."""

    def config(self, **kwargs):
        pass


class _FakeRoot:
    def update_idletasks(self):
        pass


@contextlib.contextmanager
def _empty_vault_dir():
    """Redirect every store path into a fresh temp dir with NO vault in it.

    Unlike test_trust.py's isolated_vault(), this deliberately leaves the
    directory empty -- these tests exercise first-run creation, so a vault
    must not already exist. .resolve() matters on Windows, where mkdtemp
    hands back the 8.3 short form for long usernames.
    """
    originals = {name: getattr(store, name) for name in _STORE_PATHS}
    orig_scrypt = crypto.SCRYPT_DEFAULT
    orig_show = gui.show_recovery_key_dialog
    orig_recover = gui.recover_dialog
    with tempfile.TemporaryDirectory(prefix="llm_vault_int_") as tmp:
        tmp_path = pathlib.Path(tmp).resolve()
        for name, filename in _STORE_PATHS.items():
            setattr(store, name, tmp_path / filename)
        # 6ms instead of ~114ms per derivation; the header records whatever
        # params were used, so a low-param vault reads back at low params.
        crypto.SCRYPT_DEFAULT = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
        try:
            yield tmp_path
        finally:
            for name, value in originals.items():
                setattr(store, name, value)
            crypto.SCRYPT_DEFAULT = orig_scrypt
            gui.show_recovery_key_dialog = orig_show
            gui.recover_dialog = orig_recover


# ---------------------------------------------------------------------------
# The first-run drill gates the recovery slot
#
# The obvious implementation creates the vault with a recovery slot and then
# shows the key. If the human closes that window without writing the key down,
# the vault is left advertising recovery_slot: true for a key that can never
# be shown again -- vault_info() reports protection the user does not have.
# Because the key is generated locally, the drill can run first, which makes
# the cancel path honest: no slot is written and the vault is password-only.
# ---------------------------------------------------------------------------

def test_cancelled_drill_leaves_no_recovery_slot() -> None:
    with _empty_vault_dir():
        gui.show_recovery_key_dialog = lambda key_text, slot_id: False
        gui._create_v2_with_drill("first-run-password-1", True, _FakeLabel(), _FakeRoot())
        store.save_secrets("first-run-password-1", {"A": "alpha"})
        info = store.vault_info()
        assert info.get("recovery_slot") is False, (
            "REGRESSION: cancelling the write-it-down drill left a recovery slot "
            "behind, so vault_info() advertises a recovery key the human never "
            "saw and can never be shown again")


def test_cancelled_drill_still_produces_a_usable_vault() -> None:
    """Bailing out of the drill must not cost the user their vault."""
    with _empty_vault_dir():
        gui.show_recovery_key_dialog = lambda key_text, slot_id: False
        gui._create_v2_with_drill("first-run-password-1", True, _FakeLabel(), _FakeRoot())
        store.save_secrets("first-run-password-1", {"A": "alpha"})
        assert store.load_secrets("first-run-password-1") == {"A": "alpha"}
        assert store.vault_format_version() == 2


def test_confirmed_drill_commits_the_recovery_slot() -> None:
    with _empty_vault_dir():
        seen = {}

        def _confirm(key_text, slot_id):
            seen["key"] = key_text
            return True

        gui.show_recovery_key_dialog = _confirm
        gui._create_v2_with_drill("first-run-password-2", True, _FakeLabel(), _FakeRoot())
        store.save_secrets("first-run-password-2", {"A": "alpha"})
        assert store.vault_info().get("recovery_slot") is True
        # The key shown in the drill must be the one actually committed.
        opened = crypto.open_v2_with_recovery(store.SECRETS_FILE.read_bytes(), seen["key"])
        assert opened is not None, (
            "REGRESSION: the key displayed in the drill does not open the vault "
            "that was written -- the human wrote down the wrong string")


def test_declining_recovery_never_shows_the_drill() -> None:
    with _empty_vault_dir():
        calls = []
        gui.show_recovery_key_dialog = lambda key_text, slot_id: calls.append(1) or True
        gui._create_v2_with_drill("first-run-password-3", False, _FakeLabel(), _FakeRoot())
        store.save_secrets("first-run-password-3", {"A": "alpha"})
        assert calls == [], "drill was shown to a user who declined recovery"
        assert store.vault_info().get("recovery_slot") is False


# ---------------------------------------------------------------------------
# recover_vault -- the only entry point that does not need the password
#
# Every other operation authenticates with the master password. Without this
# tool the paper recovery key is decorative: the one situation it exists for
# (a genuinely forgotten password) would have no way to use it.
# ---------------------------------------------------------------------------

def _make_recoverable_vault(password, secrets):
    """First-run vault with a confirmed recovery slot; returns the paper key."""
    held = {}

    def _confirm(key_text, slot_id):
        held["key"] = key_text
        return True

    gui.show_recovery_key_dialog = _confirm
    gui._create_v2_with_drill(password, True, _FakeLabel(), _FakeRoot())
    store.save_secrets(password, secrets)
    return held["key"]


def test_recover_vault_restores_access_with_the_paper_key() -> None:
    with _empty_vault_dir():
        secrets = {"A": "alpha-value", "B": "beta-value"}
        paper_key = _make_recoverable_vault("forgotten-password-1", secrets)

        gui.recover_dialog = lambda: {"recovery_key": paper_key,
                                      "new_password": "brand-new-password-9"}
        gui.show_recovery_key_dialog = lambda key_text, slot_id: True
        result = mcp_server._recover_vault_impl()

        assert result["applied"] is True, result
        assert store.load_secrets("brand-new-password-9") == secrets, (
            "REGRESSION: recovery completed but the secrets did not survive")


def test_recover_vault_never_returns_key_material() -> None:
    with _empty_vault_dir():
        paper_key = _make_recoverable_vault("forgotten-password-2", {"A": "alpha"})
        issued = {}
        gui.recover_dialog = lambda: {"recovery_key": paper_key,
                                      "new_password": "brand-new-password-9"}

        def _capture(key_text, slot_id):
            issued["key"] = key_text
            return True

        gui.show_recovery_key_dialog = _capture
        blob = json.dumps(mcp_server._recover_vault_impl())

        assert paper_key not in blob, (
            "REGRESSION (A1-class): the recovery key the human typed came back "
            "to the agent in the tool result")
        assert issued.get("key") and issued["key"] not in blob, (
            "REGRESSION: the replacement recovery key was returned to the agent "
            "instead of being confined to the native dialog")
        assert "brand-new-password-9" not in blob, (
            "REGRESSION: the new master password came back in the tool result")


def test_recovery_invalidates_the_key_that_was_just_used() -> None:
    """The used key was read off paper and may have been observed."""
    with _empty_vault_dir():
        paper_key = _make_recoverable_vault("forgotten-password-3", {"A": "alpha"})
        gui.recover_dialog = lambda: {"recovery_key": paper_key,
                                      "new_password": "brand-new-password-9"}
        gui.show_recovery_key_dialog = lambda key_text, slot_id: True
        mcp_server._recover_vault_impl()

        try:
            crypto.open_v2_with_recovery(store.SECRETS_FILE.read_bytes(), paper_key)
            assert False, ("REGRESSION: the recovery key stayed valid after being "
                           "used, so a key read aloud from paper keeps working")
        except crypto.WrongRecoveryKey:
            pass


def test_mistyped_recovery_key_reports_a_typo_not_a_failure() -> None:
    """The appended checksum exists so this case is distinguishable."""
    with _empty_vault_dir():
        paper_key = _make_recoverable_vault("forgotten-password-4", {"A": "alpha"})
        typo = paper_key[:-1] + ("A" if paper_key[-1] != "A" else "B")
        gui.recover_dialog = lambda: {"recovery_key": typo,
                                      "new_password": "brand-new-password-9"}
        result = mcp_server._recover_vault_impl()

        assert result["applied"] is False
        assert "mistyped" in result["error"].lower(), (
            "a checksum failure should be reported as a probable typo, not as a "
            f"generic wrong-key error: {result['error']!r}")
        assert store.load_secrets("forgotten-password-4") == {"A": "alpha"}, (
            "a mistyped recovery key must leave the vault untouched")


def test_recover_vault_on_a_vault_with_no_recovery_slot() -> None:
    with _empty_vault_dir():
        gui.show_recovery_key_dialog = lambda key_text, slot_id: False
        gui._create_v2_with_drill("no-recovery-password", False, _FakeLabel(), _FakeRoot())
        store.save_secrets("no-recovery-password", {"A": "alpha"})

        fake_key = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
        gui.recover_dialog = lambda: {"recovery_key": fake_key,
                                      "new_password": "brand-new-password-9"}
        result = mcp_server._recover_vault_impl()

        assert result["applied"] is False
        assert "no recovery key" in result["error"].lower(), result


def test_cancelled_recover_dialog_is_a_clean_no_op() -> None:
    with _empty_vault_dir():
        _make_recoverable_vault("forgotten-password-5", {"A": "alpha"})
        gui.recover_dialog = lambda: {"recovery_key": None, "new_password": None}
        result = mcp_server._recover_vault_impl()

        assert result["applied"] is False
        assert "error" not in result, "a cancelled dialog is not an error"
        assert store.load_secrets("forgotten-password-5") == {"A": "alpha"}


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
