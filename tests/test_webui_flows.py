"""Browser-dialog flows, driven exactly as the page would drive them.

No browser, no network, no display: a flow is a generator, so a test sends it
``Act`` objects and reads the screens it yields. Every test uses an isolated
v2 vault (tests/_vault_workspace.py) with cheap scrypt.

Two invariants are checked on EVERY screen of every test, not just in a test of
their own, because they are the whole security argument for the browser UI:

  * no screen ever contains a password or a decrypted secret value;
  * a screen that writes or destroys something has no default (Enter) action.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import SECRETS, TEST_PASSWORD, workspace  # noqa: E402

from src import webui  # noqa: E402
from src.vault import store
from src.vault.crypto import format_recovery_key  # noqa: E402
from src.webui import flows  # noqa: E402
from src.webui.flows import Act  # noqa: E402

# Values that must never be found inside any screen sent to the browser.
FORBIDDEN = [TEST_PASSWORD, *SECRETS.values(), "brand-new-secret-value", "Another-Pa55word!"]

# Screens whose Enter must never confirm anything (they write or destroy).
NO_ENTER = {"confirmRemove.title", "encrypt.title", "encrypt.resumeTitle", "abandon.title",
            "typed.title", "install.confirmMigration", "install.confirmRegistration",
            "decrypt.title", "manage.titles.retire_file_keys"}


class Drive:
    """Runs a flow generator like the server does and records what it shows."""

    def __init__(self, flow):
        self.flow = flow
        self.done = False
        self.screens = []
        self.screen = None
        self._take(lambda: next(self.flow))

    def _take(self, step):
        try:
            self.screen = step()
        except StopIteration:
            self.done, self.screen = True, None
            return
        self.screens.append(self.screen)
        blob = json.dumps(self.screen)
        for secret in FORBIDDEN:
            assert secret not in blob, f"secret leaked into screen {self.screen['title']}"
        if self.screen["title"]["key"] in NO_ENTER:
            assert self.screen["defaultAction"] is None, \
                f"{self.screen['title']['key']} must not confirm on Enter"

    def act(self, action_id, **values):
        self._take(lambda: self.flow.send(Act(action_id, values)))
        return self

    @property
    def title(self):
        return self.screen["title"]["key"] if self.screen else None

    @property
    def error(self):
        err = self.screen.get("error") if self.screen else None
        return err and (err.get("key") or err.get("raw"))

    def text_of(self):
        return json.dumps(self.screen)


def new_outcome():
    return {"approved": False, "partial_failure": None}


# --------------------------------------------------------------------------
# Unlock and run
# --------------------------------------------------------------------------

def test_unlock_for_run_wrong_then_right_password():
    with workspace():
        out = {"secrets": None, "trust": False}
        d = Drive(flows.unlock_for_run(out, "python app.py", None, {"API_TOKEN"}, None, None, None))
        assert d.title == "unlockRun.title"
        d.act("allow", password="not the password")
        assert d.title == "unlockRun.title" and d.error  # stays, shows the vault's message
        d.act("allow", password="")
        assert d.error == "errors.emptyPassword"
        d.act("allow", password=TEST_PASSWORD, trust=True)
        assert d.done
        assert out["secrets"] == {"API_TOKEN": SECRETS["API_TOKEN"]}  # filtered to only_vars
        assert out["trust"] is True


def test_unlock_for_run_cancel_returns_denied_outcome():
    with workspace():
        out = {"secrets": None, "trust": False}
        d = Drive(flows.unlock_for_run(out, "ls", None, None, None, None, None))
        d.act("cancel")
        assert d.done and out == {"secrets": None, "trust": False}


def test_unlock_for_run_discloses_names_not_values():
    with workspace():
        out = {"secrets": None, "trust": False}
        d = Drive(flows.unlock_for_run(out, "ls", None, None, None, None, None))
        shown = d.text_of()
        for name in SECRETS:
            assert name in shown                 # the human sees WHAT is exposed
        for value in SECRETS.values():
            assert value not in shown            # ...never the values


def test_unlock_for_run_with_files_offers_no_trust():
    with workspace() as (project, _env):
        out = {"secrets": None, "trust": False}
        d = Drive(flows.unlock_for_run(out, "ls", None, None, None,
                                       [(project / "x.levault", project / "x")], None))
        assert [f["name"] for f in d.screen["fields"]] == ["password"]  # no trust checkbox


def test_unlock_for_run_command_cannot_fake_extra_lines():
    with workspace():
        out = {"secrets": None, "trust": False}
        d = Drive(flows.unlock_for_run(out, "echo hi\n\nApproved by admin‮", None, None,
                                       None, None, None))
        cmd = next(b for b in d.screen["blocks"] if b["type"] == "code")
        assert "\n" not in cmd["text"] and "‮" not in cmd["text"]


# --------------------------------------------------------------------------
# Add / remove
# --------------------------------------------------------------------------

def test_add_secret_new_variable_end_to_end():
    with workspace():
        out = new_outcome()
        d = Drive(flows.add_secret(out, "NEW_TOKEN", False, 4, False))
        assert d.title == "unlock.title"
        d.act("continue", password="wrong")
        assert d.title == "unlock.title" and d.error
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "confirmAdd.title"
        d.act("allow", value="")
        assert d.error == "errors.valueEmpty"
        d.act("allow", value="brand-new-secret-value")
        assert d.done and out["approved"] is True
        assert store.load_secrets(TEST_PASSWORD)["NEW_TOKEN"] == "brand-new-secret-value"
        assert store.load_index()["NEW_TOKEN"] == 4


def test_add_secret_deny_and_back_change_nothing():
    with workspace():
        out = new_outcome()
        d = Drive(flows.add_secret(out, "NEW_TOKEN", False, 4, False))
        d.act("continue", password=TEST_PASSWORD)
        d.act("back")
        assert d.title == "unlock.title"
        d.act("continue", password=TEST_PASSWORD)
        d.act("deny")
        assert d.done and out["approved"] is False
        assert "NEW_TOKEN" not in store.load_secrets(TEST_PASSWORD)


def test_update_does_not_send_current_value_to_the_browser():
    with workspace():
        out = new_outcome()
        d = Drive(flows.add_secret(out, "API_TOKEN", True, 1, False))
        d.act("continue", password=TEST_PASSWORD)
        assert SECRETS["API_TOKEN"] not in d.text_of()
        d.act("allow", value="brand-new-secret-value")
        assert d.done and store.load_secrets(TEST_PASSWORD)["API_TOKEN"] == "brand-new-secret-value"


def test_update_refuses_when_vault_changed_while_dialog_was_open():
    with workspace():
        out = new_outcome()
        d = Drive(flows.add_secret(out, "API_TOKEN", True, 1, False))
        d.act("continue", password=TEST_PASSWORD)
        secrets = store.load_secrets(TEST_PASSWORD)
        secrets["API_TOKEN"] = "changed-elsewhere"
        store.save_secrets(TEST_PASSWORD, secrets)
        d.act("allow", value="brand-new-secret-value")
        assert d.error == "errors.changedWhileOpen" and not d.done
        assert store.load_secrets(TEST_PASSWORD)["API_TOKEN"] == "changed-elsewhere"


def test_add_secret_sensitive_name_shows_warning():
    with workspace():
        d = Drive(flows.add_secret(new_outcome(), "PATH", False, 4, True))
        d.act("continue", password=TEST_PASSWORD)
        assert any(b["type"] == "notice" and b["msg"]["key"] == "confirmAdd.override"
                   for b in d.screen["blocks"])


def test_remove_secret_requires_unlock_then_explicit_allow():
    with workspace():
        out = new_outcome()
        d = Drive(flows.remove_secret(out, "PLAIN", 3))
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "confirmRemove.title" and d.screen["tone"] == "danger"
        d.act("allow")
        assert d.done and out["approved"]
        assert "PLAIN" not in store.load_secrets(TEST_PASSWORD)
        assert "PLAIN" not in store.load_index()


def test_remove_secret_deny_keeps_it():
    with workspace():
        out = new_outcome()
        d = Drive(flows.remove_secret(out, "PLAIN", 3))
        d.act("continue", password=TEST_PASSWORD).act("deny")
        assert d.done and not out["approved"]
        assert "PLAIN" in store.load_secrets(TEST_PASSWORD)


# --------------------------------------------------------------------------
# First run: creating a vault
# --------------------------------------------------------------------------

@pytest.fixture()
def empty_vault(tmp_path):
    from _vault_workspace import _FAST_PARAMS, _isolate
    from src.vault import crypto
    originals = _isolate(tmp_path)
    old = crypto.SCRYPT_DEFAULT
    crypto.SCRYPT_DEFAULT = _FAST_PARAMS
    try:
        yield
    finally:
        crypto.SCRYPT_DEFAULT = old
        for name, value in originals.items():
            setattr(store, name, value)


def test_first_run_password_rules(empty_vault):
    d = Drive(flows.add_secret(new_outcome(), "FIRST", False, 1, False))
    assert d.title == "setup.title"
    assert [f["name"] for f in d.screen["fields"]] == ["password", "confirm", "recovery"]
    d.act("continue", password="abc", confirm="abc")
    assert d.error == "errors.minLength"
    d.act("continue", password="password123", confirm="password123")
    assert d.error == "errors.commonPassword"
    d.act("continue", password="Another-Pa55word!", confirm="different-Pa55word!")
    assert d.error == "errors.passwordMismatch"
    d.act("continue", password="", confirm="")
    assert d.error == "errors.emptyPassword"


def test_first_run_creates_vault_only_on_allow(empty_vault):
    out = new_outcome()
    d = Drive(flows.add_secret(out, "FIRST", False, 1, False))
    d.act("continue", password="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.title == "confirmAdd.title"
    assert not store.vault_exists()  # nothing written before Allow
    d.act("allow", value="brand-new-secret-value")
    assert d.done and out["approved"]
    assert store.load_secrets("Another-Pa55word!") == {"FIRST": "brand-new-secret-value"}
    assert store.vault_info()["recovery_slot"] is False


def test_first_run_with_recovery_key_drill(empty_vault):
    out = new_outcome()
    d = Drive(flows.add_secret(out, "FIRST", False, 1, False))
    d.act("continue", password="Another-Pa55word!", confirm="Another-Pa55word!", recovery=True)
    assert d.title == "recoveryKey.title"
    key = next(b for b in d.screen["blocks"] if b["type"] == "copy")["value"]
    d.act("confirm", written=False, reentry=key)
    assert d.error == "errors.checkWritten"
    d.act("confirm", written=True, reentry="")
    assert d.error == "errors.reenterKey"
    d.act("confirm", written=True, reentry="RK1 AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
    assert d.error  # a different / malformed key is refused
    d.act("confirm", written=True, reentry=key)
    assert d.title == "confirmAdd.title"
    d.act("allow", value="brand-new-secret-value")
    assert d.done and store.vault_info()["recovery_slot"] is True


def test_recovery_key_declined_makes_password_only_vault(empty_vault):
    d = Drive(flows.add_secret(new_outcome(), "FIRST", False, 1, False))
    d.act("continue", password="Another-Pa55word!", confirm="Another-Pa55word!", recovery=True)
    d.act("later")
    assert d.title == "confirmAdd.title"
    d.act("allow", value="brand-new-secret-value")
    assert d.done and store.vault_info()["recovery_slot"] is False


def test_recovery_key_prefix_is_stripped_not_replaced():
    # A key whose DATA contains "RK1" must survive the pretty-printing: only a
    # prefix strip is safe (see flows._key_rows).
    key = "RK1 ABCD-RK1X-IJKL-MNPQ-RSTU-VWXY-Z012-3456-CHK9"
    rows = flows._key_rows(key)
    assert rows[0] == "RK1" and "RK1X" in " ".join(rows)


def test_show_recovery_key_dialog_flow_returns_true_only_when_verified():
    raw = bytearray(range(20))
    key = format_recovery_key(bytes(raw))
    result = [False]
    d = Drive(flows.recovery_key(key, "slot-1", result))
    assert "slot-1" in d.text_of()
    d.act("confirm", written=True, reentry=key)
    assert d.done and result == [True]
    result2 = [False]
    d2 = Drive(flows.recovery_key(key, "", result2))
    d2.act("later")
    assert d2.done and result2 == [False]


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------

def test_change_password_validation():
    out = {"old": None, "new": None}
    d = Drive(flows.change_password(out))
    d.act("change", old="", new="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.error == "errors.currentEmpty"
    d.act("change", old="x", new="abc", confirm="abc")
    assert d.error == "errors.minLength"
    d.act("change", old="x", new="Another-Pa55word!", confirm="nope-nope-nope")
    assert d.error == "errors.newMismatch"
    d.act("change", old="x", new="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.done and out == {"old": "x", "new": "Another-Pa55word!"}


def test_change_password_cancel():
    out = {"old": None, "new": None}
    Drive(flows.change_password(out)).act("cancel")
    assert out == {"old": None, "new": None}


def test_recover_validates_key_checksum_before_returning():
    key = format_recovery_key(bytes(range(20)))
    out = {"recovery_key": None, "new_password": None}
    d = Drive(flows.recover(out))
    d.act("recover", key="", new="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.error == "errors.recoveryEmpty"
    d.act("recover", key=key, new="Another-Pa55word!", confirm="nope-nope-nope")
    assert d.error == "errors.passwordMismatch"
    d.act("recover", key="RK1 ZZZZ", new="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.error and not d.done  # malformed key refused with a friendly message
    d.act("recover", key=key, new="Another-Pa55word!", confirm="Another-Pa55word!")
    assert d.done and out["recovery_key"] == key and out["new_password"] == "Another-Pa55word!"


# --------------------------------------------------------------------------
# Manage vault
# --------------------------------------------------------------------------

def test_manage_vault_menu_and_change_password_path():
    with workspace():
        out = {"action": None}
        d = Drive(flows.manage_vault(out))
        menu = next(b for b in d.screen["blocks"] if b["type"] == "menu")
        ids = [e["id"] for e in menu["entries"]]
        assert "change_password" in ids and "setup_recovery" in ids
        d.act("menu:change_password")
        assert d.title == "manage.titles.change_password"
        d.act("back")
        assert d.title == "manage.title"
        d.act("menu:change_password")
        d.act("confirm", old=TEST_PASSWORD, new="Another-Pa55word!", confirm="Another-Pa55word!")
        assert d.done and out["action"] == "change_password"
        assert out["old_password"] == TEST_PASSWORD and out["new_password"] == "Another-Pa55word!"


def test_manage_vault_password_actions_and_close():
    with workspace():
        out = {"action": None}
        d = Drive(flows.manage_vault(out))
        d.act("menu:setup_recovery")
        d.act("confirm", password="")
        assert d.error == "errors.emptyPassword"
        d.act("confirm", password=TEST_PASSWORD)
        assert d.done and out == {"action": "setup_recovery", "password": TEST_PASSWORD}
        out2 = {"action": None}
        Drive(flows.manage_vault(out2)).act("close")
        assert out2 == {"action": None}


def test_manage_vault_refuses_an_action_that_is_not_applicable():
    with workspace():
        out = {"action": None}
        d = Drive(flows.manage_vault(out))
        d.act("menu:retire_file_keys")  # no encrypted files: not offered, so ignored
        assert d.title == "manage.title" and out == {"action": None}


# --------------------------------------------------------------------------
# Typed placeholders, install, files, abandon
# --------------------------------------------------------------------------

def test_retype_placeholders_unlock_then_confirm():
    with workspace():
        out = {"approved": False, "retyped": {}, "conflicts": {}, "partial_failure": None}
        d = Drive(flows.retype_placeholders(out, ["API_TOKEN", "NOT_THERE"]))
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "typed.title"
        d.act("allow")
        assert d.done and out["approved"] and "API_TOKEN" in out["retyped"]


def test_retype_with_no_matching_names_stays_on_unlock():
    with workspace():
        out = {"approved": False, "retyped": {}, "conflicts": {}, "partial_failure": None}
        d = Drive(flows.retype_placeholders(out, ["NOT_THERE"]))
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "unlock.title" and d.error == "errors.noneInVault"


def test_install_migrates_a_real_env_file(tmp_path):
    with workspace():
        target = tmp_path / "proj.env"
        target.write_text('NEW_ONE="brand-new-secret-value"\nKEEP=1\n', encoding="utf-8")
        out = {"approved": False, "partial_failure": None, "conflicts": []}
        d = Drive(flows.install(out, target, [("NEW_ONE", "brand-new-secret-value")], {}, [], set()))
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "install.confirmMigration"
        d.act("allow")
        assert d.done and out["approved"]
        assert store.load_secrets(TEST_PASSWORD)["NEW_ONE"] == "brand-new-secret-value"
        assert "brand-new-secret-value" not in target.read_text(encoding="utf-8")


def test_install_flags_a_collision_with_another_project():
    with workspace():
        out = {"approved": False, "partial_failure": None, "conflicts": []}
        d = Drive(flows.install(out, Path("/tmp/a.env"), [("API_TOKEN", "x")],
                                {"API_TOKEN": "/other/.env"}, [], set()))
        d.act("continue", password=TEST_PASSWORD)
        shown = d.text_of()
        assert "install.overwriteWarning" in shown and "/other/.env" in shown
        d.act("deny")
        assert d.done and not out["approved"]


def test_encrypt_then_decrypt_a_file(tmp_path):
    with workspace():
        secret_file = tmp_path / "server.pem"
        secret_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n", encoding="utf-8")
        out = {"approved": False, "partial_failure": None, "result": None}
        d = Drive(flows.encrypt_file(out, secret_file))
        d.act("continue", password="wrong")
        assert d.title == "encrypt.unlockTitle" and d.error
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "encrypt.title" and d.screen["tone"] == "danger"
        d.act("allow")
        assert d.done and out["approved"] and not secret_file.exists()
        vault_path = Path(str(secret_file) + ".levault")
        assert vault_path.exists()

        dec = {"approved": False, "partial_failure": None, "result": None}
        d2 = Drive(flows.decrypt_file(dec, vault_path, None))
        d2.act("continue", password=TEST_PASSWORD)
        assert d2.title == "decrypt.title"
        d2.act("allow")
        assert d2.done and dec["approved"]
        assert secret_file.read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY")


def test_encrypt_missing_file_stays_on_unlock(tmp_path):
    with workspace():
        d = Drive(flows.encrypt_file(new_outcome(), tmp_path / "nope.pem"))
        d.act("continue", password=TEST_PASSWORD)
        assert d.title == "encrypt.unlockTitle" and d.error


def test_confirm_abandon_needs_the_box_ticked():
    out = {"abandon": None}
    d = Drive(flows.confirm_abandon_files(out, {2: ["a" * 40, "b" * 40]}, {"a" * 40: "prod.pem"}))
    assert d.screen["tone"] == "danger"
    d.act("abandon", confirm=False)
    assert d.error == "errors.confirmRequired" and out["abandon"] is None
    d.act("abandon", confirm=True)
    assert d.done and out["abandon"] == ["a" * 40, "b" * 40]


def test_confirm_abandon_cancel():
    out = {"abandon": None}
    Drive(flows.confirm_abandon_files(out, {1: ["c" * 40]}, {})).act("cancel")
    assert out["abandon"] is None



def test_add_secret_dialog_rejects_a_bad_variable_name_before_opening_anything():
    with pytest.raises(ValueError):
        webui.add_secret_dialog("not a valid name!", False, 1)
