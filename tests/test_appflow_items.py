"""Personal items in the app: add, view (hidden until revealed), copy, edit, delete.

The invariant checked on EVERY screen: a hidden field's text is in a screen only
while the person has asked to reveal exactly that field.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import SECRETS, TEST_PASSWORD, workspace  # noqa: E402
from test_appflow import Clock, FakeClipboard  # noqa: E402

from src.vault import store  # noqa: E402
from src.vault import items
from src.webui import appflow  # noqa: E402
from src.webui.flows import Act  # noqa: E402

LOGIN_PASSWORD = "Gh-pa55-w0rd-xyz"
CARD_NUMBER = "4111111111111111"
NOTE_BODY = "datbase: gocycling FmAu95LWizdGy2"
SSH_KEY = "-----BEGIN KEY-----\nQUJDREVGRw==\n-----END KEY-----"
HIDDEN_VALUES = [LOGIN_PASSWORD, CARD_NUMBER, NOTE_BODY, SSH_KEY, TEST_PASSWORD, *SECRETS.values()]
IDLE = 15 * 60 + 5  # just past the default auto-lock


class ItemApp:
    """Drives the app flow; flags a hidden value that appears without a reveal."""

    def __init__(self, clip=None, clock=None):
        self.clip, self.clock = clip or FakeClipboard(), clock or Clock()
        self.flow = appflow.vault_app({"closed": False}, clip=self.clip, clock=self.clock)
        self.allow = set()
        self.screen = None
        self._step(lambda: next(self.flow))

    def _step(self, fn):
        self.screen = fn()
        blob = json.dumps(self.screen)
        for value in HIDDEN_VALUES:
            if value in self.allow:
                continue
            assert value not in blob, f"hidden value leaked into {self.screen['title']['key']}"
        return self

    def act(self, action_id, **values):
        return self._step(lambda: self.flow.send(Act(action_id, values)))

    def unlock(self):
        return self.act("continue", password=TEST_PASSWORD)

    @property
    def title(self):
        return self.screen["title"]["key"]

    @property
    def rows(self):
        return self.screen["app"]["items"]

    def row(self, name):
        return next(r for r in self.rows if r["name"] == name)

    def fields_block(self):
        return next(b for b in self.screen["blocks"] if b["type"] == "fields")

    def field(self, fid):
        return next(r for r in self.fields_block()["rows"] if r["id"] == fid)

    def add(self, item_type, **values):
        self.act("add")
        self.act(f"menu:type:{item_type}")
        return self.act("save", **values)


@pytest.fixture()
def app():
    with workspace():
        a = ItemApp()
        a.unlock()
        yield a


def test_add_asks_for_the_type_first(app):
    app.act("add")
    assert app.title == "vaultApp.item.chooseTitle"
    entries = next(b for b in app.screen["blocks"] if b["type"] == "menu")["entries"]
    assert [e["id"] for e in entries] == ["type:secret", "type:login", "type:card", "type:identity", "type:note", "type:ssh"]
    app.act("back")
    assert app.title == "vaultApp.title"


def test_a_note_is_saved_listed_and_stored_encrypted(app):
    app.allow = {NOTE_BODY}
    app.add("note", name="azure", notes=NOTE_BODY, folder="work")
    app.allow = set()
    assert app.title == "vaultApp.title" and app.screen["toast"]["msg"]["key"] == "vaultApp.toast.saved"
    row = app.row("azure")
    assert row["type"] == "note" and row["sub"] == "" and row["folder"] == "work"
    assert items.load(TEST_PASSWORD)[0]["notes"] == NOTE_BODY


def test_a_login_lists_its_username_but_never_its_password(app):
    app.allow = {LOGIN_PASSWORD}
    app.add("login", name="github", username="ana", password=LOGIN_PASSWORD, uri="https://github.com")
    app.allow = set()
    assert app.row("github")["sub"] == "ana" and app.row("github")["type"] == "login"
    assert items.load(TEST_PASSWORD)[0]["fields"]["password"] == LOGIN_PASSWORD


def test_the_list_mixes_secrets_and_items_and_counts_both(app):
    app.add("note", name="azure")
    assert {r["type"] for r in app.rows} == {"secret", "note"}
    assert app.screen["app"]["info"]["count"] == len(SECRETS) + 1
    assert [r["name"].lower() for r in app.rows] == sorted(r["name"].lower() for r in app.rows)


def test_empty_name_is_refused_with_the_form_kept(app):
    app.act("add")
    app.act("menu:type:note")
    app.act("save", name="  ")
    assert app.title == "vaultApp.item.add.note" and app.screen["error"]["key"] == "vaultApp.item.invalid"
    assert items.load(TEST_PASSWORD) == []


def test_cancelling_the_form_saves_nothing(app):
    app.act("add")
    app.act("menu:type:login")
    app.act("back")
    assert app.title == "vaultApp.title" and items.load(TEST_PASSWORD) == []


def _login_in_the_list(app):
    app.allow = {LOGIN_PASSWORD}
    app.add("login", name="github", username="ana", password=LOGIN_PASSWORD)
    app.allow = set()
    return app.row("github")["id"]


def test_the_view_hides_secret_fields_until_revealed(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    assert app.title == "vaultApp.item.view.login"
    assert app.field("username")["value"] == "ana" and app.field("username")["hidden"] is False
    password = app.field("password")
    assert password["hidden"] is True and password["value"] is None and password["revealed"] is False


def test_reveal_shows_only_that_field_and_hide_takes_it_away(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    app.allow = {LOGIN_PASSWORD}
    app.act("menu:reveal:password")
    assert app.field("password")["value"] == LOGIN_PASSWORD and app.field("password")["revealed"] is True
    app.allow = set()
    app.act("menu:hide:password")
    assert app.field("password")["value"] is None


def test_leaving_the_view_forgets_what_was_revealed(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    app.allow = {LOGIN_PASSWORD}
    app.act("menu:reveal:password")
    app.allow = set()
    app.act("back")
    app.act(f"view:{item_id}")
    assert app.field("password")["value"] is None


def test_revealing_a_field_that_does_not_exist_is_ignored(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    app.act("menu:reveal:../../etc/passwd")
    app.act("menu:reveal:notes")  # empty, so not listed
    assert app.title == "vaultApp.item.view.login"


def test_copying_a_field_uses_the_clipboard_and_the_screen_stays_clean(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    app.act("menu:copy:password")
    assert app.clip.copied == [LOGIN_PASSWORD]
    assert len(app.clip.cleared) == 1 and app.clip.cleared[0][0] == LOGIN_PASSWORD
    assert app.screen["toast"]["msg"]["key"] == "vaultApp.toast.copied"
    assert app.field("password")["value"] is None


def test_the_lists_copy_button_copies_the_primary_field(app):
    item_id = _login_in_the_list(app)
    app.act(f"icopy:{item_id}")
    assert app.clip.copied == [LOGIN_PASSWORD]
    assert len(app.clip.cleared) == 1


def test_a_note_view_hides_the_note_text(app):
    app.allow = {NOTE_BODY}
    app.add("note", name="azure", notes=NOTE_BODY)
    app.allow = set()
    app.act(f"view:{app.row('azure')['id']}")
    assert app.title == "vaultApp.item.view.note"
    assert app.field("notes")["hidden"] is True and app.field("notes")["value"] is None
    assert app.field("notes")["multiline"] is True


def test_a_multiline_ssh_key_round_trips_and_is_hidden(app):
    app.allow = {SSH_KEY}
    app.add("ssh", name="deploy", privateKey=SSH_KEY, publicKey="ssh-ed25519 AAAA test")
    app.allow = set()
    app.act(f"view:{app.row('deploy')['id']}")
    assert app.field("privateKey")["value"] is None
    assert app.field("publicKey")["value"] == "ssh-ed25519 AAAA test"
    assert items.load(TEST_PASSWORD)[0]["fields"]["privateKey"] == SSH_KEY


def test_card_number_is_hidden_and_brand_is_the_subtitle(app):
    app.allow = {CARD_NUMBER}
    app.add("card", name="visa", brand="Visa", number=CARD_NUMBER, holder="Ana")
    app.allow = set()
    assert app.row("visa")["sub"] == "Visa"
    app.act(f"view:{app.row('visa')['id']}")
    assert app.field("number")["hidden"] is True and app.field("holder")["value"] == "Ana"


def test_the_view_carries_the_history_times(app):
    app.add("note", name="azure")
    app.act(f"view:{app.row('azure')['id']}")
    history = next(b for b in app.screen["blocks"] if b["type"] == "history")
    assert history["created"] and history["created"] == history["updated"]


def test_edit_is_prefilled_for_the_owner_and_saves_changes(app):
    item_id = _login_in_the_list(app)
    app.act(f"view:{item_id}")
    app.allow = {LOGIN_PASSWORD}
    app.act("edit")
    assert app.title == "vaultApp.item.edit.login"
    by_name = {f["name"]: f for f in app.screen["fields"]}
    assert by_name["name"]["initial"] == "github" and by_name["username"]["initial"] == "ana"
    assert by_name["password"]["initial"] == LOGIN_PASSWORD
    app.allow = set()
    app.act("save", name="github", username="ana2", password="new-pass-123", notes="", folder="")
    assert app.title == "vaultApp.item.view.login"
    assert items.load(TEST_PASSWORD)[0]["fields"]["username"] == "ana2"


def test_delete_needs_a_confirmation_that_is_not_the_default(app):
    app.add("note", name="azure")
    item_id = app.row("azure")["id"]
    app.act(f"idelete:{item_id}")
    assert app.title == "vaultApp.item.deleteTitle" and app.screen["defaultAction"] is None
    app.act("deny")
    assert len(items.load(TEST_PASSWORD)) == 1
    app.act(f"idelete:{item_id}")
    app.act("allow")
    assert app.title == "vaultApp.title" and items.load(TEST_PASSWORD) == []
    assert all(r["name"] != "azure" for r in app.rows)


def test_deleting_from_the_view_returns_to_the_list(app):
    app.add("note", name="azure")
    app.act(f"view:{app.row('azure')['id']}")
    app.act("delete")
    app.act("allow")
    assert app.title == "vaultApp.title" and items.load(TEST_PASSWORD) == []


def test_items_come_back_after_locking(app):
    app.add("note", name="azure")
    app.act("lock")
    assert app.title == "vaultApp.lock.title" and "items" not in app.screen["app"]
    app.unlock()
    assert [r["name"] for r in app.rows if r["type"] == "note"] == ["azure"]


def test_the_view_does_not_keep_the_session_alive_past_the_idle_limit():
    with workspace():
        clock = Clock()
        idle = ItemApp(clock=clock)
        idle.unlock()
        idle.allow = {LOGIN_PASSWORD}
        idle.add("login", name="github", username="ana", password=LOGIN_PASSWORD)
        item_id = idle.row("github")["id"]
        idle.act(f"view:{item_id}")
        idle.act("menu:reveal:password")
        idle.allow = set()
        clock.now += IDLE
        idle.act("menu:copy:password")           # the next thing the page sends
        assert idle.title == "vaultApp.lock.title"
        assert idle.clip.copied == []             # the action was NOT carried out


def test_a_form_left_open_past_the_idle_limit_locks_instead_of_saving():
    with workspace():
        clock = Clock()
        idle = ItemApp(clock=clock)
        idle.unlock()
        idle.act("add")
        idle.act("menu:type:note")
        clock.now += IDLE
        idle.act("save", name="late")
        assert idle.title == "vaultApp.lock.title"
        assert items.load(TEST_PASSWORD) == []


def test_corrupt_items_keep_the_vault_locked_with_a_message():
    with workspace():
        body = store.load_vault_body(TEST_PASSWORD)
        body[items.ITEMS_KEY] = {"v": 99, "items": []}
        store.save_vault_body(TEST_PASSWORD, body)
        broken = ItemApp()
        broken.unlock()
        assert broken.title == "vaultApp.lock.title"
        assert broken.screen["error"]["key"] == "vaultApp.item.corrupted"


def test_a_secret_edit_does_not_touch_items(app):
    app.add("note", name="azure")
    app.act("edit:API_TOKEN")
    app.act("save", value="a-new-secret-value")
    assert [i["name"] for i in items.load(TEST_PASSWORD)] == ["azure"]
