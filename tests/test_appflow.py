"""The Thyra Vault app flow, driven exactly as the page would drive it.

No browser, no display, no real clipboard: the flow is a generator, a fake
clipboard records what would have been copied, and a fake clock stands in for
idle time. Every screen of every test is checked for the invariant that is the
whole security argument of the app: no screen ever contains the master
password or a stored VALUE ("copy" is a server-side clipboard write).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import SECRETS, TEST_PASSWORD, workspace  # noqa: E402

from src.vault import store  # noqa: E402
from src.webui import appflow, prefs  # noqa: E402
from src.webui.flows import Act  # noqa: E402

NEW_PASSWORD = "A-brand-new-passphrase-7"
NEW_VALUE = "brand-new-secret-value"
FORBIDDEN = [TEST_PASSWORD, NEW_PASSWORD, NEW_VALUE, *SECRETS.values()]


class FakeClipboard:
    def __init__(self, fail=None):
        self.copied, self.cleared, self.fail = [], [], fail

    def copy(self, text):
        if self.fail:
            return self.fail
        self.copied.append(text)
        return None

    def clear_later(self, value, seconds):
        self.cleared.append((value, seconds))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class App:
    def __init__(self, clip=None, clock=None):
        self.clip, self.clock = clip or FakeClipboard(), clock or Clock()
        self.outcome = {"closed": False}
        self.flow = appflow.vault_app(self.outcome, clip=self.clip, clock=self.clock)
        self.done = False
        self.screen = None
        self._step(lambda: next(self.flow))

    def _step(self, fn):
        try:
            self.screen = fn()
        except StopIteration:
            self.done, self.screen = True, None
            return self
        blob = json.dumps(self.screen)
        for secret in FORBIDDEN:
            assert secret not in blob, f"a secret leaked into screen {self.screen['title']}"
        return self

    def act(self, action_id, **values):
        return self._step(lambda: self.flow.send(Act(action_id, values)))

    @property
    def title(self):
        return self.screen["title"]["key"] if self.screen else None

    @property
    def app(self):
        return self.screen.get("app") or {}

    def unlock(self, password=TEST_PASSWORD):
        return self.act("continue", password=password)

    def names(self):
        return [i["name"] for i in self.app["items"]]


@pytest.fixture()
def app():
    with workspace():
        yield App()


# --- lock / unlock -----------------------------------------------------------

def test_starts_locked_and_shows_no_items(app):
    assert app.title == "vaultApp.lock.title"
    assert app.app["view"] == "lock" and "items" not in app.app
    assert app.app["firstRun"] is False


def test_wrong_password_stays_locked_with_an_error(app):
    app.unlock("not-the-password")
    assert app.title == "vaultApp.lock.title" and app.screen["error"]


def test_empty_password_is_refused(app):
    app.act("continue", password="")
    assert app.title == "vaultApp.lock.title"
    assert app.screen["error"]["key"] == "errors.emptyPassword"


def test_unlock_lists_names_without_values(app):
    app.unlock()
    assert app.title == "vaultApp.title" and app.app["view"] == "home"
    assert app.names() == sorted(SECRETS)
    api = next(i for i in app.app["items"] if i["name"] == "API_TOKEN")
    assert api["number"] == 1 and api["kind"] == "token"
    assert next(i for i in app.app["items"] if i["name"] == "DB_PASSWORD")["kind"] == "password"
    assert api["fileCount"] == 1 and api["files"] == [".env"]
    info = app.app["info"]
    assert info["format"] == 2 and info["count"] == 3


def test_quit_from_the_lock_screen_ends_the_app(app):
    app.act("quit")
    assert app.done and app.outcome["closed"] is True


def test_first_run_creates_the_vault():
    with workspace():
        store.SECRETS_FILE.unlink()
        store.SALT_FILE.unlink(missing_ok=True)
        fresh = App()
        assert fresh.app["firstRun"] is True
        fresh.act("continue", password="weak", confirm="weak")
        assert fresh.title == "vaultApp.lock.createTitle" and fresh.screen["error"]
        fresh.act("continue", password=NEW_PASSWORD, confirm="different-one-123")
        assert fresh.screen["error"]["key"] == "errors.passwordMismatch"
        fresh.act("continue", password=NEW_PASSWORD, confirm=NEW_PASSWORD)
        assert fresh.title == "vaultApp.title" and fresh.names() == []
        assert store.load_secrets(NEW_PASSWORD) == {}


# --- copy --------------------------------------------------------------------

def test_copy_puts_the_value_on_the_clipboard_and_never_in_the_screen(app):
    app.unlock()
    app.act("copy:API_TOKEN", tab="vault")
    assert app.clip.copied == [SECRETS["API_TOKEN"]]
    assert app.clip.cleared == [(SECRETS["API_TOKEN"], prefs.DEFAULTS["clipboardSeconds"])]
    assert app.screen["toast"]["msg"]["key"] == "vaultApp.toast.copied"


def test_copy_of_an_unknown_name_does_nothing(app):
    app.unlock()
    app.act("copy:NOT_THERE")
    assert app.clip.copied == [] and app.screen.get("toast") is None


def test_copy_failure_is_reported_and_nothing_is_scheduled():
    with workspace():
        failing = App(clip=FakeClipboard(fail="unavailable"))
        failing.unlock()
        failing.act("copy:API_TOKEN")
        assert failing.screen["toast"]["tone"] == "error"
        assert failing.screen["toast"]["msg"]["key"] == "vaultApp.toast.copy_unavailable"
        assert failing.clip.cleared == []


# --- add / edit / delete ------------------------------------------------------

def test_add_saves_to_the_vault_and_the_index(app):
    app.unlock()
    app.act("add")
    app.act("menu:type:secret")
    assert app.title == "vaultApp.form.addTitle"
    app.act("save", name="not a valid name", value=NEW_VALUE)
    assert app.screen["error"]["key"] == "vaultApp.form.nameInvalid"
    app.act("save", name="NEW_KEY", value="")
    assert app.screen["error"]["key"] == "errors.valueEmpty"
    app.act("save", name="NEW_KEY", value=NEW_VALUE)
    assert app.title == "vaultApp.title" and "NEW_KEY" in app.names()
    assert app.screen["toast"]["msg"]["key"] == "vaultApp.toast.saved"
    assert store.load_secrets(TEST_PASSWORD)["NEW_KEY"] == NEW_VALUE
    assert "NEW_KEY" in store.load_index()


def test_add_refuses_a_name_that_exists(app):
    app.unlock()
    app.act("add")
    app.act("menu:type:secret")
    app.act("save", name="API_TOKEN", value=NEW_VALUE)
    assert app.screen["error"]["key"] == "vaultApp.form.nameExists"
    assert store.load_secrets(TEST_PASSWORD)["API_TOKEN"] == SECRETS["API_TOKEN"]


def test_add_cancel_changes_nothing(app):
    app.unlock()
    app.act("add")
    app.act("back")
    assert app.title == "vaultApp.title"
    assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_edit_replaces_the_value_and_keeps_the_placeholder(app):
    app.unlock()
    app.act("edit:API_TOKEN")
    assert app.title == "vaultApp.form.editTitle" and app.screen["fields"][0]["name"] == "value"
    app.act("save", value=NEW_VALUE)
    assert store.load_secrets(TEST_PASSWORD)["API_TOKEN"] == NEW_VALUE
    assert store.load_index()["API_TOKEN"] == 1


def test_delete_needs_a_confirmation_that_is_not_the_default(app):
    app.unlock()
    app.act("delete:PLAIN")
    assert app.title == "confirmRemove.title" and app.screen["defaultAction"] is None
    app.act("deny")
    assert "PLAIN" in store.load_secrets(TEST_PASSWORD)
    app.act("delete:PLAIN")
    app.act("allow")
    assert app.title == "vaultApp.title" and "PLAIN" not in app.names()
    assert "PLAIN" not in store.load_secrets(TEST_PASSWORD)
    assert "PLAIN" not in store.load_index()


def test_a_write_does_not_clobber_a_change_made_elsewhere(app):
    app.unlock()
    elsewhere = store.load_secrets(TEST_PASSWORD)
    elsewhere["OTHER_PROCESS"] = "written-by-someone-else"
    store.save_secrets(TEST_PASSWORD, elsewhere)
    app.act("add")
    app.act("menu:type:secret")
    app.act("save", name="NEW_KEY", value=NEW_VALUE)
    final = store.load_secrets(TEST_PASSWORD)
    assert final["OTHER_PROCESS"] == "written-by-someone-else" and final["NEW_KEY"] == NEW_VALUE


# --- lock, idle, preferences ----------------------------------------------------

def test_lock_returns_to_the_lock_screen_and_forgets_the_secrets(app):
    app.unlock()
    app.act("lock")
    assert app.title == "vaultApp.lock.title" and "items" not in app.app
    app.unlock()
    assert app.title == "vaultApp.title"


def test_idle_beyond_the_limit_locks_even_if_the_page_does_nothing():
    with workspace():
        clock = Clock()
        idle = App(clock=clock)
        idle.unlock()
        clock.now += idle.app["prefs"]["autoLockMinutes"] * 60 + 5
        idle.act("copy:API_TOKEN")  # the next thing the page sends, after the limit
        assert idle.title == "vaultApp.lock.title"
        assert idle.clip.copied == []  # the action was NOT carried out
        assert idle.screen["toast"]["msg"]["key"] == "vaultApp.lock.auto"


def test_activity_within_the_limit_keeps_it_unlocked():
    with workspace():
        clock = Clock()
        busy = App(clock=clock)
        busy.unlock()
        for _ in range(5):
            clock.now += 10 * 60  # ten minutes each time: under the 15 minute default
            busy.act("copy:API_TOKEN")
            assert busy.title == "vaultApp.title"


def test_the_page_can_lock_itself_after_inactivity(app):
    app.unlock()
    app.act("lock", auto=True)
    assert app.title == "vaultApp.lock.title"
    assert app.screen["toast"]["msg"]["key"] == "vaultApp.lock.auto"


def test_preferences_are_saved_validated_and_clamped(app):
    app.unlock()
    app.act("prefs", changes={"language": "pt-PT", "theme": "dark", "autoLockMinutes": 5,
                              "clipboardSeconds": 9999, "generator": {"length": 1000}})
    saved = app.app["prefs"]
    assert saved["language"] == "pt-PT" and saved["theme"] == "dark"
    assert saved["autoLockMinutes"] == 5
    assert saved["clipboardSeconds"] == prefs.DEFAULTS["clipboardSeconds"]  # not on the list
    assert saved["generator"]["length"] == 128                              # clamped
    assert prefs.load() == saved                                             # persisted


def test_a_hand_edited_preferences_file_cannot_disable_the_timers(app):
    (store.ROOT / prefs.FILE_NAME).write_text(json.dumps(
        {"autoLockMinutes": 100000, "clipboardSeconds": 0, "theme": "<script>", "language": 5,
         "generator": {"length": "many"}}), "utf-8")
    loaded = prefs.load()
    assert loaded["autoLockMinutes"] == prefs.DEFAULTS["autoLockMinutes"]
    assert loaded["clipboardSeconds"] == prefs.DEFAULTS["clipboardSeconds"]
    assert loaded["theme"] == "system" and loaded["language"] is None
    assert loaded["generator"]["length"] == 20


def test_corrupt_preferences_fall_back_to_defaults(app):
    (store.ROOT / prefs.FILE_NAME).write_text("{not json", "utf-8")
    assert prefs.load() == prefs.clean({})


# --- account security --------------------------------------------------------

def test_change_password_runs_in_the_app_and_the_session_keeps_working(app):
    app.unlock()
    app.act("manage")
    assert app.title == "manage.title"
    app.act("menu:change_password")
    app.act("confirm", old=TEST_PASSWORD, new=NEW_PASSWORD, confirm=NEW_PASSWORD)
    assert app.title == "vaultApp.title"
    assert app.screen["toast"]["msg"]["key"] == "vaultApp.result.passwordChanged"
    assert store.load_secrets(NEW_PASSWORD) == SECRETS
    # still unlocked, and a write now uses the NEW password
    app.act("add")
    app.act("menu:type:secret")
    app.act("save", name="AFTER_CHANGE", value=NEW_VALUE)
    assert store.load_secrets(NEW_PASSWORD)["AFTER_CHANGE"] == NEW_VALUE


def test_change_password_with_the_wrong_current_password_is_reported(app):
    app.unlock()
    app.act("manage")
    app.act("menu:change_password")
    app.act("confirm", old="wrong-current-pass", new=NEW_PASSWORD, confirm=NEW_PASSWORD)
    assert app.title == "vaultApp.title"
    assert app.screen["toast"]["tone"] == "error"
    assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_manage_close_returns_home_without_a_message(app):
    app.unlock()
    app.act("manage")
    app.act("close")
    assert app.title == "vaultApp.title" and app.screen.get("toast") is None


# --- type classification -----------------------------------------------------

@pytest.mark.parametrize("name,kind", [
    ("OPENAI_API_KEY", "apiKey"), ("STRIPE_SECRET", "apiKey"), ("GITHUB_TOKEN", "token"),
    ("DB_PASSWORD", "password"), ("DATABASE_URL", "database"), ("REDIS_URL", "database"),
    ("WEBHOOK_URL", "url"), ("SOMETHING", "other")])
def test_kind_is_decided_from_the_name(name, kind):
    assert appflow.kind_of(name) == kind
