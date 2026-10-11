"""Personal items (logins, cards, identities, notes, SSH keys) in the encrypted vault body."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import SECRETS, TEST_PASSWORD, workspace  # noqa: E402

from src.vault import store  # noqa: E402
from src.vault import items

NOTE_TEXT = "datbase: gocycling pass-FmAu95LWizdGy2"
NEW_PASSWORD = "A-brand-new-passphrase-7"


def test_a_note_round_trips_and_gets_an_id_and_times():
    with workspace():
        made = items.add(TEST_PASSWORD, "note", "azure", notes=NOTE_TEXT)
        assert len(made["id"]) == 32 and made["created"] == made["updated"]
        again = items.load(TEST_PASSWORD)
        assert [i["name"] for i in again] == ["azure"] and again[0]["notes"] == NOTE_TEXT


def test_every_type_stores_its_own_fields():
    with workspace():
        items.add(TEST_PASSWORD, "login", "github", {"username": "ana", "password": "pw-123", "uri": "https://github.com"})
        items.add(TEST_PASSWORD, "card", "visa", {"holder": "Ana", "number": "4111111111111111", "code": "123"})
        items.add(TEST_PASSWORD, "identity", "me", {"firstName": "Ana", "email": "ana@example.com"})
        items.add(TEST_PASSWORD, "ssh", "deploy", {"privateKey": "-----BEGIN KEY-----\nabc\n-----END KEY-----\n"})
        by_name = {i["name"]: i for i in items.load(TEST_PASSWORD)}
        assert by_name["github"]["fields"]["password"] == "pw-123"
        assert by_name["visa"]["fields"]["number"] == "4111111111111111"
        assert by_name["me"]["fields"]["email"] == "ana@example.com"
        assert "\n" in by_name["deploy"]["fields"]["privateKey"]


def test_items_do_not_change_what_the_assistant_side_sees():
    """load_secrets, the index and every plaintext file are exactly as before."""
    with workspace():
        items.add(TEST_PASSWORD, "note", "azure", notes=NOTE_TEXT)
        assert store.load_secrets(TEST_PASSWORD) == SECRETS
        assert store.load_index() == {"API_TOKEN": 1, "DB_PASSWORD": 2, "PLAIN": 3}
        for path in store.ROOT.iterdir():
            if path.is_file():
                data = path.read_bytes()
                assert b"azure" not in data and NOTE_TEXT.encode() not in data, path.name


def test_saving_secrets_keeps_the_items():
    with workspace():
        items.add(TEST_PASSWORD, "note", "azure", notes=NOTE_TEXT)
        secrets = store.load_secrets(TEST_PASSWORD)
        secrets["NEW_VAR"] = "value"
        store.save_secrets(TEST_PASSWORD, secrets)
        assert [i["name"] for i in items.load(TEST_PASSWORD)] == ["azure"]
        assert store.load_secrets(TEST_PASSWORD)["NEW_VAR"] == "value"


def test_saving_items_keeps_the_secrets():
    with workspace():
        items.add(TEST_PASSWORD, "note", "azure", notes=NOTE_TEXT)
        assert store.load_secrets(TEST_PASSWORD) == SECRETS


def test_items_survive_a_password_change():
    with workspace():
        items.add(TEST_PASSWORD, "note", "azure", notes=NOTE_TEXT)
        store.change_password(TEST_PASSWORD, NEW_PASSWORD)
        assert items.load(NEW_PASSWORD)[0]["notes"] == NOTE_TEXT


def test_update_changes_the_item_and_its_updated_time_but_not_created():
    with workspace():
        made = items.add(TEST_PASSWORD, "login", "github", {"username": "ana", "password": "old"})
        changed = items.update(TEST_PASSWORD, made["id"], "github", {"username": "ana", "password": "new"}, notes="n")
        assert changed["fields"]["password"] == "new" and changed["notes"] == "n"
        assert changed["created"] == made["created"] and changed["type"] == "login"
        assert [i["fields"]["password"] for i in items.load(TEST_PASSWORD)] == ["new"]


def test_delete_removes_only_that_item():
    with workspace():
        a = items.add(TEST_PASSWORD, "note", "a")
        b = items.add(TEST_PASSWORD, "note", "b")
        items.delete(TEST_PASSWORD, a["id"])
        assert [i["id"] for i in items.load(TEST_PASSWORD)] == [b["id"]]


def test_unknown_ids_are_errors():
    with workspace():
        with pytest.raises(KeyError):
            items.update(TEST_PASSWORD, "0" * 32, "x")
        with pytest.raises(KeyError):
            items.delete(TEST_PASSWORD, "0" * 32)


def test_a_wrong_password_is_refused():
    with workspace():
        with pytest.raises(Exception):
            items.load("not-the-password")


@pytest.mark.parametrize("bad", [
    {"type": "nope", "name": "x"},
    {"type": "note", "name": "   "},
    {"type": "note", "name": "a\nb"},
    {"type": "note", "name": "x" * (items.MAX_NAME + 1)},
    {"type": "login", "name": "x", "fields": {"username": "two\nlines"}},
    {"type": "note", "name": "x", "notes": "has\x00nul"},
    {"type": "note", "name": "x", "notes": "y" * (items.MAX_VALUE + 1)},
    {"type": "note", "name": 5},
])
def test_normalize_refuses_bad_input(bad):
    with pytest.raises(ValueError):
        items.normalize(bad)


def test_normalize_drops_unknown_fields_and_keeps_multiline_where_allowed():
    clean = items.normalize({"type": "ssh", "name": "k", "fields": {"privateKey": "a\nb", "bogus": "x"}})
    assert clean["fields"] == {"privateKey": "a\nb"}


def test_a_corrupt_items_record_is_reported_not_silently_dropped():
    with workspace():
        body = store.load_vault_body(TEST_PASSWORD)
        body[items.ITEMS_KEY] = {"v": 99, "items": []}
        store.save_vault_body(TEST_PASSWORD, body)
        with pytest.raises(items.ItemsCorrupted):
            items.load(TEST_PASSWORD)


def test_duplicate_ids_are_corruption():
    with workspace():
        one = items.normalize({"type": "note", "name": "a"})
        body = store.load_vault_body(TEST_PASSWORD)
        body[items.ITEMS_KEY] = {"v": 1, "items": [one, one]}
        store.save_vault_body(TEST_PASSWORD, body)
        with pytest.raises(items.ItemsCorrupted):
            items.load(TEST_PASSWORD)


def test_item_count_is_bounded(monkeypatch):
    with workspace():
        monkeypatch.setattr(items, "MAX_ITEMS", 2)
        items.add(TEST_PASSWORD, "note", "a")
        items.add(TEST_PASSWORD, "note", "b")
        with pytest.raises(ValueError):
            items.add(TEST_PASSWORD, "note", "c")


def test_field_kinds_say_what_is_hidden():
    assert items.is_hidden(items.kind_of("login", "password"))
    assert not items.is_hidden(items.kind_of("login", "username"))
    assert items.is_hidden(items.kind_of("note", "notes"))
    assert items.is_hidden(items.kind_of("ssh", "privateKey"))
    assert not items.is_hidden(items.kind_of("ssh", "publicKey"))
    with pytest.raises(KeyError):
        items.kind_of("login", "nope")


def test_a_concurrent_change_is_not_lost():
    """Two writers, one stale: the second applies its change to what is on disk now."""
    with workspace():
        items.add(TEST_PASSWORD, "note", "first")
        stale = items.load(TEST_PASSWORD)           # a reader holding an old list
        items.add(TEST_PASSWORD, "note", "second")  # someone else writes
        items.mutate(TEST_PASSWORD, lambda current: current + [items.normalize({"type": "note", "name": "third"})])
        assert [i["name"] for i in items.load(TEST_PASSWORD)] == ["first", "second", "third"]
        assert len(stale) == 1
