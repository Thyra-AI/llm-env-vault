"""
manage_vault x always-allow (2.4.0): the always_allow_list and
always_allow_remove actions of mcp_server._manage_vault_impl, with
gui.manage_vault_dialog faked (no window) and a real throwaway vault holding
real entries (same fixture as tests/test_allowlist.py).

Covered: the listing carries only id / kind / cwd / shape / label / armed /
reason (no snapshot, no value); removal deletes the entry and disarms it in
memory; an unknown id, a wrong password, a missing entry_id and a cancelled
dialog all end in clean, value-free results.

Runs under pytest only (the conftest fixtures isolate the rollback sidecar and
forbid real windows).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
import test_allowlist as ta  # noqa: E402
from vault_lib import allowlist, gui, trust  # noqa: E402

PW = ta.PW
LIST_KEYS = {"id", "kind", "cwd", "shape", "label", "armed", "reason"}


@pytest.fixture
def fake_manage(monkeypatch):
    """Returns ``say(**outcome)``: the next manage_vault_dialog() answer."""
    state = {"outcome": {"action": None}, "calls": 0}

    def dialog():
        state["calls"] += 1
        return dict(state["outcome"])

    monkeypatch.setattr(gui, "manage_vault_dialog", dialog)

    def say(**outcome):
        state["outcome"] = outcome
        return state
    return say


def _two_armed(e):
    first = e.approve("fake", "go")
    second = e.approve("fake", "again")
    e.unlock()
    assert allowlist.describe_state()["armed"] == 2
    return first, second


def test_list_returns_only_the_allowed_fields(fake_manage) -> None:
    with ta._env() as e:
        first, second = _two_armed(e)
        fake_manage(action="always_allow_list", password=PW)
        result = mcp_server._manage_vault_impl()
        assert result["applied"] is True and result["action"] == "always_allow_list"
        assert result["message"] == "2 always-allow entries."
        assert sorted(item["id"] for item in result["entries"]) == sorted([first, second])
        for item in result["entries"]:
            assert set(item) == LIST_KEYS
            assert item["kind"] == "fake" and item["cwd"] == e.cwd
            assert item["armed"] is True and item["reason"] is None
        flat = json.dumps(result)
        assert "abc123def456" not in flat and "snapshot" not in flat
        for value in ta.SECRETS.values():
            assert value not in flat


def test_list_with_no_entries_is_a_clean_empty_result(fake_manage) -> None:
    with ta._env():
        fake_manage(action="always_allow_list", password=PW)
        result = mcp_server._manage_vault_impl()
        assert result == {"applied": True, "action": "always_allow_list", "entries": [],
                          "message": "No always-allow entries."}


def test_list_reports_a_disarmed_entry_with_its_reason(fake_manage) -> None:
    with ta._env() as e:
        e.approve("fake", "go")
        e.unlock()
        e.fake.snapshot_result = (False, "the approved state changed")
        allowlist.reset()
        e.unlock()
        fake_manage(action="always_allow_list", password=PW)
        (item,) = mcp_server._manage_vault_impl()["entries"]
        assert item["armed"] is False and item["reason"] == "the approved state changed"


def test_remove_deletes_the_entry_and_disarms_it(fake_manage) -> None:
    with ta._env() as e:
        first, second = _two_armed(e)
        assert allowlist.find_match(e.req("fake", "go")) is not None
        fake_manage(action="always_allow_remove", password=PW, entry_id=first)
        result = mcp_server._manage_vault_impl()
        assert result["applied"] is True and result["action"] == "always_allow_remove"
        assert first in result["message"]
        # Gone from the vault, from memory, and no longer matchable.
        assert [i["id"] for i in allowlist.list_entries(PW)] == [second]
        assert allowlist.find_match(e.req("fake", "go")) is None
        assert trust.check_armed((allowlist.TRUST_KEY_TAG, first))[0] is False
        assert allowlist.find_match(e.req("fake", "again")) is not None   # the other survives
        assert allowlist.describe_state()["armed"] == 1


def test_remove_strips_whitespace_around_the_id(fake_manage) -> None:
    with ta._env() as e:
        eid = e.approve("fake", "go")
        fake_manage(action="always_allow_remove", password=PW, entry_id=f"  {eid}\n")
        assert mcp_server._manage_vault_impl()["applied"] is True
        assert allowlist.list_entries(PW) == []


def test_remove_unknown_id_is_a_clean_error(fake_manage) -> None:
    with ta._env() as e:
        eid = e.approve("fake", "go")
        fake_manage(action="always_allow_remove", password=PW, entry_id="nosuchid0000")
        result = mcp_server._manage_vault_impl()
        assert result["applied"] is False
        assert "No always-allow entry with id 'nosuchid0000'" in result["error"]
        assert [i["id"] for i in allowlist.list_entries(PW)] == [eid]


@pytest.mark.parametrize("action,extra", [("always_allow_list", {}),
                                          ("always_allow_remove", {"entry_id": "x"})])
def test_wrong_password_is_a_clean_error(fake_manage, action, extra) -> None:
    with ta._env() as e:
        eid = e.approve("fake", "go")
        fake_manage(action=action, password="not-the-password", **extra)
        result = mcp_server._manage_vault_impl()
        assert result["applied"] is False
        assert result["error"] == "Incorrect master password."
        assert "entries" not in result
        assert [i["id"] for i in allowlist.list_entries(PW)] == [eid]


@pytest.mark.parametrize("entry_id", [None, "", "   ", 42])
def test_remove_without_entry_id_is_a_clean_error(fake_manage, entry_id) -> None:
    with ta._env() as e:
        eid = e.approve("fake", "go")
        fake_manage(action="always_allow_remove", password=PW, entry_id=entry_id)
        result = mcp_server._manage_vault_impl()
        assert result == {"applied": False, "error": "No always-allow entry id was given."}
        assert [i["id"] for i in allowlist.list_entries(PW)] == [eid]


@pytest.mark.parametrize("action", ["always_allow_list", "always_allow_remove"])
def test_cancelled_dialog_changes_nothing(fake_manage, action) -> None:
    with ta._env() as e:
        eid = e.approve("fake", "go")
        fake_manage(action=action, password=None, entry_id=eid)
        assert mcp_server._manage_vault_impl() == {"applied": False,
                                                   "message": "Cancelled by user."}
        assert [i["id"] for i in allowlist.list_entries(PW)] == [eid]
