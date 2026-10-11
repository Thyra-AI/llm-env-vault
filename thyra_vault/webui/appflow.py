"""The Thyra Vault app: a Bitwarden-style window the HUMAN opens.

Unlike the dialogs in flows.py -- each answers one question an AI assistant
asked and then goes away -- this is a persistent app: unlock once, browse the
secrets, add / edit / delete, copy, generate a password, change settings.

It is opened by the person (``python -m thyra_vault.app``), never by a tool call:
an assistant must not be able to put this window on screen, because the app can
put a secret on the clipboard. That is the one new power it has, and it is
bounded:

  * a value NEVER travels to the page. "Copy" is a server-side clipboard write
    (thyra_vault/webui/clipboard.py) that is wiped after a few seconds; there is no
    "show value" and no value in any screen -- only names, placeholder numbers,
    a coarse type and the files an item is used in;
  * the master password and the decrypted dict stay in this generator's local
    state, and are dropped on lock;
  * the app locks itself after a period of inactivity, enforced here as well as
    in the page, because a page timer can simply be stopped;
  * every change re-decrypts the vault first, so a write never clobbers
    something another process saved meanwhile.

Everything is a port of logic already in flows.py and mcp_server.py, so the app
and the assistant-driven dialogs cannot drift apart.
"""
import time
from pathlib import Path
from typing import Optional

from ..vault import items as personal
from ..vault import store
from ..vault.crypto import (MalformedRecoveryKey, NoRecoverySlot, VaultCorrupted, VaultTampered,
                      WrongPassword, WrongRecoveryKey)
from .uihelpers import MIN_PASSWORD_LEN, _safe_display
from . import clipboard as _clipboard
from . import flows, prefs as prefs_mod
from .flows import _b, _password_issue, _s, _save_failed, _vault_error
from .schema import (action, check_field, field_rows, history, item_header, menu, msg, notice,
                     password_field, raw_error, screen, text, text_field, textarea_field)

TABS = ("vault", "generator", "settings")
MAX_ITEMS = 5000


class AutoLocked(Exception):
    """The vault sat idle past the limit; unwinds whatever screen was open."""


IDLE_LOCK = "autolock"  # sent by the page's idle timer from any screen


def _touch(state: dict, act=None) -> None:
    """Called whenever the person acts, on EVERY screen -- not just the list.

    A form or an item view left open must not keep the session alive forever,
    and a revealed secret must not outlive the idle limit on screen. ``act`` is
    the action just received: the page's idle timer sends ``autolock`` from
    whatever screen is open, which locks at once (it can only lock, never unlock).
    """
    if act is not None and getattr(act, "id", None) == IDLE_LOCK:
        raise AutoLocked()
    now = state["clock"]()
    delta = now - state["last"]
    # A big step backwards means the wall clock was set back: treat it as idle
    # rather than let "negative idle time" keep the vault open.
    if delta > state["prefs"]["autoLockMinutes"] * 60 or delta < -60:
        raise AutoLocked()
    state["last"] = now


def _guarded(state: dict, inner):
    """Drive an inner flow (flows.py) while enforcing the idle limit on each act.

    The flows in flows.py know nothing about auto-lock; without this a screen like
    "manage vault" or a recovery key would answer an hour later as if nothing had
    happened. The act that arrives after the limit is NOT forwarded.
    """
    try:
        scr = next(inner)
        while True:
            act = yield scr
            _touch(state, act)
            scr = inner.send(act)
    except StopIteration as done:
        return done.value
    finally:
        inner.close()


def _wipe(clip) -> None:
    """Take any copied secret off the clipboard now (lock, quit, or the window closing)."""
    wipe = getattr(clip, "wipe_now", None)
    if wipe is not None:
        wipe()


# --- what the page is told about an item -----------------------------------

def kind_of(name: str, shape: Optional[str] = None) -> str:
    """A coarse type for the list filter, decided from the NAME (plaintext)."""
    n = name.upper()
    if any(w in n for w in ("PASSWORD", "PASSWD", "PWD", "PASSPHRASE")):
        return "password"
    if any(w in n for w in ("TOKEN", "BEARER", "JWT")):
        return "token"
    if any(w in n for w in ("DATABASE", "DB_", "_DB", "POSTGRES", "MYSQL", "MONGO", "REDIS", "DSN")):
        return "database"
    if (shape or "").startswith("url:") or n.endswith(("_URL", "_URI", "_ENDPOINT", "_HOST")):
        return "url"
    if any(w in n for w in ("KEY", "SECRET", "CREDENTIAL")):
        return "apiKey"
    return "other"


def _version() -> str:
    try:
        import json
        manifest = Path(__file__).resolve().parents[2] / ".claude-plugin" / "plugin.json"
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("version", ""))
    except (OSError, ValueError):
        return ""


def _quietly(fn, default):
    try:
        return fn()
    except (OSError, ValueError, UnicodeDecodeError):
        return default


def _rows(state: dict) -> list:
    index = _quietly(store.load_index, {})
    shapes = _quietly(store.load_shapes, {})
    files: dict = {}
    for path, names in _quietly(store.load_targets, {}).items():
        base = _safe_display(Path(path).name, 80)
        for n in names:
            files.setdefault(n, set()).add(base)
    rows = []
    for name in sorted(state["secrets"]):
        try:
            store.validate_var_name(name)
        except ValueError:
            continue
        used = sorted(files.get(name, ()))
        rows.append({"id": name, "type": "secret", "name": name, "number": index.get(name),
                     "kind": kind_of(name, shapes.get(name)), "files": used[:3], "fileCount": len(used)})
    for item in state.get("items", []):
        rows.append({"id": item["id"], "type": item["type"], "name": _safe_display(item["name"], 200),
                     "number": None, "kind": item["type"], "files": [], "fileCount": 0,
                     "sub": _subtitle(item), "folder": _safe_display(item["folder"], 100)})
    rows.sort(key=lambda r: r["name"].lower())
    return rows[:MAX_ITEMS]


def _subtitle(item: dict) -> str:
    """One harmless line under an item's name: never a hidden field."""
    f = item["fields"]
    if item["type"] == "login":
        return _safe_display(f.get("username", ""), 120)
    if item["type"] == "card":
        return _safe_display(f.get("brand", ""), 60)
    if item["type"] == "identity":
        return _safe_display(f.get("email", "") or " ".join(filter(None, (f.get("firstName"), f.get("lastName")))), 120)
    return ""


def _info(state: dict) -> dict:
    info = store.vault_info()
    return {"format": info.get("format"), "recovery": bool(info.get("recovery_slot")),
            "location": _safe_display(str(store.ROOT), 300), "count": len(state["secrets"]) + len(state.get("items", [])),
            "version": _version()}


def _toast(tone: str, key: str, /, **params) -> dict:
    assert tone in ("success", "warning", "error", "info")
    return {"tone": tone, "msg": msg(key, **params)}


# --- lock screen -----------------------------------------------------------

def _lock(state: dict):
    """Unlock (or create) the vault. Returns True when unlocked, False to quit."""
    error = None
    while True:
        first = not store.vault_exists()
        fields = [password_field("password", "fields.masterPassword", new=first, strength=first,
                                 autofocus=True)]
        if first:
            fields += [password_field("confirm", "fields.confirmPassword", new=True, toggle=False),
                       check_field("recovery", "setup.recovery")]
        note = state.pop("lock_note", None)
        act = yield screen(
            "vaultApp.lock.createTitle" if first else "vaultApp.lock.title", icon="lock",
            blocks=[text("setup.intro", min=MIN_PASSWORD_LEN)] if first else [],
            fields=fields,
            actions=[action("continue", "vaultApp.lock.createAction" if first else "vaultApp.lock.unlock",
                            variant="primary")]
                    + ([] if first else [action("recover", "vaultApp.lock.recover")])
                    + [action("quit", "common.close")],
            default_action="continue", error=error,
            toast=_toast("info", note) if note else None,
            app={"view": "lock", "firstRun": first, "location": _safe_display(str(store.ROOT), 300),
                 "prefs": state["prefs"]})
        if act.id == "quit":
            return False
        if act.id == "recover":
            error = yield from _recover(state)
            continue
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        if first:
            error = _password_issue(password)
            if error:
                continue
            if password != _s(act, "confirm"):
                error = msg("errors.passwordMismatch")
                continue
            state["password"] = password
            state["recovery_raw"] = None
            if _b(act, "recovery"):
                state["recovery_raw"] = yield from flows._recovery_drill()
            try:
                flows._create_vault_now(state)
            except Exception as exc:  # noqa: BLE001 -- same breadth as the dialogs
                error = _save_failed(exc)
                continue
            finally:
                state.pop("recovery_raw", None)  # the paper key is not needed in memory any longer
            state["secrets"] = {}
            state["items"] = []
            return True
        try:
            body = store.load_vault_body(password)
            state["secrets"] = {k: v for k, v in body.items() if not store.is_reserved_key(k)}
            state["items"] = personal.from_body(body)
        except WrongPassword as exc:  # includes TooManyAttempts
            error = raw_error(exc)
            continue
        except personal.ItemsCorrupted:
            error = msg("vaultApp.item.corrupted")
            continue
        except (FileNotFoundError, ValueError) as exc:
            error = _vault_error(exc)
            continue
        state["password"] = password
        return True


def _recover(state: dict):
    """Recovery-key flow. Returns an error dict to show on the lock screen, or None."""
    outcome = {"recovery_key": None, "new_password": None}
    yield from flows.recover(outcome)
    rk_text, new_password = outcome.get("recovery_key"), outcome.get("new_password")
    if not rk_text or not new_password:
        return None
    try:
        new_key = store.recover_with_recovery_key(rk_text, new_password)
    except WrongPassword as exc:  # TooManyAttempts
        return raw_error(exc)
    except MalformedRecoveryKey:
        return msg("vaultApp.result.keyMistyped")
    except WrongRecoveryKey:
        return msg("vaultApp.result.keyWrong")
    except NoRecoverySlot:
        return msg("vaultApp.result.noRecoverySlot")
    except (VaultCorrupted, VaultTampered):
        return msg("vaultApp.result.damaged")
    except RuntimeError:
        return msg("vaultApp.result.restored")
    if new_key:
        info = store.vault_info()
        shown = [False]
        yield from flows.recovery_key(new_key, info.get("recovery_slot_id", ""), shown)
    state["lock_note"] = "vaultApp.result.recovered"
    return None


# --- item forms ------------------------------------------------------------

def _item_form(state: dict, name: Optional[str] = None):
    """Add (``name`` None) or update one secret. Returns a toast dict or None."""
    editing = name is not None
    error = None
    acknowledged = False
    while True:
        blocks = [text("vaultApp.form.editing", name=_safe_display(name))] if editing else []
        if editing and store.is_sensitive_env_name(name):
            blocks.append(notice("warning", "confirmAdd.override", name=_safe_display(name)))
        fields = [] if editing else [text_field("name", "vaultApp.form.name", mono=True, autofocus=True,
                                                 placeholder="OPENAI_API_KEY")]
        fields.append(password_field("value", "vaultApp.form.value", autofocus=editing))
        act = yield screen(
            "vaultApp.form.editTitle" if editing else "vaultApp.form.addTitle",
            icon="pencil" if editing else "plus", blocks=blocks, fields=fields,
            actions=[action("back", "common.cancel"),
                     action("save", "vaultApp.form.save", variant="primary")],
            default_action="save", error=error)
        _touch(state, act)
        if act.id != "save":
            return None
        var = name if editing else _s(act, "name").strip()
        value = _s(act, "value")
        try:
            store.validate_var_name(var)
        except ValueError:
            error = msg("vaultApp.form.nameInvalid")
            continue
        if not value:
            error = msg("errors.valueEmpty")
            continue
        if not editing and store.is_sensitive_env_name(var) and not acknowledged:
            acknowledged = True
            error = msg("vaultApp.form.sensitiveAck", name=_safe_display(var))
            continue
        secrets_saved = False
        try:
            # Fresh decrypt: a stale in-memory copy re-encrypted over the file
            # would erase anything another process saved in between.
            secrets = store.load_secrets(state["password"])
            if not editing and var in secrets:
                error = msg("vaultApp.form.nameExists", name=_safe_display(var))
                continue
            secrets[var] = value
            store.save_secrets(state["password"], secrets)
            secrets_saved = True
            state["secrets"] = secrets
            index = store.load_index()
            index[var] = index.get(var, store.next_placeholder(index))
            store.save_index(index)
        except Exception as exc:  # noqa: BLE001
            if secrets_saved:
                return _toast("warning", "errors.addPartial", message=_safe_display(exc, 300))
            error = _save_failed(exc)
            continue
        return _toast("success", "vaultApp.toast.saved")


def _confirm_delete(state: dict, name: str):
    act = yield screen(
        "confirmRemove.title", icon="trash", tone="danger",
        blocks=[text("confirmRemove.proposal", name=_safe_display(name)),
                notice("danger", "confirmRemove.irreversible")],
        actions=[action("deny", "common.cancel"),
                 action("allow", "confirmRemove.allow", variant="danger")])
    _touch(state, act)
    if act.id != "allow":
        return None
    secrets_saved = False
    try:
        secrets = store.load_secrets(state["password"])
        secrets.pop(name, None)
        store.save_secrets(state["password"], secrets)
        secrets_saved = True
        state["secrets"] = secrets
        index = store.load_index()
        index.pop(name, None)
        store.save_index(index)
    except Exception as exc:  # noqa: BLE001
        if secrets_saved:
            return _toast("warning", "errors.removePartial", message=_safe_display(exc, 300))
        return _toast("error", "errors.saveFailed", message=_safe_display(exc, 300))
    return _toast("success", "vaultApp.toast.deleted")


# --- account security (the manage_vault actions, run in place) -------------

def _show_key(state: dict, new_key: str):
    info = store.vault_info()
    shown = [False]
    yield from _guarded(state, flows.recovery_key(new_key, info.get("recovery_slot_id") or "", shown))
    return shown[0]


def _manage(state: dict):
    """Account security. Returns a toast dict or None."""
    outcome: dict = {"action": None}
    yield from _guarded(state, flows.manage_vault(outcome))
    _touch(state)
    chosen = outcome.get("action")
    if not chosen:
        return None
    password = outcome.get("password")
    try:
        if chosen == "change_password":
            new_key = store.change_password(outcome["old_password"], outcome["new_password"])
            state["password"] = outcome["new_password"]
            if new_key is not None and not (yield from _show_key(state, new_key)):
                return _toast("warning", "vaultApp.result.keyNotConfirmed")
            return _toast("success", "vaultApp.result.passwordChanged")
        if chosen in ("setup_recovery", "reissue_recovery"):
            new_key = store.reissue_recovery_key(password)
            if not (yield from _show_key(state, new_key)):
                return _toast("warning", "vaultApp.result.keyNotConfirmed")
            return _toast("success", "vaultApp.result.keyIssued")
        if chosen == "upgrade_v2":
            new_key = store.upgrade_to_v2(password, recovery=False)
            if new_key is not None and not (yield from _show_key(state, new_key)):
                return _toast("warning", "vaultApp.result.keyNotConfirmed")
            return _toast("success", "vaultApp.result.upgraded")
        if chosen == "rotate_file_key":
            report = store.rotate_file_key(password)
            skipped = [r for r in report["results"] if r["status"] != "ok"]
            if skipped:
                return _toast("warning", "vaultApp.result.rotatedPartial", count=len(skipped))
            return _toast("success", "vaultApp.result.rotated", count=report["rotated"])
        if chosen == "retire_file_keys":
            return (yield from _retire(state, password))
    except WrongPassword as exc:  # includes TooManyAttempts
        return {"tone": "error", "msg": raw_error(exc)}
    except FileNotFoundError:
        return _toast("error", "vaultApp.result.noVault")
    except (VaultCorrupted, VaultTampered):
        return _toast("error", "vaultApp.result.damaged")
    except (OSError, ValueError, RuntimeError):
        return _toast("error", "vaultApp.result.restored")
    return None


def _retire(state: dict, password: str):
    try:
        report = store.retire_file_keys(password)
    except ValueError as exc:
        # Files this vault sealed are unaccounted for: let a human decide,
        # deliberately, whether to abandon them (same as manage_vault).
        outstanding = _quietly(lambda: store.file_keys_outstanding(password), {})
        if not outstanding:
            return {"tone": "error", "msg": raw_error(exc)}
        names = {}
        for entry in _quietly(store.load_file_registry, {}).values():
            if entry.get("file_id"):
                names[entry["file_id"]] = entry.get("original_name")
        ab = {"abandon": None}
        yield from _guarded(state, flows.confirm_abandon_files(ab, outstanding, names))
        if ab["abandon"] is None:
            return None
        report = store.retire_file_keys(password, abandon=ab["abandon"])
    if not report.get("retired"):
        return _toast("info", "vaultApp.result.nothingToRetire")
    return _toast("success", "vaultApp.result.retired", count=len(report["retired"]))



# --- personal items: logins, cards, identities, notes, SSH keys --------------

_TYPE_ICONS = {"secret": "key", "login": "globe", "card": "credit-card", "identity": "id-card",
               "note": "note", "ssh": "terminal"}
_TYPE_ORDER = ("secret",) + personal.TYPES


def _choose_type(state: dict):
    """What to add. Returns a type name or None."""
    act = yield screen(
        "vaultApp.item.chooseTitle", icon="plus",
        blocks=[text("vaultApp.item.chooseHint", muted=True),
                menu([{"id": f"type:{t}", "icon": _TYPE_ICONS[t], "label": msg(f"vaultApp.types.{t}"),
                       "description": msg(f"vaultApp.item.about.{t}")} for t in _TYPE_ORDER])],
        actions=[action("back", "common.cancel")])
    _touch(state, act)
    if act.id.startswith("menu:type:") and act.id[len("menu:type:"):] in _TYPE_ORDER:
        return act.id[len("menu:type:"):]
    return None


def _entry_form(state: dict, item_type: str, current: Optional[dict] = None):
    """Add (``current`` None) or edit one personal item. Returns a toast dict or None.

    Unlike an environment secret, an item being edited is shown to its owner:
    the form is pre-filled. That is the one place an item's content is sent to
    the page without a reveal, and only for the item the person chose to edit.
    """
    editing = current is not None
    cur = current or {"name": "", "folder": "", "fields": {}, personal.NOTES: ""}
    error = None
    while True:
        fields = [text_field("name", "vaultApp.item.name", autofocus=True, initial=cur["name"])]
        for fname, kind in personal.FIELD_SPECS[item_type]:
            label, initial = f"vaultApp.fields.{fname}", cur["fields"].get(fname, "")
            if kind == "text":
                fields.append(text_field(fname, label, initial=initial))
            elif kind == "secret":
                fields.append(password_field(fname, label, initial=initial))
            else:
                fields.append(textarea_field(fname, label, rows=5, mono=True, initial=initial))
        fields.append(textarea_field("notes", "vaultApp.fields.notes", rows=4, initial=cur[personal.NOTES]))
        fields.append(text_field("folder", "vaultApp.fields.folder", initial=cur["folder"]))
        act = yield screen(
            f"vaultApp.item.{'edit' if editing else 'add'}.{item_type}",
            icon=_TYPE_ICONS[item_type], fields=fields,
            actions=[action("back", "common.cancel"), action("save", "vaultApp.form.save", variant="primary")],
            default_action=None, error=error)
        _touch(state, act)
        if act.id != "save":
            return None
        values = {f: _s(act, f) for f, _k in personal.FIELD_SPECS[item_type]}
        try:
            if editing:
                personal.update(state["password"], cur["id"], _s(act, "name"), values, _s(act, "notes"), _s(act, "folder"))
            else:
                personal.add(state["password"], item_type, _s(act, "name"), values, _s(act, "notes"), _s(act, "folder"))
            state["items"] = personal.load(state["password"])
        except personal.ItemsCorrupted:
            error = msg("vaultApp.item.corrupted")
            continue
        except ValueError as exc:
            error = msg("vaultApp.item.invalid", message=_safe_display(exc, 300))
            continue
        except Exception as exc:  # noqa: BLE001 -- same breadth as the other save paths
            error = _save_failed(exc)
            continue
        return _toast("success", "vaultApp.toast.saved")


def _field_value(item: dict, field: str) -> str:
    return item[personal.NOTES] if field == personal.NOTES else item["fields"].get(field, "")


def _copy_value(state: dict, clip, value: str):
    """Server-side copy with the same wipe as a secret. Returns a toast."""
    failure = clip.copy(value)
    if failure:
        return _toast("error", f"vaultApp.toast.copy_{failure}")
    clip.clear_later(value, state["prefs"]["clipboardSeconds"])
    return _toast("success", "vaultApp.toast.copied", seconds=state["prefs"]["clipboardSeconds"])


def _view_item(state: dict, item_id: str, clip):
    """The read-only view of one item: hidden fields stay hidden until revealed.

    Revealed values live only in this generator and in the one screen that shows
    them; leaving the view (or locking) forgets them.
    """
    revealed: set = set()
    toast = None
    while True:
        item = personal.find(state["items"], item_id)
        if item is None:
            return None
        rows = []
        for fname in personal.field_names(item["type"]):
            value = _field_value(item, fname)
            if not value:
                continue
            kind = personal.kind_of(item["type"], fname)
            rows.append({"id": fname, "label": f"vaultApp.fields.{fname}", "hidden": personal.is_hidden(kind),
                         "multiline": kind.startswith("multiline"), "value": value,
                         "revealed": fname in revealed})
        act = yield screen(
            f"vaultApp.item.view.{item['type']}", icon=_TYPE_ICONS[item["type"]], toast=toast,
            blocks=[item_header(item["name"], item["type"], item["folder"]),
                    field_rows(rows) if rows else text("vaultApp.item.noFields", muted=True),
                    history(item["created"], item["updated"])],
            actions=[action("back", "common.back"), action("edit", "vaultApp.vault.edit", variant="primary"),
                     action("delete", "vaultApp.vault.delete", variant="danger")])
        toast = None
        _touch(state, act)
        if act.id == "back":
            return None
        if act.id == "edit":
            toast = yield from _entry_form(state, item["type"], item)
            revealed.clear()
        elif act.id == "delete":
            deleted = yield from _confirm_delete_item(state, item)
            if deleted:
                return deleted
        elif act.id.startswith("menu:"):
            verb, _, fname = act.id[len("menu:"):].partition(":")
            if fname in personal.field_names(item["type"]) and _field_value(item, fname):
                if verb == "reveal":
                    revealed.add(fname)
                elif verb == "hide":
                    revealed.discard(fname)
                elif verb == "copy":
                    toast = _copy_value(state, clip, _field_value(item, fname))


def _confirm_delete_item(state: dict, item: dict):
    """Returns a toast when deleted, None otherwise."""
    act = yield screen(
        "vaultApp.item.deleteTitle", icon="trash", tone="danger",
        blocks=[text("vaultApp.item.deleteBody", name=_safe_display(item["name"])),
                notice("danger", "confirmRemove.irreversible")],
        actions=[action("deny", "common.cancel"), action("allow", "confirmRemove.allow", variant="danger")])
    _touch(state, act)
    if act.id != "allow":
        return None
    try:
        personal.delete(state["password"], item["id"])
        state["items"] = personal.load(state["password"])
    except KeyError:
        state["items"] = personal.load(state["password"])
        return _toast("info", "vaultApp.toast.deleted")
    except Exception as exc:  # noqa: BLE001
        return _toast("error", "errors.saveFailed", message=_safe_display(exc, 300))
    return _toast("success", "vaultApp.toast.deleted")


# --- the home screen loop --------------------------------------------------

def _act_on(state: dict, verb: str, arg: str, clip):
    """The list's actions that open another screen. Returns a toast or None."""
    if verb == "add":
        chosen = yield from _choose_type(state)
        if chosen == "secret":
            return (yield from _item_form(state))
        if chosen:
            return (yield from _entry_form(state, chosen))
    elif verb == "edit" and arg in state["secrets"]:
        return (yield from _item_form(state, arg))
    elif verb == "delete" and arg in state["secrets"]:
        return (yield from _confirm_delete(state, arg))
    elif verb == "view" and personal.find(state["items"], arg):
        return (yield from _view_item(state, arg, clip))
    elif verb == "iedit" and personal.find(state["items"], arg):
        item = personal.find(state["items"], arg)
        return (yield from _entry_form(state, item["type"], item))
    elif verb == "idelete" and personal.find(state["items"], arg):
        return (yield from _confirm_delete_item(state, personal.find(state["items"], arg)))
    elif verb == "icopy" and personal.find(state["items"], arg):
        item = personal.find(state["items"], arg)
        field = personal.PRIMARY_FIELD[item["type"]]
        value = _field_value(item, field)
        if value:
            return _copy_value(state, clip, value)
    elif verb == "manage":
        return (yield from _manage(state))
    return None


def _home(state: dict, clip, clock):
    """Browse and act. Returns "lock" or "quit"."""
    toast = None
    tab = "vault"
    while True:
        act = yield screen(
            "vaultApp.title", icon="shield", toast=toast,
            app={"view": "home", "tab": tab, "items": _rows(state), "prefs": state["prefs"],
                 "info": _info(state)})
        toast = None
        try:
            _touch(state, act)
        except AutoLocked:
            state["lock_note"] = "vaultApp.lock.auto"
            return "lock"
        chosen_tab = act.values.get("tab")
        tab = chosen_tab if chosen_tab in TABS else tab
        verb, _, arg = act.id.partition(":")
        if verb == "close":
            return "quit"
        if verb == "lock":
            if act.values.get("auto") is True:
                state["lock_note"] = "vaultApp.lock.auto"
            return "lock"
        if verb == "prefs":
            state["prefs"] = prefs_mod.update(act.values.get("changes"))
        elif verb == "gcopy":
            # The generator's own output (not a vault value): copy it server-side so
            # it gets the same wipe as everything else.
            text_value = _s(act, "text")
            if text_value and len(text_value) <= 4096:
                toast = _copy_value(state, clip, text_value)
        elif verb == "copy" and arg in state["secrets"]:
            value = state["secrets"][arg]
            failure = clip.copy(value)
            if failure:
                toast = _toast("error", f"vaultApp.toast.copy_{failure}")
            else:
                clip.clear_later(value, state["prefs"]["clipboardSeconds"])
                toast = _toast("success", "vaultApp.toast.copied", seconds=state["prefs"]["clipboardSeconds"])
        else:
            try:
                toast = yield from _act_on(state, verb, arg, clip)
            except AutoLocked:
                state["lock_note"] = "vaultApp.lock.auto"
                return "lock"
        state["last"] = clock()


def vault_app(outcome: dict, *, clip=_clipboard, clock=time.time):
    """The whole app. Ends when the person closes it; ``outcome["closed"]``.

    The default clock is wall time, not ``time.monotonic``: monotonic time does not
    advance while a laptop sleeps, so a vault left open overnight would still look
    "recently used" in the morning.
    """
    state: dict = {"prefs": prefs_mod.load(), "secrets": {}, "items": [], "password": None,
                   "last": clock(), "clock": clock}
    try:
        while True:
            if not (yield from _lock(state)):
                break
            state["last"] = clock()
            result = yield from _home(state, clip, clock)
            state["secrets"] = {}
            state["items"] = []
            state["password"] = None
            _wipe(clip)  # locking or quitting: nothing copied stays on the clipboard
            if result == "quit":
                break
    finally:
        _wipe(clip)  # also when the window is closed and the server cancels this flow
        state["secrets"], state["items"], state["password"] = {}, [], None
    outcome["closed"] = True
