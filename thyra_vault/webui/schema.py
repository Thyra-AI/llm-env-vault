"""Server-driven screen schema for the browser dialogs.

A flow (thyra_vault/webui/flows.py) yields plain-dict *screens*; the React app
renders whatever it is sent. Every human-readable string is an i18n key plus
parameters -- never pre-rendered English -- so the page can show it in any of
the platform's languages. Strings that did not originate in this code (paths,
commands, variable names, exception text) are passed as parameters or as the
``text`` of a code block, and are sanitised here before they leave the process,
before they are put in a page.

Nothing in this module touches the vault. A screen never carries a secret: the
only credential-like value that ever travels to the page is a recovery key the
human is about to write down, in the dedicated ``keyBox`` block.
"""
from typing import Optional

from .uihelpers import _collapse_whitespace, _safe_display

# Every raw string sent to the page is capped. Consent-critical text (commands,
# paths) is collapsed to one line but NOT elided, for the reason written at
# uihelpers._collapse_whitespace; the cap only guards against absurd input.
_RAW_CAP = 20_000


def _capped(value: str) -> str:
    """Cap absurd input, but never silently: the cut is announced in the text itself
    (the human must not approve something whose tail they were never shown)."""
    if len(value) <= _RAW_CAP:
        return value
    return f"{value[:_RAW_CAP]} [... {len(value) - _RAW_CAP} more characters NOT shown]"


def msg(key: str, /, **params) -> dict:
    """An i18n message: a translation key plus interpolation parameters."""
    out: dict = {"key": key}
    if params:
        out["params"] = {k: (v if isinstance(v, (int, float)) else str(v))
                         for k, v in params.items()}
    return out


def raw_error(text) -> dict:
    """An error whose wording comes from the vault layer (shown verbatim)."""
    return {"raw": _safe_display(text, 800)}


# --- blocks ---------------------------------------------------------------

def text(key: str, /, *, muted: bool = False, **params) -> dict:
    return {"type": "text", "msg": msg(key, **params), "muted": muted}


def notice(tone: str, key: str, /, **params) -> dict:
    assert tone in ("info", "warning", "danger", "success")
    return {"type": "notice", "tone": tone, "msg": msg(key, **params)}


def raw_notice(tone: str, value) -> dict:
    """A notice whose text is not ours (e.g. trust_note, a store message)."""
    return {"type": "notice", "tone": tone, "raw": _capped(_collapse_whitespace(value))}


def code(value, *, label: Optional[str] = None, **label_params) -> dict:
    """A read-only monospace box. ``value`` is untrusted text, collapsed to a
    single line (so it cannot fake extra lines), never truncated."""
    block: dict = {"type": "code", "text": _capped(_collapse_whitespace(value))}
    if label:
        block["label"] = msg(label, **label_params)
    return block


def code_lines(lines, *, label: Optional[str] = None, verbatim: bool = False, **label_params) -> dict:
    """A monospace box with one entry per line. Each line is sanitised on its
    own, so an entry cannot smuggle a newline and impersonate a second one.
    ``verbatim`` is for lines the caller already escaped (uihelpers.escape_argument):
    whitespace runs are then kept exactly, since collapsing them would make the box
    differ from what runs."""
    block: dict = {"type": "code", "lines": [_capped(str(x) if verbatim else _collapse_whitespace(x))
                                             for x in lines]}
    if label:
        block["label"] = msg(label, **label_params)
    return block


def items(rows, *, label: Optional[str] = None, **label_params) -> dict:
    """A list of ``{"text": raw, "tag": msg|None}`` rows (e.g. variable names,
    with an overwrite flag). Scrolls instead of eliding when long."""
    out = []
    for row in rows:
        entry = {"text": _capped(_collapse_whitespace(row["text"]))}
        if row.get("tag"):
            entry["tag"] = row["tag"]
        out.append(entry)
    block: dict = {"type": "items", "rows": out}
    if label:
        block["label"] = msg(label, **label_params)
    return block


def key_box(rows) -> dict:
    """The recovery key, laid out for copying by hand (see flows.recovery_key)."""
    return {"type": "keyBox", "rows": list(rows)}


def copy_button(value: str, clear_seconds: int) -> dict:
    return {"type": "copy", "value": value, "clearSeconds": int(clear_seconds)}


def item_header(name: str, item_type: str, folder: str = "") -> dict:
    """Title row of an item: its name, its type (for the icon) and its folder."""
    return {"type": "itemHeader", "name": _capped(_collapse_whitespace(name)), "itemType": item_type,
            "folder": _capped(_collapse_whitespace(folder))}


def field_rows(rows, label: Optional[str] = None) -> dict:
    """The fields of a personal item, for the view screen.

    Each row is ``{"id", "label": i18n key, "hidden", "multiline", "value"}``.
    ``value`` is None for a hidden field that has not been revealed -- the page
    then shows dots and a reveal button, and the real text is only ever sent
    after an explicit ``reveal`` action. Visible fields carry their text.
    """
    out = []
    for r in rows:
        shown = r["value"] if (not r["hidden"] or r.get("revealed")) else None
        out.append({"id": r["id"], "label": msg(r["label"]), "hidden": bool(r["hidden"]),
                    "multiline": bool(r.get("multiline")), "revealed": bool(r.get("revealed")),
                    "empty": not r["value"], "value": shown})
    block: dict = {"type": "fields", "rows": out}
    if label:
        block["label"] = msg(label)
    return block


def history(created: str, updated: str) -> dict:
    return {"type": "history", "created": str(created)[:32], "updated": str(updated)[:32]}


def menu(entries) -> dict:
    """Clickable rows; clicking sends the action ``menu:<id>``."""
    return {"type": "menu", "entries": [
        {"id": e["id"], "icon": e["icon"], "label": e["label"],
         **({"description": e["description"]} if e.get("description") else {})}
        for e in entries]}


# --- fields ---------------------------------------------------------------

def password_field(name: str, label: str, /, *, new: bool = False, strength: bool = False,
                   toggle: bool = True, autofocus: bool = False, initial: str = "",
                   **label_params) -> dict:
    out = {"type": "password", "name": name, "label": msg(label, **label_params),
           "new": new, "strength": strength, "toggle": toggle, "autofocus": autofocus}
    if initial:
        out["initial"] = initial  # only for the human's OWN item being edited, never an env secret
    return out


def text_field(name: str, label: str, /, *, mono: bool = False, placeholder: Optional[str] = None,
               autofocus: bool = False, initial: str = "", **label_params) -> dict:
    out: dict = {"type": "text", "name": name, "label": msg(label, **label_params),
                 "mono": mono, "autofocus": autofocus}
    if placeholder:
        out["placeholder"] = placeholder
    if initial:
        out["initial"] = initial
    return out


def textarea_field(name: str, label: str, /, *, rows: int = 4, mono: bool = False, initial: str = "",
                   autofocus: bool = False, **label_params) -> dict:
    out: dict = {"type": "textarea", "name": name, "label": msg(label, **label_params),
                 "rows": rows, "mono": mono, "autofocus": autofocus}
    if initial:
        out["initial"] = initial
    return out


def check_field(name: str, label: str, /, **label_params) -> dict:
    return {"type": "checkbox", "name": name, "label": msg(label, **label_params)}


# --- actions & screens ----------------------------------------------------

def action(action_id: str, label: str, /, *, variant: str = "outline", **label_params) -> dict:
    assert variant in ("primary", "outline", "danger")
    return {"id": action_id, "label": msg(label, **label_params), "variant": variant}


def screen(title: str, /, *, icon: str = "lock", blocks=(), fields=(), actions=(),
           step: Optional[tuple] = None, tone: str = "default", badge: Optional[dict] = None,
           default_action: Optional[str] = None, error: Optional[dict] = None,
           app: Optional[dict] = None, toast: Optional[dict] = None,
           **title_params) -> dict:
    """Build one screen. ``default_action`` is what Enter does inside a field;
    leave it None on any screen that destroys or writes something, so a held
    Enter can never confirm it (a screen like that must never be confirmable
    by a key held down)."""
    assert tone in ("default", "danger", "warning")
    out: dict = {
        "title": msg(title, **title_params),
        "icon": icon,
        "tone": tone,
        "blocks": list(blocks),
        "fields": list(fields),
        "actions": list(actions),
        "defaultAction": default_action,
        "error": error,
    }
    if step:
        out["step"] = {"current": step[0], "total": step[1]}
    if badge:
        out["badge"] = badge
    if app is not None:
        # The Bitwarden-style app frame (thyra_vault/webui/appflow.py). Carries
        # item NAMES and metadata only -- never a value.
        out["app"] = app
    if toast is not None:
        out["toast"] = toast  # a one-shot message, shown once per screen id
    return out
