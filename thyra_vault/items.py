"""Personal items in the vault: logins, cards, identities, notes, SSH keys.

These are for the HUMAN, in the Thyra Vault app. They are not environment
secrets and an AI assistant never sees them:

  * they live in ONE reserved key of the encrypted vault body (``#items``), so
    titles and contents are encrypted together and the plaintext index
    (vault_index.json, readable by an agent by design) never mentions them;
  * every existing tool reads variables only -- ``load_secrets`` filters
    reserved keys out and ``save_secrets`` carries them through untouched -- so
    ``run_with_env``, ``sync_llm_env`` and friends cannot see or change an item;
  * nothing here is exposed as an MCP tool.

Everything read from the vault is re-validated before use. The body is
authenticated-encrypted, so tampering needs the password, but a bug or a future
format change must not be able to put an unbounded or ill-typed value in front
of the UI.

Persistence is a read-modify-write under the vault lock, exactly like the file
master key: see store.get_or_create_fmk for why that matters.
"""
import secrets as _secrets
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from . import store

ITEMS_KEY = store.RESERVED_KEY_PREFIX + "items"
FORMAT_VERSION = 1

LOGIN, CARD, IDENTITY, NOTE, SSH = "login", "card", "identity", "note", "ssh"
TYPES = (LOGIN, CARD, IDENTITY, NOTE, SSH)

# kind: "text" (one line, shown), "secret" (one line, hidden until revealed),
#       "multiline" (several lines, shown), "multiline-secret" (several lines, hidden).
FIELD_SPECS: Dict[str, List[tuple]] = {
    LOGIN: [("username", "text"), ("password", "secret"), ("uri", "text")],
    CARD: [("holder", "text"), ("brand", "text"), ("number", "secret"),
           ("expMonth", "text"), ("expYear", "text"), ("code", "secret")],
    IDENTITY: [("title", "text"), ("firstName", "text"), ("middleName", "text"), ("lastName", "text"),
               ("email", "text"), ("phone", "text"), ("company", "text"),
               ("address1", "text"), ("address2", "text"), ("city", "text"), ("state", "text"),
               ("postalCode", "text"), ("country", "text"),
               ("ssn", "secret"), ("passport", "secret"), ("license", "secret")],
    NOTE: [],
    SSH: [("privateKey", "multiline-secret"), ("publicKey", "multiline"), ("passphrase", "secret")],
}
# What the list's copy button copies, per type (None: nothing sensible to copy).
PRIMARY_FIELD = {LOGIN: "password", CARD: "number", IDENTITY: "email", NOTE: "notes", SSH: "privateKey"}
NOTES = "notes"  # every type has free-text notes; hidden by default, like a secret

MAX_ITEMS = 5000
MAX_NAME = 200
MAX_FOLDER = 100
MAX_VALUE = 50_000
MAX_TOTAL = 4_000_000  # characters across all items: a sanity bound, not a quota


class ItemsCorrupted(ValueError):
    """The stored items are not in a shape this version understands."""


def kind_of(item_type: str, field: str) -> str:
    """"text" | "secret" | "multiline" | "multiline-secret" for a field of a type."""
    if field == NOTES:
        return "multiline-secret"
    for name, kind in FIELD_SPECS.get(item_type, []):
        if name == field:
            return kind
    raise KeyError(field)


def is_hidden(kind: str) -> bool:
    return kind.endswith("secret")


def field_names(item_type: str) -> List[str]:
    return [name for name, _ in FIELD_SPECS[item_type]] + [NOTES]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(value, limit: int, what: str, *, multiline: bool = False) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{what} must be text")
    if len(value) > limit:
        raise ValueError(f"{what} is too long (over {limit} characters)")
    if "\x00" in value:
        raise ValueError(f"{what} contains a NUL character")
    if not multiline and ("\n" in value or "\r" in value):
        raise ValueError(f"{what} must be a single line")
    return value


def normalize(raw: dict, *, keep_times: bool = True) -> dict:
    """A clean, complete item from a dict; raises ValueError on anything off."""
    if not isinstance(raw, dict):
        raise ValueError("an item must be an object")
    item_type = raw.get("type")
    if item_type not in TYPES:
        raise ValueError(f"unknown item type {item_type!r}")
    name = _clean_text(raw.get("name"), MAX_NAME, "the name").strip()
    if not name:
        raise ValueError("the name cannot be empty")
    fields_in = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
    fields = {}
    for fname, kind in FIELD_SPECS[item_type]:
        value = _clean_text(fields_in.get(fname), MAX_VALUE, fname, multiline=kind.startswith("multiline"))
        if value:
            fields[fname] = value
    item_id = raw.get("id")
    if not (isinstance(item_id, str) and len(item_id) == 32 and all(c in "0123456789abcdef" for c in item_id)):
        item_id = _secrets.token_hex(16)
    now = _now()
    created = raw.get("created") if keep_times and isinstance(raw.get("created"), str) else now
    updated = raw.get("updated") if keep_times and isinstance(raw.get("updated"), str) else now
    return {
        "id": item_id, "type": item_type, "name": name,
        "folder": _clean_text(raw.get("folder"), MAX_FOLDER, "the folder").strip(),
        "fields": fields,
        NOTES: _clean_text(raw.get(NOTES), MAX_VALUE, "the notes", multiline=True),
        "created": created[:32], "updated": updated[:32],
    }


def _parse(raw) -> List[dict]:
    if raw is None:
        return []
    if not isinstance(raw, dict) or raw.get("v") != FORMAT_VERSION or not isinstance(raw.get("items"), list):
        raise ItemsCorrupted("The stored items are in a format this version does not understand.")
    if len(raw["items"]) > MAX_ITEMS:
        raise ItemsCorrupted("The vault holds more items than this version supports.")
    try:
        items = [normalize(i) for i in raw["items"]]
    except ValueError as exc:
        raise ItemsCorrupted(f"A stored item is invalid: {exc}") from None
    if len({i["id"] for i in items}) != len(items):
        raise ItemsCorrupted("Two stored items share one id.")
    return items


def from_body(body: dict) -> List[dict]:
    return _parse(body.get(ITEMS_KEY))


def load(password: str) -> List[dict]:
    """All items, decrypted. Raises the store's errors for a wrong password."""
    return from_body(store.load_vault_body(password))


def mutate(password: str, change: Callable[[List[dict]], List[dict]]) -> List[dict]:
    """Apply ``change(items) -> new_items`` atomically; returns the new list.

    Held under the vault lock for the whole read-modify-write. The fingerprint
    compare-and-swap stays as a second layer: if the file moved between our read
    and our write we re-read and apply the change to what is there now.
    """
    with store._vault_lock():
        for attempt in (0, 1):
            body, _envelope, fingerprint = store.load_vault_body_ex(password)
            new_items = change(from_body(body))
            if len(new_items) > MAX_ITEMS:
                raise ValueError(f"A vault holds at most {MAX_ITEMS} items.")
            if sum(len(i["name"]) + len(i[NOTES]) + sum(map(len, i["fields"].values())) for i in new_items) > MAX_TOTAL:
                raise ValueError("The items are too large to store.")
            body[ITEMS_KEY] = {"v": FORMAT_VERSION, "items": new_items}
            try:
                store.save_vault_body(password, body, expect_fingerprint=fingerprint)
            except RuntimeError:
                if attempt == 0:
                    continue
                raise
            return new_items
    raise RuntimeError("vault.enc kept changing underneath.")  # pragma: no cover


def find(items: List[dict], item_id: str) -> Optional[dict]:
    return next((i for i in items if i["id"] == item_id), None)


def add(password: str, item_type: str, name: str, fields=None, notes: str = "", folder: str = "") -> dict:
    new = normalize({"type": item_type, "name": name, "fields": fields or {}, NOTES: notes, "folder": folder},
                    keep_times=False)
    mutate(password, lambda items: items + [new])
    return new


def update(password: str, item_id: str, name: str, fields=None, notes: str = "", folder: str = "") -> dict:
    result = {}

    def change(items):
        current = find(items, item_id)
        if current is None:
            raise KeyError(item_id)
        edited = normalize({"id": item_id, "type": current["type"], "name": name, "fields": fields or {},
                            NOTES: notes, "folder": folder, "created": current["created"]}, keep_times=True)
        edited["updated"] = _now()
        result.update(edited)
        return [edited if i["id"] == item_id else i for i in items]

    mutate(password, change)
    return dict(result)


def delete(password: str, item_id: str) -> None:
    def change(items):
        if find(items, item_id) is None:
            raise KeyError(item_id)
        return [i for i in items if i["id"] != item_id]

    mutate(password, change)
