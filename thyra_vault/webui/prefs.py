"""Interface preferences for the browser app (language, theme, timers, generator).

Stored server-side because every launch uses a new random port, so the page's
own localStorage (per origin) forgets everything between runs.

``ui_prefs.json`` is PLAINTEXT and agent-writable, exactly like vault_index.json,
so nothing in it may be trusted:

  * every value is checked against a fixed allow-list or clamped to a range, and
    anything else falls back to the default;
  * the security-relevant timers cannot be switched off or stretched without
    bound -- the longest auto-lock is 60 minutes and the longest clipboard wipe
    is 2 minutes, whatever the file says.
"""
import json
from typing import Any, Dict

from ..vault import store
from .uihelpers import _CLIPBOARD_CLEAR_SECONDS

FILE_NAME = "ui_prefs.json"

LANGUAGES = ("en", "it", "fr", "de", "es", "pt-PT", "pt-BR")
THEMES = ("light", "dark", "system")
AUTO_LOCK_MINUTES = (1, 2, 5, 10, 15, 30, 60)
CLIPBOARD_SECONDS = (10, 20, 30, 60, 120)

DEFAULT_GENERATOR: Dict[str, Any] = {
    "mode": "password", "length": 20, "upper": True, "lower": True, "digits": True,
    "symbols": False, "minDigits": 1, "minSymbols": 0, "avoidAmbiguous": False,
    "words": 5, "separator": "-", "capitalize": False, "includeNumber": False,
}

DEFAULTS: Dict[str, Any] = {
    "language": None,
    "theme": "system",
    "autoLockMinutes": 15,
    "clipboardSeconds": _CLIPBOARD_CLEAR_SECONDS if _CLIPBOARD_CLEAR_SECONDS in CLIPBOARD_SECONDS else 30,
    "generator": DEFAULT_GENERATOR,
}


def _int_in(value, lo: int, hi: int, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(lo, min(hi, value))


def _choice(value, allowed, default):
    # `True in (1, 2)` is True and `15.0 in (15,)` too: take only real ints/strings.
    if isinstance(value, (bool, float)):
        return default
    return value if value in allowed else default


def _bool(value, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _sep(value, default: str) -> str:
    return value if isinstance(value, str) and len(value) == 1 and value.isprintable() else default


def clean_generator(raw) -> Dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    d = DEFAULT_GENERATOR
    return {
        "mode": _choice(raw.get("mode"), ("password", "passphrase", "username"), d["mode"]),
        "length": _int_in(raw.get("length"), 5, 128, d["length"]),
        "upper": _bool(raw.get("upper"), d["upper"]),
        "lower": _bool(raw.get("lower"), d["lower"]),
        "digits": _bool(raw.get("digits"), d["digits"]),
        "symbols": _bool(raw.get("symbols"), d["symbols"]),
        "minDigits": _int_in(raw.get("minDigits"), 0, 9, d["minDigits"]),
        "minSymbols": _int_in(raw.get("minSymbols"), 0, 9, d["minSymbols"]),
        "avoidAmbiguous": _bool(raw.get("avoidAmbiguous"), d["avoidAmbiguous"]),
        "words": _int_in(raw.get("words"), 3, 20, d["words"]),
        "separator": _sep(raw.get("separator"), d["separator"]),
        "capitalize": _bool(raw.get("capitalize"), d["capitalize"]),
        "includeNumber": _bool(raw.get("includeNumber"), d["includeNumber"]),
    }


def clean(raw) -> Dict[str, Any]:
    """A fully valid preferences dict from anything at all."""
    raw = raw if isinstance(raw, dict) else {}
    return {
        "language": _choice(raw.get("language"), LANGUAGES, DEFAULTS["language"]),
        "theme": _choice(raw.get("theme"), THEMES, DEFAULTS["theme"]),
        "autoLockMinutes": _choice(raw.get("autoLockMinutes"), AUTO_LOCK_MINUTES,
                                   DEFAULTS["autoLockMinutes"]),
        "clipboardSeconds": _choice(raw.get("clipboardSeconds"), CLIPBOARD_SECONDS,
                                    DEFAULTS["clipboardSeconds"]),
        "generator": clean_generator(raw.get("generator")),
    }


def _path():
    return store.ROOT / FILE_NAME


def load() -> Dict[str, Any]:
    try:
        raw = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    return clean(raw)


def update(changes) -> Dict[str, Any]:
    """Merge ``changes`` over the stored preferences, validate, write, return."""
    merged = load()
    if isinstance(changes, dict):
        for key, value in changes.items():
            if key == "generator":
                merged["generator"] = clean_generator(
                    {**merged["generator"], **value} if isinstance(value, dict) else None)
            elif key in DEFAULTS:
                merged[key] = value
    merged = clean(merged)
    try:
        store._atomic_write_text(_path(), json.dumps(merged, indent=2, sort_keys=True) + "\n")
    except OSError:
        pass  # preferences are a convenience: never fail the app over them
    return merged
