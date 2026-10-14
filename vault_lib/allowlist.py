"""Persistent "always allow" entries: storage, arming, rollback guard.

The list lives in the vault body under the reserved key ``#always_allow``, so
the vault's AES-GCM authenticates it (tampering makes the vault fail to open
with ``VaultTampered``) and only a human holding the password can add to it.
An entry is::

    {id, kind, label, cwd, only_vars (sorted), shape, snapshot, created}

``id`` is ``sha256(canonical_json({kind, cwd, only_vars, shape}))[:12]``, so
approving the same thing again is an upsert that refreshes the snapshot.

Arming
------
``install()`` registers ``_on_unlock`` with ``store.register_unlock_listener``.
After every master-password unlock or write the whole armed set is rebuilt
synchronously from the body the vault just produced: each entry whose profile
exists, whose ``check_snapshot`` passes and whose variables are still in the
vault is loaded into the trust cache (``trust.arm``) with ONLY its
``only_vars`` values; everything else is disarmed with a reason.  Because the
set is rebuilt from the body, a removed entry cannot stay armed.  Recovery-key
sessions (method ``"recovery"``) never arm and never touch the armed set.

Rollback guard
--------------
Every body write raises ``#generation``.  The highest generation this machine
has seen is kept in memory and in a small sidecar file OUTSIDE the vault
directory (``{vault_id, generation}``, no secrets, atomic replace, never
lowered).  A vault whose generation is below that is an older copy that was
put back: nothing is armed and a warning is recorded (``rollback_warning``).
Residual risk (documented in the plan): an attacker who also deletes the
sidecar and restarts the server defeats this.

Public API (for the server / GUI wiring)
----------------------------------------
``install() / uninstall() / reset()``, ``eligible(...)``, ``lookup(req)`` /
``find_match(req)`` -> ``Match``, ``make_offer(req)`` -> ``Offer``,
``record_denial(req)`` / ``cooldown_remaining(req)``, ``add_entry`` /
``remove_entry`` / ``list_entries(password)``, ``describe_state()``,
``entries_to_arm()``, ``last_arm_report()``, ``rollback_warning()``.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import envnames, profiles, store, trust
from .profiles import Request, Verdict

ALLOW_KEY = "#always_allow"
TRUST_KEY_TAG = "always_allow"

# Cool-down (plan section 3): this many denials of one signature inside the
# window hide the "Always allow" checkbox for that signature for the cool-down.
DENIAL_LIMIT = 3
DENIAL_WINDOW_SECONDS = 30 * 60
COOLDOWN_SECONDS = 30 * 60

ROLLBACK_MESSAGE = (
    "vault.enc is older than the last state this machine saw -- always-allow "
    "entries were NOT armed; restore the newest copy or re-approve"
)
NO_SIDECAR_NOTE = (
    "No rollback record for this vault exists on this machine (first run, or it "
    "was deleted); a restored older vault.enc could not be detected until now."
)

# argv0 names that run arbitrary code from their arguments: never eligible,
# for any profile (basename, lower case, a launcher extension stripped).
_SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash", "cmd", "powershell",
                          "pwsh", "py", "node", "perl", "ruby", "wsl",
                          # wrappers that run their arguments as a program
                          "env", "xargs", "timeout", "nice", "nohup",
                          # further interpreters / launchers
                          "php", "lua", "luajit", "deno", "bun", "java",
                          "mshta", "rundll32", "wscript", "cscript"})
_INTERPRETER_PREFIXES = ("python", "pypy")
_STRIP_EXTS = (".exe", ".com", ".cmd", ".bat", ".ps1")
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

_now = time.monotonic          # patched by tests for the cool-down

# Test/relocation hook for the rollback sidecar directory (None = default).
SIDECAR_DIR: Optional[str] = None
_IMPORT_ROOT = store.ROOT

_state_lock = threading.RLock()
_entries: dict = {}            # id -> entry, from the last pass (structurally valid only)
_status: dict = {}             # id -> (armed: bool, reason: Optional[str])
_armed: set = set()
_report: dict = {}
_warning: Optional[str] = None
_notes: list = []
_seen_mem: dict = {}           # vault_id -> highest generation seen
_denials: dict = {}            # signature -> [monotonic timestamps]
_hidden_until: dict = {}       # signature -> monotonic deadline


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _key(entry_id: str) -> tuple:
    return (TRUST_KEY_TAG, entry_id)


def canonical_cwd(cwd: str) -> str:
    """realpath (symlinks/junctions resolved) then normcase, so two spellings
    of one directory compare equal."""
    return os.path.normcase(os.path.realpath(cwd))


def entry_id(kind: str, cwd: str, only_vars, shape) -> str:
    blob = json.dumps({"kind": kind, "cwd": cwd, "only_vars": sorted(only_vars),
                       "shape": shape},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()[:12]


def _unsafe_text(text) -> bool:
    return any(unicodedata.category(ch) in _UNSAFE_CATEGORIES
               or ch in (" ", " ") for ch in text)


def _argv0_name(command) -> str:
    base = os.path.basename(str(command[0]).replace("\\", "/")).lower()
    for ext in _STRIP_EXTS:
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def eligible(command, materialize=None, background=False, files=None,
             max_reads=None, all_vars=False, only_vars=None, cwd=None):
    """May this call take part in always-allow at all?  Returns ``(ok, reason)``.

    Never eligible: runs with ``files``/``all_vars``/``background``/
    ``max_reads``/``materialize``; an empty ``only_vars`` (the server refuses
    those before any matching -- ``only_vars=None`` here means "not asked");
    shells and interpreters as argv0; any command/cwd text with control,
    format, surrogate, private-use, unassigned or line/paragraph-separator
    characters (anti-spoofing; the normal dialog still works).
    """
    if files:
        return False, "runs with encrypted files are never always-allowed"
    if all_vars:
        return False, "all_vars runs are never always-allowed"
    if background:
        return False, "background runs are never always-allowed"
    if max_reads is not None:
        return False, "max_reads runs are never always-allowed"
    if materialize:
        return False, "materialize runs are never always-allowed"
    if only_vars is not None and len(tuple(only_vars)) == 0:
        return False, "a run without only_vars is never always-allowed"
    if not command or not all(isinstance(part, str) for part in command):
        return False, "the command is empty or malformed"
    name = _argv0_name(command)
    if name in _SHELL_NAMES or name.startswith(_INTERPRETER_PREFIXES):
        return False, f"{name!r} is a shell/interpreter and is never always-allowed"
    if any(_unsafe_text(part) for part in command) or (
            cwd is not None and _unsafe_text(str(cwd))):
        return False, "the command contains non-printable or control characters"
    return True, None


def _canon_request(req: Request) -> Request:
    return Request(tuple(req.command), canonical_cwd(req.cwd),
                   tuple(req.only_vars), req.timeout)


def _request_problem(req: Request) -> Optional[str]:
    ok, reason = eligible(req.command, only_vars=req.only_vars, cwd=req.cwd)
    return None if ok else reason


def _utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Rollback sidecar
# ---------------------------------------------------------------------------

def _vault_id() -> str:
    info = store.vault_info()
    if info.get("format") == 2 and info.get("vault_id"):
        return "v2:" + str(info["vault_id"])
    try:
        return "v1:" + hashlib.sha256(store.SALT_FILE.read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def _sidecar_dir() -> Path:
    if SIDECAR_DIR is not None:
        return Path(SIDECAR_DIR)
    if store.ROOT != _IMPORT_ROOT:
        # A relocated vault (test harnesses) must never write into the real
        # per-user state directory; vault ids are random, so sharing one
        # scratch directory cannot mix state between vaults.
        return Path(tempfile.gettempdir()) / "llm-env-vault-relocated-rollback"
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return base / "llm-env-vault" / "rollback"


def _sidecar_path(vault_id: str) -> Path:
    return _sidecar_dir() / (hashlib.sha256(vault_id.encode("utf-8")).hexdigest()[:32] + ".json")


def _read_sidecar(vault_id: str) -> Optional[int]:
    """The recorded generation, or None if missing/unreadable/for another vault."""
    try:
        data = json.loads(_sidecar_path(vault_id).read_text(encoding="utf-8"))
        gen = data.get("generation")
        if (data.get("vault_id") == vault_id and isinstance(gen, int)
                and not isinstance(gen, bool) and gen >= 0):
            return gen
    except (OSError, ValueError, AttributeError):
        pass
    return None


def _write_sidecar(vault_id: str, generation: int) -> None:
    try:
        path = _sidecar_path(vault_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"vault_id": vault_id, "generation": generation}),
                       encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass            # best effort: the in-memory record still protects this process


def _rollback_check(vault_id: str, generation: int, has_entries: bool):
    """``(ok, note)``.  ok=False: this vault is older than a state already seen
    (nothing recorded).  Otherwise the sighting is recorded (never lowered)."""
    mem = _seen_mem.get(vault_id)
    side = _read_sidecar(vault_id)
    known = [g for g in (mem, side) if g is not None]
    if known and generation < max(known):
        return False, None
    note = None
    if side is None and mem is None and generation >= 1 and has_entries:
        note = NO_SIDECAR_NOTE
    _seen_mem[vault_id] = max(known + [generation])
    if side is None or generation > side:
        _write_sidecar(vault_id, max(known + [generation]))
    return True, note


# ---------------------------------------------------------------------------
# Entry parsing
# ---------------------------------------------------------------------------

def _raw_entries(body) -> list:
    raw = body.get(ALLOW_KEY) if isinstance(body, dict) else None
    return list(raw) if isinstance(raw, list) else []


def _validate(entry):
    """``(ok, reason)`` for one stored entry's structure and id."""
    if not isinstance(entry, dict):
        return False, "malformed entry"
    for field_name, kind in (("id", str), ("kind", str), ("cwd", str),
                             ("shape", dict), ("snapshot", dict)):
        if not isinstance(entry.get(field_name), kind):
            return False, f"malformed entry ({field_name})"
    names = entry.get("only_vars")
    if (not isinstance(names, list) or not names
            or not all(isinstance(n, str) and n for n in names)):
        return False, "malformed entry (only_vars)"
    if entry["id"] != entry_id(entry["kind"], entry["cwd"], names, entry["shape"]):
        return False, "entry id does not match its contents"
    return True, None


def _label_of(entry) -> str:
    label = entry.get("label") if isinstance(entry, dict) else None
    return label if isinstance(label, str) else "(unlabelled entry)"


# ---------------------------------------------------------------------------
# Arming
# ---------------------------------------------------------------------------

def install() -> None:
    """Register the arming listener with the vault (idempotent)."""
    store.register_unlock_listener(_on_unlock)


def uninstall() -> None:
    store.unregister_unlock_listener(_on_unlock)


def _disarm_locked(entry_id_: str, reason: str) -> None:
    trust.disarm(_key(entry_id_))
    _armed.discard(entry_id_)
    _status[entry_id_] = (False, reason)


def _disarm_all_locked(reason: str) -> None:
    for eid in list(_armed):
        trust.disarm(_key(eid))
    _armed.clear()
    for eid in list(_status):
        _status[eid] = (False, reason)


def _on_unlock(body, fingerprint, method) -> None:
    """Unlock listener: rebuild the armed set from *body* (see module doc)."""
    if method == "recovery":
        return                                   # a recovery key never arms
    try:
        disk_fp = hashlib.sha256(store.SECRETS_FILE.read_bytes()).hexdigest()
    except OSError:
        return
    if disk_fp != fingerprint:
        return                                   # a stale view: another write won
    with _state_lock:
        _rebuild(body, fingerprint, method)


def _rebuild(body: dict, fp: str, method: str) -> None:
    global _warning, _notes, _report
    raw = _raw_entries(body)
    vault_id = _vault_id()
    ok, note = _rollback_check(vault_id, store.body_generation(body), bool(raw))
    previously_known = set(_status) | set(_armed)
    entries: dict = {}
    status: dict = {}
    for item in raw:
        valid, why = _validate(item)
        if valid:
            entries[item["id"]] = copy.deepcopy(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            status[item["id"]] = (False, why)
    _entries.clear()
    _entries.update(entries)
    notes = [note] if note else []

    if not ok:
        _warning = ROLLBACK_MESSAGE
        for eid in previously_known | set(entries):
            trust.disarm(_key(eid))
        _armed.clear()
        _status.clear()
        for eid in entries:
            status[eid] = (False, ROLLBACK_MESSAGE)
        _status.update(status)
        _notes = notes
        _report = _make_report(method, entries)
        return
    _warning = None

    armed: set = set()
    for eid, entry in entries.items():
        try:
            reason = _arm_one(entry, body, fp)
        except Exception as exc:                 # one bad entry must not skip the disarm pass
            trust.disarm(_key(eid))
            reason = f"arming failed: {exc}"
        if reason is None:
            armed.add(eid)
            status[eid] = (True, None)
        else:
            status[eid] = (False, reason)
    for eid in previously_known - armed:
        trust.disarm(_key(eid))                  # vanished or newly disarmed
    _armed.clear()
    _armed.update(armed)
    _status.clear()
    _status.update(status)
    _notes = notes
    _report = _make_report(method, entries)


def _arm_one(entry: dict, body: dict, fp: str) -> Optional[str]:
    """Arm one entry; return None on success or the reason it stays disarmed."""
    names = entry["only_vars"]
    tool_control = getattr(store, "is_tool_control_name", envnames.is_tool_control_name)
    for name in names:
        if tool_control is not None and tool_control(name):
            return f"variable {name} is a tool-control name and cannot be always-allowed"
        if name not in body or not isinstance(body[name], str) or store.is_reserved_key(name):
            return f"variable {name} is no longer in the vault"
    profile = profiles.get_profile(entry["kind"])
    if profile is None:
        return profiles.unavailable_reason(entry["kind"])
    try:
        ok, reason = profile.check_snapshot(copy.deepcopy(entry))
    except Exception as exc:
        return f"snapshot check failed: {exc}"
    if not ok:
        return reason or "the approved state no longer holds"
    trust.arm(_key(entry["id"]), entry["snapshot"],
              {name: body[name] for name in names}, vault_fp=fp)
    return None


def _make_report(method: str, entries: dict) -> dict:
    return {
        "method": method,
        "armed": [_summary(entries[eid]) for eid, (armed, _r) in sorted(_status.items())
                  if armed and eid in entries],
        "disarmed": [{"id": eid, "label": _label_of(entries.get(eid)), "reason": reason}
                     for eid, (armed, reason) in sorted(_status.items()) if not armed],
        "warning": _warning,
        "notes": list(_notes),
    }


def _summary(entry: dict) -> dict:
    return {"id": entry["id"], "kind": entry["kind"], "label": _label_of(entry),
            "only_vars": list(entry["only_vars"])}


def last_arm_report() -> dict:
    """What the latest arming pass did: armed / disarmed (with reasons),
    warning, notes.  For the unlock result and dialog; no secrets."""
    with _state_lock:
        return copy.deepcopy(_report) if _report else {
            "method": None, "armed": [], "disarmed": [], "warning": _warning,
            "notes": list(_notes)}


def rollback_warning() -> Optional[str]:
    """The rollback refusal message while the vault is older than the last
    state seen; None otherwise."""
    with _state_lock:
        return _warning


def entries_to_arm() -> list:
    """Known entries that a master-password unlock would arm right now (known
    to this process but not currently armed): ``[{id, kind, label, only_vars}]``.
    Entries live inside the ciphertext, so before the process's first unlock
    this is necessarily empty -- the arming pass reports what it armed in
    ``last_arm_report`` instead."""
    with _state_lock:
        return [_summary(e) for eid, e in sorted(_entries.items()) if eid not in _armed]


def describe_state() -> dict:
    """Non-secret in-process state for diagnostics."""
    with _state_lock:
        return {
            "installed": _on_unlock in store._unlock_listeners,
            "entries": len(_entries),
            "armed": len(_armed),
            "rollback_warning": _warning,
            "notes": list(_notes),
            "status": {eid: {"kind": _entries[eid]["kind"] if eid in _entries else None,
                             "label": _label_of(_entries.get(eid)),
                             "armed": armed, "reason": reason}
                       for eid, (armed, reason) in sorted(_status.items())},
        }


def reset() -> None:
    """Forget all in-process state and disarm everything (tests)."""
    global _warning, _report, _notes
    with _state_lock:
        for eid in set(_status) | set(_armed) | set(_entries):
            trust.disarm(_key(eid))
        _entries.clear()
        _status.clear()
        _armed.clear()
        _seen_mem.clear()
        _denials.clear()
        _hidden_until.clear()
        _warning = None
        _report = {}
        _notes = []


# ---------------------------------------------------------------------------
# Storage: add / remove / list
# ---------------------------------------------------------------------------

def _modify(password: str, mutate):
    """Read-modify-write ``#always_allow`` only, with one CAS retry.

    ``mutate(body, entries) -> (new_entries_or_None, result)``; None means
    "no change, do not write".  Every other body key (``#fmk``, ``#generation``
    ...) rides along untouched.  Wrong password, throttling and
    ``VaultTampered`` propagate from the vault.
    """
    for attempt in range(2):
        body, _envelope, fingerprint = store.load_vault_body_ex(password)
        new_entries, result = mutate(body, _raw_entries(body))
        if new_entries is None:
            return result
        new_body = dict(body)
        new_body[ALLOW_KEY] = new_entries
        try:
            store.save_vault_body(password, new_body, expect_fingerprint=fingerprint)
        except RuntimeError as exc:
            if attempt == 0 and "compare-and-swap" in str(exc):
                continue
            raise
        return result
    raise AssertionError("unreachable")          # pragma: no cover


def add_entry(password: str, *, kind: str, cwd: str, only_vars, shape: dict,
              snapshot: dict, label: str) -> str:
    """Approve (or re-approve) one entry; returns its id.  Re-approving the
    same kind/cwd/vars/shape replaces label and snapshot and keeps ``created``."""
    names = sorted(set(only_vars))
    if not names:
        raise ValueError("an always-allow entry needs at least one variable")
    if profiles.get_profile(kind) is None:
        raise ValueError(profiles.unavailable_reason(kind))
    tool_control = getattr(store, "is_tool_control_name", envnames.is_tool_control_name)
    eid = entry_id(kind, cwd, names, shape)

    def mutate(body, entries):
        for name in names:
            if name not in body or store.is_reserved_key(name):
                raise ValueError(f"variable {name} is not in the vault")
            if tool_control is not None and tool_control(name):
                raise ValueError(f"variable {name} is a tool-control name")
        created = _utc_iso()
        kept = []
        for item in entries:
            if isinstance(item, dict) and item.get("id") == eid:
                if isinstance(item.get("created"), str):
                    created = item["created"]
                continue
            kept.append(item)
        kept.append({"id": eid, "kind": kind, "label": label, "cwd": cwd,
                     "only_vars": names, "shape": shape, "snapshot": snapshot,
                     "created": created})
        return kept, eid

    return _modify(password, mutate)


def remove_entry(password: str, entry_id_: str) -> bool:
    """Delete one entry; True if it existed.  The armed set is rebuilt from the
    post-write body before this returns, and the entry is disarmed regardless."""
    def mutate(body, entries):
        kept = [i for i in entries
                if not (isinstance(i, dict) and i.get("id") == entry_id_)]
        if len(kept) == len(entries):
            return None, False
        return kept, True

    removed = _modify(password, mutate)
    if removed:
        with _state_lock:
            _entries.pop(entry_id_, None)
            trust.disarm(_key(entry_id_))
            _armed.discard(entry_id_)
            _status.pop(entry_id_, None)
    return removed


def list_entries(password: str) -> list:
    """Password-gated listing: ONLY ``id, kind, cwd, shape, label`` per entry,
    plus ``armed``/``reason`` from this process.  Never snapshots, URLs, hook
    inventories or any value."""
    body, _envelope, _fp = store.load_vault_body_ex(password)
    out = []
    with _state_lock:
        for item in _raw_entries(body):
            if not isinstance(item, dict):
                continue
            armed, reason = _status.get(item.get("id"), (False, None))
            out.append({"id": item.get("id"), "kind": item.get("kind"),
                        "cwd": item.get("cwd"),
                        "shape": copy.deepcopy(item.get("shape")),
                        "label": item.get("label"),
                        "armed": armed, "reason": reason})
    return out


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

@dataclass
class Match:
    """An armed entry that verified for one request.

    ``entry`` is a copy of the stored entry, ``verdict`` the profile's final
    argv/env, ``secrets`` ONLY the request's variables.  Call ``recheck()``
    right before spawning; call ``close()`` when done with the values.
    """
    entry: dict
    verdict: Verdict
    secrets: dict
    request: Request
    label: str = ""
    id: str = ""
    _rechecked: bool = field(default=False, repr=False)

    def recheck(self) -> Verdict:
        """Re-verify right before spawn.  On drift the entry is disarmed with
        the reason and a not-ok verdict is returned (fall back to the dialog)."""
        verdict = _verify_armed(self.entry, self.request)
        if verdict.ok:
            self.verdict = verdict
        else:
            self.secrets.clear()
        return verdict

    def close(self) -> None:
        self.secrets.clear()


def _verify_armed(entry: dict, req: Request) -> Verdict:
    """check_armed + profile.verify for one entry; disarms on any drift."""
    eid = entry["id"]
    ok, why = trust.check_armed(_key(eid))
    if not ok:
        with _state_lock:
            if why:
                _disarm_all_locked(why)
            elif eid in _armed:
                _disarm_locked(eid, "no longer armed")
        return Verdict(ok=False, reason=why or "no longer armed")
    profile = profiles.get_profile(entry["kind"])
    if profile is None:
        reason = profiles.unavailable_reason(entry["kind"])
        with _state_lock:
            _disarm_locked(eid, reason)
        return Verdict(ok=False, reason=reason)
    try:
        verdict = profile.verify(copy.deepcopy(entry), req)
    except Exception as exc:
        verdict = Verdict(ok=False, reason=f"verification failed: {exc}")
    if not verdict.ok and verdict.reason:
        with _state_lock:
            _disarm_locked(eid, verdict.reason)
    return verdict


def lookup(req: Request):
    """``(Match|None, reason|None)``.  *reason* is why an entry that applied to
    this request was disarmed (drift, vault changed ...), for the dialog."""
    if _request_problem(req) is not None:
        return None, None
    canon = _canon_request(req)
    with _state_lock:
        candidates = sorted(
            (e for eid, e in _entries.items()
             if eid in _armed
             and e["cwd"].casefold() == canon.cwd.casefold()
             and set(canon.only_vars) <= set(e["only_vars"])),
            key=lambda e: (len(e["only_vars"]), e["id"]))
    reason = None
    for entry in candidates:
        verdict = _verify_armed(entry, canon)
        if verdict.ok:
            cached = trust.cached_secrets(_key(entry["id"]))
            if cached is None or not set(canon.only_vars) <= set(cached):
                with _state_lock:
                    _disarm_locked(entry["id"], "cached values are unavailable")
                reason = reason or "cached values are unavailable"
                continue
            secrets = {n: cached[n] for n in canon.only_vars}
            return Match(entry=copy.deepcopy(entry), verdict=verdict, secrets=secrets,
                         request=canon, label=_label_of(entry), id=entry["id"]), None
        if verdict.reason:
            reason = reason or verdict.reason
    return None, reason


def find_match(req: Request) -> Optional[Match]:
    return lookup(req)[0]


# ---------------------------------------------------------------------------
# Offers and the denial cool-down
# ---------------------------------------------------------------------------

def _signature(req: Request) -> tuple:
    return trust.make_signature(req.command, canonical_cwd(req.cwd), req.only_vars,
                                None, timeout=req.timeout)


def record_denial(req: Request) -> None:
    """The human denied this request's dialog.  DENIAL_LIMIT denials of one
    signature inside DENIAL_WINDOW_SECONDS hide the checkbox for COOLDOWN_SECONDS."""
    sig = _signature(req)
    now = _now()
    with _state_lock:
        recent = [t for t in _denials.get(sig, ()) if now - t <= DENIAL_WINDOW_SECONDS]
        recent.append(now)
        if len(recent) >= DENIAL_LIMIT:
            _hidden_until[sig] = now + COOLDOWN_SECONDS
            recent = []
        _denials[sig] = recent


def cooldown_remaining(req: Request) -> float:
    """Seconds the checkbox stays hidden for this request's signature (0 = shown)."""
    sig = _signature(req)
    with _state_lock:
        left = _hidden_until.get(sig, 0) - _now()
        if left <= 0:
            _hidden_until.pop(sig, None)
            return 0.0
        return left


@dataclass
class Offer:
    """What the dialog shows for the "Always allow" checkbox.  ``pattern`` is
    the profile's description (canonical pattern first); ``commit`` stores the
    entry once the human has typed the password."""
    kind: str
    label: str
    pattern: str
    cwd: str
    only_vars: tuple
    shape: dict
    snapshot: dict

    def commit(self, password: str) -> str:
        """Add the entry (upsert); returns its id.  Raises like the vault does
        (WrongPassword, TooManyAttempts, VaultTampered ...) or ValueError."""
        return add_entry(password, kind=self.kind, cwd=self.cwd,
                         only_vars=self.only_vars, shape=self.shape,
                         snapshot=self.snapshot, label=self.label)


def _default_label(kind: str, pattern: str) -> str:
    first = pattern.splitlines()[0] if pattern else kind
    first = first if first.lower().startswith(kind) else f"{kind}: {first}"
    return first if len(first) <= 100 else first[:97] + "..."


def make_offer(req: Request) -> Optional[Offer]:
    """An Offer for this request, or None when no checkbox should be shown
    (ineligible request, cool-down active, no profile claims it, or the
    profile could not snapshot/describe it)."""
    if _request_problem(req) is not None or cooldown_remaining(req) > 0:
        return None
    canon = _canon_request(req)
    for kind, profile in profiles.iter_profiles():
        try:
            candidate = profile.match(canon)
        except Exception:
            continue
        if candidate is None:
            continue
        try:
            snapshot = profile.snapshot(canon, candidate)
            pattern = profile.describe(canon, candidate)
            label_fn = getattr(profile, "label", None)
            label = label_fn(canon, candidate) if label_fn else _default_label(kind, pattern)
        except Exception:
            return None
        if not isinstance(snapshot, dict) or not isinstance(candidate, dict):
            return None
        return Offer(kind=kind, label=label, pattern=pattern, cwd=canon.cwd,
                     only_vars=tuple(canon.only_vars), shape=candidate,
                     snapshot=snapshot)
    return None
