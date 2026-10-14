"""Profile registry and protocol for persistent "always allow" entries.

A *profile* knows how to turn one concrete ``run_with_env`` request into a
clamped, re-verifiable approval (an entry in the vault's ``#always_allow``
list) and how to re-check that approval later.  This module holds the two
value types every profile speaks (``Request``, ``Verdict``), the registry that
finds profiles by ``kind``, and nothing else -- the profiles themselves live
in sibling modules (``exact``, ``git``, ``docker``, ``kubectl``).

Profile protocol
----------------
A profile is a module (or any object) exposing:

``kind: str``
    Registry key and the ``kind`` stored in entries.

``match(req) -> Optional[dict]``
    The JSON-serialisable *candidate shape* if ``req`` belongs to this
    profile, else ``None``.  The shape is what ends up in the entry (it feeds
    the entry id), so it must be canonical: equal requests, equal shape.

``snapshot(req, candidate) -> dict``
    Approval-time snapshot (JSON-serialisable).  Runs BEFORE the dialog, may
    run read-only probes, and must not need vault secrets.

``describe(req, candidate) -> str``
    Human text for the dialog: first line is the canonical pattern the entry
    will match, then findings and warnings.

``check_snapshot(entry) -> (ok, reason)``
    Arm-time check with no concrete command: does the approved state still
    hold?  ``reason`` is shown to the human when ``ok`` is False.

``verify(entry, req) -> Verdict``
    Run-time check for a concrete request.  ``ok=False, reason=None`` means
    "this entry does not apply to this request"; ``ok=False, reason=str``
    means "applies, but drifted or refused"; ``ok=True`` carries the final
    ``argv`` and ``env`` to spawn.

Optional: ``label(req, candidate) -> str`` (server-generated entry label).

``Verdict.env`` semantics: ``replace_env=True`` -- ``env`` is the COMPLETE
child environment (the caller adds only the ``only_vars`` values on top);
``replace_env=False`` -- ``env`` is merged onto ``os.environ``; ``env=None``
-- ``os.environ`` plus the secrets.

Loading is lazy and tolerant: a kind whose module is missing or fails to
import is simply *unavailable* (see ``unavailable_reason``); entries of that
kind are disarmed with that reason and nothing else is affected.
"""
from __future__ import annotations

import importlib
import threading
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple


@dataclass(frozen=True)
class Request:
    """One concrete run_with_env request, as seen by a profile.

    ``command`` is the argv as a tuple of str, ``cwd`` the (already
    canonicalised) working directory, ``only_vars`` the sorted, de-duplicated
    tuple of variable names the call asked for, ``timeout`` the call's
    timeout in seconds (or None).
    """
    command: Tuple[str, ...]
    cwd: str
    only_vars: Tuple[str, ...] = ()
    timeout: Optional[int] = None

    def __post_init__(self):
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "only_vars",
                           tuple(sorted(set(self.only_vars or ()))))


@dataclass(frozen=True)
class Verdict:
    """Result of Profile.verify.  See the module docstring for the cases."""
    ok: bool
    reason: Optional[str] = None
    argv: Optional[list] = None
    env: Optional[dict] = None
    replace_env: bool = False
    # Bytes the caller must write to the child's stdin (compose `up -f -`,
    # kubectl apply's original manifest); None means stdin stays closed.
    stdin: Optional[bytes] = field(default=None, repr=False, compare=False)
    # False: the caller must NOT add the only_vars values to the child env
    # (docker: values already live inside ``stdin`` or must never reach a
    # build).  Output is still redacted against them either way.
    inject_secrets: bool = True


# kind -> module name, in MATCH ORDER; "exact" must stay last because it
# accepts anything a more specific profile did not claim.  The git, docker and
# kubectl modules are added by their own work units; until a module exists the
# kind is just unavailable.  Nothing outside this dict needs editing to add one.
REGISTRY = {
    "git": "vault_lib.profiles.git",
    "docker": "vault_lib.profiles.docker",
    "kubectl": "vault_lib.profiles.kubectl",
    "exact": "vault_lib.profiles.exact",
}

_lock = threading.RLock()
_loaded: dict = {}       # kind -> profile object (imported or registered)
_failed: dict = {}       # kind -> reason string
_injected: list = []     # kinds added with register_profile (tests), match order


def _import(kind: str):
    module_name = REGISTRY[kind]
    try:
        return importlib.import_module(module_name), None
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            return None, f"profile '{kind}' is not available in this version"
        return None, f"profile '{kind}' failed to load: {exc}"
    except Exception as exc:  # a broken profile must disarm, not crash unlock
        return None, f"profile '{kind}' failed to load: {exc}"


def get_profile(kind) -> Optional[Any]:
    """The profile object for *kind*, importing it on first use; ``None`` if
    the kind is unknown or its module is missing/broken (never raises)."""
    if not isinstance(kind, str):
        return None
    with _lock:
        if kind in _loaded:
            return _loaded[kind]
        if kind not in REGISTRY:
            return None
        if kind in _failed:
            return None
        profile, reason = _import(kind)
        if profile is None:
            _failed[kind] = reason
            return None
        _loaded[kind] = profile
        return profile


def unavailable_reason(kind) -> str:
    """Why *kind* has no profile (for the disarm reason shown to the human)."""
    with _lock:
        if get_profile(kind) is not None:
            return ""
        if kind in _failed:
            return _failed[kind]
    return f"unknown always-allow kind {kind!r}"


def iter_profiles():
    """Yield ``(kind, profile)`` for every AVAILABLE profile in match order
    (injected test profiles first, then REGISTRY order, ``exact`` last)."""
    with _lock:
        kinds = list(_injected) + [k for k in REGISTRY if k not in _injected]
    for kind in kinds:
        profile = get_profile(kind)
        if profile is not None:
            yield kind, profile


def register_profile(kind: str, profile) -> None:
    """Install *profile* for *kind* ahead of the registry (tests / plug-ins).
    Replaces any earlier profile of that kind; always matched before the
    REGISTRY profiles so a test double wins over the real one."""
    with _lock:
        _loaded[kind] = profile
        _failed.pop(kind, None)
        if kind in _injected:
            _injected.remove(kind)
        _injected.append(kind)


def unregister_profile(kind: str) -> None:
    """Undo register_profile (a REGISTRY kind is re-imported on next use)."""
    with _lock:
        if kind in _injected:
            _injected.remove(kind)
            _loaded.pop(kind, None)


def reset_cache() -> None:
    """Forget loaded/failed profiles so the next lookup re-imports (tests)."""
    with _lock:
        for kind in list(_loaded):
            if kind not in _injected:
                del _loaded[kind]
        _failed.clear()
