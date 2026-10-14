"""The "exact" profile: no wildcards, the whole command line must match.

Plan 2.4.0 section 5.0.  An exact entry keeps the same key as today's 8 h
trust (``trust.make_signature``, JSON-normalised) and adds everything that
makes it safe to keep forever:

* argv0 must be a NATIVE executable (PE / ELF / Mach-O).  It is resolved to an
  absolute real path once, at approval (never through the cwd), hashed, its
  directory must not be user-writable, and it is executed by that absolute
  path and never resolved again (``_common.resolve_pinned_binary`` /
  ``verify_pinned_binary``).
* Shells, interpreters and the launcher denylist are refused (``match``
  returns ``None``: no checkbox is offered; same for git/docker/kubectl/helm and
  credential helpers, which need their own vetted profile), and so is any argv0 that
  resolves to ``.cmd`` / ``.bat`` / ``.ps1`` (``trust.persistent_or_8h_refusal``
  is the same predicate the 8 h trust applies).
* The child environment is built from scratch (``verdict.replace_env``): a
  few system variables, a PATH made of the approval-time protected
  directories, and nothing else; the caller adds the requested vault values.
* Windows: the ``*.dll`` files in the cwd are snapshotted.
* Every file named on the command line -- also inside an ``--opt=file``,
  ``@file``, ``-d@file`` or ``file,Entry`` token -- (and the conventional config
  files of well-known tools) is hashed; names that do not exist are recorded as
  ``"absent"`` so a file that appears later is drift.  A built-in table adds
  the config files / directories of ``gh aws az terraform curl`` as
  monitored paths, absent ones included.

Any drift disarms the entry; the human sees the dialog again.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import List, Optional

from .. import trust
from . import Request, Verdict
from . import _common
from ._common import ProfileRefusal

kind = "exact"

# Shells, interpreters and launchers that run arbitrary code named by their
# arguments (basename, ".exe" stripped, case-insensitive); "python*" too.
SHELLS_AND_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh", "py", "node", "perl",
    "ruby", "wsl",
})
LAUNCHER_DENYLIST = frozenset({
    "npm", "npx", "yarn", "pnpm", "bun", "deno", "pytest", "tox", "nox", "cargo", "make",
    "cmake", "ninja", "gradle", "gradlew", "mvn", "mvnw", "dotnet", "go", "uv", "poetry",
    "pipx", "pre-commit", "just", "task", "rake", "bundle", "composer", "java",
    # Windows proxy-execution binaries: they run code named inside one of their
    # arguments (``rundll32 x.dll,Entry``, ``msbuild proj``, ``forfiles /c ...``).
    "rundll32", "regsvr32", "wscript", "cscript", "mshta", "msiexec", "forfiles", "cmstp",
    "installutil", "msbuild",
})

# Tools that have (or need) a vetted profile of their own: as an exact entry
# they would skip every pin that profile applies (git hooksPath/fsmonitor and
# remote-URL checks, docker host/context, kubeconfig), so they only get the
# per-run dialog (and the ordinary 8 h trust).
PROFILED_TOOLS = frozenset({"git", "docker", "docker-compose", "kubectl", "helm"})
PROFILED_PREFIXES = ("git-credential", "docker-credential", "gh-credential")

WARNING_LINE = (
    "Exact entries pin the command line, not what the program does with the "
    "variables: its own config files, plugins and the files it reads can change "
    "its behaviour, and the agent can obtain these values."
)

_MAX_ARGS = 200
_MAX_TREE_FILES = 500
_MAX_LISTING = 2000


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def _base_name(program: str) -> str:
    name = re.split(r"[\\/]", program)[-1].strip().casefold()
    return name[:-4] if name.endswith(".exe") else name


def denied_program(program: str) -> Optional[str]:
    """Reason when *program* (a name or path) is a shell, interpreter or
    launcher; None otherwise."""
    base = _base_name(program)
    if base in SHELLS_AND_INTERPRETERS or base.startswith("python"):
        return f"{base!r} is a shell or interpreter and cannot be always-allowed"
    if base in PROFILED_TOOLS or base.startswith(PROFILED_PREFIXES):
        return (f"{base!r} needs a vetted profile and cannot be an exact always-allow "
                f"entry; it is approved per run")
    if base in LAUNCHER_DENYLIST:
        return f"{base!r} is a launcher that runs other programs and cannot be always-allowed"
    return None


def _program_refusal(command, cwd) -> Optional[str]:
    if not command or not isinstance(command[0], str):
        return "the command is empty"
    return denied_program(command[0]) or trust.persistent_or_8h_refusal(command, cwd)


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

def _signature(req: Request) -> list:
    # The variable names are NOT part of the shape: the entry carries its own
    # only_vars and the allowlist enforces request-vars <= entry-vars.
    sig = trust.make_signature(req.command, req.cwd, (), None, timeout=req.timeout)
    # JSON-normalised so it compares equal after a round trip through the vault.
    return json.loads(json.dumps(sig))


def match(req: Request) -> Optional[dict]:
    """Every command is a candidate (this profile is last in match order)
    except shells/interpreters/launchers and ``.cmd``/``.bat``/``.ps1``."""
    if not req.command or _program_refusal(req.command, req.cwd) is not None:
        return None
    return {"signature": _signature(req)}


def label(req: Request, candidate: dict) -> str:
    """Server-generated entry label (never agent text beyond the argv itself)."""
    text = "exact: " + " ".join(req.command)
    text = " ".join(text.split())                      # no newlines / runs of blanks
    return text if len(text) <= 100 else text[:97] + "..."


# ---------------------------------------------------------------------------
# Files named on the command line
# ---------------------------------------------------------------------------

def _token_files(arg: str) -> List[str]:
    """The arg itself plus the file names it may carry: the part after the first
    ``=`` (``--var-file=x``), after an ``@`` (``@x``, ``-d@x``), and each
    comma-separated piece (``x.dll,Entry``)."""
    out = [arg]
    for part in (arg.split("=", 1)[1] if "=" in arg else "",
                 arg.split("@", 1)[1] if "@" in arg else ""):
        if part:
            out.append(part)
    for piece in list(out):
        if "," in piece:
            out.extend(p for p in piece.split(",") if p)
    seen, uniq = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _scan_files(command, cwd: str, pin_path: str) -> dict:
    """``{path: sha256 | "absent"}`` for every argument (argv0 excluded) that is
    a file or does not exist, plus the conventional config files of the tool."""
    args = list(command[1:])
    if len(args) > _MAX_ARGS:
        raise ProfileRefusal("the command line has too many arguments")
    candidates = []
    for arg in args:
        if not isinstance(arg, str) or not arg or "\0" in arg:
            continue
        for name in _token_files(arg):
            candidates.append(Path(name) if os.path.isabs(name) else Path(cwd) / name)
    if len(candidates) > 4 * _MAX_ARGS:
        raise ProfileRefusal("the command line has too many file names")
    stem = _base_name(command[0])
    for name in trust._IMPLICIT_CONFIG_FILES.get(stem, ()):
        candidates.append(Path(cwd) / name)
    skip = os.path.normcase(pin_path)
    out: dict = {}
    for path in candidates:
        try:
            if not os.path.lexists(path):
                out[os.path.normpath(os.path.abspath(path))] = "absent"
                continue
            lexical = os.path.normpath(os.path.abspath(path))
            resolved = os.path.realpath(path)
            if os.path.normcase(resolved) != os.path.normcase(lexical):
                # A link (or a link in the parent chain): retargeting it is drift
                # even when the old target is unchanged.  Also covers dangling links.
                out[lexical] = _LINK_PREFIX + resolved
            if not path.is_file():
                continue                               # directories are not tracked
            real = os.path.realpath(path)
            if os.path.normcase(real) == skip:
                continue
            digest = _common.hash_file(real)
        except (OSError, ValueError):
            raise ProfileRefusal(f"cannot inspect {path}")
        if digest is None:
            raise ProfileRefusal(f"cannot hash {path}")
        out[real] = digest
    return out


_LINK_PREFIX = "link:"


def _files_drift(files) -> Optional[str]:
    if not isinstance(files, dict):
        return "the approved file record is malformed"
    for path, state in files.items():
        if not isinstance(path, str) or not isinstance(state, str):
            return "the approved file record is malformed"
        if state == "absent":
            if os.path.lexists(path):
                return f"a file the command may use appeared: {path}"
            continue
        if state.startswith(_LINK_PREFIX):
            if not os.path.lexists(path)                     or os.path.realpath(path) != state[len(_LINK_PREFIX):]:
                return f"a link the command references now points elsewhere: {path}"
            continue
        current = _common.hash_file(path)
        if current is None:
            return f"a file the command references is no longer readable: {path}"
        if current != state:
            return f"a file the command references changed: {path}"
    return None


# ---------------------------------------------------------------------------
# Monitored paths (built-in table by argv0 basename)
# ---------------------------------------------------------------------------

def _monitor_specs(stem: str, cwd: str) -> List[tuple]:
    """``(path, mode, skip)``; mode is "file", "tree" (content hashes) or
    "listing" (names and sizes).  Indicative, per plan 5.0."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA") if os.name == "nt" else None
    specs: List[tuple] = []
    if stem == "gh":
        override = os.environ.get("GH_CONFIG_DIR")
        if override and os.path.isabs(override):
            specs.append((override, "tree", ("state.yml",)))
        specs.append((os.path.join(home, ".config", "gh"), "tree", ("state.yml",)))
        if appdata:
            specs.append((os.path.join(appdata, "GitHub CLI"), "tree", ("state.yml",)))
    elif stem == "aws":
        specs += [(os.path.join(home, ".aws", "config"), "file", ()),
                  (os.path.join(home, ".aws", "credentials"), "file", ())]
    elif stem == "az":
        specs += [(os.path.join(home, ".azure", "config"), "file", ()),
                  (os.path.join(home, ".azure", "clouds.config"), "file", ())]
    elif stem == "terraform":
        specs += [(os.path.join(home, ".terraformrc"), "file", ()),
                  (os.path.join(home, ".terraform.d", "plugins"), "listing", ())]
        if appdata:
            specs += [(os.path.join(appdata, "terraform.rc"), "file", ()),
                      (os.path.join(appdata, "terraform.d", "plugins"), "listing", ())]
        else:
            specs.append((os.path.join(home, "terraform.rc"), "file", ()))
    elif stem == "curl":
        for base in (home, appdata, cwd):
            if base:
                for name in (".curlrc", "_curlrc"):
                    specs.append((os.path.join(base, name), "file", ()))
        specs += [(os.path.join(home, ".netrc"), "file", ()),
                  (os.path.join(home, "_netrc"), "file", ())]
    seen, out = set(), []
    for path, mode, skip in specs:
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            out.append((os.path.abspath(path), mode, tuple(skip)))
    return out


def _listing(root: str):
    out: dict = {}
    for here, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(names) + list(dirs):
            full = os.path.join(here, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if len(out) >= _MAX_LISTING:
                return None
            if _common.is_reparse_point(full):
                out[rel] = "link"
            elif os.path.isdir(full):
                out[rel + "/"] = "dir"
            else:
                out[rel] = os.path.getsize(full)
    return out


def _observe(path: str, mode: str, skip) -> object:
    """JSON-able state of a monitored path: "absent", a hash, a dict, or None
    when it cannot be observed."""
    try:
        if not os.path.lexists(path):
            return "absent"
        if mode == "file":
            return _common.hash_file(path)
        if mode == "tree":
            tree = _common.hash_tree(path, max_files=_MAX_TREE_FILES)
            return {k: v for k, v in tree.items() if k.rstrip("/") not in skip}
        if mode == "listing":
            return _listing(path) if os.path.isdir(path) else None
    except (ProfileRefusal, OSError, ValueError):
        return None
    return None


def _monitored_snapshot(stem: str, cwd: str) -> list:
    out = []
    for path, mode, skip in _monitor_specs(stem, cwd):
        state = _observe(path, mode, skip)
        if state is None:
            raise ProfileRefusal(f"cannot inspect the monitored path {path}")
        out.append({"path": path, "mode": mode, "skip": list(skip), "state": state})
    return out


def _monitored_drift(records) -> Optional[str]:
    if not isinstance(records, list):
        return "the approved monitored-path record is malformed"
    for rec in records:
        if not isinstance(rec, dict) or not isinstance(rec.get("path"), str) \
                or rec.get("mode") not in ("file", "tree", "listing") \
                or not isinstance(rec.get("skip", []), list):
            return "the approved monitored-path record is malformed"
        now = _observe(rec["path"], rec["mode"], tuple(rec.get("skip", [])))
        if now != rec.get("state"):
            return f"a monitored path changed (or appeared/disappeared): {rec['path']}"
    return None


# ---------------------------------------------------------------------------
# Profile protocol
# ---------------------------------------------------------------------------

def snapshot(req: Request, candidate: dict) -> dict:
    """Pin the program and record every drift input.  Raises ``ProfileRefusal``
    (so no offer is made) when the program is not a protected native
    executable or something cannot be inspected."""
    refusal = _program_refusal(req.command, req.cwd)
    if refusal:
        raise ProfileRefusal(refusal)
    pin = _common.resolve_pinned_binary(req.command[0])
    real_refusal = denied_program(pin.path) or trust.persistent_or_8h_refusal([pin.path], req.cwd)
    if real_refusal:
        raise ProfileRefusal(real_refusal)
    return {
        "pin": pin.to_dict(),
        "path_dirs": _common.pinned_path_dirs(None, [os.path.dirname(pin.path)]),
        "cwd_dlls": _common.snapshot_cwd_dlls(req.cwd),
        "files": _scan_files(req.command, req.cwd, pin.path),
        "monitored": _monitored_snapshot(_base_name(req.command[0]), req.cwd),
    }


def describe(req: Request, candidate: dict) -> str:
    pattern = " ".join(repr(part) for part in req.command)
    lines = [f"Exact command: {pattern}"]
    try:
        pin = _common.resolve_pinned_binary(req.command[0])
        lines.append(f"Program: {pin.path} (sha256 {pin.sha256[:16]}...), pinned and never "
                     f"searched for again")
    except ProfileRefusal:
        pass
    try:
        paths = [p for p, _m, _s in _monitor_specs(_base_name(req.command[0]), req.cwd)]
    except Exception:
        paths = []
    if paths:
        shown = ", ".join(paths[:4]) + (", ..." if len(paths) > 4 else "")
        lines.append(f"Monitored (a change disarms the entry): {shown}")
    lines.append(WARNING_LINE)
    return "\n".join(lines)


def _drift(snap, command, cwd: str) -> Optional[str]:
    """Everything except the signature and the variable names."""
    if not isinstance(snap, dict):
        return "the approved snapshot is malformed"
    refusal = _program_refusal(command, cwd)
    if refusal:
        return refusal
    try:
        pin = _common.PinnedBinary.from_dict(snap.get("pin"))
    except ProfileRefusal as exc:
        return exc.reason
    dirs = snap.get("path_dirs")
    if not isinstance(dirs, list) or not all(isinstance(d, str) for d in dirs):
        return "the approved PATH record is malformed"
    return (_common.verify_pinned_binary(pin)
            or _files_drift(snap.get("files"))
            or _common.verify_cwd_dlls(cwd, snap.get("cwd_dlls"))
            or _monitored_drift(snap.get("monitored")))


def check_snapshot(entry: dict):
    try:
        command = tuple(entry["shape"]["signature"][0])
        cwd = entry["cwd"]
        if not all(isinstance(part, str) for part in command) or not isinstance(cwd, str):
            raise TypeError
    except (KeyError, IndexError, TypeError):
        return False, "the approved command record is malformed"
    reason = _drift(entry.get("snapshot"), command, cwd)
    return (reason is None), reason


def verify(entry: dict, req: Request) -> Verdict:
    shape = entry.get("shape")
    if not isinstance(shape, dict) or shape != {"signature": _signature(req)}:
        return Verdict(ok=False, reason=None)          # not this entry's command
    snap = entry.get("snapshot")
    reason = _drift(snap, req.command, req.cwd) or _common.injected_name_problem(req.only_vars)
    if reason is not None:
        return Verdict(ok=False, reason=reason)
    pin = _common.PinnedBinary.from_dict(snap["pin"])
    try:
        env = _common.build_env(snap["path_dirs"])
    except ProfileRefusal as exc:
        return Verdict(ok=False, reason=exc.reason)
    return Verdict(ok=True, argv=[pin.path] + list(req.command[1:]), env=env, replace_env=True)
