"""The "git" always-allow profile: push / pull / fetch / ls-remote (plan 2.4.0
section 5.1; decisions 7.1 and 7.2).

What an entry means
-------------------
``shape`` = ``{sub, flags, remote, branch_glob}``: the subcommand, the set of
allowlisted flags used (without values), the configured remote name and a
glob the branch slots must match (default ``*``).  The branch names themselves
are the wildcard.  Everything else is clamped by the server:

* the final argv is *rebuilt* (``<pinned git> <sub> <flags> -- <remote> ...``;
  push refspecs rewritten to ``refs/heads/N:refs/heads/N``, ``--atomic`` always,
  pull gets ``--ff-only --no-rebase --no-edit --no-recurse-submodules``);
* the env is built from scratch (``_common.build_env``) and carries the
  ``GIT_CONFIG_COUNT`` command-scope pins (they beat local and global config,
  validate-git C1), including the credential-helper reset followed by the
  approval-time effective helper list (C2) and ``core.hooksPath`` pinned to
  the approved hooks directory (hooks run normally; that tree is hashed);
* the remote URL is *checked*, not pinned (C3): ``git remote get-url
  [--push] --all`` run with the same pins/env must print exactly one line,
  equal to the approved URL.

Snapshot / drift
----------------
``snapshot`` records the pinned git binary (+ version, floor-checked), the
approved URL, the hooks tree digest, the effective credential helpers (hashed),
a digest of the system/global configuration (``git config --list
--show-origin --show-scope -z``, parsed by ``parse_git_config_z``), the hashes
of every non-local config file that was read, ``.gitattributes`` /
``.git/info/attributes`` / ``.gitmodules`` / ``.lfsconfig``, the remote's fetch
refspecs and the Windows cwd DLLs.  Local/worktree config may only contain the
benign allowlist (``_local_key_ok``), ``.git`` must be a real directory and
``core.worktree`` must not exist.  ``check_snapshot`` (arm time) and ``verify``
(right before spawn) run the very same ``_check_state``.

``check_snapshot`` runs under the vault lock: only local file reads and a few
short ``git`` probes (``_common.run_probe``, no secrets in their env).

Not covered (plan section 6): ``.git/config`` edited between the URL check and
the spawn, hook bodies (hashed, but the code they run is the agent's own).
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from collections import namedtuple
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from . import Request, Verdict
from . import _common as c

kind = "git"

SUBCOMMANDS = ("push", "pull", "fetch", "ls-remote")

_REMOTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,200}")
_GLOB_RE = re.compile(r"[A-Za-z0-9_./*-]{1,201}")
_MAX_PUSH_BRANCHES = 16
MAX_NESTED_ATTRIBUTES = 256

# Test-only seam, same status as ``_common.RELAXATIONS``: merged into every
# git env (tests put GIT_CONFIG_NOSYSTEM=1 here).  Changed only by test
# monkeypatching; empty in production (a test asserts it).
_TEST_EXTRA_ENV: Dict[str, str] = {}

PROBE_TIMEOUT = 20.0

# ---------------------------------------------------------------------------
# Warnings shown to the human (plan 7.1, 7.2 and the truth-in-labelling rule)
# ---------------------------------------------------------------------------

HOOK_WARNING = (
    "WARNING: the injected variables are meant for pre-push hooks that run your tests. "
    "Hooks run normally, and a hook that runs the test suite executes repository code the "
    "agent can edit: the agent can obtain these values. The hooks directory is "
    "fingerprinted, the code it runs is not. Approve only the variables the tests genuinely "
    "need and use test-grade credentials."
)


# ---------------------------------------------------------------------------
# Argv grammar
# ---------------------------------------------------------------------------

_SPECS = {
    "push": (
        c.FlagSpec(long="--set-upstream", short="-u"),
        c.FlagSpec(long="--dry-run"),
        c.FlagSpec(long="--atomic"),
        c.FlagSpec(long="--porcelain"),
    ),
    "fetch": (
        c.FlagSpec(long="--no-tags"),
        c.FlagSpec(long="--tags"),
        c.FlagSpec(long="--depth", value=True, pattern=r"[1-9][0-9]{0,5}"),
    ),
    "pull": (),
    "ls-remote": (
        c.FlagSpec(long="--heads"),
        c.FlagSpec(long="--tags"),
        c.FlagSpec(long="--refs"),
    ),
}


def remote_problem(name) -> Optional[str]:
    """Why *name* is not an acceptable remote slot value, or None.  Strictly
    narrower than git's own rules (validate-git C8)."""
    if not isinstance(name, str) or not _REMOTE_RE.fullmatch(name):
        return "the remote name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
    if ".." in name or ".lock" in name or name.endswith("."):
        return "the remote name contains '..', '.lock' or a trailing '.'"
    return None


def branch_problem(name) -> Optional[str]:
    """Why *name* is not an acceptable branch slot value, or None."""
    if not isinstance(name, str) or not _BRANCH_RE.fullmatch(name):
        return "the branch name must match [A-Za-z0-9][A-Za-z0-9_./-]{0,200}"
    if (".." in name or "//" in name or "/." in name or "@{" in name
            or name.endswith("/") or name.endswith(".")):
        return "the branch name contains '..', '//', '/.', '@{' or a trailing '/' or '.'"
    if any(part.endswith(".lock") for part in name.split("/")):
        return "a branch name component ends with '.lock'"
    if name in ("HEAD", "@"):
        return "HEAD is not a branch name"
    return None


@dataclass(frozen=True)
class _Parsed:
    sub: str
    flag_keys: Tuple[str, ...]      # shape flags (declaration order, no --atomic)
    flag_tokens: Tuple[str, ...]    # canonical tokens for the final argv
    remote: str
    branches: Tuple[str, ...]


def _parse(command) -> _Parsed:
    """Parse *command* (full argv incl. ``git``) or raise ``ArgvRejected``."""
    command = tuple(command)
    if len(command) < 2:
        raise c.ArgvRejected("not a git subcommand")
    prog = command[0]
    if not isinstance(prog, str) or prog.lower() not in ("git", "git.exe"):
        raise c.ArgvRejected("the program is not a bare 'git'")
    sub = command[1]
    if sub not in SUBCOMMANDS:
        raise c.ArgvRejected(f"git {sub!r} is not a profile subcommand")
    specs = _SPECS[sub]
    max_pos = {"push": 1 + _MAX_PUSH_BRANCHES, "pull": 2, "fetch": 1, "ls-remote": 1}[sub]
    parsed = c.tokenize_argv(command[2:], specs, max_positionals=max_pos, min_positionals=1)
    if sub == "push" and len(parsed.positionals) < 2:
        raise c.ArgvRejected("git push needs a remote and at least one branch")
    if sub == "fetch" and parsed.has("--tags") and parsed.has("--no-tags"):
        raise c.ArgvRejected("--tags and --no-tags together")
    remote = parsed.positionals[0]
    problem = remote_problem(remote)
    if problem:
        raise c.ArgvRejected(problem)
    branches = tuple(parsed.positionals[1:])
    for branch in branches:
        problem = branch_problem(branch)
        if problem:
            raise c.ArgvRejected(problem)
    if len(set(branches)) != len(branches):
        raise c.ArgvRejected("a branch is listed twice")
    keys = tuple(spec.key for spec in specs
                 if spec.key in parsed.flags and spec.key != "--atomic")
    return _Parsed(sub=sub, flag_keys=keys,
                   flag_tokens=tuple(parsed.canonical_flag_tokens()),
                   remote=remote, branches=branches)


def _shape_of(p: _Parsed, glob: str = "*") -> dict:
    return {"sub": p.sub, "flags": list(p.flag_keys), "remote": p.remote,
            "branch_glob": glob}


def _glob_ok(glob) -> bool:
    return isinstance(glob, str) and bool(_GLOB_RE.fullmatch(glob))


# ---------------------------------------------------------------------------
# `git config --list --show-origin --show-scope -z` (validate-git C10)
# ---------------------------------------------------------------------------

ConfigRecord = namedtuple("ConfigRecord", "scope origin key value")


def parse_git_config_z(data: bytes) -> List[ConfigRecord]:
    """Parse the output of ``git config --list --show-origin --show-scope -z``.

    Record = ``SCOPE NUL ORIGIN NUL KEY ["\\n" VALUE] NUL``.  The value starts
    after the FIRST newline; a record without a newline is a valueless key
    (``value is None``), ``key\\n`` + NUL is the empty string -- the two stay
    distinct.  Raises ``ProfileRefusal`` on a malformed stream."""
    if not data:
        return []
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 3:
        raise c.ProfileRefusal("the git configuration listing is malformed")
    out: List[ConfigRecord] = []
    for i in range(0, len(fields), 3):
        scope = fields[i].decode("utf-8", "replace")
        origin = fields[i + 1].decode("utf-8", "replace")
        entry = fields[i + 2].decode("utf-8", "replace")
        key, nl, value = entry.partition("\n")
        out.append(ConfigRecord(scope, origin, key, value if nl else None))
    return out


def last_values(records) -> Dict[str, Optional[str]]:
    """Effective value per key: the last record wins (command scope is last)."""
    out: Dict[str, Optional[str]] = {}
    for rec in records:
        out[rec.key] = rec.value
    return out


def _split_key(key: str):
    """``(section, subsection|None, variable)``; section and variable are
    already lower-case in git's output."""
    first = key.find(".")
    last = key.rfind(".")
    if first < 0:
        return key, None, ""
    if first == last:
        return key[:first].lower(), None, key[first + 1:].lower()
    return key[:first].lower(), key[first + 1:last], key[last + 1:].lower()


_LOCAL_CORE_KEYS = frozenset({"repositoryformatversion", "filemode", "bare",
                              "logallrefupdates", "symlinks", "ignorecase", "autocrlf"})


def _local_key_ok(key: str) -> bool:
    """The benign allowlist for local/worktree scope (plan 5.1)."""
    section, sub, var = _split_key(key)
    if not var:
        return False
    if section == "core":
        return sub is None and var in _LOCAL_CORE_KEYS
    if section == "remote":
        return sub is not None and var in ("url", "fetch")
    if section == "branch":
        return sub is not None and var in ("remote", "merge")
    if section == "user":
        return sub is None
    if section == "extensions":
        return sub is None
    return False


def _is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")


def normalise_url(url) -> Optional[str]:
    """The exact normalised form of an acceptable remote URL, or None.

    Strict: ``https://host[/path]`` with no userinfo, port, query, fragment or
    ``%``.  ``RELAXATIONS.skip_https_only_check`` (tests only) additionally
    accepts any printable string (a local bare repository path) verbatim."""
    if not isinstance(url, str) or not url or len(url) > 2048 or c.has_unsafe_text(url) \
            or url != url.strip():
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        parts = None
        host = port = None
    if (parts is not None and parts.scheme == "https" and host and port is None
            and "@" not in parts.netloc and ":" not in parts.netloc
            and not parts.query and not parts.fragment and "%" not in url
            and " " not in url and "\\" not in url and _HOST_RE.fullmatch(host)):
        return f"https://{host.lower()}{parts.path}"
    if c.RELAXATIONS.skip_https_only_check:
        return url
    return None


def _url_matches_pattern(pattern: str, url: str) -> bool:
    """Does the ``credential.<pattern>.helper`` section apply to *url*?  An
    over-match is the safe direction (the helper is just pinned and hashed
    too); anything that does not parse as a URL pattern does not match."""
    try:
        pat, tgt = urlsplit(pattern), urlsplit(url)
        if not pat.scheme or not pat.netloc:
            return False
        if pat.scheme != tgt.scheme:
            return False
        if pat.hostname and "*" not in pat.hostname and pat.hostname != (tgt.hostname or ""):
            return False
        if pat.port and pat.port != (tgt.port or 443):
            return False
        ppath = pat.path.rstrip("/")
        if ppath and not (tgt.path == ppath or tgt.path.startswith(ppath + "/")):
            return False
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Pins and env
# ---------------------------------------------------------------------------

def _posix(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def _escape_helper_path(path: str) -> str:
    """A helper that is an absolute path is run through the shell as-is, so
    spaces and shell characters in the path are backslash-escaped."""
    return re.sub(r"([^A-Za-z0-9_./:@%+=,-])", r"\\\1", _posix(path))


def pin_pairs(hooks_dir: str, helpers=()) -> List[Tuple[str, str]]:
    """The command-scope ``GIT_CONFIG_COUNT`` pins, in order (plan 5.1).
    *helpers* are already-normalised pin strings (``resolve_helpers``)."""
    pairs = [("credential.helper", "")]
    pairs += [("credential.helper", h) for h in helpers]
    pairs += [
        ("core.fsmonitor", "false"),
        ("core.sshCommand", ""),
        ("core.pager", "cat"),
        ("core.editor", "true"),
        ("core.askPass", ""),
        ("core.hooksPath", _posix(hooks_dir)),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("http.proxy", ""),
        ("http.extraHeader", ""),
        ("submodule.recurse", "false"),
        ("push.recurseSubmodules", "no"),
        ("fetch.recurseSubmodules", "no"),
        ("push.pushOption", ""),
        ("pull.rebase", "false"),
        ("push.gpgSign", "false"),
        ("transfer.credentialsInUrl", "die"),
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
    ]
    return pairs


def command_env(path_dirs, pairs=None, *, injected=None) -> Dict[str, str]:
    """The complete child env: system essentials, the pinned PATH, *injected*
    vault values (checked against the tool-control denylist) and git's own
    pins.  Nothing else from the server's environment is passed (``GIT_DIR``,
    ``GIT_*``, ``*_proxy``, editors, askpass, ``XDG_CONFIG_HOME``, ``GCM_*`` ...)."""
    extra = {
        "GIT_ALLOW_PROTOCOL": c.RELAXATIONS.git_allowed_protocols,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
    }
    extra.update(_TEST_EXTRA_ENV)
    if pairs:
        extra["GIT_CONFIG_COUNT"] = str(len(pairs))
        for i, (key, value) in enumerate(pairs):
            extra[f"GIT_CONFIG_KEY_{i}"] = key
            extra[f"GIT_CONFIG_VALUE_{i}"] = value
    return c.build_env(list(path_dirs), injected=injected, extra=extra)


def build_argv(git_path: str, p: _Parsed) -> List[str]:
    """The final argv for a parsed request (server-emitted ``--`` and rewrites)."""
    argv = [git_path, p.sub]
    if p.sub == "push":
        argv += list(p.flag_tokens)
        if "--atomic" not in argv:
            argv.append("--atomic")
        argv += ["--", p.remote]
        argv += [f"refs/heads/{b}:refs/heads/{b}" for b in p.branches]
    elif p.sub == "pull":
        argv += ["--ff-only", "--no-rebase", "--no-edit", "--no-recurse-submodules",
                 "--", p.remote]
        argv += list(p.branches)
    else:
        argv += list(p.flag_tokens) + ["--", p.remote]
    return argv


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

@dataclass
class _Ctx:
    cwd: str
    pin: c.PinnedBinary
    path_dirs: List[str]
    pairs: Optional[List[Tuple[str, str]]] = None


def _probe(ctx: _Ctx, args):
    env = command_env(ctx.path_dirs, ctx.pairs)
    return c.run_probe([ctx.pin.path, "-C", ctx.cwd] + list(args), env,
                       timeout=PROBE_TIMEOUT, expect_sha256=ctx.pin.sha256)


def _git_version_text(pin: c.PinnedBinary, path_dirs) -> str:
    res = c.run_probe([pin.path, "--version"], command_env(path_dirs),
                      timeout=PROBE_TIMEOUT, expect_sha256=pin.sha256)
    if not res.ok:
        raise c.ProfileRefusal("cannot determine the git version")
    return res.stdout_text().strip()


def _read_config(ctx: _Ctx) -> List[ConfigRecord]:
    res = _probe(ctx, ["config", "--list", "--show-origin", "--show-scope", "-z"])
    if not res.ok:
        raise c.ProfileRefusal("cannot read the git configuration (" + res.failure_reason() + ")")
    return parse_git_config_z(res.stdout)


def _remote_url(ctx: _Ctx, remote: str, push: bool) -> str:
    """The single configured URL of *remote* (``get-url [--push] --all``);
    raises ``ProfileRefusal`` unless it prints exactly one line."""
    args = ["remote", "get-url"] + (["--push"] if push else []) + ["--all", "--", remote]
    res = _probe(ctx, args)
    if not res.ok:
        raise c.ProfileRefusal(f"{remote!r} is not a configured remote, or its URL "
                               "cannot be read (" + res.failure_reason() + ")")
    lines = res.stdout_text().replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 1:
        raise c.ProfileRefusal(
            f"the remote {remote!r} has {len(lines)} {'push ' if push else ''}URLs; "
            "exactly one is required")
    return lines[0]


# ---------------------------------------------------------------------------
# Facts gathered from the repository
# ---------------------------------------------------------------------------

def _digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def _resolve_origin(origin: str, scope: str, cwd: str) -> Optional[str]:
    if not origin.startswith("file:"):
        return None
    path = origin[len("file:"):]
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    return os.path.normpath(path)


def _hooks_dir_from(values: Dict[str, Optional[str]], cwd: str) -> str:
    raw = values.get("core.hookspath")
    if raw is None:
        return _posix(os.path.join(cwd, ".git", "hooks"))
    if c.has_unsafe_text(raw) or not raw:
        raise c.ProfileRefusal("core.hooksPath has an unusable value")
    if raw.startswith("~/"):
        raw = os.path.join(os.path.expanduser("~"), raw[2:])
    if _is_unc(raw):
        raise c.ProfileRefusal("core.hooksPath is a network path")
    if not os.path.isabs(raw):
        raise c.ProfileRefusal("core.hooksPath is a relative path")
    return _posix(raw)


def _file_hash_or_none(path: str) -> Optional[str]:
    if not os.path.lexists(path):
        return None
    if c.is_reparse_point(path):
        raise c.ProfileRefusal(f"{os.path.basename(path)} is a link/reparse point")
    digest = c.hash_file(path)
    if digest is None:
        raise c.ProfileRefusal(f"cannot hash {os.path.basename(path)}")
    return digest


def _nested_attributes(ctx: _Ctx) -> Dict[str, Optional[str]]:
    """``{relative path: sha256 | None}`` of every ``.gitattributes`` below the
    worktree top level.  One ``git ls-files`` probe lists tracked files and
    untracked ones (ignored included: git reads them all; case-insensitive,
    as on Windows).  Refuses (``ProfileRefusal``) when the probe fails, times
    out, or finds more than ``MAX_NESTED_ATTRIBUTES`` files."""
    res = _probe(ctx, ["ls-files", "-z", "--cached", "--others", "--",
                       ":(glob,icase)**/.gitattributes"])
    if not res.ok:
        raise c.ProfileRefusal("cannot list the nested .gitattributes files ("
                               + res.failure_reason() + ")")
    try:
        names = sorted({n.decode("utf-8") for n in res.stdout.split(b"\0") if n})
    except UnicodeDecodeError:
        raise c.ProfileRefusal("a .gitattributes path is not valid UTF-8")
    names = [n for n in names if n != ".gitattributes"]
    if len(names) > MAX_NESTED_ATTRIBUTES:
        raise c.ProfileRefusal(f"more than {MAX_NESTED_ATTRIBUTES} nested .gitattributes files")
    out: Dict[str, Optional[str]] = {}
    for rel in names:
        parts = rel.split("/")
        if rel.startswith("/") or "\\" in rel or ".." in parts or ".git" in parts \
                or os.path.isabs(rel):
            raise c.ProfileRefusal("a nested .gitattributes path is not acceptable")
        out[rel] = _file_hash_or_none(os.path.join(ctx.cwd, *parts))
    return out


def _pinned_key_set(pairs) -> set:
    return {k.lower() for k, _v in (pairs or ())}


def _gather(ctx: _Ctx, remote: str):
    """Read the repository facts.  Returns ``(facts, records)``; raises
    ``ProfileRefusal`` for anything that makes the repository ineligible."""
    cwd = ctx.cwd
    git_dir = os.path.join(cwd, ".git")
    if c.is_reparse_point(git_dir) or not os.path.isdir(git_dir):
        raise c.ProfileRefusal(".git is not a plain directory (gitdir files, worktrees and "
                               "links are not supported); run from the repository top level")
    records = [r for r in _read_config(ctx)]
    real = [r for r in records if r.scope != "command"]
    for rec in real:
        if rec.scope in ("local", "worktree") and not _local_key_ok(rec.key):
            raise c.ProfileRefusal(f"the repository config sets {rec.key}, which is not on "
                                   "the benign allowlist")
        if rec.key == "core.worktree":
            raise c.ProfileRefusal("core.worktree is set")
        if rec.key == "include.path" or (rec.key.startswith("includeif.")
                                         and rec.key.endswith(".path")):
            if rec.value and _is_unc(rec.value):
                raise c.ProfileRefusal("a config include points at a network path")
        if _is_unc(rec.origin[len("file:"):] if rec.origin.startswith("file:") else ""):
            raise c.ProfileRefusal("a config file lives on a network path")
    if not any(r.key == f"remote.{remote}.url" for r in real):
        raise c.ProfileRefusal(f"{remote!r} is not a configured remote")
    values = last_values(real)
    hooks_dir = _hooks_dir_from(values, cwd)
    if os.path.lexists(hooks_dir):
        tree = c.hash_tree(hooks_dir)
        hooks_tree: Optional[str] = _digest(tree)
    else:
        hooks_tree = None
    skip = _pinned_key_set(ctx.pairs) | set(_pinned_key_set(pin_pairs(".")))
    digest_rows = []
    origin_files: Dict[str, Optional[str]] = {}
    for rec in real:
        if rec.scope in ("system", "global"):
            section, _sub, var = _split_key(rec.key)
            if rec.key.lower() in skip or (section == "credential" and var == "helper"):
                continue
            digest_rows.append([rec.scope, rec.key, rec.value])
        path = _resolve_origin(rec.origin, rec.scope, cwd)
        if path:
            norm = path.replace("\\", "/")
            if not norm.startswith(_posix(git_dir) + "/"):
                origin_files[norm] = _file_hash_or_none(path)
    files = {}
    for name in (".gitattributes", ".gitmodules", ".lfsconfig"):
        files[name] = _file_hash_or_none(os.path.join(cwd, name))
    files[".git/info/attributes"] = _file_hash_or_none(
        os.path.join(git_dir, "info", "attributes"))
    nested = _nested_attributes(ctx)
    facts = {
        "hooks_dir": hooks_dir,
        "hooks_tree": hooks_tree,
        "config_digest": _digest(digest_rows),
        "origin_files": origin_files,
        "files": files,
        "nested_attributes": nested,
        "remote_fetch": [r.value for r in real if r.key == f"remote.{remote}.fetch"],
        "dlls": c.snapshot_cwd_dlls(cwd),
    }
    return facts, records


def effective_helpers(records, url: str) -> List[str]:
    """The ordered credential helpers git would consult for *url*: every
    ``credential.helper`` and matching ``credential.<url>.helper`` in config
    order, an empty value resets the list (validate-git C2)."""
    out: List[str] = []
    for rec in records:
        if rec.scope == "command":
            continue
        section, sub, var = _split_key(rec.key)
        if section != "credential" or var != "helper":
            continue
        if sub is not None and not _url_matches_pattern(sub, url):
            continue
        if rec.value is None:
            continue
        if rec.value == "":
            out.clear()
        else:
            out.append(rec.value)
    return out


_BARE_HELPER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def resolve_helpers(raw_helpers, git_pin: c.PinnedBinary, path_dirs) -> List[dict]:
    """Normalise each effective helper to an absolute program, hashed.  Returns
    ``[{"value", "pin", "binary": PinnedBinary dict}]``.  ``!shell`` helpers,
    helpers with arguments and unresolvable helpers raise ``ProfileRefusal``."""
    out = []
    exec_dir = None
    for value in raw_helpers:
        if c.has_unsafe_text(value):
            raise c.ProfileRefusal("a credential helper has unprintable characters")
        if value.startswith("!"):
            raise c.ProfileRefusal("a '!' shell credential helper is not supported")
        try:
            if _BARE_HELPER_RE.fullmatch(value):
                if exec_dir is None:
                    res = c.run_probe([git_pin.path, "--exec-path"], command_env(path_dirs),
                                      timeout=PROBE_TIMEOUT, expect_sha256=git_pin.sha256)
                    exec_dir = res.stdout_text().strip() if res.ok else ""
                dirs = ([exec_dir] if exec_dir else []) + list(path_dirs)
                binary = c.resolve_pinned_binary("git-credential-" + value,
                                                 search_path=os.pathsep.join(dirs))
            elif os.path.isabs(value) and os.path.isfile(value):
                binary = c.resolve_pinned_binary(value)
            else:
                raise c.ProfileRefusal(
                    f"the credential helper {value!r} is not a bare name or a plain "
                    "absolute program path")
        except c.BinaryRefused as exc:
            raise c.ProfileRefusal(f"credential helper {value!r}: {exc.reason}")
        out.append({"value": value, "pin": _escape_helper_path(binary.path),
                    "binary": binary.to_dict()})
    return out


# ---------------------------------------------------------------------------
# Snapshot / check
# ---------------------------------------------------------------------------

_summaries: Dict[tuple, dict] = {}


def _remember_summary(cwd: str, shape: dict, summary: dict) -> None:
    if len(_summaries) > 16:
        _summaries.pop(next(iter(_summaries)))
    _summaries[(cwd, json.dumps(shape, sort_keys=True))] = summary


def match(req: Request) -> Optional[dict]:
    """The candidate shape, or None when this is not a clamped git command."""
    try:
        return _shape_of(_parse(req.command))
    except c.ArgvRejected:
        return None


def label(req: Request, candidate: dict) -> str:
    text = f"git {candidate['sub']} {candidate['remote']}"
    return text if len(text) <= 100 else text[:97] + "..."


def snapshot(req: Request, candidate: dict) -> dict:
    """Approval-time snapshot.  Raises ``ProfileRefusal`` (no offer) when the
    repository, binary or configuration cannot be made always-allow safe."""
    parsed = _parse(req.command)
    if _shape_of(parsed) != candidate:
        raise c.ProfileRefusal("the request no longer matches the candidate")
    problem = c.injected_name_problem(req.only_vars)
    if problem:
        raise c.ProfileRefusal(problem)
    cwd = req.cwd
    pin = c.resolve_pinned_binary("git")
    path_dirs = c.pinned_path_dirs(extra=[os.path.dirname(pin.path)])
    version_text = _git_version_text(pin, path_dirs)
    problem = c.version_problem("git", version_text)
    if problem:
        raise c.ProfileRefusal(problem)
    ctx = _Ctx(cwd, pin, path_dirs)
    facts, records = _gather(ctx, parsed.remote)
    # First pass pins (no helpers yet) only so the URL probes use command scope.
    ctx.pairs = pin_pairs(facts["hooks_dir"])
    push = parsed.sub == "push"
    url = normalise_url(_remote_url(ctx, parsed.remote, push))
    if url is None:
        raise c.ProfileRefusal("the remote URL is not an acceptable https URL "
                               "(no userinfo, port, query or '%')")
    helpers = resolve_helpers(effective_helpers(records, url), pin, path_dirs)
    ctx.pairs = pin_pairs(facts["hooks_dir"], [h["pin"] for h in helpers])
    if normalise_url(_remote_url(ctx, parsed.remote, push)) != url:
        raise c.ProfileRefusal("the remote URL changed while it was being checked")
    snap = dict(facts)
    snap.update({
        "version": 1,
        "git": pin.to_dict(),
        "git_version": version_text,
        "path_dirs": list(path_dirs),
        "url": url,
        "url_push": push,
        "helpers": helpers,
    })
    _remember_summary(cwd, candidate, {
        "git": pin.path, "version": version_text, "url": url, "push": push,
        "hooks_dir": facts["hooks_dir"], "hooks_present": facts["hooks_tree"] is not None,
        "helpers": [h["value"] for h in helpers],
    })
    return snap


def _snap_problem(snap) -> Optional[str]:
    if not isinstance(snap, dict) or snap.get("version") != 1:
        return "the approved git snapshot is malformed"
    for key, typ in (("git", dict), ("git_version", str), ("path_dirs", list), ("url", str),
                     ("helpers", list), ("hooks_dir", str), ("origin_files", dict),
                     ("files", dict), ("nested_attributes", dict),
                     ("remote_fetch", list), ("dlls", dict),
                     ("config_digest", str)):
        if not isinstance(snap.get(key), typ):
            return "the approved git snapshot is malformed"
    return None


def _check_state(entry: dict) -> Optional[str]:
    """Drift/refusal reason for an entry's approved state, or None.  Shared by
    ``check_snapshot`` (arm time) and ``verify`` (right before spawn)."""
    snap, shape, cwd = entry.get("snapshot"), entry.get("shape"), entry.get("cwd")
    problem = _snap_problem(snap)
    if problem:
        return problem
    if not isinstance(shape, dict) or shape.get("sub") not in SUBCOMMANDS \
            or remote_problem(shape.get("remote")) or not _glob_ok(shape.get("branch_glob")):
        return "the approved git pattern is malformed"
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        return "the approved working directory is gone"
    try:
        pin = c.PinnedBinary.from_dict(snap["git"])
        reason = c.verify_pinned_binary(pin)
        if reason:
            return reason
        reason = c.version_problem("git", snap["git_version"])
        if reason:
            return reason
        reason = c.verify_cwd_dlls(cwd, snap["dlls"])
        if reason:
            return reason
        helpers = snap["helpers"]
        for h in helpers:
            if not isinstance(h, dict) or not isinstance(h.get("pin"), str) \
                    or not isinstance(h.get("value"), str):
                return "the approved credential helper record is malformed"
            reason = c.verify_pinned_binary(h.get("binary"))
            if reason:
                return "credential helper: " + reason
        ctx = _Ctx(cwd, pin, list(snap["path_dirs"]),
                   pin_pairs(snap["hooks_dir"], [h["pin"] for h in helpers]))
        facts, records = _gather(ctx, shape["remote"])
        labels = {"hooks_dir": "the hooks directory setting", "hooks_tree": "the hooks",
                  "config_digest": "the git configuration",
                  "origin_files": "a git configuration file",
                  "files": "a git attributes/modules file",
                  "nested_attributes": "a nested .gitattributes file",
                  "remote_fetch": "the remote's fetch refspecs", "dlls": "the DLLs"}
        for key, what in labels.items():
            if facts[key] != snap.get(key):
                return f"{what} changed since it was approved"
        if [h["value"] for h in helpers] != effective_helpers(records, snap["url"]):
            return "the credential helpers changed since they were approved"
        push = shape["sub"] == "push"
        if bool(snap.get("url_push")) != push:
            return "the approved snapshot belongs to a different subcommand"
        now = normalise_url(_remote_url(ctx, shape["remote"], push))
        if now != snap["url"]:
            return "the remote URL changed since it was approved"
    except c.ProfileRefusal as exc:
        return exc.reason
    return None


def check_snapshot(entry: dict):
    reason = _check_state(entry)
    return (reason is None), reason


def describe(req: Request, candidate: dict) -> str:
    sub = candidate.get("sub", "?")
    flags = "".join(f" [{f}]" for f in candidate.get("flags", ()))
    glob = candidate.get("branch_glob", "*")
    slot = {"push": " <branch>...", "pull": " [<branch>]"}.get(sub, "")
    if slot and glob != "*":
        slot = slot.replace("<branch>", f"<branch matching {glob}>")
    lines = [f"git {sub}{flags} {candidate.get('remote')}{slot}"]
    info = _summaries.get((req.cwd, json.dumps(candidate, sort_keys=True)))
    if info:
        lines.append(f"{'Push' if info['push'] else 'Remote'} URL pinned: {info['url']}")
        lines.append(f"git program pinned: {info['git']} ({info['version']})")
        hooks = info["hooks_dir"] + ("" if info["hooks_present"] else " (does not exist)")
        lines.append(f"Hooks run normally from: {hooks} (fingerprinted)")
        lines.append("Credential helpers (your own, pinned): "
                     + (", ".join(info["helpers"]) or "none"))
    lines.append("Only push/pull/fetch/ls-remote to the configured remote; branches are "
                 "rewritten to refs/heads/N:refs/heads/N; no force, delete, tags, mirror "
                 "or push options; pull is fast-forward only.")
    lines.append(HOOK_WARNING)
    return "\n".join(lines)


def verify(entry: dict, req: Request) -> Verdict:
    shape = entry.get("shape")
    if not isinstance(shape, dict):
        return Verdict(ok=False, reason=None)
    try:
        parsed = _parse(req.command)
    except c.ArgvRejected:
        return Verdict(ok=False, reason=None)
    glob = shape.get("branch_glob")
    if not _glob_ok(glob) or _shape_of(parsed, glob) != shape:
        return Verdict(ok=False, reason=None)
    if any(not fnmatch.fnmatchcase(b, glob) for b in parsed.branches):
        return Verdict(ok=False, reason=None)
    if parsed.sub == "pull" and not parsed.branches and glob != "*":
        # The merge ref then comes from branch.<cur>.merge in .git/config, which
        # is not snapshotted: the glob cannot be enforced, so it is not applicable.
        return Verdict(ok=False, reason=None)
    ecwd = entry.get("cwd")
    if not isinstance(ecwd, str) or c.canonical_cwd(ecwd) != c.canonical_cwd(req.cwd):
        return Verdict(ok=False, reason=None)
    problem = c.injected_name_problem(req.only_vars)
    if problem:
        return Verdict(ok=False, reason=problem)
    reason = _check_state(entry)
    if reason:
        return Verdict(ok=False, reason=reason)
    snap = entry["snapshot"]
    pairs = pin_pairs(snap["hooks_dir"], [h["pin"] for h in snap["helpers"]])
    try:
        env = command_env(snap["path_dirs"], pairs)
    except c.ProfileRefusal as exc:
        return Verdict(ok=False, reason=exc.reason)
    return Verdict(ok=True, argv=build_argv(snap["git"]["path"], parsed), env=env,
                   replace_env=True)
