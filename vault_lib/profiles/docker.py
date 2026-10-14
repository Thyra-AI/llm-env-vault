"""docker profile for persistent "always allow" entries (plan 2.4.0 section 5.2).

Two entry families share the kind ``"docker"``:

* ``compose`` -- ``docker compose [-f F]... -p NAME [--profile P]...
  up|down|pull|ps|logs|build ...`` for ONE approved project (files, project
  name, profiles).  The subcommands and their flags are a closed grammar.
* ``image`` -- ``docker pull|push [--platform=] [-q] <image>`` for an approved
  registry host + namespace prefix (a port of distribution/reference).

How the pieces fit (every number refers to the plan):

* **Endpoint pin** -- resolved once at approval with ``docker context inspect``
  (``DOCKER_*`` removed), checked against a fixed allowlist, always passed as
  ``-H <endpoint>`` (D3).
* **Vault-owned DOCKER_CONFIG** -- a generated directory holding only
  ``config.json`` (``auths`` hosts as empty objects, ``credsStore``,
  ``credHelpers``); no ``cli-plugins``, ``plugins``, ``proxies``,
  ``HttpHeaders``, ``contexts``.  The child env is built from scratch
  (``_common.build_env``): no ``DOCKER_*``/``COMPOSE_*``/``BUILDKIT_*``/
  ``BUILDX_*``/proxies ever reach docker except our own ``DOCKER_CONFIG``.
* **Pins** -- docker.exe, the compose plugin (path read from ``docker info``
  under the vault config) and every credential helper are resolved to absolute
  paths, must sit in protected directories, and are re-hashed before use.
* **Raw-YAML scan first** (D1/D4) -- before ANY ``compose config`` the approved
  files are parsed and the local include/extends chain is followed; oci://,
  git, URL references, remote build contexts are refused.
* **Trust anchor** (D1/D2/D6) -- SHA-256 of ``compose config`` run with a
  distinct constant sentinel per vault variable ("S", YAML) plus the JSON form
  (the lint input).  ``up`` runs S, then the real-value config R (held in
  memory only), then S' again; S == S' == approved is required and R is piped
  to ``docker compose -f - up``.  Every other subcommand pipes S and receives
  no secrets.
* **Model lint** -- Class A (refuse always-allow) and Class B (findings shown
  to the human, hash-bound); see ``lint_model``.
* **Build tier** -- the approved buildable-service list; ``up`` counts every
  service with a ``build:`` section as buildable (D6).

Contract note: ``verify`` returns a plain ``Verdict`` whose ``stdin`` carries
the compose model to pipe into ``docker compose -f -`` (for ``up`` it holds the
real values; for every other subcommand the sentinel model).  A caller that
ignores ``stdin`` runs ``compose -f -`` on an empty stdin, which fails closed.
Every ``ok`` verdict sets ``inject_secrets=False``: the ``up`` values already
live inside the stdin model R and no other subcommand may ever receive them,
so the caller must not add the ``only_vars`` values to the child env.  (A
request's ``only_vars`` is never empty -- the server refuses that first -- so
``match`` cannot refuse a non-empty ``only_vars`` for pull/push/ps/...: those
requests exist precisely because the entry was approved for ``up``'s variables
or, for images, as the entry's blast radius.  ``inject_secrets=False`` is what
keeps them out.)

Residuals (plan section 6): bind-mounted directory contents, Dockerfiles and
build contexts, images of non-built services, and the short windows between
the S/R/S' reads and the spawn.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from ..procs import NO_WINDOW  # noqa: F401  (imported so a missing procs fails at load, not at run)
from . import Request, Verdict
from . import _common as c
from ._common import (ArgvRejected, FlagSpec, PinnedBinary, ProfileRefusal)

kind = "docker"

SNAPSHOT_VERSION = 1

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENTINEL_PREFIX = "__VAULT_SENTINEL_"

# Endpoints an entry may be pinned to (plan 5.2).
_ENDPOINT_FIXED = frozenset({
    "npipe:////./pipe/docker_engine",
    "npipe:////./pipe/dockerDesktopLinuxEngine",
    "unix:///var/run/docker.sock",
})
_ENDPOINT_ROOTLESS = re.compile(r"unix:///run/user/[0-9]{1,10}/docker\.sock")

PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
SERVICE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_INT_RE = r"[0-9]{1,6}"

MAX_YAML_BYTES = 2 * 1024 * 1024
MAX_SCAN_FILES = 64
MAX_SCAN_DEPTH = 8
CONFIG_MAX_OUTPUT = 8 * 1024 * 1024
CONFIG_TIMEOUT = 30.0
SMALL_TIMEOUT = 15.0
DOCKERFILE_HEAD_BYTES = 64 * 1024

COMPOSE_SUBS = ("up", "down", "pull", "ps", "logs", "build")

_REMOTE_PATTERNS = (
    re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://"),
    re.compile(r"^[\w.-]+@[\w.-]+:"),
    re.compile(r"^(github|gitlab|bitbucket)\.com/", re.IGNORECASE),
    re.compile(r"\.git(#|$)"),
)

# Image registry aliases normalised to one canonical host.
_DOCKER_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io",
                                 "registry.hub.docker.com"})

DOCKERFILE_DIRECTIVE_RE = re.compile(r"^\s*#\s*(\w+)\s*=\s*(.*)$")
_SYNTAX_DIRECTIVE_RE = re.compile(r"(?i)^\s*#\s*syntax\s*=")


class _Unsupported(ProfileRefusal):
    """The request does not belong to this profile or entry (never a drift)."""


# ---------------------------------------------------------------------------
# Argv grammar
# ---------------------------------------------------------------------------

def _enum(*values: str) -> str:
    return "(?:" + "|".join(re.escape(v) for v in values) + ")"


_GLOBAL_SPECS = (
    FlagSpec(long="--file", short="-f", value=True, repeatable=True),
    FlagSpec(long="--project-name", short="-p", value=True, pattern=PROJECT_RE.pattern),
    FlagSpec(long="--profile", value=True, repeatable=True, pattern=PROFILE_RE.pattern),
    FlagSpec(long="--ansi", value=True, pattern=_enum("never", "always", "auto")),
    FlagSpec(long="--progress", value=True,
             pattern=_enum("auto", "tty", "plain", "json", "quiet")),
    FlagSpec(long="--dry-run"),
)

_TIMEOUT = FlagSpec(long="--timeout", short="-t", value=True, pattern=_INT_RE)

SUB_SPECS: Dict[str, Tuple[FlagSpec, ...]] = {
    "up": (
        FlagSpec(long="--detach", short="-d"),
        FlagSpec(long="--wait"),
        FlagSpec(long="--wait-timeout", value=True, pattern=_INT_RE),
        FlagSpec(long="--no-build"),
        FlagSpec(long="--build"),
        FlagSpec(long="--pull", value=True, pattern=_enum("always", "missing", "never")),
        FlagSpec(long="--no-recreate"),
        FlagSpec(long="--force-recreate"),
        FlagSpec(long="--no-deps"),
        FlagSpec(long="--quiet-pull"),
        FlagSpec(long="--no-color"),
        _TIMEOUT,
        FlagSpec(long="--remove-orphans"),
    ),
    "down": (
        _TIMEOUT,
        FlagSpec(long="--remove-orphans"),
    ),
    "logs": (
        FlagSpec(long="--tail", short="-n", value=True, pattern=r"(?:[0-9]{1,7}|all)"),
        FlagSpec(long="--since", value=True, pattern=r"[0-9A-Za-z:.+_-]{1,64}"),
        FlagSpec(long="--until", value=True, pattern=r"[0-9A-Za-z:.+_-]{1,64}"),
        FlagSpec(long="--timestamps", short="-t"),
        FlagSpec(long="--no-color"),
        FlagSpec(long="--no-log-prefix"),
    ),
    "pull": (
        FlagSpec(long="--quiet", short="-q"),
        FlagSpec(long="--policy", value=True, pattern=_enum("always", "missing")),
        FlagSpec(long="--ignore-pull-failures"),
    ),
    "ps": (
        FlagSpec(long="--all", short="-a"),
        FlagSpec(long="--format", value=True, pattern=_enum("table", "json")),
        FlagSpec(long="--status", value=True,
                 pattern=_enum("paused", "restarting", "removing", "running", "dead",
                               "created", "exited")),
    ),
    "build": (
        FlagSpec(long="--pull"),
        FlagSpec(long="--no-cache"),
        FlagSpec(long="--quiet", short="-q"),
    ),
}

_IMAGE_SPECS = (
    FlagSpec(long="--platform", value=True, pattern=r"[a-z0-9]+/[a-z0-9._]+(?:/[a-z0-9._]+)?"),
    FlagSpec(long="--quiet", short="-q"),
)


@dataclass
class ComposeCommand:
    """A parsed ``docker compose ...`` request (no filesystem access yet)."""
    sub: str
    files: List[str]
    project: str
    profiles: List[str]
    globals: c.ParsedArgv
    flags: c.ParsedArgv
    services: List[str]


@dataclass
class ImageCommand:
    op: str                          # "pull" | "push"
    flags: c.ParsedArgv
    image: str


def _program_is_docker(token: str) -> bool:
    return isinstance(token, str) and token.lower() in ("docker", "docker.exe")


def _split_global(tokens: List[str]) -> int:
    """Index of the first non-flag token (the compose subcommand)."""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("-"):
            i += 2 if token in ("-f", "-p") else 1
            continue
        return i
    raise ArgvRejected("no compose subcommand")


def parse_command(command) -> object:
    """Parse an argv tuple into a ``ComposeCommand`` or ``ImageCommand``.
    Raises ``ArgvRejected`` for anything outside the grammar (callers turn
    that into "not this profile" / "not this entry")."""
    command = list(command)
    if len(command) < 3 or not _program_is_docker(command[0]):
        raise ArgvRejected("not a docker compose/pull/push command")
    for token in command:
        if not isinstance(token, str) or c.has_unsafe_text(token):
            raise ArgvRejected("an argument is not plain text")
    word = command[1]
    if word == "compose":
        rest = command[2:]
        idx = _split_global(rest)
        sub = rest[idx]
        if sub not in COMPOSE_SUBS:
            raise ArgvRejected(f"compose subcommand {sub!r} is not allowed")
        globals_ = c.tokenize_argv(rest[:idx], _GLOBAL_SPECS, max_positionals=0)
        files = list(globals_.flags.get("--file", []))
        if not files:
            raise ArgvRejected("-f is required (the compose files must be explicit)")
        project = globals_.value("--project-name")
        if not project:
            raise ArgvRejected("-p is required (the project name must be explicit)")
        parsed = c.tokenize_argv(rest[idx + 1:], SUB_SPECS[sub])
        for name in parsed.positionals:
            if not SERVICE_RE.fullmatch(name):
                raise ArgvRejected(f"service name {name!r} is not allowed")
        if len(set(parsed.positionals)) != len(parsed.positionals):
            raise ArgvRejected("a service is named twice")
        return ComposeCommand(sub=sub, files=files, project=project,
                              profiles=sorted(set(globals_.flags.get("--profile", []))),
                              globals=globals_, flags=parsed, services=list(parsed.positionals))
    if word in ("pull", "push"):
        parsed = c.tokenize_argv(command[2:], _IMAGE_SPECS, max_positionals=1, min_positionals=1)
        return ImageCommand(op=word, flags=parsed, image=parsed.positionals[0])
    raise ArgvRejected(f"docker {word!r} is not covered by this profile")


# ---------------------------------------------------------------------------
# Image references (port of distribution/reference, restricted)
# ---------------------------------------------------------------------------

_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN_RE = re.compile(rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]+)?")
_PATH_COMPONENT_RE = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG_RE = re.compile(r"[\w][\w.-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}")
DEFAULT_TAG_PATTERN = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"


@dataclass(frozen=True)
class ImageRef:
    registry: str                # canonical host ("docker.io" for the hub aliases)
    path: str                    # repository path, "library/" added for hub single names
    tag: Optional[str]           # None when absent
    digest: Optional[str]

    @property
    def namespace(self) -> str:
        return self.path.rpartition("/")[0]

    @property
    def effective_tag(self) -> Optional[str]:
        return self.tag or (None if self.digest else "latest")


def parse_reference(text: str) -> ImageRef:
    """Parse an image reference the way ``docker pull`` would (normalised
    names), but accepting only the strict subset the profile can reason about.
    Raises ``ArgvRejected``."""
    if not isinstance(text, str) or not text or len(text) > 400 or c.has_unsafe_text(text):
        raise ArgvRejected("the image reference is empty or contains odd characters")
    if text != text.strip() or text.startswith("-"):
        raise ArgvRejected("the image reference is malformed")
    name, at, digest = text.partition("@")
    if at:
        if not _DIGEST_RE.fullmatch(digest):
            raise ArgvRejected("only @sha256:<64 hex> digests are accepted")
    else:
        digest = None
    tag = None
    last_slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > last_slash:
        tag = name[colon + 1:]
        name = name[:colon]
        if not _TAG_RE.fullmatch(tag):
            raise ArgvRejected("the image tag is malformed")
    if not name:
        raise ArgvRejected("the image name is empty")
    first, slash, remainder = name.partition("/")
    if not slash or (not any(ch in first for ch in ".:") and first != "localhost"
                     and first.lower() == first):
        registry, remainder = "docker.io", name
    else:
        registry = first
    if registry != "docker.io":
        if not _DOMAIN_RE.fullmatch(registry):
            raise ArgvRejected("the registry host is malformed")
    registry = registry.lower()
    if registry in _DOCKER_HUB_ALIASES:
        registry = "docker.io"
        if "/" not in remainder:
            remainder = "library/" + remainder
    if not remainder:
        raise ArgvRejected("the repository path is empty")
    for part in remainder.split("/"):
        if not _PATH_COMPONENT_RE.fullmatch(part):
            raise ArgvRejected("the repository path is malformed")
    if len(registry) + 1 + len(remainder) > 255:
        raise ArgvRejected("the repository name is too long")
    return ImageRef(registry=registry, path=remainder, tag=tag, digest=digest)


def image_shape(cmd: ImageCommand, ref: ImageRef) -> dict:
    """The entry shape generalising one concrete pull/push request."""
    return {
        "family": "image",
        "op": cmd.op,
        "registry": ref.registry,
        "namespace": ref.namespace,
        "tag_pattern": DEFAULT_TAG_PATTERN,
        "allow_latest": ref.effective_tag == "latest",
    }


def image_problem(shape: Mapping, cmd: ImageCommand, ref: ImageRef) -> Optional[str]:
    """Why this request is outside the approved image shape (None = inside)."""
    if shape.get("op") != cmd.op:
        return "a different docker operation"
    if shape.get("registry") != ref.registry:
        return f"registry {ref.registry} is not the approved registry"
    namespace = shape.get("namespace", "")
    if namespace:
        if not ref.path.startswith(namespace + "/"):
            return f"repository {ref.path} is outside the approved namespace {namespace}/"
    elif "/" in ref.path:
        return f"repository {ref.path} is outside the approved registry root"
    if cmd.op == "push" and ref.digest:
        return "push takes no digest"
    tag = ref.effective_tag
    if tag is not None:
        pattern = shape.get("tag_pattern") or DEFAULT_TAG_PATTERN
        try:
            if not re.fullmatch(pattern, tag):
                return f"tag {tag} does not match the approved pattern"
        except re.error:
            return "the approved tag pattern is invalid"
        if tag == "latest" and not shape.get("allow_latest"):
            return "the tag 'latest' was not approved"
    return None


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def sentinel_for(name: str) -> str:
    return f"{SENTINEL_PREFIX}{name}__"


def docker_env(path_dirs: Iterable[str], config_dir: str, *,
               injected: Optional[Mapping[str, str]] = None,
               source: Optional[Mapping[str, str]] = None,
               windows: Optional[bool] = None) -> Dict[str, str]:
    """The complete child environment: system essentials, the pinned PATH, our
    own ``DOCKER_CONFIG``, and (probes/R only) the *injected* values.  Nothing
    from ``DOCKER_*``, ``COMPOSE_*``, ``BUILDKIT_*``, ``BUILDX_*``, proxies, ...
    survives because the env is built, not scrubbed."""
    return c.build_env(path_dirs, injected=injected, extra={"DOCKER_CONFIG": config_dir},
                       source=source, windows=windows)


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

def compose_version_problem(text) -> Optional[str]:
    """``docker compose version --short`` output against the numeric floor
    (2, 40, 2); every 5.x passes.  Never a string comparison."""
    return c.version_problem("compose", text)


def desktop_problem(platform_name) -> Optional[str]:
    """Only a Docker Desktop server is checked (floor 4.44.3)."""
    if not isinstance(platform_name, str) or "docker desktop" not in platform_name.lower():
        return None
    return c.version_problem("docker_desktop", platform_name)


def desktop_problem_applies(platform_name) -> bool:
    """True when ``platform_name`` names a Docker Desktop server."""
    return isinstance(platform_name, str) and "docker desktop" in platform_name.lower()


def buildkit_problem(text) -> Optional[str]:
    """BuildKit floor 0.12.5 (build tier).  Exposed for callers that can read the
    BuildKit version; the profile itself does not probe it (no cheap, daemon-safe
    source -- see the handback)."""
    return c.version_problem("buildkit", text)


# ---------------------------------------------------------------------------
# Path normalisation and bind-mount classification
# ---------------------------------------------------------------------------

def norm_host_path(path) -> str:
    """Comparable form of a host path: ``~`` expanded, backslashes to ``/``,
    casefolded, leading ``//`` collapsed (``//var/run/docker.sock`` equals
    ``/var/run/docker.sock``), named pipes unified to ``//./pipe/<name>``
    (``\\\\.\\pipe\\docker_engine`` and ``\\.\\pipe\\docker_engine`` both)."""
    text = str(path)
    if text.startswith("~"):
        text = os.path.expanduser(text)
    text = text.replace("\\", "/").casefold()
    match = re.match(r"^/+\./pipe(?:/(.*))?$", text)
    if match:
        rest = (match.group(1) or "").rstrip("/")
        return "//./pipe/" + rest if rest else "//./pipe"
    text = re.sub(r"^/{2,}", "/", text)
    text = posixpath.normpath(text) if text else text
    return text


def _home_norm() -> str:
    return norm_host_path(os.path.expanduser("~"))


def bind_danger(path, *, home: Optional[str] = None) -> Optional[str]:
    """A label when a host bind source is the root, a drive root, the home
    directory (or a parent of it) or the docker socket/pipe; else None."""
    norm = norm_host_path(path)
    home = _home_norm() if home is None else norm_host_path(home)
    if norm in ("/", ""):
        return "the host root"
    if re.fullmatch(r"[a-z]:/?", norm):
        return "a drive root"
    if norm == home or (home and home.startswith(norm.rstrip("/") + "/")):
        return "the home directory (or a parent of it)"
    if (norm.endswith("/docker.sock") or norm.startswith("//./pipe/docker")
            or "dockerdesktoplinuxengine" in norm):
        return "the docker socket/pipe"
    if _holds_docker_socket(norm, home):
        return "a directory that contains the docker socket/pipe"
    return None


def _holds_docker_socket(norm: str, home: str) -> bool:
    """True when ``norm`` is a proper ancestor of a well-known docker socket or
    the pipe namespace (mounting it exposes the socket as well)."""
    cand = norm.rstrip("/")
    if cand == "//./pipe":
        return True
    if re.fullmatch(r"/run/user(?:/\d+)?", cand):
        return True
    sockets = ["/var/run/docker.sock", "/run/docker.sock"]
    if home:
        sockets.append(home.rstrip("/") + "/.docker/run/docker.sock")
    return any(sock.startswith(cand + "/") for sock in sockets)


# ---------------------------------------------------------------------------
# Reference checks shared by the raw scan and the JSON lint
# ---------------------------------------------------------------------------

def is_remote_reference(value) -> bool:
    """True for oci://, https://, git+..., scp-style git, github.com/..., *.git
    references (plan 5.2 raw-file scan)."""
    if not isinstance(value, str):
        return True
    return any(p.search(value) for p in _REMOTE_PATTERNS)


def is_plain_dir_reference(value) -> bool:
    """An ``additional_contexts`` value that is a plain relative/absolute
    directory: not remote and not any ``scheme:`` / ``service:`` form (a
    Windows drive letter is fine)."""
    if not isinstance(value, str) or not value or is_remote_reference(value):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    return not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)


# ---------------------------------------------------------------------------
# Raw-YAML scan (BEFORE any `compose config`)
# ---------------------------------------------------------------------------

_yaml_loader_cls = None
_yaml_lock = threading.Lock()


def _yaml_loader():
    """A SafeLoader that rejects duplicate keys (compose does too), accepts
    compose's ``!reset`` / ``!override`` tags and yields plain data.  PyYAML is
    imported lazily; without it the compose family is refused (fail closed)."""
    global _yaml_loader_cls
    with _yaml_lock:
        if _yaml_loader_cls is not None:
            return _yaml_loader_cls
        try:
            import yaml
        except ImportError:
            raise ProfileRefusal("PyYAML is not installed, so compose files cannot be "
                                 "scanned safely")

        class Loader(yaml.SafeLoader):
            pass

        def construct_mapping(self, node, deep=False):
            if isinstance(node, yaml.MappingNode):
                seen = set()
                for key_node, _value in node.value:
                    if key_node.tag == "tag:yaml.org,2002:merge":
                        continue
                    key = self.construct_object(key_node, deep=True)
                    try:
                        hash(key)
                    except TypeError:
                        raise yaml.YAMLError("unhashable mapping key")
                    if key in seen:
                        raise yaml.YAMLError(f"duplicate mapping key {key!r}")
                    seen.add(key)
            return yaml.SafeLoader.construct_mapping(self, node, deep=deep)

        def any_tag(self, suffix, node):
            if isinstance(node, yaml.ScalarNode):
                return self.construct_scalar(node)
            if isinstance(node, yaml.SequenceNode):
                return self.construct_sequence(node, deep=True)
            return construct_mapping(self, node, deep=True)

        Loader.add_constructor("tag:yaml.org,2002:map", construct_mapping)
        Loader.add_multi_constructor("!", any_tag)
        _yaml_loader_cls = Loader
        return Loader


def load_yaml_document(text: str):
    """Parse exactly one YAML document; ``ProfileRefusal`` otherwise."""
    loader = _yaml_loader()
    import yaml
    try:
        docs = list(yaml.load_all(text, Loader=loader))
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise ProfileRefusal(f"a compose file is not valid YAML ({type(exc).__name__})")
    docs = [d for d in docs if d is not None] if len(docs) > 1 else docs
    if len(docs) != 1:
        raise ProfileRefusal("a compose file must contain exactly one YAML document")
    return docs[0]


def _read_limited(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise ProfileRefusal(f"cannot read {os.path.basename(path)}: {exc.strerror or exc}")
    if len(data) > limit:
        raise ProfileRefusal(f"{os.path.basename(path)} is larger than {limit} bytes")
    return data


@dataclass
class ScanResult:
    files: List[str] = field(default_factory=list)       # yaml files visited, in order
    env_files: List[str] = field(default_factory=list)   # env_file paths (maybe missing)
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def scan_compose_files(files: Iterable[str], *, max_files: int = MAX_SCAN_FILES,
                       max_depth: int = MAX_SCAN_DEPTH) -> ScanResult:
    """Parse each file and the local include/extends chain; collect refusals
    for non-local references (``include``, ``extends.file``, ``build``,
    ``build.context``, ``additional_contexts``).  Reads files only; spawns
    nothing.  ``result.problems`` empty means the chain is local."""
    result = ScanResult()
    seen = set()

    def problem(text: str):
        if text not in result.problems:
            result.problems.append(text)

    def visit(path: str, depth: int):
        real = os.path.realpath(path)
        key = os.path.normcase(real)
        if key in seen:
            return
        if depth > max_depth:
            problem("the include/extends chain is nested too deeply")
            return
        if len(seen) >= max_files:
            problem("the include/extends chain has too many files")
            return
        seen.add(key)
        name = os.path.basename(real)
        if not os.path.isfile(real):
            problem(f"{name} is not a regular file")
            return
        try:
            data = load_yaml_document(_read_limited(real, MAX_YAML_BYTES)
                                      .decode("utf-8", "replace").lstrip("﻿"))
        except ProfileRefusal as exc:
            problem(f"{name}: {exc.reason}")
            return
        result.files.append(real)
        if not isinstance(data, dict):
            problem(f"{name} is not a YAML mapping")
            return
        base = os.path.dirname(real)

        def local_target(value, what: str) -> Optional[str]:
            if not isinstance(value, str) or not value:
                problem(f"{name}: {what} is not a plain path")
                return None
            if "$" in value:
                problem(f"{name}: {what} contains a variable and cannot be verified")
                return None
            if is_remote_reference(value):
                problem(f"{name}: {what} is a remote reference ({value[:60]!r})")
                return None
            return value if os.path.isabs(value) else os.path.join(base, value)

        for item in _as_list(data.get("include")):
            if isinstance(item, str):
                paths = [item]
            elif isinstance(item, dict):
                paths = _as_list(item.get("path"))
                for envf in _as_list(item.get("env_file")):
                    target = local_target(envf, "include env_file")
                    if target:
                        result.env_files.append(os.path.realpath(target))
                project_dir = item.get("project_directory")
                if project_dir is not None:
                    local_target(project_dir, "include project_directory")
            else:
                problem(f"{name}: an include entry has an unsupported form")
                continue
            for entry in paths:
                target = local_target(entry, "an include")
                if target:
                    visit(target, depth + 1)
        services = data.get("services")
        if services is not None and not isinstance(services, dict):
            problem(f"{name}: services is not a mapping")
            return
        for svc_name, svc in (services or {}).items():
            if not isinstance(svc, dict):
                continue
            extends = svc.get("extends")
            if isinstance(extends, dict) and extends.get("file") is not None:
                target = local_target(extends.get("file"), f"{svc_name}: extends.file")
                if target:
                    visit(target, depth + 1)
            elif extends is not None and not isinstance(extends, (str, dict)):
                problem(f"{name}: {svc_name}: extends has an unsupported form")
            build = svc.get("build")
            if isinstance(build, str):
                if is_remote_reference(build):
                    problem(f"{name}: {svc_name}: build is a remote context")
            elif isinstance(build, dict):
                context = build.get("context")
                if context is not None and (not isinstance(context, str)
                                            or is_remote_reference(context)):
                    problem(f"{name}: {svc_name}: build.context is a remote context")
                extra = build.get("additional_contexts")
                if isinstance(extra, dict):
                    values = list(extra.values())
                else:
                    values = [v.partition("=")[2] if isinstance(v, str) else v
                              for v in _as_list(extra)]
                for value in values:
                    if not is_plain_dir_reference(value):
                        problem(f"{name}: {svc_name}: additional_contexts has a "
                                f"non-directory value")
                        break
            elif build is not None:
                problem(f"{name}: {svc_name}: build has an unsupported form")
            for envf in _as_list(svc.get("env_file")):
                raw = envf.get("path") if isinstance(envf, dict) else envf
                if not isinstance(raw, str) or not raw:
                    problem(f"{name}: {svc_name}: env_file is not a plain path")
                elif "$" in raw:
                    problem(f"{name}: {svc_name}: env_file contains a variable and cannot "
                            f"be verified")
                else:
                    result.env_files.append(os.path.realpath(
                        raw if os.path.isabs(raw) else os.path.join(base, raw)))

    for path in files:
        visit(path, 0)
    return result


# ---------------------------------------------------------------------------
# Dockerfile directive scan (CVE-2024-23653)
# ---------------------------------------------------------------------------

def dockerfile_syntax_problem(text: str) -> Optional[str]:
    """Refusal reason when a Dockerfile (or ``dockerfile_inline``) starts with a
    ``# syntax=`` parser directive.  Scans the leading comment/blank lines
    (BOM, CRLF and lone CR tolerated); stops at the first instruction.  More
    conservative than BuildKit (which stops at the first non-directive line)."""
    text = text.lstrip("﻿")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            return None
        if _SYNTAX_DIRECTIVE_RE.match(line):
            return "a Dockerfile has a '# syntax=' parser directive"
    return None


def _read_dockerfile_head(path: str) -> Optional[str]:
    """The first ``DOCKERFILE_HEAD_BYTES`` of a Dockerfile.  ``None`` when it
    cannot be read, or when the window ends before the first instruction (a
    ``# syntax=`` further down could not be ruled out: refuse, never skip)."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(DOCKERFILE_HEAD_BYTES + 1)
    except OSError:
        return None
    text = raw[:DOCKERFILE_HEAD_BYTES].decode("utf-8", "replace")
    if len(raw) > DOCKERFILE_HEAD_BYTES and not any(
            line.strip() and not line.strip().startswith("#")
            for line in text.lstrip("﻿").splitlines()[:-1]):
        return None
    return text


# ---------------------------------------------------------------------------
# Model lint (on the sentinel-interpolated `config --format json`)
# ---------------------------------------------------------------------------

@dataclass
class Lint:
    class_a: List[str] = field(default_factory=list)
    class_b: List[str] = field(default_factory=list)
    buildable: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    @property
    def refused(self) -> bool:
        return bool(self.class_a)


def _present(value) -> bool:
    return value not in (None, False, "", 0, [], {})


def _is_host(value) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "host"


def lint_model(model, vault_vars: Iterable[str], *, read_dockerfile=_read_dockerfile_head,
               home: Optional[str] = None) -> Lint:
    """Classify the interpolated model (plan 5.2).

    Class A -- the entry cannot be always-allowed: a sentinel under any
    ``services.*.build``; a build secret fed from a vault variable or a file;
    ``build.privileged|entitlements|network: host``; remote build contexts or
    non-directory ``additional_contexts``; a Dockerfile ``# syntax=``
    directive (named, inline).
    Class B -- findings shown to the human (hash-bound): see the list in the
    module docstring / plan.  ``buildable`` is every service with a
    ``build:`` section (they all count for ``up``, D6)."""
    out = Lint()
    names = {str(n).casefold() for n in vault_vars}
    if not isinstance(model, dict):
        out.class_a.append("the compose model is not a mapping")
        return out
    # An absent/null section is empty; a present section of the wrong type
    # (even an empty list) is refused, never silently treated as empty.
    sections = {key: ({} if model.get(key) is None else model[key])
                for key in ("services", "secrets", "configs", "volumes")}
    if not all(isinstance(v, dict) for v in sections.values()):
        out.class_a.append("the compose model has an unexpected shape")
        return out
    services, top_secrets = sections["services"], sections["secrets"]
    out.services = sorted(str(s) for s in services)
    for svc_name, svc in sorted(services.items()):
        if not isinstance(svc, dict):
            continue
        build = svc.get("build")
        if build is not None:
            out.buildable.append(svc_name)
            build = {"context": build} if isinstance(build, str) else build
            if not isinstance(build, dict):
                out.class_a.append(f"{svc_name}: build has an unsupported form")
                build = {}
            if SENTINEL_PREFIX in json.dumps(build, sort_keys=True, default=str):
                out.class_a.append(f"{svc_name}: a vault variable is used under build")
            context = build.get("context")
            if isinstance(context, str) and is_remote_reference(context):
                out.class_a.append(f"{svc_name}: remote build context")
            extra = build.get("additional_contexts") or {}
            values = (list(extra.values()) if isinstance(extra, dict)
                      else [v.partition("=")[2] if isinstance(v, str) else v for v in extra])
            if any(not is_plain_dir_reference(v) for v in values):
                out.class_a.append(f"{svc_name}: additional_contexts is not a plain directory")
            if build.get("privileged"):
                out.class_a.append(f"{svc_name}: build.privileged")
            if build.get("entitlements"):
                out.class_a.append(f"{svc_name}: build.entitlements")
            if _is_host(build.get("network")):
                out.class_a.append(f"{svc_name}: build.network is host")
            for secret in build.get("secrets") or []:
                source = secret.get("source") if isinstance(secret, dict) else secret
                top = top_secrets.get(source) if isinstance(source, str) else None
                if not isinstance(top, dict):
                    continue
                env_name = top.get("environment")
                if isinstance(env_name, str) and env_name.casefold() in names:
                    out.class_a.append(f"{svc_name}: build secret {source} reads a vault variable")
                if top.get("file"):
                    out.class_a.append(f"{svc_name}: build secret {source} reads a host file")
            inline = build.get("dockerfile_inline")
            if isinstance(inline, str):
                why = dockerfile_syntax_problem(inline)
                if why:
                    out.class_a.append(f"{svc_name}: {why}")
            elif isinstance(context, str) and not is_remote_reference(context):
                dockerfile = build.get("dockerfile") or "Dockerfile"
                path = (dockerfile if os.path.isabs(dockerfile)
                        else os.path.join(context, dockerfile))
                head = read_dockerfile(path)
                if head is None:
                    out.class_a.append(f"{svc_name}: the Dockerfile cannot be read or scanned")
                else:
                    why = dockerfile_syntax_problem(head)
                    if why:
                        out.class_a.append(f"{svc_name}: {why}")
        # ---- Class B -----------------------------------------------------
        for flag in ("privileged", "use_api_socket"):
            if _present(svc.get(flag)):
                out.class_b.append(f"{svc_name}: {flag}")
        for key in ("cap_add", "devices", "device_cgroup_rules", "gpus", "security_opt",
                    "runtime", "sysctls", "volumes_from", "credential_spec", "cgroup_parent",
                    "provider", "models", "post_start", "pre_stop"):
            if _present(svc.get(key)):
                out.class_b.append(f"{svc_name}: {key}")
        for key in ("network_mode", "userns_mode", "pid", "ipc", "uts", "cgroup"):
            if _is_host(svc.get(key)):
                out.class_b.append(f"{svc_name}: {key}: host")
        develop = svc.get("develop")
        if isinstance(develop, dict):
            for rule in develop.get("watch") or []:
                if isinstance(rule, dict) and _present(rule.get("exec")):
                    out.class_b.append(f"{svc_name}: develop.watch exec")
        for volume in svc.get("volumes") or []:
            if not isinstance(volume, dict):
                continue
            vtype = volume.get("type")
            source = volume.get("source")
            if vtype == "bind" and isinstance(source, str):
                danger = bind_danger(source, home=home)
                text = f"{svc_name}: bind mount {source} -> {volume.get('target')}"
                if danger:
                    text += f" (DANGEROUS: {danger})"
                out.class_b.append(text + " (code reaches secrets)")
            elif vtype == "npipe":
                out.class_b.append(f"{svc_name}: named pipe mount {source}")
    for vol_name, vol in sorted(sections["volumes"].items()):
        if not isinstance(vol, dict):
            continue
        driver = vol.get("driver")
        opts = vol.get("driver_opts")
        if (_present(driver) and str(driver) != "local") or _present(opts):
            text = f"volume {vol_name}: driver/driver_opts"
            device = opts.get("device") if isinstance(opts, dict) else None
            if isinstance(device, str):
                danger = bind_danger(device, home=home)
                if danger:
                    text += f" (DANGEROUS: binds {danger})"
            out.class_b.append(text)
    for section in ("secrets", "configs"):
        for item_name, item in sorted(sections[section].items()):
            if isinstance(item, dict) and item.get("file"):
                out.class_b.append(f"{section[:-1]} {item_name}: reads host file {item['file']}")
    if _present(model.get("models")):
        out.class_b.append("top-level models")
    out.class_a = sorted(set(out.class_a))
    out.class_b = sorted(set(out.class_b))
    return out


# ---------------------------------------------------------------------------
# Docker config.json (user's) -> vault-owned copy
# ---------------------------------------------------------------------------

_CRED_FIELDS = ("auth", "identitytoken", "registrytoken", "username", "password")
_HELPER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_DROPPED_KEYS = ("currentContext", "proxies", "plugins", "HttpHeaders", "cliPluginsExtraDirs")


@dataclass
class SanitisedConfig:
    vault_doc: dict
    findings: List[str]
    helpers: List[str]


def sanitise_docker_config(user_cfg) -> SanitisedConfig:
    """Derive the vault copy of ``config.json``.  Raises ``ProfileRefusal``
    for inline credentials or odd helper names (credentials must come from the
    OS credential store)."""
    if user_cfg is None:
        user_cfg = {}
    if not isinstance(user_cfg, dict):
        raise ProfileRefusal("the docker config.json is not a JSON object")
    findings: List[str] = []
    auths = user_cfg.get("auths")
    if auths is None:
        auths = {}
    if not isinstance(auths, dict):
        raise ProfileRefusal("the docker config.json 'auths' is malformed")
    hosts = {}
    for host, value in auths.items():
        if not isinstance(host, str) or c.has_unsafe_text(host):
            raise ProfileRefusal("the docker config.json has an odd registry host")
        if isinstance(value, dict) and any(value.get(f) for f in _CRED_FIELDS):
            raise ProfileRefusal(f"the docker config.json stores credentials inline for "
                                 f"{host}; use the OS credential store")
        hosts[host] = {}
    doc: dict = {}
    if hosts:
        doc["auths"] = dict(sorted(hosts.items()))
    helpers = set()
    store = user_cfg.get("credsStore")
    if store not in (None, ""):
        if not isinstance(store, str) or not _HELPER_NAME_RE.fullmatch(store):
            raise ProfileRefusal("the docker credsStore name is not acceptable")
        doc["credsStore"] = store
        helpers.add(store)
    cred_helpers = user_cfg.get("credHelpers")
    if cred_helpers is None:
        cred_helpers = {}
    if not isinstance(cred_helpers, dict):
        raise ProfileRefusal("the docker credHelpers is malformed")
    if cred_helpers:
        clean = {}
        for host, helper in cred_helpers.items():
            if (not isinstance(host, str) or c.has_unsafe_text(host)
                    or not isinstance(helper, str) or not _HELPER_NAME_RE.fullmatch(helper)):
                raise ProfileRefusal("a docker credHelpers entry is not acceptable")
            clean[host] = helper
            helpers.add(helper)
        doc["credHelpers"] = dict(sorted(clean.items()))
    for key in _DROPPED_KEYS:
        if _present(user_cfg.get(key)):
            findings.append(f"the user's docker config.json has '{key}' (not copied to the "
                            f"vault-owned config)")
    return SanitisedConfig(doc, findings, sorted(helpers))


def user_docker_dir() -> str:
    """The user's docker config directory (the server's own ``DOCKER_CONFIG``,
    which the agent cannot set, or ``~/.docker``).  Tests monkeypatch this."""
    return os.environ.get("DOCKER_CONFIG") or os.path.join(os.path.expanduser("~"), ".docker")


def _read_user_config() -> dict:
    path = os.path.join(user_docker_dir(), "config.json")
    if not os.path.exists(path):
        return {}
    try:
        data = json.loads(_read_limited(path, 1024 * 1024).decode("utf-8-sig"))
    except (ValueError, ProfileRefusal):
        raise ProfileRefusal("the docker config.json cannot be read as JSON")
    return data


def _listing(path: str) -> List[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _user_listings() -> dict:
    base = user_docker_dir()
    return {"contexts": _listing(os.path.join(base, "contexts", "meta")),
            "cli_plugins": _listing(os.path.join(base, "cli-plugins"))}


def config_text(doc: Mapping) -> str:
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


_cfg_lock = threading.Lock()


def ensure_config_dir(doc: Mapping) -> str:
    """The vault-owned DOCKER_CONFIG directory for *doc*: contains exactly
    ``config.json``.  Recreated if it disappeared; extra entries or changed
    content are tampering (``ProfileRefusal``).  The name is derived from the
    content hash, so two different configs never share a directory."""
    import tempfile
    text = config_text(doc)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]
    base = os.path.join(tempfile.gettempdir(), "llm-env-vault-docker", digest)
    with _cfg_lock:
        try:
            os.makedirs(base, exist_ok=True)
            if c.is_reparse_point(base):
                raise ProfileRefusal("the vault docker config directory is a link")
            names = os.listdir(base)
            path = os.path.join(base, "config.json")
            if not names:
                with open(path, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                os.chmod(path, 0o600)
                return base
            if names != ["config.json"]:
                raise ProfileRefusal("the vault docker config directory contains unexpected files")
            with open(path, "r", encoding="utf-8", newline="") as handle:
                if handle.read() != text:
                    raise ProfileRefusal("the vault docker config.json was modified")
        except OSError as exc:
            raise ProfileRefusal(f"cannot prepare the vault docker config directory "
                                 f"({exc.strerror or exc})")
    return base


# ---------------------------------------------------------------------------
# Context object: everything a docker invocation needs
# ---------------------------------------------------------------------------

@dataclass
class Ctx:
    pin: PinnedBinary
    endpoint: str
    path_dirs: List[str]
    config_dir: str
    # compose only
    project_dir: str = ""
    project: str = ""
    profiles: Tuple[str, ...] = ()
    files: Tuple[str, ...] = ()

    def env(self, injected: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        return docker_env(self.path_dirs, self.config_dir, injected=injected)

    def compose_prefix(self, files: bool = True) -> List[str]:
        """``docker -H ep compose --project-directory D -p P --profile=.. -f ..``
        (files=False -> ``-f -``)."""
        argv = [self.pin.path, "-H", self.endpoint, "compose",
                "--project-directory", self.project_dir, "-p", self.project]
        argv += [f"--profile={p}" for p in self.profiles]
        if files:
            for f in self.files:
                argv += ["-f", f]
        else:
            argv += ["-f", "-"]
        return argv


def _probe(argv, env, *, stdin: Optional[bytes] = None, pin: Optional[PinnedBinary] = None,
           timeout: float = SMALL_TIMEOUT, max_output: int = c.PROBE_MAX_OUTPUT) -> c.ProbeResult:
    return c.run_probe(argv, env, timeout=timeout, max_output=max_output,
                       stdin_bytes=stdin, expect_sha256=pin.sha256 if pin else None)


def _run_config(ctx: Ctx, values: Mapping[str, str], fmt: str) -> bytes:
    """``compose config`` (YAML or ``--format json``) with *values* injected;
    stdout only.  Raises ``ProfileRefusal`` when it fails (fail closed)."""
    argv = ctx.compose_prefix(files=True) + ["config"]
    if fmt == "json":
        argv += ["--format", "json"]
    result = _probe(argv, ctx.env(values), pin=ctx.pin, timeout=CONFIG_TIMEOUT,
                    max_output=CONFIG_MAX_OUTPUT)
    if not result.ok or not result.stdout.strip():
        raise ProfileRefusal("the compose model could not be produced: " +
                             (result.failure_reason() if not result.ok
                              else "empty output"))
    return result.stdout


def _sentinels(names: Iterable[str]) -> Dict[str, str]:
    return {n: sentinel_for(n) for n in names}


# ---------------------------------------------------------------------------
# Probes used at approval time
# ---------------------------------------------------------------------------

def _probe_text(ctx_like_pin: PinnedBinary, env, argv_tail: List[str],
                what: str, *, accept_failure: bool = False) -> str:
    result = _probe([ctx_like_pin.path] + argv_tail, env, pin=ctx_like_pin)
    if not result.ok and not (accept_failure and result.stdout.strip()):
        raise ProfileRefusal(f"cannot determine {what}: {result.failure_reason()}")
    return result.stdout_text()


def endpoint_allowed(endpoint) -> bool:
    return isinstance(endpoint, str) and (endpoint in _ENDPOINT_FIXED
                                          or bool(_ENDPOINT_ROOTLESS.fullmatch(endpoint)))


def _resolve_endpoint(pin: PinnedBinary, path_dirs) -> str:
    """``docker context inspect`` with DOCKER_* removed; DOCKER_CONFIG is only
    our own pointer at the user's config dir (the contexts live there)."""
    env = docker_env(path_dirs, user_docker_dir())
    text = _probe_text(pin, env, ["context", "inspect", "--format",
                                  "{{.Endpoints.docker.Host}}"], "the docker endpoint")
    endpoint = text.strip()
    if not endpoint_allowed(endpoint):
        raise ProfileRefusal(f"the docker endpoint {endpoint[:80]!r} is not an allowed local "
                             f"engine endpoint")
    return endpoint


def _plugin_search_dirs(config_dir: str) -> List[str]:
    dirs = [os.path.join(config_dir, "cli-plugins")]
    if os.name == "nt":
        for var in ("ProgramData", "ProgramFiles"):
            root = os.environ.get(var)
            if root:
                dirs.append(os.path.join(root, "Docker", "cli-plugins"))
    else:
        dirs += ["/usr/local/lib/docker/cli-plugins", "/usr/local/libexec/docker/cli-plugins",
                 "/usr/lib/docker/cli-plugins", "/usr/libexec/docker/cli-plugins"]
    return dirs


def _resolve_compose_plugin(pin, path_dirs, config_dir, endpoint) -> PinnedBinary:
    env = docker_env(path_dirs, config_dir)
    text = _probe_text(pin, env, ["-H", endpoint, "info", "--format",
                                  "{{json .ClientInfo.Plugins}}"],
                       "the docker plugins", accept_failure=True)
    try:
        plugins = json.loads(text)
    except ValueError:
        raise ProfileRefusal("the docker plugin list could not be read")
    path = None
    for plugin in plugins or []:
        if isinstance(plugin, dict) and plugin.get("Name") == "compose":
            path = plugin.get("Path")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ProfileRefusal("the docker compose plugin was not found")
    for directory in _plugin_search_dirs(config_dir):
        names = [n for n in _listing(directory) if n.lower().startswith("docker-compose")]
        if names and not c.dir_not_user_writable(directory):
            raise ProfileRefusal(f"{directory} is user-writable and holds a docker-compose "
                                 f"plugin; it could shadow the real one")
    try:
        return c.resolve_pinned_binary(path)
    except ProfileRefusal as exc:
        raise ProfileRefusal(f"the compose plugin cannot be pinned: {exc.reason}")


def _desktop_name(pin, ctx_env, endpoint) -> Optional[str]:
    result = _probe([pin.path, "-H", endpoint, "version", "--format",
                     "{{.Server.Platform.Name}}"], ctx_env, pin=pin)
    return result.stdout_text().strip() if result.ok else None


def _compose_version(pin, env, endpoint) -> str:
    return _probe_text(pin, env, ["-H", endpoint, "compose", "version", "--short"],
                       "the compose version").strip()


def _common_snapshot(cwd: str) -> Tuple[dict, Ctx]:
    """Everything shared by both families.  Raises ``ProfileRefusal``."""
    pin = c.resolve_pinned_binary("docker")
    path_dirs = c.pinned_path_dirs(extra=[os.path.dirname(pin.path)])
    sanitised = sanitise_docker_config(_read_user_config())
    search = os.pathsep.join(path_dirs)
    helpers = {}
    for name in sanitised.helpers:
        try:
            helpers[name] = c.resolve_pinned_binary(f"docker-credential-{name}",
                                                    search_path=search).to_dict()
        except ProfileRefusal as exc:
            raise ProfileRefusal(f"credential helper {name} cannot be pinned: {exc.reason}")
    config_dir = ensure_config_dir(sanitised.vault_doc)
    endpoint = _resolve_endpoint(pin, path_dirs)
    env = docker_env(path_dirs, config_dir)
    plugin = _resolve_compose_plugin(pin, path_dirs, config_dir, endpoint)
    version_text = _compose_version(pin, env, endpoint)
    problem = compose_version_problem(version_text)
    if problem:
        raise ProfileRefusal(problem)
    desktop = _desktop_name(pin, env, endpoint)
    problem = desktop_problem(desktop)
    if problem:
        raise ProfileRefusal(problem)
    snap = {
        "v": SNAPSHOT_VERSION,
        "docker": pin.to_dict(),
        "plugin": plugin.to_dict(),
        "compose_version": version_text,
        "desktop": desktop,
        "path_dirs": list(path_dirs),
        "endpoint": endpoint,
        "config": {"vault": sanitised.vault_doc, "findings": sanitised.findings},
        "cred_helpers": helpers,
        "listings": _user_listings(),
        "cwd_dlls": c.snapshot_cwd_dlls(cwd),
    }
    return snap, Ctx(pin=pin, endpoint=endpoint, path_dirs=list(path_dirs), config_dir=config_dir)


def _ctx_from_snapshot(snap: Mapping) -> Ctx:
    return Ctx(pin=PinnedBinary.from_dict(snap["docker"]), endpoint=snap["endpoint"],
               path_dirs=list(snap["path_dirs"]), config_dir=ensure_config_dir(snap["config"]["vault"]))


# ---------------------------------------------------------------------------
# match / snapshot / describe / label
# ---------------------------------------------------------------------------

def _inside(root: str, path: str) -> bool:
    root_n = os.path.normcase(os.path.realpath(root))
    path_n = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_n, path_n]) == root_n
    except ValueError:
        return False


def _compose_shape(cmd: ComposeCommand, cwd: str) -> dict:
    files = []
    for raw in cmd.files:
        full = raw if os.path.isabs(raw) else os.path.join(cwd, raw)
        real = os.path.realpath(full)
        if not os.path.isfile(real) or not _inside(cwd, real):
            raise _Unsupported("a compose file is not a regular file inside the project root")
        if c.is_reparse_point(full):
            raise _Unsupported("a compose file is a link")
        files.append(real)
    if len(set(os.path.normcase(f) for f in files)) != len(files):
        raise _Unsupported("a compose file is listed twice")
    return {"family": "compose", "project": cmd.project, "profiles": list(cmd.profiles),
            "files": files, "project_dir": os.path.dirname(files[0])}


def _shape_for(req: Request):
    """``(parsed command, shape)``; ``ArgvRejected``/``_Unsupported`` if outside."""
    cmd = parse_command(req.command)
    if isinstance(cmd, ComposeCommand):
        return cmd, _compose_shape(cmd, req.cwd)
    ref = parse_reference(cmd.image)
    return cmd, image_shape(cmd, ref)


def match(req: Request) -> Optional[dict]:
    if c.injected_name_problem(req.only_vars):
        return None
    try:
        _cmd, shape = _shape_for(req)
    except ProfileRefusal:
        return None
    return shape


_snapshot_cache: Dict[str, Tuple[float, dict]] = {}
_SNAPSHOT_CACHE_SECONDS = 120.0


def _cache_key(req: Request, candidate: dict) -> str:
    return json.dumps([list(req.command), req.cwd, list(req.only_vars), candidate],
                      sort_keys=True)


def snapshot(req: Request, candidate: dict) -> dict:
    """Approval-time snapshot (probes run, no vault secrets).  Raises
    ``ProfileRefusal`` when the request cannot be always-allowed -- the caller
    then offers no checkbox."""
    problem = c.injected_name_problem(req.only_vars)
    if problem:
        raise ProfileRefusal(problem)
    cmd = parse_command(req.command)
    snap, ctx = _common_snapshot(req.cwd)
    snap["family"] = candidate["family"]
    if candidate["family"] == "compose":
        _compose_snapshot(snap, ctx, candidate, req)
    _snapshot_cache[_cache_key(req, candidate)] = (time.monotonic(), snap)
    if isinstance(cmd, ComposeCommand):
        pass
    return snap


def _tracked_hashes(scan: ScanResult, project_dir: str) -> Dict[str, Optional[str]]:
    paths = list(scan.files) + list(scan.env_files) + [os.path.join(project_dir, ".env")]
    return {os.path.normcase(p): c.hash_file(p) for p in paths}


def _compose_snapshot(snap: dict, ctx: Ctx, shape: dict, req: Request) -> None:
    scan = scan_compose_files(shape["files"])
    if not scan.ok:
        raise ProfileRefusal("compose files: " + "; ".join(scan.problems[:3]))
    ctx.project_dir = shape["project_dir"]
    ctx.project = shape["project"]
    ctx.profiles = tuple(shape["profiles"])
    ctx.files = tuple(shape["files"])
    sentinels = _sentinels(req.only_vars)
    yaml_s = _run_config(ctx, sentinels, "yaml")
    json_s = _run_config(ctx, sentinels, "json")
    try:
        model = json.loads(json_s.decode("utf-8"))
    except ValueError:
        raise ProfileRefusal("the compose model is not valid JSON")
    lint = lint_model(model, req.only_vars)
    if lint.refused:
        raise ProfileRefusal("not eligible for always-allow: " + "; ".join(lint.class_a[:3]))
    if any(is_remote_reference(s) for s in _json_contexts(model)):
        raise ProfileRefusal("a build context in the model is remote")
    snap["compose"] = {
        "anchor_yaml": hashlib.sha256(yaml_s).hexdigest(),
        "anchor_json": hashlib.sha256(json_s).hexdigest(),
        "tracked": _tracked_hashes(scan, shape["project_dir"]),
        "buildable": lint.buildable,
        "services": lint.services,
        "class_b": lint.class_b,
    }


def _json_contexts(model) -> List[str]:
    out = []
    for svc in (model.get("services") or {}).values():
        build = svc.get("build") if isinstance(svc, dict) else None
        if isinstance(build, dict):
            if isinstance(build.get("context"), str):
                out.append(build["context"])
    return out


def _pattern_text(req: Request, shape: Mapping) -> str:
    cmd = parse_command(req.command)
    if shape["family"] == "image":
        ns = shape["namespace"]
        where = f"{shape['registry']}/{ns + '/' if ns else ''}*"
        tags = "any tag" if shape.get("allow_latest") else "any tag except 'latest'"
        return f"docker {shape['op']} [--platform=...] [-q] {where} ({tags})"
    files = " ".join(f"-f {f}" for f in shape["files"])
    profiles = "".join(f" --profile {p}" for p in shape["profiles"])
    subs = "|".join(COMPOSE_SUBS)
    return f"docker compose {files} -p {shape['project']}{profiles} {subs} [allowed flags] [service...]"


def describe(req: Request, candidate: dict) -> str:
    """First line: the canonical pattern the entry matches; then findings and
    the truth-in-labelling warnings."""
    lines = [_pattern_text(req, candidate)]
    key = _cache_key(req, candidate)
    cached = _snapshot_cache.get(key)
    if cached and time.monotonic() - cached[0] <= _SNAPSHOT_CACHE_SECONDS:
        snap = cached[1]
    else:
        snap = snapshot(req, candidate)
    lines.append(f"Engine endpoint: {snap['endpoint']} (always passed as -H); "
                 f"Docker Compose {snap['compose_version']}"
                 + (f"; {snap['desktop']}" if snap.get("desktop") else ""))
    for finding in snap["config"]["findings"]:
        lines.append(f"Note: {finding}")
    if candidate["family"] == "compose":
        info = snap["compose"]
        lines.append("Allowed: " + ", ".join(COMPOSE_SUBS)
                     + ". Vault values are used only for 'up'; pull, ps, logs, down and "
                       "build receive none.")
        if info["buildable"]:
            lines.append("Build tier: services that may be built: " + ", ".join(info["buildable"])
                         + ". Builds receive no vault values.")
        for finding in info["class_b"]:
            lines.append(f"WARNING: {finding}")
    else:
        lines.append("Vault values are not passed to pull/push; registry credentials come from "
                     "the OS credential store.")
    lines.append("Containers for non-built services run images the vault does not pin, and the "
                 "agent can read container env and logs. The agent can obtain these values; use "
                 "test-grade credentials.")
    return "\n".join(lines)


def label(req: Request, candidate: dict) -> str:
    if candidate["family"] == "image":
        ns = candidate["namespace"]
        return f"docker {candidate['op']} {candidate['registry']}/{ns + '/' if ns else ''}*"
    name = os.path.basename(candidate["files"][0])
    extra = f" +{len(candidate['files']) - 1}" if len(candidate["files"]) > 1 else ""
    return f"docker compose {candidate['project']} ({name}{extra})"


# ---------------------------------------------------------------------------
# Drift checks (arm time and run time)
# ---------------------------------------------------------------------------

def _entry_parts(entry) -> Tuple[dict, dict]:
    snap, shape = entry.get("snapshot"), entry.get("shape")
    if (not isinstance(snap, dict) or not isinstance(shape, dict)
            or snap.get("v") != SNAPSHOT_VERSION or snap.get("family") != shape.get("family")):
        raise ProfileRefusal("the approved docker snapshot is missing or from another version")
    return snap, shape


def _static_drift(entry) -> Optional[str]:
    """Cheap checks (file reads and hashes only): binaries, versions, endpoint,
    user config, listings, DLLs, compose input files.  Returns a reason."""
    try:
        snap, shape = _entry_parts(entry)
        for label_, record in (("docker", snap["docker"]), ("compose plugin", snap["plugin"])):
            problem = c.verify_pinned_binary(record)
            if problem:
                return problem
        for name, record in snap["cred_helpers"].items():
            problem = c.verify_pinned_binary(record)
            if problem:
                return f"credential helper {name}: {problem}"
        problem = compose_version_problem(snap["compose_version"]) or \
            desktop_problem(snap.get("desktop"))
        if problem:
            return problem
        if not endpoint_allowed(snap["endpoint"]):
            return "the approved docker endpoint is not allowed"
        sanitised = sanitise_docker_config(_read_user_config())
        if sanitised.vault_doc != snap["config"]["vault"]:
            return "the docker config.json (registries/credential store) changed since it was approved"
        for name in sanitised.helpers:
            if name not in snap["cred_helpers"]:
                return f"credential helper {name} was not approved"
        ensure_config_dir(snap["config"]["vault"])
        if _user_listings() != snap["listings"]:
            return "the docker contexts or cli-plugins directory changed since approval"
        problem = c.verify_cwd_dlls(entry.get("cwd") or "", snap.get("cwd_dlls") or {})
        if problem:
            return problem
        if shape["family"] == "compose":
            scan = scan_compose_files(shape["files"])
            if not scan.ok:
                return "compose files: " + "; ".join(scan.problems[:3])
            if _tracked_hashes(scan, shape["project_dir"]) != snap["compose"]["tracked"]:
                return "the compose files (or .env / env_file files) changed since approval"
    except ProfileRefusal as exc:
        return exc.reason
    except (KeyError, TypeError, ValueError):
        return "the approved docker snapshot is malformed"
    return None


def check_snapshot(entry) -> Tuple[bool, Optional[str]]:
    """Arm-time check (runs under the vault lock: file reads and hashes, no
    subprocess)."""
    reason = _static_drift(entry)
    return (reason is None), reason


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def _load_run_secrets(entry: Mapping, req: Request) -> Dict[str, str]:
    """The request's real values from the in-memory armed cache.  Tests
    monkeypatch this."""
    from .. import trust
    cached = trust.cached_secrets(("always_allow", entry["id"]))
    if not cached or not set(req.only_vars) <= set(cached):
        raise ProfileRefusal("the armed values are unavailable")
    return {name: cached[name] for name in req.only_vars}


def _same_files(a: Iterable[str], b: Iterable[str]) -> bool:
    return [os.path.normcase(x) for x in a] == [os.path.normcase(x) for x in b]


def _shape_applies(shape: Mapping, mine: Mapping) -> bool:
    if shape.get("family") != mine.get("family"):
        return False
    if shape["family"] == "image":
        return (shape.get("op") == mine["op"] and shape.get("registry") == mine["registry"])
    return (shape.get("project") == mine["project"]
            and list(shape.get("profiles", [])) == mine["profiles"]
            and _same_files(shape.get("files", []), mine["files"]))


def verify(entry, req: Request) -> Verdict:
    try:
        cmd = parse_command(req.command)
        shape = entry.get("shape") or {}
        if isinstance(cmd, ComposeCommand):
            mine = _compose_shape(cmd, req.cwd)
            ref = None
        else:
            ref = parse_reference(cmd.image)
            mine = image_shape(cmd, ref)
        if not _shape_applies(shape, mine):
            return Verdict(ok=False)
        if not set(req.only_vars) <= set(entry.get("only_vars") or ()):
            return Verdict(ok=False)               # more variables than were approved
        if ref is not None:
            problem = image_problem(shape, cmd, ref)
            if problem:
                return Verdict(ok=False)               # outside the approved clamp -> dialog
    except ProfileRefusal:
        return Verdict(ok=False)
    reason = _static_drift(entry)
    if reason:
        return Verdict(ok=False, reason=reason)
    try:
        snap = entry["snapshot"]
        ctx = _ctx_from_snapshot(snap)
        problem = c.verify_pinned_binary(snap["docker"])
        if problem:
            return Verdict(ok=False, reason=problem)
        _best_effort_desktop(ctx, snap.get("desktop"))
        if ref is not None:
            return _image_verdict(ctx, cmd)
        return _compose_verdict(entry, snap, shape, ctx, cmd, req)
    except _Unsupported:
        return Verdict(ok=False)
    except ArgvRejected:
        return Verdict(ok=False)
    except ProfileRefusal as exc:
        return Verdict(ok=False, reason=exc.reason)


def _best_effort_desktop(ctx: Ctx, approved_desktop=None) -> None:
    """A Docker Desktop below the floor is refused.  A failed probe is only let
    through when the entry was not approved on a Docker Desktop (the command
    itself then fails if the daemon is unreachable); for an entry approved on
    Docker Desktop an unreadable version is refused, never skipped."""
    name = _desktop_name(ctx.pin, ctx.env(), ctx.endpoint)
    if name is None and desktop_problem_applies(approved_desktop):
        raise ProfileRefusal("the Docker Desktop version could not be re-checked")
    problem = desktop_problem(name)
    if problem:
        raise ProfileRefusal(problem)


def _image_verdict(ctx: Ctx, cmd: ImageCommand) -> Verdict:
    argv = [ctx.pin.path, "-H", ctx.endpoint, cmd.op] + cmd.flags.canonical_flag_tokens() \
        + [cmd.image]
    return Verdict(ok=True, argv=argv, env=ctx.env(), replace_env=True, inject_secrets=False)


def _compose_global_tokens(cmd: ComposeCommand) -> List[str]:
    keep = [s for s in _GLOBAL_SPECS if s.key in ("--ansi", "--progress", "--dry-run")]
    view = c.ParsedArgv(tuple(keep), {k: v for k, v in cmd.globals.flags.items()
                                      if k in {s.key for s in keep}})
    return view.canonical_flag_tokens()


def _compose_verdict(entry, snap, shape, ctx: Ctx, cmd: ComposeCommand, req: Request) -> Verdict:
    ctx.project_dir = shape["project_dir"]
    ctx.project = shape["project"]
    ctx.profiles = tuple(shape["profiles"])
    ctx.files = tuple(shape["files"])
    info = snap["compose"]
    approved_vars = tuple(entry["only_vars"])
    sentinels = _sentinels(approved_vars)
    yaml_s = _run_config(ctx, sentinels, "yaml")
    if hashlib.sha256(yaml_s).hexdigest() != info["anchor_yaml"]:
        raise ProfileRefusal("the compose model changed since it was approved")
    json_s = _run_config(ctx, sentinels, "json")
    if hashlib.sha256(json_s).hexdigest() != info["anchor_json"]:
        raise ProfileRefusal("the compose model (JSON form) changed since it was approved")
    try:
        model = json.loads(json_s.decode("utf-8"))
    except ValueError:
        raise ProfileRefusal("the compose model is not valid JSON")
    lint = lint_model(model, approved_vars)
    if lint.refused:
        raise ProfileRefusal("the compose model is no longer eligible: " + "; ".join(lint.class_a[:3]))
    if not set(lint.buildable) <= set(info["buildable"]):
        raise ProfileRefusal("the set of buildable services changed since approval")
    if any(is_remote_reference(s) for s in _json_contexts(model)):
        raise ProfileRefusal("a build context in the model is remote")
    # ---- request-level rules (violations -> normal dialog, not a drift) ----
    unknown = [s for s in cmd.services if s not in lint.services]
    if unknown:
        raise ArgvRejected(f"unknown service {unknown[0]!r}")
    if cmd.sub == "build" or cmd.flags.has("--build"):
        if not info["buildable"]:
            raise ArgvRejected("this entry has no approved buildable services")
        outside = [s for s in cmd.services if s not in info["buildable"]]
        if outside:
            raise ArgvRejected(f"service {outside[0]!r} is not an approved buildable service")
    if cmd.sub == "up":
        stdin, argv_env = _real_model(entry, ctx, req, yaml_s, info)
    else:
        stdin, argv_env = yaml_s, ctx.env()
    argv = (ctx.compose_prefix(files=False)[:4] + _compose_global_tokens(cmd)
            + ctx.compose_prefix(files=False)[4:] + [cmd.sub]
            + cmd.flags.canonical_flag_tokens() + list(cmd.services))
    return Verdict(ok=True, argv=argv, env=argv_env, replace_env=True, stdin=stdin,
                   inject_secrets=False)


def _real_model(entry, ctx: Ctx, req: Request, approved_yaml: bytes, info) -> Tuple[bytes, dict]:
    """The S -> R -> S' bracket for ``up`` (S was just verified by the caller)."""
    if set(req.only_vars) != set(entry["only_vars"]):
        # S and S' anchor every approved variable; an R built from fewer would
        # leave the rest unset and could resolve defaults the lint never saw.
        raise ArgvRejected("up needs exactly the approved variables")
    values = _load_run_secrets(entry, req)
    real = _run_config(ctx, values, "yaml")
    twin = _run_config(ctx, _sentinels(entry["only_vars"]), "yaml")
    if (hashlib.sha256(twin).hexdigest() != info["anchor_yaml"]
            or hashlib.sha256(approved_yaml).hexdigest() != info["anchor_yaml"]):
        raise ProfileRefusal("the compose files changed while the model was being read")
    if SENTINEL_PREFIX.encode() in real:
        raise ProfileRefusal("the real compose model still contains a sentinel")
    return real, ctx.env()
