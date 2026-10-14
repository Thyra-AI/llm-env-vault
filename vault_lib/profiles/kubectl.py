"""The kubectl profile for persistent "always allow" entries (plan 2.4.0 5.3).

Read-mostly kubectl (``get``, ``describe``, ``logs``, ``rollout status``) in one
namespace, plus ``apply -f <file>`` of one hash-pinned manifest.  Nothing else
is wildcarded; every other kubectl command stays an exact entry or a dialog.

What an entry pins (``shape``, feeds the entry id)
    ``access``     ``"read"`` or ``"apply"``
    ``context``    the kubeconfig context approved (a context switch needs
                   re-approval: the id changes)
    ``namespace``  the namespace pin (``None`` for ``scope == "all"``)
    ``scope``      read only: ``"namespace"`` or ``"all"`` (approved with
                   ``-A`` or a cluster-scoped kind)
    ``file``       apply only: the manifest's real path

What the snapshot holds (re-verified at arm time and before every spawn)
    kubectl binary pin, version, pinned PATH, the vault-owned SANITISED
    kubeconfig (sealed text + SHA-256), the exec credential plugin (absolute
    path, pinned binary), the generated kuberc, the cwd DLLs and, for apply,
    the approved manifest hash.

Where the sanitised kubeconfig lives (state it plainly)
    It contains the credentials of the one context (a token user's token, a
    client key).  The text is kept sealed in the entry snapshot (the vault
    body is AES-GCM) and written to a content-addressed file in a vault-owned
    private directory (``STATE_DIR``/kubectl, user-only ACL as best effort,
    mode 0600 on POSIX).  The agent runs as the same user, so while the copy
    exists it can read it: if the original is the user's own kubeconfig that
    adds no exposure, but the vault does NOT claim to hide cluster
    credentials.  A kubeconfig that is itself a vault secret is unsupported.
    Before every spawn the file is rewritten from the sealed text if it is
    missing or differs (a missing kubeconfig makes kubectl fall back silently
    to ``http://localhost:8080``).

Contract notes for the server (WU5/W3)
    ``verify()`` returns a :class:`KubectlVerdict` (a ``Verdict`` subclass):
    ``Verdict.stdin`` (base field) holds the bytes to write to the child's stdin
    (apply feeds the approved manifest bytes through ``-f -``), ``wall_clock`` is the number of
    seconds after which the child must be killed (kubectl's own
    ``--request-timeout`` does not bound a dead server), ``cleanup_paths`` are
    per-run directories to delete after the run, ``stderr_fatal_markers`` must
    not appear in the child's stderr (kuberc strict-decoding fail-open: mark
    the result as an error).  ``stderr_problem(text)`` implements the check.

Everything here runs under the vault lock: local files and bounded kubectl
subprocesses only, never a vault call.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets as _secrets
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import Request, Verdict
from . import _common as c
from ._common import ArgvRejected, FlagSpec, ProfileRefusal, tokenize_argv

kind = "kubectl"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KUBECTL_PROGRAM = "kubectl"                  # tests may point this elsewhere
KUBERC_MIN_VERSION = (1, 35)                 # credentialPluginPolicy exists from here
REQUEST_TIMEOUT = "30s"
ROLLOUT_TIMEOUT_CAP = 300                    # seconds
LOGS_TAIL_MAX = 5000
LIMIT_BYTES_MAX = 10 * 1024 * 1024
MANIFEST_MAX_BYTES = 1024 * 1024
MANIFEST_MAX_OBJECTS = 200
WALL_CLOCK = {"get": 60, "describe": 60, "logs": 120, "apply": 180}
ROLLOUT_WALL_SLACK = 30
CACHE_MAX_AGE_SECONDS = 24 * 3600
STDERR_FATAL_MARKERS = ("ignoring strict decoding",)
NORMALISER_TIMEOUT = 30.0
MANIFEST_HINT_MAX = 160
NORMALISER_MAX_OUTPUT = 8 * 1024 * 1024

# Test-only: relocate the private state directory (default: per-user state dir).
STATE_DIR: Optional[str] = None

_DNS_LABEL = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
_DNS_SUBDOMAIN = rf"{_DNS_LABEL}(\.{_DNS_LABEL})*"
_DNS_LABEL_RE = re.compile(_DNS_LABEL)
_DNS_SUBDOMAIN_RE = re.compile(_DNS_SUBDOMAIN)
_CONTEXT_RE = re.compile(r"[A-Za-z0-9._:@/+=-]{1,253}")
_SEL_KEY = r"([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?"
_SEL_VAL = r"([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?"
_SEL_REQ_RE = re.compile(rf"({_SEL_KEY})==?({_SEL_VAL})")
_DURATION_RE = re.compile(r"([0-9]{1,6})([smh])")

# canonical plural -> accepted spellings
_KIND_SPELLINGS = {
    "pods": ("pods", "pod", "po"),
    "deployments": ("deployments", "deployment", "deploy"),
    "replicasets": ("replicasets", "replicaset", "rs"),
    "statefulsets": ("statefulsets", "statefulset", "sts"),
    "daemonsets": ("daemonsets", "daemonset", "ds"),
    "jobs": ("jobs", "job"),
    "cronjobs": ("cronjobs", "cronjob", "cj"),
    "services": ("services", "service", "svc"),
    "endpoints": ("endpoints", "endpoint", "ep"),
    "endpointslices": ("endpointslices", "endpointslice"),
    "ingresses": ("ingresses", "ingress", "ing"),
    "configmaps": ("configmaps", "configmap", "cm"),
    "events": ("events", "event", "ev"),
    "namespaces": ("namespaces", "namespace", "ns"),
    "nodes": ("nodes", "node", "no"),
    "persistentvolumeclaims": ("persistentvolumeclaims", "persistentvolumeclaim", "pvc"),
    "horizontalpodautoscalers": ("horizontalpodautoscalers", "horizontalpodautoscaler", "hpa"),
    "networkpolicies": ("networkpolicies", "networkpolicy", "netpol"),
}
KIND_ALIASES: Dict[str, str] = {alias: plural for plural, names in _KIND_SPELLINGS.items()
                                for alias in names}
CLUSTER_SCOPED = frozenset({"namespaces", "nodes"})

# ``kind/name`` prefixes: logs accepts anything with pods; rollout status three.
_LOGS_PREFIXES = {"pod": "pod", "po": "pod", "deployment": "deployment", "deploy": "deployment",
                  "replicaset": "replicaset", "rs": "replicaset", "statefulset": "statefulset",
                  "sts": "statefulset", "daemonset": "daemonset", "ds": "daemonset",
                  "job": "job"}
_ROLLOUT_PREFIXES = {"deployment": "deployment", "deploy": "deployment",
                     "statefulset": "statefulset", "sts": "statefulset",
                     "daemonset": "daemonset", "ds": "daemonset"}


class KubeconfigRefused(ProfileRefusal):
    """The kubeconfig cannot be reduced to a safe vault-owned copy."""


class ManifestRefused(ProfileRefusal):
    """The apply manifest breaks the object policy (or cannot be normalised)."""


@dataclass(frozen=True)
class KubectlVerdict(Verdict):
    """``Verdict`` plus what a kubectl run needs beyond argv/env (see the module
    docstring).  The base fields keep their contract meaning."""
    wall_clock: Optional[float] = None
    cleanup_paths: Tuple[str, ...] = ()
    stderr_fatal_markers: Tuple[str, ...] = STDERR_FATAL_MARKERS


def stderr_problem(text) -> Optional[str]:
    """Reason a kubectl run's stderr must be treated as an error even if the
    exit code was 0 (the kuberc fail-open signal), else None."""
    if not isinstance(text, str):
        return None
    low = text.lower()
    for marker in STDERR_FATAL_MARKERS:
        if marker in low:
            return ("kubectl reported that the vault-generated kuberc was not strictly "
                    "decoded, so the credential-plugin policy may not have applied")
    return None


# ---------------------------------------------------------------------------
# Argv grammar
# ---------------------------------------------------------------------------

def _check_selector(value: str) -> Optional[str]:
    if len(value) > 500:
        return "the label selector is too long"
    for requirement in value.split(","):
        if not _SEL_REQ_RE.fullmatch(requirement):
            return "only equality label selectors (key=value) are allowed"
    return None


def _check_tail(value: str) -> Optional[str]:
    return None if 0 <= int(value) <= LOGS_TAIL_MAX else f"--tail must be at most {LOGS_TAIL_MAX}"


def _check_limit(value: str) -> Optional[str]:
    return (None if 1 <= int(value) <= LIMIT_BYTES_MAX
            else f"--limit-bytes must be between 1 and {LIMIT_BYTES_MAX}")


def _check_label(value: str) -> Optional[str]:
    return None if len(value) <= 63 else "a namespace or container name is at most 63 characters"


def _check_file_arg(value: str) -> Optional[str]:
    if value == "-" or re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", value) \
            or value.startswith(("\\\\", "//")):
        return "apply -f must name a local file (no URL, stdin, or network path)"
    return None


_NS = FlagSpec(long="--namespace", short="-n", value=True, pattern=_DNS_LABEL, check=_check_label)
_ALL = FlagSpec(long="--all-namespaces", short="-A")
_SEL = FlagSpec(long="--selector", short="-l", value=True, check=_check_selector)
_OUT = FlagSpec(long="--output", short="-o", value=True, pattern=r"wide|name|json|yaml")
_NOHDR = FlagSpec(long="--no-headers")
_LABELS = FlagSpec(long="--show-labels")
_CONTAINER = FlagSpec(long="--container", short="-c", value=True, pattern=_DNS_LABEL,
                    check=_check_label)
_TAIL = FlagSpec(long="--tail", value=True, pattern=r"[0-9]{1,4}", check=_check_tail)
_SINCE = FlagSpec(long="--since", value=True, pattern=r"[1-9][0-9]{0,5}[smh]")
_PREVIOUS = FlagSpec(long="--previous")
_TIMESTAMPS = FlagSpec(long="--timestamps")
_ALLCONT = FlagSpec(long="--all-containers")
_LIMIT = FlagSpec(long="--limit-bytes", value=True, pattern=r"[0-9]{1,8}", check=_check_limit)
_TIMEOUT = FlagSpec(long="--timeout", value=True, pattern=r"[0-9]{1,6}[smh]")
_FILE = FlagSpec(long="--filename", short="-f", value=True, check=_check_file_arg)
_DRY = FlagSpec(long="--dry-run", value=True, pattern=r"client|server")
_VALIDATE = FlagSpec(long="--validate", value=True, pattern=r"strict")

_GET_SPECS = (_NS, _ALL, _SEL, _OUT, _NOHDR, _LABELS)
_DESCRIBE_SPECS = (_NS, _SEL)
_LOGS_SPECS = (_NS, _CONTAINER, _TAIL, _SINCE, _PREVIOUS, _TIMESTAMPS, _ALLCONT, _LIMIT)
_ROLLOUT_SPECS = (_NS, _TIMEOUT)
_APPLY_SPECS = (_NS, _FILE, _DRY, _VALIDATE)

_SUBCOMMANDS = frozenset({"get", "describe", "logs", "rollout", "apply"})


@dataclass(frozen=True)
class Parsed:
    """A request that satisfies the grammar.  ``args`` is the canonical argv
    after the injected global flags, WITHOUT any namespace flag (added by
    :meth:`render`)."""
    access: str                      # "read" | "apply"
    sub: str                         # get | describe | logs | rollout | apply
    args: Tuple[str, ...]
    namespace: Optional[str]         # explicit -n
    all_namespaces: bool
    cluster_scoped: bool
    file: Optional[str]              # apply: the -f argument as given
    wall_clock: int

    def render(self, namespace: Optional[str]) -> List[str]:
        out = list(self.args)
        if namespace is not None:
            out.append(f"--namespace={namespace}")
        if self.all_namespaces:
            out.append("--all-namespaces")
        return out


def _is_kubectl(token: str) -> bool:
    if not isinstance(token, str) or "/" in token or "\\" in token:
        return False
    low = token.lower()
    return low in ("kubectl", "kubectl.exe")


def _dns_subdomain(name: str, what: str) -> str:
    if len(name) > 253 or not _DNS_SUBDOMAIN_RE.fullmatch(name):
        raise ArgvRejected(f"{what} {name!r} is not a valid Kubernetes name")
    return name


def _kind_slot(token: str) -> str:
    plural = KIND_ALIASES.get(token)
    if plural is None:
        raise ArgvRejected(f"resource kind {token!r} is not allowed")
    return plural


def _duration_seconds(text: str) -> int:
    m = _DURATION_RE.fullmatch(text)
    if not m:
        raise ArgvRejected(f"bad duration {text!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def _parse_get_like(tokens, specs, sub: str) -> Parsed:
    parsed = tokenize_argv(tokens, specs, min_positionals=1, max_positionals=2)
    plural = _kind_slot(parsed.positionals[0])
    name = None
    if len(parsed.positionals) == 2:
        name = _dns_subdomain(parsed.positionals[1], "resource name")
        if parsed.has("--selector"):
            raise ArgvRejected("a name and a label selector cannot be combined")
    all_ns = parsed.has("--all-namespaces")
    if all_ns and parsed.has("--namespace"):
        raise ArgvRejected("-A and -n cannot be combined")
    if all_ns and name:
        raise ArgvRejected("-A cannot be combined with a name")
    args = [sub, plural] + ([name] if name else [])
    for spec in specs:
        if spec.key in ("--namespace", "--all-namespaces"):
            continue
        for value in parsed.flags.get(spec.key, ()):
            args.extend(spec.canonical(value))
    return Parsed("read", sub, tuple(args), parsed.value("--namespace"), all_ns,
                  plural in CLUSTER_SCOPED, None, WALL_CLOCK[sub])


def _parse_logs(tokens) -> Parsed:
    parsed = tokenize_argv(tokens, _LOGS_SPECS, min_positionals=1, max_positionals=1)
    target = parsed.positionals[0]
    if "/" in target:
        prefix, _sep, name = target.partition("/")
        if prefix not in _LOGS_PREFIXES:
            raise ArgvRejected(f"logs target kind {prefix!r} is not allowed")
        target = f"{_LOGS_PREFIXES[prefix]}/{_dns_subdomain(name, 'resource name')}"
    else:
        target = _dns_subdomain(target, "pod name")
    args = ["logs", target]
    for spec in _LOGS_SPECS:
        if spec.key == "--namespace":
            continue
        for value in parsed.flags.get(spec.key, ()):
            args.extend(spec.canonical(value))
    if not parsed.has("--tail"):
        args.append(f"--tail={LOGS_TAIL_MAX}")
    if not parsed.has("--limit-bytes"):
        args.append(f"--limit-bytes={LIMIT_BYTES_MAX}")
    return Parsed("read", "logs", tuple(args), parsed.value("--namespace"), False, False,
                  None, WALL_CLOCK["logs"])


def _parse_rollout(tokens) -> Parsed:
    if not tokens or tokens[0] != "status":
        raise ArgvRejected("only 'rollout status' is allowed")
    parsed = tokenize_argv(tokens[1:], _ROLLOUT_SPECS, min_positionals=1, max_positionals=1)
    target = parsed.positionals[0]
    prefix, sep, name = target.partition("/")
    if not sep or prefix not in _ROLLOUT_PREFIXES:
        raise ArgvRejected("rollout status needs <deployment|statefulset|daemonset>/<name>")
    target = f"{_ROLLOUT_PREFIXES[prefix]}/{_dns_subdomain(name, 'resource name')}"
    # Plan 5.3: "always gets a capped --timeout".  A request of 0s (kubectl: wait forever) or more
    # than the cap is clamped to the cap, never passed through; the dialog text says "capped".
    seconds = ROLLOUT_TIMEOUT_CAP
    if parsed.has("--timeout"):
        asked = _duration_seconds(parsed.value("--timeout"))
        if 0 < asked <= ROLLOUT_TIMEOUT_CAP:
            seconds = asked
    return Parsed("read", "rollout", ("rollout", "status", target, f"--timeout={seconds}s"),
                  parsed.value("--namespace"), False, False, None,
                  seconds + ROLLOUT_WALL_SLACK)


def _parse_apply(tokens) -> Parsed:
    parsed = tokenize_argv(tokens, _APPLY_SPECS, max_positionals=0)
    if not parsed.has("--filename"):
        raise ArgvRejected("apply needs -f <file>")
    args = ["apply", "-f", "-"]
    for spec in (_DRY, _VALIDATE):
        for value in parsed.flags.get(spec.key, ()):
            args.extend(spec.canonical(value))
    return Parsed("apply", "apply", tuple(args), parsed.value("--namespace"), False, False,
                  parsed.value("--filename"), WALL_CLOCK["apply"])


def parse_command(command) -> Optional[Parsed]:
    """``None`` when this is not a kubectl command of this profile's
    subcommands (another profile may claim it); a :class:`Parsed` when it
    satisfies the grammar; ``ArgvRejected`` when it is a kubectl command of
    ours that the grammar refuses (the normal dialog applies)."""
    command = tuple(command)
    if len(command) < 2 or not _is_kubectl(command[0]):
        return None
    sub = command[1]
    if sub not in _SUBCOMMANDS:
        return None
    rest = list(command[2:])
    if sub == "get":
        return _parse_get_like(rest, _GET_SPECS, "get")
    if sub == "describe":
        return _parse_get_like(rest, _DESCRIBE_SPECS, "describe")
    if sub == "logs":
        return _parse_logs(rest)
    if sub == "rollout":
        return _parse_rollout(rest)
    return _parse_apply(rest)


# ---------------------------------------------------------------------------
# Sanitised kubeconfig
# ---------------------------------------------------------------------------

_TOP_KEYS = frozenset({"apiVersion", "kind", "clusters", "users", "contexts",
                       "current-context", "preferences"})
_CLUSTER_KEYS = frozenset({"server", "certificate-authority-data", "insecure-skip-tls-verify"})
_USER_KEYS = frozenset({"client-certificate-data", "client-key-data", "token", "exec"})
_EXEC_KEYS = frozenset({"apiVersion", "command", "args", "env", "interactiveMode",
                        "provideClusterInfo", "installHint"})
_CONTEXT_KEYS = frozenset({"cluster", "user", "namespace"})
_EXEC_API_VERSIONS = ("client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1")
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

_BAD_KEY_REASONS = {
    "proxy-url": "a proxy-url could redirect every request",
    "tls-server-name": "tls-server-name changes who the server certificate must be for",
    "certificate-authority": "the CA is a file path, not inlined (use --flatten)",
    "client-certificate": "the client certificate is a file path, not inlined (use --flatten)",
    "client-key": "the client key is a file path, not inlined (use --flatten)",
    "auth-provider": "auth-provider plugins are not supported",
    "tokenFile": "a tokenFile is a path that can change after approval",
    "username": "basic authentication is not supported",
    "password": "basic authentication is not supported",
    "as": "impersonation is not supported", "as-groups": "impersonation is not supported",
    "as-uid": "impersonation is not supported",
    "as-user-extra": "impersonation is not supported",
    "disable-compression": "unsupported cluster option",
    "extensions": "extensions are not supported",
}


@dataclass
class Sanitized:
    clean: dict
    context: str
    namespace: Optional[str]
    server: str
    auth: str                         # "token" | "client-certificate" | "exec" | "none"
    exec: Optional[dict]              # {"command", "args", "interactiveMode"...}

    def text(self) -> str:
        return json.dumps(self.clean, indent=2, sort_keys=True) + "\n"


def _refuse(why: str):
    raise KubeconfigRefused(f"the kubeconfig cannot be used: {why}")


def _only_keys(section: dict, allowed, where: str):
    for key in section:
        if key in allowed:
            continue
        why = _BAD_KEY_REASONS.get(key, "unsupported setting")
        _refuse(f"{where} has '{key}' ({why})")


def _one(data: dict, key: str, inner: str) -> Tuple[str, dict]:
    items = data.get(key)
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        _refuse(f"it must contain exactly one {key[:-1]} (use --minify)")
    item = items[0]
    name, body = item.get("name"), item.get(inner)
    if set(item) - {"name", inner}:
        _refuse(f"the {key[:-1]} entry has unexpected fields")
    if not isinstance(name, str) or not _CONTEXT_RE.fullmatch(name) or name.startswith("-"):
        _refuse(f"the {key[:-1]} name is not acceptable")
    if not isinstance(body, dict):
        _refuse(f"the {key[:-1]} entry is empty")
    return name, body


def normalise_exec_command(command) -> str:
    """The exec plugin command as the copy and the kuberc must spell it:
    absolute, backslash-normalised on Windows, ``.exe`` on Windows, BMP text."""
    if not isinstance(command, str) or not command or c.has_unsafe_text(command):
        raise KubeconfigRefused("the exec plugin command is not acceptable text")
    if any(ord(ch) > 0xFFFF for ch in command):
        raise KubeconfigRefused("the exec plugin path has characters outside the BMP")
    if os.name == "nt":
        if command.startswith(("\\\\", "//")):
            raise KubeconfigRefused("the exec plugin command is a network path")
        if not re.match(r"[A-Za-z]:[\\/]", command):
            raise KubeconfigRefused("the exec plugin command must be an absolute path")
        normal = os.path.normpath(command)
        if not normal.lower().endswith(".exe"):
            raise KubeconfigRefused("the exec plugin must be a .exe (a script or extension-less "
                                    "name is not accepted)")
        return normal
    if not command.startswith("/"):
        raise KubeconfigRefused("the exec plugin command must be an absolute path")
    return os.path.normpath(command)


def sanitize_kubeconfig(data, *, allow_exec: bool = True) -> Sanitized:
    """Reduce the output of ``kubectl config view --raw --minify --flatten
    -o json`` to a minimal safe kubeconfig, or raise ``KubeconfigRefused``.

    Rules (plan 5.3): exactly one cluster/user/context; ``https`` server
    (``RELAXATIONS.kubectl_allow_http_loopback``: also ``http`` to loopback);
    no insecure-skip-tls-verify, proxy-url, tls-server-name, auth-provider,
    tokenFile, file paths, impersonation, basic auth; ``exec`` only with an
    absolute command, no ``exec.env``, and only when *allow_exec* (kubectl
    >= 1.35).  The result is rebuilt from a whitelist, never copied."""
    if not isinstance(data, dict):
        _refuse("it is not a mapping")
    _only_keys(data, _TOP_KEYS, "the file")
    if data.get("preferences") not in (None, {}):
        _refuse("preferences must be empty")
    cluster_name, cluster = _one(data, "clusters", "cluster")
    user_name, user = _one(data, "users", "user")
    ctx_name, ctx = _one(data, "contexts", "context")
    _only_keys(cluster, _CLUSTER_KEYS, "the cluster")
    _only_keys(user, _USER_KEYS, "the user")
    _only_keys(ctx, _CONTEXT_KEYS, "the context")
    if ctx.get("cluster") != cluster_name or ctx.get("user") != user_name:
        _refuse("the context does not reference the cluster and user")
    if data.get("current-context") not in (None, ctx_name):
        _refuse("current-context differs from the context")
    if cluster.get("insecure-skip-tls-verify") not in (None, False):
        _refuse("the cluster sets insecure-skip-tls-verify")
    server = cluster.get("server")
    if not isinstance(server, str) or c.has_unsafe_text(server) or " " in server:
        _refuse("the server URL is missing or malformed")
    try:
        url = urlparse(server)
        port = url.port
    except ValueError:
        _refuse("the server URL is malformed")
    loopback_ok = c.RELAXATIONS.kubectl_allow_http_loopback and url.hostname in _LOOPBACK_HOSTS
    if url.scheme != "https" and not (url.scheme == "http" and loopback_ok):
        _refuse("the server must use https")
    if not url.hostname or url.username or url.password or url.query or url.fragment:
        _refuse("the server URL has userinfo, a query or no host")
    del port
    namespace = ctx.get("namespace")
    if namespace is not None and (not isinstance(namespace, str)
                                  or len(namespace) > 63 or not _DNS_LABEL_RE.fullmatch(namespace)):
        _refuse("the context namespace is not a valid namespace name")

    clean_cluster = {"server": server}
    ca = cluster.get("certificate-authority-data")
    if ca is not None:
        if not isinstance(ca, str) or c.has_unsafe_text(ca):
            _refuse("certificate-authority-data is malformed")
        clean_cluster["certificate-authority-data"] = ca

    clean_user: dict = {}
    auth = "none"
    for key in ("client-certificate-data", "client-key-data", "token"):
        value = user.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value or c.has_unsafe_text(value):
            _refuse(f"{key} is malformed")
        clean_user[key] = value
    if ("client-certificate-data" in clean_user) != ("client-key-data" in clean_user):
        _refuse("client certificate and key must come together")
    if "token" in clean_user:
        auth = "token"
    elif "client-certificate-data" in clean_user:
        auth = "client-certificate"
    exec_info = None
    if user.get("exec") is not None:
        if auth != "none":
            _refuse("the user combines an exec plugin with other credentials")
        if not allow_exec:
            _refuse("exec credential plugins need kubectl 1.35 or newer (credential plugin policy)")
        raw = user["exec"]
        if not isinstance(raw, dict):
            _refuse("the exec stanza is malformed")
        _only_keys(raw, _EXEC_KEYS, "exec")
        if raw.get("env"):
            _refuse("exec.env is not supported")
        api = raw.get("apiVersion")
        if api not in _EXEC_API_VERSIONS:
            _refuse("exec.apiVersion is not a client.authentication.k8s.io version")
        try:
            command = normalise_exec_command(raw.get("command"))
        except KubeconfigRefused as exc:
            _refuse(exc.reason)
        args = raw.get("args") or []
        if not isinstance(args, list) or not all(isinstance(a, str) and not c.has_unsafe_text(a)
                                                 for a in args):
            _refuse("exec.args must be a list of plain strings")
        mode = raw.get("interactiveMode") or "Never"
        if mode not in ("Never", "IfAvailable"):
            _refuse("exec.interactiveMode must be Never or IfAvailable")
        exec_info = {"apiVersion": api, "command": command, "args": list(args),
                     "interactiveMode": mode}
        if raw.get("provideClusterInfo") is True:
            exec_info["provideClusterInfo"] = True
        clean_user["exec"] = dict(exec_info)
        auth = "exec"

    clean_ctx = {"cluster": cluster_name, "user": user_name}
    if namespace:
        clean_ctx["namespace"] = namespace
    clean = {
        "apiVersion": "v1", "kind": "Config", "preferences": {},
        "clusters": [{"name": cluster_name, "cluster": clean_cluster}],
        "users": [{"name": user_name, "user": clean_user}],
        "contexts": [{"name": ctx_name, "context": clean_ctx}],
        "current-context": ctx_name,
    }
    return Sanitized(clean, ctx_name, namespace, server, auth, exec_info)


# ---------------------------------------------------------------------------
# kuberc
# ---------------------------------------------------------------------------

def build_kuberc(exec_command: Optional[str]) -> str:
    """The kuberc, byte-exact.  *exec_command* is the exact backslash-normalised
    string ``exec.LookPath`` will return for the kubeconfig's command, or None
    (-> ``DenyAll``).  A wrong apiVersion or a typo'd key makes kubectl ignore
    the file with only a stderr line, so nothing here is free-form."""
    head = "apiVersion: kubectl.config.k8s.io/v1beta1\nkind: Preference\n"
    if exec_command is None:
        return head + "credentialPluginPolicy: DenyAll\n"
    if any(ord(ch) > 0xFFFF for ch in exec_command) or c.has_unsafe_text(exec_command):
        raise ProfileRefusal("the exec plugin path cannot be written to a kuberc")
    return (head + "credentialPluginPolicy: Allowlist\ncredentialPluginAllowlist:\n"
            "- command: " + json.dumps(exec_command, ensure_ascii=True) + "\n")


# ---------------------------------------------------------------------------
# Private state files
# ---------------------------------------------------------------------------

_hardened: set = set()
_state_lock = threading.Lock()


def _state_root() -> Path:
    if STATE_DIR is not None:
        return Path(STATE_DIR)
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return base / "llm-env-vault" / "kubectl"


def _harden_dir(path: Path) -> None:
    """Best effort: user-only access.  POSIX: mode 0700.  Windows: drop
    inherited ACEs and grant only the current user (icacls); failures are
    ignored, the files stay readable by same-user code either way."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o700)
            return
        user = os.environ.get("USERNAME")
        if not user:
            return
        from ..procs import NO_WINDOW
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"{user}:(OI)(CI)F"], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=NO_WINDOW, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _private_dir(*parts: str) -> Path:
    path = _state_root().joinpath(*parts)
    path.mkdir(parents=True, exist_ok=True)
    with _state_lock:
        if str(path) not in _hardened:
            _hardened.add(str(path))
            _harden_dir(path)
    if c.is_reparse_point(path):
        raise ProfileRefusal(f"{path} is a link; the private kubectl directory is unusable")
    return path


def _ensure_file(directory: Path, name: str, data: bytes) -> str:
    """Make ``directory/name`` hold exactly *data* (rewritten atomically when
    missing or different) and return its path."""
    path = directory / name
    try:
        if path.is_file() and not c.is_reparse_point(path) and path.read_bytes() == data:
            return str(path)
    except OSError:
        pass
    tmp = directory / f".{name}.{os.getpid()}.{_secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(tmp), flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(str(tmp), str(path))
        if os.name != "nt":
            os.chmod(path, 0o600)
        if path.read_bytes() != data or c.is_reparse_point(path):
            raise ProfileRefusal(f"could not write {name} reliably")
    except OSError as exc:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise ProfileRefusal(f"cannot write the private kubectl file {name}: "
                             f"{exc.strerror or exc}")
    return str(path)


def _new_cache_dir() -> str:
    root = _private_dir("cache")
    cutoff = time.time() - CACHE_MAX_AGE_SECONDS
    try:
        for entry in root.iterdir():
            try:
                if entry.is_dir() and entry.stat().st_mtime < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
            except OSError:
                continue
    except OSError:
        pass
    return tempfile.mkdtemp(prefix="c-", dir=str(root))


# ---------------------------------------------------------------------------
# Running kubectl probes
# ---------------------------------------------------------------------------

def _kubeconfig_env() -> Dict[str, str]:
    """The user's KUBECONFIG (if the server has one), made absolute against
    the server's cwd because probes run elsewhere.  Without it kubectl uses
    ``~/.kube/config`` itself."""
    raw = os.environ.get("KUBECONFIG")
    if not raw:
        return {}
    parts = [os.path.abspath(p) for p in raw.split(os.pathsep) if p.strip()]
    return {"KUBECONFIG": os.pathsep.join(parts)} if parts else {}


def _probe(pin: c.PinnedBinary, path_dirs, args, *, extra=None, stdin_bytes=None,
           timeout=20.0, max_output=c.PROBE_MAX_OUTPUT) -> c.ProbeResult:
    env = c.build_env(path_dirs, extra=extra)
    return c.run_probe([pin.path] + list(args), env, timeout=timeout, max_output=max_output,
                       stdin_bytes=stdin_bytes, expect_sha256=pin.sha256)


def _resolve_kubectl() -> c.PinnedBinary:
    return c.resolve_pinned_binary(KUBECTL_PROGRAM)


def _client_version(pin, path_dirs) -> Tuple[int, ...]:
    result = _probe(pin, path_dirs, ["version", "--client", "-o", "json"],
                    extra={"KUBERC": "off"})
    if not result.ok:
        raise ProfileRefusal(f"cannot determine the kubectl version: {result.failure_reason()}")
    text = result.stdout_text()
    try:
        git_version = json.loads(text)["clientVersion"]["gitVersion"]
    except (ValueError, KeyError, TypeError):
        git_version = text
    version = c.parse_version(git_version)
    if version is None:
        raise ProfileRefusal("cannot determine the kubectl version")
    return version


def _current_context(pin, path_dirs) -> Optional[Tuple[str, Optional[str]]]:
    extra = {"KUBERC": "off", **_kubeconfig_env()}
    result = _probe(pin, path_dirs, ["config", "view", "--minify", "-o", "json"], extra=extra)
    if not result.ok:
        return None
    try:
        data = json.loads(result.stdout_text())
        name = data["current-context"]
        ns = data["contexts"][0]["context"].get("namespace")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    if not isinstance(name, str) or not _CONTEXT_RE.fullmatch(name):
        return None
    return name, (ns if isinstance(ns, str) and ns else None)


def _view_context(pin, path_dirs, context: str) -> dict:
    extra = {"KUBERC": "off", **_kubeconfig_env()}
    result = _probe(pin, path_dirs, ["config", "view", "--raw", "--minify", "--flatten",
                                     "-o", "json", f"--context={context}"], extra=extra,
                    max_output=2 * 1024 * 1024)
    if not result.ok:
        raise KubeconfigRefused("kubectl could not produce the kubeconfig for this context: "
                                + result.failure_reason())
    try:
        return json.loads(result.stdout_text())
    except ValueError:
        raise KubeconfigRefused("kubectl produced an unreadable kubeconfig")


def kuberc_selftest(pin, path_dirs, kuberc_path: str) -> Optional[str]:
    """None when kubectl accepts the kuberc strictly (the credential-plugin
    policy will apply); otherwise the reason.  Any 'strict decoding' / kuberc
    message on stderr is fatal (fail-open hazard)."""
    result = _probe(pin, path_dirs, ["version", "--client", f"--kuberc={kuberc_path}"],
                    timeout=20.0)
    if not result.ok:
        return f"kubectl rejected the generated kuberc: {result.failure_reason()}"
    err = result.stderr_text().lower()
    if stderr_problem(err) or "kuberc" in err:
        return "kubectl did not apply the generated kuberc strictly"
    return None


# ---------------------------------------------------------------------------
# apply: manifest normalisation and object policy
# ---------------------------------------------------------------------------

_ALLOWED_OBJECTS = frozenset({
    ("v1", "ConfigMap"), ("v1", "Service"), ("v1", "PersistentVolumeClaim"), ("v1", "Pod"),
    ("apps/v1", "Deployment"), ("apps/v1", "StatefulSet"), ("apps/v1", "DaemonSet"),
    ("apps/v1", "ReplicaSet"), ("batch/v1", "Job"), ("batch/v1", "CronJob"),
    ("networking.k8s.io/v1", "Ingress"), ("networking.k8s.io/v1", "NetworkPolicy"),
    ("autoscaling/v2", "HorizontalPodAutoscaler"), ("autoscaling/v1", "HorizontalPodAutoscaler"),
})
_DENIED_KINDS = frozenset({
    "Secret", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding",
    "CustomResourceDefinition", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Namespace",
    "CertificateSigningRequest", "TokenRequest", "TokenReview", "SubjectAccessReview",
    "APIService", "PodSecurityPolicy", "StorageClass", "PersistentVolume", "Node",
})
_ALLOWED_VOLUME_TYPES = frozenset({"name", "emptyDir", "configMap", "persistentVolumeClaim",
                                   "downwardAPI"})
# automountServiceAccountToken: a pod-level true overrides a hardened ServiceAccount's false.
_FORBIDDEN_TRUE = ("privileged", "allowPrivilegeEscalation", "hostNetwork", "hostPID", "hostIPC",
                   "automountServiceAccountToken")
_FORBIDDEN_PRESENT = ("secretKeyRef", "secretRef", "secretName", "projected")
_FORBIDDEN_NONEMPTY = ("imagePullSecrets",)       # a list: [] / null references nothing


def parse_json_stream(text: str) -> List[dict]:
    """The ``kubectl label --local -f - -o json`` output: concatenated JSON
    objects (not a List).  Raises ``ManifestRefused`` on anything else."""
    decoder = json.JSONDecoder()
    docs: List[dict] = []
    pos, end = 0, len(text)
    while True:
        while pos < end and text[pos] in " \t\r\n":
            pos += 1
        if pos >= end:
            break
        try:
            doc, pos = decoder.raw_decode(text, pos)
        except ValueError:
            raise ManifestRefused("kubectl's normalised manifest could not be parsed")
        if not isinstance(doc, dict):
            raise ManifestRefused("kubectl's normalised manifest has a non-object document")
        docs.append(doc)
        if len(docs) > MANIFEST_MAX_OBJECTS * 2:
            raise ManifestRefused("the manifest has too many documents")
    return docs


def _flatten(docs: List[dict]) -> List[dict]:
    out: List[dict] = []
    stack = list(reversed(docs))
    while stack:
        doc = stack.pop()
        items = doc.get("items")
        kind_ = doc.get("kind")
        if isinstance(kind_, str) and kind_.endswith("List") and isinstance(items, list):
            stack.extend(reversed([i for i in items]))
            if not all(isinstance(i, dict) for i in items):
                raise ManifestRefused("a List contains a non-object item")
            continue
        out.append(doc)
    return out


def _scan_spec(node, where: str, out: List[str]) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            here = f"{where}.{key}"
            if key in _FORBIDDEN_TRUE and val not in (False, None):
                out.append(f"{here} is not false")
            elif key == "hostPort" and val not in (None, 0):
                out.append(f"{here} (host port)")
            elif key in _FORBIDDEN_PRESENT and val is not None:
                out.append(f"{here} references a Secret/projected volume")
            elif key in _FORBIDDEN_NONEMPTY and val:
                out.append(f"{here} references a Secret (image pull secret)")
            elif key in ("serviceAccountName", "serviceAccount") and val not in (None, "default"):
                out.append(f"{here} is a non-default service account")
            elif key == "capabilities" and isinstance(val, dict) and val.get("add"):
                out.append(f"{here}.add adds Linux capabilities")
            elif key == "volumes" and isinstance(val, list):
                for i, volume in enumerate(val):
                    if not isinstance(volume, dict):
                        out.append(f"{here}[{i}] is malformed")
                        continue
                    bad = sorted(k for k, v in volume.items()
                                 if k not in _ALLOWED_VOLUME_TYPES and v is not None)
                    if bad:
                        out.append(f"{here}[{i}] uses volume type {bad[0]}")
            _scan_spec(val, here, out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _scan_spec(item, f"{where}[{i}]", out)


def check_manifest(docs: List[dict], namespace: str) -> List[str]:
    """Policy violations (empty list = allowed) for the normalised objects."""
    objects = _flatten(docs)
    if not objects:
        return ["the manifest contains no objects"]
    if len(objects) > MANIFEST_MAX_OBJECTS:
        return [f"the manifest has more than {MANIFEST_MAX_OBJECTS} objects"]
    problems: List[str] = []
    for idx, obj in enumerate(objects):
        api, kind_ = obj.get("apiVersion"), obj.get("kind")
        name = (obj.get("metadata") or {}).get("name") if isinstance(obj.get("metadata"), dict) \
            else None
        who = f"{kind_}/{name}" if isinstance(kind_, str) and isinstance(name, str) \
            else f"object {idx + 1}"
        if not isinstance(api, str) or not isinstance(kind_, str):
            problems.append(f"{who}: missing apiVersion or kind")
            continue
        if kind_ in _DENIED_KINDS:
            problems.append(f"{who}: kind {kind_} is never allowed")
            continue
        if (api, kind_) not in _ALLOWED_OBJECTS:
            problems.append(f"{who}: {api} {kind_} is not in the allowed kinds")
            continue
        meta = obj.get("metadata")
        if not isinstance(meta, dict):
            problems.append(f"{who}: missing metadata")
            continue
        object_name = meta.get("name")
        generate = meta.get("generateName")
        if isinstance(object_name, str):
            if len(object_name) > 253 or not _DNS_SUBDOMAIN_RE.fullmatch(object_name):
                problems.append(f"{who}: the name is not a valid Kubernetes name")
        elif not (isinstance(generate, str) and generate):
            problems.append(f"{who}: missing metadata.name")
        ns = meta.get("namespace")
        if ns is not None and ns != namespace:
            problems.append(f"{who}: metadata.namespace is not the approved namespace "
                            f"{namespace!r}")
        if kind_ != "ConfigMap":
            scan: List[str] = []
            _scan_spec(obj.get("spec"), "spec", scan)
            problems.extend(f"{who}: {s}" for s in scan)
    return problems


def summarize_objects(docs: List[dict]) -> List[str]:
    out = []
    for obj in _flatten(docs):
        meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
        out.append(f"{obj.get('kind')}/{meta.get('name') or meta.get('generateName')}")
    return out


def resolve_manifest(path_arg: str, cwd: str) -> Tuple[Optional[str], Optional[str]]:
    """``(real path, None)`` or ``(None, reason)`` for an apply ``-f`` argument."""
    if _check_file_arg(path_arg) or c.has_unsafe_text(path_arg):
        return None, "apply -f must name a local file"
    joined = path_arg if os.path.isabs(path_arg) else os.path.join(cwd, path_arg)
    joined = os.path.abspath(joined)
    if c.is_reparse_point(joined):
        return None, "the manifest is a link"
    if not os.path.isfile(joined):
        return None, "the manifest is not a regular file"
    if os.path.splitext(joined)[1].lower() not in (".yaml", ".yml", ".json"):
        return None, "the manifest must be a .yaml, .yml or .json file"
    real = os.path.realpath(joined)
    if real.startswith("\\\\"):
        return None, "the manifest is on a network path"
    return os.path.normcase(real), None


def _read_manifest(real: str) -> bytes:
    try:
        with open(real, "rb") as handle:
            data = handle.read(MANIFEST_MAX_BYTES + 1)
    except OSError as exc:
        raise ManifestRefused(f"cannot read the manifest: {exc.strerror or exc}")
    if len(data) > MANIFEST_MAX_BYTES:
        raise ManifestRefused("the manifest is larger than 1 MiB")
    if not data.strip():
        raise ManifestRefused("the manifest is empty")
    return data


_QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


def _stderr_hint(stderr: bytes) -> str:
    """One short, content-free line out of kubectl's stderr for the refusal text.
    kubectl sometimes echoes manifest fragments (quoted strings, JSON), so
    quoted spans are blanked, anything from the first brace/bracket is cut, and
    only printable ASCII survives."""
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, (bytes, bytearray)) else ""
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    line = _QUOTED_RE.sub("...", line)
    line = re.split(r"[{\[]", line, maxsplit=1)[0]
    line = "".join(ch for ch in line if " " <= ch <= "~")
    line = re.sub(r"\s+", " ", line).strip()
    if line.lower().startswith("error:"):
        line = line[6:].strip()
    return line[:MANIFEST_HINT_MAX]


def normalise_manifest(data: bytes, pin, path_dirs, global_flags, extra_env) -> List[dict]:
    """Run kubectl's own decoder offline over *data* and return the documents it
    sees (duplicate keys last-wins, YAML 1.1 coercions, anchors/merge keys
    resolved).  Raises ``ManifestRefused``."""
    result = _probe(pin, path_dirs, list(global_flags) + ["label", "--local", "-f", "-", "-o",
                                                          "json", "zzz-"],
                    extra=extra_env, stdin_bytes=data, timeout=NORMALISER_TIMEOUT,
                    max_output=NORMALISER_MAX_OUTPUT)
    if not result.ok:
        why = result.failure_reason()
        hint = _stderr_hint(result.stderr)
        raise ManifestRefused("kubectl could not decode the manifest: " + why
                              + (f" ({hint})" if hint else ""))
    return parse_json_stream(result.stdout_text())


# ---------------------------------------------------------------------------
# Snapshot loading and verification
# ---------------------------------------------------------------------------

@dataclass
class _Loaded:
    pin: c.PinnedBinary
    version: Tuple[int, ...]
    path_dirs: List[str]
    kubeconfig_text: str
    kubeconfig_sha: str
    context: str
    namespace: Optional[str]
    exec_info: Optional[dict]
    exec_pin: Optional[c.PinnedBinary]
    kuberc_mode: str                  # "file" | "env_off"
    kuberc_text: Optional[str]
    dlls: dict
    manifest: Optional[dict]
    server: str = ""
    auth: str = "none"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load(entry: dict) -> _Loaded:
    """Parse and cross-check an entry's snapshot (no spawns).  Raises
    ``ProfileRefusal``."""
    snap, shape = entry.get("snapshot"), entry.get("shape")
    if not isinstance(snap, dict) or not isinstance(shape, dict):
        raise ProfileRefusal("the approved kubectl record is malformed")
    try:
        pin = c.PinnedBinary.from_dict(snap["kubectl"])
        version = tuple(int(p) for p in snap["kubectl_version"])
        path_dirs = [str(p) for p in snap["path_dirs"]]
        kc = snap["kubeconfig"]
        text, sha = kc["text"], kc["sha256"]
        kuberc = snap["kuberc"]
        mode = kuberc["mode"]
        dlls = snap["dlls"]
        exec_raw = snap.get("exec")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProfileRefusal("the approved kubectl record is malformed")
    if not isinstance(text, str) or _sha(text) != sha or mode not in ("file", "env_off"):
        raise ProfileRefusal("the approved kubeconfig record is damaged")
    try:
        data = json.loads(text)
    except ValueError:
        raise ProfileRefusal("the approved kubeconfig record is damaged")
    san = sanitize_kubeconfig(data, allow_exec=mode == "file")
    if san.text() != text:
        raise ProfileRefusal("the approved kubeconfig record does not match its sanitised form")
    if san.context != shape.get("context"):
        raise ProfileRefusal("the approved kubeconfig is for a different context")
    exec_pin = None
    kuberc_text = None
    if mode == "file":
        kuberc_text = build_kuberc(san.exec["command"] if san.exec else None)
        if kuberc.get("text") != kuberc_text:
            raise ProfileRefusal("the approved kuberc does not match the template")
    if san.exec:
        if not isinstance(exec_raw, dict) or exec_raw.get("command") != san.exec["command"]:
            raise ProfileRefusal("the approved exec plugin record is damaged")
        exec_pin = c.PinnedBinary.from_dict(exec_raw.get("binary"))
        if os.path.normcase(exec_pin.path) != os.path.normcase(san.exec["command"]):
            raise ProfileRefusal("the exec plugin is reached through a link or another path")
    elif exec_raw:
        raise ProfileRefusal("the approved exec plugin record is damaged")
    if shape.get("access") == "apply" and not isinstance(snap.get("manifest"), dict):
        raise ProfileRefusal("the approved manifest record is missing")
    return _Loaded(pin, version, path_dirs, text, sha, san.context, san.namespace,
                   san.exec, exec_pin, mode, kuberc_text, dlls if isinstance(dlls, dict) else {},
                   snap.get("manifest"), san.server, san.auth)


def _check_binaries(loaded: _Loaded) -> None:
    problem = c.verify_pinned_binary(loaded.pin)
    if problem:
        raise ProfileRefusal(problem)
    if loaded.exec_pin is not None:
        problem = c.verify_pinned_binary(loaded.exec_pin)
        if problem:
            raise ProfileRefusal("exec credential plugin: " + problem)


def _materialise(loaded: _Loaded) -> Tuple[str, Optional[str]]:
    """(kubeconfig path, kuberc path or None), rewritten from the sealed text
    when missing or different, then hash-verified."""
    directory = _private_dir("files")
    kc_path = _ensure_file(directory, f"kubeconfig-{loaded.kubeconfig_sha[:24]}.json",
                           loaded.kubeconfig_text.encode("utf-8"))
    if c.hash_file(kc_path) != loaded.kubeconfig_sha:
        raise ProfileRefusal("the vault-owned kubeconfig copy does not verify")
    rc_path = None
    if loaded.kuberc_mode == "file":
        data = loaded.kuberc_text.encode("utf-8")
        rc_path = _ensure_file(directory, f"kuberc-{hashlib.sha256(data).hexdigest()[:24]}.yaml",
                               data)
    return kc_path, rc_path


def _global_flags(kubeconfig: str, context: str, kuberc: Optional[str],
                  cache_dir: Optional[str]) -> List[str]:
    flags = [f"--kubeconfig={kubeconfig}", f"--context={context}"]
    if cache_dir is not None:
        flags.append(f"--cache-dir={cache_dir}")
    flags.append(f"--request-timeout={REQUEST_TIMEOUT}")
    if kuberc is not None:
        flags.append(f"--kuberc={kuberc}")
    return flags


def _run_env_extra(loaded: _Loaded) -> Dict[str, str]:
    return {"KUBERC": "off"} if loaded.kuberc_mode == "env_off" else {}


# ---------------------------------------------------------------------------
# Profile protocol
# ---------------------------------------------------------------------------

_LAST: Dict[tuple, dict] = {}
_LAST_LOCK = threading.Lock()


def _request_key(req: Request) -> tuple:
    return (req.cwd, tuple(req.command), tuple(req.only_vars))


def match(req: Request) -> Optional[dict]:
    """The candidate shape, or ``None`` (not ours / outside the grammar / no
    usable kubeconfig context)."""
    try:
        parsed = parse_command(req.command)
    except ArgvRejected:
        return None
    if parsed is None:
        return None
    try:
        pin = _resolve_kubectl()
        path_dirs = c.pinned_path_dirs(extra=[os.path.dirname(pin.path)])
        found = _current_context(pin, path_dirs)
    except ProfileRefusal:
        return None
    if found is None:
        return None
    context, default_ns = found
    if parsed.access == "apply":
        real, err = resolve_manifest(parsed.file, req.cwd)
        if err:
            return None
        return {"access": "apply", "context": context,
                "namespace": parsed.namespace or default_ns or "default", "file": real}
    if parsed.all_namespaces or parsed.cluster_scoped:
        return {"access": "read", "context": context, "namespace": None, "scope": "all"}
    return {"access": "read", "context": context, "scope": "namespace",
            "namespace": parsed.namespace or default_ns or "default"}


def label(req: Request, candidate: dict) -> str:
    ns = candidate.get("namespace") or "*"
    if candidate.get("access") == "apply":
        text = f"kubectl apply {os.path.basename(candidate['file'])} ns={ns} ctx={candidate['context']}"
    else:
        text = f"kubectl read ns={ns} ctx={candidate['context']}"
    return text if len(text) <= 100 else text[:97] + "..."


def snapshot(req: Request, candidate: dict) -> dict:
    """Approval-time snapshot.  Raises ``ProfileRefusal`` when the request
    cannot be made safe (no offer is shown then)."""
    pin = _resolve_kubectl()
    base_dirs = c.pinned_path_dirs(extra=[os.path.dirname(pin.path)])
    version = _client_version(pin, base_dirs)
    allow_exec = c.vercmp(version, KUBERC_MIN_VERSION) >= 0
    raw = _view_context(pin, base_dirs, candidate["context"])
    san = sanitize_kubeconfig(raw, allow_exec=allow_exec)
    if san.context != candidate["context"]:
        raise KubeconfigRefused("kubectl returned a different context than the one approved")
    exec_pin = None
    path_dirs = list(base_dirs)
    if san.exec:
        exec_pin = c.resolve_pinned_binary(san.exec["command"])
        if os.path.normcase(exec_pin.path) != os.path.normcase(san.exec["command"]):
            raise KubeconfigRefused("the exec plugin is reached through a link; use its real path")
        path_dirs = c.pinned_path_dirs(extra=[os.path.dirname(pin.path),
                                              os.path.dirname(exec_pin.path)])
    text = san.text()
    mode = "file" if allow_exec else "env_off"
    kuberc_text = build_kuberc(san.exec["command"] if san.exec else None) if mode == "file" \
        else None
    snap = {
        "kubectl": pin.to_dict(), "kubectl_version": list(version), "path_dirs": path_dirs,
        "kubeconfig": {"text": text, "sha256": _sha(text), "server": san.server,
                       "auth": san.auth, "namespace": san.namespace},
        "exec": ({"command": san.exec["command"], "args": san.exec["args"],
                  "binary": exec_pin.to_dict()} if san.exec else None),
        "kuberc": {"mode": mode, "text": kuberc_text},
        "dlls": c.snapshot_cwd_dlls(req.cwd),
        "manifest": ({"path": candidate["file"], "sha256": "", "size": 0, "objects": []}
                     if candidate["access"] == "apply" else None),
    }
    loaded = _load({"snapshot": snap, "shape": candidate})
    if mode == "file":
        _kc, rc_path = _materialise(loaded)
        problem = kuberc_selftest(pin, path_dirs, rc_path)
        if problem:
            raise ProfileRefusal(problem)
    summary: List[str] = []
    if candidate["access"] == "apply":
        data = _read_manifest(candidate["file"])
        docs = _normalise_for(loaded, data)
        problems = check_manifest(docs, candidate["namespace"])
        if problems:
            raise ManifestRefused("the manifest breaks the object policy: " + "; ".join(problems[:5]))
        summary = summarize_objects(docs)
        snap["manifest"] = {"path": candidate["file"], "sha256": hashlib.sha256(data).hexdigest(),
                            "size": len(data), "objects": summary}
    with _LAST_LOCK:
        if len(_LAST) > 8:
            _LAST.clear()
        _LAST[_request_key(req)] = {"snapshot": snap, "version": version}
    return snap


def _normalise_for(loaded: _Loaded, data: bytes) -> List[dict]:
    kc_path, rc_path = _materialise(loaded)
    return normalise_manifest(data, loaded.pin, loaded.path_dirs,
                              _global_flags(kc_path, loaded.context, rc_path, None),
                              _run_env_extra(loaded))


def describe(req: Request, candidate: dict) -> str:
    ns = candidate.get("namespace")
    where = f"namespace {ns}" if ns else "ALL namespaces and cluster-scoped kinds"
    ctx = candidate["context"]
    with _LAST_LOCK:
        info = _LAST.get(_request_key(req))
    snap = info["snapshot"] if info else None
    if candidate["access"] == "apply":
        head = f"kubectl apply -f {candidate['file']}  (this exact manifest, namespace {ns}, context {ctx})"
    else:
        head = (f"kubectl get|describe|logs|rollout status <allowed kinds> in {where} "
                f"(context {ctx})")
    lines = [head]
    if snap:
        kc = snap["kubeconfig"]
        lines.append(f"Cluster: {kc['server']}  authentication: {kc['auth']}  "
                     f"kubectl {'.'.join(str(p) for p in snap['kubectl_version'])}")
        if snap["exec"]:
            lines.append(f"Credential plugin (hash pinned, allowlisted by a generated kuberc): "
                         f"{snap['exec']['command']} {' '.join(snap['exec']['args'])}".rstrip())
            lines.append("The plugin inherits the whole child environment, so only_vars must "
                         "contain nothing the plugin must not see.")
        if snap["manifest"]:
            m = snap["manifest"]
            lines.append(f"Manifest sha256 {m['sha256'][:16]}... ({m['size']} bytes): "
                         + ", ".join(m["objects"][:12]))
            lines.append("Policy checked on kubectl's own decoding: no Secret/RBAC/CRD/webhook/"
                         "Namespace, no privileged/host*/hostPath/secret volumes/capabilities.")
    lines.append("Server-injected: vault-owned sanitised kubeconfig copy (it holds this "
                 "context's credentials; same-user code can read it while it exists), pinned "
                 "context, fresh --cache-dir, --request-timeout=30s, a wall-clock kill, logs "
                 f"capped at {LOGS_TAIL_MAX} lines / {LIMIT_BYTES_MAX // (1024 * 1024)} MiB, "
                 f"rollout status capped at {ROLLOUT_TIMEOUT_CAP}s.")
    lines.append("Never allowed: secrets, RBAC, exec/cp/port-forward/delete/edit/patch and every "
                 "other verb; changing the context or namespace asks again.")
    lines.append("The agent can obtain these values (objects it applies or logs it reads can "
                 "expose them). Use test-grade credentials.")
    return "\n".join(lines)


def _dll_problem(entry: dict, loaded: _Loaded) -> Optional[str]:
    return c.verify_cwd_dlls(entry.get("cwd") or ".", loaded.dlls)


def check_snapshot(entry: dict):
    """Arm-time check (no concrete command): fast, no vault calls."""
    try:
        loaded = _load(entry)
        _check_binaries(loaded)
        cwd = entry.get("cwd")
        if not isinstance(cwd, str) or not os.path.isdir(cwd):
            return False, "the approved working directory no longer exists"
        problem = _dll_problem(entry, loaded)
        if problem:
            return False, problem
        _kc, rc_path = _materialise(loaded)
        if loaded.kuberc_mode == "file":
            problem = kuberc_selftest(loaded.pin, loaded.path_dirs, rc_path)
            if problem:
                return False, problem
        if entry["shape"].get("access") == "apply":
            m = loaded.manifest
            real, err = resolve_manifest(entry["shape"].get("file", ""), cwd)
            if err or real != os.path.normcase(m["path"]):
                return False, err or "the approved manifest moved"
            if c.hash_file(real) != m["sha256"]:
                return False, "the manifest changed since it was approved"
        return True, None
    except ProfileRefusal as exc:
        return False, exc.reason


_NOT_MINE = Verdict(ok=False, reason=None)


def verify(entry: dict, req: Request) -> Verdict:
    """Run-time check.  Not applicable (``reason=None``) for requests outside
    the grammar or the entry's pins; a reason for drift."""
    try:
        parsed = parse_command(req.command)
    except ArgvRejected:
        return _NOT_MINE
    if parsed is None:
        return _NOT_MINE
    shape = entry.get("shape")
    if not isinstance(shape, dict) or shape.get("access") != parsed.access:
        return _NOT_MINE
    pin_ns = shape.get("namespace")
    inject_ns: Optional[str]
    if parsed.access == "apply":
        real, err = resolve_manifest(parsed.file, req.cwd)
        if err or real != shape.get("file"):
            return _NOT_MINE
        if parsed.namespace not in (None, pin_ns):
            return _NOT_MINE
        inject_ns = pin_ns
    elif shape.get("scope") == "namespace":
        if parsed.all_namespaces or parsed.cluster_scoped:
            return _NOT_MINE
        if parsed.namespace not in (None, pin_ns):
            return _NOT_MINE
        inject_ns = pin_ns
    elif shape.get("scope") == "all":
        inject_ns = parsed.namespace
    else:
        return _NOT_MINE
    try:
        loaded = _load(entry)
        _check_binaries(loaded)
        problem = _dll_problem(entry, loaded)
        if problem:
            return Verdict(ok=False, reason=problem)
        kc_path, rc_path = _materialise(loaded)
        stdin_data = None
        if parsed.access == "apply":
            stdin_data = _verify_manifest(loaded, real, kc_path, rc_path, pin_ns)
        cache_dir = _new_cache_dir()
    except ProfileRefusal as exc:
        return Verdict(ok=False, reason=exc.reason)
    argv = ([loaded.pin.path] + _global_flags(kc_path, loaded.context, rc_path, cache_dir)
            + parsed.render(inject_ns))
    env = c.build_env(loaded.path_dirs, extra=_run_env_extra(loaded))
    return KubectlVerdict(ok=True, argv=argv, env=env, replace_env=True,
                          stdin=stdin_data, wall_clock=parsed.wall_clock,
                          cleanup_paths=(cache_dir,))


def _verify_manifest(loaded: _Loaded, real: str, kc_path, rc_path, namespace) -> bytes:
    """Read the manifest ONCE, compare with the approved hash, run the object
    policy on kubectl's own normalisation; return the bytes to feed ``apply``."""
    data = _read_manifest(real)
    if hashlib.sha256(data).hexdigest() != loaded.manifest.get("sha256"):
        raise ProfileRefusal("the manifest changed since it was approved")
    docs = normalise_manifest(data, loaded.pin, loaded.path_dirs,
                              _global_flags(kc_path, loaded.context, rc_path, None),
                              _run_env_extra(loaded))
    problems = check_manifest(docs, namespace)
    if problems:
        raise ProfileRefusal("the manifest breaks the object policy: " + "; ".join(problems[:3]))
    return data
