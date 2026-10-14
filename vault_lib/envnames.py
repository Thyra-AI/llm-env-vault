"""Canonical denylist of tool-control environment variable names.

Plan 2.4.0 section 4 ("Tool-control name denylist"). These names steer the
behaviour of git, docker, kubectl, the runtime or the OS loader rather than
carrying a credential, so a vault variable under one of them could redirect a
tool that an always-allow entry runs unattended (GIT_SSH_COMMAND, DOCKER_HOST,
KUBECONFIG, HTTPS_PROXY, LD_PRELOAD, ...).

Enforced at two points:
  * ``add_secret`` refuses a NEW variable with such a name. Names already in a
    vault keep working for ordinary run_with_env use; they are simply ineligible
    for always-allow.
  * ``allowlist`` refuses to add or arm an entry that injects such a name.

Matching is case-insensitive (Windows env names are, and a lower-case
``https_proxy`` is honoured by curl-family tools).
"""

# Exact names (compared upper-case).
EXACT_NAMES: frozenset = frozenset({
    "PATH", "PATHEXT", "HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "TMP", "TEMP", "SYSTEMROOT", "WINDIR",
    "COMSPEC", "REQUESTS_CA_BUNDLE", "KUBECONFIG", "KUBERC", "CURL_CA_BUNDLE",
})

# Prefixes (compared upper-case). "KUBE" and "PYTHON" are deliberately bare:
# KUBECACHEDIR, KUBECTL_*, KUBERNETES_*, PYTHONPATH, PYTHONSTARTUP, ...
PREFIXES: tuple = (
    "GIT_", "GCM_", "DOCKER_", "COMPOSE_", "BUILDKIT_", "BUILDX_",
    "KUBE", "KUBERNETES_", "DOTNET_", "XDG_", "LD_", "DYLD_", "PYTHON",
    "NODE_", "SSL_CERT_", "CURL_", "SSH_",
)

# Suffixes (compared upper-case).
SUFFIXES: tuple = ("_PROXY",)


def is_tool_control_name(name: str) -> bool:
    """True if *name* is on the tool-control denylist (case-insensitive)."""
    if not isinstance(name, str):
        return False
    upper = name.upper()
    return (upper in EXACT_NAMES
            or upper.startswith(PREFIXES)
            or upper.endswith(SUFFIXES))


def refusal_message(name: str) -> str:
    """The explanation shown when a new variable under such a name is refused."""
    return (f"{name} is refused: its name controls how tools such as git, docker, "
            f"kubectl, proxies or the OS loader behave (e.g. GIT_*, DOCKER_*, KUBE*, "
            f"*_PROXY, PATH, HOME, LD_*, PYTHON*, SSH_*). A vault value under that "
            f"name could redirect a command that always-allow runs unattended. Pick "
            f"a different name (e.g. MYAPP_TOKEN). Names already in the vault are "
            f"not affected.")
