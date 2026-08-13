"""In-memory-only trust cache for run_with_env.

Everything in this module lives purely in this MCP server process's
memory. Nothing here is ever written to disk, and none of it survives
past this process exiting -- restarting the server forgets every trust
grant and every cached secret, and the very next run (trusted or not)
needs a fresh master-password unlock. This is deliberate: it's what lets
the feature exist at all without weakening the invariant documented in
crypto.py -- the master password (and anything it unlocks) never touches
disk outside of vault.enc itself.

This is a convenience feature, not a security boundary. It exists to
save a human from re-typing the master password for a command they've
already reviewed and approved once this session. It provides no
protection against a malicious or compromised caller that can edit this
process's own source -- nothing local-only can. See README.md's
"Trusted commands" section for the full reasoning.

A command is "trusted" only for the exact argv, cwd, only_vars,
materialize target, and foreground/background mode it was approved for
-- changing any of those is a different command as far as this cache is
concerned, and falls back to asking again. On top of that, trust is
scoped to the content of every file named directly as a whole argument
on the command line (e.g. a docker-compose.yml named after -f): if that
file's content changes -- or it disappears -- trust is silently revoked
and the caller falls back to asking the human again, with a note
explaining why. It does NOT see into files only referenced indirectly
(a Dockerfile pulled in via a compose file's `context:`, fused flags
like `--file=x.yml`, directories) -- see README.md's "Trusted commands"
section for the full list of what this can't catch.

Trust is also tied to the vault's own content: if the vault changes
(add_secret, remove_secret, install_migrate, or unlocking with a
different password) after secrets were cached here, the cache is stale
for every trusted command at once, not just one, so it's dropped
entirely rather than silently serving pre-rotation values.
"""
import hashlib
import os
from pathlib import Path
from typing import Optional

from . import store

# Bounds on the file-scanning below -- not security controls (nothing here
# is), just guards against a pathological command list (hundreds of args,
# or one pointing at a multi-GB file) making every trusted run silently
# slow.
_MAX_HASHED_FILES = 20
_MAX_HASH_BYTES = 64 * 1024 * 1024  # 64 MiB

# Populated only after the human checks "trust this command" in
# unlock_for_run_dialog at least once this session -- until then this
# stays None and every run behaves exactly as it did before this feature
# existed (decrypt, use, discard).
_cached_secrets: Optional[dict] = None

# sha256 of vault.enc at the moment _cached_secrets was populated. Compared
# against the live file on every check() so a vault change (rotation, a
# new/removed secret, even re-encrypting under the same values) invalidates
# the whole cache instead of quietly keeping stale values alive.
_cached_vault_fingerprint: Optional[str] = None

# signature -> {resolved_path_str: sha256_hex, ...}
_trusted: dict = {}


def make_signature(command, cwd, only_vars, materialize, background=False):
    """A hashable key identifying "this exact run_with_env call shape".
    Any change to any of these is treated as a different, unapproved
    command.

    only_vars=[] and only_vars=None are deliberately kept distinct here
    (empty tuple vs None) -- they mean opposite things to the caller
    (inject nothing vs inject the entire vault), so collapsing them would
    let a grant for one silently cover the other. Same reasoning for
    background: a foreground run and a detached background run (secrets
    sitting in an unmanaged child process's environment) are materially
    different approvals even with identical argv.
    """
    return (
        tuple(command),
        os.path.normcase(os.path.abspath(cwd)) if cwd else None,
        tuple(sorted(set(only_vars))) if only_vars is not None else None,
        materialize if materialize else None,
        bool(background),
    )


def _candidate_paths(command, cwd):
    """Returns (paths, truncated). paths is every command argument that
    resolves to an existing regular file, capped at _MAX_HASHED_FILES;
    truncated is True if more distinct files were found than that cap.

    A relative argument is only checked against `cwd` (the directory the
    command will actually run in) -- never against this server process's
    own working directory, which the spawned subprocess never consults
    and which can differ from `cwd` arbitrarily. An absolute argument is
    checked as-is.
    """
    base = Path(cwd) if cwd else Path.cwd()
    seen = set()
    paths = []
    for arg in command:
        candidate = Path(arg) if os.path.isabs(arg) else base / arg
        try:
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    truncated = len(paths) > _MAX_HASHED_FILES
    return paths[:_MAX_HASHED_FILES], truncated


def _hash_file(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def referenced_file_hashes(command, cwd) -> dict:
    """sha256 of every file the command appears to reference on disk.
    Files too large or unreadable to hash cheaply are skipped rather than
    included with a placeholder -- a skipped file just never contributes
    to drift detection, same as if the command didn't reference it. See
    unmonitored_file_warning() for surfacing that gap to the human."""
    hashes = {}
    paths, _truncated = _candidate_paths(command, cwd)
    for path in paths:
        digest = _hash_file(path)
        if digest is not None:
            hashes[str(path)] = digest
    return hashes


def unmonitored_file_warning(command, cwd) -> Optional[str]:
    """Human-facing note about referenced files this trust grant will NOT
    actually detect drift in: files too large/unreadable to hash, or
    files beyond the _MAX_HASHED_FILES cap. None if nothing was left out.
    Meant to be shown once, at the moment trust is granted -- silently
    excluding a file from drift detection is fine, silently *implying*
    full coverage while doing that is not."""
    paths, truncated = _candidate_paths(command, cwd)
    unmonitored = [str(p) for p in paths if _hash_file(p) is None]
    parts = []
    if unmonitored:
        parts.append(f"{len(unmonitored)} referenced file(s) too large or unreadable to "
                      f"monitor: {', '.join(unmonitored)}")
    if truncated:
        parts.append(f"more than {_MAX_HASHED_FILES} referenced files were found -- only "
                      f"the first {_MAX_HASHED_FILES} are drift-monitored")
    if not parts:
        return None
    return "Note: " + "; ".join(parts) + ". Changes to these won't revoke trust."


def _vault_fingerprint() -> Optional[str]:
    try:
        return hashlib.sha256(store.SECRETS_FILE.read_bytes()).hexdigest()
    except OSError:
        return None


def cache_secrets(secrets: dict) -> None:
    global _cached_secrets, _cached_vault_fingerprint
    _cached_secrets = dict(secrets)
    _cached_vault_fingerprint = _vault_fingerprint()


def has_cached_secrets() -> bool:
    return _cached_secrets is not None


def cached_secrets() -> Optional[dict]:
    return dict(_cached_secrets) if _cached_secrets is not None else None


def trust(signature, file_hashes: dict) -> None:
    _trusted[signature] = file_hashes


def check(signature, command, cwd):
    """Returns (ok, invalidated_reason).

    ok=True: this exact signature was trusted, its referenced files are
    unchanged, the vault hasn't changed since these secrets were cached,
    and secrets are cached -- the caller may auto-allow with no dialog.

    ok=False, reason=None: never trusted for this exact signature, or
    trusted but no secrets cached yet (e.g. the server just started) --
    the caller must fall back to the normal dialog.

    ok=False, reason=<str>: WAS trusted, but either a referenced file
    changed/disappeared, or the vault itself changed, since approval.
    Trust (for this signature, or -- on a vault change -- for every
    signature) is revoked here and the reason is meant to be shown to the
    human in the fallback dialog.
    """
    global _cached_secrets, _cached_vault_fingerprint

    if signature not in _trusted or _cached_secrets is None:
        return False, None

    if _cached_vault_fingerprint is not None and _vault_fingerprint() != _cached_vault_fingerprint:
        # The vault changed since these secrets were cached -- every
        # trusted command was approved against a vault snapshot that no
        # longer exists, so the whole cache is stale, not just this one
        # signature. Drop it all; the next call (trusted or not) re-unlocks
        # and repopulates from the current vault.
        _trusted.clear()
        _cached_secrets = None
        _cached_vault_fingerprint = None
        return False, ("The vault changed since these secrets were cached (a secret was "
                        "added, removed, or the vault was re-unlocked) -- re-enter the "
                        "master password to refresh it.")

    approved_hashes = _trusted[signature]
    current_hashes = referenced_file_hashes(command, cwd)
    if current_hashes == approved_hashes:
        return True, None

    del _trusted[signature]
    # Parenthesized explicitly -- set `-` binds tighter than `|`, so
    # `a | b - c` is `a | (b - c)`, not the `(a | b) - c` this needs.
    unchanged = {p for p in approved_hashes
                 if approved_hashes.get(p) == current_hashes.get(p)}
    changed = sorted((set(approved_hashes) | set(current_hashes)) - unchanged)
    where = ", ".join(changed) if changed else "a referenced file"
    return False, (f"Trust for this exact command was revoked -- {where} "
                    f"changed (or appeared/disappeared) since it was approved. "
                    f"Re-approve to trust it again.")
