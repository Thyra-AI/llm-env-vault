"""Vault storage.

Two files hold the state, deliberately split by sensitivity:

  vault_index.json   plaintext map of  VAR_NAME -> placeholder number
                      (safe for anyone, including an AI agent, to read)

  vault.enc           Fernet-encrypted map of  VAR_NAME -> real secret value
                      (unreadable without the master password)

llm.env is regenerated purely from vault_index.json, so keeping it in
sync never requires the master password.

All writes to these files are atomic (write to a temp file in the same
directory, fsync, then os.replace over the target) so a crash or power
loss mid-write can never leave a truncated/corrupted vault.
"""
import base64
import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import crypto

# When installed as a Claude Code plugin, __file__ resolves inside a
# version-scoped cache directory (e.g.
# ~/.claude/plugins/cache/llm-env-vault/llm-env-vault/1.0.0/) that does NOT
# survive `claude plugin update` -- confirmed by a red-team audit to
# silently orphan vault.enc AND vault.salt in the old version's directory
# on a routine update, with no warning and no recovery path (the salt goes
# with it, so even a surviving vault.enc becomes permanently
# undecryptable). CLAUDE_PLUGIN_DATA is exported by Claude Code into every
# MCP server subprocess's environment automatically and is the one
# directory documented to survive plugin updates -- plugin_launcher.py
# already uses it for the venv, for exactly this reason. Store the vault
# in a subdirectory of it whenever it's set, so the vault survives updates
# the same way the venv does.
#
# Falls back to the old next-to-the-module location for a manual/dev
# install (running mcp_server.py directly, no CLAUDE_PLUGIN_DATA set),
# which was never affected by plugin updates in the first place.
_PLUGIN_DATA_DIR = os.environ.get("CLAUDE_PLUGIN_DATA")
ROOT = (Path(_PLUGIN_DATA_DIR).resolve() / "vault") if _PLUGIN_DATA_DIR \
    else Path(__file__).resolve().parent.parent
ROOT.mkdir(parents=True, exist_ok=True)

SALT_FILE = ROOT / "vault.salt"
SECRETS_FILE = ROOT / "vault.enc"
INDEX_FILE = ROOT / "vault_index.json"
ENV_FILE = ROOT / "llm.env"
TARGETS_FILE = ROOT / "targets.json"
TARGETS_LOCK_FILE = TARGETS_FILE.parent / "targets.json.lock"
BAK_FILE = ROOT / "vault.enc.bak"
# Plaintext inventory of encrypted files. Agent-readable BY DESIGN (it holds
# names and paths, never contents) and therefore agent-WRITABLE -- see the
# whole-file encryption section for the invariant that follows from that.
FILES_FILE = ROOT / "files.json"
FILES_LOCK_FILE = ROOT / "files.json.lock"
# vault.format.txt is a plaintext sibling recording format version, date, and minimum
# plugin version.  INVARIANT: purely informational -- no code path may ever read or
# branch on it, or it becomes an agent-writable downgrade lever.
FORMAT_FILE = ROOT / "vault.format.txt"
# Serialises the ENTIRE read-modify-write of vault.enc across processes.
# save_secrets' expect_fingerprint compare-and-swap is a TOCTOU check on its
# own -- it compares the on-disk hash and only then calls os.replace, with no
# lock in between. Within one process the Tkinter one-dialog-at-a-time rule
# hides that, but two Claude Code sessions are two servers: both can read a
# vault with no FMK, both mint one, both pass the fingerprint compare, and the
# second write silently clobbers the first -- after the first has already
# destroyed a plaintext whose only key was the FMK it just lost. The lock is
# advisory and best-effort (a stale lock file must never wedge the vault), so
# the fingerprint CAS stays as the second layer, not as the only one.
VAULT_LOCK_FILE = ROOT / "vault.enc.lock"

# How many times to retry acquiring the targets lock before giving up, and
# how long to sleep between retries.  30 × 50 ms = 1.5 s total maximum wait,
# which is generous for a low-contention, short critical-section local lock.
_LOCK_RETRIES = 30
_LOCK_RETRY_SLEEP = 0.05  # seconds

VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_VAR_NAME_LEN = 128

# Keys the vault body holds for its own purposes rather than as user
# variables. The prefix is deliberately a character validate_var_name can
# never accept, so the two namespaces cannot collide no matter what a user
# names a variable -- see is_reserved_key.
RESERVED_KEY_PREFIX = "#"
FMK_KEY = "#fmk"
FMK_BYTES = 32
ENV_LINE_RE = re.compile(
    r'^(?P<indent>\s*)(?P<export>export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)$'
)
PLACEHOLDER_VALUE_RE = re.compile(r'^"?value \d+"?$')

# Well-known OS/runtime-critical environment variable names.  Vaulting a
# secret under one of these names and then calling run_with_env will
# completely replace that variable for the launched child process (e.g. a
# secret named PATH would clobber the child's executable search path).
# This list is checked case-insensitively because Windows env var names
# are case-insensitive in practice.
SENSITIVE_ENV_NAMES: frozenset = frozenset({
    "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
    "PYTHONPATH", "PYTHONHOME", "LD_LIBRARY_PATH", "LD_PRELOAD", "NODE_OPTIONS",
    "HOME", "USERPROFILE", "TEMP", "TMP",
})


def validate_var_name(name: str) -> str:
    if not VAR_NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid variable name {name!r} -- must match [A-Za-z_][A-Za-z0-9_]* "
            "(letters, digits, underscore; can't start with a digit, no newlines/spaces)."
        )
    if len(name) > MAX_VAR_NAME_LEN:
        raise ValueError(
            f"Invalid variable name {name!r} -- length {len(name)} exceeds the "
            f"{MAX_VAR_NAME_LEN}-character maximum "
            "(Windows environment blocks and the consent-dialog layout both impose limits)."
        )
    return name


def is_sensitive_env_name(name: str) -> bool:
    """Return True if *name* matches a well-known OS/runtime-critical
    environment variable name (case-insensitive).  Does NOT block the
    operation -- callers use this only to surface a warning to the human.
    """
    return name.upper() in SENSITIVE_ENV_NAMES


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, mode)
        except OSError:
            pass  # best-effort; Windows ACLs don't map cleanly onto POSIX modes
        # Retry os.replace on Windows to handle transient antivirus file locks.
        for _attempt in range(_LOCK_RETRIES):
            try:
                os.replace(tmp_path, path)
                break
            except OSError:
                if _attempt == _LOCK_RETRIES - 1:
                    raise
                time.sleep(_LOCK_RETRY_SLEEP)
        # Best-effort POSIX directory fsync so the rename is durable on disk.
        try:
            _dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(_dir_fd)
            finally:
                os.close(_dir_fd)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def vault_exists() -> bool:
    """Return True if a usable vault exists on disk.

    v2 vault: SECRETS_FILE exists and starts with the v2 magic bytes.
    v1 vault: SECRETS_FILE exists AND SALT_FILE exists (both required for decryption).
    """
    if not SECRETS_FILE.exists():
        return False
    try:
        data = SECRETS_FILE.read_bytes()
    except OSError:
        return False
    if crypto.is_v2(data):
        return True
    return SALT_FILE.exists()


def load_index() -> dict:
    """vault_index.json is plaintext and, by design, meant to be safe for
    an AI agent to read -- which also means it must be validated on
    *read*, not just on write, so a tampered or hand-edited entry can
    never inject something unexpected (a newline, another assignment)
    into a target file via sync_target_file/regenerate_llm_env.
    """
    if not INDEX_FILE.exists():
        return {}
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"vault_index.json is corrupted: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("vault_index.json must contain a JSON object of VAR_NAME -> number.")
    seen_placeholders = {}
    for name, placeholder in data.items():
        validate_var_name(name)
        if not isinstance(placeholder, int) or isinstance(placeholder, bool) or placeholder < 1:
            raise ValueError(f"vault_index.json: {name!r} has a non-positive-integer placeholder.")
        # Two names sharing one placeholder number would make llm.env's
        # VAR="value N" lines ambiguous -- both names would read as the
        # same value, silently breaking the one-to-one mapping the whole
        # placeholder scheme depends on (found by a red-team audit: a
        # hand-edited or corrupted index with a duplicate number validated
        # cleanly and produced exactly this).
        if placeholder in seen_placeholders:
            raise ValueError(
                f"vault_index.json: placeholder number {placeholder} is used by both "
                f"{seen_placeholders[placeholder]!r} and {name!r} -- each variable must "
                f"have its own unique placeholder number."
            )
        seen_placeholders[placeholder] = name
    return data


def save_index(index: dict) -> None:
    """Persists vault_index.json and regenerates this repo's own llm.env.

    Deliberately does NOT touch any registered target .env -- that would
    be a silent side effect on a file outside this repo triggered by an
    unrelated add/remove. Call the resync_targets MCP tool explicitly
    when you want registered project files refreshed.
    """
    for name in index:
        validate_var_name(name)
    _atomic_write_text(INDEX_FILE, json.dumps(index, indent=2, sort_keys=True) + "\n")
    regenerate_llm_env(index)


def next_placeholder(index: dict) -> int:
    used = set(index.values())
    n = 1
    while n in used:
        n += 1
    return n


def regenerate_llm_env(index: dict) -> None:
    lines = [
        "# AUTO-GENERATED by llm-env-vault -- do not hand-edit.",
        "# Real values live encrypted in vault.enc and are never written here.",
        "# Call the run_with_env MCP tool to execute your app with the real values.",
        "",
    ]
    for var_name, placeholder in sorted(index.items(), key=lambda kv: kv[1]):
        validate_var_name(var_name)
        lines.append(f'{var_name}="value {placeholder}"')
    _atomic_write_text(ENV_FILE, "\n".join(lines) + "\n")


def load_targets() -> dict:
    """External real .env files this vault has migrated, mapped to the set
    of variable names *that specific file* declared. Scoping by file keeps
    one project's variable names from ever leaking into another project's
    .env when it gets resynced."""
    if not TARGETS_FILE.exists():
        return {}
    try:
        data = json.loads(TARGETS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"targets.json is corrupted: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("targets.json must contain a JSON object of path -> [var names].")
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, list) or not all(isinstance(n, str) for n in v):
            raise ValueError("targets.json is malformed: expected {path: [var names]}.")
        if not k.strip() or "\n" in k or "\r" in k or "\x00" in k:
            raise ValueError(f"targets.json has an invalid path key: {k!r}")
        for name in v:
            validate_var_name(name)
    return data


def save_targets(targets: dict) -> None:
    _atomic_write_text(TARGETS_FILE, json.dumps(targets, indent=2, sort_keys=True) + "\n")


# Per-thread re-entrancy depth, keyed by lock file. See _json_lock.
_lock_depth = threading.local()


@contextlib.contextmanager
def _json_lock(lock_path, label: str):
    """File-backed mutex serialising a read-modify-write on one state file.

    On Windows (the primary platform for this project), uses
    ``msvcrt.locking()`` on a dedicated lock file alongside the file it
    guards.  Falls back to ``fcntl.flock()`` on POSIX for cross-platform
    correctness.

    Retries up to ``_LOCK_RETRIES`` times with ``_LOCK_RETRY_SLEEP``-second
    gaps between attempts, then raises ``RuntimeError`` if the lock still
    can't be acquired (e.g. a process died while holding it).

    *label* names the guarded file in that error, since one generic
    "could not acquire lock" message across several independent locks would
    leave the user with no idea which operation is stuck.

    Every lock gets its OWN file.  Sharing one would serialise unrelated
    operations and couple two independent failure modes: a process stuck
    holding the targets lock would block file encryption, which has nothing
    to do with targets.json.

    RE-ENTRANT within a thread.  The OS-level lock is what excludes other
    PROCESSES; re-acquiring it on the same thread must not self-deadlock,
    because the natural way to write these operations nests them --
    get_or_create_fmk holds the vault lock and calls save_vault_body, which
    now takes it too.  Without re-entrancy that combination hangs for
    _LOCK_RETRIES and then raises, turning a correctness fix into an outage.
    Depth is tracked per thread, so two threads still serialise properly.
    """
    counts = getattr(_lock_depth, "counts", None)
    if counts is None:
        counts = _lock_depth.counts = {}
    key = os.path.normcase(str(lock_path))
    if counts.get(key):
        counts[key] += 1
        try:
            yield
        finally:
            counts[key] -= 1
        return

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        try:
            import msvcrt as _msvcrt  # Windows only
            _windows = True
        except ImportError:
            _windows = False

        if _windows:
            # msvcrt.locking() locks from the *current* file position, so
            # always seek to 0 before locking and before unlocking.
            for attempt in range(_LOCK_RETRIES):
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if attempt == _LOCK_RETRIES - 1:
                        raise RuntimeError(
                            f"Could not acquire the {label} lock after "
                            f"{_LOCK_RETRIES} retries -- another process may be "
                            f"stuck holding it."
                        ) from None
                    time.sleep(_LOCK_RETRY_SLEEP)
            counts[key] = 1
            try:
                yield
            finally:
                counts[key] = 0
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        else:
            import fcntl as _fcntl
            # Bounded like the Windows branch above rather than a blocking
            # flock: a process that died holding this must not wedge the vault
            # forever with no way to find out why.
            for attempt in range(_LOCK_RETRIES):
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    break
                except OSError:
                    if attempt == _LOCK_RETRIES - 1:
                        raise RuntimeError(
                            f"Could not acquire the {label} lock after "
                            f"{_LOCK_RETRIES} retries -- another process may be "
                            f"stuck holding it."
                        ) from None
                    time.sleep(_LOCK_RETRY_SLEEP)
            counts[key] = 1
            try:
                yield
            finally:
                counts[key] = 0
                _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _targets_lock():
    """Serialises the targets.json read-modify-write."""
    with _json_lock(TARGETS_LOCK_FILE, "targets.json"):
        yield


@contextlib.contextmanager
def _vault_lock():
    """Serialises the ENTIRE read-modify-write of vault.enc across processes.

    Hold this around any operation that reads the vault body, changes it, and
    writes it back -- get_or_create_fmk, save_secrets' reserved-key merge, and
    the file-key rotate/retire operations.  See VAULT_LOCK_FILE for why the
    fingerprint compare-and-swap is not sufficient on its own.

    The credential operations (change_password, upgrade_to_v2,
    reissue_recovery_key, recover_with_recovery_key) hold it too, and an
    earlier version of this docstring wrongly argued they need not: that they
    carry the body plaintext through verbatim rather than reconstructing it,
    so they had nothing to lose.  Carrying it verbatim is precisely the
    hazard.  They read the body, spend ~250 ms in two scrypt derivations and a
    backup write, and then write that stale plaintext back -- so a file key
    minted by another process in between is erased exactly as it was by
    save_secrets.  A safety audit destroyed a private key through
    change_password this way.  Backup-and-rollback does not help, because
    nothing failed: the credential change succeeds, and the loss is silent.

    Wedging is answered by the bounded retry on both branches (roughly 1.5 s,
    then a clear error naming the file), and by the fact that every one of
    these writes through _atomic_write_bytes with backup-and-rollback, so a
    failure to acquire leaves the vault exactly as it was.
    """
    with _json_lock(VAULT_LOCK_FILE, "vault.enc"):
        yield


def add_target(path: str, names) -> None:
    with _targets_lock():
        targets = load_targets()
        existing = set(targets.get(path, []))
        existing.update(names)
        targets[path] = sorted(existing)
        save_targets(targets)


def _find_closing_quote(value: str, q: str) -> int:
    """Index of the real closing quote matching the opening quote at index
    0, skipping backslash-escaped quotes, or -1 if there isn't one. Using
    the naive "first occurrence" search here previously truncated any
    quoted value containing an escaped quote of its own (e.g.
    `JSON="{\\"a\\":1}"` was cut down to just `{`), silently destroying
    the rest of the real secret.
    """
    i = 1
    n = len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if value[i] == q:
            return i
        i += 1
    return -1


def _unquote(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    q = value[0]
    if q in ("'", '"'):
        # Match the closing quote wherever it is, not only at the exact
        # end of the string -- "abc123"  # inline comment is an extremely
        # common, well-formed .env line, and requiring the quote to be the
        # literal last character misclassified it as unterminated (see
        # _looks_unterminated_quote) and swallowed following lines whole.
        end = _find_closing_quote(value, q)
        if end != -1:
            # Unescape the quote character itself (python-dotenv decodes
            # this too) so e.g. "{\"a\":1}" comes out as {"a":1}, matching
            # what the application actually received -- not the raw,
            # still-escaped fragment.
            return value[1:end].replace(f"\\{q}", q)
    else:
        # Unquoted values: strip a trailing inline comment the same way
        # python-dotenv does (whitespace, then #...), so `API_KEY=abc123
        # # prod key` migrates as `abc123`, not `abc123  # prod key`.
        value = re.sub(r"\s+#.*$", "", value)
    return value


def _looks_unterminated_quote(value: str) -> bool:
    stripped = value.rstrip()
    for q in ("'", '"'):
        if stripped.startswith(q) and _find_closing_quote(stripped, q) == -1:
            return True
    return False


def _read_raw(path: Path) -> str:
    """Reads text without translating line endings, so callers can
    preserve the file's original CRLF/LF/CR terminators on rewrite.
    utf-8-sig strips a leading BOM if present (common in files saved by
    Notepad/PowerShell on Windows) -- without it the first line becomes
    '\\ufeffFOO=bar', which doesn't match ENV_LINE_RE, so that variable
    would silently never be recognized as migratable.
    """
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return f.read()


def _dominant_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"


LOOKS_LIKE_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?[^\s#=]+\s*=")
# Captures only the key portion (before the first =) from an assignment-shaped line.
# Used to strip the value before storing unrecognized/swallowed lines so that real
# secret values never propagate into warning messages.
_KEY_EXTRACTOR_RE = re.compile(r"^\s*(?:export\s+)?([^\s#=]+)\s*=")

# Deliberately looser than VAR_NAME_RE -- still allows the intentionally-
# invalid-but-name-like text (hyphens, a leading digit) that
# unrecognized_name/swallowed exist to surface as a useful, unredacted
# diagnostic. Only rejects text that clearly isn't a name at all: contains
# ':', '/', '@', '?', or whitespace (the shape of a URL or credential
# string), or is implausibly long for a variable name.
_PLAUSIBLE_KEY_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")


def _safe_extracted_key(key: str, line_no: int) -> str:
    """Returns `key` verbatim only if it plausibly IS a name. Guards
    against the case _KEY_EXTRACTOR_RE's "everything before the first '='"
    capture isn't actually a name -- e.g. a URL or credential string
    swallowed from inside a multi-line value, where the text before the
    first '=' can itself BE the secret (https://user:secretpass@host/path?a=b
    extracts as 'https://user:secretpass@host/path?a'). Withholding this
    instead of the extracted text protects the one channel
    (unrecognized_name/swallowed) that's meant to carry only a name, never
    a value, into a warning the caller returns to the AI agent with no
    password or dialog."""
    if _PLAUSIBLE_KEY_RE.fullmatch(key):
        return key
    return f"(line {line_no}, contents withheld)"


def parse_env_file(path: Path) -> list:
    """Returns each line as one of:
      ('raw', text)                 -- comment/blank/genuinely unrecognized
      ('var', name, real_value)     -- a plain single-line assignment
      ('unsupported', name)         -- looks like the start of a multi-line
                                        or unterminated quoted value; the
                                        caller should skip it rather than
                                        silently truncate a real secret
      ('unrecognized_name', name)   -- assignment-shaped (KEY=...) but the
                                        key isn't a valid identifier (has a
                                        hyphen, starts with a digit, etc.);
                                        this vault can't manage it, but the
                                        caller must not claim the file is
                                        secret-free while it still holds a
                                        real, un-migrated value.
                                        Carries only the KEY name, never
                                        the raw line or the secret value.
      ('swallowed', name)           -- assignment-shaped line that landed
                                        inside an unterminated-quote's
                                        continuation range; likely a real
                                        value that never got migrated.
                                        Carries only the KEY name, never
                                        the raw line or the secret value.

    Once an unterminated quote is found, every following line is treated
    as part of that same broken/multi-line value until one is found ending
    in the same quote character -- otherwise a PEM key's body lines (which
    can themselves look like BASE64==\\nKEY=VALUE-shaped text) would each
    get independently misparsed as their own bogus variable and migrated
    as garbage.
    """
    parsed = []
    lines = _read_raw(path).splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            parsed.append(("raw", line))
            i += 1
            continue
        m = ENV_LINE_RE.match(line)
        if not m:
            if LOOKS_LIKE_ASSIGNMENT_RE.match(line):
                _km = _KEY_EXTRACTOR_RE.match(line)
                _key = _safe_extracted_key(_km.group(1), i + 1) if _km else "(unparseable name)"
                parsed.append(("unrecognized_name", _key))
            else:
                parsed.append(("raw", line))
            i += 1
            continue
        name, raw_value = m.group("name"), m.group("value")
        if _looks_unterminated_quote(raw_value):
            parsed.append(("unsupported", name))
            quote_char = raw_value[0]
            i += 1
            while i < n:
                cont = lines[i]
                if LOOKS_LIKE_ASSIGNMENT_RE.match(cont):
                    _km2 = _KEY_EXTRACTOR_RE.match(cont)
                    _key2 = _safe_extracted_key(_km2.group(1), i + 1) if _km2 else "(unparseable name)"
                    parsed.append(("swallowed", _key2))
                else:
                    parsed.append(("raw", cont))
                i += 1
                if cont.rstrip().endswith(quote_char):
                    break
            continue
        parsed.append(("var", name, _unquote(raw_value)))
        i += 1
    return parsed


def sync_target_file(path: Path, index: dict, managed_names, force_names=None) -> list:
    """Rewrite one external .env in place, touching only lines for
    `managed_names` (this file's own previously-migrated variables) --
    never variables that belong to some other registered target.

    A managed line is only overwritten if its current value already
    looks like one of our own placeholders (idempotent resync) -- UNLESS
    its name is in `force_names`, which install_migrate uses for the
    variables it just captured into the vault in this same operation (their real
    value obviously doesn't look like a placeholder yet; that's exactly
    what this call is meant to fix). Outside of `force_names`, a line
    that looks like something else -- a real value someone hand-edited
    back in -- is left completely alone and reported as a conflict
    rather than silently destroyed. A managed variable that no longer
    exists in the vault index gets its line commented out (not deleted,
    not left as a misleading literal "value N").

    Preserves the file's original permissions and line-ending style.
    Silently no-ops if the file has since been removed.
    """
    if not path.exists():
        return []
    managed_names = set(managed_names)
    force_names = set(force_names or ())
    raw = _read_raw(path)
    newline = _dominant_newline(raw)
    lines = raw.splitlines()

    # Anomaly guard: a legitimate resync comments out managed variables one
    # at a time -- each remove_secret call removes exactly one name from
    # the index, so at most one previously-live line per target typically
    # goes stale between resyncs. If a LARGE FRACTION of the currently-live
    # managed placeholders in this file would be commented out in a single
    # call, that's a far more likely sign the vault/index was replaced,
    # restored from an old backup, or corrupted out from under this file
    # than that a human genuinely removed most of this target's secrets in
    # the same breath. resync_targets needs no password by design
    # specifically because it can only ever touch placeholder text -- but
    # silently wiping most of a file's managed lines at once is still a
    # real, unattended data-loss event worth refusing rather than applying.
    #
    # Deliberately a fraction (at least half), not "every single one" --
    # confirmed by a red-team audit that an all-or-nothing check is trivial
    # to defeat: an index that happens to still share even one overlapping
    # name with this target's managed set (e.g. a corrupted/replaced index
    # that coincidentally retains one old name) let 3 of 4 lines be wiped
    # with no refusal. A single genuine removal (1 of N, however small N
    # is) must still always pass -- that's the behavior this guard exists
    # to leave alone -- so the fraction check is gated on at least 2
    # removals to begin with.
    currently_live, would_be_removed = set(), set()
    for line in lines:
        m = ENV_LINE_RE.match(line)
        if m and m.group("name") in managed_names:
            name = m.group("name")
            if PLACEHOLDER_VALUE_RE.match(m.group("value").strip()):
                currently_live.add(name)
                if name not in index and name not in force_names:
                    would_be_removed.add(name)
    if len(would_be_removed) >= 2 and len(would_be_removed) * 2 >= len(currently_live):
        raise ValueError(
            f"Refusing to resync {path}: this would comment out "
            f"{len(would_be_removed)} of {len(currently_live)} currently-managed "
            f"variable(s) ({', '.join(sorted(would_be_removed))}) in this file at "
            f"once, which looks like the vault/index was replaced or corrupted "
            f"rather than a genuine one-at-a-time remove_secret. Re-run "
            f"install_migrate to re-confirm this target with a human in the loop, "
            f"or fix the vault/index first if this is unexpected."
        )

    out_lines = []
    seen = set()
    conflicts = []
    for line in lines:
        m = ENV_LINE_RE.match(line)
        if m and m.group("name") in managed_names:
            name = m.group("name")
            current = m.group("value").strip()
            prefix = f'{m.group("indent")}{m.group("export") or ""}'
            if name in index:
                expected = f'"value {index[name]}"'
                if name in force_names or current == expected or PLACEHOLDER_VALUE_RE.match(current):
                    out_lines.append(f'{prefix}{name}={expected}')
                else:
                    out_lines.append(line)  # don't clobber something that isn't our own placeholder
                    conflicts.append(name)
            elif PLACEHOLDER_VALUE_RE.match(current):
                # Indent only, never the "export " prefix -- "export # ..."
                # is not a comment, it's an unparseable bare `export`
                # statement to python-dotenv and to `source`.
                out_lines.append(f'{m.group("indent")}# [llm-env-vault] {name} was removed '
                                  f'from the vault -- was: {line.strip()}')
            else:
                out_lines.append(line)
            seen.add(name)
        else:
            out_lines.append(line)

    for name in sorted(managed_names):
        if name in index and name not in seen:
            out_lines.append(f'{name}="value {index[name]}"')

    _atomic_write_bytes(
        path,
        newline.join(out_lines).encode("utf-8") + newline.encode("utf-8"),
        mode=stat.S_IMODE(path.stat().st_mode),
    )
    return conflicts


def _looks_like_plugin_cache_path(path: Path) -> bool:
    """True if `path` sits inside a Claude Code plugin cache directory
    (".../plugins/cache/...") -- the version-scoped location that does NOT
    survive `claude plugin update` (see the ROOT comment above this
    module's globals). Used only as a last-resort safety net in
    create_secrets_vault: if CLAUDE_PLUGIN_DATA isn't set (so ROOT fell
    back to next to the module) AND the module itself is running from
    inside a plugin cache path, creating a brand-new vault there would
    silently repeat the exact update-destroying failure the ROOT
    relocation exists to close -- refuse instead of doing it quietly, in
    case a future Claude Code version ever stops exporting
    CLAUDE_PLUGIN_DATA (or exports it under a different name)."""
    parts = {p.lower() for p in path.parts}
    return "plugins" in parts and "cache" in parts


def create_secrets_vault(password: str) -> None:
    """First-time setup: new salt, empty encrypted secrets store.

    Refuses if vault.salt already exists without a matching vault.enc --
    generating a fresh salt in that state would silently make any
    surviving backup copy of vault.enc permanently undecryptable, even
    with the correct password.
    """
    if not _PLUGIN_DATA_DIR and _looks_like_plugin_cache_path(Path(__file__).resolve()):
        raise RuntimeError(
            "Refusing to create a new vault here: this looks like a Claude Code "
            "plugin install (running from inside a plugins/cache directory), but "
            "CLAUDE_PLUGIN_DATA isn't set in this process's environment. Creating "
            "the vault next to the module in that state would silently place it "
            "somewhere `claude plugin update` destroys later -- exactly the "
            "failure this project's vault-location logic exists to avoid. If "
            "you're intentionally running a manual/dev copy from inside that "
            "path, move it outside .claude/plugins/cache first."
        )
    if SECRETS_FILE.exists():
        raise RuntimeError(
            "vault.enc already exists. Refusing to overwrite an existing vault -- "
            "delete vault.enc yourself if you really want to start over (this is "
            "unrecoverable; make sure you have exported all secrets first)."
        )
    if SALT_FILE.exists():
        raise RuntimeError(
            "vault.salt already exists but vault.enc is missing. Refusing to "
            "generate a new salt -- restore vault.enc from backup, or delete "
            "vault.salt yourself if you really want to start over."
        )
    salt = crypto.new_salt()
    _atomic_write_bytes(SALT_FILE, salt)
    save_secrets(password, {})


def render_env_text(secrets: dict) -> str:
    """Real .env-format text for a decrypted secrets dict -- used only to
    materialize a short-lived real file for tools (Docker's --env-file,
    etc.) that insist on reading a file rather than inheriting process
    environment variables. Never written by anything except the
    run_with_env MCP tool, and only for the lifetime of the command it
    launches.

    Deliberately unquoted: `docker run --env-file` takes the entire
    remainder of the line after the first "=" as the literal value and
    does NOT strip quotes the way python-dotenv does -- a quoted value
    would arrive in the container with the quote characters still in it
    (confirmed empirically; this bit the first version of this function).
    Since --materialize exists specifically for --env-file-style
    consumers, matching their actual parsing is the correct default.

    Raises ValueError if any value contains a newline: there is no safe
    single-line representation for that, and writing one anyway would let
    a secret value inject an unrelated extra "NAME=..." line into a file
    a tool like Docker parses as trusted configuration.
    """
    # Defence in depth: this function writes real values to a real file, so a
    # reserved body key reaching it would put vault-internal key material on
    # disk in plaintext. load_secrets already filters them out -- if one is
    # here, something upstream is broken and the right move is to stop, not to
    # write the file and hope.
    leaked = sorted(k for k in secrets if is_reserved_key(k))
    if leaked:
        raise ValueError(
            f"Internal error: reserved vault key(s) {leaked} reached "
            f"render_env_text -- refusing to write them to disk."
        )

    lines = []
    for name, value in sorted(secrets.items()):
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"{name}'s value contains a newline -- refusing to materialize it as a "
                f"single-line .env file (it could inject an unrelated extra assignment "
                f"into whatever reads that file)."
            )
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def write_materialized_env(path: Path, secrets: dict) -> None:
    """Writes the real, decrypted secrets to `path` as a short-lived plain
    .env file (mode 0600, atomic). This is the one place real values ever
    land on disk outside of vault.enc -- keep the write itself here,
    alongside render_env_text, rather than callers reaching into
    _atomic_write_text directly across the module boundary."""
    _atomic_write_text(path, render_env_text(secrets), mode=0o600)


# Coarsens vault.enc's ciphertext length to a multiple of this many bytes
# before encryption, via PKCS7-style padding. Fernet's CBC mode leaks the
# plaintext length rounded up to its own 16-byte block size; since variable
# NAMES are already public by design (vault_index.json), the only thing
# this narrows further is the aggregate byte size of every real VALUE
# combined -- a weak signal (not per-value, not content), but free to
# reduce. A red-team audit called this out as worth doing "if you care."
_PAD_BLOCK = 64


def _pkcs7_pad(data: bytes, block_size: int = _PAD_BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = _PAD_BLOCK) -> bytes:
    """Best-effort strip: only removes trailing bytes that actually look
    like this module's own padding (in-range count, every padding byte
    matching that count). Anything else is returned unchanged -- this is
    what lets load_secrets tell a genuinely padded vault apart from an
    older, unpadded one without a format version flag (see load_secrets)."""
    if not data:
        return data
    pad_len = data[-1]
    if not (1 <= pad_len <= block_size) or pad_len > len(data):
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# v2 private helpers
# ---------------------------------------------------------------------------

def _pkcs7_unpad_strict(data: bytes, block_size: int = _PAD_BLOCK) -> bytes:
    """Strict PKCS7 unpadding for v2 vaults.

    For v2, the GCM tag is verified before this runs, so there is no padding
    oracle.  We unpad strictly and raise on any malformed padding rather than
    silently returning data as-is (the 'best-effort' behaviour of _pkcs7_unpad
    is a compatibility shim for unpadded v1 vaults, which does not apply here).
    """
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad_len = data[-1]
    if not (1 <= pad_len <= block_size) or pad_len > len(data):
        raise ValueError(f"Invalid PKCS7 padding length byte: {pad_len!r}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("PKCS7 padding bytes are malformed.")
    return data[:-pad_len]


def _b64u(data: bytes) -> str:
    """URL-safe base64 encode to ASCII string (no line breaks, no padding stripped)."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def _file_fingerprint(path: Path) -> str:
    """SHA-256 hex digest of path's current bytes -- used for compare-and-swap."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _backup_vault() -> bytes:
    """Write vault.enc.bak (mode 0600) before a credential-changing write.

    Returns the original bytes so the caller can use them for rollback without
    a second read.  The backup is a safety net only; callers MUST call
    _cleanup_backup() after a successful read-back so the old password slot is
    not left alive on disk.
    """
    original = SECRETS_FILE.read_bytes()
    _atomic_write_bytes(BAK_FILE, original, mode=0o600)
    return original


def _cleanup_backup() -> None:
    """Delete vault.enc.bak after a successful credential-changing write.

    Left in place the backup keeps the old password slot alive on disk and
    turns a rollback attack into a one-file copy -- delete it promptly.
    Best-effort; never raises.
    """
    try:
        BAK_FILE.unlink()
    except OSError:
        pass


def _write_format_file(version: int) -> None:
    """Write vault.format.txt as a purely informational plaintext sibling.

    INVARIANT: no code path may ever read or branch on this file.  It is
    written here and nowhere else; reading it would make it an agent-writable
    downgrade lever.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    text = (
        f"format_version={version}\n"
        f"date={now}\n"
        f"min_plugin_version=1.4.0\n"
    )
    _atomic_write_text(FORMAT_FILE, text, mode=0o644)


def _vault_id_from_header(header: dict) -> bytes:
    """Decode the vault_id field from a parsed v2 header."""
    return base64.urlsafe_b64decode(header["vault_id"] + "==")


def _params_from_header(header: dict) -> "crypto.ScryptParams":
    """Extract and floor-correct scrypt params from a v2 header.

    If the header's password-slot params are below SCRYPT_FLOOR (possible if
    an attacker downgrades the header), returns SCRYPT_DEFAULT so that the
    weakened params are not persisted on the next save.
    """
    pw_slot = next(
        (s for s in header.get("slots", []) if s.get("type") == "password"), None
    )
    if pw_slot is None:
        return crypto.SCRYPT_DEFAULT
    kdf = pw_slot["kdf"]
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    try:
        crypto.validate_scrypt_params(n, r, p)
    except crypto.VaultCorrupted:
        return crypto.SCRYPT_DEFAULT
    floor = crypto.SCRYPT_FLOOR
    if n < floor.n or r < floor.r or p < floor.p:
        return crypto.SCRYPT_DEFAULT
    return crypto.ScryptParams(n=n, r=r, p=p)


def _build_password_slot(
    dek: bytes,
    password: str,
    params: "crypto.ScryptParams",
    vault_id: bytes,
) -> dict:
    """Construct a password-slot dict for a v2 header."""
    pw_salt = os.urandom(16)
    pw_kek = crypto.derive_password_kek(password, pw_salt, params)
    pw_aad = crypto.slot_aad(vault_id, "password")
    pw_nonce, pw_wrapped = crypto.wrap_dek(pw_kek, dek, pw_aad)
    return {
        "type": "password",
        "kdf": {
            "name": "scrypt",
            "n": params.n,
            "r": params.r,
            "p": params.p,
            "salt": _b64u(pw_salt),
        },
        "nonce": _b64u(pw_nonce),
        "wrapped_dek": _b64u(pw_wrapped),
    }


def _build_recovery_slot(
    dek: bytes,
    recovery_raw: bytes,
    vault_id: bytes,
) -> tuple:
    """Construct a recovery-slot dict for a v2 header.  Returns (slot_dict, slot_id)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rk_salt = os.urandom(16)
    rk_kek = crypto.derive_recovery_kek(recovery_raw, rk_salt, vault_id)
    rk_aad = crypto.slot_aad(vault_id, "recovery")
    rk_nonce, rk_wrapped = crypto.wrap_dek(rk_kek, dek, rk_aad)
    slot_id = crypto.new_slot_id()
    slot = {
        "type": "recovery",
        "id": slot_id,
        "created": now,
        "kdf": {
            "name": "hkdf-sha256",
            "salt": _b64u(rk_salt),
            "info": "llm-env-vault/v2/recovery-kek",
        },
        "nonce": _b64u(rk_nonce),
        "wrapped_dek": _b64u(rk_wrapped),
    }
    return slot, slot_id


def _verify_v2_slots(
    data: bytes,
    password: str,
    new_recovery_raw: Optional[bytes] = None,
) -> None:
    """Re-read and verify every slot in a freshly-written v2 vault.

    Always verifies the password slot.  If *new_recovery_raw* is provided,
    also verifies the recovery slot and asserts the unwrapped DEKs match --
    a mismatched DEK means one slot was written wrong and would silently
    deliver wrong plaintext (or fail to open) at the exact moment it is needed.

    Raises RuntimeError with a clear message; never raises WrongPassword
    (that would make the caller think it was a user-input problem, not an
    internal consistency failure).
    """
    try:
        _pt_pw, dek_pw, _hdr = crypto.open_v2_with_password(data, password)
    except Exception as exc:
        raise RuntimeError(
            f"Password slot read-back failed after write: {exc}"
        ) from exc

    # Verify the stored plaintext is structurally valid (well-padded JSON).
    try:
        _pkcs7_unpad_strict(_pt_pw)
    except ValueError as exc:
        raise RuntimeError(f"Password slot plaintext padding corrupt: {exc}") from exc

    if new_recovery_raw is not None:
        rk_text = crypto.format_recovery_key(bytes(new_recovery_raw))
        try:
            _pt_rk, dek_rk, _hdr2 = crypto.open_v2_with_recovery(data, rk_text)
        except Exception as exc:
            raise RuntimeError(
                f"Recovery slot read-back failed after write: {exc}"
            ) from exc
        if bytes(dek_pw) != bytes(dek_rk):
            raise RuntimeError(
                "DEK mismatch between password and recovery slots -- "
                "vault is internally inconsistent (slot write error)."
            )


def _load_secrets_v1(password: str, token: bytes) -> dict:
    """Decrypt a v1 (Fernet/PBKDF2) vault.  Internal use only."""
    salt = SALT_FILE.read_bytes()
    plaintext = crypto.decrypt(password, salt, token)
    # Padding was added after vaults already existed in the wild (including
    # this repo's own), so decryption has to accept both shapes: try the
    # raw bytes first (an older, unpadded vault is exactly valid JSON as-is
    # and this succeeds immediately with no fallback needed), and only fall
    # back to stripping padding if that fails. Not "the current code always
    # takes the second path" -- when the padding length happens to equal a
    # JSON whitespace byte (tab/LF/CR/space -- 9, 10, 13, or 32), the padded
    # bytes are indistinguishable from ordinary trailing whitespace and the
    # FIRST parse already succeeds with the correct value; the fallback only
    # fires for the other ~94% of possible padding lengths. Either path
    # returns the same correct dict -- this is a code-path note, not a
    # correctness distinction. Every vault gets padded on its next save
    # regardless of which path loaded it.
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    try:
        return json.loads(_pkcs7_unpad(plaintext).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Decrypted vault contents are corrupted.") from None


# ---------------------------------------------------------------------------
# Reserved body keys
# ---------------------------------------------------------------------------
#
# The encrypted body is a flat  {VAR_NAME: value}  dict.  Whole-file
# encryption needs one more thing in there -- the File Master Key -- and it
# has to live INSIDE the body rather than in the v2 header, because every
# credential operation (change_password, reissue_recovery_key,
# recover_with_recovery_key) rotates the DEK but carries the body plaintext
# through verbatim.  A key in the body therefore survives all three for free;
# a key in the header would have to be rebuilt correctly in four places, and
# forgetting one silently orphans every encrypted file.
#
# Two hazards come with sharing the namespace, and the second is worse:
#
#   1. Leaking.  run_with_env does env.update(secrets); Windows CreateProcess
#      is happy to pass a "#"-prefixed name straight to the child.  A reserved
#      key in that dict would also trip gui._disclosure_mismatch, which
#      fail-safes by refusing every only_vars=None run.
#   2. Dropping.  Every mutation here is load -> mutate -> save.  If any of
#      those saves a variables-only dict, the FMK is deleted and every
#      encrypted file becomes permanently unopenable -- with no error at the
#      time, and the failure surfacing weeks later on a file whose plaintext
#      was already destroyed.
#
# So the SAFE names are the existing ones: load_secrets/save_secrets handle
# reserved keys correctly and callers need no edits.  Raw access lives behind
# load_vault_body/save_vault_body -- names that appear nowhere else in this
# codebase and read as a warning at the call site.


def is_reserved_key(name) -> bool:
    """True if *name* is a vault-internal body key rather than a user variable.

    validate_var_name requires [A-Za-z_][A-Za-z0-9_]*, so it can never accept
    a name starting with "#".  That is the whole collision argument: the two
    namespaces are disjoint by construction, not by convention.
    """
    return isinstance(name, str) and name.startswith(RESERVED_KEY_PREFIX)


def _split_body(body: dict) -> tuple:
    """Split a raw body dict into ``(variables, reserved)``."""
    variables, reserved = {}, {}
    for key, value in body.items():
        (reserved if is_reserved_key(key) else variables)[key] = value
    return variables, reserved


def _merge_reserved(prior_body: dict, new_vars: dict) -> dict:
    """Rebuild a full body from *new_vars* plus *prior_body*'s reserved keys.

    Disk always wins for reserved keys: they are vault-internal state that no
    variable-level caller has any business changing, and letting a stale
    in-memory copy overwrite them is exactly the lost-FMK bug this exists to
    prevent.

    Raises ValueError if *new_vars* itself carries a reserved key.  That is the
    trap: a caller who "helpfully" round-trips a raw body through save_secrets
    fails loudly here instead of maybe-working and silently discarding the
    reserved state it thought it was preserving.
    """
    smuggled = sorted(k for k in new_vars if is_reserved_key(k))
    if smuggled:
        raise ValueError(
            f"save_secrets refuses reserved vault key(s) {smuggled} -- these are "
            f"internal state, not variables. Use save_vault_body if you really "
            f"mean to write the raw body."
        )
    return {**new_vars, **{k: v for k, v in prior_body.items() if is_reserved_key(k)}}


def _decode_body(plaintext: bytes, what: str) -> dict:
    """Strict-unpad and JSON-decode a v2 body plaintext."""
    try:
        return json.loads(_pkcs7_unpad_strict(plaintext).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise ValueError(f"Decrypted {what} contents are corrupted.") from None


# ---------------------------------------------------------------------------
# Raw body accessors -- reserved keys INCLUDED.  Prefer load_secrets.
# ---------------------------------------------------------------------------

def load_vault_body(password: str) -> dict:
    """Decrypt and return the FULL body, reserved keys included.

    Almost every caller wants load_secrets instead.  Use this only when you
    genuinely need the vault's internal state, and pair it with
    save_vault_body -- never with save_secrets, which would refuse the
    reserved keys you are holding.
    """
    body, _envelope, _fingerprint = load_vault_body_ex(password)
    return body


def load_vault_body_ex(password: str) -> tuple:
    """``(full_body, envelope_bytes_or_None, fingerprint)`` -- see load_secrets_ex."""
    data = SECRETS_FILE.read_bytes()
    fingerprint = hashlib.sha256(data).hexdigest()
    if crypto.is_v2(data):
        plaintext, _dek, _header = crypto.open_v2_with_password(data, password)
        return _decode_body(plaintext, "v2 vault"), data, fingerprint
    return _load_secrets_v1(password, data), None, fingerprint


def save_vault_body(
    password: str,
    body: dict,
    expect_fingerprint=None,
) -> None:
    """Encrypt and persist a FULL body verbatim -- no reserved-key merge.

    The caller is responsible for having preserved every reserved key it does
    not intend to remove.  save_secrets is the safe door; this is the one that
    trusts you.
    """
    _write_body(password, body, expect_fingerprint)


# ---------------------------------------------------------------------------
# File Master Key
# ---------------------------------------------------------------------------

def _update_sealed(password: str, additions=None, removals=None) -> None:
    """Record or clear sealed file identities, under the vault lock.

    *additions* and *removals* are ``{generation_id: [file_id, ...]}``.

    Both operations are idempotent: adding an id already present is a no-op,
    and removing one that is absent is a no-op. That is the whole point --
    a retried encrypt cannot inflate the record, and a duplicated registry
    entry cannot deflate it. Every failure mode rounds toward retire refusing,
    which is the safe direction.
    """
    additions = additions or {}
    removals = removals or {}
    if not additions and not removals:
        return
    with _vault_lock():
        body, _envelope, fingerprint = load_vault_body_ex(password)
        record = body.get(FMK_KEY)
        if record is None:
            return
        sealed = {gen: list(ids) for gen, ids in (record.get("sealed") or {}).items()}
        for gen, ids in removals.items():
            if gen in sealed:
                drop = set(ids)
                sealed[gen] = [i for i in sealed[gen] if i not in drop]
        for gen, ids in additions.items():
            current = sealed.setdefault(gen, [])
            for file_id in ids:
                if file_id not in current:
                    current.append(file_id)
        record = dict(record)
        record["sealed"] = sealed
        body[FMK_KEY] = record
        save_vault_body(password, body, expect_fingerprint=fingerprint)


def _sealed_ids(record: dict, gen: str) -> list:
    """The file_ids outstanding under one generation."""
    return list(((record or {}).get("sealed") or {}).get(gen) or [])


def get_fmk(password: str):
    """Return the FMK record ``{"active": id, "keys": {id: b64u}}``, or None.

    Read-only: never mints.  None means this vault has never encrypted a file.
    """
    return load_vault_body(password).get(FMK_KEY)


def get_or_create_fmk(password: str) -> dict:
    """Return the FMK record, minting and persisting one on first use.

    Held under _vault_lock for the whole read-modify-write.  Without it two
    processes can both observe "no FMK", both mint, and the second write wipes
    the first -- orphaning any file the first already encrypted.  The
    fingerprint compare-and-swap is kept as a second layer: on a mismatch we
    re-read and ADOPT whatever FMK is now on disk rather than minting a rival,
    and only mint again if there still isn't one.
    """
    with _vault_lock():
        for attempt in (0, 1):
            body, _envelope, fingerprint = load_vault_body_ex(password)
            existing = body.get(FMK_KEY)
            if existing is not None:
                return existing

            fmk_id = crypto.new_fmk_id()
            record = {
                "active": fmk_id,
                "keys": {fmk_id: _b64u(bytes(crypto.new_fmk()))},
                # WHICH files this vault has sealed under each generation and
                # not yet moved off it -- a list of file_ids, not a count.
                # Identities rather than events, because every way a count can
                # be driven wrong is a way to delete a key something still
                # needs: two registry entries pointing at copies of one
                # envelope decrement it twice, and a crash-then-resume
                # increments it twice. Removing an id is idempotent, so none
                # of that can happen. Lives in the encrypted body, so the
                # STORAGE travels with vault.enc and no agent can edit it --
                # though the inputs to it still come from disk, so this is a
                # strong backstop rather than an oracle. See retire_file_keys.
                "sealed": {fmk_id: []},
            }
            body[FMK_KEY] = record
            try:
                save_vault_body(password, body, expect_fingerprint=fingerprint)
            except RuntimeError:
                # Someone wrote vault.enc between our read and our write.
                # Loop once to adopt their FMK instead of clobbering it.
                if attempt == 0:
                    continue
                raise
            return record

    # pragma: no cover -- the loop above always returns or raises
    raise RuntimeError(
        "Could not establish a file master key: vault.enc kept changing underneath."
    )


def load_secrets(password: str) -> dict:
    """Decrypt and return the secrets dict.

    Routes on the vault magic bytes: v2 uses scrypt/AES-GCM; v1 uses the
    legacy PBKDF2/Fernet path.  The routing decision is based on the file
    content, not on any external flag -- there is no agent-writable downgrade
    lever (vault.format.txt is never read here; see FORMAT_FILE's invariant).

    Returns USER VARIABLES ONLY -- reserved body keys are filtered out.  Pair
    it with save_secrets, which puts them back.  If you actually need the
    vault's internal state, use load_vault_body.
    """
    variables, _reserved = _split_body(load_vault_body(password))
    return variables


def load_secrets_ex(password: str) -> tuple:
    """Decrypt vault and return ``(secrets, envelope_bytes_or_None, fingerprint)``.

    *envelope_bytes_or_None* is the raw file bytes for v2 (so callers can
    pass it to ``crypto.build_envelope`` etc.) or None for v1.

    *fingerprint* is the SHA-256 hex digest of the on-disk bytes at the time
    of this read -- pass it back to ``save_secrets`` as *expect_fingerprint*
    to turn a silent lost-update into an honest error.

    Like load_secrets, returns USER VARIABLES ONLY.
    """
    body, envelope, fingerprint = load_vault_body_ex(password)
    variables, _reserved = _split_body(body)
    return variables, envelope, fingerprint


def save_secrets(
    password: str,
    secrets: dict,
    expect_fingerprint: Optional[str] = None,
) -> None:
    """Encrypt and persist the user variables, preserving reserved body keys.

    Writes back in whatever format the vault is currently in (v1 stays v1,
    v2 stays v2) -- use ``upgrade_to_v2`` to promote a v1 vault.

    *secrets* is variables only, exactly what load_secrets returned.  Any
    reserved key the vault holds is re-read from disk and merged back in, so
    the ordinary load -> mutate -> save cycle can never drop one.  Passing a
    reserved key in *secrets* raises ValueError -- see _merge_reserved.

    *expect_fingerprint*: if provided, the call raises ``RuntimeError`` if the
    on-disk file changed since the caller last read it (compare-and-swap guard
    against concurrent writers -- e.g. GUI + MCP server).

    v2 saves reuse the header's existing KDF params so that every save does
    not silently mutate user-chosen parameters.  Exception: if the header's
    scrypt params are below SCRYPT_FLOOR (possible via attacker-written header),
    the password slot is silently upgraded to SCRYPT_DEFAULT on this save so
    that the weakness is not persisted.
    """
    _write_body(password, secrets, expect_fingerprint, merge_reserved=True)


def _write_body(
    password: str,
    body: dict,
    expect_fingerprint: Optional[str] = None,
    *,
    merge_reserved: bool = False,
) -> None:
    """Shared writer behind save_secrets and save_vault_body.

    *merge_reserved* is what separates the two doors: True re-reads the
    on-disk body and folds its reserved keys into *body* before writing
    (save_secrets), False writes *body* exactly as given (save_vault_body).

    The merge is free on v2: the branch below already decrypts to reach the
    DEK and header, and used to throw that plaintext away.  It now keeps it.

    HELD UNDER _vault_lock for the whole read-modify-write, and that is not
    optional.  This is the one writer that reconstructs the body from a value
    it read earlier, so it is the one writer that can destroy state another
    process wrote in between.  The window is not small: between reading
    vault.enc and replacing it sits a full scrypt derivation (~100 ms at
    n=2**16).  A file-key mint landing inside that window used to be
    overwritten by the stale body, and because encrypt_file had already
    destroyed the plaintext by then, every file sealed under that key became
    permanently unopenable -- silently, with no error at any point.
    expect_fingerprint cannot cover this on its own: it compares and *then*
    replaces, which is the definition of a TOCTOU race.
    """
    with _vault_lock():
        _write_body_locked(password, body, expect_fingerprint,
                            merge_reserved=merge_reserved)


def _write_body_locked(
    password: str,
    body: dict,
    expect_fingerprint: Optional[str] = None,
    *,
    merge_reserved: bool = False,
) -> None:
    """_write_body's body, with the vault lock assumed already held."""
    # If vault.enc doesn't exist yet, this is first-time creation from
    # create_secrets_vault which writes vault.salt first and then calls us.
    # Fall through to the v1 path -- there's nothing to read yet, so there is
    # no prior body to merge and the smuggled-key check is all that applies.
    if not SECRETS_FILE.exists():
        if merge_reserved:
            body = _merge_reserved({}, body)
        salt = SALT_FILE.read_bytes()
        padded = _pkcs7_pad(json.dumps(body).encode("utf-8"))
        token = crypto.encrypt(password, salt, padded)
        _atomic_write_bytes(SECRETS_FILE, token)
        return

    data = SECRETS_FILE.read_bytes()

    if expect_fingerprint is not None:
        fp = hashlib.sha256(data).hexdigest()
        if fp != expect_fingerprint:
            raise RuntimeError(
                "vault.enc changed since it was last read -- refusing to overwrite "
                "(compare-and-swap mismatch).  Re-read the vault and retry."
            )

    if crypto.is_v2(data):
        _pt, dek, header = crypto.open_v2_with_password(data, password)
        if merge_reserved:
            body = _merge_reserved(_decode_body(_pt, "v2 vault"), body)
        padded = _pkcs7_pad(json.dumps(body).encode("utf-8"))
        vault_id = _vault_id_from_header(header)

        # Determine if the password slot is below the floor and needs upgrading.
        pw_slot_orig = next(
            (s for s in header.get("slots", []) if s.get("type") == "password"), None
        )
        if pw_slot_orig is not None:
            orig_n = int(pw_slot_orig["kdf"].get("n", 0))
            below_floor = orig_n < crypto.SCRYPT_FLOOR.n
        else:
            below_floor = True  # no password slot is definitely wrong

        if below_floor:
            # Silently upgrade the password slot to SCRYPT_DEFAULT; keep
            # the existing DEK (this is NOT a credential change, so no
            # backup/rollback is performed -- the body content is unchanged
            # and the DEK is the same; only the password KDF wrapping is stronger).
            good_params = crypto.SCRYPT_DEFAULT
            new_pw_slot = _build_password_slot(bytes(dek), password, good_params, vault_id)
            new_slots = [new_pw_slot] + [
                s for s in header["slots"] if s.get("type") != "password"
            ]
            new_header = dict(header)
            new_header["slots"] = new_slots
        else:
            new_header = header

        new_data = crypto.build_envelope(new_header, bytes(dek), padded)
        _atomic_write_bytes(SECRETS_FILE, new_data)
    else:
        # v1 path.  Unlike v2 there is no decryption on the way in, so the
        # merge costs an extra PBKDF2 -- do it anyway for correctness, but
        # never let it turn a working save into a failure.  change_password's
        # v1 path in particular calls us with the NEW password while the file
        # on disk is still under the OLD one, so this read cannot succeed
        # there; that path bypasses the merge entirely via save_vault_body,
        # and this except is the belt to that braces.
        if merge_reserved:
            try:
                prior = _load_secrets_v1(password, data)
            except Exception:
                prior = {}
            body = _merge_reserved(prior, body)
        padded = _pkcs7_pad(json.dumps(body).encode("utf-8"))
        salt = SALT_FILE.read_bytes()
        token = crypto.encrypt(password, salt, padded)
        _atomic_write_bytes(SECRETS_FILE, token)


def change_password(
    old_password: str,
    new_password: str,
) -> Optional[str]:
    """Re-encrypt vault.enc under new_password with DEK rotation.

    v1 vault: reuses vault.salt; re-encrypts body under new Fernet key.
    v2 vault: rotates the DEK so that an adversary who later learns the old
    password cannot decrypt future snapshots; rebuilds all slots.  If the
    vault had a recovery slot, a NEW recovery key is issued (the old printout
    is immediately invalidated) and its formatted string is returned.  If
    there was no recovery slot, returns None.

    Read-back verification unwraps every slot written before returning.
    Backup is written before the write and deleted after successful
    verification; if read-back fails the original bytes are restored and a
    clear error is raised -- the password is NOT changed.

    Raises crypto.WrongPassword for a bad old_password.
    Raises FileNotFoundError if no vault exists.
    """
    with _vault_lock():
        return _change_password_locked(old_password, new_password)


def _change_password_locked(old_password: str,
    new_password: str,
):
    """change_password's body, with the vault lock assumed already held."""
    if not vault_exists():
        raise FileNotFoundError(
            "No vault found (vault.enc or vault.salt is missing). "
            "Create a vault first before changing the password."
        )

    data = SECRETS_FILE.read_bytes()

    if not crypto.is_v2(data):
        # ---- v1 path (legacy) ----
        # crypto.WrongPassword propagates unchanged; do not swallow it.
        #
        # Deliberately the RAW body accessors, not load_secrets/save_secrets.
        # save_secrets would try to merge reserved keys by re-reading the file,
        # but at this instant vault.enc is still sealed under old_password
        # while we are handing it new_password -- it cannot read the prior body
        # and would drop every reserved key. Carrying the whole body across
        # sidesteps the merge entirely, which is also more obviously correct:
        # a password change should change the password and nothing else.
        body = load_vault_body(old_password)
        original_bytes = SECRETS_FILE.read_bytes()
        # The salt is deliberately reused -- rotating it would require a
        # two-file atomic write that does not exist, creating a crash window
        # that can permanently brick the vault.
        save_vault_body(new_password, body)
        try:
            verified = load_vault_body(new_password)
        except Exception as exc:
            _atomic_write_bytes(SECRETS_FILE, original_bytes)
            raise RuntimeError(
                "Password change failed during read-back verification -- "
                "vault has been restored to its previous state. "
                "The password was NOT changed."
            ) from exc
        if verified != body:
            _atomic_write_bytes(SECRETS_FILE, original_bytes)
            raise RuntimeError(
                "Password change aborted: read-back produced a different secret dict -- "
                "vault has been restored to its previous state. "
                "The password was NOT changed."
            )
        return None

    # ---- v2 path ----
    # open_v2_with_password raises WrongPassword if old_password is wrong.
    plaintext_bytes, old_dek, header = crypto.open_v2_with_password(data, old_password)

    vault_id = _vault_id_from_header(header)
    params = _params_from_header(header)  # floor-corrected

    rk_slot_exists = any(
        s.get("type") == "recovery" for s in header.get("slots", [])
    )

    # Back up before the write.
    original_bytes = _backup_vault()

    # Rotate DEK.  An adversary who later learns the old password and has a
    # snapshot of the old vault.enc cannot decrypt future bodies, because the
    # new DEK is independent of the old one -- re-wrapping alone would make
    # change_password security theater in this threat model.
    new_dek = crypto.new_dek()

    # New password slot.
    new_pw_slot = _build_password_slot(bytes(new_dek), new_password, params, vault_id)
    new_slots = [new_pw_slot]

    # New recovery slot (new key) if one existed.
    new_recovery_raw: Optional[bytearray] = None
    if rk_slot_exists:
        new_recovery_raw = crypto.new_recovery_key()
        rec_slot, _ = _build_recovery_slot(
            bytes(new_dek), bytes(new_recovery_raw), vault_id
        )
        new_slots.append(rec_slot)

    new_header = dict(header)
    new_header["slots"] = new_slots

    # Build and atomically write the new envelope.  plaintext_bytes is already
    # padded (that is what seal_body stored).
    new_data = crypto.build_envelope(new_header, bytes(new_dek), plaintext_bytes)
    _atomic_write_bytes(SECRETS_FILE, new_data)

    # Read-back: verify every slot written.
    try:
        _verify_v2_slots(
            SECRETS_FILE.read_bytes(),
            new_password,
            bytes(new_recovery_raw) if new_recovery_raw is not None else None,
        )
    except RuntimeError:
        _atomic_write_bytes(SECRETS_FILE, original_bytes)
        _cleanup_backup()
        raise RuntimeError(
            "Password change failed during read-back verification -- "
            "vault has been restored to its previous state. "
            "The password was NOT changed."
        )

    _cleanup_backup()
    return (
        crypto.format_recovery_key(bytes(new_recovery_raw))
        if new_recovery_raw is not None
        else None
    )


# ---------------------------------------------------------------------------
# v2 vault creators and credential operations
# ---------------------------------------------------------------------------

def create_v2_vault(
    password: str,
    *,
    recovery_raw: Optional[bytes] = None,
) -> Optional[str]:
    """Create a new v2 vault from scratch.

    This is the first-run creator for new installations.  The legacy
    ``create_secrets_vault`` remains the v1 creator and is used by the
    existing test suite.  Wave 7 will switch the GUI's first-run flow to
    this function.

    *recovery_raw*: 20 random bytes from ``crypto.new_recovery_key()``.
    If provided, a recovery slot is added and the formatted key string is
    returned.  If None, no recovery slot is added and None is returned.

    Raises RuntimeError if vault.enc already exists (regardless of format).
    """
    if not _PLUGIN_DATA_DIR and _looks_like_plugin_cache_path(Path(__file__).resolve()):
        raise RuntimeError(
            "Refusing to create a new vault here: this looks like a Claude Code "
            "plugin install (running from inside a plugins/cache directory), but "
            "CLAUDE_PLUGIN_DATA isn't set in this process's environment."
        )
    if SECRETS_FILE.exists():
        raise RuntimeError(
            "vault.enc already exists. Refusing to overwrite an existing vault -- "
            "delete vault.enc yourself if you really want to start over (this is "
            "unrecoverable; make sure you have exported all secrets first)."
        )

    padded = _pkcs7_pad(json.dumps({}).encode("utf-8"))
    envelope, _dek, _vault_id = crypto.build_v2_vault(
        password, padded, recovery_raw=recovery_raw
    )
    _atomic_write_bytes(SECRETS_FILE, envelope)
    _write_format_file(2)

    return (
        crypto.format_recovery_key(bytes(recovery_raw))
        if recovery_raw is not None
        else None
    )


def upgrade_to_v2(password: str, *, recovery: bool) -> Optional[str]:
    """Upgrade a v1 vault to the v2 AES-256-GCM/scrypt format in place.

    Preserves every secret.  Keeps vault.salt on disk forever -- a surviving
    v1 backup (vault.enc.bak or a user copy) is permanently undecryptable
    without its salt, so deleting 16 bytes to tidy up would silently destroy
    every backup the user holds.

    *recovery*: if True, generate a recovery slot and return its formatted
    key string.  If False, no recovery slot; returns None.

    Raises RuntimeError if vault is already v2.
    Raises FileNotFoundError if no vault exists.
    Raises crypto.WrongPassword on a bad password.
    """
    with _vault_lock():
        return _upgrade_to_v2_locked(password, recovery=recovery)


def _upgrade_to_v2_locked(password: str, *, recovery: bool):
    """upgrade_to_v2's body, with the vault lock assumed already held."""
    if not vault_exists():
        raise FileNotFoundError("No vault found. Create a vault first.")
    data = SECRETS_FILE.read_bytes()
    if crypto.is_v2(data):
        raise RuntimeError("Vault is already v2. No upgrade needed.")

    # Raw body: an FMK planted on a v1 vault must survive the upgrade, and
    # load_secrets would filter it out on the way in.
    body = load_vault_body(password)  # WrongPassword propagates

    recovery_raw: Optional[bytearray] = crypto.new_recovery_key() if recovery else None

    padded = _pkcs7_pad(json.dumps(body).encode("utf-8"))
    original_bytes = _backup_vault()

    envelope, _dek, _vault_id = crypto.build_v2_vault(
        password, padded, recovery_raw=bytes(recovery_raw) if recovery_raw else None
    )
    _atomic_write_bytes(SECRETS_FILE, envelope)

    try:
        _verify_v2_slots(
            SECRETS_FILE.read_bytes(),
            password,
            bytes(recovery_raw) if recovery_raw is not None else None,
        )
    except RuntimeError:
        _atomic_write_bytes(SECRETS_FILE, original_bytes)
        _cleanup_backup()
        raise RuntimeError(
            "Upgrade to v2 failed during read-back verification -- "
            "vault has been restored to its v1 state. "
            "The vault was NOT upgraded."
        )

    _write_format_file(2)
    # vault.salt is deliberately left on disk -- see module docstring and
    # the comment at the top of this function.
    _cleanup_backup()

    return (
        crypto.format_recovery_key(bytes(recovery_raw))
        if recovery_raw is not None
        else None
    )


def reissue_recovery_key(password: str) -> str:
    """Issue a new recovery key for a v2 vault, invalidating the old one.

    The old printed recovery key is immediately invalidated.  Use this after
    a recovery key has been lost, potentially compromised, or after a
    password change (which already auto-rotates the recovery key).

    Returns the new formatted recovery key string.

    Raises RuntimeError if vault is not v2 or does not exist.
    Raises crypto.WrongPassword on a bad password.
    """
    with _vault_lock():
        return _reissue_recovery_key_locked(password)


def _reissue_recovery_key_locked(password: str):
    """reissue_recovery_key's body, with the vault lock assumed already held."""
    if not vault_exists():
        raise FileNotFoundError("No vault found.")
    data = SECRETS_FILE.read_bytes()
    if not crypto.is_v2(data):
        raise RuntimeError(
            "Recovery keys require a v2 vault. Call upgrade_to_v2 first."
        )

    plaintext_bytes, dek, header = crypto.open_v2_with_password(data, password)
    vault_id = _vault_id_from_header(header)

    new_recovery_raw = crypto.new_recovery_key()
    rec_slot, _ = _build_recovery_slot(bytes(dek), bytes(new_recovery_raw), vault_id)

    # Replace or add the recovery slot; keep password slot and any others.
    new_slots = [s for s in header["slots"] if s.get("type") != "recovery"]
    new_slots.append(rec_slot)
    new_header = dict(header)
    new_header["slots"] = new_slots

    original_bytes = _backup_vault()

    # Same DEK and body; only the recovery slot changes.
    new_data = crypto.build_envelope(new_header, bytes(dek), plaintext_bytes)
    _atomic_write_bytes(SECRETS_FILE, new_data)

    try:
        _verify_v2_slots(SECRETS_FILE.read_bytes(), password, bytes(new_recovery_raw))
    except RuntimeError:
        _atomic_write_bytes(SECRETS_FILE, original_bytes)
        _cleanup_backup()
        raise RuntimeError(
            "Recovery key reissue failed during read-back verification -- "
            "vault has been restored. The recovery key was NOT reissued."
        )

    _cleanup_backup()
    return crypto.format_recovery_key(bytes(new_recovery_raw))


def recover_with_recovery_key(
    recovery_key_text: str,
    new_password: str,
) -> Optional[str]:
    """Use a recovery key to set a new master password.

    Rotates the DEK, as every credential change does, and re-wraps the
    recovery slot with the SAME recovery key. Returns None -- the caller has
    no new key to display, because the human's existing printout still works.

    This is the one credential operation that can keep the key, and the reason
    is simply that we have it: the human just typed it in. change_password
    cannot do this, because it runs without the paper key in hand and has no
    way to re-wrap the rotated DEK for it.

    An earlier version minted a replacement here, on the grounds that a key
    read aloud off paper may have been observed. That reasoning is real but it
    loses on balance: it invalidates a printout the user has already stored
    safely, and forces the whole write-it-down ceremony again at the worst
    possible moment -- they have just recovered from losing a password, and if
    they skip or fumble the new ceremony they are left with no recovery path at
    all. A speculative compromise traded against a concrete, repeated chance to
    lose the vault. Anyone who believes the key WAS observed can reissue
    deliberately from manage_vault, which is the right place for that judgement.

    Raises crypto.MalformedRecoveryKey if recovery_key_text is malformed.
    Raises crypto.WrongRecoveryKey if the key is well-formed but wrong.
    Raises crypto.NoRecoverySlot if the vault has no recovery slot.
    """
    with _vault_lock():
        return _recover_with_recovery_key_locked(recovery_key_text, new_password)


def _recover_with_recovery_key_locked(recovery_key_text: str,
    new_password: str,
):
    """recover_with_recovery_key's body, with the vault lock assumed already held."""
    if not vault_exists():
        raise FileNotFoundError("No vault found.")
    data = SECRETS_FILE.read_bytes()
    if not crypto.is_v2(data):
        raise RuntimeError(
            "Recovery requires a v2 vault. Call upgrade_to_v2 first."
        )

    # open_v2_with_recovery validates checksum, finds slot, unwraps DEK.
    plaintext_bytes, old_dek, header = crypto.open_v2_with_recovery(
        data, recovery_key_text
    )
    vault_id = _vault_id_from_header(header)
    params = _params_from_header(header)

    # Rotate the DEK: an attacker holding a copy of the old ciphertext who
    # later learns the old password must not get a key that still opens future
    # bodies.
    new_dek = crypto.new_dek()

    new_pw_slot = _build_password_slot(bytes(new_dek), new_password, params, vault_id)

    # Re-wrap the recovery slot with the SAME key the human just used, so their
    # printout stays valid. Possible only because they supplied it a moment ago.
    new_recovery_raw = crypto.parse_recovery_key(recovery_key_text)
    rec_slot, _ = _build_recovery_slot(
        bytes(new_dek), bytes(new_recovery_raw), vault_id
    )
    # Preserve the slot id: it identifies the printout, and the printout has
    # not changed. Rotating it would make a still-valid paper key look stale.
    if header.get("slots"):
        for _old in header["slots"]:
            if _old.get("type") == "recovery" and _old.get("id"):
                rec_slot["id"] = _old["id"]
                rec_slot["created"] = _old.get("created", rec_slot.get("created"))
                break

    new_header = dict(header)
    new_header["slots"] = [new_pw_slot, rec_slot]

    original_bytes = _backup_vault()

    new_data = crypto.build_envelope(new_header, bytes(new_dek), plaintext_bytes)
    _atomic_write_bytes(SECRETS_FILE, new_data)

    try:
        _verify_v2_slots(
            SECRETS_FILE.read_bytes(), new_password, bytes(new_recovery_raw)
        )
    except RuntimeError:
        _atomic_write_bytes(SECRETS_FILE, original_bytes)
        _cleanup_backup()
        raise RuntimeError(
            "Recovery failed during read-back verification -- "
            "vault has been restored. The password was NOT changed."
        )

    _cleanup_backup()
    # Zero our copy; the human's paper is the only place this key lives.
    for _i in range(len(new_recovery_raw)):
        new_recovery_raw[_i] = 0
    # None: nothing new to display, because the existing printout still works.
    return None


def vault_format_version() -> Optional[int]:
    """Return the current vault format version (1 or 2) or None if no vault.

    Never reads vault.format.txt (that file is purely informational; reading
    it here would make it an agent-writable downgrade lever).  Detects format
    from the actual file bytes.
    """
    if not SECRETS_FILE.exists():
        return None
    try:
        data = SECRETS_FILE.read_bytes()
    except OSError:
        return None
    if crypto.is_v2(data):
        return 2
    return 1 if SALT_FILE.exists() else None


def vault_info() -> dict:
    """Return non-secret metadata about the vault.

    Keys: format, kdf, recovery_slot (bool), and for v2: vault_id, created,
    kdf_params, recovery_slot_id, recovery_slot_created.

    Never returns secret data.  Raises nothing -- on error returns
    {"error": <reason>}.  Intended for mcp_server.vault_status.
    """
    if not SECRETS_FILE.exists():
        return {"error": "no vault"}
    try:
        data = SECRETS_FILE.read_bytes()
    except OSError as exc:
        return {"error": f"could not read vault.enc: {exc}"}
    if not crypto.is_v2(data):
        return {
            "format": 1,
            "kdf": "pbkdf2-hmac-sha256",
            "kdf_params": {"iterations": crypto.PBKDF2_ITERATIONS},
            "recovery_slot": False,
        }
    try:
        header, _aad, _body = crypto.parse_envelope(data)
    except crypto.VaultCorrupted as exc:
        return {"error": f"vault corrupted: {exc}"}
    pw_slot = next(
        (s for s in header.get("slots", []) if s.get("type") == "password"), None
    )
    rk_slot = next(
        (s for s in header.get("slots", []) if s.get("type") == "recovery"), None
    )
    info: dict = {
        "format": 2,
        "vault_id": header.get("vault_id"),
        "created": header.get("created"),
        "kdf": "scrypt",
        "recovery_slot": rk_slot is not None,
    }
    if pw_slot:
        kdf = pw_slot["kdf"]
        info["kdf_params"] = {
            "n": kdf.get("n"),
            "r": kdf.get("r"),
            "p": kdf.get("p"),
        }
    if rk_slot:
        info["recovery_slot_id"] = rk_slot.get("id")
        info["recovery_slot_created"] = rk_slot.get("created")
    return info


# ---------------------------------------------------------------------------
# Whole-file encryption
# ---------------------------------------------------------------------------
#
# A file is encrypted IN PLACE to a sidecar: certs/server.pem becomes
# certs/server.pem.levault beside it, and the original is destroyed only after
# the sidecar has been written, re-read, and verified. The sidecar is pure
# ciphertext and is meant to be committed -- which is also why the original
# filename lives inside the ciphertext rather than in the header.
#
# The registry (files.json) is deliberately NOT authoritative for reading.
# Every envelope is self-describing, so decrypt works on any .levault whether
# or not it is registered. That is a different relationship than
# vault_index.json has to vault.enc, where the index is load-bearing for
# placeholder numbers.
#
# ONE EXCEPTION, and it is the dangerous one: retire_file_keys. Deleting an old
# key generation is safe only if nothing still needs it, and the registry is
# the only inventory of what "anything" means. So retire refuses outright when
# the registry is empty or cannot account for the .levault files it can see.
# Losing files.json therefore does NOT cost only visibility -- it costs the
# safety net on the single irreversible operation in this feature.
#
# INVARIANT: no registry value may ever gate or parameterise a write.
# files.json is agent-WRITABLE, not merely agent-readable. If the mode came
# from the registry, an agent could turn "0600" into "0777" and a restored
# private key would land world-readable; if restores_to were used as an output
# path, the agent would choose where a secret gets written. So the mode and
# the original name used at decrypt time come from the in-ciphertext meta, and
# the output path is derived from the sidecar path or supplied by the caller
# and shown in full in the consent dialog. The registry feeds display and
# orphan detection only.

VAULT_FILE_SUFFIX = ".levault"


def derived_vault_path(path: Path) -> Path:
    """certs/server.pem -> certs/server.pem.levault"""
    return path.parent / (path.name + VAULT_FILE_SUFFIX)


def derived_plaintext_path(vault_path: Path) -> Path:
    """certs/server.pem.levault -> certs/server.pem

    Derived from the SIDECAR NAME, never from the name stored inside the
    ciphertext. That is what keeps the entire path-traversal class out of this
    feature: the in-ciphertext name is attacker-influenced data that is only
    ever compared, never used to build a path, so there is no "..", no drive
    letter, and no reserved device name to sanitise.
    """
    if vault_path.suffix != VAULT_FILE_SUFFIX:
        raise ValueError(
            f"{vault_path.name} does not end in {VAULT_FILE_SUFFIX} -- name the "
            f"output file explicitly."
        )
    return vault_path.parent / vault_path.name[: -len(VAULT_FILE_SUFFIX)]


def _registry_key(path: Path) -> str:
    r"""Normalised absolute path used as a files.json key.

    normcase matters on Windows: without it C:\Proj\a.levault and
    c:\proj\a.levault become two entries for one file.
    """
    return os.path.normcase(str(path))


def _is_reparse_point(path: Path) -> bool:
    """True for a Windows junction or any other reparse point.

    is_symlink() alone misses junctions, which behave like directory symlinks
    and would let an "encrypt this file" destroy something that is really
    somewhere else.
    """
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


# ---------------------------------------------------------------------------
# The file registry
# ---------------------------------------------------------------------------

_MODE_RE = re.compile(r"^0[0-7]{3}$")


@contextlib.contextmanager
def _files_lock():
    """Serialises the files.json read-modify-write."""
    with _json_lock(FILES_LOCK_FILE, "files.json"):
        yield


def load_file_registry() -> dict:
    """Read files.json, validating on the way in.

    Validated on READ rather than trusted, for the same reason load_index is:
    this file is plaintext and an agent can edit it. A malformed entry raises
    ValueError so the caller reports it, rather than surfacing later as a
    KeyError from somewhere less obvious.
    """
    if not FILES_FILE.exists():
        return {}
    try:
        raw = json.loads(FILES_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"files.json is not valid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise ValueError("files.json must contain a JSON object.")

    version = raw.get("version", 1)
    if version != 1:
        raise ValueError(
            f"files.json declares version {version!r}, but this plugin only "
            f"understands version 1. Upgrade the plugin."
        )
    entries = raw.get("files", {})
    if not isinstance(entries, dict):
        raise ValueError("files.json's \"files\" must be a JSON object.")

    for key, entry in entries.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("files.json has an empty path key.")
        if any(ch in key for ch in "\n\r\x00"):
            raise ValueError("files.json has a path key containing a control character.")
        if not isinstance(entry, dict):
            raise ValueError(f"files.json entry for {key} is not an object.")
        mode = entry.get("mode")
        if mode is not None and not (isinstance(mode, str) and _MODE_RE.match(mode)):
            raise ValueError(
                f"files.json entry for {key} has an invalid mode {mode!r} "
                f"(expected a string like \"0600\")."
            )
    return entries


def save_file_registry(entries: dict) -> None:
    _atomic_write_text(
        FILES_FILE,
        json.dumps({"version": 1, "files": entries}, indent=2, sort_keys=True) + "\n",
    )


def register_encrypted_file(vault_path: Path, entry: dict) -> None:
    with _files_lock():
        entries = load_file_registry()
        entries[_registry_key(vault_path)] = entry
        save_file_registry(entries)


def unregister_encrypted_file(vault_path: Path) -> bool:
    """Drop an entry. Returns True if there was one. Never touches the file."""
    with _files_lock():
        entries = load_file_registry()
        removed = entries.pop(_registry_key(vault_path), None) is not None
        if removed:
            save_file_registry(entries)
        return removed


def file_registry_status() -> list:
    """Per-entry health of every registered encrypted file.

    Mirrors resync_targets' per-item status shape. Never heals anything: a
    "modified" entry is far more likely to be a file re-encrypted on another
    machine and pulled in than damage, and silently rewriting the registry to
    match would erase the only signal that the two disagree.
    """
    entries = load_file_registry()
    report = []
    for key, entry in sorted(entries.items()):
        row = {
            "path": key,
            "original_name": entry.get("original_name"),
            "restores_to": entry.get("restores_to"),
            "plaintext_size": entry.get("plaintext_size"),
            "encrypted_at": entry.get("encrypted_at"),
        }
        try:
            vault_path = Path(key)
            if not vault_path.exists():
                row["status"] = "missing"
            else:
                digest = _file_fingerprint(vault_path)
                expected = entry.get("envelope_sha256")
                row["status"] = "ok" if (expected is None or digest == expected) else "modified"
                # From the envelope header, not the registry: the header is
                # plaintext (no password needed) and is the only account of
                # this file that an agent cannot edit.
                try:
                    row["fmk_id"] = crypto.file_envelope_info(
                        vault_path.read_bytes())["fmk_id"]
                except (OSError, ValueError, crypto.VaultCorrupted):
                    row["status"] = "error"
                    row["error"] = "not a readable llm-env-vault encrypted file"
                restores_to = entry.get("restores_to")
                if row["status"] == "ok" and restores_to and Path(restores_to).exists():
                    # The secret is sitting in the clear next to its own
                    # ciphertext -- usually a decrypt_file the user forgot to
                    # undo. Worth surfacing; not an error.
                    row["status"] = "plaintext_present"
        except OSError as exc:
            row["status"] = "error"
            row["error"] = str(exc)
        report.append(row)
    return report


# ---------------------------------------------------------------------------
# FMK generation lookup
# ---------------------------------------------------------------------------

def _fmk_key_bytes(record: dict, fmk_id: str) -> bytes:
    """Raw key bytes for one generation of an FMK record.

    Raises ValueError naming the generation when it is not held -- which is
    what a file encrypted under a retired key looks like, and the message has
    to be better than a KeyError.
    """
    keys = (record or {}).get("keys") or {}
    encoded = keys.get(fmk_id)
    if encoded is None:
        raise ValueError(
            f"This vault does not hold the file key generation ({fmk_id}) that "
            f"encrypted this file. It was encrypted by a different vault, or "
            f"under a key generation that has since been retired."
        )
    raw = base64.urlsafe_b64decode(encoded + "==")
    if len(raw) != crypto.FMK_BYTES:
        raise ValueError(f"Stored file key {fmk_id} is malformed.")
    return raw


def _active_fmk(record: dict) -> tuple:
    """``(fmk_id, raw_key_bytes)`` for the active generation."""
    fmk_id = (record or {}).get("active")
    if not fmk_id:
        raise ValueError("The vault's file key record has no active generation.")
    return fmk_id, _fmk_key_bytes(record, fmk_id)


# ---------------------------------------------------------------------------
# Refusal rules
# ---------------------------------------------------------------------------

def precheck_encrypt(path: Path) -> dict:
    """Every password-free reason to refuse encrypting *path*.

    Raises ValueError with a message written for the human who has to act on
    it. Returns non-secret facts for the consent dialog, plus whether a
    sidecar is already sitting there (the crash-limbo case -- see
    encrypt_file_in_place).

    Re-run inside the dialog's Allow handler as well as before it opens: the
    dialog can sit open for minutes, and everything checked here can change.
    """
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise ValueError(f"Cannot resolve {path}: {exc}") from None

    if not resolved.exists():
        raise ValueError(f"{resolved} does not exist.")
    if path.is_symlink() or _is_reparse_point(path):
        # Unlinking a link destroys nothing while reporting success, leaving
        # the real secret exactly where it was.
        raise ValueError(
            f"{path} is a symbolic link or junction. Encrypt the file it points "
            f"at instead -- encrypting the link would leave the real file in place."
        )
    if not resolved.is_file():
        raise ValueError(f"{resolved} is not a regular file.")

    try:
        st = resolved.stat()
    except OSError as exc:
        raise ValueError(f"Cannot read {resolved}: {exc}") from None

    if getattr(st, "st_nlink", 1) > 1:
        raise ValueError(
            f"{resolved} has more than one hard link, so destroying this name "
            f"would leave the contents readable under another one. Remove the "
            f"other link first."
        )
    if resolved.suffix == VAULT_FILE_SUFFIX:
        raise ValueError(f"{resolved.name} is already an encrypted vault file.")

    try:
        if resolved.is_relative_to(ROOT.resolve()):
            # Blankets vault.enc, vault.salt, vault_index.json, llm.env,
            # targets.json, files.json, the lock files and any in-flight .tmp.
            raise ValueError(
                f"{resolved} is inside the vault's own directory. The vault "
                f"cannot encrypt its own state files."
            )
    except OSError:
        pass

    if st.st_size == 0:
        raise ValueError(f"{resolved} is empty -- there is nothing to encrypt.")
    if st.st_size > crypto.MAX_FILE_PLAINTEXT_BYTES:
        raise ValueError(
            f"{resolved} is {st.st_size} bytes, over the "
            f"{crypto.MAX_FILE_PLAINTEXT_BYTES // (1024 * 1024)} MiB limit for "
            f"vault file encryption."
        )

    # Catch a renamed envelope whatever it is called -- this is the mistake
    # people actually make, and re-encrypting ciphertext is never intended.
    with open(resolved, "rb") as handle:
        magic = handle.read(8)
    if magic in (crypto.FILE_MAGIC, crypto.VAULT_MAGIC):
        raise ValueError(
            f"{resolved.name} is already an encrypted llm-env-vault file "
            f"(it has been renamed, but its contents say otherwise)."
        )

    if not vault_exists():
        raise ValueError("No vault found. Create one before encrypting files.")
    # v2 only, decided by the magic bytes of vault.enc and by nothing else.
    # vault.format.txt is never read -- see FORMAT_FILE's invariant.
    if not crypto.is_v2(SECRETS_FILE.read_bytes()):
        raise ValueError(
            "File encryption requires a v2 vault. Run manage_vault and choose "
            "upgrade_v2 first."
        )

    return {
        "path": resolved,
        "vault_path": derived_vault_path(resolved),
        "size": st.st_size,
        "mode": _mode_string(st.st_mode),
        "sidecar_exists": derived_vault_path(resolved).exists(),
    }


def _mode_string(st_mode: int) -> str:
    return "0" + oct(stat.S_IMODE(st_mode))[2:].rjust(3, "0")[-3:]


def precheck_decrypt(vault_path: Path, output_path=None, *, check_output: bool = True) -> dict:
    """Every password-free reason to refuse decrypting *vault_path*.

    *check_output* False validates only the .levault itself and skips every
    check on the derived output path. run_with_env needs that: it writes into
    the command's working directory, not beside the sidecar, so validating the
    sibling path would both miss the path that matters and spuriously refuse
    over a leftover file it is never going to touch.
    """
    try:
        resolved = vault_path.resolve()
    except OSError as exc:
        raise ValueError(f"Cannot resolve {vault_path}: {exc}") from None

    if not resolved.exists():
        raise ValueError(f"{resolved} does not exist.")
    if not resolved.is_file():
        raise ValueError(f"{resolved} is not a regular file.")

    size = resolved.stat().st_size
    if size > crypto.MAX_FILE_ENVELOPE_BYTES:
        # Refused before reading, not after -- a hostile 4 GiB file must not
        # be loaded into a long-lived server just to be rejected.
        raise ValueError(
            f"{resolved} is {size} bytes, far larger than any file this vault "
            f"could have written. Refusing to read it."
        )

    with open(resolved, "rb") as handle:
        if handle.read(8) != crypto.FILE_MAGIC:
            raise ValueError(
                f"{resolved.name} is not a llm-env-vault encrypted file."
            )

    if not check_output:
        return {"vault_path": resolved, "output_path": None, "envelope_size": size}

    if output_path is None:
        out = derived_plaintext_path(resolved)
    else:
        out = Path(output_path)
        try:
            out = out.resolve() if out.is_absolute() else (resolved.parent / out).resolve()
        except OSError as exc:
            raise ValueError(f"Cannot resolve output path {output_path}: {exc}") from None

    if out.exists():
        raise ValueError(
            f"{out} already exists -- refusing to overwrite it. Move or delete "
            f"it first, or name a different output path."
        )
    if out.is_symlink():
        raise ValueError(f"{out} is a symbolic link -- writing through it could escape.")
    if not out.parent.exists():
        raise ValueError(
            f"{out.parent} does not exist. Create the directory first -- this "
            f"tool will not create directories for a decrypted secret."
        )
    try:
        if out.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError(
                f"{out} is inside the vault's own directory -- refusing to write "
                f"a decrypted secret there."
            )
    except OSError:
        pass

    return {"vault_path": resolved, "output_path": out, "envelope_size": size}


# ---------------------------------------------------------------------------
# Destroying a plaintext
# ---------------------------------------------------------------------------

def secure_delete(path: Path) -> bool:
    """Overwrite *path* once with random bytes, fsync, then unlink.

    Returns True if the file is gone afterwards. Never raises -- callers are
    usually in a cleanup path where a raise would mask the real error.
    Use secure_delete_ex when you need to tell the two failure modes apart.

    ONE pass, and honestly documented as best-effort everywhere it is
    surfaced. Multi-pass overwriting is security theater on this platform: on
    NTFS plus an SSD the original bytes plausibly survive in FTL
    wear-levelling, the $LogFile and USN journal, Volume Shadow Copy, the MFT
    record itself if the file was small enough to be resident, the editor's
    swap file, the search indexer, AV quarantine and OneDrive. If one pass
    does not reach the media, three do not either. It is still worth doing for
    the page-cache and rotating-disk cases, which is why it is here at all.
    """
    return secure_delete_ex(path)["removed"]


def secure_delete_ex(path: Path) -> dict:
    """secure_delete, reporting WHICH half succeeded.

    Returns ``{"removed": bool, "overwritten": bool}``.

    The distinction matters to the human. If the overwrite succeeded and only
    the unlink failed -- an antivirus scan or an open handle, exactly what the
    retry loop below exists for -- then the leftover file contains random
    bytes, not their secret, and the encrypted copy is the authoritative one.
    Telling them "this file still contains the real secret" in that state is
    not just wrong, it points them at deleting the wrong file.
    """
    overwritten = False
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                handle.write(os.urandom(chunk))
                remaining -= chunk
            handle.flush()
            os.fsync(handle.fileno())
        overwritten = True
    except OSError:
        pass  # fall through and still try to unlink

    for attempt in range(_LOCK_RETRIES):
        try:
            path.unlink()
            return {"removed": True, "overwritten": overwritten}
        except FileNotFoundError:
            return {"removed": True, "overwritten": overwritten}
        except OSError:
            # Same transient-antivirus-lock reasoning as _atomic_write_bytes.
            if attempt == _LOCK_RETRIES - 1:
                break
            time.sleep(_LOCK_RETRY_SLEEP)
    return {"removed": not path.exists(), "overwritten": overwritten}


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_file_in_place(path: Path, password: str, *, allow_resume: bool = False) -> dict:
    """Encrypt *path* to its sidecar and destroy the original.

    The ordering is the whole safety argument, and every step exists because
    of what a crash at that point would cost:

      1. Re-validate. The consent dialog can sit open for minutes.
      2. Read, size-check again, hash.
      3. Build the envelope in memory.
      4. Write the sidecar (0644 -- it is ciphertext meant to be committed;
         0600 just confuses a git checkout on a shared machine).
      5. Verified read-back, re-reading BOTH the file and the FMK from disk.
         Verifying against the in-memory key would happily confirm a file
         sealed under a key that another process has since replaced.
      6. On any failure: unlink the sidecar, leave the plaintext completely
         untouched, raise. This is change_password's rollback discipline.
      7. Register. Deliberately before the unlink: an entry pointing at a real
         sidecar is never wrong, but an unlinked plaintext with no entry is
         silently invisible.
      8. Key-liveness re-check -- confirm the generation we sealed under is
         still on disk. Cheap, and it is the second layer against a
         concurrent mint being clobbered.
      9. Only now destroy the plaintext.

    A crash between 4 and 9 leaves a verified sidecar beside an intact
    original. That is recoverable but wedged, because both tools then refuse
    ("sidecar exists" / "output exists"). *allow_resume* is the way out: with
    it, an existing sidecar that opens to exactly this plaintext is accepted
    and the function proceeds straight to destroying the original.
    """
    info = precheck_encrypt(path)
    resolved, vault_path = info["path"], info["vault_path"]

    file_bytes = resolved.read_bytes()
    if len(file_bytes) > crypto.MAX_FILE_PLAINTEXT_BYTES:
        # TOCTOU: the file can grow between stat() and read().
        raise ValueError(
            f"{resolved} grew past the size limit while it was being read."
        )
    digest = hashlib.sha256(file_bytes).hexdigest()
    meta = {
        "name": resolved.name,
        "mode": info["mode"],
        "mtime": resolved.stat().st_mtime,
        "sha256": digest,
    }

    resumed = False
    if vault_path.exists():
        if not allow_resume:
            raise ValueError(
                f"{vault_path} already exists -- refusing to overwrite it."
            )
        resumed = _sidecar_matches(vault_path, password, digest)
        if not resumed:
            raise ValueError(
                f"{vault_path} already exists and does NOT contain this file's "
                f"current contents. Resolve this by hand: one of the two is not "
                f"what you think it is."
            )

    record = get_or_create_fmk(password)
    fmk_id, fmk = _active_fmk(record)

    if not resumed:
        envelope = crypto.build_file_envelope(fmk, fmk_id, file_bytes, meta)
        _atomic_write_bytes(vault_path, envelope, mode=0o644)

        try:
            _verify_encrypted_file(vault_path, password, digest, meta)
        except Exception as exc:
            # Roll back to exactly the state we found: the sidecar goes, the
            # plaintext was never touched.
            try:
                vault_path.unlink()
            except OSError:
                pass
            raise RuntimeError(
                f"Encryption failed during read-back verification -- {resolved.name} "
                f"has NOT been changed and nothing was deleted. ({exc})"
            ) from exc

    # Read what is ACTUALLY in the sidecar rather than assuming the active
    # generation. On a resumed run the sidecar was sealed by an earlier call,
    # possibly under a generation that has since been rotated away from, and
    # crediting the active one would leave the older generation under-counted
    # for a file that genuinely still needs it.
    sealed_info = crypto.file_envelope_info(vault_path.read_bytes())
    sealed_gen, sealed_file_id = sealed_info["fmk_id"], sealed_info["file_id"]

    entry = {
        "restores_to": str(resolved),
        "original_name": resolved.name,
        "file_id": sealed_file_id,
        "fmk_id": sealed_gen,
        "plaintext_size": len(file_bytes),
        "mode": info["mode"],
        "encrypted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "envelope_sha256": _file_fingerprint(vault_path),
    }
    register_encrypted_file(vault_path, entry)

    # Key-liveness: is the generation we just sealed under still the one on
    # disk? If a concurrent process clobbered the mint, this file's key no
    # longer exists anywhere and destroying the plaintext would be permanent.
    live = get_fmk(password) or {}
    if sealed_gen not in (live.get("keys") or {}):
        try:
            vault_path.unlink()
        except OSError:
            pass
        unregister_encrypted_file(vault_path)
        raise RuntimeError(
            "The vault's file key changed while this file was being encrypted, "
            f"so {resolved.name} has NOT been changed and nothing was deleted. "
            "Try again."
        )

    # Record the seal BEFORE the plaintext is destroyed. If this write
    # succeeds and the delete then fails, the id stays outstanding, which only
    # ever makes retire more cautious. The reverse order could leave a sealed
    # file unrecorded, which is what lets retire delete its key. Because this
    # records an identity, a resumed run after a crash here re-adds the same
    # id and changes nothing.
    _update_sealed(password, additions={sealed_gen: [sealed_file_id]})

    # Re-verify immediately before destroying. Everything between the read
    # above and this point -- building the envelope, the sidecar write, a
    # verified read-back that includes a vault scrypt -- takes a couple of
    # hundred milliseconds, and this function is about to irreversibly
    # overwrite whatever is at that path NOW. Two things can have changed:
    # an editor autosave (the sidecar would hold the older contents, and the
    # newer ones would be destroyed), or, since this project's threat model
    # grants filesystem write access, a swap for a link to something else.
    try:
        if resolved.is_symlink() or _is_reparse_point(resolved):
            raise ValueError("it became a link")
        recheck = resolved.stat()
        if getattr(recheck, "st_nlink", 1) > 1:
            raise ValueError("it gained a hard link")
        if hashlib.sha256(resolved.read_bytes()).hexdigest() != digest:
            raise ValueError("its contents changed")
    except (OSError, ValueError) as exc:
        return {
            "path": str(resolved),
            "vault_path": str(vault_path),
            "original_name": resolved.name,
            "plaintext_size": len(file_bytes),
            "mode": info["mode"],
            "fmk_id": sealed_gen,
            "original_destroyed": False,
            "resumed": resumed,
            "not_destroyed_reason": (
                f"{resolved.name} was not deleted because {exc} while it was being "
                f"encrypted. The encrypted copy holds the contents as they were when "
                f"this started; check the file and delete it yourself if that is "
                f"still what you want."),
        }

    outcome = secure_delete_ex(resolved)

    return {
        "path": str(resolved),
        "vault_path": str(vault_path),
        "original_name": resolved.name,
        "plaintext_size": len(file_bytes),
        "mode": info["mode"],
        "fmk_id": sealed_gen,
        "original_destroyed": outcome["removed"],
        "original_overwritten": outcome["overwritten"],
        "resumed": resumed,
    }


def _sidecar_matches(vault_path: Path, password: str, digest: str) -> bool:
    """True if an existing sidecar decrypts to exactly this plaintext hash."""
    try:
        file_bytes, _meta = read_encrypted_file(vault_path, password)
    except Exception:
        return False
    return hashlib.sha256(file_bytes).hexdigest() == digest


def _verify_encrypted_file(vault_path: Path, password: str, digest: str, meta: dict) -> None:
    """Re-read the sidecar AND the FMK from disk and confirm they agree.

    The FMK is deliberately re-fetched rather than reused from memory: this
    step's job is to prove the file on disk can be opened by the vault as it
    exists now, which is precisely the thing an in-memory copy cannot tell us.
    """
    file_bytes, got_meta = read_encrypted_file(vault_path, password)
    if hashlib.sha256(file_bytes).hexdigest() != digest:
        raise RuntimeError("read-back produced different bytes than were encrypted")
    for field in ("name", "mode", "sha256"):
        if got_meta.get(field) != meta.get(field):
            raise RuntimeError(f"read-back metadata mismatch on {field!r}")


def read_encrypted_file(vault_path: Path, password: str) -> tuple:
    """Decrypt a .levault entirely in memory. Returns ``(file_bytes, meta)``.

    Nothing is written. This is what the run_with_env path uses, so that the
    file master key never leaves this module -- only the decrypted bytes cross
    back out, exactly as only the decrypted secrets do today.
    """
    data = Path(vault_path).read_bytes()
    if len(data) > crypto.MAX_FILE_ENVELOPE_BYTES:
        raise ValueError(f"{vault_path} is too large to be a vault file.")
    fmk_id = crypto.file_envelope_info(data)["fmk_id"]
    record = get_fmk(password)
    if record is None:
        raise ValueError(
            "This vault has no file keys -- it has never encrypted a file, so "
            "it cannot open this one."
        )
    fmk = _fmk_key_bytes(record, fmk_id)
    file_bytes, meta, _header = crypto.open_file_envelope(fmk, data)
    return file_bytes, meta


def write_restored_file(path: Path, file_bytes: bytes, meta: dict) -> None:
    """Write decrypted contents to *path*, restoring the recorded mode.

    The mode comes from the in-ciphertext meta, never from the registry --
    files.json is agent-writable and "0777" on a restored private key is
    exactly the bug that invariant exists to prevent. chmod is best-effort on
    Windows, as everywhere else in this module.
    """
    mode = 0o600
    raw = meta.get("mode")
    if isinstance(raw, str) and _MODE_RE.match(raw):
        mode = int(raw, 8)
    _atomic_write_bytes(path, file_bytes, mode=mode)


def decrypt_file_to(vault_path: Path, password: str, output_path=None) -> dict:
    """Restore a .levault to a real file on disk, permanently.

    The sidecar is left in place -- this does not remove the file from the
    vault, it just puts a plaintext copy back.
    """
    info = precheck_decrypt(Path(vault_path), output_path)
    resolved, out = info["vault_path"], info["output_path"]

    file_bytes, meta = read_encrypted_file(resolved, password)

    # Re-check right before writing: the password dialog can sit open for
    # minutes, and the earlier check was only a fast-fail nicety.
    if out.exists():
        raise ValueError(
            f"{out} came into existence while the password prompt was open -- "
            f"refusing to overwrite it."
        )
    write_restored_file(out, file_bytes, meta)

    try:
        if hashlib.sha256(out.read_bytes()).hexdigest() != meta.get("sha256"):
            raise RuntimeError("the bytes written to disk do not match what was decrypted")
    except Exception as exc:
        try:
            out.unlink()
        except OSError:
            pass
        raise RuntimeError(f"Decryption failed verification, nothing was left behind: {exc}")

    warnings = []
    stored_name = meta.get("name")
    if stored_name and stored_name != out.name:
        # A rename is legitimate -- the user controls the sidecar's name -- so
        # this is worth saying, never worth refusing over.
        warnings.append(
            f"This file was encrypted as {stored_name!r} but has been restored as "
            f"{out.name!r}, because the output name comes from the .levault file's "
            f"name rather than from what is stored inside it."
        )

    with _files_lock():
        entries = load_file_registry()
        entry = entries.get(_registry_key(resolved))
        if entry is not None:
            entry["restored_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            entries[_registry_key(resolved)] = entry
            save_file_registry(entries)

    return {
        "vault_path": str(resolved),
        "output_path": str(out),
        "original_name": stored_name,
        "size": len(file_bytes),
        "mode": meta.get("mode"),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# File key rotation
# ---------------------------------------------------------------------------
#
# The FMK deliberately does NOT rotate when the master password changes -- that
# is the whole reason a .levault written last year still opens today, and why
# committing one to git is a sensible thing to do. The cost is that a leaked
# FMK is total and retroactive: it decrypts every file ever written under it,
# including ones already pushed to a public remote. Rotation is the answer to
# that, and it has to cope with the fact that the files it is rotating may not
# all be reachable from this machine.
#
# Hence GENERATIONS. The body key #fmk holds
#     {"active": "<id>", "keys": {"<id>": "<b64u 32 bytes>", ...}}
# and every envelope header names the generation that sealed it. Rotation
# mints a new generation, makes it active, and re-encrypts whatever it can
# find. Retired keys STAY until a separate, explicitly-confirmed retire step
# removes them -- which is what makes a partial rotation safe rather than a
# way to brick every file that happened to be on another laptop.


def rotate_file_key(password: str) -> dict:
    """Mint a new file key generation and re-encrypt every reachable file.

    Returns {"fmk_id", "rotated", "results": [{path, status, ...}]}, where each
    status is ok / missing / error. A single failure never aborts the run: the
    point of rotation is to move as many files as possible off a key that may
    be compromised, and stopping at the first unreachable one would leave the
    rest exposed for no benefit.

    The new key is minted and SAVED FIRST, before any file is touched. A crash
    at that moment costs nothing -- no file references the new generation yet,
    and the old one is still present, so every existing file still opens. The
    reverse order would leave files sealed under a key the vault never
    recorded, which is unrecoverable.
    """
    if not vault_exists() or not crypto.is_v2(SECRETS_FILE.read_bytes()):
        raise ValueError("File key rotation requires a v2 vault.")

    with _vault_lock():
        body, _envelope, fingerprint = load_vault_body_ex(password)
        record = body.get(FMK_KEY)
        if record is None:
            raise ValueError(
                "This vault has no file keys -- it has never encrypted a file, so "
                "there is nothing to rotate."
            )
        new_id = crypto.new_fmk_id()
        new_key = bytes(crypto.new_fmk())
        record = {
            "active": new_id,
            "keys": {**(record.get("keys") or {}), new_id: _b64u(new_key)},
            # Carry the seal counts forward. Rebuilding this dict without them
            # silently zeroes every outstanding count, which is exactly the
            # signal retire_file_keys refuses on -- so dropping it here would
            # let retire destroy a key that unreachable files still need,
            # while looking like it had checked.
            "sealed": {**(record.get("sealed") or {}), new_id: []},
        }
        body[FMK_KEY] = record
        save_vault_body(password, body, expect_fingerprint=fingerprint)

    results = []
    rotated = 0
    additions, removals = {}, {}
    for key, entry in sorted(load_file_registry().items()):
        vault_path = Path(key)
        row = {"path": key, "original_name": entry.get("original_name")}
        try:
            if not vault_path.exists():
                row["status"] = "missing"
                row["note"] = ("Not on this machine -- it still opens under its old "
                               "key, which is retained until you retire it.")
                results.append(row)
                continue
            moved = _rotate_one(vault_path, record, new_id, new_key)
            row["status"] = "ok"
            rotated += 1
            if moved:
                old_gen, old_file_id, new_file_id = moved
                removals.setdefault(old_gen, []).append(old_file_id)
                additions.setdefault(new_id, []).append(new_file_id)
        except Exception as exc:  # noqa: BLE001 -- one bad file must not stop the rest
            row["status"] = "error"
            row["error"] = str(exc)
        results.append(row)

    _update_sealed(password, additions=additions, removals=removals)

    # The generation every file above was just re-sealed under must still
    # exist. With _write_body holding the vault lock this should be
    # unreachable, but the consequence of being wrong here is that every
    # rotated file is now sealed under a key that exists nowhere -- the exact
    # catastrophe rotation is supposed to prevent. Cheap to check, and it
    # turns a silent total loss into a loud error naming the problem.
    live = get_fmk(password) or {}
    if new_id not in (live.get("keys") or {}):
        raise RuntimeError(
            f"The vault's file key record changed while rotation was running, and "
            f"the new generation ({new_id}) is no longer present. {rotated} file(s) "
            f"were re-encrypted under it and cannot currently be opened. Do NOT "
            f"retire any keys. Restore vault.enc from a backup, or re-run rotation "
            f"once no other session is writing to the vault."
        )

    return {"fmk_id": new_id, "rotated": rotated, "results": results}


def _rotate_one(vault_path: Path, record: dict, new_id: str, new_key: bytes) -> None:
    """Re-encrypt one .levault under the new generation, verifying the result.

    Returns ``(old_generation, old_file_id, new_file_id)``, or None if the
    file was already on the active generation, so the caller can move the
    exact identity across rather than adjusting a count.

    Same write-then-verify-then-replace discipline as encrypt_file_in_place.
    The original ciphertext is only replaced once the new one has been read
    back off disk and confirmed to hold the identical plaintext -- and on any
    failure the file is restored byte for byte, because a half-rotated file is
    a destroyed file.
    """
    data = vault_path.read_bytes()
    before = crypto.file_envelope_info(data)
    old_id, old_file_id = before["fmk_id"], before["file_id"]
    if old_id == new_id:
        return None  # already rotated, e.g. a resumed run
    old_key = _fmk_key_bytes(record, old_id)
    file_bytes, meta, _header = crypto.open_file_envelope(old_key, data)

    # build_file_envelope mints a fresh file DEK every call, so the re-encrypted
    # file shares no key material with the old one -- never re-seal under a
    # reused DEK, even with a fresh nonce.
    envelope = crypto.build_file_envelope(new_key, new_id, file_bytes, meta)
    _atomic_write_bytes(vault_path, envelope, mode=0o644)

    try:
        written = vault_path.read_bytes()
        check_bytes, check_meta, _hdr = crypto.open_file_envelope(new_key, written)
        if check_bytes != file_bytes or check_meta != meta:
            raise RuntimeError("read-back produced different contents")
        new_file_id = crypto.file_envelope_info(written)["file_id"]
    except Exception:
        _atomic_write_bytes(vault_path, data, mode=0o644)  # exact restore
        raise

    with _files_lock():
        entries = load_file_registry()
        entry = entries.get(_registry_key(vault_path))
        if entry is not None:
            entry["fmk_id"] = new_id
            entry["envelope_sha256"] = _file_fingerprint(vault_path)
            entry["file_id"] = new_file_id
            entries[_registry_key(vault_path)] = entry
            save_file_registry(entries)
    return old_id, old_file_id, new_file_id


def file_generations() -> dict:
    """Which key generation each registered file is actually sealed under.

    Reads it from the ENVELOPE HEADER, not from files.json. Needs no password
    -- the header is plaintext by design -- and the registry is agent-writable
    and can simply be wrong, which matters enormously at retire time.

    Returns {"generations": {fmk_id: count}, "unreadable": [paths]}.
    """
    generations, unreadable = {}, []
    for key in sorted(load_file_registry()):
        path = Path(key)
        try:
            fmk_id = crypto.file_envelope_info(path.read_bytes())["fmk_id"]
        except (OSError, ValueError, crypto.VaultCorrupted):
            unreadable.append(key)
            continue
        generations[fmk_id] = generations.get(fmk_id, 0) + 1
    return {"generations": generations, "unreadable": unreadable}


def _unregistered_siblings(entries: dict) -> list:
    """.levault files next to registered ones that the registry doesn't name.

    Bounded to the directories the registry already points at -- this is a
    safety net for "the user copied a file in", not a filesystem crawl.
    """
    known = set(entries)
    found = []
    seen_dirs = set()
    for key in entries:
        parent = Path(key).parent
        marker = os.path.normcase(str(parent))
        if marker in seen_dirs:
            continue
        seen_dirs.add(marker)
        try:
            for candidate in parent.glob("*" + VAULT_FILE_SUFFIX):
                if _registry_key(candidate) not in known:
                    found.append(str(candidate))
        except OSError as exc:
            # A directory we cannot list is not a directory we can vouch for.
            # Swallowing this would turn "I could not check" into "there is
            # nothing there", which is the wrong default for the one
            # irreversible operation in this module.
            found.append(f"{parent} (could not be listed: {exc})")
    return sorted(found)


def file_keys_outstanding(password: str) -> dict:
    """``{generation_id: [file_id, ...]}`` still sealed under a non-active key.

    Password-free callers cannot have this -- it lives in the encrypted body.
    Used by the retire flow to tell a human exactly what they would be
    abandoning, rather than a bare count they have no way to act on.
    """
    record = get_fmk(password)
    if record is None:
        return {}
    active = record.get("active")
    sealed = record.get("sealed") or {}
    return {gen: list(ids) for gen, ids in sealed.items() if gen != active and ids}


def retire_file_keys(password: str, abandon=None) -> dict:
    """Drop every non-active file key generation from the vault.

    This is the irreversible half of rotation, and its precondition is checked
    against ENVELOPE HEADERS rather than against files.json. The registry says
    what rotation believed; the headers say what is actually on disk, and the
    two diverge in a case that really happens: a user restores an older
    .levault from git history after rotating. A registry-driven check would
    pass and destroy that file's only key.

    Refuses if any registered file is missing, unreadable, or still on an old
    generation. Returns {"retired": [ids]} or raises ValueError explaining
    exactly which file is in the way.

    *abandon*: file_ids the human has been shown and explicitly confirmed are
    gone forever. Without an escape hatch a single crashed encrypt could
    strand a user permanently -- unable to retire a key they believe is
    compromised, with no way to discover which file was blocking it. Only ids
    passed here are waived, so the confirmation names what is being given up
    rather than being a blanket force flag.
    """
    # Hashing every registered .levault (up to 16 MiB each) happens BEFORE the
    # lock is taken. Doing it inside would let a large registry starve a
    # concurrent save_secrets out of its retry budget, which then fails with a
    # message about a stuck process that is really just busy.
    precomputed_status = file_registry_status()
    precomputed_gens = file_generations()

    with _vault_lock():
        body, _envelope, fingerprint = load_vault_body_ex(password)
        record = body.get(FMK_KEY)
        if record is None:
            raise ValueError("This vault has no file keys, so there is nothing to retire.")
        active = record.get("active")
        stale = [k for k in (record.get("keys") or {}) if k != active]
        if not stale:
            return {"retired": [], "message": "Only the current file key is held -- "
                                              "there is nothing to retire."}

        # The seal record is the authoritative guard, and the only one that is
        # machine-independent. Every other check here is scoped to paths
        # files.json names, so a .levault in a directory this vault was never
        # told about -- pulled from git on a second machine, say -- is
        # invisible to all of them.
        #
        # Its STORAGE is agent-proof: it lives in the encrypted body and
        # travels with vault.enc. Its inputs are not -- they come from the
        # registry and from files on disk, both of which an agent can write.
        # Storing identities rather than counts is what limits the damage:
        # removals are idempotent, so duplicate registry entries pointing at
        # copies of one envelope cannot forge extra removals the way repeated
        # decrements of a counter could. Treat this as a strong backstop, not
        # an oracle.
        sealed = record.get("sealed")
        if sealed is None:
            raise ValueError(
                "Refusing to retire old file keys: this vault predates seal "
                "accounting, so there is no trustworthy record of how many files "
                "each old key protects. Run file key rotation once to establish it."
            )
        outstanding = {gen: list(sealed.get(gen) or []) for gen in stale
                       if sealed.get(gen)}
        if abandon is not None:
            # The human was shown these exact identities and confirmed they are
            # gone for good. Only ids they actually saw may be waived -- an
            # empty or partial confirmation must not clear the rest.
            waived = set(abandon)
            outstanding = {gen: [i for i in ids if i not in waived]
                           for gen, ids in outstanding.items()}
            outstanding = {gen: ids for gen, ids in outstanding.items() if ids}
        if outstanding:
            total = sum(len(ids) for ids in outstanding.values())
            summary = ", ".join(f"{len(ids)} under {gen}" for gen, ids in outstanding.items())
            raise ValueError(
                f"Refusing to retire old file keys: this vault sealed {total} file(s) "
                f"that have not been moved to the current key -- {summary}. They may "
                f"be on another machine, or in a directory this vault has no record "
                f"of. Make them reachable and run rotation again; retiring now would "
                f"make them permanently unreadable. If they are gone for good, the "
                f"retire dialog can list them and let you abandon them deliberately."
            )

        # The registry is the only inventory of what these keys protect, and
        # every check below is scoped to the paths it names. If it is empty
        # while old keys exist, we are not "safe to retire" -- we are blind.
        # This state arrives without any adversary: copy vault.enc to a second
        # machine to open .levault files pulled from git, and files.json does
        # not come with it.
        entries = load_file_registry()
        if not entries:
            raise ValueError(
                f"Refusing to retire {len(stale)} old file key(s): this vault has no "
                f"record of any encrypted file (files.json is empty or missing), so "
                f"there is no way to check whether anything still needs them. Any "
                f".levault on an old key would become permanently unreadable. "
                f"Re-encrypt or re-register your files first."
            )

        # Unregistered .levault files sitting beside registered ones are the
        # other blind spot, and one a user can actually hit by copying a file
        # in. Cheap to look for; refuse rather than guess.
        unregistered = _unregistered_siblings(entries)
        if unregistered:
            raise ValueError(
                f"Refusing to retire old file keys: found encrypted file(s) this vault "
                f"has no record of, so their key generation cannot be checked -- "
                f"{', '.join(unregistered[:5])}. Re-encrypt or remove them first."
            )

        status = precomputed_status
        blockers = [r for r in status if r.get("status") in ("missing", "modified", "error")]
        if blockers:
            names = ", ".join(f"{r['path']} ({r['status']})" for r in blockers[:5])
            raise ValueError(
                f"Refusing to retire old file keys: {len(blockers)} registered file(s) "
                f"could not be verified -- {names}. Retiring now would permanently "
                f"destroy the only key for any of them still on an old generation. "
                f"Restore or re-pull them and run rotation again first."
            )

        gens = precomputed_gens
        if gens["unreadable"]:
            raise ValueError(
                f"Refusing to retire old file keys: could not read the header of "
                f"{', '.join(gens['unreadable'][:5])}."
            )
        old_gen = {gen: count for gen, count in gens["generations"].items() if gen != active}
        if old_gen:
            summary = ", ".join(f"{count} file(s) on {gen}" for gen, count in old_gen.items())
            raise ValueError(
                f"Refusing to retire old file keys: {summary}. Run file key rotation "
                f"again so every file is on the current key first."
            )

        record = {
            "active": active,
            "keys": {active: record["keys"][active]},
            "sealed": {active: list(sealed.get(active) or [])},
        }
        body[FMK_KEY] = record
        save_vault_body(password, body, expect_fingerprint=fingerprint)
        return {"retired": sorted(stale)}
