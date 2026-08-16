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
# vault.format.txt is a plaintext sibling recording format version, date, and minimum
# plugin version.  INVARIANT: purely informational -- no code path may ever read or
# branch on it, or it becomes an agent-writable downgrade lever.
FORMAT_FILE = ROOT / "vault.format.txt"

# How many times to retry acquiring the targets lock before giving up, and
# how long to sleep between retries.  30 × 50 ms = 1.5 s total maximum wait,
# which is generous for a low-contention, short critical-section local lock.
_LOCK_RETRIES = 30
_LOCK_RETRY_SLEEP = 0.05  # seconds

VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_VAR_NAME_LEN = 128
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


@contextlib.contextmanager
def _targets_lock():
    """File-backed mutex that serialises the targets.json read-modify-write.

    On Windows (the primary platform for this project), uses
    ``msvcrt.locking()`` on a dedicated lock file (``targets.json.lock``
    in the same directory as ``targets.json``).  Falls back to
    ``fcntl.flock()`` on POSIX for cross-platform correctness.

    Retries up to ``_LOCK_RETRIES`` times with ``_LOCK_RETRY_SLEEP``-second
    gaps between attempts, then raises ``RuntimeError`` if the lock still
    can't be acquired (e.g. a process died while holding it).
    """
    fd = os.open(str(TARGETS_LOCK_FILE), os.O_CREAT | os.O_RDWR)
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
                            f"Could not acquire targets.json lock after "
                            f"{_LOCK_RETRIES} retries -- another process may be "
                            f"stuck holding it."
                        ) from None
                    time.sleep(_LOCK_RETRY_SLEEP)
            try:
                yield
            finally:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        else:
            import fcntl as _fcntl
            _fcntl.flock(fd, _fcntl.LOCK_EX)
            try:
                yield
            finally:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


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


def load_secrets(password: str) -> dict:
    """Decrypt and return the secrets dict.

    Routes on the vault magic bytes: v2 uses scrypt/AES-GCM; v1 uses the
    legacy PBKDF2/Fernet path.  The routing decision is based on the file
    content, not on any external flag -- there is no agent-writable downgrade
    lever (vault.format.txt is never read here; see FORMAT_FILE's invariant).
    """
    data = SECRETS_FILE.read_bytes()
    if crypto.is_v2(data):
        plaintext, _dek, _header = crypto.open_v2_with_password(data, password)
        try:
            return json.loads(_pkcs7_unpad_strict(plaintext).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            raise ValueError("Decrypted v2 vault contents are corrupted.") from None
    return _load_secrets_v1(password, data)


def load_secrets_ex(password: str) -> tuple:
    """Decrypt vault and return ``(secrets, envelope_bytes_or_None, fingerprint)``.

    *envelope_bytes_or_None* is the raw file bytes for v2 (so callers can
    pass it to ``crypto.build_envelope`` etc.) or None for v1.

    *fingerprint* is the SHA-256 hex digest of the on-disk bytes at the time
    of this read -- pass it back to ``save_secrets`` as *expect_fingerprint*
    to turn a silent lost-update into an honest error.
    """
    data = SECRETS_FILE.read_bytes()
    fingerprint = hashlib.sha256(data).hexdigest()
    if crypto.is_v2(data):
        plaintext, _dek, _header = crypto.open_v2_with_password(data, password)
        try:
            secrets = json.loads(_pkcs7_unpad_strict(plaintext).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            raise ValueError("Decrypted v2 vault contents are corrupted.") from None
        return secrets, data, fingerprint
    secrets = _load_secrets_v1(password, data)
    return secrets, None, fingerprint


def save_secrets(
    password: str,
    secrets: dict,
    expect_fingerprint: Optional[str] = None,
) -> None:
    """Encrypt and persist the secrets dict.

    Writes back in whatever format the vault is currently in (v1 stays v1,
    v2 stays v2) -- use ``upgrade_to_v2`` to promote a v1 vault.

    *expect_fingerprint*: if provided, the call raises ``RuntimeError`` if the
    on-disk file changed since the caller last read it (compare-and-swap guard
    against concurrent writers -- e.g. GUI + MCP server).

    v2 saves reuse the header's existing KDF params so that every save does
    not silently mutate user-chosen parameters.  Exception: if the header's
    scrypt params are below SCRYPT_FLOOR (possible via attacker-written header),
    the password slot is silently upgraded to SCRYPT_DEFAULT on this save so
    that the weakness is not persisted.
    """
    # If vault.enc doesn't exist yet, this is first-time creation from
    # create_secrets_vault which writes vault.salt first and then calls us.
    # Fall through to the v1 path -- there's nothing to read yet.
    if not SECRETS_FILE.exists():
        salt = SALT_FILE.read_bytes()
        padded = _pkcs7_pad(json.dumps(secrets).encode("utf-8"))
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

    padded = _pkcs7_pad(json.dumps(secrets).encode("utf-8"))

    if crypto.is_v2(data):
        _pt, dek, header = crypto.open_v2_with_password(data, password)
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
        # v1 path
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
    if not vault_exists():
        raise FileNotFoundError(
            "No vault found (vault.enc or vault.salt is missing). "
            "Create a vault first before changing the password."
        )

    data = SECRETS_FILE.read_bytes()

    if not crypto.is_v2(data):
        # ---- v1 path (legacy) ----
        # crypto.WrongPassword propagates unchanged; do not swallow it.
        secrets = load_secrets(old_password)
        original_bytes = SECRETS_FILE.read_bytes()
        # The salt is deliberately reused -- rotating it would require a
        # two-file atomic write that does not exist, creating a crash window
        # that can permanently brick the vault.
        save_secrets(new_password, secrets)
        try:
            verified = load_secrets(new_password)
        except Exception as exc:
            _atomic_write_bytes(SECRETS_FILE, original_bytes)
            raise RuntimeError(
                "Password change failed during read-back verification -- "
                "vault has been restored to its previous state. "
                "The password was NOT changed."
            ) from exc
        if verified != secrets:
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
    if not vault_exists():
        raise FileNotFoundError("No vault found. Create a vault first.")
    data = SECRETS_FILE.read_bytes()
    if crypto.is_v2(data):
        raise RuntimeError("Vault is already v2. No upgrade needed.")

    secrets = load_secrets(password)  # WrongPassword propagates

    recovery_raw: Optional[bytearray] = crypto.new_recovery_key() if recovery else None

    padded = _pkcs7_pad(json.dumps(secrets).encode("utf-8"))
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

    Rotates the DEK (same reason as change_password), issues a new recovery
    key (since the old one was used), and returns the new formatted key string.

    The new recovery key replaces the old one in the vault.  The caller
    MUST display the returned key to the user immediately -- it is not stored.

    Raises crypto.MalformedRecoveryKey if recovery_key_text is malformed.
    Raises crypto.WrongRecoveryKey if the key is well-formed but wrong.
    Raises crypto.NoRecoverySlot if the vault has no recovery slot.
    """
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

    # Rotate the DEK so the compromised recovery key cannot decrypt future bodies.
    new_dek = crypto.new_dek()

    new_pw_slot = _build_password_slot(bytes(new_dek), new_password, params, vault_id)

    # Always issue a fresh recovery key after recovery (the old one was used,
    # possibly observed, and is now invalid).
    new_recovery_raw = crypto.new_recovery_key()
    rec_slot, _ = _build_recovery_slot(
        bytes(new_dek), bytes(new_recovery_raw), vault_id
    )

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
    return crypto.format_recovery_key(bytes(new_recovery_raw))


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
