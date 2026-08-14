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
import contextlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

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

# How many times to retry acquiring the targets lock before giving up, and
# how long to sleep between retries.  30 × 50 ms = 1.5 s total maximum wait,
# which is generous for a low-contention, short critical-section local lock.
_LOCK_RETRIES = 30
_LOCK_RETRY_SLEEP = 0.05  # seconds

VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
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
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def vault_exists() -> bool:
    return SALT_FILE.exists() and SECRETS_FILE.exists()


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


def create_secrets_vault(password: str) -> None:
    """First-time setup: new salt, empty encrypted secrets store.

    Refuses if vault.salt already exists without a matching vault.enc --
    generating a fresh salt in that state would silently make any
    surviving backup copy of vault.enc permanently undecryptable, even
    with the correct password.
    """
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


def load_secrets(password: str) -> dict:
    salt = SALT_FILE.read_bytes()
    token = SECRETS_FILE.read_bytes()
    plaintext = crypto.decrypt(password, salt, token)
    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError:
        raise ValueError("Decrypted vault contents are corrupted.") from None


def save_secrets(password: str, secrets: dict) -> None:
    salt = SALT_FILE.read_bytes()
    token = crypto.encrypt(password, salt, json.dumps(secrets).encode("utf-8"))
    _atomic_write_bytes(SECRETS_FILE, token)
