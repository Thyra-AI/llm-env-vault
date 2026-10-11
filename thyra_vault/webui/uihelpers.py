"""Pure helpers shared by the dialogs and the app.

Everything here is pure: no windows, no I/O, no vault access. Password policy, display
sanitising of untrusted text, recovery-key parsing and the manage-menu rules live in one
place so the dialogs (thyra_vault/webui/flows.py) and the app (appflow.py) cannot drift apart.
"""
import re
import unicodedata
from typing import Optional

from ..vault.crypto import MalformedRecoveryKey, parse_recovery_key


def _strip_hidden(text: str) -> str:
    """Strip Unicode format characters (category Cf) and C0/C1 control
    characters that are not ordinary ASCII whitespace (\\t \\n \\r \\f \\v).
    These can hide a boundary in text a human is approving: a zero-width
    joiner or directional mark inserted between two words looks like a word
    boundary in the rendered string but not in the underlying code-point
    sequence. A Right-to-Left Override (U+202E) can visually reverse the text
    around it in a browser as well, which is why the whole Cf class goes, not
    just the zero-width half.
    Ordinary whitespace chars (\\t, \\n, \\r, \\f, \\v) are left in place so
    _safe_display and _collapse_whitespace can still collapse them to spaces.
    """
    result = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue  # zero-width joiners/non-joiners, bidi marks, soft hyphen, etc.
        if cat == "Cc" and ch not in "\t\n\r\f\v":
            continue  # C0 (U+0000-U+001F minus whitespace) and C1 (U+0080-U+009F)
        result.append(ch)
    return "".join(result)


def _safe_display(text, max_len: int = 200) -> str:
    """Collapses all whitespace (including newlines) to single spaces and
    hard-caps length. Applied to any text this module did not itself
    generate before it's rendered into a dialog, so attacker-controlled
    input (a command line, a process description) can never inject fake
    extra lines or grow tall/wide enough to push the real consent content
    and the Allow/Deny buttons off a non-resizable, non-scrolling window.
    Also strips Unicode format characters (Cf) and C0/C1 controls via
    _strip_hidden before collapsing -- see that function for why.
    """
    collapsed = re.sub(r"\s+", " ", _strip_hidden(str(text))).strip()
    if len(collapsed) <= max_len:
        return collapsed
    head = max_len // 2 - 2
    tail = max_len - head - 3
    if head < 0 or tail < 0:
        # Too small for a head...tail split with an ellipsis -- fall back
        # to a hard cut rather than slicing with a negative index (which
        # would silently wrap from the end and stop enforcing the cap).
        return collapsed[:max_len]
    return f"{collapsed[:head]}...{collapsed[-tail:]}"


def _collapse_whitespace(text) -> str:
    """Like _safe_display but with no length cap -- for content going into
    a horizontally-scrollable Text widget rather than a fixed-size Label,
    where truncating with an ellipsis would hide the middle of the very
    thing the human is being asked to approve (a caller can pad both ends
    with innocuous text specifically to bury the interesting part inside
    the elided middle). Still collapses newlines so attacker-controlled
    text can't fake extra lines that look like separate disclosures.
    Also strips Unicode format characters (Cf) and C0/C1 controls via
    _strip_hidden before collapsing -- see that function for why.
    """
    return re.sub(r"\s+", " ", _strip_hidden(str(text))).strip()


# Longest command text the consent dialog will show. A longer one is REFUSED before
# any dialog: eliding or truncating the middle would hide part of what the human is
# approving (padding both ends with innocuous text buries the interesting part).
MAX_COMMAND_DISPLAY_CHARS = 4000


def command_refusal_reason(command) -> Optional[str]:
    """Why this argv cannot be shown faithfully in a consent dialog (None if it can).

    Refused outright, because escaping them would still leave the human guessing:
    any Unicode format character (category Cf: bidi overrides, zero-width joiners),
    any control character other than newline and tab, and a command whose displayed
    form would not fit in MAX_COMMAND_DISPLAY_CHARS."""
    for index, arg in enumerate(command):
        for ch in arg:
            cat = unicodedata.category(ch)
            if cat == "Cf" or (cat == "Cc" and ch not in "\n\t"):
                return (f"argument {index} of the command contains an invisible or control "
                        f"character (U+{ord(ch):04X}); refused, because the approval dialog "
                        f"could not show it faithfully.")
    if sum(len(line) + 1 for line in command_display_lines(command)) > MAX_COMMAND_DISPLAY_CHARS:
        return (f"the command is too long to display in full (over {MAX_COMMAND_DISPLAY_CHARS} "
                f"characters); refused rather than truncated. Put the long part in a file.")
    return None


def escape_argument(arg: str) -> str:
    """One argument with everything invisible or ambiguous made visible: backslash,
    quote, newline, tab and every control / format / separator / unassigned code point
    become escapes, and the second and later spaces of a run become \\x20 (a browser
    would otherwise collapse them)."""
    out = []
    prev_space = False
    for ch in arg:
        if ch == " ":
            out.append("\\x20" if prev_space else " ")
            prev_space = True
            continue
        prev_space = False
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"):
            out.append(f"\\u{ord(ch):04X}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08X}")
        else:
            out.append(ch)
    return "".join(out)


def command_display_lines(command) -> list:
    """One line per argument, quoted and escaped, in argv order -- what the consent
    dialog shows instead of a re-joined, whitespace-collapsed string."""
    return [f'{i}: "{escape_argument(a)}"' for i, a in enumerate(command)]


# Minimum acceptable master-password length (creation and change only --
# existing vaults are never checked retroactively).
#
# Deliberately low, and the reasoning is worth writing down because it looks
# like an oversight otherwise.
#
# The adversary this product is built against is an AI agent. It never sees the
# password, and the only way it could guess one is through the dialog itself,
# where the unlock throttle (a doubling cool-down after five failures) bounds the
# rate. Length buys almost nothing against that threat. Meanwhile a password the human cannot remember is a
# certain, self-inflicted total loss of the vault -- a far more likely outcome
# than the alternative.
#
# The alternative being: an attacker who gets a COPY of vault.enc off the
# machine attacks it offline, where no dialog stands in the way, and there the
# password is the only remaining secret. A short user-chosen password falls to
# a wordlist in seconds regardless of the KDF. That path needs the ciphertext
# to be exfiltrated first, which is a bigger step than reading it, but it is
# not exotic. This floor accepts that risk in exchange for memorability; the
# README says so plainly rather than implying the minimum is strong.
MIN_PASSWORD_LEN = 5

# How long a copied recovery key is allowed to sit on the clipboard before
# it is wiped. The clipboard is readable by every process running as this
# user, so the window is kept short -- long enough to paste into the
# confirm field, not long enough to still be there later.
_CLIPBOARD_CLEAR_SECONDS = 30

# Passwords refused outright regardless of length.
#
# This is the cheap half of the trade-off above. Length and dictionary rank are
# different axes: a 5-character random password needs millions of guesses, while
# "password1" survives no attack at all -- it sits in the first few hundred
# entries of every wordlist in existence, so an attacker holding a copy of
# vault.enc opens it essentially instantly however expensive the KDF is.
#
# Blocking these costs the user nothing in memorability (nobody picks "qwerty"
# because it is the only thing they can remember) and removes the entire
# top-of-wordlist attack class. It is not a strength meter and deliberately does
# not try to be one -- no complexity rules, no scoring, no nagging. Just the
# handful of strings that are guaranteed to be tried first.
#
# Compared case-insensitively after stripping surrounding whitespace.
_COMMON_PASSWORDS = frozenset({
    # numeric runs and keyboard walks
    "123456", "123456789", "12345678", "1234567", "12345", "1234567890",
    "1234", "111111", "123123", "000000", "654321", "666666", "121212",
    "112233", "789456", "159753", "987654321", "11111111", "22222222",
    "123321", "555555", "777777", "888888", "999999", "101010", "202020",
    "qwerty", "qwerty123", "qwertyuiop", "qwe123", "1q2w3e", "1q2w3e4r",
    "1q2w3e4r5t", "qazwsx", "qazwsxedc", "zxcvbnm", "asdfgh", "asdfghjkl",
    "poiuytrewq", "1qaz2wsx", "q1w2e3r4", "azerty", "wasd",
    # the perennial classics
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "p@ssword", "pass123", "passwd", "letmein", "welcome", "welcome1",
    "welcome123", "monkey", "dragon", "sunshine", "princess", "football",
    "baseball", "basketball", "superman", "batman", "shadow", "master",
    "michael", "jennifer", "jordan", "harley", "ranger", "hunter",
    "buster", "soccer", "hockey", "killer", "george", "andrew",
    "charlie", "thomas", "robert", "daniel", "joshua", "matthew",
    "trustno1", "starwars", "whatever", "freedom", "iloveyou", "lovely",
    "flower", "cookie", "chocolate", "computer", "internet", "samsung",
    "google", "facebook", "myspace1", "abc123", "abcd1234", "abc12345",
    "a1b2c3", "aa123456", "123abc", "696969", "7777777", "12345678910",
    # developer and infrastructure defaults -- the ones that matter most here
    "admin", "admin123", "administrator", "root", "root123", "toor",
    "changeme", "change_me", "changeit", "default", "guest", "test",
    "test123", "testing", "temp", "temp123", "secret", "secret123",
    "docker", "jenkins", "postgres", "mysql", "oracle", "redis",
    "mongodb", "elastic", "kibana", "grafana", "tomcat", "apache",
    "nginx", "ubuntu", "centos", "debian", "vagrant", "raspberry",
    "raspberrypi", "pi", "user", "user123", "demo", "demo123",
    "public", "private", "master123", "manager", "service", "system",
    "backup", "database", "server", "localhost", "example", "sample",
    "dummy", "foobar", "foo", "bar", "baz", "qwerty1", "hello",
    "hello123", "helloworld", "letmein123", "openses", "opensesame",
    "access", "login", "logmein", "enter", "start", "install",
    "setup", "config", "sysadmin", "operator", "supervisor", "owner",
    "developer", "devops", "deploy", "release", "staging", "production",
    "prod", "dev", "development", "qwer1234", "asd123", "zxc123",
    "1234abcd", "pass1234", "mypassword", "newpassword", "oldpassword",
    "thisisapassword", "correcthorsebatterystaple",
    # vault- and secret-manager flavoured guesses
    "vault", "vault123", "keychain", "keystore", "secrets", "mysecret",
    "topsecret", "confidential", "encrypted", "decrypt", "unlock",
    "masterkey", "master_key", "privatekey", "apikey", "token",
})


def _shorten_path(text: str, max_len: int = 64) -> str:
    # targets.json paths are attacker-writable state (see load_targets), so
    # this goes through the same whitespace-collapse + hard-cap as any
    # other untrusted text before it's ever put in a dialog.
    return _safe_display(text, max_len)


def _format_bytes(count) -> str:
    """Human-readable byte count for a consent dialog. Pure; unit-tested."""
    try:
        count = int(count)
    except (TypeError, ValueError):
        return "unknown size"
    if count < 1024:
        return f"{count} bytes"
    for unit in ("KiB", "MiB", "GiB"):
        count /= 1024.0
        if count < 1024 or unit == "GiB":
            return f"{count:.1f} {unit}"
    return f"{count:.1f} GiB"


_OVERWRITE_CAVEAT = (
    "Overwriting is best-effort. On SSDs and journaling filesystems the "
    "original bytes may still exist in storage this program cannot reach -- "
    "wear-levelling, shadow copies, backups, your editor's swap file. If this "
    "file was ever exposed, rotate the credential; do not rely on this deletion."
)

_DURABILITY_CAVEAT = (
    "If vault.enc on this machine is lost, this file cannot be recovered. The "
    "recovery key alone is not enough -- it only works together with vault.enc. "
    "Back that file up."
)


def _disclosure_mismatch(disclosed_names, actual_secret_names) -> Optional[str]:
    """None if what was disclosed to the human matches what's actually in
    the vault; otherwise a human-facing message naming the difference.

    Exists because unlock_for_run_dialog's "Will expose N variable(s)" list
    (for the only_vars=None, "expose everything" case) is necessarily built
    from vault_index.json BEFORE the password is entered -- decrypting
    upfront just to compute a disclosure list would defeat the point of
    having a plaintext index at all. If vault.enc and vault_index.json have
    ever diverged (e.g. a prior add_secret call where save_secrets
    succeeded but save_index then failed -- reported as a partial_failure
    at the time, but the desync itself isn't auto-reconciled), a variable
    present in the vault but absent from the index would otherwise get
    injected into the child process without ever having appeared in what
    the human approved. This is the one point both sources are known --
    right after decryption, before injection -- so it's the one place this
    can be caught.

    Pure on purpose, so it's directly unit-testable
    without spinning up a real dialog."""
    disclosed, actual = set(disclosed_names), set(actual_secret_names)
    if disclosed == actual:
        return None
    parts = []
    extra = sorted(actual - disclosed)
    missing = sorted(disclosed - actual)
    if extra:
        parts.append(f"in the vault but not disclosed above: {', '.join(extra)}")
    if missing:
        parts.append(f"disclosed above but no longer in the vault: {', '.join(missing)}")
    return ("The vault and vault_index.json have diverged -- refusing to run until this "
            "is fixed (call sync_llm_env, or re-run add_secret/remove_secret for the "
            "affected name(s)): " + "; ".join(parts))


def _is_common_password(pw: str) -> bool:
    """True if pw is in the blocklist, compared case- and whitespace-insensitively."""
    return pw.strip().lower() in _COMMON_PASSWORDS


def _password_rejection_reason(pw: str) -> Optional[str]:
    """Why this password cannot be used, or None if it is acceptable.

    Single source of truth: every dialog that sets a password routes through
    here, so the blocklist cannot end up enforced in one flow and not another.
    """
    if not pw:
        return "Password cannot be empty."
    if len(pw) < MIN_PASSWORD_LEN:
        return f"Use at least {MIN_PASSWORD_LEN} characters."
    if _is_common_password(pw):
        return ("That is one of the most commonly used passwords in the world. "
                "Anyone who copies vault.enc would guess it within seconds, no "
                "matter how strong the encryption is. Please pick another.")
    return None


def _parse_rk_input(text: str):
    """Try to parse and checksum-verify a recovery key string.

    Returns (bytearray, None) on success, (None, friendly_error_str) on
    failure.  The caller must zero the returned bytearray when done —
    best-effort in CPython, does not defeat a memory dump.

    The friendly error message for MalformedRecoveryKey deliberately says
    'that looks like a typo' so users can distinguish a transcription error
    from an entirely wrong key.  The raw exception message is included
    (it never contains key material — only character counts and
    mismatched checksum digests) to give actionable detail.

    Pure, so it can be unit-tested without a browser."""
    try:
        raw = parse_recovery_key(text)
        return raw, None
    except MalformedRecoveryKey as exc:
        return None, (
            f"That looks like a typo — check what you entered ({exc})."
        )
    except Exception:
        # Guard: never let unexpected exceptions surface key material.
        return None, "Could not read recovery key (unexpected format)."


def _applicable_manage_actions(info: dict, encrypted_file_count: int = 0) -> list:
    """Return the list of manage_vault_dialog action IDs that make sense for
    the current vault state described by *info* (from store.vault_info()).

    *encrypted_file_count* gates the two file-key actions: offering "rotate the
    key that protects your encrypted files" to someone who has never encrypted
    one is noise, and a menu of mostly-inapplicable options is how people stop
    reading menus.

    Ordering matches the recommended display order.
    Pure, so it can be unit-tested without a browser."""
    if "error" in info:
        return []
    actions = ["change_password"]
    fmt = info.get("format")
    if fmt == 1:
        actions.append("upgrade_v2")
    if fmt == 2:
        if info.get("recovery_slot"):
            actions.append("reissue_recovery")
        else:
            actions.append("setup_recovery")
        if encrypted_file_count:
            actions.append("rotate_file_key")
            actions.append("retire_file_keys")
    return actions
