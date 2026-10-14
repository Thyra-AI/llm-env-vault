#!/usr/bin/env python3
"""MCP server exposing llm-env-vault's operations as tools an AI coding
assistant calls directly -- instead of shelling out to standalone
scripts and parsing stdout. Every mutating tool still pops up the same
Tkinter consent dialog as before; nothing is written to disk until a
human clicks Allow and types the master password themselves. vault_lib
(crypto, parsing, atomic writes, the dialogs) is unchanged -- this file
only changes how those operations are invoked.

Run directly for local testing:
    python mcp_server.py

Register with an MCP-aware client via a config entry pointing at this
file and this venv's python.exe -- see README.md.
"""
import sys

# Set before importing vault_lib: when this runs as an installed plugin, the
# import below resolves out of ${CLAUDE_PLUGIN_ROOT} -- a version-scoped
# directory the plugin manager owns and treats as immutable. Without this,
# Python drops a vault_lib/__pycache__ into it on every start. Must stay above
# the vault_lib import; after it, it's a no-op.
sys.dont_write_bytecode = True

import base64
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from vault_lib import (allowlist, envnames, gui, legacy_swap, procs, profiles, runstore,
                       singleview, store, trust)
from vault_lib.crypto import (WrongPassword, TooManyAttempts, WrongRecoveryKey,
                              MalformedRecoveryKey, NoRecoverySlot, VaultCorrupted,
                              VaultTampered)

# Arm always-allow entries whenever the master password unlocks the vault (the
# listener is idempotent; nothing is armed until a password unlock happens).
allowlist.install()

# Standing policy handed to every client that connects, so it applies
# unconditionally rather than depending on a skill trigger firing at the exact
# moment an agent is about to open a .env.
_AGENT_INSTRUCTIONS = """\
This server exists so you can work with .env variable NAMES without ever \
seeing the real VALUES. To keep that guarantee:

- Never read vault.enc, vault.salt, or any .env file this server manages. \
Their real values are not yours to see, and vault.enc is ciphertext anyway. \
Call vault_status() to learn which variables exist.
- Never ask the user to type or paste the master password (or any secret \
value) into the chat. Every tool that needs it opens a native dialog the \
human types into directly -- that is the only correct path.
- Never ask the user to type or paste a recovery key into the chat. Recovery \
keys are displayed and confirmed exclusively in a native dialog the human \
reads from their printed copy -- the chat is never the right channel for a \
recovery key, and a key entered into chat is immediately compromised.
- run_with_env requires only_vars: list the variables the command actually \
needs, and only those are injected. A call with neither only_vars nor \
all_vars=True is refused. all_vars=True injects the whole vault; use it only \
when the command really needs most of it, because every unrelated secret is \
then exposed to that command and anything it spawns.
- run_with_env output is redacted before it reaches you: vault values, and \
their base64 and URL-encoded forms, are replaced with [REDACTED:NAME]. This \
is best-effort damage control, NOT a guarantee -- values under 8 characters \
are left alone (they would shred unrelated output; the names are reported in \
redaction_skipped), and a command that transforms what it prints can still \
emit a real value. Do not echo run_with_env output back verbatim, and never \
craft a command whose purpose is to get a value past the redactor.
- run_with_env returns only the last tail_chars characters (default 4000) of \
each stream, plus a run_id and the stream's total size. When the part you need \
is not in that tail, call read_run_output(run_id, pattern=...) to search the \
whole redacted output, or read a window of lines -- do not re-run the command \
for it (that costs the human another password prompt). It needs no password, \
because only already-redacted output is kept, and only in this server's \
memory (the last 20 runs; gone when the server restarts).
- Never read the background-run log file (the llm-env-vault-run-*.log path \
returned when background=True) while the process is still running -- it \
contains real secret values until the server redacts it in place once the \
process exits. Wait for the process to finish before reading the log.
- Never read a materialize target file -- it contains real secret values and \
is deleted the instant the foreground command exits. Its path should be \
treated as write-only from your perspective.
- Never read a file this server decrypts. encrypt_file and decrypt_file move \
whole files -- certificates, private keys, kubeconfigs, service-account JSON -- \
in and out of the vault, and their decrypted contents are precisely the values \
you are not meant to see. Treat the path decrypt_file writes to as write-only, \
exactly like a materialize target. vault_status() lists every encrypted file's \
path, original name, size and date; that is the only information about them you \
should ever hold.
- A .levault file is pure ciphertext. It is safe to read, commit, and move, but \
there is nothing in it for you -- do not try to decrypt one outside this server.
- Never propose encrypt_file on a file you were not asked to encrypt. It \
destroys the original after encrypting, and the only way back is the master \
password or the recovery key.
- Real values reach a command through its ENVIRONMENT. That serves every \
consumer that reads its own environment, which is almost all of them by \
default -- python-dotenv, pydantic-settings, Node --env-file, Vite, Next, \
Bun, uv run and compose ${VAR} interpolation all let the environment win \
over the file. Reach for materialize= only for a tool that reads an env \
FILE and nothing else: `docker run --env-file`, compose `env_file:`, \
kubectl --from-env-file. Pair it with only_vars, and with max_reads=1 (2 \
for docker compose) so the file is emptied the moment it has been read.
- Never edit targets.json, target_styles.json or swap.journal.json.
- If a result contains swap_recovered or legacy_swap_live, a pre-2.0 \
install left real values in a project's own .env. Stop, quote that field to \
the user verbatim, and wait for their instruction before running anything \
else -- real values may still be on disk somewhere they need to look.
"""

mcp = FastMCP("llm-env-vault", instructions=_AGENT_INSTRUCTIONS)

# How old a background-run log has to be before opportunistic cleanup
# deletes it. Generous on purpose -- this only ever removes a log from a
# run that finished long ago, never one from a process that might still be
# writing to it.
_STALE_RUN_LOG_AGE_SECONDS = 7 * 24 * 60 * 60  # 7 days


# Full redacted output of recent foreground runs (and background runs, once the
# server has redacted their log), for read_run_output. Memory only.
_RUN_OUTPUT = runstore.RunOutputStore()

# Reports from a recovery performed at server start, before any tool call
# existed to return them in. Drained into the first tool result that can carry
# them, so a restore the user never asked for is never a restore they never
# hear about.
_startup_recovery: list = []


def _recover_swaps() -> list:
    """Restore any swapped .env whose owning server died or whose own restore
    failed (see legacy_swap.recover_stale_swaps), plus anything server start found.
    Never raises: a broken journal is reported as an entry, because the
    tool call this runs inside must still do its own job."""
    reports = list(_startup_recovery)
    _startup_recovery.clear()
    try:
        reports.extend(legacy_swap.recover_stale_swaps())
    except (OSError, ValueError, RuntimeError) as e:
        reports.append({"error": f"could not process swap.journal.json: {e}"})
    return reports


def _live_swap_paths() -> tuple:
    """({normcased path: entry}, error) for files some live server has real
    values in. On an unreadable journal the error is set and the dict is
    empty -- callers that would rewrite a target must treat that as "cannot
    tell" and refuse, not as "nothing is swapped". A corrupted journal is
    exactly the state in which a file is most likely to be mid-swap with
    nobody watching it."""
    try:
        return {os.path.normcase(k): v for k, v in legacy_swap.live_swaps().items()}, None
    except (OSError, ValueError, RuntimeError) as e:
        return {}, f"swap.journal.json could not be read: {e}"


def _with_swap_recovery(result_fn) -> dict:
    """Run a tool body after stale-swap recovery, attaching the recovery
    report to whatever it returns."""
    recovered = _recover_swaps()
    result = result_fn()
    if recovered and isinstance(result, dict):
        result["swap_recovered"] = recovered
    return result


def _cleanup_stale_run_logs() -> None:
    """Best-effort deletion of old background=True run logs in the system
    temp directory. These can contain a run's real environment if the
    command printed its own config (documented in README's Known
    limitations) and were previously never cleaned up at all. Called
    opportunistically right before a new background run creates its own
    log -- never allowed to fail the actual run it's piggybacking on."""
    try:
        temp_dir = Path(tempfile.gettempdir())
        cutoff = time.time() - _STALE_RUN_LOG_AGE_SECONDS
        for log_path in temp_dir.glob("llm-env-vault-run-*.log"):
            try:
                if log_path.stat().st_mtime < cutoff:
                    log_path.unlink()
            except OSError:
                continue  # another process may hold it open, or it's already gone -- skip, don't fail the run
    except OSError:
        pass

# Minimum byte-length a vault value must have before _redact_secrets will
# replace it in command output. Values shorter than this (e.g. "1", "true",
# "no") are too short to replace safely: they would match common substrings
# and destroy the output. They are reported in the result instead so the
# omission is visible rather than silent.
REDACT_MIN_VALUE_LEN = 8


# Cap on the captured output of a run that an always-allow entry auto-approved
# (plan 2.4.0 s4), per stream, in bytes of UTF-8. It limits volume, not leakage.
STRICT_OUTPUT_CAP_BYTES = 256 * 1024
# First characters of the note _redact_secrets(strict=True) puts at the start of
# a capped stream, so a caller can tell the output was truncated.
STRICT_TRUNCATION_PREFIX = "[llm-env-vault: output truncated"
# The raw (pre-redaction) capture of an auto-allowed run is bounded too, so a
# command that prints without end cannot balloon this process: at most this many
# bytes per stream are kept (the tail), the rest is read and discarded.
STRICT_RAW_CAPTURE_BYTES = 4 * STRICT_OUTPUT_CAP_BYTES


def _strict_variants(value: str) -> list:
    """Every textual form of *value* that strict redaction replaces, longest
    first: the value and its upper()/lower() forms, each as raw, standard and
    urlsafe base64 (padded and unpadded), hex (lower and upper) and URL-encoded
    (quote and quote_plus, upper- and lower-case %XX)."""
    out = set()
    for base in {value, value.upper(), value.lower()}:
        raw = base.encode("utf-8")
        out.add(base)
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            padded = enc(raw).decode("ascii")
            out.add(padded)
            out.add(padded.rstrip("="))
        # The same bytes embedded in a larger base64 blob start at byte offset
        # 0, 1 or 2 of a 3-byte group. At offsets 1 and 2 the leading chars mix
        # in the neighbouring bytes, and a partial last group mixes in the
        # following ones, so those boundary-affected chars are dropped and the
        # untouched middle is what gets matched (unpadded; urlsafe too).
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            for offset, lead in ((0, 0), (1, 2), (2, 3)):
                coded = enc(bytes(offset) + raw).decode("ascii").rstrip("=")
                coded = coded[lead:]
                if (offset + len(raw)) % 3:
                    coded = coded[:-1]
                if len(coded) >= REDACT_MIN_VALUE_LEN:
                    out.add(coded)
        hexed = raw.hex()
        out.add(hexed)
        out.add(hexed.upper())
        for quoted in (urllib.parse.quote(base, safe=""), urllib.parse.quote_plus(base, safe="")):
            out.add(quoted)
            out.add(re.sub(r"%[0-9A-Fa-f]{2}", lambda m: m.group().lower(), quoted))
    out.discard("")
    return sorted(out, key=lambda v: (-len(v), v))


def _cap_strict_output(text: str) -> str:
    """Keep the last STRICT_OUTPUT_CAP_BYTES of *text* (UTF-8) and say so.
    Call on text that is already redacted: cutting can then split a marker but
    never expose a raw value."""
    raw = text.encode("utf-8")
    if len(raw) <= STRICT_OUTPUT_CAP_BYTES:
        return text
    kept = raw[-STRICT_OUTPUT_CAP_BYTES:].decode("utf-8", errors="ignore")
    return (f"{STRICT_TRUNCATION_PREFIX}: this command was auto-allowed, so only the last "
            f"{STRICT_OUTPUT_CAP_BYTES} of {len(raw)} bytes of this stream are kept]\n" + kept)


def _redact_secrets(text: str, secrets: dict, strict: bool = False) -> tuple:
    """Replace every vault value in text with [REDACTED:VAR_NAME].

    Matches the exact value, its base64-encoded form, and its
    URL-percent-encoded form. Values shorter than REDACT_MIN_VALUE_LEN
    are skipped to avoid substring-destroying false positives.

    strict=True is for runs auto-allowed by an always-allow entry (plan 2.4.0
    s4). It additionally redacts base64 and base64url (padded and unpadded),
    hex (lower/upper), quote and quote_plus URL-encodings and the upper()/lower()
    forms of the value (each in those encodings), and caps the result at
    STRICT_OUTPUT_CAP_BYTES, keeping the tail and prefixing a truncation note.
    The cap is applied AFTER redaction.

    Returns (redacted_text, names_skipped_as_too_short).
    """
    skipped: list = []
    # Process longest values first so a long value isn't masked before its
    # shorter substring (a different vault entry) is replaced first.
    for name, value in sorted(secrets.items(), key=lambda kv: -len(kv[1])):
        if len(value) < REDACT_MIN_VALUE_LEN:
            skipped.append(name)
            continue
        marker = f"[REDACTED:{name}]"
        if strict:
            for variant in _strict_variants(value):
                text = text.replace(variant, marker)
            continue
        # Exact value
        text = text.replace(value, marker)
        # Base64-encoded form (e.g. as it might appear in an HTTP Authorization header)
        b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
        text = text.replace(b64, marker)
        # URL-percent-encoded form (e.g. as it might appear in a connection string)
        url_enc = urllib.parse.quote(value, safe="")
        text = text.replace(url_enc, marker)
    if strict:
        text = _cap_strict_output(text)
    return text, skipped


# GUI-opening tools are deliberately plain, synchronous functions -- NOT
# offloaded to a worker thread via asyncio.to_thread. That was tried: it
# does avoid freezing the event loop while a dialog sits open, but Tkinter
# is not reliably safe to run outside whichever thread happens to own its
# Tcl interpreter state, and moving dialogs onto asyncio's worker-thread
# pool produced a real, reproducible `Tcl_AsyncDelete: async handler
# deleted by the wrong thread` error the very first time this was tested
# end-to-end. Given the pinned mcp 1.29.0 already runs sync tools inline
# on the loop thread (verified against FuncMetadata.call_fn_with_arg_
# validation), staying synchronous here isn't a regression -- it keeps
# every Tk() instance on the one thread that has ever created one, which
# is what actually matters. Trade-off: only one tool call can be in
# flight while a dialog is open (no ping/cancellation/concurrent calls
# until it's answered) -- acceptable for the single-agent, one-call-at-
# a-time usage this is built for; a real fix would run dialogs in a
# separate dedicated process instead.


def _vault_status_impl() -> dict:
    return _with_swap_recovery(_vault_status_core)


def _vault_status_core() -> dict:
    try:
        index = store.load_index()
        targets = store.load_targets()
        # Paths, names, sizes and dates -- never contents. Same principle as
        # vault_index.json exposing variable NAMES but never values.
        files = store.file_registry_status()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"error": str(e)}

    # format_version is cheap to compute (just reads the first bytes of vault.enc)
    # and lets the agent suggest an upgrade to v2 when appropriate -- the human
    # still decides and acts via manage_vault.
    result = {
        "vault_exists": store.vault_exists(),
        "variables": index,
        "llm_env_path": str(store.ENV_FILE),
        "targets": targets,
        "files": files,
        "format_version": store.vault_format_version(),
    }
    # Files another live server currently has real values written into.
    # Disclosed so an agent can see why a resync skipped them and so a
    # human asking "is anything unlocked right now" gets a true answer.
    live, live_error = _live_swap_paths()
    if live:
        result["legacy_swap_live"] = [
            {"path": k, "names": e["names"], "pid": e["pid"]} for k, e in sorted(live.items())]
    if live_error:
        result["swap_journal_error"] = live_error
    # Journal-independent: which managed lines currently hold something that
    # is not a placeholder. Names only. This is how a real value left behind
    # by any means -- a crash whose journal was later deleted, a swap in a
    # session whose server can no longer be reached -- becomes visible on
    # the next status call, without trusting any record the agent can edit.
    holding = {}
    for path_str, names in targets.items():
        path = Path(path_str)
        if not path.is_file():
            continue
        try:
            preview = store.placeholder_state(path, names)
        except (OSError, ValueError) as e:
            holding[path_str] = {"error": str(e)}
            continue
        if preview["not_placeholder"]:
            holding[path_str] = preview["not_placeholder"]
        if preview["pending"]:
            result.setdefault("targets_with_pending_placeholders", {})[path_str] = \
                preview["pending"]
    if holding:
        result["targets_holding_non_placeholders"] = holding

    # Whether placeholders carry a type, and which variables do not yet. A
    # vault made before typed placeholders existed stays in the old format
    # until a human runs retype_placeholders -- upgrading never rewrites
    # anybody's .env on its own -- so this is how that state is visible
    # rather than something the user has to already know to ask about.
    shapes_now = store.load_shapes()
    result["placeholder_style"] = store.placeholder_style()
    managed_names = {n for names in targets.values() for n in names}
    untyped = sorted(n for n in managed_names
                     if shapes_now.get(n, store.SHAPE_STR) == store.SHAPE_STR)
    if untyped and result["placeholder_style"] != store.STYLE_TYPED:
        result["untyped_vars"] = untyped
        result["untyped_note"] = (
            f"{len(untyped)} variable(s) still use the untyped `\"value N\"` placeholder, "
            f"which a typed settings loader (pydantic-settings, django-environ) cannot "
            f"parse from a placeholder-only .env. Call retype_placeholders to fix that; "
            f"it needs the master password and rewrites the registered files.")

    # Non-secret recovery-slot metadata so the agent can surface "you have no
    # recovery slot set up" without ever touching private key material.
    # vault_id is deliberately excluded: it is a random internal identifier that
    # serves no purpose for the agent and could be misused to correlate vault
    # files across backups or machines.
    info = store.vault_info()
    if "error" not in info:
        result["recovery_key"] = {
            "present": info.get("recovery_slot", False),
            "id": info.get("recovery_slot_id"),
            "created": info.get("recovery_slot_created"),
        }

    return result


@mcp.tool()
def vault_status() -> dict:
    """Read-only snapshot of the vault: which variables are managed, their
    llm.env placeholder numbers, which project files are registered for
    resync_targets, which whole files are encrypted, the vault format version,
    and whether a recovery slot exists. Reads vault.enc headers for format
    metadata but never decrypts -- no password needed, safe to call anytime.
    Secret values are never returned; vault_id is deliberately omitted
    (internal identifier only).

    The "files" list gives each encrypted file's path, original name, size and
    date -- never its contents -- plus a status: ok, missing (the .levault is
    gone), modified (re-encrypted elsewhere), plaintext_present (a decrypted
    copy is sitting next to it), or error."""
    return _vault_status_impl()


def _sync_llm_env_impl() -> dict:
    if not store.INDEX_FILE.exists():
        return {"error": "vault_index.json not found -- nothing to sync from."}
    try:
        index = store.load_index()
        store.regenerate_llm_env(index)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"error": str(e)}
    return {"applied": True, "variable_count": len(index)}


@mcp.tool()
def sync_llm_env() -> dict:
    """Regenerate this repo's own llm.env from vault_index.json. No
    password needed. Useful if llm.env was deleted or hand-edited. Does
    not touch any registered target .env -- use resync_targets for that."""
    return _sync_llm_env_impl()


def _add_secret_impl(var_name: str) -> dict:
    try:
        store.validate_var_name(var_name)
        index = store.load_index()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"applied": False, "error": str(e)}
    is_update = var_name in index
    if not is_update and envnames.is_tool_control_name(var_name):
        # Plan 2.4.0 s4: NEW names that steer git/docker/kubectl/proxies/the
        # loader are refused before any dialog. Names already in the vault
        # (is_update) keep working.
        return {"applied": False, "error": envnames.refusal_message(var_name)}
    placeholder = index[var_name] if is_update else store.next_placeholder(index)
    is_sensitive = store.is_sensitive_env_name(var_name)
    outcome = gui.add_secret_dialog(var_name, is_update, placeholder, is_sensitive=is_sensitive)
    if outcome["approved"]:
        return {"applied": True, "message": f'{var_name} -> "value {placeholder}" in llm.env'}
    if outcome["partial_failure"]:
        return {"applied": False, "error": outcome["partial_failure"]}
    return {"applied": False, "message": "Denied by user."}


@mcp.tool()
def add_secret(var_name: str) -> dict:
    """Add or update one secret in the vault. Opens a GUI window where the
    human types the master password and the real value; nothing is
    written until they click Allow. The real value is never returned or
    logged -- only a placeholder-mapping confirmation."""
    return _add_secret_impl(var_name)


def _remove_secret_impl(var_name: str) -> dict:
    try:
        store.validate_var_name(var_name)
        index = store.load_index()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"applied": False, "error": str(e)}
    if var_name not in index:
        return {"applied": False, "message": f"{var_name} is not in the vault."}
    if not store.vault_exists():
        # Previously auto-pruned this entry with no dialog and no password,
        # on the reasoning that an unrecoverable vault means there's no
        # real secret left to protect. But that also means an agent
        # (wrong cwd, vault.enc mid-restore, permissions hiccup) can wipe
        # the whole index unattended, one call per entry, with zero
        # confirmation -- contradicting the "nothing written until a
        # human clicks Allow" contract every other tool honors. Report
        # the inconsistent state instead of acting on it.
        return {"applied": False,
                "error": f"vault_index.json lists {var_name}, but vault.enc/vault.salt are "
                         f"missing -- refusing to remove it without human confirmation. "
                         f"Restore the vault files, or edit vault_index.json by hand if "
                         f"you're sure it's safe."}
    outcome = gui.remove_secret_dialog(var_name, index[var_name])
    if outcome["approved"]:
        return {"applied": True, "message": f"{var_name} removed from llm.env"}
    if outcome["partial_failure"]:
        return {"applied": False, "error": outcome["partial_failure"]}
    return {"applied": False, "message": "Denied by user."}


@mcp.tool()
def remove_secret(var_name: str) -> dict:
    """Remove one secret from the vault. Opens a GUI confirm dialog (master
    password, then the proposed removal); nothing is removed until the
    human clicks Allow."""
    return _remove_secret_impl(var_name)


def _find_on_path(name: str) -> Optional[str]:
    """Locate an executable on PATH -- and ONLY on PATH.

    Not shutil.which: on Windows it consults the current directory first,
    and so does CreateProcess when handed a bare name. This server's
    current directory is whatever project the client has open, which an
    agent can write to, so a bare "git" could resolve to a git.exe planted
    in the project. Walk PATH ourselves, skip empty entries and the cwd,
    and hand back an absolute path or nothing.
    """
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    # Only real executables. A .cmd/.bat shim runs through cmd.exe with
    # its own argument mangling, and an agent can write one anywhere on
    # PATH that is under the project (an activated venv's Scripts dir,
    # node_modules\.bin).
    exts = [".exe", ".com"] if os.name == "nt" else [""]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry.strip() or not os.path.isabs(entry):
            continue
        norm = os.path.normcase(os.path.abspath(entry))
        if norm == cwd or norm.startswith(cwd + os.sep):
            continue
        for ext in exts:
            candidate = os.path.join(entry, name + ext)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None


# Resolved once, at import, before any agent-influenced cwd change could
# matter. None means "no git": the probes answer "unknown" and never run
# anything.
_GIT_EXE = _find_on_path("git")

# Git will run a program named by repo-level config on the most innocent
# commands -- `core.fsmonitor` fires on every index read, including
# ls-files and check-ignore. The probe runs BEFORE any dialog, in a
# directory the agent can write .git/config (or a `.git` file pointing at a
# repo it controls), so every config source that could name a program is
# switched off for the duration: no system or global config, hooks pointed
# at an empty directory, fsmonitor forced off. The environment is built
# from scratch rather than inherited so nothing else leaks in.
_GIT_HOOKS_DIR = os.path.join(tempfile.gettempdir(), "llm-env-vault-no-hooks")
try:
    os.makedirs(_GIT_HOOKS_DIR, exist_ok=True)
except OSError:
    pass


def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE",
                            "LANG", "LC_ALL")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": _GIT_HOOKS_DIR,
    })
    return env


def _gitdir_is_suspicious(repo_dir: Path) -> bool:
    """A `.git` FILE (not directory) redirects git with `gitdir: <path>`. An
    agent can write one pointing at a share or a named pipe, turning the
    probe into a network touch and a 10 s hang before any dialog. Refuse to
    probe when the redirect is not a plain local absolute-or-relative path."""
    probe = repo_dir
    for _ in range(64):
        dot_git = probe / ".git"
        try:
            if dot_git.is_dir():
                return False
            if dot_git.is_file():
                first = dot_git.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
                target = first[0].partition("gitdir:")[2].strip() if first else ""
                return (not target or store._looks_like_unc(target)
                        or target.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")))
        except OSError:
            return True
        if probe.parent == probe:
            return False
        probe = probe.parent
    return False


def _git(args: list, cwd: Path) -> Optional[int]:
    """Run git with the hardened environment; the exit code, or None if git
    is unavailable, timed out, could not start, or the repo looks hostile.

    The process's own cwd is git's directory, not the project: Windows
    searches the current directory for DLLs before PATH, and the project
    is agent-writable. `-C` points git at the project instead. The `-c`
    overrides duplicate the GIT_CONFIG_* environment for git older than
    2.31, which ignores the environment form."""
    if _GIT_EXE is None or _gitdir_is_suspicious(cwd):
        return None
    try:
        proc = subprocess.run(
            [_GIT_EXE, "-C", str(cwd),
             "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={_GIT_HOOKS_DIR}",
             "-c", "core.virtualFilesystem=", *args],
            cwd=os.path.dirname(_GIT_EXE), env=_git_env(), capture_output=True, timeout=10,
            creationflags=procs.NO_WINDOW)
        return proc.returncode
    except (OSError, subprocess.SubprocessError):
        return None


def _git_tracks(path: Path) -> Optional[bool]:
    """Is *path* tracked by a git repo? None if the question can't be answered.

    Best-effort and never fatal: git may not be installed, the directory may
    not be a repo, or the call may hang on a network filesystem. See _git
    for why the call is hardened.
    """
    rc = _git(["ls-files", "--error-unmatch", "--", path.name], path.parent)
    return None if rc is None else rc == 0


def _git_ignores(path: Path) -> Optional[bool]:
    """Is *path* covered by a .gitignore rule (of this repo -- the global
    excludes file is deliberately not consulted)? None if unanswerable."""
    rc = _git(["check-ignore", "-q", "--", path.name], path.parent)
    if rc in (0, 1):
        return rc == 0
    return None


# Windows marks a file that lives under a cloud-sync root (OneDrive, and
# any provider using the Cloud Files API) with recall attributes; the
# well-known sync roots cover Dropbox/Google Drive/iCloud on every platform.
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_FILE_ATTRIBUTE_OFFLINE = 0x1000
_IO_REPARSE_TAG_CLOUD = 0x9000001A  # the family tag; provider bits masked off


def _cloud_synced(path: Path) -> Optional[str]:
    """Name of the sync provider that appears to cover *path*, or None.

    A swapped file inside a synced folder can be uploaded -- with real
    values -- before the command finishes, and no restore recalls it from
    the provider. This is the single most probable accidental leak on a
    default Windows install (Documents and Desktop are OneDrive roots), so
    the dialog names it. Warn only: refusing would block the feature for
    everyone whose projects live under Documents.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return None
    roots = []
    for var, label in (("OneDrive", "OneDrive"), ("OneDriveConsumer", "OneDrive"),
                       ("OneDriveCommercial", "OneDrive")):
        value = os.environ.get(var)
        if value:
            roots.append((Path(value), label))
    home = Path.home()
    for sub, label in (("Dropbox", "Dropbox"), ("Google Drive", "Google Drive"),
                       ("My Drive", "Google Drive"), ("iCloud Drive", "iCloud"),
                       ("Library/Mobile Documents", "iCloud")):
        roots.append((home / sub, label))
    for root, label in roots:
        try:
            if resolved.is_relative_to(root.resolve()):
                return label
        except (OSError, ValueError):
            continue
    for sub in ("Library/CloudStorage",):
        try:
            if resolved.is_relative_to((home / sub).resolve()):
                return "a cloud-sync provider (macOS CloudStorage)"
        except (OSError, ValueError):
            pass
    if os.name == "nt":
        for root, label in _windows_sync_roots():
            try:
                if resolved.is_relative_to(root):
                    return label
            except ValueError:
                continue
        probe = resolved
        for _ in range(64):
            try:
                st = os.lstat(probe)  # lstat: never follow a junction to a share
                attrs = st.st_file_attributes
                tag = getattr(st, "st_reparse_tag", 0)
            except (OSError, AttributeError):
                break
            if attrs & (_FILE_ATTRIBUTE_RECALL_ON_OPEN | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                        | _FILE_ATTRIBUTE_OFFLINE):
                return "a cloud-sync provider (file has cloud recall attributes)"
            if tag and (tag & 0xFFFF0FFF) == _IO_REPARSE_TAG_CLOUD:
                return "a cloud-sync provider (Cloud Files reparse point)"
            if probe.parent == probe:
                break
            probe = probe.parent
    return None


def _windows_sync_roots() -> list:
    """Every Cloud Filter sync root registered on this machine -- OneDrive,
    Dropbox, iCloud, Box, Google Drive in mirror mode -- as (Path, label)."""
    roots = []
    try:
        import winreg
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, sub) as k:
                        path, _ = winreg.QueryValueEx(k, "UserSyncRootPath")
                        if path:
                            roots.append((Path(path).resolve(), sub.split("!")[0]))
                except OSError:
                    continue
    except (OSError, ImportError):
        pass
    return roots


def _encrypt_file_impl(path: str) -> dict:
    try:
        target = Path(path)
        # Fast-fail before opening a window. precheck runs again inside the
        # Allow handler, because the dialog can sit open for minutes.
        info = store.precheck_encrypt(target)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"applied": False, "error": str(e)}

    # Ask git BEFORE the file is destroyed -- afterwards the path is gone and
    # the answer is unobtainable.
    tracked = _git_tracks(info["path"])

    outcome = gui.encrypt_file_dialog(info["path"])
    if outcome["approved"]:
        result = outcome["result"] or {}
        if not result.get("vault_path"):
            # Cannot happen with the real dialog, which always returns
            # encrypt_file_in_place's result on approval. But this tool must
            # never raise, and a KeyError here would surface as a protocol
            # error rather than something the caller can act on.
            return {"applied": False,
                    "error": "Internal error: the encrypt dialog approved the change "
                              "but returned no result."}
        response = {
            "applied": True,
            "message": (f"{result.get('original_name')} encrypted to "
                        f"{result.get('vault_path')}; the original was destroyed."),
            "vault_path": result.get("vault_path"),
            "original_name": result.get("original_name"),
            "plaintext_size": result.get("plaintext_size"),
        }
        warnings = []
        if tracked:
            # Encrypting now does nothing for a secret already in history.
            warnings.append(
                f"{result.get('original_name')} was tracked by git. If it was ever "
                f"committed, the real contents are still in the repository history "
                f"and encrypting it now protects nothing -- the plaintext must be "
                f"purged (git filter-repo or similar) AND the credential rotated. "
                f"Add the plaintext name to .gitignore and commit the .levault file "
                f"instead.")
        if _git_ignores(Path(result["vault_path"])) is True:
            # The one file that SHOULD be committed is being ignored.
            warnings.append(
                f"{Path(result['vault_path']).name} is covered by a .gitignore rule. "
                f"It is pure ciphertext and is the file you want in the repository -- "
                f"without it, this secret exists only on this machine.")
        if warnings:
            response["warnings"] = warnings
        return response

    if outcome["partial_failure"]:
        return {"applied": False, "error": outcome["partial_failure"]}
    return {"applied": False, "message": "Denied by user."}


@mcp.tool()
def encrypt_file(path: str) -> dict:
    """Encrypt any whole file into the vault, under the same master password.

    For secrets that are not .env variables -- certificates, private keys,
    kubeconfigs, service-account JSON, .p12 bundles. certs/server.pem becomes
    certs/server.pem.levault beside it, and the ORIGINAL IS DESTROYED once the
    encrypted copy has been written and verified. The .levault file is pure
    ciphertext and is safe to commit to git.

    Opens a GUI window where the human types the master password and confirms
    the specific file; nothing is written or deleted until they click Allow.
    The file's contents are never returned to you.

    Requires a v2 vault (run manage_vault -> upgrade_v2 first). Refuses
    symlinks, hard-linked files, empty files, anything already encrypted,
    anything inside the vault's own directory, files over 16 MiB, and any path
    whose .levault sidecar already exists."""
    return _encrypt_file_impl(path)


def _decrypt_file_impl(vault_path: str, output_path: Optional[str] = None) -> dict:
    try:
        target = Path(vault_path)
        store.precheck_decrypt(target, output_path)  # fast-fail before the window
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"applied": False, "error": str(e)}
    except (VaultCorrupted, VaultTampered) as e:
        return {"applied": False, "error": str(e)}

    outcome = gui.decrypt_file_dialog(target, output_path)
    if outcome["approved"]:
        result = outcome["result"] or {}
        if not result.get("output_path"):
            return {"applied": False,
                    "error": "Internal error: the decrypt dialog approved the change "
                              "but returned no result."}
        out = Path(result["output_path"])
        response = {
            "applied": True,
            "message": (f"{result.get('vault_path')} decrypted to {out}. "
                        f"This is a real secret on disk -- do not read it."),
            "output_path": str(out),
            "size": result.get("size"),
        }
        warnings = list(result.get("warnings") or [])
        if _git_ignores(out) is False and _git_tracks(out) is not None:
            # A real secret just landed in a working tree with no rule to keep
            # it out of the next commit.
            warnings.append(
                f"{out.name} is NOT covered by any .gitignore rule. It now contains "
                f"a real secret in plaintext -- add it to .gitignore before your next "
                f"commit, or re-encrypt it when you are done.")
        if warnings:
            response["warnings"] = warnings
        return response

    if outcome["partial_failure"]:
        return {"applied": False, "error": outcome["partial_failure"]}
    return {"applied": False, "message": "Denied by user."}


@mcp.tool()
def decrypt_file(vault_path: str, output_path: Optional[str] = None) -> dict:
    """Restore a .levault file to a real, plaintext file on disk, permanently.

    The decrypted file is NOT cleaned up -- use run_with_env's files= parameter
    instead when a command just needs the file for the duration of one run.

    Opens a GUI window where the human types the master password and confirms
    the output path; nothing is written until they click Allow. The .levault
    file is left in place. The restored contents are never returned to you, and
    you must not read the file this creates.

    By default the output name comes from the .levault file's own name
    (server.pem.levault -> server.pem), never from the name stored inside the
    ciphertext. Pass output_path to choose a different one. Refuses to
    overwrite an existing file."""
    return _decrypt_file_impl(vault_path, output_path)


def _install_migrate_impl(target_path: str) -> dict:
    try:
        target = Path(target_path).resolve()
        if not target.exists():
            return {"applied": False, "error": f"{target} does not exist."}
        if not target.is_file():
            return {"applied": False, "error": f"{target} is not a file."}
        live_all, live_error = _live_swap_paths()
        if live_error:
            # Fail closed: if the journal cannot say whether this file is
            # mid-swap in another session, migrating it could capture real
            # values as new secrets. Refuse until the journal is readable.
            return {"applied": False,
                    "error": f"cannot tell whether {target} is currently swapped by another "
                             f"llm-env-vault session ({live_error}) -- refusing to migrate "
                             f"it until swap.journal.json is readable."}
        live = live_all.get(os.path.normcase(str(target)))
        if live:
            # The file holds REAL values right now, written by a run_with_env
            # swap in another session. Migrating it would re-capture them as
            # "new" secrets and rewrite the lines that session is about to
            # restore. Refuse; the swap finishes on its own.
            return {"applied": False,
                    "error": f"{target} currently has real values swapped into it by "
                             f"another llm-env-vault session (pid {live['pid']}) -- wait "
                             f"for that command to finish, then try again."}

        parsed = store.parse_env_file(target)
        index_now = store.load_index()
        shapes_now = store.load_shapes()
        targets_now = store.load_targets()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"applied": False, "error": str(e)}

    found = [(item[1], item[2]) for item in parsed if item[0] == "var"]
    unsupported = [item[1] for item in parsed if item[0] == "unsupported"]
    unrecognized = [item[1] for item in parsed if item[0] == "unrecognized_name"]
    swallowed = [item[1] for item in parsed if item[0] == "swallowed"]

    dedup, dup_names = {}, set()
    for name, value in found:
        if name in dedup:
            dup_names.add(name)
        dedup[name] = value
    found = list(dedup.items())

    to_migrate, invalid_names, already_migrated, empty_names, stale_placeholders = [], [], [], [], []
    for name, value in found:
        try:
            store.validate_var_name(name)
        except ValueError:
            invalid_names.append(name)
            continue
        if not value:
            empty_names.append(name)
            continue
        if name in index_now and value == store._bare(
                store.placeholder_for(name, index_now, shapes_now)):
            already_migrated.append(name)
            continue
        # The guard that stops a placeholder being vaulted AS ITS OWN VALUE.
        # Index-aware since 2.0: without it a typed vault would store the
        # literal `false` as SMTP_USE_SSL's secret on the next migrate.
        if store.is_placeholder(name, value, index_now, shapes_now):
            stale_placeholders.append(name)
            continue
        to_migrate.append((name, value))

    warnings = []
    if invalid_names:
        warnings.append(f"Skipped non-standard name(s): {', '.join(invalid_names)}")
    if unsupported:
        warnings.append(f"Skipped multi-line/unterminated value(s), still real secrets in "
                         f"the file: {', '.join(unsupported)}")
    if unrecognized:
        warnings.append(f"Left real value(s) behind (var name isn't valid, e.g. a hyphen): "
                         f"{', '.join(unrecognized)}")
    if swallowed:
        warnings.append(f"Left real value(s) behind (swallowed inside a multi-line value): "
                         f"{', '.join(swallowed)}")
    if dup_names:
        warnings.append(f"Duplicate name(s) in the file, used last occurrence: "
                         f"{', '.join(sorted(dup_names))}")
    if empty_names:
        warnings.append(f"Skipped empty value(s): {', '.join(empty_names)}")
    if stale_placeholders:
        warnings.append(f"Skipped value(s) that look like a stale placeholder, not a real "
                         f"secret: {', '.join(sorted(stale_placeholders))}")

    if not to_migrate:
        if already_migrated and str(target) not in targets_now:
            # Registering into targets.json is a meaningful action: it grants
            # this file permanent unattended-rewrite eligibility via future
            # resync_targets calls. Require the same human-consented, password-
            # gated dialog as real migrations instead of silently writing
            # targets.json with zero confirmation.
            outcome = gui.install_dialog(target, to_migrate=[], other_owner={},
                                         also_register=already_migrated)
            if not outcome["approved"]:
                if outcome["partial_failure"]:
                    return {"applied": False, "error": outcome["partial_failure"],
                            "warnings": warnings}
                return {"applied": False, "message": "Denied by user.", "warnings": warnings}
            return {"applied": True,
                    "message": f"Registered {target} for future resync_targets calls.",
                    "warnings": warnings, "already_migrated": already_migrated}
        return {"applied": False, "message": "Nothing new to migrate.", "warnings": warnings,
                "already_migrated": already_migrated}

    other_owner = {}
    for name, _ in to_migrate:
        for path_str, names in targets_now.items():
            if path_str != str(target) and name in names:
                other_owner[name] = path_str
                break

    sensitive_names = {name for name, _ in to_migrate if store.is_sensitive_env_name(name)}
    outcome = gui.install_dialog(target, to_migrate, other_owner, also_register=already_migrated,
                                 sensitive_names=sensitive_names)
    if not outcome["approved"]:
        if outcome["partial_failure"]:
            return {"applied": False, "error": outcome["partial_failure"], "warnings": warnings}
        return {"applied": False, "message": "Denied by user.", "warnings": warnings}

    ret = {
        "applied": True,
        "migrated_count": len(to_migrate),
        "migrated_names": [n for n, _ in to_migrate],
        "target_still_has_real_secrets": bool(unsupported or unrecognized or swallowed),
        "warnings": warnings,
    }
    conflicts = outcome.get("conflicts", [])
    if conflicts:
        ret["conflicts"] = conflicts
    return ret


@mcp.tool()
def install_migrate(target_path: str) -> dict:
    """Migrate a project's real .env into the vault in place: real values
    move into the encrypted vault, and the target file is rewritten with
    placeholders (comments, indentation, export prefix, and line endings
    preserved). Opens a GUI dialog listing exactly which variable NAMES
    (never values) will move, calling out any that would overwrite
    another registered project's vault entry -- the human must click
    Allow before anything is written. Safe to call again later on the
    same file; already-migrated variables are skipped automatically."""
    return _with_swap_recovery(lambda: _install_migrate_impl(target_path))


def _resync_targets_impl() -> dict:
    return _with_swap_recovery(_resync_targets_core)


def _resync_targets_core() -> dict:
    try:
        index = store.load_index()
        targets = store.load_targets()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"error": str(e)}
    if not targets:
        return {"message": "No target files registered. Call install_migrate first."}

    live, live_error = _live_swap_paths()
    if live_error:
        # Same fail-closed rule as install_migrate: a resync rewrites managed
        # lines, and an unreadable journal means it cannot know which files
        # currently hold real values.
        return {"error": f"refusing to resync: cannot tell which targets are mid-swap "
                         f"({live_error})."}
    results = {}
    for path_str, names in targets.items():
        path = Path(path_str)
        if not path.exists():
            results[path_str] = {"status": "missing"}
            continue
        entry = live.get(os.path.normcase(path_str))
        if entry:
            # Every managed line in this file is a real value at the moment,
            # so a resync would report all of them as conflicts (names only,
            # never values -- sync_target_file's conflict list is names) and
            # touch nothing. Say why instead.
            results[path_str] = {"status": "swap_in_progress", "pid": entry["pid"]}
            continue
        try:
            conflicts = store.sync_target_file(path, index, names)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            results[path_str] = {"status": "error", "error": str(e)}
            continue
        removed = sorted(n for n in names if n not in index)
        if conflicts:
            results[path_str] = {"status": "conflicts", "conflicts": conflicts}
        elif removed:
            results[path_str] = {"status": "ok", "removed_from_vault": removed}
        else:
            results[path_str] = {"status": "ok"}
    return results


@mcp.tool()
def resync_targets() -> dict:
    """Refresh every project .env previously migrated with install_migrate
    against the current vault index -- e.g. after add_secret/remove_secret
    changed something elsewhere. No password needed (only placeholder
    numbers move, never values). Never overwrites a line that doesn't
    already look like one of this tool's own placeholders; a variable
    removed from the vault gets its line commented out, not deleted."""
    return _resync_targets_impl()


def _retype_placeholders_impl(only_vars: Optional[list] = None) -> dict:
    index = store.load_index()
    if not index:
        return {"applied": False, "message": "This vault has no variables yet."}
    shapes_before = store.load_shapes()
    if only_vars is not None:
        if not isinstance(only_vars, list) or not all(isinstance(v, str) for v in only_vars):
            return {"error": "only_vars must be a list of variable-name strings."}
        unknown = sorted(set(only_vars) - set(index))
        if unknown:
            return {"error": f"not in this vault: {', '.join(unknown)}"}
        names = sorted(set(only_vars))
    else:
        names = sorted(index)
    outcome = gui.retype_placeholders_dialog(names)
    if not outcome["approved"]:
        if outcome["partial_failure"]:
            return {"applied": False, "error": outcome["partial_failure"]}
        return {"applied": False, "message": "Denied by user."}
    # `retyped` is what a human would SEE change in their files. A value with
    # no shape to preserve -- an opaque string, a password -- keeps the
    # legacy `"value N"` because there is nothing better to render, so
    # listing it as retyped would overstate what happened.
    result = {
        "applied": True,
        "retyped": {n: s for n, s in outcome["retyped"].items()
                    if s != store.SHAPE_STR and shapes_before.get(n) != s},
        "left_opaque": sorted(n for n, s in outcome["retyped"].items()
                              if s == store.SHAPE_STR),
        "already_typed": sorted(n for n, s in outcome["retyped"].items()
                                if s != store.SHAPE_STR and shapes_before.get(n) == s),
        "placeholder_style": store.placeholder_style(),
    }
    if outcome["conflicts"]:
        result["conflicts"] = outcome["conflicts"]
        result["conflict_note"] = (
            "These lines were left exactly as they are because they do not hold one of "
            "this tool's own placeholders -- a real value may have been hand-edited back "
            "in. Look at each one; nothing was overwritten.")
    if outcome["partial_failure"]:
        result["warning"] = outcome["partial_failure"]
    return result


@mcp.tool()
def retype_placeholders(only_vars: Optional[list[str]] = None) -> dict:
    """Give this vault's placeholders a TYPE, so a placeholder-only .env can
    be parsed by the app that reads it.

    `SMTP_PORT="value 17"` is not an int and `SMTP_USE_SSL="value 38"` is not
    a bool, so a protected project cannot run a test suite that loads .env
    with a typed settings library -- pydantic-settings, django-environ,
    Spring -- even with this tool not involved in the run at all. After
    retyping, those lines read `SMTP_PORT=17` and `SMTP_USE_SSL=false` and
    parse cleanly, while still carrying no real value.

    Opens a password dialog: a value's type can only be read from the real
    value. The dialog lists every line exactly as it will end up, and says
    what this discloses -- the TYPE of each value, and a URL's scheme, to
    anything that can read the file, including you. Never the content: a
    bool always renders `false` and a bit always `0`, whatever the real one
    is.

    Applies to the whole vault, or to `only_vars`. Registered target files
    are rewritten to match, and a line that does NOT currently hold one of
    our own placeholders is reported in `conflicts` and left untouched.
    Retyping changes the bytes of every managed file, so any trusted
    docker/compose command drift-hashing one of them is revoked and the
    human re-approves it once -- that is the trust feature working, not a
    fault.

    A vault created on 2.0 is typed from its first secret and never needs
    this. It exists for vaults made before typed placeholders existed, which
    stay in the old format until you run it -- upgrading must not rewrite
    anybody's .env on its own."""
    return _with_swap_recovery(lambda: _retype_placeholders_impl(only_vars))


def _change_password_impl() -> dict:
    outcome = gui.change_password_dialog()
    if outcome["old"] is None or outcome["new"] is None:
        return {"applied": False, "message": "Cancelled by user."}
    try:
        new_key = store.change_password(outcome["old"], outcome["new"])
    except FileNotFoundError:
        return {"applied": False,
                "error": "No vault found (vault.enc or vault.salt is missing). "
                         "Create a vault first before changing the password."}
    except TooManyAttempts as e:
        return {"applied": False, "error": str(e)}
    except WrongPassword:
        return {"applied": False, "error": "Incorrect current password."}
    except (RuntimeError, VaultCorrupted, VaultTampered):
        # Re-encryption or read-back verification failed; vault was rolled back.
        # Do NOT include the exception message: it could theoretically carry
        # password material under unexpected code paths, even though in
        # practice store.change_password raises a fixed-text RuntimeError.
        return {"applied": False,
                "error": "Password change failed -- the vault has been restored "
                         "to its previous state. The password was NOT changed. "
                         "Try again or check for disk issues."}

    if new_key is not None:
        # The password change rotated the data encryption key and issued a new
        # recovery key -- the old printed recovery key is now permanently
        # invalid.  Show the new key in a native dialog so the human can write
        # it down; NEVER put the key in the tool result (MCP tool results
        # flow into the agent's context window and session logs).
        info = store.vault_info()
        slot_id = info.get("recovery_slot_id") or ""
        key_written = gui.show_recovery_key_dialog(new_key, slot_id)
        if not key_written:
            # The human closed the dialog without confirming they wrote the key
            # down.  The password HAS already changed -- that is irreversible.
            # Report honestly: the key is gone, the old printout is invalid.
            return {
                "applied": True,
                "warning": (
                    "Master password changed successfully. "
                    "The recovery key display was dismissed before confirming -- "
                    "the new recovery key cannot be recovered. "
                    "Your previous printed recovery key is now invalid. "
                    "Use manage_vault to issue a replacement recovery key."
                ),
            }

    return {"applied": True, "message": "Master password changed successfully."}


@mcp.tool()
def change_password() -> dict:
    """Change the vault's master password. Opens a GUI dialog where the
    human types the current password and the new password; nothing is
    written until they confirm. The passwords are never returned or
    logged. A cancelled dialog is a clean no-op. Three failure cases:
    wrong current password, no vault found, and a rare read-back failure
    (vault is automatically restored to its previous state in that last
    case). For v2 vaults with a recovery slot the password change also
    rotates the data encryption key and issues a new recovery key --
    a native dialog shows the new key so the human can write it down;
    the key never appears in this tool's result."""
    return _change_password_impl()


def _manage_vault_impl() -> dict:
    """Dispatch vault management actions selected by the human in a GUI dialog.

    gui.manage_vault_dialog() collects the action and all required parameters
    (passwords, flags) without exposing them to the agent.  This function drives
    the vault I/O and routes any recovery key through a separate native dialog
    so the key is never written into the tool result or the agent's context.

    Expected keys per action in the dialog response:
      change_password  -- "old_password" (str), "new_password" (str)
      setup_recovery   -- "password" (str)
      reissue_recovery -- "password" (str)
      always_allow_list   -- "password" (str)
      always_allow_remove -- "password" (str), "entry_id" (str)
      rotate_file_key  -- "password" (str)
      retire_file_keys -- "password" (str)
      upgrade_v2       -- "password" (str). The dialog never sets "recovery";
                          the kwarg is still passed through to store because
                          upgrade_to_v2 accepts it, but no UI path produces
                          True. Adding a recovery key is setup_recovery's job.
      None             -- cancelled; returns a clean no-change result

    Recovery key handling contract: whenever a store call returns a key, it is
    passed to gui.show_recovery_key_dialog and NEVER placed in the return dict.
    If the human closes that dialog without confirming, the result says so
    explicitly -- the credential change already occurred and is permanent.
    """
    outcome = gui.manage_vault_dialog()
    action = outcome.get("action")

    if action is None:
        return {"applied": False, "message": "Cancelled by user."}

    # ------------------------------------------------------------------ #
    # change_password                                                      #
    # ------------------------------------------------------------------ #
    if action == "change_password":
        old = outcome.get("old_password")
        new = outcome.get("new_password")
        if old is None or new is None:
            return {"applied": False, "message": "Cancelled by user."}
        try:
            new_key = store.change_password(old, new)
        except FileNotFoundError:
            return {"applied": False,
                    "error": "No vault found. Create a vault first before changing the password."}
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect current password."}
        except (RuntimeError, VaultCorrupted, VaultTampered):
            return {"applied": False,
                    "error": "Password change failed -- vault restored to its previous state. "
                             "The password was NOT changed. Try again or check for disk issues."}
        if new_key is not None:
            info = store.vault_info()
            slot_id = info.get("recovery_slot_id") or ""
            key_written = gui.show_recovery_key_dialog(new_key, slot_id)
            if not key_written:
                return {
                    "applied": True,
                    "action": "change_password",
                    "warning": (
                        "Master password changed successfully. "
                        "The recovery key display was dismissed before confirming -- "
                        "the new recovery key cannot be recovered. "
                        "Your previous printed recovery key is now invalid. "
                        "Use manage_vault to issue a replacement recovery key."
                    ),
                }
        return {"applied": True, "action": "change_password",
                "message": "Master password changed successfully."}

    # ------------------------------------------------------------------ #
    # rotate_file_key / retire_file_keys                                  #
    # The file key deliberately survives a password change, so it needs   #
    # its own rotation path -- see store.rotate_file_key.                 #
    # ------------------------------------------------------------------ #
    if action == "rotate_file_key":
        password = outcome.get("password")
        if password is None:
            return {"applied": False, "message": "Cancelled by user."}
        try:
            report = store.rotate_file_key(password)
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect master password."}
        except (OSError, ValueError, RuntimeError, VaultCorrupted, VaultTampered) as e:
            return {"applied": False, "error": str(e)}
        skipped = [r for r in report["results"] if r["status"] != "ok"]
        result = {
            "applied": True,
            "action": "rotate_file_key",
            "message": (f"Encrypted-file key rotated. {report['rotated']} file(s) "
                        f"re-encrypted under the new key."),
            "rotated": report["rotated"],
            "results": report["results"],
        }
        if skipped:
            # Never let this be silent. A file that did not rotate is still
            # readable with the key the user just decided to stop trusting.
            result["warning"] = (
                f"{len(skipped)} file(s) were NOT rotated and still open under the "
                f"old key, which has been retained so they keep working: "
                + ", ".join(f"{r['path']} ({r['status']})" for r in skipped[:10])
                + ". Make them reachable and run rotation again before retiring the "
                  "old keys.")
        return result

    if action == "retire_file_keys":
        password = outcome.get("password")
        if password is None:
            return {"applied": False, "message": "Cancelled by user."}
        try:
            report = store.retire_file_keys(password)
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect master password."}
        except (OSError, RuntimeError, VaultCorrupted, VaultTampered) as e:
            return {"applied": False, "error": str(e)}
        except ValueError as e:
            # Files this vault sealed are unaccounted for. Refusing forever is
            # its own failure mode -- a single crashed encrypt would leave the
            # user unable to retire a key they believe is compromised, with no
            # way to see what was blocking it. Show the identities and let a
            # human deliberately abandon them.
            try:
                outstanding = store.file_keys_outstanding(password)
            except Exception:  # noqa: BLE001
                outstanding = {}
            if not outstanding:
                return {"applied": False, "error": str(e)}
            names = {}
            try:
                for entry in store.load_file_registry().values():
                    if entry.get("file_id"):
                        names[entry["file_id"]] = entry.get("original_name")
            except (OSError, ValueError):
                pass
            abandon = gui.confirm_abandon_files_dialog(outstanding, names)
            if not abandon:
                return {"applied": False, "message": "Cancelled by user."}
            try:
                report = store.retire_file_keys(password, abandon=abandon)
            except TooManyAttempts as e:
                return {"applied": False, "error": str(e)}
            except WrongPassword:
                return {"applied": False, "error": "Incorrect master password."}
            except (OSError, ValueError, RuntimeError,
                    VaultCorrupted, VaultTampered) as exc:
                return {"applied": False, "error": str(exc)}
        if not report.get("retired"):
            return {"applied": False,
                    "message": report.get("message", "Nothing to retire.")}
        return {"applied": True, "action": "retire_file_keys",
                "message": (f"Retired {len(report['retired'])} old file key(s). Any "
                            f".levault still encrypted under one is now permanently "
                            f"unreadable.")}

    # ------------------------------------------------------------------ #
    # setup_recovery / reissue_recovery                                   #
    # Both use store.reissue_recovery_key: it adds a recovery slot if     #
    # none exists, or replaces the existing slot with a fresh key.        #
    # ------------------------------------------------------------------ #
    if action in ("setup_recovery", "reissue_recovery"):
        password = outcome.get("password")
        if password is None:
            return {"applied": False, "message": "Cancelled by user."}
        try:
            new_key = store.reissue_recovery_key(password)
        except FileNotFoundError:
            return {"applied": False, "error": "No vault found."}
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect password."}
        except (RuntimeError, VaultCorrupted, VaultTampered):
            return {"applied": False,
                    "error": "Recovery key operation failed -- vault restored to its previous state."}
        info = store.vault_info()
        slot_id = info.get("recovery_slot_id") or ""
        key_written = gui.show_recovery_key_dialog(new_key, slot_id)
        if not key_written:
            return {
                "applied": True,
                "action": action,
                "warning": (
                    "Recovery key issued but the display was dismissed before confirming -- "
                    "the new key is unrecoverable. Use manage_vault to issue a replacement."
                ),
            }
        return {"applied": True, "action": action,
                "message": "Recovery key issued successfully."}

    # ------------------------------------------------------------------ #
    # upgrade_v2                                                          #
    # ------------------------------------------------------------------ #
    if action == "upgrade_v2":
        password = outcome.get("password")
        recovery = bool(outcome.get("recovery", False))
        if password is None:
            return {"applied": False, "message": "Cancelled by user."}
        try:
            new_key = store.upgrade_to_v2(password, recovery=recovery)
        except FileNotFoundError:
            return {"applied": False, "error": "No vault found."}
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect password."}
        except (RuntimeError, VaultCorrupted, VaultTampered):
            return {"applied": False,
                    "error": "Upgrade to v2 failed -- vault restored to its previous state."}
        if new_key is not None:
            info = store.vault_info()
            slot_id = info.get("recovery_slot_id") or ""
            key_written = gui.show_recovery_key_dialog(new_key, slot_id)
            if not key_written:
                return {
                    "applied": True,
                    "action": "upgrade_v2",
                    "warning": (
                        "Vault upgraded to v2 format successfully. "
                        "The recovery key display was dismissed before confirming -- "
                        "the new recovery key is unrecoverable. "
                        "Use manage_vault to issue a replacement recovery key."
                    ),
                }
        return {"applied": True, "action": "upgrade_v2",
                "message": "Vault upgraded to v2 format successfully."}

    # ------------------------------------------------------------------ #
    # always_allow_list / always_allow_remove                             #
    # Entries live inside the vault body, so both need the master         #
    # password; the listing carries no snapshot, URL or value.            #
    # ------------------------------------------------------------------ #
    if action in ("always_allow_list", "always_allow_remove"):
        password = outcome.get("password")
        if password is None:
            return {"applied": False, "message": "Cancelled by user."}
        entry_id = outcome.get("entry_id")
        if action == "always_allow_remove":
            entry_id = entry_id.strip() if isinstance(entry_id, str) else ""
            if not entry_id:
                return {"applied": False, "error": "No always-allow entry id was given."}
        try:
            if action == "always_allow_list":
                entries = allowlist.list_entries(password)
            else:
                removed = allowlist.remove_entry(password, entry_id)
        except FileNotFoundError:
            return {"applied": False, "error": "No vault found."}
        except TooManyAttempts as e:
            return {"applied": False, "error": str(e)}
        except WrongPassword:
            return {"applied": False, "error": "Incorrect master password."}
        except (OSError, ValueError, RuntimeError, VaultCorrupted, VaultTampered) as e:
            return {"applied": False, "error": str(e)}
        if action == "always_allow_list":
            return {"applied": True, "action": action, "entries": entries,
                    "message": (f"{len(entries)} always-allow entr"
                                f"{'y' if len(entries) == 1 else 'ies'}."
                                if entries else "No always-allow entries.")}
        # Whatever the vault says, make sure nothing stays armed in memory.
        trust.disarm((allowlist.TRUST_KEY_TAG, entry_id))
        if not removed:
            return {"applied": False, "action": action,
                    "error": f"No always-allow entry with id {entry_id!r}."}
        return {"applied": True, "action": action,
                "message": f"Always-allow entry {entry_id} removed."}

    return {"applied": False, "error": f"Unrecognised action from vault management dialog."}


@mcp.tool()
def manage_vault() -> dict:
    """Open the vault management dialog for password changes, recovery key
    setup and reissue, v1-to-v2 format upgrades, and listing or removing
    always-allow entries. All sensitive input
    (passwords, recovery keys) is collected exclusively through native
    dialogs; nothing is returned to the agent. A cancelled dialog is a
    clean no-op.

    Actions the human can choose:
      change_password  -- change the master password; on v2 vaults with a
                          recovery slot the data key is rotated and a new
                          recovery key is shown in a separate native dialog.
      setup_recovery   -- add a recovery slot to a v2 vault that has none.
      reissue_recovery -- replace an existing recovery key (e.g. after it
                          was lost or potentially compromised).
      upgrade_v2       -- upgrade a v1 vault to the v2 AES-256-GCM/scrypt
                          format. It does NOT add a recovery key; run
                          setup_recovery afterwards for that. Two explicit
                          steps, each with its own consent dialog, rather
                          than one that quietly does two things.
      always_allow_list   -- list the always-allow entries (id, kind, cwd,
                          shape, label, armed, reason) in this tool's result;
                          never snapshots or values.
      always_allow_remove -- remove one always-allow entry by id.

    Recovery keys are displayed in a dedicated write-it-down dialog and
    never appear in this tool's result. If the human closes that dialog
    before confirming, the result says so explicitly -- the credential
    change already occurred and is permanent."""
    return _manage_vault_impl()


def _recover_vault_impl() -> dict:
    """Drive gui.recover_dialog() -> store.recover_with_recovery_key().

    Without this the recovery key is decorative: every other entry point
    needs the master password, so a human who has actually forgotten it --
    the one situation the paper key exists for -- would have no way to use
    it. That is why this is a separate tool rather than an action inside
    manage_vault, whose other actions all authenticate with the password.
    """
    if not store.vault_exists():
        return {"applied": False, "error": "No vault found. Nothing to recover."}
    outcome = gui.recover_dialog()
    rk_text = outcome.get("recovery_key")
    new_password = outcome.get("new_password")
    if not rk_text or not new_password:
        return {"applied": False, "message": "Cancelled by user."}
    try:
        new_key = store.recover_with_recovery_key(rk_text, new_password)
    except TooManyAttempts as e:
        return {"applied": False, "error": str(e)}
    except MalformedRecoveryKey:
        # Checksum caught it before any unwrap -- almost always a typo.
        return {"applied": False,
                "error": "That recovery key looks mistyped (its checksum does "
                         "not match). Check it against your printed copy."}
    except WrongRecoveryKey:
        return {"applied": False,
                "error": "That recovery key is not valid for this vault. If the "
                         "password was changed since it was printed, the old key "
                         "was invalidated and this printout is stale."}
    except NoRecoverySlot:
        return {"applied": False,
                "error": "This vault has no recovery key configured, so it cannot "
                         "be recovered without the master password."}
    except (VaultCorrupted, VaultTampered):
        return {"applied": False,
                "error": "The vault file is damaged or has been tampered with. "
                         "Restore vault.enc from a backup."}
    except RuntimeError:
        return {"applied": False,
                "error": "Recovery failed -- the vault has been restored to its "
                         "previous state. Nothing was changed."}
    # Recovery keeps the key the human just supplied, so there is normally
    # nothing new to display -- their printout still works. The branch stays
    # because store may still hand back a key in future variants, and a key
    # returned but never shown would be a silently dead recovery path.
    if new_key:
        info = store.vault_info()
        shown = gui.show_recovery_key_dialog(new_key, info.get("recovery_slot_id", ""))
        if not shown:
            return {"applied": True,
                    "warning": "Access was recovered and the new master password is "
                               "set, but a replacement recovery key was issued and "
                               "not confirmed, and cannot be shown again. Run "
                               "manage_vault and choose reissue_recovery to get a "
                               "usable one."}
    return {"applied": True,
            "message": "Access recovered and a new master password set. Your "
                       "existing recovery key still works -- keep the printout."}


@mcp.tool()
def recover_vault() -> dict:
    """Regain access to the vault using the printed paper recovery key, when
    the master password has been forgotten. Opens a dedicated native dialog
    that collects the recovery key and a new master password; neither is ever
    passed through this tool.

    This is the only entry point that does not require the existing master
    password -- every other operation authenticates with it, which is exactly
    why a forgotten password would otherwise be unrecoverable.

    Never ask the user to type or paste their recovery key into the chat. It
    is a second full-power credential for the whole vault; the native dialog
    is the only correct channel.

    The recovery key survives being used: the data key is rotated, but the
    recovery slot is re-wrapped with the same key, so the human's printout
    stays valid and no new ceremony is required. If they believe the key was
    observed while they typed it, manage_vault can reissue deliberately."""
    return _recover_vault_impl()


def _cleanup_restored(paths: list) -> list:
    """Shred every restored plaintext. Returns the ones that survived.

    Only ever called with paths this run created -- see where restored_paths
    is built. secure_delete never raises, so this is safe in a finally block
    and on every error path.
    """
    survivors = []
    for path in paths:
        try:
            if not store.secure_delete(path):
                survivors.append(path)
        except OSError:
            survivors.append(path)
    return survivors


class _Terminated(Exception):
    pass


def _on_sigterm(signum, frame):
    raise _Terminated()


def _resolve_materialize_path(materialize: str, cwd: Optional[str]) -> Path:
    base = (Path(cwd) if cwd else Path.cwd()).resolve()
    # Both string checks run BEFORE resolve(), because resolving is itself the
    # dangerous step: a UNC path -- or a junction whose target is UNC -- makes
    # this process open SMB with the user's credentials, and a materialize
    # target is a file we are about to write REAL VALUES into. On Windows an
    # absolute segment wins the join, so a UNC `materialize` would escape the
    # containment check below by being resolved first.
    if store._looks_like_unc(materialize):
        raise ValueError(f"materialize path {materialize!r} is a UNC path -- refused. "
                         f"Real values must not be written to a network location.")
    candidate = base / materialize
    if _reparse_points_to_share(str(candidate)):
        raise ValueError(f"materialize path {materialize!r} is reached through a junction or "
                         f"symlink pointing at a network share -- refused.")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(
            f"materialize must resolve to a path inside cwd ({base}); got {resolved}, "
            f"which escapes it. Use a plain relative filename, not an absolute path or "
            f"one with '..' segments that climb above cwd."
        )
    # A mapped drive is the same exposure as a UNC path wearing a letter: the
    # real values cross the wire, and land wherever the server keeps them --
    # backups, snapshots, another machine's disk -- outside anything this tool
    # can clean up when the command exits.
    if _drive_is_remote(str(resolved)):
        raise ValueError(
            f"{resolved} is on a mapped network drive -- refused. materialize writes REAL "
            f"values to that path for the lifetime of the command, which would send them "
            f"over the network and leave them on the server's storage, where the unlink "
            f"on exit cannot reach any copy it has already made. Point materialize at a "
            f"local path, or run the command from a local checkout."
        )
    return resolved


def _resolve_restore_paths(files: list, cwd: Optional[str]) -> list:
    """Map each .levault path to where its plaintext will be written.

    Returns a list of (vault_path, restore_path) pairs.

    The restore name comes from the SIDECAR's own filename -- server.pem.levault
    restores as server.pem -- never from the name stored inside the ciphertext
    and never from files.json. Both of those are influenced by someone other
    than the person clicking Allow: the in-ciphertext name travels with a file
    that may have come from anywhere, and files.json is a plaintext file an
    agent can edit. Deriving from the sidecar name instead means there is no
    "..", no drive letter and no reserved device name to sanitise, because no
    attacker-supplied string ever reaches path construction.

    The file lands in `cwd` rather than beside the .levault, because `cwd` is
    where the command will actually look for it.

    Raises ValueError with a message written for a human.
    """
    base = (Path(cwd) if cwd else Path.cwd()).resolve()
    pairs, seen_restore = [], {}
    for raw in files:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("files must be a list of non-empty path strings.")
        try:
            vault_path = Path(raw)
            vault_path = (vault_path if vault_path.is_absolute() else base / vault_path).resolve()
        except OSError as exc:
            raise ValueError(f"Cannot resolve {raw}: {exc}") from None

        # check_output=False: this validates the .levault itself -- existence,
        # size, magic bytes, suffix -- and nothing about where the plaintext
        # goes. The default would check a path BESIDE the sidecar, which is
        # not where this writes (it writes into the command's cwd), so it
        # would both miss the path that matters and refuse over a leftover
        # file it was never going to touch. The real restore path is checked
        # below and again immediately before writing.
        info = store.precheck_decrypt(vault_path, check_output=False)
        name = store.derived_plaintext_path(info["vault_path"]).name
        restore_path = (base / name).resolve()

        if not restore_path.is_relative_to(base):
            raise ValueError(
                f"{name} would restore to {restore_path}, outside the command's "
                f"working directory ({base}). Refusing.")
        if restore_path.exists():
            # Never overwrite. Cleanup shreds every path this run wrote, so
            # overwriting here would mean irreversibly destroying a file the
            # user already had -- e.g. one they restored with decrypt_file
            # yesterday.
            raise ValueError(
                f"{restore_path} already exists -- refusing to overwrite it. A file "
                f"restored for a command is deleted when that command exits, so "
                f"overwriting yours would destroy it.")
        prior = seen_restore.get(restore_path)
        if prior is not None:
            raise ValueError(
                f"{Path(prior).name} and {info['vault_path'].name} would both "
                f"restore to {restore_path}. Rename one of them.")
        seen_restore[restore_path] = info["vault_path"]
        pairs.append((info["vault_path"], restore_path))
    return pairs


def _drive_is_remote(path_str: str) -> bool:
    """Windows: is this path on a mapped network drive? Resolving one goes
    over the wire. Never called with a UNC string (rejected earlier)."""
    if os.name != "nt":
        return False
    drive = os.path.splitdrive(path_str)[0]
    if not drive:
        return False
    try:
        import ctypes
        DRIVE_REMOTE = 4
        return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == DRIVE_REMOTE
    except Exception:  # noqa: BLE001
        return False


def _target_is_unc(target: str) -> bool:
    r"""Does this junction/symlink target point at a network share?

    Precise rather than a substring test, in both directions. A junction's
    target usually comes back in the NT namespace: `\??\C:\dir` for a local
    one and `\??\UNC\server\share` for a network one. Both begin with a
    backslash pair once normalised, so a plain "starts with two backslashes"
    test calls the LOCAL form a share -- and the `"UNC" in target[:8]`
    companion test it used to be paired with calls `C:\Uncommon` one too.
    Each error refuses a legitimate local junction, which is its own kind of
    wrong: a guard nobody can keep enabled protects nothing.
    """
    t = (target or "").replace("/", "\\")
    up = t.upper()
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if up.startswith(prefix):
            return up[len(prefix):].startswith("UNC\\")
    return t.startswith("\\\\")


def _reparse_points_to_share(path_str: str) -> bool:
    """Walk the UNRESOLVED path with lstat; a junction or symlink whose
    target is UNC would make Path.resolve() open the share before the
    post-resolve check could refuse it."""
    if os.name != "nt":
        return False
    parts = Path(path_str).parts
    probe = Path(parts[0]) if parts else None
    for part in parts[1:]:
        probe = probe / part
        try:
            st = os.lstat(probe)
        except OSError:
            return False
        if not getattr(st, "st_reparse_tag", 0):
            continue
        try:
            target = os.readlink(probe)
        except OSError:
            return True              # cannot inspect it -- refuse rather than guess
        if _target_is_unc(target):
            return True
    return False


MAX_TIMEOUT_SECONDS = 24 * 3600


def _to_text(data) -> str:
    """A captured stream as str (subprocess hands back bytes when no text mode
    was asked for, and on a timeout in either mode)."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


class _CappedRunResult(procs.RunResult):
    """RunResult from a capped capture: raw_truncated names the streams
    ("stdout"/"stderr") whose beginning was dropped to stay within the limit."""
    __slots__ = ("raw_truncated",)

    def __init__(self, returncode, stdout, stderr, timed_out, binding, raw_truncated=()):
        super().__init__(returncode, stdout, stderr, timed_out, binding)
        self.raw_truncated = tuple(raw_truncated)


def _run_capped(command: list, env: dict, cwd: Optional[str], timeout: Optional[float],
                stdin_bytes: Optional[bytes], limit: int) -> "_CappedRunResult":
    """Unbound foreground run that keeps only the last *limit* bytes of each
    output stream while the child runs (the rest is read and thrown away, so
    the child never blocks on a full pipe). On timeout the child AND everything
    it started are killed: a Job object (procs._windows_job, KILL_ON_JOB_CLOSE)
    on Windows, the process group the child leads on POSIX -- the same
    mechanism as vault_lib.profiles._common.run_probe. The same kill ends a
    descendant that still holds an output pipe after the child exited, so the
    call can never wait on it forever. On Windows the job is closed when the
    run ends, which also ends any other leftover descendant (as in a bound run)."""
    extra_popen = {} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(
        command, env=env, cwd=cwd, creationflags=procs.NO_WINDOW,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **extra_popen)
    job_terminate = close_job = None
    if os.name == "nt":
        try:
            assign, job_terminate, close_job, _job = procs._windows_job()
            if assign is None or not assign(int(proc._handle)):
                job_terminate = None
        except Exception:  # noqa: BLE001 -- ctypes trouble must not block a run
            job_terminate = None

    def _kill_tree() -> None:
        if job_terminate is not None:
            try:
                job_terminate()
            except Exception:  # noqa: BLE001
                pass
        elif os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    dropped = {"stdout": False, "stderr": False}

    def _drain(name: str, pipe) -> None:
        buf = buffers[name]
        try:
            while True:
                chunk = pipe.read1(65536) if hasattr(pipe, "read1") else pipe.read(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 2 * limit:
                    del buf[:len(buf) - limit]
                    dropped[name] = True
        except (OSError, ValueError):
            pass

    def _feed() -> None:
        try:
            proc.stdin.write(stdin_bytes)
        except (OSError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass

    threads = [threading.Thread(target=_drain, args=("stdout", proc.stdout), daemon=True),
               threading.Thread(target=_drain, args=("stderr", proc.stderr), daemon=True)]
    if stdin_bytes is not None:
        threads.append(threading.Thread(target=_feed, daemon=True))
    for t in threads:
        t.start()
    timed_out = False
    try:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree()
            proc.wait()
        except BaseException:
            _kill_tree()
            proc.wait()
            raise
        # The readers normally end at once (the pipes closed with the child).
        # One still alive means a descendant holds the pipe open: end the tree
        # and give them a moment, rather than blocking the server on it.
        deadline = time.monotonic() + (5.0 if timed_out else 2.0)
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        if not timed_out and any(t.is_alive() for t in threads):
            _kill_tree()
            deadline = time.monotonic() + 3.0
            for t in threads:
                t.join(max(0.0, deadline - time.monotonic()))
    finally:
        if close_job is not None:
            try:
                close_job()
            except Exception:  # noqa: BLE001
                pass
    out = {}
    for name, buf in buffers.items():
        if len(buf) > limit:
            del buf[:len(buf) - limit]
            dropped[name] = True
        out[name] = bytes(buf).decode("utf-8", errors="replace")
    return _CappedRunResult(None if timed_out else proc.returncode, out["stdout"], out["stderr"],
                            timed_out, "none", [n for n in ("stdout", "stderr") if dropped[n]])


def _run_command(command: list, env: dict, cwd: Optional[str],
                 timeout: Optional[float], bind: bool = True,
                 on_start=None, stdin_bytes: Optional[bytes] = None,
                 capture_limit: Optional[int] = None) -> procs.RunResult:
    """The one place a foreground command is executed. A seam for tests, and
    the point where the child is bound to this server's lifetime.

    bind=False keeps 1.6.0 behaviour for a plain injection run: its
    descendants may outlive it (a script that starts a daemon and exits).
    Binding is for runs that put real values on disk, where "the command
    exited" must mean nothing of it is still reading them.

    stdin_bytes (always-allow runs only: a profile's Verdict.stdin) is written
    to the child's stdin instead of closing it. Such runs never write values
    to disk, so they are never bound.

    capture_limit (auto-allowed runs only) bounds the raw capture per stream;
    see _run_capped. Also unbound-only.

    Which runs kill the whole process tree on a timeout: bound runs
    (procs.run_bound), capture_limit runs and stdin_bytes runs (_run_capped).
    Only the plain unbound run (no stdin_bytes, no capture_limit) uses
    subprocess.run, which kills just the direct child -- see _kills_tree."""
    if capture_limit is not None:
        if bind:
            raise ValueError("capture_limit is only supported for unbound runs")
        return _run_capped(command, env, cwd, timeout, stdin_bytes, capture_limit)
    if stdin_bytes is not None:
        if bind:
            raise ValueError("stdin_bytes is only supported for unbound runs")
        # Same tree-killing runner as the capped path, with no cap: a timeout
        # must end what the command started, not only the direct child.
        return _run_capped(command, env, cwd, timeout, stdin_bytes, sys.maxsize)
    if not bind:
        proc = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                              timeout=timeout, creationflags=procs.NO_WINDOW)
        return procs.RunResult(proc.returncode, proc.stdout, proc.stderr, False, "none")
    return procs.run_bound(command, env, cwd, timeout, on_start=on_start)


def _kills_tree(bind: bool, capture_limit: Optional[int], stdin_bytes: Optional[bytes]) -> bool:
    """Whether _run_command ends the command's whole process tree on a timeout
    (true for every path except the plain unbound subprocess.run one, which
    kills only the direct child). Keep in step with _run_command."""
    return bool(bind) or capture_limit is not None or stdin_bytes is not None


MAX_READS_LIMIT = 1000

# How much of each stream run_with_env returns inline. The rest stays
# searchable through read_run_output.
DEFAULT_TAIL_CHARS = 4000
MAX_TAIL_CHARS = 200_000


def _tail(text: str, n: int) -> str:
    # text[-0:] is the whole string, which is the opposite of what 0 asks for.
    return text[-n:] if n > 0 else ""


def _stream_info(text: str, tail_chars: int) -> dict:
    return {"chars": len(text), "lines": runstore.count_lines(text),
            "truncated": len(text) > tail_chars}


def _verdict_cleanup_paths(verdict) -> list:
    """Paths a profile's verdict wants deleted after the run (kubectl's per-run
    cache dir). Read generically: profiles without the attribute have none."""
    paths = getattr(verdict, "cleanup_paths", None) or ()
    return [str(x) for x in paths if x]


def _remove_paths(paths) -> None:
    for path in paths:
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass


def _always_allow_arm_report() -> Optional[str]:
    """Plain text for the unlock dialog: what the latest always-allow arming
    pass armed or could not arm, plus any rollback warning. None when there is
    nothing to say. Names and reasons only -- never a value."""
    lines = []
    try:
        warning = allowlist.rollback_warning()
        report = allowlist.last_arm_report()
    except Exception:  # noqa: BLE001 -- a report must never block a run
        return None

    def one_line(value) -> str:
        # Labels and reasons derive from the command and its directory, which
        # the agent influences: a line break inside one must never become an
        # extra status line the human reads as a separate verdict.
        return " ".join(str(value).splitlines())

    if warning:
        lines.append(f"Warning: {one_line(warning)}")
    for item in report.get("armed", []):
        lines.append(f"Always-allow armed: {one_line(item.get('label'))}")
    for item in report.get("disarmed", []):
        lines.append(f"Always-allow NOT armed: {one_line(item.get('label'))} -- "
                     f"{one_line(item.get('reason'))}")
    for note in report.get("notes", []):
        lines.append(one_line(note))
    return "\n".join(lines) if lines else None


def _run_with_env_impl(command: list, materialize: Optional[str], background: bool,
                        cwd: Optional[str], only_vars: Optional[list] = None,
                        files: Optional[list] = None,
                        timeout: Optional[int] = None,
                        max_reads: Optional[int] = None,
                        all_vars: bool = False,
                        tail_chars: int = DEFAULT_TAIL_CHARS) -> dict:
    return _with_swap_recovery(
        lambda: _run_with_env_core(command, materialize, background, cwd, only_vars, files,
                                   timeout, max_reads, all_vars, tail_chars))


def _run_with_env_core(command: list, materialize: Optional[str], background: bool,
                        cwd: Optional[str], only_vars: Optional[list] = None,
                        files: Optional[list] = None,
                        timeout: Optional[int] = None,
                        max_reads: Optional[int] = None,
                        all_vars: bool = False,
                        tail_chars: int = DEFAULT_TAIL_CHARS) -> dict:
    if not command or not all(isinstance(c, str) for c in command):
        return {"error": "command must be a non-empty list of strings."}
    # Scope is explicit: a call must name the variables it needs, or say in so
    # many words that it wants the whole vault. Checked before anything else
    # can open a dialog. only_vars=None survives past this point only when
    # all_vars=True, so it still means "whole vault" everywhere below (the
    # trust signature included).
    if not isinstance(all_vars, bool):
        return {"error": "all_vars must be true or false."}
    if all_vars and only_vars is not None:
        return {"error": "Pass either only_vars (inject just those variables) or "
                         "all_vars=True (inject the whole vault), not both."}
    if only_vars is None and not all_vars:
        return {"error": "run_with_env now requires a scope: pass only_vars=[...] naming the "
                         "variables this command needs (see vault_status for the names), or "
                         "all_vars=True to inject the whole vault. Prefer only_vars."}
    if isinstance(only_vars, list) and not only_vars:
        return {"error": "only_vars is empty: that would inject nothing and still cost a "
                         "password prompt. Name the variables the command needs (see "
                         "vault_status for the names), or run it without the vault."}
    if isinstance(tail_chars, bool) or not isinstance(tail_chars, int) or \
            not 0 <= tail_chars <= MAX_TAIL_CHARS:
        return {"error": f"tail_chars must be an integer between 0 and {MAX_TAIL_CHARS}."}
    # Before anything resolves, stats or which()es these: a UNC string in
    # either would make this process open a network connection -- with the
    # user's credentials -- on an agent's say-so, before any dialog.
    if store._looks_like_unc(command[0]) or (cwd is not None and store._looks_like_unc(str(cwd))):
        return {"error": "UNC paths are refused for the command and cwd."}
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, int) or \
                not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            return {"error": f"timeout must be an integer number of seconds between 1 and "
                             f"{MAX_TIMEOUT_SECONDS}."}
        if background:
            return {"error": "timeout is not supported together with background=True (the "
                             "process is detached; nothing is left to enforce it)."}
    if max_reads is not None:
        if isinstance(max_reads, bool) or not isinstance(max_reads, int) or \
                not 1 <= max_reads <= MAX_READS_LIMIT:
            return {"error": f"max_reads must be an integer between 1 and {MAX_READS_LIMIT}."}
        if not materialize:
            return {"error": "max_reads only means something with materialize= -- there is "
                             "no file to revert otherwise."}
        if background:
            return {"error": "max_reads is not supported together with background=True in "
                             "this release."}
        reason = singleview.unsupported_reason()
        if reason:
            return {"error": reason}
    if background and materialize:
        return {"error": "materialize is not supported together with background=True "
                          "(there's no reliable moment to clean the file up if the "
                          "process is left running)."}
    if background and files:
        # The highest-severity rule in this feature. A detached process has no
        # reliable moment at which the decrypted file can be removed, so a
        # private key would be left in the working directory indefinitely --
        # and unlike a materialized .env, nothing else would ever notice.
        return {"error": "files is not supported together with background=True "
                          "(there's no reliable moment to delete the decrypted "
                          "file if the process is left running, and it would be "
                          "left on disk indefinitely)."}
    if not store.vault_exists():
        return {"error": "No vault exists yet. Call add_secret first."}

    if only_vars is not None:
        try:
            known = set(store.load_index().keys())
        except (OSError, UnicodeDecodeError, ValueError) as e:
            return {"error": str(e)}
        unknown = [v for v in only_vars if v not in known]
        if unknown:
            return {"error": f"Unknown variable(s): {', '.join(unknown)}"}

    # Resolved against `cwd` (where the command will actually run and look
    # for it), not this server process's own cwd -- otherwise, run in the
    # exact pattern the docs show (a relative materialize path alongside a
    # cwd pointing at the user's project), the file lands in the wrong
    # directory and the child can't find it.
    # Containment is enforced: absolute paths and relative paths that climb
    # above cwd via '..' are rejected here, before the password dialog opens.
    # Also guards against OSError from resolving a genuinely unreachable/
    # unusual path (e.g. an unreachable UNC share), same as install_migrate.
    try:
        materialized_path = _resolve_materialize_path(materialize, cwd) if materialize else None
        if materialized_path is not None and materialized_path.exists():
            return {"error": f"{materialized_path} already exists -- refusing to overwrite it. "
                              f"Pick a path that doesn't exist yet."}
        # Resolved and validated before the dialog opens, so a doomed request
        # never puts a modal window in front of a human. Re-checked again
        # right before writing, because the dialog can sit open for minutes.
        file_pairs = _resolve_restore_paths(files, cwd) if files else []
    except (OSError, ValueError, VaultCorrupted, VaultTampered, UnicodeDecodeError) as e:
        return {"error": str(e)}
    if max_reads is not None and materialized_path is not None:
        # Prove -- before the dialog -- that this filesystem grants an oplock
        # with handle caching and holds a foreign open until we release, so
        # the dialog promises only what will hold. The target must not exist
        # yet, so the proof runs on a throwaway probe beside it.
        reason = singleview.self_test_for_new_file(str(materialized_path))
        if reason:
            return {"error": f"max_reads cannot be honoured for {materialized_path}: {reason}"}

    # Trust is scoped to this exact (command, cwd, only_vars, materialize,
    # background) shape AND the content of every file named directly on
    # the command line -- see vault_lib/trust.py. Everything it tracks
    # lives only in this server process's memory; it's forgotten the
    # moment the process exits, same as if the feature didn't exist.
    signature = trust.make_signature(command, cwd, only_vars, materialize, background,
                                      files, timeout=timeout, max_reads=max_reads)
    # Always-allow (plan 2.4.0): a persistent, vault-stored entry that a
    # profile verifies against this concrete request. Looked up before the
    # session trust cache, and only for requests allowlist.eligible() accepts
    # (never files, all_vars, background, materialize, max_reads, shells).
    aa_request = None
    aa_match = None
    aa_reason = None
    if not file_pairs:
        aa_eligible, _aa_why = allowlist.eligible(command, materialize, background, files,
                                                  max_reads, all_vars, only_vars, cwd)
        if aa_eligible:
            try:
                aa_request = profiles.Request(
                    tuple(command), allowlist.canonical_cwd(cwd or os.getcwd()),
                    tuple(only_vars), timeout)
                aa_match, aa_reason = allowlist.lookup(aa_request)
            except Exception as e:  # noqa: BLE001 -- fail closed to the dialog
                aa_match, aa_reason = None, f"always-allow lookup failed: {e}"
    if file_pairs:
        # A run that writes decrypted files to disk is NEVER auto-allowed and
        # never grants trust: a human sees the paths and approves every single
        # time. Injecting a token into an environment for 8 unattended hours is
        # one risk; writing a private key into a directory unattended is
        # another, and the trust feature was designed for the first.
        auto_ok, invalidated_reason = False, None
    elif aa_match is not None:
        auto_ok, invalidated_reason = False, None
    else:
        auto_ok, invalidated_reason = trust.check(signature, command, cwd)
        if aa_reason:
            # The always-allow entry drifted and was disarmed: say why in the
            # dialog and the result, ahead of any session-trust revocation.
            invalidated_reason = (f"{aa_reason} {invalidated_reason}"
                                  if invalidated_reason else aa_reason)
    trust_info = {}
    if aa_reason and aa_match is None:
        trust_info["invalidated_reason"] = aa_reason
    aa_strict = aa_match is not None
    # Per-run paths a profile created while verifying (lookup and recheck both
    # verify); deleted on every exit from here on.
    aa_cleanup = _verdict_cleanup_paths(aa_match.verdict) if aa_match is not None else []

    # trust.check()'s own contract guarantees cached_secrets(signature) is
    # non-None whenever it returns auto_ok=True, so this should be
    # unreachable in practice -- kept as a cheap belt-and-suspenders
    # fallback to the real dialog rather than trusting that invariant to
    # hold forever (e.g. across a future change to how/whether tool calls
    # can overlap). On this path, raw_secrets is already the subset scoped
    # to this signature's own only_vars, not the full vault -- see
    # trust.cache_secrets()'s caller below, which filters before caching.
    raw_secrets = trust.cached_secrets(signature) if auto_ok else None

    if aa_match is not None:
        raw_secrets = aa_match.secrets
        trust_info["auto_allowed"] = True
        trust_info["always_allow"] = aa_match.id
        trust_info["trust_note"] = (
            f"Auto-allowed by always-allow entry '{aa_match.label}' ({aa_match.id})")
    elif auto_ok and raw_secrets is not None:
        trust_info["auto_allowed"] = True
        # Show the remaining TTL so the human knows how long auto-allow lasts.
        _entry = trust._trusted.get(signature, {})
        if _entry:
            _elapsed = time.time() - _entry.get("granted_wall", time.time())
            _remaining = max(0, trust._TRUST_TTL_SECONDS - int(_elapsed))
            if _remaining >= 3600:
                _remaining_str = f"{_remaining // 3600} hours"
            elif _remaining >= 60:
                _remaining_str = f"{_remaining // 60} minutes"
            else:
                _remaining_str = "less than a minute"
            _ttl_part = f" ({_remaining_str} remaining)"
        else:
            _ttl_part = ""
        trust_info["trust_note"] = (
            f"Auto-allowed: this exact command is trusted for this session{_ttl_part} "
            f"and its referenced file(s) are unchanged -- no password prompt was shown.")
    else:
        # Hashed *before* the dialog opens, not after Allow is clicked --
        # the dialog can sit open for minutes while a human reads it, and
        # trust must bind to the file content they actually reviewed, not
        # to whatever it happens to contain the instant they click Allow.
        pre_hashes = trust.referenced_file_hashes(command, cwd)
        # Determine what the trust grant will actually monitor, so we can
        # warn the human BEFORE they tick the trust checkbox -- not only in
        # the tool result they see afterward.
        monitored_paths, is_executable_only = trust.monitored_summary(command, cwd)
        _dialog_parts = []
        if invalidated_reason:
            _dialog_parts.append(invalidated_reason)
        # Warn only where a human could plausibly believe in coverage that is
        # not there. Executable-only monitoring is unremarkable for `ls`,
        # `git push` or `python -c "..."` -- alarming on every one of those
        # teaches people to dismiss the warning, and then it is gone for the
        # case it exists for. trust.should_warn_executable_only() draws that
        # line; the grant note below still enumerates unconditionally, so the
        # quieter dialog never costs accuracy.
        if trust.should_warn_executable_only(command, cwd):
            _dialog_parts.append(
                "Note: this command reads configuration from its working "
                "directory, but no such config file was found to monitor. Only "
                "the executable binary is drift-monitored, so changes to "
                "whatever config it does load will NOT revoke trust.")
        dialog_trust_note = " ".join(_dialog_parts) if _dialog_parts else None
        # The "Always allow" checkbox: offered only for an eligible request, no
        # files, and outside the denial cool-down. The offer is built (profile
        # snapshot taken) BEFORE the dialog opens, like pre_hashes above.
        aa_offer = None
        if aa_request is not None and not file_pairs \
                and allowlist.cooldown_remaining(aa_request) <= 0:
            try:
                aa_offer = allowlist.make_offer(aa_request)
            except Exception:  # noqa: BLE001 -- no offer, the normal dialog still works
                aa_offer = None
        hide_trust = bool(trust.persistent_or_8h_refusal(command, cwd))
        outcome = gui.unlock_for_run_dialog(subprocess.list2cmdline(command),
                                             materialize_path=str(materialized_path)
                                             if materialized_path else None,
                                             only_vars=only_vars,
                                             trust_note=dialog_trust_note,
                                             files=file_pairs or None,
                                             timeout=timeout, max_reads=max_reads,
                                             always_allow=aa_offer,
                                             hide_trust=hide_trust,
                                             arm_report=_always_allow_arm_report())
        raw_secrets = outcome["secrets"]
        if raw_secrets is None:
            if aa_request is not None:
                allowlist.record_denial(aa_request)
            result = {"applied": False, "message": "Denied by user."}
            if invalidated_reason:
                result["trust_note"] = invalidated_reason
            return result
        aa_created = bool(outcome.get("always_allow")) and aa_offer is not None
        # A failed save of the always-allow entry never blocks the approved run,
        # but the caller must be told it was NOT created. The message is built
        # by the dialog from the exception text only: no password, no values.
        aa_error = outcome.get("always_allow_error")
        if aa_error and aa_offer is not None:
            trust_info["always_allow_error"] = str(aa_error)[:300]
        if aa_created:
            # Always-allow wins over the 8 h trust when both were ticked: the
            # entry is the stronger, longer-lived grant, and the dialog only
            # commits one of them.
            granted_note = (
                f"Always-allow entry '{aa_offer.label}' created: identical runs are "
                f"auto-allowed with no password prompt, even after a restart, for as "
                f"long as what it pinned is unchanged. Remove it with manage_vault "
                f"(always_allow_remove).")
            trust_info["trust_note"] = (f"{invalidated_reason} {granted_note}"
                                         if invalidated_reason else granted_note)
        elif outcome["trust"] and not file_pairs:
            # The dialog hides the checkbox for a files run, so this should
            # already be False. Belt to that braces: a grant here would let a
            # later identical call decrypt a private key with no human present.
            trust.trust(signature, pre_hashes)
            # Cache only what was actually approved for this signature, not
            # the whole vault raw_secrets holds -- a command trusted with a
            # narrow only_vars must not leave every other secret resident
            # in memory for the rest of the session. Mirrors the filter
            # applied below to what's actually injected.
            to_cache = ({k: v for k, v in raw_secrets.items() if k in only_vars}
                        if only_vars is not None else raw_secrets)
            trust.cache_secrets(signature, to_cache)
            # Derive the TTL string from the constant so it can't drift.
            _ttl_hours = trust._TRUST_TTL_SECONDS // 3600
            if is_executable_only:
                # Only the binary is tracked. State that plainly either way --
                # the enumeration is unconditional so the note never overstates
                # coverage -- but reserve the pointed warning for tools that
                # actually read config, so it stays worth reading.
                _exe_path = monitored_paths[0]
                _coverage = (
                    "This command reads configuration from its working "
                    "directory, but no such config file was found to monitor, "
                    "so changes to whatever it does load will NOT revoke trust."
                    if trust.should_warn_executable_only(command, cwd) else
                    "Nothing else on this command line resolved to a file, so "
                    "nothing else is monitored.")
                granted_note = (
                    f"This exact command is now trusted for the next "
                    f"{_ttl_hours} hours (or until this server restarts, "
                    f"whichever comes first). "
                    f"Future identical runs auto-allow with no password prompt. "
                    f"Drift-monitored: only the executable ({_exe_path}). "
                    f"{_coverage}")
            elif monitored_paths:
                _path_list = ", ".join(monitored_paths)
                granted_note = (
                    f"This exact command is now trusted for the next "
                    f"{_ttl_hours} hours (or until this server restarts, "
                    f"whichever comes first). "
                    f"Future identical runs auto-allow with no password prompt, "
                    f"as long as its referenced file(s) stay unchanged. "
                    f"Drift-monitored: {_path_list}.")
            else:
                # Unresolvable argv0 and no file args -- nothing monitored;
                # unmonitored_file_warning below will cover the disclosure.
                granted_note = (
                    f"This exact command is now trusted for the next "
                    f"{_ttl_hours} hours (or until this server restarts, "
                    f"whichever comes first). "
                    f"Future identical runs auto-allow with no password prompt.")
            warning = trust.unmonitored_file_warning(command, cwd)
            if warning:
                granted_note += " " + warning
            # Prepend, not replace: if a *previous* trust grant for this same
            # signature was just revoked (invalidated_reason set), that fact
            # would otherwise only ever have been shown inside the now-closed
            # dialog -- silently dropped from the tool result the caller
            # actually sees, defeating "a message still shows" for the one
            # case (drift -> re-approval) where it matters most.
            trust_info["trust_note"] = (f"{invalidated_reason} {granted_note}"
                                         if invalidated_reason else granted_note)
        elif invalidated_reason:
            trust_info["trust_note"] = invalidated_reason

    # Single-view watchers, keyed by path. Created after the unlock, torn down
    # in the finally; their early restores are folded into the outcome.
    watchers = {}
    _restore_lock = threading.Lock()

    def _materialize_early_restore(w):
        # The materialize file has no placeholders to go back to: empty it
        # through the handle now; the finally unlinks it.
        w.write_all(b"")
        return {"restored": [], "conflicts": [], "verify_failed": [], "error": None}

    def _finish(result: dict) -> dict:
        result.update(trust_info)
        return result

    secrets = raw_secrets
    if only_vars is not None:
        secrets = {k: v for k, v in secrets.items() if k in only_vars}

    # Defence in depth. The vault body holds reserved keys alongside user
    # variables -- the file master key lives there -- and load_secrets filters
    # them out, so in a correct build none can be here. But this is the exact
    # spot where being wrong is worst: Windows CreateProcess will happily hand
    # a "#"-prefixed name to the child, so a filtering bug upstream would ship
    # the key that decrypts every vaulted file into an arbitrary subprocess's
    # environment. Refuse to launch instead.
    leaked = sorted(k for k in secrets if store.is_reserved_key(k))
    if leaked:
        if aa_match is not None:
            aa_match.close()
            _remove_paths(aa_cleanup)
        return _finish({"applied": False,
                "error": f"Internal error: reserved vault key(s) {leaked} reached the "
                          f"environment builder -- refusing to launch the command."})

    env = os.environ.copy()
    env.update(secrets)

    if materialized_path is not None:
        if materialized_path.exists():
            # Re-check right before writing, not just at the top of this
            # function -- the password dialog above can sit open for
            # minutes, and the earlier check is only a fast-fail UX
            # nicety, not the actual guard against clobbering a file that
            # came into existence while it was open.
            return _finish({"applied": False,
                    "error": f"{materialized_path} came into existence while the password "
                              f"prompt was open -- refusing to overwrite it. Try again."})
        try:
            if max_reads is not None:
                text = store.render_env_text(secrets).encode("utf-8")
                w = singleview.Watcher(materialized_path, max_reads, _materialize_early_restore,
                                       _restore_lock,
                                       deadline=time.time() + timeout if timeout else None)
                w.open(create=True)
                try:
                    w.write_all(text)
                    w.arm()
                    w.settle()
                except Exception:
                    w.close()
                    raise
                watchers[str(materialized_path)] = w
            else:
                store.write_materialized_env(materialized_path, secrets)
        except (OSError, ValueError) as e:
            if str(materialized_path) in watchers:
                watchers.pop(str(materialized_path)).close()
                materialized_path.unlink(missing_ok=True)
            return _finish({"applied": False, "error": str(e)})

    # Only paths this run actually created go in here, and cleanup touches
    # nothing else. Shredding a path we merely found would destroy a file the
    # user already had.
    restored_paths = []
    if file_pairs:
        decrypted = outcome.get("files") if not auto_ok else None
        if not decrypted:
            return _finish({"applied": False,
                    "error": "Internal error: the unlock dialog approved a run with "
                              "files= but returned no decrypted contents."})
        for vault_path, restore_path in file_pairs:
            payload = decrypted.get(str(vault_path))
            if payload is None:
                _cleanup_restored(restored_paths)
                return _finish({"applied": False,
                        "error": f"Internal error: {vault_path} was approved but not "
                                  f"decrypted."})
            if restore_path.exists():
                # Re-check right before writing: the password dialog can sit
                # open for minutes, and the earlier check was a fast-fail UX
                # nicety, not the guard.
                _cleanup_restored(restored_paths)
                return _finish({"applied": False,
                        "error": f"{restore_path} came into existence while the password "
                                  f"prompt was open -- refusing to overwrite it. Try again."})
            try:
                store.write_restored_file(restore_path, payload["bytes"], payload)
            except (OSError, ValueError) as e:
                _cleanup_restored(restored_paths)
                return _finish({"applied": False,
                        "error": f"Could not restore {restore_path}: {e}"})
            restored_paths.append(restore_path)

    redact_map = dict(raw_secrets)

    if background:
        # Under the stdio transport this process's own stdout/stdin ARE the
        # JSON-RPC channel -- a detached child inheriting them would either
        # inject its own output as garbage into the protocol stream (and
        # corrupt/kill the session for as long as it runs) or steal bytes
        # meant for this server. Redirect explicitly; never inherit.
        _cleanup_stale_run_logs()
        log_fd, log_path = tempfile.mkstemp(suffix=".log", prefix="llm-env-vault-run-")
        os.close(log_fd)
        try:
            with open(log_path, "wb") as log_file:
                proc = subprocess.Popen(command, env=env, cwd=cwd,
                                         stdin=subprocess.DEVNULL,
                                         stdout=log_file, stderr=subprocess.STDOUT,
                                         creationflags=procs.NO_WINDOW)
        except OSError as e:
            return _finish({"applied": False, "error": f"could not start {command[0]!r}: {e}"})
        # Redact the log in place once the process exits. Best-effort: a
        # watcher daemon thread waits on the process and then rewrites the
        # log with [REDACTED:NAME] markers. If the server dies before the
        # process does, the thread dies too and the log stays unredacted --
        # that is why we disclose the unredacted-while-running caveat below.
        # We do NOT pipe the child's output through the server to redact live:
        # if the server dies, the pipe fills and the child hangs.
        _secrets_for_redaction = dict(raw_secrets)
        # Reserved now so the caller has an id to ask about; filled in by the
        # thread below, and ONLY with the text it has just redacted. Until then
        # read_run_output says the run is still in progress.
        bg_run_id = _RUN_OUTPUT.reserve()

        def _log_redactor_thread() -> None:
            try:
                proc.wait()
            except Exception:
                _RUN_OUTPUT.abandon(bg_run_id)
                return
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as _f:
                    _content = _f.read()
                _redacted, _ = _redact_secrets(_content, _secrets_for_redaction)
                with open(log_path, "w", encoding="utf-8") as _f:
                    _f.write(_redacted)
            except OSError:
                # best-effort: swallow all IO failures silently. If the log
                # could not be rewritten it may still hold real values, so
                # nothing from it is registered either.
                _RUN_OUTPUT.abandon(bg_run_id)
                return
            # The child's stderr was redirected into the same log, so a
            # background run has one merged stream, reported as stdout.
            if not _RUN_OUTPUT.fulfil(bg_run_id, {"stdout": _redacted, "stderr": ""}):
                # The reservation was pushed out of the store while the process
                # ran (too many background runs pending at once). The redacted
                # text is simply dropped -- read_run_output reports the run as
                # unknown -- and only the run_id is logged, never any output.
                print(f"llm-env-vault: background run {bg_run_id} output not kept "
                      f"for read_run_output (its slot was evicted).", file=sys.stderr)

        threading.Thread(target=_log_redactor_thread, daemon=True).start()
        return _finish({"applied": True, "started": True, "pid": proc.pid, "log_file": log_path,
                "run_id": bg_run_id,
                "note": "Running detached. The log file is unredacted while the process is "
                        "still running -- secret values may appear in it until the process "
                        "exits and the server redacts it in place. Once it has exited, "
                        "read_run_output(run_id) searches the redacted log (stdout and stderr "
                        "are merged into 'stdout' for a background run). "
                        "Use the OS/your own process manager to stop it later."})

    spawn_command = command
    spawn_stdin = None
    spawn_timeout = timeout
    aa_stderr_markers = ()
    if aa_match is not None:
        # Verify once more immediately before the process is created: the file
        # hashes, config and vault fingerprint may have moved since lookup.
        recheck = aa_match.recheck()
        aa_cleanup += _verdict_cleanup_paths(recheck)
        if not recheck.ok or not recheck.argv:
            aa_match.close()
            _remove_paths(aa_cleanup)
            why = recheck.reason or "the profile returned no command to run"
            return _finish({"applied": False,
                            "error": f"Always-allow entry '{aa_match.label}' no longer applies "
                                     f"and was disarmed: {why}. Nothing was run; call again "
                                     f"to be asked.",
                            "invalidated_reason": why})
        spawn_command = list(recheck.argv)
        spawn_stdin = recheck.stdin
        # Optional KubectlVerdict-style extras, read generically: a hard wall
        # clock (the effective timeout is the smaller of it and the caller's)
        # and stderr markers that turn a "successful" run into an error.
        wall_clock = getattr(recheck, "wall_clock", None)
        if isinstance(wall_clock, (int, float)) and not isinstance(wall_clock, bool) \
                and wall_clock > 0:
            spawn_timeout = wall_clock if timeout is None else min(timeout, wall_clock)
        aa_stderr_markers = tuple(getattr(recheck, "stderr_fatal_markers", None) or ())
        if recheck.env is None:
            env = os.environ.copy()
        elif recheck.replace_env:
            env = dict(recheck.env)
        else:
            env = os.environ.copy()
            env.update(recheck.env)
        # inject_secrets=False: the profile carries the values itself (docker's
        # compose model on stdin) or they must never reach this subcommand. The
        # output is still redacted against match.secrets (redact_map).
        if getattr(recheck, "inject_secrets", True) is not False:
            env.update(secrets)

    old_sigterm = None
    if materialized_path is not None or restored_paths:
        # `or restored_paths` is load-bearing: without it a SIGTERM during a
        # files-only run skips the handler entirely and leaves decrypted
        # private keys sitting in the working directory.
        try:
            old_sigterm = signal.signal(signal.SIGTERM, _on_sigterm)
        except (ValueError, OSError):
            pass

    cleanup_error = None
    survivors = []
    early = None
    _tree_kill = False
    try:
        try:
            # stdin=DEVNULL: under the stdio transport this process's own
            # stdin IS the JSON-RPC input pipe. Without this, a command
            # that reads stdin (an interactive prompt, a TTY attach) would
            # consume protocol bytes and/or block forever with the whole
            # server frozen behind it -- DEVNULL makes it fail fast on EOF
            # instead.
            if watchers:
                for w in watchers.values():
                    w.start()

            def _on_start(job_handle, _pid):
                for w in watchers.values():
                    w.set_job(job_handle)

            extra = {"stdin_bytes": spawn_stdin} if spawn_stdin is not None else {}
            if aa_strict:
                extra["capture_limit"] = STRICT_RAW_CAPTURE_BYTES
            _run_bound = bool(materialized_path is not None or restored_paths)
            _tree_kill = _kills_tree(_run_bound, extra.get("capture_limit"), spawn_stdin)
            proc = _run_command(spawn_command, env, cwd, spawn_timeout,
                                bind=_run_bound,
                                on_start=_on_start if watchers else None, **extra)
        except subprocess.TimeoutExpired as e:
            # Unbound plain run hit its timeout: subprocess.run already killed
            # the direct child (only it -- see _kills_tree). Report it the same
            # way a bound run does.
            proc = procs.RunResult(None, _to_text(e.stdout), _to_text(e.stderr), True, "none")
        except OSError as e:
            # Not returned from inside the try: the result must be built
            # AFTER the finally block below has cleaned the materialized
            # file up, or it could not report how that cleanup went.
            early = {"applied": False, "error": f"could not run {command[0]!r}: {e}"}
        except (KeyboardInterrupt, _Terminated):
            early = {"applied": False, "message": "Interrupted."}
    finally:
        if aa_match is not None:
            aa_match.close()
            _remove_paths(aa_cleanup)
        if old_sigterm is not None:
            signal.signal(signal.SIGTERM, old_sigterm)
        # Watchers first: stop, join OUTSIDE the restore lock (a watcher
        # mid-restore needs it), then fold whatever they already restored
        # into the records so the file-based restore below is skipped for
        # those files. A watcher that did not restore has released its
        # handle in its own finally, so the path-based restore can proceed.
        for w in watchers.values():
            w.stop()
        for w in watchers.values():
            if not w.join(5.0):
                # The thread still owns the handle; touching it from here
                # would race it. Leave it -- its own finally closes it -- and
                # let the restore below report the file it could not open;
                # the journal keeps the entry for the next recovery.
                w.error = (w.error or "") + " watcher thread did not stop within 5 s"
        # Each step here is independent -- a failure in one never skips
        # the next.
        if materialized_path is not None:
            try:
                materialized_path.unlink(missing_ok=True)
            except OSError as e:
                cleanup_error = str(e)
        survivors = _cleanup_restored(restored_paths)

    if early is not None:
        if cleanup_error:
            early["warning"] = (f"Could not delete {materialized_path}, it still contains "
                                f"real secret values -- remove it by hand: {cleanup_error}")
        if survivors:
            early["files_warning"] = (
                "Could not delete the following decrypted file(s) -- they still contain "
                "real secret contents, remove them by hand: "
                + ", ".join(str(p) for p in survivors))
        return _finish(early)

    # Redact BEFORE the tail_chars slice so a secret value that straddles the
    # cut point is still caught. The full output is redacted first, then
    # truncated -- the truncation can split a [REDACTED:NAME] marker but
    # cannot leave a raw secret value visible. The same redacted text (never
    # the raw output) is what read_run_output later searches.
    _stdout_full = proc.stdout or ""
    _stderr_full = proc.stderr or ""
    _raw_cut = tuple(getattr(proc, "raw_truncated", ()) or ())
    if _raw_cut:
        # The capture dropped the beginning of these streams, which can leave a
        # fragment of a value at the very start that no redaction pattern can
        # match: drop as many characters as the longest redactable form has.
        _lead = max((len(v) for val in redact_map.values()
                     if len(val) >= REDACT_MIN_VALUE_LEN for v in _strict_variants(val)),
                    default=0)
        if "stdout" in _raw_cut:
            _stdout_full = _stdout_full[_lead:]
        if "stderr" in _raw_cut:
            _stderr_full = _stderr_full[_lead:]
    # An always-allow run nobody watched gets the strict redactor (more
    # encodings, plus a per-stream size cap).
    _stdout_redacted, _stdout_skipped = _redact_secrets(_stdout_full, redact_map,
                                                        strict=aa_strict)
    _stderr_redacted, _stderr_skipped = _redact_secrets(_stderr_full, redact_map,
                                                        strict=aa_strict)
    _all_skipped = sorted(set(_stdout_skipped) | set(_stderr_skipped))
    _raw_note = (f"{STRICT_TRUNCATION_PREFIX}: this command was auto-allowed and printed more "
                 f"than {STRICT_RAW_CAPTURE_BYTES} bytes on this stream; only the end is kept]\n")
    if "stdout" in _raw_cut and not _stdout_redacted.startswith(STRICT_TRUNCATION_PREFIX):
        _stdout_redacted = _raw_note + _stdout_redacted
    if "stderr" in _raw_cut and not _stderr_redacted.startswith(STRICT_TRUNCATION_PREFIX):
        _stderr_redacted = _raw_note + _stderr_redacted
    _run_id = _RUN_OUTPUT.put({"stdout": _stdout_redacted, "stderr": _stderr_redacted})
    result = {
        "applied": True,
        "run_id": _run_id,
        "exit_code": proc.returncode,
        "stdout": _tail(_stdout_redacted, tail_chars),
        "stderr": _tail(_stderr_redacted, tail_chars),
        "streams": {
            "stdout": _stream_info(_stdout_redacted, tail_chars),
            "stderr": _stream_info(_stderr_redacted, tail_chars),
        },
    }
    if aa_strict and (_stdout_redacted.startswith(STRICT_TRUNCATION_PREFIX)
                      or _stderr_redacted.startswith(STRICT_TRUNCATION_PREFIX)):
        result["output_truncated"] = True
        result["truncation_note"] = (
            f"This command was auto-allowed by an always-allow entry, so each stream is "
            f"capped at {STRICT_OUTPUT_CAP_BYTES} bytes (the end is kept); the stream(s) "
            f"starting with '{STRICT_TRUNCATION_PREFIX}' were cut.")
    if len(_stdout_redacted) > runstore.MAX_STREAM_CHARS or \
            len(_stderr_redacted) > runstore.MAX_STREAM_CHARS:
        result["retention_note"] = (
            f"A stream longer than {runstore.MAX_STREAM_CHARS} characters is kept only as "
            f"its last {runstore.MAX_STREAM_CHARS} for read_run_output.")
    if watchers:
        result["single_read"] = {k: w.report() for k, w in watchers.items()}
        early = [k for k, w in watchers.items() if w.restored_early]
        if early:
            result["single_read_note"] = (
                f"Real values were reverted before the command exited for: {', '.join(early)}. "
                f"A read labelled 'unattributed' was too fast for the Restart Manager to name "
                f"the reader; it was counted because the command was running at that moment.")
        # No padded-tail note. The padding itself is NOT swap-only -- if a
        # memory-mapped view blocks SetEndOfFile, write_all pads the tail with
        # newlines, and for materialize that is precisely what overwrites the
        # real values when the file cannot be truncated. What is swap-only is
        # having anything to say about it afterwards: a swapped .env had to be
        # left byte-correct for its own project, whereas the materialize target
        # is unlinked regardless, and a failure to unlink is already reported
        # as files_warning/cleanup_error.
        after = {k: w.reads_after_restore for k, w in watchers.items() if w.reads_after_restore}
        if after:
            result["single_read_restored_early"] = after
            result["single_read_note"] = result.get("single_read_note", "") + (
                " Something opened the file AFTER it had reverted -- a consumer that reads more "
                "than max_reads times saw placeholders: " +
                ", ".join(f"{k} ({n} later read(s))" for k, n in after.items()) +
                ". Raise max_reads if that was the command.")
    if getattr(proc, "timed_out", False):
        result["timed_out"] = True
        _killed = ("its whole process tree" if _tree_kill else
                   "the command itself only -- a process it started may still be running")
        result["timeout_note"] = (
            f"The command was killed after {spawn_timeout} seconds ({_killed}) "
            f"and every real value was restored/removed. Pass a larger timeout= if it "
            f"legitimately needs longer.")
    if aa_stderr_markers:
        _stderr_low = _stderr_full.lower()
        _hit = [m for m in aa_stderr_markers if isinstance(m, str) and m and m.lower() in _stderr_low]
        if _hit:
            result["stderr_fatal"] = True
            result["error"] = (
                "The tool reported a condition on stderr that its always-allow profile "
                "treats as fatal (a safety policy may not have applied), so this run is "
                "an error even though it exited with code "
                f"{proc.returncode}: matched {_hit[0]!r}.")
    _binding = getattr(proc, "binding", None)
    if _binding and _binding != "job" and os.name == "nt":
        result["process_binding"] = (
            "Windows refused to place the command in a Job object, so a descendant it "
            "left running would not be terminated with it.")
    if _all_skipped:
        result["redaction_skipped"] = (
            f"These vault variables were NOT redacted from output because their "
            f"values are shorter than {REDACT_MIN_VALUE_LEN} characters: "
            + ", ".join(_all_skipped))
    if cleanup_error:
        result["warning"] = (f"Could not delete {materialized_path}, it still contains real "
                              f"secret values -- remove it by hand: {cleanup_error}")
    if survivors:
        # Name every one. These are decrypted private keys and certificates;
        # a silent leftover is not acceptable, and "some files" would leave the
        # user hunting.
        result["files_warning"] = (
            "Could not delete the following decrypted file(s) -- they still contain "
            "real secret contents, remove them by hand: "
            + ", ".join(str(p) for p in survivors))
    if restored_paths and not survivors:
        result["files_restored"] = len(restored_paths)
    return _finish(result)


@mcp.tool()
def run_with_env(command: list[str], materialize: Optional[str] = None,
                  background: bool = False, cwd: Optional[str] = None,
                  only_vars: Optional[list[str]] = None,
                  files: Optional[list[str]] = None,
                  timeout: Optional[int] = None,
                  max_reads: Optional[int] = None,
                  all_vars: bool = False,
                  tail_chars: int = 4000) -> dict:
    """Run a real command with the vault's real secret values injected as
    environment variables. Prompts once for the master password via a GUI
    (which also lists which variable names -- never values -- will be
    exposed) and never writes real values to disk unless materialize is
    given. Returns the command's exit code, run_id, and the last tail_chars
    characters of stdout and stderr, with every
    vault value -- plus its base64 and URL-encoded forms -- replaced by
    [REDACTED:VAR_NAME] before the result is handed back. That redaction is
    accident-prevention, not a boundary: values shorter than 8 characters
    are skipped (listed in redaction_skipped) because replacing them would
    shred unrelated output, and a command that transforms what it prints
    can still emit a real value. Two paths are deliberately not covered --
    a background run's log file is only redacted once the process exits,
    and a materialize target holds real values on disk by design.

    only_vars: REQUIRED unless all_vars=True. The vault variables to
    inject, by name (e.g. ["DATABASE_URL"]); nothing else is exposed to
    the command or anything it spawns. Unknown names are rejected before
    the password prompt opens. A call with neither only_vars nor
    all_vars=True is refused with an error naming both options. An empty
    list is refused too (it would inject nothing and still prompt).

    all_vars: pass True to inject the WHOLE vault (what omitting
    only_vars used to do). Mutually exclusive with only_vars. Use it only
    when the command really needs most variables: every unrelated secret
    is exposed to it and to anything it spawns.

    tail_chars: how many characters from the end of each of stdout and
    stderr to return inline (default 4000, 0 to 200000; anything else is
    rejected). Applied AFTER redaction. Each result also carries a run_id
    and, per stream, the total chars and lines and whether the inline text
    was truncated -- the full redacted output stays in this server's
    memory (last 20 runs, up to 10 MB per stream, never written to disk,
    lost on restart) and is searchable with read_run_output(run_id, ...).
    Not part of the trust signature. For background=True the result
    carries a run_id too, which read_run_output can use once the process
    has exited and the log has been redacted.

    materialize: path for a short-lived real .env file (mode 0600,
    unquoted -- matches `docker run --env-file` semantics exactly),
    resolved relative to `cwd` if given and enforced to remain inside it
    (absolute paths and relative paths with '..' segments that climb above
    cwd are rejected before the password prompt opens), deleted the
    instant the command exits. Refuses to overwrite an existing file.
    Needed for tools that read a real .env FILE directly (Docker's
    --env-file / env_file:); not needed for `${VAR}`-style Compose
    interpolation, which already inherits process environment.

    background: start the process detached (stdout/stderr redirected to a
    returned log file, stdin closed -- never inherited, since this
    server's own stdio is the MCP protocol channel) and return immediately
    with its PID, for long-running commands (e.g. a dev server) instead of
    blocking until it exits. Not compatible with materialize or files.

    files: paths to .levault files (as listed by vault_status) to decrypt
    into the command's working directory for the lifetime of this one run --
    a certificate, private key or kubeconfig the command needs as a real
    file. Each is restored under its own name with .levault stripped
    (certs/server.pem.levault -> server.pem inside cwd), with its recorded
    permissions, and is deleted the moment the command exits. The restore
    path is enforced to stay inside cwd and an existing file is NEVER
    overwritten -- both re-checked immediately before writing, after the
    password prompt closes. Not compatible with background=True: a detached
    process has no reliable moment to clean a decrypted private key off disk.
    A run using files is never auto-allowed and never grants trust, so a
    human approves it every time. Restored file CONTENTS are not redacted
    from this tool's output the way variable values are -- a command that
    prints one hands you the real secret verbatim, so never write one that
    does.

    timeout: seconds after which a foreground command is killed -- its whole
    process tree, via a Windows Job object / POSIX process group -- and every
    real value is restored or removed. Plain runs have no limit unless you
    pass one. Part of the trust signature and shown in the dialog. A run
    that hits it returns timed_out=true. Not compatible with
    background=True.

    max_reads: single-view mode (Windows). With materialize=, the real
    values are reverted as soon as the command's process tree has
    opened and closed the file this many times -- a dotenv loader reads
    once at startup -- instead of when the command exits, so the window
    with real values on disk is milliseconds, not the command's lifetime.
    Use 1 for docker run --env-file, kubectl, source, python-dotenv,
    pydantic-settings, Node --env-file; 2 for docker compose (it reads .env
    twice); more for a harness that spawns several loaders. Opens by other
    programs are reported (foreign_apps) and, when the Restart Manager can
    name them, not counted; an open too fast to name is counted as the
    command's and labelled 'unattributed'. A read that arrives after the
    file reverted is reported as single_read_restored_early -- raise
    max_reads if it was the command. Checked before the dialog: refused
    where opens cannot be observed (macOS, Linux for now) or the filesystem
    grants no oplock. Part of the trust signature.

    Trusted commands: the dialog offers a "Trust this exact command for
    the rest of this session" checkbox. If checked, this exact
    (command, cwd, only_vars or all_vars, materialize, background, files,
    timeout, max_reads) combination (tail_chars is not part of it)
    auto-runs on every later call with no dialog at all, as long as every
    file named directly on the command line (e.g. a compose file named
    after -f) hasn't changed, and the vault itself hasn't changed (a
    secret added/removed/rotated) since -- if either has, trust is
    revoked and the dialog reappears with an explanation. Every result
    from this tool includes an "auto_allowed" flag and a "trust_note"
    whenever trust was used, granted, or revoked, so this is always
    visible even though no dialog popped up. This trust is held only in
    this server process's memory -- restarting the server forgets it --
    and it is a convenience feature, not a security boundary (see
    README.md's "Trusted commands" section, which also covers what this
    can't catch -- e.g. a Dockerfile only referenced indirectly via a
    compose file's `context:`).

    Always-allow: for a narrow set of commands (the git, docker and kubectl
    profiles, or a pinned native executable) the dialog also offers "Always
    allow (survives restarts)". The entry is stored encrypted in the vault and
    re-verified, per profile, before every run; a run it covers shows no
    dialog and the result carries auto_allowed, always_allow (the entry id) and
    a trust_note. Such a run gets stricter output redaction (more encodings of
    each value) and each stream is capped at 256 KiB (output_truncated is set
    when the cap cut something). Never offered with files, all_vars,
    background, materialize or max_reads, nor for shells and interpreters. If
    an entry no longer matches (a pinned file changed ...) it is disarmed and
    the dialog appears again with the reason in invalidated_reason. The human
    lists and removes entries with manage_vault."""
    return _run_with_env_impl(command, materialize, background, cwd, only_vars, files,
                              timeout, max_reads, all_vars, tail_chars)


READ_RUN_MAX_CONTEXT = 20
READ_RUN_MAX_LIMIT = 5000
READ_RUN_MAX_CHARS = 200_000
READ_RUN_MAX_OFFSET = 100_000_000


def _read_run_output_impl(run_id: str, stream: str = "both", pattern: Optional[str] = None,
                           context_lines: int = 0, offset: int = 0, limit: int = 200,
                           max_chars: int = 20000) -> dict:
    def _bad_int(v, lo, hi):
        return isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi

    if not isinstance(run_id, str) or not run_id:
        return {"error": "run_id must be the run_id string a run_with_env result returned."}
    if stream not in ("stdout", "stderr", "both"):
        return {"error": "stream must be 'stdout', 'stderr' or 'both'."}
    if _bad_int(context_lines, 0, READ_RUN_MAX_CONTEXT):
        return {"error": f"context_lines must be an integer between 0 and "
                         f"{READ_RUN_MAX_CONTEXT}."}
    if _bad_int(offset, 0, READ_RUN_MAX_OFFSET):
        return {"error": f"offset must be an integer line number between 0 and "
                         f"{READ_RUN_MAX_OFFSET}."}
    if _bad_int(limit, 1, READ_RUN_MAX_LIMIT):
        return {"error": f"limit must be an integer between 1 and {READ_RUN_MAX_LIMIT}."}
    if _bad_int(max_chars, 1, READ_RUN_MAX_CHARS):
        return {"error": f"max_chars must be an integer between 1 and {READ_RUN_MAX_CHARS}."}
    rx = None
    if pattern is not None:
        try:
            rx = runstore.validate_pattern(pattern)
        except ValueError as e:
            return {"error": str(e)}
    try:
        run = _RUN_OUTPUT.get(run_id)
    except runstore.RunNotFound:
        return {"error": f"Unknown run_id {run_id!r}: it never existed in this server "
                         f"process, or it has been evicted (only the last "
                         f"{runstore.MAX_RUNS} runs are kept, in memory, and are lost when the "
                         f"server restarts)."}
    except runstore.RunPending:
        return {"error": f"Run {run_id!r} is a background run that has not exited yet. Its "
                         f"output is available here once the process exits and the server "
                         f"has redacted its log."}
    names = ["stdout", "stderr"] if stream == "both" else [stream]
    per_stream_chars = max(max_chars // len(names), 1)
    streams = {}
    for name in names:
        s = run.streams[name]
        if rx is not None:
            info = runstore.search(s, rx, context_lines, offset, limit, per_stream_chars)
        else:
            info = runstore.read_window(s, offset, limit, per_stream_chars)
        info["total_chars"] = len(s.text) + s.dropped_chars
        if s.retention_truncated:
            info["retention_truncated"] = True
            info["retention_note"] = (
                f"This stream was longer than {runstore.MAX_STREAM_CHARS} characters; only its "
                f"tail is kept, starting at line {s.first_line}.")
        streams[name] = info
    return {"run_id": run_id, "streams": streams}


@mcp.tool()
def read_run_output(run_id: str, stream: str = "both", pattern: Optional[str] = None,
                     context_lines: int = 0, offset: int = 0, limit: int = 200,
                     max_chars: int = 20000) -> dict:
    """Search or page through the full output of an earlier run_with_env call,
    by the run_id its result returned, instead of re-running the command (which
    would cost the human another password prompt).

    What it reads is the output AFTER the server redacted vault values from
    it -- the same text run_with_env's inline tail is cut from -- held only in
    this server's memory: the last 20 runs, each stream capped at 10 MB (a
    longer one keeps its tail and says so), never written to disk, gone when
    the server restarts. So no password is needed. An unknown or evicted
    run_id is an error. A background run (background=True) is registered too,
    once the process has exited and the server has redacted its log in place;
    its stdout and stderr are one merged stream, reported as stdout. Before
    that, the call says the run is still in progress.

    stream: 'stdout', 'stderr' or 'both' (default). With 'both', max_chars is
    split evenly between the two.

    pattern: optional Python regular expression, matched against each line
    (use (?i) at the start for case-insensitive). With it, the result is the
    matching lines with their 1-based line numbers (`N: matching line`) and
    context_lines lines either side (`N- context line`), grep-style. Without
    it, the result is a window of lines. Patterns are deliberately
    restricted (Python's regex engine cannot be interrupted): at most 200
    characters, NO repeat of any kind inside a repeat that can match more
    than once (so not (a+)+, and not (a{0,5})+ either), NO alternation inside
    such a repeat (so not (a|b)* with multi-character branches; [ab]* is
    fine), at most 3 variable-width repeats in total (*, +, ?, {n,m}; fixed counts like
    \\d{4} are free), only the first 1000 characters of a
    line are matched (in overlapping 200-character windows; a match spanning
    more than ~100 characters across a window edge may be missed), and a scan stops after 5 seconds. Literals, classes,
    `.*`, anchors, a single-level `\\d+` and top-level alternation such as
    FAILED|ERROR all work. Invalid or refused patterns return an error. A
    line longer than max_chars is cut and marked, so paging always advances.

    context_lines: 0 to 20 (default 0). Only used with pattern.
    offset: the 0-based line to start from (default 0). In a search it is
    where scanning starts, so it pages through matches. Per stream.
    limit: lines returned in a window, or matching lines returned in a
    search (1 to 5000, default 200). Per stream.
    max_chars: cap on the text returned in total (1 to 200000, default 20000);
    lines are cut to fit.

    Each stream's entry has the text, total_lines and total_chars, and
    next_offset -- the offset to pass to continue, or null when everything has
    been returned."""
    return _read_run_output_impl(run_id, stream, pattern, context_lines, offset, limit,
                                 max_chars)


if __name__ == "__main__":
    # A swap left behind by a server that died is restored here, before the
    # first tool call can even arrive, and the report is stashed for the
    # first result that can carry it. `--recover` does only that and exits,
    # so a user can clean up from a terminal without opening a chat.
    _force = "--force" in sys.argv[1:]
    _drop = "--drop-rejected" in sys.argv[1:]
    if (_force or _drop) and not sys.stdin.isatty():
        # A human at a terminal is the authority for a forced recovery; an
        # agent with a shell is not, and this is the difference.
        print("--force / --drop-rejected require an interactive terminal.", file=sys.stderr)
        sys.exit(2)
    try:
        _startup_recovery.extend(legacy_swap.recover_stale_swaps(force=_force, drop_rejected=_drop))
    except (OSError, ValueError, RuntimeError) as _e:
        _startup_recovery.append({"error": f"could not process swap.journal.json: {_e}"})
    if "--recover" in sys.argv[1:]:
        import json as _json
        print(_json.dumps(_startup_recovery or [{"message": "nothing to recover"}], indent=2))
        sys.exit(0)
    if _startup_recovery:
        print(f"llm-env-vault: restored {len(_startup_recovery)} swapped file(s) left by a "
              f"previous server -- details in the next tool result.", file=sys.stderr)
    mcp.run()
