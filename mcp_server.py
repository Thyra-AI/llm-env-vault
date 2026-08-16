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
import signal
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from vault_lib import gui, store, trust
from vault_lib.crypto import (WrongPassword, WrongRecoveryKey, MalformedRecoveryKey,
                              NoRecoverySlot, VaultCorrupted, VaultTampered)

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
- When running a command with run_with_env, pass only_vars to scope the \
exposure to the variables that command actually needs. Injecting the whole \
vault when two variables would do is the main avoidable risk here.
- run_with_env output is redacted before it reaches you: vault values, and \
their base64 and URL-encoded forms, are replaced with [REDACTED:NAME]. This \
is best-effort damage control, NOT a guarantee -- values under 8 characters \
are left alone (they would shred unrelated output; the names are reported in \
redaction_skipped), and a command that transforms what it prints can still \
emit a real value. Do not echo run_with_env output back verbatim, and never \
craft a command whose purpose is to get a value past the redactor.
- Never read the background-run log file (the llm-env-vault-run-*.log path \
returned when background=True) while the process is still running -- it \
contains real secret values until the server redacts it in place once the \
process exits. Wait for the process to finish before reading the log.
- Never read a materialize target file -- it contains real secret values and \
is deleted the instant the foreground command exits. Its path should be \
treated as write-only from your perspective.
"""

mcp = FastMCP("llm-env-vault", instructions=_AGENT_INSTRUCTIONS)

# How old a background-run log has to be before opportunistic cleanup
# deletes it. Generous on purpose -- this only ever removes a log from a
# run that finished long ago, never one from a process that might still be
# writing to it.
_STALE_RUN_LOG_AGE_SECONDS = 7 * 24 * 60 * 60  # 7 days


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


def _redact_secrets(text: str, secrets: dict) -> tuple:
    """Replace every vault value in text with [REDACTED:VAR_NAME].

    Matches the exact value, its base64-encoded form, and its
    URL-percent-encoded form. Values shorter than REDACT_MIN_VALUE_LEN
    are skipped to avoid substring-destroying false positives.

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
        # Exact value
        text = text.replace(value, marker)
        # Base64-encoded form (e.g. as it might appear in an HTTP Authorization header)
        b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
        text = text.replace(b64, marker)
        # URL-percent-encoded form (e.g. as it might appear in a connection string)
        url_enc = urllib.parse.quote(value, safe="")
        text = text.replace(url_enc, marker)
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
    try:
        index = store.load_index()
        targets = store.load_targets()
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
        "format_version": store.vault_format_version(),
    }

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
    resync_targets, the vault format version, and whether a recovery slot
    exists. Reads vault.enc headers for format metadata but never decrypts
    -- no password needed, safe to call anytime. Secret values are never
    returned; vault_id is deliberately omitted (internal identifier only)."""
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


def _install_migrate_impl(target_path: str) -> dict:
    try:
        target = Path(target_path).resolve()
        if not target.exists():
            return {"applied": False, "error": f"{target} does not exist."}
        if not target.is_file():
            return {"applied": False, "error": f"{target} is not a file."}

        parsed = store.parse_env_file(target)
        index_now = store.load_index()
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
        if name in index_now and value == f"value {index_now[name]}":
            already_migrated.append(name)
            continue
        if store.PLACEHOLDER_VALUE_RE.match(value):
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
    return _install_migrate_impl(target_path)


def _resync_targets_impl() -> dict:
    try:
        index = store.load_index()
        targets = store.load_targets()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return {"error": str(e)}
    if not targets:
        return {"message": "No target files registered. Call install_migrate first."}

    results = {}
    for path_str, names in targets.items():
        path = Path(path_str)
        if not path.exists():
            results[path_str] = {"status": "missing"}
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
      upgrade_v2       -- "password" (str); "recovery" (bool, optional, defaults False)
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

    return {"applied": False, "error": f"Unrecognised action from vault management dialog."}


@mcp.tool()
def manage_vault() -> dict:
    """Open the vault management dialog for password changes, recovery key
    setup and reissue, and v1-to-v2 format upgrades. All sensitive input
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
                          format; optionally adds a recovery slot in the
                          same operation.

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
    # Recovery always mints a fresh key: the one just used was typed from
    # paper and may have been observed in the process.
    if new_key:
        info = store.vault_info()
        shown = gui.show_recovery_key_dialog(new_key, info.get("recovery_slot_id", ""))
        if not shown:
            return {"applied": True,
                    "warning": "Access was recovered and the new master password is "
                               "set, but the replacement recovery key was not "
                               "confirmed and cannot be shown again. The key you "
                               "just used is now invalid. Run manage_vault and "
                               "choose reissue_recovery to get a usable one."}
    return {"applied": True,
            "message": "Access recovered and a new master password set."}


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

    Recovering always issues a replacement recovery key (the one just used was
    read aloud from paper and may have been observed) and shows it in the
    write-it-down dialog. It never appears in this result."""
    return _recover_vault_impl()


class _Terminated(Exception):
    pass


def _on_sigterm(signum, frame):
    raise _Terminated()


def _resolve_materialize_path(materialize: str, cwd: Optional[str]) -> Path:
    base = (Path(cwd) if cwd else Path.cwd()).resolve()
    resolved = (base / materialize).resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(
            f"materialize must resolve to a path inside cwd ({base}); got {resolved}, "
            f"which escapes it. Use a plain relative filename, not an absolute path or "
            f"one with '..' segments that climb above cwd."
        )
    return resolved


def _run_with_env_impl(command: list, materialize: Optional[str], background: bool,
                        cwd: Optional[str], only_vars: Optional[list] = None) -> dict:
    if not command or not all(isinstance(c, str) for c in command):
        return {"error": "command must be a non-empty list of strings."}
    if background and materialize:
        return {"error": "materialize is not supported together with background=True "
                          "(there's no reliable moment to clean the file up if the "
                          "process is left running)."}
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
    except (OSError, ValueError) as e:
        return {"error": str(e)}

    # Trust is scoped to this exact (command, cwd, only_vars, materialize,
    # background) shape AND the content of every file named directly on
    # the command line -- see vault_lib/trust.py. Everything it tracks
    # lives only in this server process's memory; it's forgotten the
    # moment the process exits, same as if the feature didn't exist.
    signature = trust.make_signature(command, cwd, only_vars, materialize, background)
    auto_ok, invalidated_reason = trust.check(signature, command, cwd)
    trust_info = {}

    # trust.check()'s own contract guarantees cached_secrets(signature) is
    # non-None whenever it returns auto_ok=True, so this should be
    # unreachable in practice -- kept as a cheap belt-and-suspenders
    # fallback to the real dialog rather than trusting that invariant to
    # hold forever (e.g. across a future change to how/whether tool calls
    # can overlap). On this path, raw_secrets is already the subset scoped
    # to this signature's own only_vars, not the full vault -- see
    # trust.cache_secrets()'s caller below, which filters before caching.
    raw_secrets = trust.cached_secrets(signature) if auto_ok else None

    if auto_ok and raw_secrets is not None:
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
        if is_executable_only:
            _dialog_parts.append(
                "Note: only the executable binary is drift-monitored for this "
                "command -- no config files are named on the command line, so "
                "changes to compose files or scripts will NOT revoke trust.")
        dialog_trust_note = " ".join(_dialog_parts) if _dialog_parts else None
        outcome = gui.unlock_for_run_dialog(subprocess.list2cmdline(command),
                                             materialize_path=str(materialized_path)
                                             if materialized_path else None,
                                             only_vars=only_vars,
                                             trust_note=dialog_trust_note)
        raw_secrets = outcome["secrets"]
        if raw_secrets is None:
            result = {"applied": False, "message": "Denied by user."}
            if invalidated_reason:
                result["trust_note"] = invalidated_reason
            return result
        if outcome["trust"]:
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
                # "docker compose up" shape: only the binary is tracked.
                # Make the limited coverage explicit in the tool result.
                _exe_path = monitored_paths[0]
                granted_note = (
                    f"This exact command is now trusted for the next "
                    f"{_ttl_hours} hours (or until this server restarts, "
                    f"whichever comes first). "
                    f"Future identical runs auto-allow with no password prompt. "
                    f"Drift-monitored: only the executable ({_exe_path}). "
                    f"No config files are named on this command line -- changes "
                    f"to compose files or scripts will NOT revoke trust.")
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

    def _finish(result: dict) -> dict:
        result.update(trust_info)
        return result

    secrets = raw_secrets
    if only_vars is not None:
        secrets = {k: v for k, v in secrets.items() if k in only_vars}

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
            store.write_materialized_env(materialized_path, secrets)
        except (OSError, ValueError) as e:
            return _finish({"applied": False, "error": str(e)})

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
                                         stdout=log_file, stderr=subprocess.STDOUT)
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

        def _log_redactor_thread() -> None:
            try:
                proc.wait()
            except Exception:
                return
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as _f:
                    _content = _f.read()
                _redacted, _ = _redact_secrets(_content, _secrets_for_redaction)
                with open(log_path, "w", encoding="utf-8") as _f:
                    _f.write(_redacted)
            except OSError:
                pass  # best-effort: swallow all IO failures silently

        threading.Thread(target=_log_redactor_thread, daemon=True).start()
        return _finish({"applied": True, "started": True, "pid": proc.pid, "log_file": log_path,
                "note": "Running detached. The log file is unredacted while the process is "
                        "still running -- secret values may appear in it until the process "
                        "exits and the server redacts it in place. "
                        "Use the OS/your own process manager to stop it later."})

    old_sigterm = None
    if materialized_path is not None:
        try:
            old_sigterm = signal.signal(signal.SIGTERM, _on_sigterm)
        except (ValueError, OSError):
            pass

    cleanup_error = None
    try:
        try:
            # stdin=DEVNULL: under the stdio transport this process's own
            # stdin IS the JSON-RPC input pipe. Without this, a command
            # that reads stdin (an interactive prompt, a TTY attach) would
            # consume protocol bytes and/or block forever with the whole
            # server frozen behind it -- DEVNULL makes it fail fast on EOF
            # instead.
            proc = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL)
        except OSError as e:
            return _finish({"applied": False, "error": f"could not run {command[0]!r}: {e}"})
        except (KeyboardInterrupt, _Terminated):
            return _finish({"applied": False, "message": "Interrupted."})
    finally:
        if old_sigterm is not None:
            signal.signal(signal.SIGTERM, old_sigterm)
        if materialized_path is not None:
            try:
                materialized_path.unlink(missing_ok=True)
            except OSError as e:
                cleanup_error = str(e)

    # Redact BEFORE the [-4000:] slice so a secret value that straddles the
    # cut point is still caught. The full output is redacted first, then
    # truncated -- the truncation can split a [REDACTED:NAME] marker but
    # cannot leave a raw secret value visible.
    _stdout_full = proc.stdout or ""
    _stderr_full = proc.stderr or ""
    _stdout_redacted, _stdout_skipped = _redact_secrets(_stdout_full, raw_secrets)
    _stderr_redacted, _stderr_skipped = _redact_secrets(_stderr_full, raw_secrets)
    _all_skipped = sorted(set(_stdout_skipped) | set(_stderr_skipped))
    result = {
        "applied": True,
        "exit_code": proc.returncode,
        "stdout": _stdout_redacted[-4000:],
        "stderr": _stderr_redacted[-4000:],
    }
    if _all_skipped:
        result["redaction_skipped"] = (
            f"These vault variables were NOT redacted from output because their "
            f"values are shorter than {REDACT_MIN_VALUE_LEN} characters: "
            + ", ".join(_all_skipped))
    if cleanup_error:
        result["warning"] = (f"Could not delete {materialized_path}, it still contains real "
                              f"secret values -- remove it by hand: {cleanup_error}")
    return _finish(result)


@mcp.tool()
def run_with_env(command: list[str], materialize: Optional[str] = None,
                  background: bool = False, cwd: Optional[str] = None,
                  only_vars: Optional[list[str]] = None) -> dict:
    """Run a real command with the vault's real secret values injected as
    environment variables. Prompts once for the master password via a GUI
    (which also lists which variable names -- never values -- will be
    exposed) and never writes real values to disk unless materialize is
    given. Returns the command's exit code, stdout, and stderr, with every
    vault value -- plus its base64 and URL-encoded forms -- replaced by
    [REDACTED:VAR_NAME] before the result is handed back. That redaction is
    accident-prevention, not a boundary: values shorter than 8 characters
    are skipped (listed in redaction_skipped) because replacing them would
    shred unrelated output, and a command that transforms what it prints
    can still emit a real value. Two paths are deliberately not covered --
    a background run's log file is only redacted once the process exits,
    and a materialize target holds real values on disk by design.

    only_vars: restrict which vault variables are actually injected, by
    name (e.g. ["DATABASE_URL"]). Strongly recommended whenever the
    command only needs a few of them -- without it, every unrelated
    secret in the vault is exposed to this command and anything it
    spawns. Unknown names are rejected before the password prompt opens.

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
    blocking until it exits. Not compatible with materialize.

    Trusted commands: the dialog offers a "Trust this exact command for
    the rest of this session" checkbox. If checked, this exact
    (command, cwd, only_vars, materialize, background) combination
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
    compose file's `context:`)."""
    return _run_with_env_impl(command, materialize, background, cwd, only_vars)


if __name__ == "__main__":
    mcp.run()
