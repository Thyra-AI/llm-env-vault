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
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from vault_lib import gui, store

mcp = FastMCP("llm-env-vault")

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
    return {
        "vault_exists": store.vault_exists(),
        "variables": index,
        "llm_env_path": str(store.ENV_FILE),
        "targets": targets,
    }


@mcp.tool()
def vault_status() -> dict:
    """Read-only snapshot of the vault: which variables are managed, their
    llm.env placeholder numbers, and which project files are registered
    for resync_targets. Never touches vault.enc -- no password needed,
    safe to call anytime."""
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
    approved = gui.add_secret_dialog(var_name, is_update, placeholder, is_sensitive=is_sensitive)
    if approved:
        return {"applied": True, "message": f'{var_name} -> "value {placeholder}" in llm.env'}
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
    approved = gui.remove_secret_dialog(var_name, index[var_name])
    if approved:
        return {"applied": True, "message": f"{var_name} removed from llm.env"}
    return {"applied": False, "message": "Denied by user."}


@mcp.tool()
def remove_secret(var_name: str) -> dict:
    """Remove one secret from the vault. Opens a GUI confirm dialog (master
    password, then the proposed removal); nothing is removed until the
    human clicks Allow."""
    return _remove_secret_impl(var_name)


def _install_migrate_impl(target_path: str) -> dict:
    target = Path(target_path).resolve()
    if not target.exists():
        return {"applied": False, "error": f"{target} does not exist."}
    if not target.is_file():
        return {"applied": False, "error": f"{target} is not a file."}

    try:
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
            try:
                store.add_target(str(target), already_migrated)
                warnings.append(f"Registered {target} for future resync_targets calls.")
            except ValueError as e:
                return {"applied": False, "error": str(e), "warnings": warnings}
        return {"applied": False, "message": "Nothing new to migrate.", "warnings": warnings,
                "already_migrated": already_migrated}

    other_owner = {}
    for name, _ in to_migrate:
        for path_str, names in targets_now.items():
            if path_str != str(target) and name in names:
                other_owner[name] = path_str
                break

    sensitive_names = {name for name, _ in to_migrate if store.is_sensitive_env_name(name)}
    result = gui.install_dialog(target, to_migrate, other_owner, also_register=already_migrated,
                                sensitive_names=sensitive_names)
    if not result["approved"]:
        return {"applied": False, "message": "Denied by user.", "warnings": warnings}

    ret = {
        "applied": True,
        "migrated_count": len(to_migrate),
        "migrated_names": [n for n, _ in to_migrate],
        "target_still_has_real_secrets": bool(unsupported or unrecognized or swallowed),
        "warnings": warnings,
    }
    conflicts = result.get("conflicts", [])
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


class _Terminated(Exception):
    pass


def _on_sigterm(signum, frame):
    raise _Terminated()


def _resolve_materialize_path(materialize: str, cwd: Optional[str]) -> Path:
    base = Path(cwd) if cwd else Path.cwd()
    return (base / materialize).resolve()


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
    materialized_path = _resolve_materialize_path(materialize, cwd) if materialize else None
    if materialized_path is not None and materialized_path.exists():
        return {"error": f"{materialized_path} already exists -- refusing to overwrite it. "
                          f"Pick a path that doesn't exist yet."}

    secrets = gui.unlock_for_run_dialog(" ".join(command),
                                         materialize_path=str(materialized_path)
                                         if materialized_path else None,
                                         only_vars=only_vars)
    if secrets is None:
        return {"applied": False, "message": "Denied by user."}

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
            return {"applied": False,
                    "error": f"{materialized_path} came into existence while the password "
                              f"prompt was open -- refusing to overwrite it. Try again."}
        try:
            store.write_materialized_env(materialized_path, secrets)
        except (OSError, ValueError) as e:
            return {"applied": False, "error": str(e)}

    if background:
        # Under the stdio transport this process's own stdout/stdin ARE the
        # JSON-RPC channel -- a detached child inheriting them would either
        # inject its own output as garbage into the protocol stream (and
        # corrupt/kill the session for as long as it runs) or steal bytes
        # meant for this server. Redirect explicitly; never inherit.
        log_fd, log_path = tempfile.mkstemp(suffix=".log", prefix="llm-env-vault-run-")
        os.close(log_fd)
        try:
            with open(log_path, "wb") as log_file:
                proc = subprocess.Popen(command, env=env, cwd=cwd,
                                         stdin=subprocess.DEVNULL,
                                         stdout=log_file, stderr=subprocess.STDOUT)
        except OSError as e:
            return {"applied": False, "error": f"could not start {command[0]!r}: {e}"}
        return {"applied": True, "started": True, "pid": proc.pid, "log_file": log_path,
                "note": "Running detached. This tool does not track or stop it -- "
                        "use the OS/your own process manager to stop it later."}

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
            return {"applied": False, "error": f"could not run {command[0]!r}: {e}"}
        except (KeyboardInterrupt, _Terminated):
            return {"applied": False, "message": "Interrupted."}
    finally:
        if old_sigterm is not None:
            signal.signal(signal.SIGTERM, old_sigterm)
        if materialized_path is not None:
            try:
                materialized_path.unlink(missing_ok=True)
            except OSError as e:
                cleanup_error = str(e)

    result = {
        "applied": True,
        "exit_code": proc.returncode,
        "stdout": (proc.stdout or "")[-4000:],
        "stderr": (proc.stderr or "")[-4000:],
    }
    if cleanup_error:
        result["warning"] = (f"Could not delete {materialized_path}, it still contains real "
                              f"secret values -- remove it by hand: {cleanup_error}")
    return result


@mcp.tool()
def run_with_env(command: list[str], materialize: Optional[str] = None,
                  background: bool = False, cwd: Optional[str] = None,
                  only_vars: Optional[list[str]] = None) -> dict:
    """Run a real command with the vault's real secret values injected as
    environment variables. Prompts once for the master password via a GUI
    (which also lists which variable names -- never values -- will be
    exposed) and never writes real values to disk unless materialize is
    given. Returns the command's exit code, stdout, and stderr (not
    secret -- that's the app's own output, same as running it in a
    terminal, though be aware a command that echoes its own environment
    or dumps its config on error will put real secret values into that
    output, and therefore into this result).

    only_vars: restrict which vault variables are actually injected, by
    name (e.g. ["DATABASE_URL"]). Strongly recommended whenever the
    command only needs a few of them -- without it, every unrelated
    secret in the vault is exposed to this command and anything it
    spawns. Unknown names are rejected before the password prompt opens.

    materialize: path for a short-lived real .env file (mode 0600,
    unquoted -- matches `docker run --env-file` semantics exactly),
    resolved relative to `cwd` if given, deleted the instant the command
    exits. Refuses to overwrite an existing file. Needed for tools that
    read a real .env FILE directly (Docker's --env-file / env_file:); not
    needed for `${VAR}`-style Compose interpolation, which already
    inherits process environment.

    background: start the process detached (stdout/stderr redirected to a
    returned log file, stdin closed -- never inherited, since this
    server's own stdio is the MCP protocol channel) and return immediately
    with its PID, for long-running commands (e.g. a dev server) instead of
    blocking until it exits. Not compatible with materialize."""
    return _run_with_env_impl(command, materialize, background, cwd, only_vars)


if __name__ == "__main__":
    mcp.run()
