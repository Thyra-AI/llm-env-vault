#!/usr/bin/env python3
"""Bootstrap launcher for llm-env-vault as a Claude Code plugin.

This is what .mcp.json actually runs (via bare `python`) instead of
mcp_server.py directly. Reasons a launcher is needed at all:

- A plugin can't ship a committed virtualenv: .venv/ is gitignored on
  purpose (platform-specific binaries have no business in git), but
  every *installed* copy of this plugin still needs cryptography and
  mcp[cli] importable.
- Claude Code auto-installs a plugin's Node.js dependencies into the
  cache when it installs/updates the plugin (see "Node.js package
  dependencies" in the plugins reference), but there is no equivalent
  automatic step for Python. The documented pattern for exactly this
  case is: provision it yourself into ${CLAUDE_PLUGIN_DATA} -- the
  persistent directory that survives plugin updates -- and the Node.js
  example in that same doc section (installing node_modules from a
  SessionStart hook) is the direct analog of what this script does for
  a venv, just inline in the launcher instead of a separate hook.

CLAUDE_PLUGIN_ROOT and CLAUDE_PLUGIN_DATA are exported by Claude Code
into every MCP server subprocess's environment automatically -- this
script doesn't need them passed as args, and doesn't do anything if
they're absent (falls back to running next to itself, so `python
plugin_launcher.py` still works for local testing outside a plugin
install).

If the plugin's tools never show up as available, check
${CLAUDE_PLUGIN_DATA}/provision.log first. Confirmed to happen in
practice: an MCP client's server-startup timeout can kill this launcher
mid-install (venv created, but `pip install` never finishes) -- from the
outside that looks identical to the server simply never having started,
with no error visible anywhere else. provision.log captures the exact pip
output for whichever attempt ran last, successful or not.
"""
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("CLAUDE_PLUGIN_DATA", PLUGIN_ROOT / ".venv-data"))
VENV_DIR = DATA_DIR / "venv"
INSTALL_LOG = DATA_DIR / "provision.log"

# The hash-pinned lockfile is Windows-only (the platform pywin32 -- a
# transitive mcp[cli] dependency -- actually has wheels for, and this
# project's tested/primary platform). Falls back to the unpinned
# requirements.txt everywhere else rather than risk a hash-pinned file
# that silently can't resolve on a platform it wasn't verified against.
_LOCKFILE = PLUGIN_ROOT / "requirements-lock.txt"
REQUIREMENTS = _LOCKFILE if sys.platform == "win32" and _LOCKFILE.exists() \
    else PLUGIN_ROOT / "requirements.txt"

STAMP_FILE = DATA_DIR / "requirements.sha256"

# Only set when actually running as an installed plugin (Claude Code
# exports it into every MCP server subprocess automatically).
_IS_INSTALLED_PLUGIN = "CLAUDE_PLUGIN_ROOT" in os.environ


def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _requirements_hash() -> str:
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()


def _log(message: str) -> None:
    """Appends a timestamped line to provision.log. Best-effort -- a
    logging failure (e.g. DATA_DIR unwritable) must never take down
    provisioning itself, so this only ever swallows OSError, never raises."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(INSTALL_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def _run_logged(cmd: list, step: str) -> None:
    """Runs `cmd`, logs its full output to provision.log regardless of
    outcome, and raises a clean RuntimeError pointing at that log on
    failure -- never a bare, unlogged CalledProcessError. Used for BOTH
    venv creation and the pip install, so a venv-creation failure (disk
    full, missing ensurepip, permission denied on DATA_DIR) gets the same
    diagnosable trail as a dependency-install failure, not a raw traceback
    while the log stays empty.

    `text=True` decoding is pinned to UTF-8 with errors replaced rather
    than the platform default (on Windows, the ANSI codepage) -- otherwise
    non-ASCII bytes in the subprocess's own output (an accented username
    in a path, non-ASCII text in a dependency's error message) could raise
    an uncaught UnicodeDecodeError before this function ever gets a chance
    to log anything, defeating the entire point of it existing."""
    _log(f"Running ({step}): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
    if result.stdout:
        _log(result.stdout.rstrip())
    if result.returncode != 0:
        if result.stderr:
            _log(result.stderr.rstrip())
        _log(f"FAILED ({step}) with exit code {result.returncode}")
        raise RuntimeError(
            f"llm-env-vault: {step} failed (exit code {result.returncode}). "
            f"Full output in {INSTALL_LOG}."
        )


def _install_marker() -> str:
    """What decides whether the venv needs (re)provisioning.

    Installed plugin (CLAUDE_PLUGIN_ROOT set): keyed on CLAUDE_PLUGIN_ROOT's
    own resolved path, NOT requirements.txt's content hash. A real `claude
    plugin update` always moves the plugin to a new version-scoped
    directory -- that's the same fact behind vault_lib/store.py's ROOT
    relocation: an update orphans whatever was in the OLD version's
    directory precisely because it creates a new one. So a path change IS
    a genuine update event, and requirements.txt's content is replaced
    wholesale as part of that same update -- nothing legitimate is missed
    by keying off the path instead of the hash. What this closes: content-
    hash-based triggering meant an agent with filesystem write access to
    an *installed* plugin's requirements.txt could get it automatically
    pip-installed on the very next server restart, with no real update
    having happened at all -- an auto-triggered, persistent code-execution
    path a red-team audit flagged as sharper than "the agent can edit this
    tool's source" plainly implies. Editing requirements.txt alone, with
    no update, no longer triggers anything.

    Manual/dev install (no CLAUDE_PLUGIN_ROOT): unchanged, still the
    content hash. There's no "version" to key off in a local checkout, and
    immediate reinstall-on-edit is exactly the iterative workflow a
    developer testing a dependency change wants -- this is the
    maintainer's own trusted working copy, not the threat this is about.
    """
    if _IS_INSTALLED_PLUGIN:
        return str(PLUGIN_ROOT)
    return _requirements_hash()


def _ensure_venv() -> Path:
    """Creates (or recreates, if the install marker -- see _install_marker
    -- changed since last time) the venv in the plugin's persistent data
    directory. A no-op stat check on every normal startup once it's
    already provisioned.

    Confirmed in practice (not hypothetical): an MCP client's server-
    startup timeout can kill this process mid-install -- the venv gets
    created (fast) but `pip install` never finishes, and no error surfaces
    anywhere a user would think to look. STAMP_FILE only being written
    AFTER a successful install already meant the next run would retry
    rather than silently trust a half-finished venv -- but a python.exe
    that already works is skipped on retry instead of being recreated
    (faster on a retry, and the actual slow part was never venv creation),
    and every attempt's pip output -- success or failure -- goes to
    provision.log, so a repeatedly-interrupted install is diagnosable
    without inspecting internal files by hand.
    """
    python = _venv_python()
    current_marker = _install_marker()
    up_to_date = (
        python.exists()
        and STAMP_FILE.exists()
        and STAMP_FILE.read_text().strip() == current_marker
    )
    if up_to_date:
        return python

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if python.exists() and not STAMP_FILE.exists():
        _log("Found a venv with no completed-install stamp -- a previous "
             "provisioning attempt likely didn't finish (killed by a startup "
             "timeout, ran out of disk, etc.). Retrying.")
    print(f"[llm-env-vault] Setting up its Python environment in {VENV_DIR} "
          f"(first run, or dependencies changed since last run) -- this "
          f"can take a little while the first time. Progress: {INSTALL_LOG}",
          file=sys.stderr, flush=True)

    if not python.exists():
        _run_logged([sys.executable, "-m", "venv", str(VENV_DIR)], "venv creation")

    pip_cmd = [str(python), "-m", "pip", "install"]
    if REQUIREMENTS is _LOCKFILE:
        pip_cmd.append("--require-hashes")
    pip_cmd += ["-r", str(REQUIREMENTS)]
    _run_logged(pip_cmd, "dependency install")

    _log("Provisioning succeeded.")
    STAMP_FILE.write_text(current_marker)
    return python


def main() -> None:
    python = _ensure_venv()
    server = str(PLUGIN_ROOT / "mcp_server.py")
    # Replaces this process rather than subprocess.run()-ing it: the real
    # server needs to own stdio directly for the MCP stdio transport, not
    # inherit it through an extra layer of process indirection.
    os.execv(str(python), [str(python), server])


if __name__ == "__main__":
    main()
