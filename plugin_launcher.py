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
"""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("CLAUDE_PLUGIN_DATA", PLUGIN_ROOT / ".venv-data"))
VENV_DIR = DATA_DIR / "venv"
REQUIREMENTS = PLUGIN_ROOT / "requirements.txt"
STAMP_FILE = DATA_DIR / "requirements.sha256"


def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _requirements_hash() -> str:
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()


def _ensure_venv() -> Path:
    """Creates (or recreates, if requirements.txt changed since last time)
    the venv in the plugin's persistent data directory. A no-op stat/hash
    check on every normal startup once it's already provisioned."""
    python = _venv_python()
    current_hash = _requirements_hash()
    up_to_date = (
        python.exists()
        and STAMP_FILE.exists()
        and STAMP_FILE.read_text().strip() == current_hash
    )
    if up_to_date:
        return python

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[llm-env-vault] Setting up its Python environment in {VENV_DIR} "
          f"(first run, or requirements.txt changed since last run) -- this "
          f"can take a little while the first time.", file=sys.stderr, flush=True)
    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    subprocess.run([str(python), "-m", "pip", "install", "--quiet",
                     "-r", str(REQUIREMENTS)], check=True)
    STAMP_FILE.write_text(current_hash)
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
