#!/usr/bin/env python3
"""Run a real command with the real secret values injected as env vars.

Usage:
    python run_with_env.py -- node app.js
    python run_with_env.py -- python manage.py runserver

Prompts once for the master password via a small GUI, decrypts the
vault in-memory, launches the target process with the real values
merged into its environment, and forwards its exit code. The real
values are never written to disk and never appear in this script's
own stdout/stderr.
"""
import os
import subprocess
import sys

from vault_lib import gui, store


def main() -> int:
    if "--" not in sys.argv:
        print("Usage: python run_with_env.py -- <command...>", file=sys.stderr)
        return 2
    sep = sys.argv.index("--")
    command = sys.argv[sep + 1:]
    if not command:
        print("No command given after --", file=sys.stderr)
        return 2

    if not store.vault_exists():
        gui.notify_no_vault()
        return 1

    secrets = gui.unlock_for_run_dialog(" ".join(command))
    if secrets is None:
        print("Cancelled: vault not unlocked.")
        return 1

    env = os.environ.copy()
    env.update(secrets)

    try:
        proc = subprocess.run(command, env=env)
    except OSError as e:
        print(f"Error: could not run {command[0]!r}: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    rc = proc.returncode
    return 128 - rc if rc < 0 else rc


if __name__ == "__main__":
    raise SystemExit(main())
