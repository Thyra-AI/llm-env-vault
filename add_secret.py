#!/usr/bin/env python3
"""Add or update one secret in the vault.

Usage:
    python add_secret.py VAR_NAME

Opens a small GUI where the human types the real value and the master
password. Nothing sensitive is ever printed to stdout or passed as a
command-line argument -- this script only prints a non-secret
confirmation line, so it's safe to run from an AI coding assistant.

Exit codes: 0 = applied, 1 = denied/cancelled, 2 = usage error.
"""
import sys

from vault_lib import gui, store


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("Usage: python add_secret.py VAR_NAME", file=sys.stderr)
        return 2

    var_name = sys.argv[1].strip()
    try:
        store.validate_var_name(var_name)
        index = store.load_index()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    is_update = var_name in index
    placeholder = index[var_name] if is_update else store.next_placeholder(index)

    approved = gui.add_secret_dialog(var_name, is_update, placeholder)

    if approved:
        print(f'Applied: {var_name} -> "value {placeholder}" in llm.env')
        return 0
    print("Denied: no changes made.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
