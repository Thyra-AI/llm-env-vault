#!/usr/bin/env python3
"""Remove one secret from the vault.

Usage:
    python remove_secret.py VAR_NAME

Exit codes: 0 = applied, 1 = denied/cancelled/not-found, 2 = usage error.
"""
import sys

from vault_lib import gui, store


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("Usage: python remove_secret.py VAR_NAME", file=sys.stderr)
        return 2

    var_name = sys.argv[1].strip()
    try:
        store.validate_var_name(var_name)
        index = store.load_index()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if var_name not in index:
        print(f"{var_name} is not in the vault.")
        return 1

    if not store.vault_exists():
        # No vault means no encrypted secret can exist -- just drop the
        # stale index entry so llm.env stops advertising it.
        index.pop(var_name)
        store.save_index(index)
        print(f"Applied: removed stale index entry for {var_name} (no vault present).")
        return 0

    approved = gui.remove_secret_dialog(var_name, index[var_name])
    if approved:
        print(f"Applied: {var_name} removed from llm.env")
        return 0
    print("Denied: no changes made.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
