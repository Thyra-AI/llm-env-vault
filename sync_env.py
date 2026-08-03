#!/usr/bin/env python3
"""Regenerate llm.env from vault_index.json.

No password required -- the index only holds VAR_NAME -> placeholder
number, never real values. Useful if llm.env was deleted or edited by
hand.
"""
import sys

from vault_lib import store


def main() -> int:
    if not store.INDEX_FILE.exists():
        print("vault_index.json not found -- refusing to overwrite llm.env "
              "with an empty file. Restore vault_index.json first.", file=sys.stderr)
        return 1
    try:
        index = store.load_index()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    store.regenerate_llm_env(index)
    print(f"llm.env regenerated with {len(index)} variable(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
