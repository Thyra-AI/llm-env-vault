"""Open the Thyra Vault app: ``python -m thyra_vault.app``.

A Bitwarden-style window for the person who owns the vault: unlock, browse,
add / edit / delete secrets, copy one to the clipboard (it is wiped again after
a few seconds), generate a password, change settings.

This is a command the PERSON runs. It is deliberately not an MCP tool: the app
can place a secret on the clipboard, and an assistant must not be able to open
it. See thyra_vault/webui/appflow.py for what the app can and cannot do.

    python -m thyra_vault.app                 # your real vault
    python -m thyra_vault.webui_demo app      # a throwaway demo vault

Where the vault lives: THYRA_VAULT_HOME, else CLAUDE_PLUGIN_DATA, else next to
the code (a checkout) or in your user data directory (a package install). See
thyra_vault/vault/datadir.py.
"""
import argparse
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m thyra_vault.app", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--where", action="store_true", help="print the vault folder and exit")
    args = parser.parse_args(argv)

    from thyra_vault import webui
    from thyra_vault.vault import store
    if args.where:
        print(store.ROOT)
        return 0
    if not webui.available():
        print("The browser UI is not built. Run `pnpm install && pnpm build:embed` in web/.",
              file=sys.stderr)
        return 2
    print(f"Thyra Vault: opening the app (vault: {store.ROOT})", file=sys.stderr)
    webui.vault_app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
