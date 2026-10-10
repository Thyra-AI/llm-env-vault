"""Try a browser dialog without an AI assistant: ``python -m thyra_vault.webui_demo <dialog>``.

Builds a THROWAWAY vault in a temporary directory, opens the dialog in your
browser, and prints what the dialog returned -- with every secret redacted. The
demo master password is printed so you can type it in.

    python -m thyra_vault.webui_demo unlock-run
    python -m thyra_vault.webui_demo first-run        # no vault yet: create one
    python -m thyra_vault.webui_demo --list

Why this is NOT thyra_vault/webui/__main__.py: ``python -m thyra_vault.webui`` would
import the webui package -- and with it thyra_vault.store -- BEFORE this code could
point the vault at a temp directory. store resolves its location at import time,
so the demo would have created a vault in the real data directory. Keeping this
module outside the package, and refusing to run unless store.ROOT really is
inside the temp directory, makes that impossible.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

DEMO_PASSWORD = "demo-password-123"
DEMO_SECRETS = {"OPENAI_API_KEY": "sk-demo-not-a-real-key", "DATABASE_URL": "postgres://demo:demo@localhost/demo",
                "STRIPE_SECRET": "sk_test_demo_not_real"}
DIALOGS = ["unlock-run", "first-run", "add", "update", "remove", "retype", "install", "encrypt",
           "decrypt", "abandon", "change-password", "recovery-key", "recover", "manage", "app"]


def _redact(value):
    """Show shape, never content."""
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items() if k not in ("bytes",)}
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, str) and value:
        return "<redacted>"
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m thyra_vault.webui_demo", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dialog", nargs="?", choices=DIALOGS)
    parser.add_argument("--list", action="store_true", help="list the dialogs and exit")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser; print the link instead")
    args = parser.parse_args(argv)
    if args.list or not args.dialog:
        print("\n".join(DIALOGS))
        return 0

    if "thyra_vault.store" in sys.modules:
        print("refusing to run: thyra_vault.store is already imported, so the vault location "
              "is already fixed", file=sys.stderr)
        return 2
    work = Path(tempfile.mkdtemp(prefix="thyra-vault-demo-")).resolve()
    os.environ["CLAUDE_PLUGIN_DATA"] = str(work)  # BEFORE thyra_vault.store is imported
    if args.no_browser:
        os.environ["THYRA_VAULT_NO_BROWSER"] = "1"

    from thyra_vault import crypto, store, webui
    if work not in store.ROOT.resolve().parents:
        print(f"refusing to run: the vault would be at {store.ROOT}, not inside {work}",
              file=sys.stderr)
        return 2
    crypto.SCRYPT_DEFAULT = crypto.ScryptParams(n=2 ** 12, r=8, p=1)  # snappy demo

    if args.dialog != "first-run":
        store.create_v2_vault(DEMO_PASSWORD)
        store.save_secrets(DEMO_PASSWORD, dict(DEMO_SECRETS))
        store.save_index({name: i for i, name in enumerate(DEMO_SECRETS, 1)})

    print(f"Demo vault: {store.ROOT}", file=sys.stderr)
    if args.dialog != "first-run":
        print(f"Demo master password: {DEMO_PASSWORD}", file=sys.stderr)

    d = args.dialog
    if d in ("unlock-run", "first-run"):
        result = (webui.unlock_for_run_dialog("python manage.py migrate", only_vars=set(DEMO_SECRETS))
                  if d == "unlock-run" else webui.add_secret_dialog("OPENAI_API_KEY", False, 1))
    elif d == "add":
        result = webui.add_secret_dialog("NEW_TOKEN", False, 4)
    elif d == "update":
        result = webui.add_secret_dialog("OPENAI_API_KEY", True, 1)
    elif d == "remove":
        result = webui.remove_secret_dialog("STRIPE_SECRET", 3)
    elif d == "retype":
        result = webui.retype_placeholders_dialog(sorted(DEMO_SECRETS))
    elif d == "install":
        env = work / "project.env"
        env.write_text('NEW_ONE="sk-demo-new-value"\nOPENAI_API_KEY="other"\n', encoding="utf-8")
        result = webui.install_dialog(env, [("NEW_ONE", "sk-demo-new-value")],
                                      other_owner={"NEW_ONE": "/work/other/.env"})
    elif d in ("encrypt", "decrypt"):
        pem = work / "server.pem"
        pem.write_text("-----BEGIN PRIVATE KEY-----\ndemo\n-----END PRIVATE KEY-----\n", encoding="utf-8")
        if d == "encrypt":
            result = webui.encrypt_file_dialog(pem)
        else:
            store.encrypt_file_in_place(pem, DEMO_PASSWORD)
            result = webui.decrypt_file_dialog(Path(str(pem) + ".levault"))
    elif d == "abandon":
        result = webui.confirm_abandon_files_dialog({1: ["a" * 40, "b" * 40]}, {"a" * 40: "prod.pem"})
    elif d == "change-password":
        result = webui.change_password_dialog()
    elif d == "recovery-key":
        key = crypto.format_recovery_key(bytes(crypto.new_recovery_key()))
        result = webui.show_recovery_key_dialog(key, "demo-slot")
    elif d == "recover":
        result = webui.recover_dialog()
    elif d == "app":
        result = webui.vault_app()
    else:
        result = webui.manage_vault_dialog()
    print("Dialog returned:", _redact(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
