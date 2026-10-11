"""The consent dialogs, as browser pages: one function per dialog.

mcp_server.py calls these. Under the hood each one builds a flow (flows.py), hands it to
the loopback server (server.py), blocks until the human answers, and returns an ``outcome``
dict. ``vault_app`` (appflow.py) is the separate, human-opened app.
"""
from pathlib import Path

from .. import store
from . import flows, server
from .server import Limits, WebUiUnavailable  # noqa: F401 -- re-exported

# Tests shrink these; production uses the defaults.
LIMITS = Limits()


def available() -> bool:
    """True if the built browser assets are present."""
    try:
        server._assets_dir()
        return True
    except WebUiUnavailable:
        return False


def _run(flow, status_of=None) -> None:
    server.run_flow(flow, status_of=status_of, limits=LIMITS)


def _approved(outcome):
    return lambda: "approved" if outcome.get("approved") else "declined"


def add_secret_dialog(var_name: str, is_update: bool, placeholder: int,
                      is_sensitive: bool = False):
    store.validate_var_name(var_name)
    outcome = {"approved": False, "partial_failure": None}
    _run(flows.add_secret(outcome, var_name, is_update, placeholder, is_sensitive),
         _approved(outcome))
    return outcome


def remove_secret_dialog(var_name: str, placeholder: int):
    outcome = {"approved": False, "partial_failure": None}
    _run(flows.remove_secret(outcome, var_name, placeholder), _approved(outcome))
    return outcome


def retype_placeholders_dialog(names):
    outcome = {"approved": False, "retyped": {}, "conflicts": {}, "partial_failure": None}
    _run(flows.retype_placeholders(outcome, names), _approved(outcome))
    return outcome


def install_dialog(target, to_migrate, other_owner=None, also_register=None,
                   sensitive_names=None):
    outcome = {"approved": False, "partial_failure": None, "conflicts": []}
    _run(flows.install(outcome, Path(target), to_migrate, other_owner or {},
                       also_register or [], set(sensitive_names or ())),
         _approved(outcome))
    return outcome


def encrypt_file_dialog(path):
    outcome = {"approved": False, "partial_failure": None, "result": None}
    _run(flows.encrypt_file(outcome, path), _approved(outcome))
    return outcome


def decrypt_file_dialog(vault_path, output_path=None):
    outcome = {"approved": False, "partial_failure": None, "result": None}
    _run(flows.decrypt_file(outcome, vault_path, output_path), _approved(outcome))
    return outcome


def confirm_abandon_files_dialog(outstanding: dict, registry_names: dict):
    outcome = {"abandon": None}
    _run(flows.confirm_abandon_files(outcome, outstanding, registry_names),
         lambda: "approved" if outcome["abandon"] is not None else "declined")
    return outcome["abandon"]


def unlock_for_run_dialog(command_str: str, materialize_path: str = None, only_vars=None,
                          trust_note: str = None, files=None, *, timeout=None,
                          max_reads=None, cwd: str = None, executable: str = None,
                          command_lines=None, background: bool = False):
    outcome = {"secrets": None, "trust": False}
    _run(flows.unlock_for_run(outcome, command_str, materialize_path, only_vars, trust_note,
                              files, max_reads, cwd, executable, command_lines, background),
         lambda: "approved" if outcome["secrets"] is not None else "declined")
    return outcome


def change_password_dialog() -> dict:
    outcome = {"old": None, "new": None}
    _run(flows.change_password(outcome),
         lambda: "approved" if outcome["old"] is not None else "declined")
    return outcome


def show_recovery_key_dialog(key_text: str, slot_id: str) -> bool:
    result = [False]
    _run(flows.recovery_key(key_text, slot_id, result),
         lambda: "approved" if result[0] else "declined")
    return result[0]


def recover_dialog() -> dict:
    outcome = {"recovery_key": None, "new_password": None}
    _run(flows.recover(outcome),
         lambda: "approved" if outcome["recovery_key"] is not None else "declined")
    return outcome


def manage_vault_dialog() -> dict:
    outcome = {"action": None}
    _run(flows.manage_vault(outcome),
         lambda: "approved" if outcome["action"] is not None else "declined")
    return outcome


# --- the persistent app (opened by the person, never by a tool call) --------

APP_WINDOW_SIZE = (480, 840)
APP_MAX_LIFETIME = 12 * 3600.0


def vault_app() -> dict:
    """Open the Thyra Vault app and block until the person closes it."""
    from . import appflow
    from .. import clipboard
    limits = Limits(launch_timeout=LIMITS.launch_timeout, heartbeat_timeout=LIMITS.heartbeat_timeout,
                    closing_grace=LIMITS.closing_grace,
                    max_lifetime=max(LIMITS.max_lifetime, APP_MAX_LIFETIME),
                    max_bad_codes=LIMITS.max_bad_codes)
    outcome = {"closed": False}
    # SIGTERM / SIGHUP (closing the terminal) skip atexit: wipe the clipboard first.
    restore = clipboard.install_signal_handlers()
    try:
        server.run_flow(appflow.vault_app(outcome), status_of=lambda: "approved", limits=limits,
                        window_size=APP_WINDOW_SIZE)
    finally:
        restore()
    return outcome
