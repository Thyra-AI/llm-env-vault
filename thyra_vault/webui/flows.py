"""The browser dialogs' logic, one generator per dialog.

Each flow is a coroutine in the plain-generator sense: it ``yield``s a screen
(see schema.py) and is resumed with the human's :class:`Act` -- which button
they pressed and the values in the form. The flow decides what to show next,
and finally returns. Because a flow only ever sees ``Act`` objects, every one
of them can be driven from a test with no browser, no network and no display.

They keep the security contract the dialogs always had:

  * the master password and every decrypted value stay inside this process --
    they live in a flow's local variables and are never put in a screen;
  * a vault change is applied only inside the confirming action's handler,
    after the secrets are re-decrypted fresh (never from a snapshot taken when
    the dialog opened, which may be minutes stale);
  * a "partial failure" -- the vault changed but a follow-up write did not --
    is reported honestly, never swallowed;
  * a screen that writes or destroys something has no default action, so a
    held Enter cannot confirm it.

Each flow takes the ``outcome`` dict its public wrapper (webui/__init__.py)
returns. A closed tab or timeout simply ends the flow early, leaving
``outcome`` at its denied defaults -- the same as closing the window.
"""
import hashlib
from pathlib import Path
from typing import Optional

from .. import store, trust
from ..crypto import (MalformedRecoveryKey, VaultCorrupted, WrongPassword,
                      format_recovery_key, new_recovery_key, parse_recovery_key)
from ..uihelpers import (MIN_PASSWORD_LEN, _CLIPBOARD_CLEAR_SECONDS,
                         _applicable_manage_actions, _collapse_whitespace,
                         _disclosure_mismatch, _format_bytes, _parse_rk_input,
                         _password_rejection_reason, _safe_display, _shorten_path)
from .schema import (action, check_field, code, code_lines, copy_button, items,
                     key_box, menu, msg, notice, password_field, raw_error,
                     raw_notice, screen, text, text_field)


class Act:
    """What the human did on a screen: a button id plus the form's values."""
    __slots__ = ("id", "values")

    def __init__(self, action_id: str, values: Optional[dict] = None):
        self.id = action_id
        self.values = values if isinstance(values, dict) else {}


def _s(act: Act, name: str) -> str:
    v = act.values.get(name)
    return v if isinstance(v, str) else ""


def _b(act: Act, name: str) -> bool:
    return act.values.get(name) is True


# --- shared error mapping -------------------------------------------------

def _password_issue(pw: str) -> Optional[dict]:
    """Why ``pw`` cannot be used, as a translatable error -- or None.

    The *decision* is uihelpers._password_rejection_reason, the single source
    of truth for the policy; this only picks which translated message fits.
    """
    if not _password_rejection_reason(pw):
        return None
    if not pw:
        return msg("errors.emptyPassword")
    if len(pw) < MIN_PASSWORD_LEN:
        return msg("errors.minLength", min=MIN_PASSWORD_LEN)
    return msg("errors.commonPassword")


def _vault_error(exc) -> dict:
    return msg("errors.vault", message=_safe_display(exc, 500))


def _save_failed(exc) -> dict:
    return msg("errors.saveFailed", message=_safe_display(exc, 500))


def _cancel(label="common.cancel"):
    return action("cancel", label)


# --- recovery key ---------------------------------------------------------

def _key_rows(key_text: str) -> list:
    """Lay the key out for copying by hand: three groups of four per row.

    Includes a hazard note: strip the
    ``RK1`` PREFIX only. A blanket replace would also eat any "RK1" that
    occurs inside the key data -- Crockford base32 produces those by chance --
    and the human would write down a key that can never open the vault.
    """
    stripped = key_text.strip()
    body = stripped[3:] if stripped.upper().startswith("RK1") else stripped
    groups = [g for g in body.replace("-", " ").split() if g]
    if groups and all(len(g) == 4 for g in groups):
        return ["RK1"] + ["  ".join(groups[i:i + 3]) for i in range(0, len(groups), 3)]
    # The pretty form would be lying about the key: show the canonical string.
    return [stripped]


def recovery_key(key_text: str, slot_id: str, result: list):
    """Show a newly issued recovery key and run the write-it-down drill.

    ``result[0]`` becomes True only when the box is ticked AND the whole key is
    re-entered correctly (checksum-verified, compared byte for byte).
    """
    stripped = key_text.strip()
    blocks = [notice("warning", "recoveryKey.warning")]
    if slot_id:
        blocks.append(text("recoveryKey.slot", muted=True, id=_safe_display(slot_id)))
    blocks += [
        key_box(_key_rows(key_text)),
        text("recoveryKey.groups", muted=True),
        copy_button(stripped, _CLIPBOARD_CLEAR_SECONDS),
        text("recoveryKey.steps"),
    ]
    error = None
    while True:
        act = yield screen(
            "recoveryKey.title", icon="file-text", blocks=blocks,
            fields=[check_field("written", "recoveryKey.written"),
                    text_field("reentry", "recoveryKey.reentry", mono=True, autofocus=False)],
            actions=[action("later", "recoveryKey.later"),
                     action("confirm", "recoveryKey.confirm", variant="primary")],
            error=error)
        if act.id != "confirm":
            return
        if not _b(act, "written"):
            error = msg("errors.checkWritten")
            continue
        typed = _s(act, "reentry")
        if not typed.strip():
            error = msg("errors.reenterKey")
            continue
        typed_raw = displayed_raw = None
        try:
            typed_raw, parse_err = _parse_rk_input(typed)
            if parse_err or typed_raw is None:
                error = raw_error(parse_err or "Could not read recovery key.")
                continue
            try:
                displayed_raw = parse_recovery_key(key_text)
            except MalformedRecoveryKey:
                error = msg("errors.keyInternal")
                continue
            if bytes(typed_raw) != bytes(displayed_raw):
                error = msg("errors.keyMismatch")
                continue
            result[0] = True
            return
        except Exception:  # noqa: BLE001 -- never let an exception surface key material
            error = msg("errors.keyUnexpected")
        finally:
            # Best-effort in CPython; does not defeat a memory dump.
            for buf in (typed_raw, displayed_raw):
                if buf is not None:
                    for i in range(len(buf)):
                        buf[i] = 0


def _recovery_drill():
    """Generate a recovery key and make the human write it down. Returns the
    raw key bytes if they confirmed, or None. Nothing is written here."""
    raw = new_recovery_key()
    try:
        result = [False]
        yield from recovery_key(format_recovery_key(bytes(raw)), "", result)
        return bytes(raw) if result[0] else None
    finally:
        for i in range(len(raw)):
            raw[i] = 0


# --- step 1 shared by add_secret and install ------------------------------

def _create_or_unlock(state: dict, intro: list):
    """Master password step. When no vault exists yet the human *creates* one
    (password twice, optional paper recovery key); otherwise they unlock it.
    Returns True to continue, False if they cancelled."""
    error = None
    while True:
        first = state["first_run"]
        fields = [password_field("password", "fields.masterPassword", new=first,
                                 strength=first, autofocus=True)]
        blocks = list(intro)
        if first:
            blocks.append(text("setup.intro", min=MIN_PASSWORD_LEN))
            fields += [password_field("confirm", "fields.confirmPassword", new=True, toggle=False),
                       check_field("recovery", "setup.recovery")]
        act = yield screen(
            "setup.title" if first else "unlock.title", icon="lock", step=(1, 2),
            blocks=blocks, fields=fields,
            actions=[_cancel(), action("continue", "common.continue", variant="primary")],
            default_action="continue", error=error)
        if act.id != "continue":
            return False
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        if first:
            error = _password_issue(password)
            if error:
                continue
            if password != _s(act, "confirm"):
                error = msg("errors.passwordMismatch")
                continue
            state["password"] = password
            state["secrets"] = {}
            if _b(act, "recovery"):
                # Recovery setup belongs with the password decision, not after
                # an unrelated Allow several steps later.
                state["recovery_raw"] = yield from _recovery_drill()
            return True
        try:
            state["secrets"] = store.load_secrets(password)
        except WrongPassword as e:
            error = raw_error(e)
            continue
        except (FileNotFoundError, ValueError) as e:
            error = _vault_error(e)
            continue
        state["password"] = password
        return True


def _unlock_only(state: dict, intro: list, *, title="unlock.title", icon="lock",
                 verify=None):
    """Master password step for dialogs that never create a vault. ``verify``
    runs after a successful decrypt and may return an error to stay on this
    screen. Returns True to continue, False if cancelled."""
    error = None
    while True:
        act = yield screen(
            title, icon=icon, step=(1, 2), blocks=list(intro),
            fields=[password_field("password", "fields.masterPassword", autofocus=True)],
            actions=[_cancel(), action("continue", "common.continue", variant="primary")],
            default_action="continue", error=error)
        if act.id != "continue":
            return False
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        try:
            secrets = store.load_secrets(password)
        except WrongPassword as e:
            error = raw_error(e)
            continue
        except (FileNotFoundError, ValueError) as e:
            error = _vault_error(e)
            continue
        state["password"] = password
        state["secrets"] = secrets
        if verify is not None:
            error = verify(state)
            if error:
                continue
        return True


def _create_vault_now(state: dict) -> None:
    """Create the first-run v2 vault (one to two scrypt rounds: slow)."""
    store.create_v2_vault(state["password"], recovery_raw=state.get("recovery_raw"))


# --- add / remove / retype ------------------------------------------------

def add_secret(outcome, var_name, is_update, placeholder, is_sensitive):
    state: dict = {"password": None, "secrets": None, "first_run": not store.vault_exists(),
             "recovery_raw": None}
    var = _safe_display(var_name)
    intro = [text("add.aboutUpdate" if is_update else "add.aboutAdd", name=var)]
    while True:
        if not (yield from _create_or_unlock(state, intro)):
            return
        # An update shows no "current value": decrypted secrets are not sent to
        # the browser. The snapshot is kept server-side only, to detect a vault
        # that changed while this dialog sat open.
        current = (state.get("secrets") or {}).get(var_name) if is_update else None
        error = None
        while True:
            blocks = [text("confirmAdd.proposalUpdate" if is_update else "confirmAdd.proposalAdd",
                           name=var),
                      code(f'{var}="value {placeholder}"', label="confirmAdd.llmEnvReads"),
                      text("confirmAdd.note", muted=True)]
            if current is not None:
                blocks.append(notice("info", "confirmAdd.replaces"))
            if is_sensitive:
                blocks.append(notice("warning", "confirmAdd.override", name=var))
            act = yield screen(
                "confirmAdd.title", icon="plus", step=(2, 2), blocks=blocks,
                fields=[password_field("value", "fields.realValue", autofocus=True, name=var)],
                actions=[action("back", "common.back"), action("deny", "common.deny"),
                         action("allow", "common.allow", variant="primary")],
                default_action="allow", error=error)
            if act.id == "back":
                break
            if act.id != "allow":
                return
            value = _s(act, "value")
            if not value:
                error = msg("errors.valueEmpty")
                continue
            secrets_saved = False
            try:
                if state["first_run"]:
                    _create_vault_now(state)
                    state["first_run"] = False
                    secrets = {}
                else:
                    # Re-decrypt right now rather than reusing the dict from
                    # step 1: a stale in-memory copy re-encrypted over the real
                    # file would silently erase anything saved meanwhile.
                    secrets = store.load_secrets(state["password"])
                    if current is not None and secrets.get(var_name) != current:
                        error = msg("errors.changedWhileOpen", name=var)
                        continue
                secrets[var_name] = value
                store.save_secrets(state["password"], secrets)
                secrets_saved = True
                index = store.load_index()
                index[var_name] = index.get(var_name, store.next_placeholder(index))
                store.save_index(index)
            except Exception as e:  # noqa: BLE001 -- a broad catch on purpose: any failure is shown to the human
                if secrets_saved:
                    outcome["partial_failure"] = (
                        f"Saved to the vault, but could not update "
                        f"vault_index.json/llm.env: {e}. The real value IS in the "
                        f"vault now; fix the problem and call add_secret again "
                        f"(or sync_llm_env) to finish linking it to a placeholder.")
                    error = msg("errors.addPartial", message=_safe_display(e, 500))
                else:
                    error = _save_failed(e)
                continue
            outcome["approved"] = True
            return


def remove_secret(outcome, var_name, placeholder):
    state: dict = {"password": None, "secrets": None}
    var = _safe_display(var_name)
    while True:
        if not (yield from _unlock_only(state, [text("remove.about", name=var)])):
            return
        error = None
        while True:
            act = yield screen(
                "confirmRemove.title", icon="trash", step=(2, 2), tone="danger",
                blocks=[text("confirmRemove.proposal", name=var),
                        code(f'{var}="value {placeholder}"', label="confirmRemove.llmEnvEntry"),
                        notice("danger", "confirmRemove.irreversible")],
                actions=[action("deny", "common.deny"),
                         action("allow", "confirmRemove.allow", variant="danger")],
                error=error)
            if act.id != "allow":
                return
            secrets_saved = False
            try:
                secrets = store.load_secrets(state["password"])
                secrets.pop(var_name, None)
                store.save_secrets(state["password"], secrets)
                secrets_saved = True
                index = store.load_index()
                index.pop(var_name, None)
                store.save_index(index)
            except Exception as e:  # noqa: BLE001
                if secrets_saved:
                    outcome["partial_failure"] = (
                        f"The secret was already removed from the vault (this "
                        f"cannot be undone), but vault_index.json/llm.env could "
                        f"not be updated: {e}. They will incorrectly still show a "
                        f"placeholder for a value that no longer exists -- call "
                        f"remove_secret again to clean that up, or edit "
                        f"vault_index.json by hand.")
                    error = msg("errors.removePartial", message=_safe_display(e, 500))
                else:
                    error = _save_failed(e)
                continue
            outcome["approved"] = True
            return


def retype_placeholders(outcome, names):
    state: dict = {"password": None, "secrets": None, "plan": {}}

    def build_plan(st):
        st["plan"] = {n: store.infer_shape(st["secrets"][n]) for n in names if n in st["secrets"]}
        return None if st["plan"] else msg("errors.noneInVault")

    intro = [text("retype.about", count=len(names)),
             text("retype.why", muted=True)]
    if not (yield from _unlock_only(state, intro, icon="variable", verify=build_plan)):
        return
    index = store.load_index()
    lines = [f"{_safe_display(n)}={store.render_placeholder(index.get(n, 1), state['plan'][n])}"
             for n in sorted(state["plan"])]
    blocks = [text("typed.description"), code_lines(lines)]
    leaks = sorted({s.split(":")[0] for s in state["plan"].values() if s != store.SHAPE_STR})
    if leaks:
        blocks.append(notice("warning", "typed.leaks", kinds=", ".join(leaks)))
    error = None
    while True:
        act = yield screen(
            "typed.title", icon="variable", step=(2, 2), blocks=blocks,
            actions=[_cancel(), action("allow", "common.allow", variant="primary")],
            error=error)
        if act.id != "allow":
            return
        try:
            store.record_shapes(state["plan"])
            store.set_placeholder_style(store.STYLE_TYPED)
        except (OSError, ValueError) as e:
            error = msg("errors.recordTypes", message=_safe_display(e, 500))
            continue
        outcome["retyped"] = dict(state["plan"])
        outcome["approved"] = True
        # Rewrite the registered files to match what was just approved. A
        # failure is reported, not swallowed: the vault now says "typed" while
        # some file may still say otherwise, and the user must know which.
        try:
            index_now = store.load_index()
            shapes_now = store.load_shapes()
            for path_str, names_for_path in store.load_targets().items():
                try:
                    conflicts = store.sync_target_file(
                        Path(path_str), index_now, names_for_path, shapes=shapes_now)
                except (OSError, ValueError) as e:
                    outcome["conflicts"].setdefault(path_str, []).append(f"error: {e}")
                    continue
                if conflicts:
                    outcome["conflicts"][path_str] = conflicts
        except (OSError, ValueError) as e:
            outcome["partial_failure"] = (
                f"The types were recorded, but the registered files could not be "
                f"rewritten: {e}. Run resync_targets once that is fixed.")
        return


# --- install --------------------------------------------------------------

def install(outcome, target, to_migrate, other_owner, also_register, sensitive_names):
    state: dict = {"password": None, "secrets": None, "first_run": not store.vault_exists(),
             "recovery_raw": None}
    intro = [text("install.aboutMigrate" if to_migrate else "install.aboutRegister",
                  count=len(to_migrate)),
             code(target)]
    names_all = [name for name, _ in to_migrate]
    while True:
        if not (yield from _create_or_unlock(state, intro)):
            return
        if to_migrate:
            # Collisions with another project's vault entry go first so they
            # are visible without scrolling, never buried below the fold.
            display = [n for n, _ in sorted(to_migrate, key=lambda nv: nv[0] not in other_owner)]
        else:
            display = sorted(also_register)
        rows = [{"text": n,
                 "tag": msg("install.overwrites", path=_shorten_path(other_owner[n], 40))
                 if n in other_owner else None} for n in display]
        blocks = [text("install.migrateWill", count=len(to_migrate)) if to_migrate
                  else text("install.registerWill", file=_safe_display(Path(target).name)),
                  items(rows, label="install.variables")]
        if other_owner:
            blocks.append(notice("warning", "install.overwriteWarning", count=len(other_owner),
                                 names=_collapse_whitespace(", ".join(sorted(other_owner)))))
        sensitive = sorted(n for n in names_all if n in sensitive_names)
        if sensitive:
            blocks.append(notice("warning", "install.sensitiveWarning",
                                 names=_collapse_whitespace(", ".join(sensitive))))
        blocks.append(text("install.cancelNote", muted=True))
        error = None
        while True:
            act = yield screen(
                "install.confirmMigration" if to_migrate else "install.confirmRegistration",
                icon="download", step=(2, 2), blocks=blocks,
                actions=[action("back", "common.back"), action("deny", "common.deny"),
                         action("allow", "common.allow", variant="primary")],
                error=error)
            if act.id == "back":
                break
            if act.id != "allow":
                return
            vault_saved = False
            try:
                if state["first_run"]:
                    _create_vault_now(state)
                    state["first_run"] = False
                    secrets = {}
                else:
                    secrets = store.load_secrets(state["password"])
                # Re-read the target right now rather than trusting the values
                # captured when this dialog opened: it can sit open for minutes
                # and force_names below overwrites the file unconditionally.
                fresh_parsed, fresh_styles = store.parse_env_file_with_styles(target)
                fresh = {item[1]: item[2] for item in fresh_parsed if item[0] == "var"}
                index = store.load_index()
                shapes = store.load_shapes()
                for name, original_value in to_migrate:
                    fresh_value = fresh.get(name)
                    # Never treat an empty value, or something that already
                    # looks like one of our own placeholders, as a real secret.
                    if fresh_value and not store.is_placeholder(name, fresh_value, index, shapes):
                        secrets[name] = fresh_value
                    else:
                        secrets[name] = original_value
                    if name not in index:
                        index[name] = store.next_placeholder(index)
                store.save_secrets(state["password"], secrets)
                store.save_index(index)
                vault_saved = True
                all_names = names_all + [n for n in also_register if n not in names_all]
                store.add_target(str(target), all_names)
                store.record_target_styles(
                    str(target), {n: fresh_styles[n] for n in names_all if n in fresh_styles})
                outcome["conflicts"] = store.sync_target_file(
                    target, index, set(all_names), force_names=set(names_all))
            except Exception as e:  # noqa: BLE001
                if vault_saved:
                    outcome["partial_failure"] = (
                        f"Saved to the vault, but could not rewrite {target.name}: "
                        f"{e}. The real values are safe; fix the problem and call "
                        f"resync_targets.")
                    error = msg("errors.installPartial", file=_safe_display(target.name),
                                message=_safe_display(e, 500))
                else:
                    error = _save_failed(e)
                continue
            outcome["approved"] = True
            return


# --- whole-file encryption ------------------------------------------------

def encrypt_file(outcome, path):
    path = Path(path)
    state: dict = {"password": None, "info": None, "resume": False}
    error = None
    while True:
        # step 1: unlock
        act = yield screen(
            "encrypt.unlockTitle", icon="file-lock", step=(1, 2),
            blocks=[code(path, label="fields.fileToEncrypt")],
            fields=[password_field("password", "fields.masterPassword", autofocus=True)],
            actions=[_cancel(), action("continue", "common.continue", variant="primary")],
            default_action="continue", error=error)
        if act.id != "continue":
            return
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        try:
            # Verify by decrypting, the pattern every other dialog uses. NOT
            # get_or_create_fmk: minting writes to the vault, and nothing may be
            # written before Allow.
            store.load_secrets(password)
            info = store.precheck_encrypt(path)
        except WrongPassword as e:
            error = raw_error(e)
            continue
        except (FileNotFoundError, ValueError, OSError) as e:
            error = raw_error(e)
            continue
        state["resume"] = False
        if info["sidecar_exists"]:
            # Crash limbo: a verified sidecar beside an intact original. Offer
            # to finish only if it really holds this file.
            if store._sidecar_matches(info["vault_path"], password,
                                      hashlib.sha256(info["path"].read_bytes()).hexdigest()):
                state["resume"] = True
            else:
                error = msg("errors.sidecarMismatch", name=_safe_display(info["vault_path"].name))
                continue
        state["password"], state["info"] = password, info
        error = None

        # step 2: confirm
        blocks = []
        if state["resume"]:
            blocks.append(notice("warning", "encrypt.resume"))
        blocks += [code(info["path"], label="fields.fileToEncrypt"),
                   text("fields.sizePerms", muted=True, size=_format_bytes(info["size"]),
                        mode=info["mode"]),
                   code(info["vault_path"], label="fields.encryptedCopy"),
                   notice("danger", "encrypt.destroyed", name=_safe_display(info["path"].name, 60)),
                   notice("warning", "encrypt.overwriteCaveat"),
                   notice("warning", "encrypt.durabilityCaveat"),
                   text("encrypt.gitSafe", muted=True)]
        while True:
            act = yield screen(
                "encrypt.resumeTitle" if state["resume"] else "encrypt.title",
                icon="file-lock", step=(2, 2), tone="danger", blocks=blocks,
                actions=[action("back", "common.back"), action("deny", "common.deny"),
                         action("allow", "common.allow", variant="danger")],
                error=error)
            if act.id == "back":
                error = None
                break
            if act.id != "allow":
                return
            try:
                result = store.encrypt_file_in_place(
                    state["info"]["path"], state["password"], allow_resume=state["resume"])
            except Exception as e:  # noqa: BLE001
                error = msg("errors.encryptFailed", message=_safe_display(e, 500))
                continue
            outcome["result"] = result
            if not result.get("original_destroyed"):
                # The ciphertext is good and registered; only the removal failed.
                # WHICH half failed decides what the user should do, and getting
                # it wrong is dangerous: calling a random-byte husk "the real
                # secret" invites them to delete the .levault, the only copy.
                if result.get("not_destroyed_reason"):
                    error = raw_error(result["not_destroyed_reason"])
                    outcome["partial_failure"] = result["not_destroyed_reason"]
                elif result.get("original_overwritten"):
                    error = msg("errors.leftoverOverwritten", name=_safe_display(result["original_name"]))
                    outcome["partial_failure"] = (
                        f"The encrypted copy was written and verified. The original "
                        f"{result['original_name']} was overwritten with random bytes "
                        f"but could not be deleted (it may be open in another "
                        f"program). It no longer contains your secret -- the "
                        f".levault file does. Delete the leftover yourself.")
                else:
                    error = msg("errors.leftoverIntact", name=_safe_display(result["original_name"]))
                    outcome["partial_failure"] = (
                        f"The encrypted copy was written and verified, but the "
                        f"original {result['original_name']} could NOT be removed "
                        f"(it may be open in another program). It still contains "
                        f"the real secret -- close whatever is holding it and "
                        f"delete it yourself. Your data is safe either way: the "
                        f".levault file is complete and verified.")
                continue
            outcome["approved"] = True
            return


def decrypt_file(outcome, vault_path, output_path):
    vault_path = Path(vault_path)
    state: dict = {"password": None, "info": None, "meta": None, "size": None}
    error = None
    while True:
        act = yield screen(
            "decrypt.unlockTitle", icon="file-unlock", step=(1, 2),
            blocks=[code(vault_path, label="fields.encryptedFile")],
            fields=[password_field("password", "fields.masterPassword", autofocus=True)],
            actions=[_cancel(), action("continue", "common.continue", variant="primary")],
            default_action="continue", error=error)
        if act.id != "continue":
            return
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        try:
            info = store.precheck_decrypt(vault_path, output_path)
            # Open it now so step 2 can state the real size, permissions and
            # original name rather than the registry's version of them.
            file_bytes, meta = store.read_encrypted_file(info["vault_path"], password)
        except WrongPassword as e:
            error = raw_error(e)
            continue
        except (FileNotFoundError, ValueError, OSError, VaultCorrupted) as e:
            error = raw_error(e)
            continue
        state.update(password=password, info=info, meta=meta, size=len(file_bytes))
        error = None
        blocks = [code(info["vault_path"], label="fields.encryptedFile"),
                  code(info["output_path"], label="fields.restoredTo"),
                  text("fields.permsRestored", muted=True, size=_format_bytes(state["size"]),
                       mode=meta.get("mode", "unknown"))]
        stored_name = meta.get("name")
        if stored_name and stored_name != info["output_path"].name:
            blocks.append(notice("warning", "decrypt.renamed", name=_safe_display(stored_name, 60)))
        blocks += [notice("warning", "decrypt.warn"), text("decrypt.leftInPlace", muted=True)]
        while True:
            act = yield screen(
                "decrypt.title", icon="file-unlock", step=(2, 2), blocks=blocks,
                actions=[action("back", "common.back"), action("deny", "common.deny"),
                         # primary, not danger: this creates a file rather than
                         # destroying one; the risk is carried by the warning.
                         action("allow", "common.allow", variant="primary")],
                error=error)
            if act.id == "back":
                error = None
                break
            if act.id != "allow":
                return
            try:
                result = store.decrypt_file_to(
                    state["info"]["vault_path"], state["password"],
                    output_path=str(state["info"]["output_path"]))
            except Exception as e:  # noqa: BLE001
                error = msg("errors.decryptFailed", message=_safe_display(e, 500))
                continue
            outcome["approved"] = True
            outcome["result"] = result
            return


def confirm_abandon_files(outcome, outstanding, registry_names):
    ids = [(gen, fid) for gen, group in sorted(outstanding.items()) for fid in group]
    rows = []
    for gen, fid in ids:
        label = registry_names.get(fid)
        # The name is a hint from a registry an agent can edit, so it is shown
        # as supplementary to the identity rather than instead of it.
        shown = f"{label}  ({fid[:12]}...)" if label else f"unknown file  ({fid[:12]}...)"
        rows.append({"text": f"{shown}  [key {gen}]"})
    error = None
    while True:
        act = yield screen(
            "abandon.title", icon="alert-triangle", tone="danger",
            blocks=[notice("danger", "abandon.warning", count=len(ids)),
                    text("abandon.onlyIf"),
                    items(rows),
                    text("abandon.otherwise", muted=True)],
            fields=[check_field("confirm", "abandon.confirm")],
            # Never Enter-to-confirm on a screen that destroys data irrecoverably.
            actions=[_cancel(), action("abandon", "abandon.action", variant="danger")],
            error=error)
        if act.id != "abandon":
            return
        if not _b(act, "confirm"):
            error = msg("errors.confirmRequired")
            continue
        outcome["abandon"] = [fid for _gen, fid in ids]
        return


# --- run a command --------------------------------------------------------

def unlock_for_run(outcome, command_str, materialize_path, only_vars, trust_note, files,
                   max_reads, cwd=None, executable=None):
    if only_vars is not None:
        var_names = sorted(only_vars)
    else:
        try:
            var_names = sorted(store.load_index().keys())
        except (OSError, UnicodeDecodeError, ValueError):
            var_names = []  # a safe default: the disclosure list is just empty

    blocks = []
    if trust_note:
        blocks.append(raw_notice("warning", trust_note))
    blocks.append(text("unlockRun.expose", count=len(var_names)))
    if var_names:
        blocks.append(items([{"text": n} for n in var_names]))
    blocks += [text("unlockRun.output", muted=True), code(command_str, label="fields.command")]
    # Where it runs and which program that really is: the command line alone does not
    # say, and relative programs, Makefiles and package.json resolve against the folder.
    if cwd:
        blocks.append(code(cwd, label="unlockRun.cwd"))
    if executable:
        blocks.append(code(executable, label="unlockRun.executable"))
    if files:
        blocks += [items([{"text": str(restore)} for _vault, restore in files],
                         label="unlockRun.files", count=len(files)),
                   text("unlockRun.filesCleanup", muted=True),
                   notice("warning", "unlockRun.notRedacted")]
    if materialize_path:
        blocks += [code(materialize_path, label="unlockRun.materialize"),
                   text("unlockRun.materializeOnce", muted=True, count=max_reads)
                   if max_reads else text("unlockRun.materializeExit", muted=True)]

    fields = [password_field("password", "fields.masterPassword", autofocus=True)]
    if files:
        # No trust offer at all for a run that writes decrypted files to disk:
        # an unattended grant would let a private key be written out repeatedly
        # with no human present. Say why, rather than silently omitting it.
        blocks.append(text("unlockRun.noTrustFiles", muted=True))
    else:
        fields.append(check_field("trust", "unlockRun.trust",
                                  hours=trust._TRUST_TTL_SECONDS // 3600))
    error = None
    while True:
        act = yield screen(
            "unlockRun.title", icon="lock", blocks=blocks, fields=fields,
            actions=[_cancel(), action("allow", "unlockRun.submit", variant="primary")],
            default_action="allow", error=error)
        if act.id != "allow":
            return
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        try:
            secrets = store.load_secrets(password)
        except WrongPassword as e:
            error = raw_error(e)
            continue
        except (FileNotFoundError, ValueError) as e:
            error = _vault_error(e)
            continue
        if only_vars is None:
            mismatch = _disclosure_mismatch(var_names, secrets.keys())
            if mismatch:
                error = raw_error(mismatch)
                continue
        if files:
            # Decrypt here, inside the Allow handler, and hand back only the
            # plaintext bytes: the file master key never crosses this boundary.
            decrypted = {}
            failed = None
            for _vault_path, _restore_path in files:
                try:
                    _bytes, _meta = store.read_encrypted_file(_vault_path, password)
                except Exception as e:  # noqa: BLE001
                    failed = msg("errors.decryptPath", path=_safe_display(_vault_path, 200),
                                 message=_safe_display(e, 300))
                    break
                decrypted[str(_vault_path)] = {
                    "name": _meta.get("name"), "mode": _meta.get("mode"),
                    "bytes": _bytes, "restore_path": str(_restore_path)}
            if failed:
                error = failed
                continue
            outcome["files"] = decrypted
        outcome["secrets"] = ({k: v for k, v in secrets.items() if k in only_vars}
                              if only_vars is not None else secrets)
        outcome["trust"] = _b(act, "trust") and not files
        return


# --- passwords and recovery -----------------------------------------------

def change_password(outcome):
    error = None
    while True:
        act = yield screen(
            "changePassword.title", icon="key",
            fields=[password_field("old", "fields.currentPassword", autofocus=True),
                    password_field("new", "fields.newPassword", new=True, strength=True,
                                   min=MIN_PASSWORD_LEN),
                    password_field("confirm", "fields.confirmNewPassword", new=True, toggle=False)],
            actions=[_cancel(), action("change", "changePassword.submit", variant="primary")],
            default_action="change", error=error)
        if act.id != "change":
            return
        old, new, confirm = _s(act, "old"), _s(act, "new"), _s(act, "confirm")
        if not old:
            error = msg("errors.currentEmpty")
            continue
        error = _password_issue(new)
        if error:
            continue
        if new != confirm:
            error = msg("errors.newMismatch")
            continue
        outcome["old"], outcome["new"] = old, new
        return


def recover(outcome):
    error = None
    while True:
        act = yield screen(
            "recover.title", icon="life-buoy", tone="warning",
            blocks=[notice("warning", "recover.warning")],
            fields=[text_field("key", "fields.recoveryKey", mono=True, autofocus=True,
                               placeholder="RK1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"),
                    password_field("new", "fields.newPassword", new=True, strength=True,
                                   min=MIN_PASSWORD_LEN),
                    password_field("confirm", "fields.confirmNewPassword", new=True, toggle=False)],
            actions=[_cancel(), action("recover", "recover.submit", variant="primary")],
            default_action="recover", error=error)
        if act.id != "recover":
            return
        rk_text, new, confirm = _s(act, "key"), _s(act, "new"), _s(act, "confirm")
        if not rk_text.strip():
            error = msg("errors.recoveryEmpty")
            continue
        error = _password_issue(new)
        if error:
            continue
        if new != confirm:
            error = msg("errors.passwordMismatch")
            continue
        # Validate the checksum before returning: a friendly message for a
        # transcription error instead of an opaque failure in the caller.
        parsed = None
        try:
            parsed, parse_err = _parse_rk_input(rk_text)
            if parse_err:
                error = raw_error(parse_err)
                continue
            outcome["recovery_key"] = rk_text.strip()
            outcome["new_password"] = new
            return
        except Exception:  # noqa: BLE001
            error = msg("errors.recoveryUnexpected")
        finally:
            if parsed is not None:
                for i in range(len(parsed)):
                    parsed[i] = 0


# --- vault settings -------------------------------------------------------

_MANAGE_ICONS = {
    "change_password": "key", "upgrade_v2": "refresh", "setup_recovery": "file-text",
    "reissue_recovery": "file-text", "rotate_file_key": "file-lock", "retire_file_keys": "trash",
}
_MANAGE_ORDER = ["change_password", "upgrade_v2", "setup_recovery", "reissue_recovery",
                 "rotate_file_key", "retire_file_keys"]


def manage_vault(outcome):
    try:
        info = store.vault_info()
    except Exception as exc:  # noqa: BLE001
        info = {"error": str(exc)}
    try:
        encrypted_file_count = len(store.load_file_registry())
    except (OSError, ValueError):
        encrypted_file_count = 0
    actions = _applicable_manage_actions(info, encrypted_file_count)
    fmt = info.get("format")

    status = []
    if "error" in info:
        status.append(raw_notice("danger", f"Vault status: {_safe_display(info['error'])}"))
    else:
        status.append(text("manage.format", muted=True, version=fmt if fmt else "?"))
        if fmt == 2:
            if info.get("recovery_slot", False):
                status.append(text("manage.recoveryActive", muted=True,
                                   id=_safe_display(info.get("recovery_slot_id", "")) or "-",
                                   created=_safe_display(info.get("recovery_slot_created", "")) or "-"))
            else:
                status.append(text("manage.recoveryNone", muted=True))

    while True:
        entries = [{"id": a, "icon": _MANAGE_ICONS[a], "label": msg(f"manage.titles.{a}")}
                   for a in _MANAGE_ORDER if a in actions]
        blocks = status + ([menu(entries)] if entries else [text("manage.noActions")])
        act = yield screen("manage.title", icon="shield", blocks=blocks,
                           actions=[action("close", "common.close")])
        if not act.id.startswith("menu:"):
            return
        chosen = act.id[len("menu:"):]
        if chosen not in actions:
            continue
        done = yield from _manage_action(outcome, chosen, encrypted_file_count)
        if done:
            return


def _manage_action(outcome, chosen, encrypted_file_count):
    """One manage_vault action form. Returns True when the dialog is finished."""
    blocks = []
    tone = "default"
    if chosen == "upgrade_v2":
        blocks.append(notice("warning", "manage.warnUpgrade"))
    elif chosen == "setup_recovery":
        blocks.append(text("manage.infoSetupRecovery", muted=True))
    elif chosen == "rotate_file_key":
        blocks.append(notice("warning", "manage.warnRotate", count=encrypted_file_count))
    elif chosen == "retire_file_keys":
        blocks.append(notice("danger", "manage.warnRetire"))
        tone = "danger"
    elif chosen == "reissue_recovery":
        blocks.append(notice("warning", "manage.warnReissue"))

    error = None
    while True:
        if chosen == "change_password":
            fields = [password_field("old", "fields.currentPassword", autofocus=True),
                      password_field("new", "fields.newPassword", new=True, strength=True,
                                     min=MIN_PASSWORD_LEN),
                      password_field("confirm", "fields.confirmNewPassword", new=True, toggle=False)]
            confirm_label, variant, default = "changePassword.submit", "primary", "confirm"
        else:
            fields = [password_field("password", "fields.masterPassword", autofocus=True)]
            confirm_label = f"manage.confirm.{chosen}"
            variant = "danger" if chosen == "retire_file_keys" else "primary"
            # The one action here that can permanently destroy data: never
            # Enter-to-confirm. Everything else is recoverable or additive.
            default = None if chosen == "retire_file_keys" else "confirm"
        act = yield screen(
            f"manage.titles.{chosen}", icon=_MANAGE_ICONS[chosen], tone=tone, blocks=blocks,
            fields=fields,
            actions=[action("back", "common.back"), action("confirm", confirm_label, variant=variant)],
            default_action=default, error=error)
        if act.id != "confirm":
            return False
        if chosen == "change_password":
            old, new, confirm = _s(act, "old"), _s(act, "new"), _s(act, "confirm")
            if not old:
                error = msg("errors.currentEmpty")
                continue
            error = _password_issue(new)
            if error:
                continue
            if new != confirm:
                error = msg("errors.passwordMismatch")
                continue
            outcome.update(action="change_password", old_password=old, new_password=new)
            return True
        password = _s(act, "password")
        if not password:
            error = msg("errors.emptyPassword")
            continue
        outcome.update(action=chosen, password=password)
        return True
