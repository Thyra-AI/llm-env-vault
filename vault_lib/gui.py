"""Small Tkinter dialogs.

Two-step flow: first the master password (unlocking or creating the
vault), then -- only after that succeeds -- the proposed change and the
real value. Password verification happens inside the GUI process
itself, in the button handlers.

Security contract: add_secret_dialog / remove_secret_dialog return only
a plain approved/denied boolean to the calling code -- the password
and any decrypted values stay inside this process and are never printed
or returned. install_dialog returns a small outcome dict (keys:
"approved", "conflicts") rather than a plain bool so callers can learn
whether any conflict-protected lines were left unchanged. unlock_for_run_dialog
is the one deliberate exception that hands back the decrypted secrets
dict, because its whole job is to let the run_with_env MCP tool inject
real values into a child process's environment.
"""
import re
import tkinter as tk
from tkinter import ttk

from . import store
from .crypto import WrongPassword


def _safe_display(text, max_len: int = 200) -> str:
    """Collapses all whitespace (including newlines) to single spaces and
    hard-caps length. Applied to any text this module did not itself
    generate before it's rendered into a dialog, so attacker-controlled
    input (a command line, a process description) can never inject fake
    extra lines or grow tall/wide enough to push the real consent content
    and the Allow/Deny buttons off a non-resizable, non-scrolling window.
    """
    collapsed = re.sub(r"\s+", " ", str(text)).strip()
    if len(collapsed) <= max_len:
        return collapsed
    head = max_len // 2 - 2
    tail = max_len - head - 3
    if head < 0 or tail < 0:
        # Too small for a head...tail split with an ellipsis -- fall back
        # to a hard cut rather than slicing with a negative index (which
        # would silently wrap from the end and stop enforcing the cap).
        return collapsed[:max_len]
    return f"{collapsed[:head]}...{collapsed[-tail:]}"


def _collapse_whitespace(text) -> str:
    """Like _safe_display but with no length cap -- for content going into
    a horizontally-scrollable Text widget rather than a fixed-size Label,
    where truncating with an ellipsis would hide the middle of the very
    thing the human is being asked to approve (a caller can pad both ends
    with innocuous text specifically to bury the interesting part inside
    the elided middle). Still collapses newlines so attacker-controlled
    text can't fake extra lines that look like separate disclosures.
    """
    return re.sub(r"\s+", " ", str(text)).strip()

WINDOW_BG = "#1e1e1e"
FIELD_BG = "#2d2d2d"
FG = "#e8e8e8"
ACCENT = "#4c8bf5"

FONT_FAMILY = "Segoe UI"
FONT_BODY = (FONT_FAMILY, 11)
FONT_TITLE = (FONT_FAMILY, 14, "bold")

# Every widget in every dialog uses FONT_BODY (titles use FONT_TITLE: same
# family, just bold/larger for a heading) -- no other font is used anywhere
# in this module. _style() also forces it as the Tk-wide default so any
# widget that forgets to set one explicitly still can't end up on a
# different font.


def _style(root):
    root.configure(bg=WINDOW_BG)
    root.attributes("-topmost", True)
    root.option_add("*Font", FONT_BODY)


def _label(parent, text, **kw):
    kw.setdefault("fg", FG)
    kw.setdefault("wraplength", 460)
    kw.setdefault("font", FONT_BODY)
    return tk.Label(parent, text=text, bg=WINDOW_BG, **kw)


def _entry(parent, **kw):
    kw.setdefault("font", FONT_BODY)
    return tk.Entry(parent, bg=FIELD_BG, fg=FG, insertbackground=FG,
                     relief="flat", highlightthickness=1,
                     highlightbackground="#444", highlightcolor=ACCENT, **kw)


def _button(parent, **kw):
    kw.setdefault("font", FONT_BODY)
    kw.setdefault("relief", "flat")
    kw.setdefault("cursor", "hand2")
    return tk.Button(parent, **kw)


def _center(root):
    # Release any explicit geometry set by a previous step so the window's
    # requested size reflects the *current* content, not the last one.
    root.geometry("")
    root.update_idletasks()
    w, h = root.winfo_reqwidth(), root.winfo_reqheight()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")


def _show_error(root, err_label, text):
    # _center() was already called once when this screen was first laid
    # out, based on whatever text `err_label` held then (usually empty).
    # An explicit geometry, once set, doesn't grow to fit later content --
    # a longer error message set afterward (e.g. a save failure with a
    # real exception message) would otherwise wrap past the window's
    # fixed height and clip itself, and the buttons below it, off-screen.
    err_label.config(text=text)
    _center(root)


def add_secret_dialog(var_name: str, is_update: bool, placeholder: int,
                      is_sensitive: bool = False):
    """Step 1: master password. Step 2 (only after step 1 succeeds): the
    proposed change plus the real value, with Allow/Deny.
    Returns an outcome dict: {"approved": bool, "partial_failure": Optional[str]}.
    approved is True only on full success. partial_failure is set to an honest
    description when save_secrets succeeded but save_index/llm.env did not --
    in that case the real value IS in vault.enc even though approved is False.

    is_sensitive: when True, step 2 displays an amber warning that this
    variable name matches a well-known OS/runtime-critical env var and
    that run_with_env will override it for any command it launches.
    """
    store.validate_var_name(var_name)
    outcome = {"approved": False, "partial_failure": None}
    state = {"password": None, "secrets": None, "first_run": not store.vault_exists()}
    pad = {"padx": 14, "pady": 5}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        title = "Create Vault" if state["first_run"] else "Unlock Vault"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        verb = "update" if is_update else "add"
        _label(container, f"About to {verb} the secret for {var_name}.",
               justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        if state["first_run"]:
            _label(container, "No vault exists yet -- choose a master password\n"
                               "(at least 8 characters).", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            _label(container, "Confirm password:").grid(row=row, column=0, sticky="e", **pad)
            pw2 = _entry(container, show="*", width=30)
            pw2.grid(row=row, column=1, **pad)
            row += 1
        else:
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            pw2 = None

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_continue():
            password = pw1.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            if state["first_run"]:
                if len(password) < 8:
                    _show_error(root, err, "Use at least 8 characters.")
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["password"] = password
                state["secrets"] = {}
                show_step2()
                return
            try:
                state["secrets"] = store.load_secrets(password)
            except WrongPassword as e:
                _show_error(root, err, str(e))
                return
            except (FileNotFoundError, ValueError) as e:
                _show_error(root, err, f"Vault error: {e}")
                return
            state["password"] = password
            show_step2()

        def on_cancel():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Cancel", width=12, command=on_cancel).pack(side="left", padx=6)
        _button(btns, text="Continue", width=12, bg=ACCENT, fg="white",
                  activebackground=ACCENT, command=on_continue).pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw1.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        _label(container, "Confirm Change", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        verb = "Update" if is_update else "Add"
        proposal = (
            f"Proposed change:\n"
            f"  {verb} secret for  {var_name}\n"
            f'  llm.env will read:  {var_name}="value {placeholder}"\n'
            f"  The real value below is encrypted and never shown to the AI."
        )
        _label(container, proposal, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        ttk.Separator(container).grid(row=row, column=0, columnspan=2, sticky="ew", padx=14, pady=4)
        row += 1

        _label(container, f"Real value for {var_name}:").grid(row=row, column=0, sticky="e", **pad)
        val = _entry(container, show="*", width=30)
        val.grid(row=row, column=1, **pad)
        row += 1

        if is_sensitive:
            _label(container,
                   f"Warning: {var_name} overrides a system/runtime environment variable "
                   f"and could affect any command run_with_env launches later.",
                   fg="#ffb454", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_allow():
            value = val.get()
            if not value:
                _show_error(root, err, "Secret value cannot be empty.")
                return
            secrets_saved = False
            try:
                if state["first_run"]:
                    store.create_secrets_vault(state["password"])
                    state["first_run"] = False
                    secrets = {}
                else:
                    # Re-decrypt right now rather than reusing the dict
                    # captured back in step 1 -- this dialog can sit open
                    # for a while, and a stale in-memory copy re-encrypted
                    # over the real file would silently erase anything
                    # another operation saved to the vault in the meantime.
                    secrets = store.load_secrets(state["password"])
                secrets[var_name] = value
                store.save_secrets(state["password"], secrets)
                secrets_saved = True

                index = store.load_index()
                resolved_placeholder = index.get(var_name, store.next_placeholder(index))
                index[var_name] = resolved_placeholder
                store.save_index(index)
            except Exception as e:
                if secrets_saved:
                    msg = (
                        f"Saved to the vault, but could not update "
                        f"vault_index.json/llm.env: {e}. The real value IS in the "
                        f"vault now; fix the problem and call add_secret again "
                        f"(or sync_llm_env) to finish linking it to a placeholder."
                    )
                    outcome["partial_failure"] = msg
                    _show_error(root, err, msg)
                else:
                    _show_error(root, err, f"Failed to save: {e}")
                return
            outcome["approved"] = True
            root.destroy()

        def on_deny():
            root.destroy()

        def on_back():
            show_step1()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Back", width=10, command=on_back).pack(side="left", padx=4)
        _button(btns, text="Deny", width=10, command=on_deny).pack(side="left", padx=4)
        _button(btns, text="Allow", width=12, bg=ACCENT, fg="white",
                  activebackground=ACCENT, command=on_allow).pack(side="left", padx=4)
        root.bind("<Escape>", lambda e: on_deny())
        root.bind("<Return>", lambda e: on_allow())
        val.focus_force()
        _center(root)

    show_step1()
    root.mainloop()
    return outcome


def remove_secret_dialog(var_name: str, placeholder: int):
    outcome = {"approved": False, "partial_failure": None}
    state = {"password": None, "secrets": None}
    pad = {"padx": 14, "pady": 5}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        _label(container, "Unlock Vault", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _label(container, f"About to remove the secret for {var_name}.").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
        pw = _entry(container, show="*", width=30)
        pw.grid(row=row, column=1, **pad)
        row += 1

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_continue():
            password = pw.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            try:
                state["secrets"] = store.load_secrets(password)
            except WrongPassword as e:
                _show_error(root, err, str(e))
                return
            except (FileNotFoundError, ValueError) as e:
                _show_error(root, err, f"Vault error: {e}")
                return
            state["password"] = password
            show_step2()

        def on_cancel():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Cancel", width=12, command=on_cancel).pack(side="left", padx=6)
        _button(btns, text="Continue", width=12, bg=ACCENT, fg="white",
                  activebackground=ACCENT, command=on_continue).pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        _label(container, "Confirm Removal", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        proposal = (
            f"Proposed change:\n"
            f"  remove secret for  {var_name}\n"
            f'  llm.env entry  {var_name}="value {placeholder}"  will be deleted.'
        )
        _label(container, proposal, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_allow():
            secrets_saved = False
            try:
                # Re-decrypt now, not the copy captured in step 1 -- see
                # add_secret_dialog for why.
                secrets = store.load_secrets(state["password"])
                secrets.pop(var_name, None)
                store.save_secrets(state["password"], secrets)
                secrets_saved = True

                index = store.load_index()
                index.pop(var_name, None)
                store.save_index(index)
            except Exception as e:
                if secrets_saved:
                    msg = (
                        f"The secret was already removed from the vault (this "
                        f"cannot be undone), but vault_index.json/llm.env could "
                        f"not be updated: {e}. They will incorrectly still show a "
                        f"placeholder for a value that no longer exists -- call "
                        f"remove_secret again to clean that up, or edit "
                        f"vault_index.json by hand."
                    )
                    outcome["partial_failure"] = msg
                    _show_error(root, err, msg)
                else:
                    _show_error(root, err, f"Failed to save: {e}")
                return
            outcome["approved"] = True
            root.destroy()

        def on_deny():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Deny", width=12, command=on_deny).pack(side="left", padx=6)
        _button(btns, text="Allow", width=12, bg="#c94b4b", fg="white",
                  activebackground="#c94b4b", command=on_allow).pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_deny())
        # No <Return>-to-Allow here on purpose: unlike step 1 (Continue) or
        # add_secret_dialog's step 2 (gated by a required, empty-on-render
        # value field), this screen has no input to type into, so a held
        # or double-tapped Enter carrying over from step 1 could otherwise
        # fire the actual removal before the human has read this screen.
        # Rebind (don't just "not bind") -- root.bind is per-widget-per-
        # event, so without this, step 1's <Return> -> on_continue handler
        # stays active and fires against the Entry `clear()` already
        # destroyed, raising TclError inside the Tk callback.
        root.bind("<Return>", lambda e: None)
        _center(root)

    show_step1()
    root.mainloop()
    return outcome


def _shorten_path(text: str, max_len: int = 64) -> str:
    # targets.json paths are attacker-writable state (see load_targets), so
    # this goes through the same whitespace-collapse + hard-cap as any
    # other untrusted text before it's ever put in a dialog.
    return _safe_display(text, max_len)


def install_dialog(target, to_migrate, other_owner=None, also_register=None,
                   sensitive_names=None):
    """target: Path to the real .env being migrated.
    to_migrate: list of (var_name, real_value) pulled from that file.
    other_owner: optional {var_name: other_target_path} for names already
    claimed by a different registered target -- migrating will overwrite
    that other project's vault entry, so it's called out explicitly.
    also_register: names already in the vault (nothing new to migrate for
    them) that this target file also declares -- registered alongside
    to_migrate's names so the resync_targets tool tracks all of this
    file's variables, not just the ones that changed on this run.
    sensitive_names: optional set of names in to_migrate that match
    well-known OS/runtime-critical environment variable names; if any are
    present, step 2 shows an amber warning (non-blocking).
    Real values only ever live in this process's memory and inside the
    files this module writes -- they are never returned to the caller.
    Returns a dict {"approved": bool, "partial_failure": Optional[str],
    "conflicts": list} -- partial_failure is set to an honest description
    when the vault was saved but rewriting the target file failed (see
    add_secret_dialog for the same pattern); conflicts lists any lines the
    caller can learn were left unchanged because they didn't look like our
    own placeholder.
    """
    other_owner = other_owner or {}
    also_register = also_register or []
    sensitive_names = set(sensitive_names or ())
    outcome = {"approved": False, "partial_failure": None, "conflicts": []}
    state = {"password": None, "secrets": None, "first_run": not store.vault_exists()}
    pad = {"padx": 14, "pady": 5}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        title = "Create Vault" if state["first_run"] else "Unlock Vault"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        if to_migrate:
            _label(container, f"About to migrate {len(to_migrate)} variable(s) out of:").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
        else:
            _label(container, "About to register for future resync_targets:").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        path_frame = tk.Frame(container, bg=WINDOW_BG)
        path_text = tk.Text(path_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                            highlightthickness=1, highlightbackground="#444",
                            selectbackground=ACCENT, insertbackground=FG,
                            height=2, width=52, wrap="none")
        path_xscroll = tk.Scrollbar(path_frame, orient="horizontal", command=path_text.xview)
        path_text.config(xscrollcommand=path_xscroll.set)
        path_text.insert("end", _collapse_whitespace(str(target)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_xscroll.grid(row=1, column=0, sticky="ew")
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=14)
        row += 1

        if state["first_run"]:
            _label(container, "No vault exists yet -- choose a master password\n"
                               "(at least 8 characters).", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            _label(container, "Confirm password:").grid(row=row, column=0, sticky="e", **pad)
            pw2 = _entry(container, show="*", width=30)
            pw2.grid(row=row, column=1, **pad)
            row += 1
        else:
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            pw2 = None

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_continue():
            password = pw1.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            if state["first_run"]:
                if len(password) < 8:
                    _show_error(root, err, "Use at least 8 characters.")
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["password"] = password
                state["secrets"] = {}
                show_step2()
                return
            try:
                state["secrets"] = store.load_secrets(password)
            except WrongPassword as e:
                _show_error(root, err, str(e))
                return
            except (FileNotFoundError, ValueError) as e:
                _show_error(root, err, f"Vault error: {e}")
                return
            state["password"] = password
            show_step2()

        def on_cancel():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Cancel", width=12, command=on_cancel).pack(side="left", padx=6)
        _button(btns, text="Continue", width=12, bg=ACCENT, fg="white",
                activebackground=ACCENT, command=on_continue).pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw1.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        title = "Confirm Migration" if to_migrate else "Confirm Registration"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        if to_migrate:
            _label(container, "Clicking Allow will:", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
            _label(container,
                   f"  1. Encrypt the {len(to_migrate)} real value(s) below into vault.enc\n"
                   f"     (only readable with your master password).\n"
                   f"  2. Rewrite the file so each line below becomes VAR=\"value N\" --\n"
                   f"     that placeholder is all an AI assistant will ever see.",
                   justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
        else:
            _label(container,
                   f"No new secrets to migrate. Clicking Allow will register "
                   f"{_safe_display(target.name)} so future resync_targets calls keep "
                   f"it in sync for the variable(s) listed below.",
                   justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        _label(container, "Variables (select text below and press Ctrl+C to copy):").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        if to_migrate:
            # Collisions with another project's vault entry go first so they're
            # visible without scrolling, never buried below the fold.
            display_names = [name for name, _ in
                             sorted(to_migrate, key=lambda nv: nv[0] not in other_owner)]
            list_count = len(to_migrate)
        else:
            # Registration-only: show which variables this file will be tracked for.
            display_names = sorted(also_register)
            list_count = len(also_register)

        list_height = min(8, max(2, list_count))
        txt_frame = tk.Frame(container, bg=WINDOW_BG)
        txt = tk.Text(txt_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                      highlightthickness=1, highlightbackground="#444",
                      selectbackground=ACCENT, insertbackground=FG,
                      height=list_height, width=46, wrap="none")
        yscroll = tk.Scrollbar(txt_frame, orient="vertical", command=txt.yview)
        xscroll = tk.Scrollbar(txt_frame, orient="horizontal", command=txt.xview)
        txt.config(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        for name in display_names:
            label = name
            if name in other_owner:
                label += f"   [OVERWRITES value used by {_shorten_path(other_owner[name], 40)}]"
            txt.insert("end", label + "\n")
        txt.config(state="disabled")  # Text stays selectable/copyable even when disabled
        txt.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        # Always shown, not just when there are more rows than fit
        # vertically: the "[OVERWRITES value used by ...]" marker on a
        # collision line -- consent-relevant info about whose value is
        # about to be destroyed -- can exceed the box's width on its own.
        xscroll.grid(row=1, column=0, sticky="ew")
        txt_frame.grid_rowconfigure(0, weight=1)
        txt_frame.grid_columnconfigure(0, weight=1)
        txt_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=14)
        row += 1
        if list_count > list_height:
            _label(container, f"({list_count} total -- scroll to see the rest.)",
                   fg="#9a9a9a").grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
            row += 1

        if other_owner:
            # Bounded (unlike the scrollable list above, which is the real,
            # complete record of every collision) -- this is only a
            # secondary summary, so truncating it can't hide anything the
            # human couldn't already see by scrolling up.
            _label(container,
                   f"Warning: {len(other_owner)} name(s) above are already used by another "
                   f"registered project (listed first, scroll up if needed). Continuing will "
                   f"overwrite that project's vault value: "
                   f"{_safe_display(', '.join(sorted(other_owner)), 200)}",
                   fg="#ffb454", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        sensitive_in_migrate = sorted(n for n, _ in to_migrate if n in sensitive_names)
        if sensitive_in_migrate:
            _label(container,
                   f"Warning: {_safe_display(', '.join(sensitive_in_migrate), 200)} "
                   f"override(s) system/runtime environment variable(s) -- any command "
                   f"run_with_env launches later will see the vaulted value instead of "
                   f"the real system value.",
                   fg="#ffb454", justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        _label(container, "Deny (or close this window) cancels everything -- nothing is "
                           "written. Call resync_targets later to refresh this file "
                           "after future vault changes.",
               justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_allow():
            vault_saved = False
            try:
                if state["first_run"]:
                    store.create_secrets_vault(state["password"])
                    state["first_run"] = False
                    secrets = {}
                else:
                    # Re-decrypt now, not the dict captured in step 1 -- see
                    # add_secret_dialog for why.
                    secrets = store.load_secrets(state["password"])

                # Re-read the target right now rather than trusting values
                # captured when this dialog first opened -- it can sit open
                # for minutes, and force_names below will overwrite the
                # file unconditionally. Without this, a real edit made to
                # the file while the dialog was open would be silently
                # destroyed and replaced with a placeholder for a value
                # the vault never actually saw.
                # Filter by kind via indexing, not tuple-unpacking in the
                # comprehension's `for` clause -- parse_env_file also
                # yields 2-tuples for 'raw'/'unsupported' lines, and a
                # comprehension unpacks the for-target before applying the
                # if-filter, so `for kind, n, v in ...` would raise on the
                # very first comment or blank line in the file.
                fresh = {item[1]: item[2] for item in store.parse_env_file(target)
                         if item[0] == "var"}

                index = store.load_index()
                names = [name for name, _ in to_migrate]
                for name, original_value in to_migrate:
                    fresh_value = fresh.get(name)
                    # Same guard install_migrate applies before ever calling
                    # this dialog: never treat an empty value or something that
                    # already looks like one of our own placeholders as a
                    # real secret, even if that's what's on disk right now.
                    if fresh_value and not store.PLACEHOLDER_VALUE_RE.match(fresh_value):
                        secrets[name] = fresh_value
                    else:
                        secrets[name] = original_value
                    if name not in index:
                        index[name] = store.next_placeholder(index)
                store.save_secrets(state["password"], secrets)
                store.save_index(index)
                vault_saved = True
                all_names = names + [n for n in also_register if n not in names]
                store.add_target(str(target), all_names)
                conflicts = store.sync_target_file(
                    target, index, set(all_names), force_names=set(names))
                outcome["conflicts"] = conflicts
            except Exception as e:
                if vault_saved:
                    msg = (
                        f"Saved to the vault, but could not rewrite {target.name}: "
                        f"{e}. The real values are safe; fix the problem and call "
                        f"resync_targets."
                    )
                    outcome["partial_failure"] = msg
                    _show_error(root, err, msg)
                else:
                    _show_error(root, err, f"Failed to save: {e}")
                return
            outcome["approved"] = True
            root.destroy()

        def on_deny():
            root.destroy()

        def on_back():
            show_step1()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=12)
        _button(btns, text="Back", width=10, command=on_back).pack(side="left", padx=4)
        _button(btns, text="Deny", width=10, command=on_deny).pack(side="left", padx=4)
        _button(btns, text="Allow", width=12, bg=ACCENT, fg="white",
                activebackground=ACCENT, command=on_allow).pack(side="left", padx=4)
        root.bind("<Escape>", lambda e: on_deny())
        # No <Return>-to-Allow here on purpose -- see remove_secret_dialog's
        # step 2 for why: no input field gates it, so a carried-over Enter
        # from step 1 could migrate the file before it's been read.
        # Rebind (not just "don't bind") -- otherwise step 1's <Return> ->
        # on_continue stays active and fires against the Entry `clear()`
        # already destroyed, raising TclError inside the Tk callback.
        root.bind("<Return>", lambda e: None)
        _center(root)

    show_step1()
    root.mainloop()
    return outcome


def unlock_for_run_dialog(command_str: str, materialize_path: str = None, only_vars=None):
    """Used by the run_with_env MCP tool. Returns the decrypted secrets
    dict, or None if denied/failed. Callers that pass only_vars are
    expected to filter the returned dict down to those names themselves
    -- this function still returns everything, since it has to decrypt
    the whole vault anyway to get any of it.

    No separate "Requested by" line here -- unlike the other dialogs, this
    one already shows exactly what's about to run in the Command box
    below, so a second line repeating the same command would just be a
    redundant wall of the same long text twice.
    """
    outcome = {"secrets": None}
    pad = {"padx": 14, "pady": 5}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
    _style(root)

    if only_vars is not None:
        # Caller already validated these against the index -- show exactly
        # what will actually be injected, not the whole vault.
        var_names = sorted(only_vars)
    else:
        try:
            var_names = sorted(store.load_index().keys())
        except (OSError, UnicodeDecodeError, ValueError):
            # `root` already exists at this point -- an uncaught exception
            # here would leave it orphaned (never destroyed, since
            # mainloop() hasn't started yet) instead of just falling back
            # to an empty disclosure list, which is a safe default anyway.
            var_names = []

    row = 0
    _label(root, "Unlock Vault to Run Command", font=FONT_TITLE).grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    if var_names:
        _label(root, f"Will expose {len(var_names)} variable(s) to this command: "
                     f"{_safe_display(', '.join(var_names), 300)}",
               justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
    else:
        _label(root, "Will expose 0 variable(s) to this command.").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

    _label(root, "Command:").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    cmd_frame = tk.Frame(root, bg=WINDOW_BG)
    cmd_text = tk.Text(cmd_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                        highlightthickness=1, highlightbackground="#444",
                        selectbackground=ACCENT, insertbackground=FG,
                        height=3, width=52, wrap="none")
    cmd_xscroll = tk.Scrollbar(cmd_frame, orient="horizontal", command=cmd_text.xview)
    cmd_text.config(xscrollcommand=cmd_xscroll.set)
    cmd_text.insert("end", _collapse_whitespace(command_str))
    cmd_text.config(state="disabled")
    cmd_text.grid(row=0, column=0, sticky="we")
    cmd_xscroll.grid(row=1, column=0, sticky="ew")
    cmd_frame.grid_columnconfigure(0, weight=1)
    cmd_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=14)
    row += 1

    if materialize_path:
        _label(root, f"Also writes real values to:", fg="#9a9a9a").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(5, 0))
        row += 1
        path_frame = tk.Frame(root, bg=WINDOW_BG)
        path_text = tk.Text(path_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                            highlightthickness=1, highlightbackground="#444",
                            selectbackground=ACCENT, insertbackground=FG,
                            height=2, width=52, wrap="none")
        path_xscroll = tk.Scrollbar(path_frame, orient="horizontal", command=path_text.xview)
        path_text.config(xscrollcommand=path_xscroll.set)
        path_text.insert("end", _collapse_whitespace(str(materialize_path)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_xscroll.grid(row=1, column=0, sticky="ew")
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=14)
        row += 1
        _label(root, "(deleted the moment the command exits)", fg="#9a9a9a").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

    _label(root, "Master password:").grid(row=row, column=0, sticky="e", **pad)
    pw = _entry(root, show="*", width=30)
    pw.grid(row=row, column=1, **pad)
    row += 1

    err = _label(root, "", fg="#ff6b6b")
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
    row += 1

    def on_allow():
        password = pw.get()
        if not password:
            _show_error(root, err, "Password cannot be empty.")
            return
        try:
            outcome["secrets"] = store.load_secrets(password)
        except WrongPassword as e:
            _show_error(root, err, str(e))
            return
        except (FileNotFoundError, ValueError) as e:
            _show_error(root, err, f"Vault error: {e}")
            return
        root.destroy()

    def on_deny():
        root.destroy()

    btns = tk.Frame(root, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=12)
    _button(btns, text="Cancel", width=12, command=on_deny).pack(side="left", padx=6)
    _button(btns, text="Unlock && Run", width=14, bg=ACCENT, fg="white",
              activebackground=ACCENT, command=on_allow).pack(side="left", padx=6)

    root.bind("<Escape>", lambda e: on_deny())
    root.bind("<Return>", lambda e: on_allow())
    pw.focus_force()
    _center(root)
    root.mainloop()
    return outcome["secrets"]
