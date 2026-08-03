"""Small Tkinter dialogs.

Two-step flow: first the master password (unlocking or creating the
vault), then -- only after that succeeds -- the proposed change and the
real value. Password verification happens inside the GUI process
itself, in the button handlers.

Security contract: add_secret_dialog / remove_secret_dialog return only
a plain approved/denied boolean to the calling script -- the password
and any decrypted values stay inside this process and are never printed
or returned. unlock_for_run_dialog is the one deliberate exception: it
hands back the decrypted secrets dict, because its whole job is to let
run_with_env.py inject real values into a child process's environment.
"""
import tkinter as tk
from tkinter import messagebox, ttk

from . import store
from .crypto import WrongPassword

WINDOW_BG = "#1e1e1e"
FIELD_BG = "#2d2d2d"
FG = "#e8e8e8"
ACCENT = "#4c8bf5"

FONT_FAMILY = "Segoe UI"
FONT_BODY = (FONT_FAMILY, 11)
FONT_TITLE = (FONT_FAMILY, 14, "bold")
FONT_MONO = ("Consolas", 11)


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
    kw.setdefault("font", FONT_MONO)
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


def add_secret_dialog(var_name: str, is_update: bool, placeholder: int):
    """Step 1: master password. Step 2 (only after step 1 succeeds): the
    proposed change plus the real value, with Allow/Deny.
    Returns True if applied, False if denied/cancelled/failed.
    """
    store.validate_var_name(var_name)
    first_run = not store.vault_exists()
    outcome = {"approved": False}
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
        title = "Create Vault" if first_run else "Unlock Vault"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        verb = "update" if is_update else "add"
        _label(container, f"About to {verb} the secret for {var_name}.",
               justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        if first_run:
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
                err.config(text="Password cannot be empty.")
                return
            if first_run:
                if len(password) < 8:
                    err.config(text="Use at least 8 characters.")
                    return
                if password != pw2.get():
                    err.config(text="Passwords do not match.")
                    return
                state["password"] = password
                state["secrets"] = {}
                show_step2()
                return
            try:
                state["secrets"] = store.load_secrets(password)
            except WrongPassword as e:
                err.config(text=str(e))
                return
            except (FileNotFoundError, ValueError) as e:
                err.config(text=f"Vault error: {e}")
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
        pw1.focus_set()
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

        err = _label(container, "", fg="#ff6b6b")
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=14)
        row += 1

        def on_allow():
            value = val.get()
            if not value:
                err.config(text="Secret value cannot be empty.")
                return
            try:
                if first_run:
                    store.create_secrets_vault(state["password"])
                secrets = state["secrets"]
                secrets[var_name] = value
                store.save_secrets(state["password"], secrets)

                index = store.load_index()
                resolved_placeholder = index.get(var_name, store.next_placeholder(index))
                index[var_name] = resolved_placeholder
                store.save_index(index)
            except Exception as e:
                err.config(text=f"Failed to save: {e}")
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
        val.focus_set()
        _center(root)

    show_step1()
    root.mainloop()
    return outcome["approved"]


def remove_secret_dialog(var_name: str, placeholder: int):
    outcome = {"approved": False}
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
                err.config(text="Password cannot be empty.")
                return
            try:
                state["secrets"] = store.load_secrets(password)
            except WrongPassword as e:
                err.config(text=str(e))
                return
            except (FileNotFoundError, ValueError) as e:
                err.config(text=f"Vault error: {e}")
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
        pw.focus_set()
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
            try:
                secrets = state["secrets"]
                secrets.pop(var_name, None)
                store.save_secrets(state["password"], secrets)

                index = store.load_index()
                index.pop(var_name, None)
                store.save_index(index)
            except Exception as e:
                err.config(text=f"Failed to save: {e}")
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
        root.bind("<Return>", lambda e: on_allow())
        _center(root)

    show_step1()
    root.mainloop()
    return outcome["approved"]


def unlock_for_run_dialog(command_str: str):
    """Used by run_with_env.py. Returns the decrypted secrets dict, or None if denied/failed."""
    outcome = {"secrets": None}
    pad = {"padx": 14, "pady": 5}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
    _style(root)

    row = 0
    _label(root, "Unlock Vault to Run Command", font=FONT_TITLE).grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    _label(root, f"Command:\n  {command_str}", justify="left").grid(
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
            err.config(text="Password cannot be empty.")
            return
        try:
            outcome["secrets"] = store.load_secrets(password)
        except WrongPassword as e:
            err.config(text=str(e))
            return
        except (FileNotFoundError, ValueError) as e:
            err.config(text=f"Vault error: {e}")
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
    pw.focus_set()
    _center(root)
    root.mainloop()
    return outcome["secrets"]


def notify_no_vault():
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("llm-env-vault", "No vault exists yet. Run add_secret.py first.")
    root.destroy()
