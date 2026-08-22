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
dict (inside its own outcome dict, keys "secrets"/"trust"), because its
whole job is to let the run_with_env MCP tool inject real values into a
child process's environment. See vault_lib/trust.py for what "trust"
means there -- an in-memory-only cache scoped to this one server
process, never written to disk.
"""
import hashlib
import re
import sys
import tkinter as tk
import tkinter.font as tkfont
import unicodedata
from pathlib import Path
from typing import Optional

from . import store, trust
from .crypto import (WrongPassword, MalformedRecoveryKey, NoRecoverySlot,
                     VaultCorrupted, format_recovery_key, new_recovery_key,
                     parse_recovery_key)


def _strip_hidden(text: str) -> str:
    """Strip Unicode format characters (category Cf) and C0/C1 control
    characters that are not ordinary ASCII whitespace (\\t \\n \\r \\f \\v).
    These can hide a boundary in text a human is approving: a zero-width
    joiner or directional mark inserted between two words looks like a word
    boundary in the rendered string but not in the underlying code-point
    sequence. Tk 8.6 does not implement bidi reordering, so a Right-to-Left
    Override (U+202E) renders as a missing-glyph box rather than visually
    reversing surrounding text -- the zero-width half of Cf is the plausible
    attack surface here, not visual reordering.
    Ordinary whitespace chars (\\t, \\n, \\r, \\f, \\v) are left in place so
    _safe_display and _collapse_whitespace can still collapse them to spaces.
    """
    result = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue  # zero-width joiners/non-joiners, bidi marks, soft hyphen, etc.
        if cat == "Cc" and ch not in "\t\n\r\f\v":
            continue  # C0 (U+0000-U+001F minus whitespace) and C1 (U+0080-U+009F)
        result.append(ch)
    return "".join(result)


def _safe_display(text, max_len: int = 200) -> str:
    """Collapses all whitespace (including newlines) to single spaces and
    hard-caps length. Applied to any text this module did not itself
    generate before it's rendered into a dialog, so attacker-controlled
    input (a command line, a process description) can never inject fake
    extra lines or grow tall/wide enough to push the real consent content
    and the Allow/Deny buttons off a non-resizable, non-scrolling window.
    Also strips Unicode format characters (Cf) and C0/C1 controls via
    _strip_hidden before collapsing -- see that function for why.
    """
    collapsed = re.sub(r"\s+", " ", _strip_hidden(str(text))).strip()
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
    Also strips Unicode format characters (Cf) and C0/C1 controls via
    _strip_hidden before collapsing -- see that function for why.
    """
    return re.sub(r"\s+", " ", _strip_hidden(str(text))).strip()


# --- Design tokens -----------------------------------------------------
# A single zinc-neutral scale plus one accent color, matching the dark
# theme at thyra-ai.com -- picked over the old ad hoc dark-grey-plus-
# bright-blue scheme because every neutral here sits on the same scale,
# so nothing competes for attention except the one accent and the
# amber/red status colors. All hex values below are that site's own
# computed colors (read directly from its stylesheet), not eyeballed.
WINDOW_BG = "#18181B"      # zinc-900 -- window background, every plain container
FIELD_BG = "#27272A"       # zinc-800 -- inputs and read-only text boxes
BORDER = "#3F3F46"         # zinc-700 -- the one border color, used everywhere
FG = "#FAFAFA"             # zinc-50 -- primary text
FG_MUTED = "#A1A1AA"       # zinc-400 -- secondary / hint text
ACCENT = "#3266DA"         # thyra-ai.com's primary button blue
ACCENT_HOVER = "#2A56B8"   # ~15% darker, hover/press feedback
DANGER = "#F87171"         # red-400 -- destructive actions (remove_secret's Allow)
DANGER_HOVER = "#E85959"
WARNING = "#FBBF24"        # amber-400 -- non-blocking warnings/notes

# Segoe UI, not Inter (thyra-ai.com's font): Inter isn't installed on this
# machine, and Tkinter silently falls back to a generic default for any
# unavailable family rather than erroring, which would undo the whole
# point of picking a specific typeface. Segoe UI is the closest already-
# installed match in spirit -- both are humanist UI sans faces in the
# same weight range -- so the shift in tone comes from color, spacing,
# and shape below, not the typeface itself.
FONT_FAMILY = "Segoe UI"
FONT_BODY = (FONT_FAMILY, 11)
FONT_BODY_BOLD = (FONT_FAMILY, 11, "bold")
FONT_TITLE = (FONT_FAMILY, 16, "bold")
FONT_BUTTON = (FONT_FAMILY, 10, "bold")

# Every widget in every dialog uses one of the FONT_* constants above --
# no other font is used anywhere in this module. _style() also forces
# FONT_BODY as the Tk-wide default so any widget that forgets to set one
# explicitly still can't end up on a different font.

# Minimum acceptable master-password length (creation and change only --
# existing vaults are never checked retroactively).
#
# Deliberately low, and the reasoning is worth writing down because it looks
# like an oversight otherwise.
#
# The adversary this product is built against is an AI agent, and an agent
# cannot attack the password at all: it can neither see nor drive the native
# dialog, so every attempt it makes is simply an error. Length buys nothing
# against that threat. Meanwhile a password the human cannot remember is a
# certain, self-inflicted total loss of the vault -- a far more likely outcome
# than the alternative.
#
# The alternative being: an attacker who gets a COPY of vault.enc off the
# machine attacks it offline, where no dialog stands in the way, and there the
# password is the only remaining secret. A short user-chosen password falls to
# a wordlist in seconds regardless of the KDF. That path needs the ciphertext
# to be exfiltrated first, which is a bigger step than reading it, but it is
# not exotic. This floor accepts that risk in exchange for memorability; the
# README says so plainly rather than implying the minimum is strong.
MIN_PASSWORD_LEN = 5

# How long a copied recovery key is allowed to sit on the clipboard before
# it is wiped. The clipboard is readable by every process running as this
# user, so the window is kept short -- long enough to paste into the
# confirm field, not long enough to still be there later.
_CLIPBOARD_CLEAR_SECONDS = 30

# Passwords refused outright regardless of length.
#
# This is the cheap half of the trade-off above. Length and dictionary rank are
# different axes: a 5-character random password needs millions of guesses, while
# "password1" survives no attack at all -- it sits in the first few hundred
# entries of every wordlist in existence, so an attacker holding a copy of
# vault.enc opens it essentially instantly however expensive the KDF is.
#
# Blocking these costs the user nothing in memorability (nobody picks "qwerty"
# because it is the only thing they can remember) and removes the entire
# top-of-wordlist attack class. It is not a strength meter and deliberately does
# not try to be one -- no complexity rules, no scoring, no nagging. Just the
# handful of strings that are guaranteed to be tried first.
#
# Compared case-insensitively after stripping surrounding whitespace.
_COMMON_PASSWORDS = frozenset({
    # numeric runs and keyboard walks
    "123456", "123456789", "12345678", "1234567", "12345", "1234567890",
    "1234", "111111", "123123", "000000", "654321", "666666", "121212",
    "112233", "789456", "159753", "987654321", "11111111", "22222222",
    "123321", "555555", "777777", "888888", "999999", "101010", "202020",
    "qwerty", "qwerty123", "qwertyuiop", "qwe123", "1q2w3e", "1q2w3e4r",
    "1q2w3e4r5t", "qazwsx", "qazwsxedc", "zxcvbnm", "asdfgh", "asdfghjkl",
    "poiuytrewq", "1qaz2wsx", "q1w2e3r4", "azerty", "wasd",
    # the perennial classics
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "p@ssword", "pass123", "passwd", "letmein", "welcome", "welcome1",
    "welcome123", "monkey", "dragon", "sunshine", "princess", "football",
    "baseball", "basketball", "superman", "batman", "shadow", "master",
    "michael", "jennifer", "jordan", "harley", "ranger", "hunter",
    "buster", "soccer", "hockey", "killer", "george", "andrew",
    "charlie", "thomas", "robert", "daniel", "joshua", "matthew",
    "trustno1", "starwars", "whatever", "freedom", "iloveyou", "lovely",
    "flower", "cookie", "chocolate", "computer", "internet", "samsung",
    "google", "facebook", "myspace1", "abc123", "abcd1234", "abc12345",
    "a1b2c3", "aa123456", "123abc", "696969", "7777777", "12345678910",
    # developer and infrastructure defaults -- the ones that matter most here
    "admin", "admin123", "administrator", "root", "root123", "toor",
    "changeme", "change_me", "changeit", "default", "guest", "test",
    "test123", "testing", "temp", "temp123", "secret", "secret123",
    "docker", "jenkins", "postgres", "mysql", "oracle", "redis",
    "mongodb", "elastic", "kibana", "grafana", "tomcat", "apache",
    "nginx", "ubuntu", "centos", "debian", "vagrant", "raspberry",
    "raspberrypi", "pi", "user", "user123", "demo", "demo123",
    "public", "private", "master123", "manager", "service", "system",
    "backup", "database", "server", "localhost", "example", "sample",
    "dummy", "foobar", "foo", "bar", "baz", "qwerty1", "hello",
    "hello123", "helloworld", "letmein123", "openses", "opensesame",
    "access", "login", "logmein", "enter", "start", "install",
    "setup", "config", "sysadmin", "operator", "supervisor", "owner",
    "developer", "devops", "deploy", "release", "staging", "production",
    "prod", "dev", "development", "qwer1234", "asd123", "zxc123",
    "1234abcd", "pass1234", "mypassword", "newpassword", "oldpassword",
    "thisisapassword", "correcthorsebatterystaple",
    # vault- and secret-manager flavoured guesses
    "vault", "vault123", "keychain", "keystore", "secrets", "mysecret",
    "topsecret", "confidential", "encrypted", "decrypt", "unlock",
    "masterkey", "master_key", "privatekey", "apikey", "token",
})



def _enable_dark_titlebar(root) -> None:
    """Best-effort: asks Windows' DWM to paint this window's native
    titlebar dark. Without this, every dialog had a bright white OS
    titlebar wrapped around an otherwise all-dark window -- the single
    most jarring inconsistency in the old look, and the first thing
    visible before any of the content even renders. Silently does
    nothing on non-Windows or older Windows builds that don't support
    the attribute; never allowed to break dialog creation over cosmetics.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def _style(root):
    root.configure(bg=WINDOW_BG)
    root.attributes("-topmost", True)
    root.option_add("*Font", FONT_BODY)
    _enable_dark_titlebar(root)


def _new_window():
    """Returns (window, run_modal) for a dialog.

    Tk does not tolerate two live Tk() roots in one process. A dialog opened
    from inside another dialog's callback -- the recovery drill during
    first-run vault creation is exactly this -- would create a second root and
    a NESTED mainloop, and on Windows that produces two very confusing
    symptoms: the new window opens *behind* the one that spawned it, so it
    looks like nothing happened, and destroy() fails to unwind the nested loop
    cleanly, so the dialog appears frozen -- you can tick the checkbox and
    click Confirm and never leave the page.

    So the first window in a process becomes the real root and is driven with
    mainloop(); any window opened while one is already alive becomes a
    Toplevel of it, made transient and modal and driven with wait_window().
    Behaviour is identical to before for the common single-dialog case.
    """
    existing = getattr(tk, "_default_root", None)
    try:
        alive = existing is not None and existing.winfo_exists()
    except Exception:  # noqa: BLE001 -- interpreter torn down mid-teardown
        alive = False

    if alive:
        win = tk.Toplevel(existing)

        def run_modal():
            try:
                win.transient(existing)
            except Exception:  # noqa: BLE001 -- transient is best-effort
                pass
            _foreground(win)
            win.grab_set()
            win.wait_window(win)

        return win, run_modal

    win = tk.Tk()

    def run_root():
        _foreground(win)
        win.mainloop()

    return win, run_root


def _foreground(win):
    """Take the foreground and the keyboard, not just the top of the z-order.

    This is a security control, not a politeness. If the dialog is visible but
    does NOT own keyboard focus, the human starts typing their master password
    into whatever window does -- an editor, a terminal, a chat box. The secret
    this whole product exists to contain ends up somewhere arbitrary, in
    plaintext, with no way to take it back.

    focus_force() is not enough on its own. Windows refuses SetForegroundWindow
    to a process that is not already the foreground process (SPI_SETFOREGROUND-
    LOCKTIMEOUT), and this server is typically launched in the background by an
    editor or an MCP client, so it is exactly that kind of process. Tk's
    focus_force() then moves focus only *within* our application, which changes
    nothing about where the keystrokes actually land.

    The AttachThreadInput dance below is the documented way through: a thread
    attached to the current foreground thread's input queue temporarily shares
    its input state, and is allowed to set the foreground window while attached.
    Every step is best-effort -- if any of it is refused we still have topmost
    and lift, so the window is at least visible.
    """
    try:
        win.deiconify()
        win.lift()
        win.attributes("-topmost", True)
        win.update_idletasks()
        _win32_take_foreground(win)
        win.focus_force()
        # Drop always-on-top once we hold the foreground, so the dialog does not
        # hover over everything else for the rest of its life.
        win.after(400, lambda: _safe_untopmost(win))
    except Exception:  # noqa: BLE001 -- window manager may refuse any of this
        pass


def _win32_take_foreground(win):
    """Windows-only: borrow the foreground thread's input state long enough to
    legally call SetForegroundWindow. No-op everywhere else, and silent on any
    failure -- this is a best-effort improvement on top of topmost/lift."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # Tk's winfo_id() is the client area; the real top-level window Windows
        # cares about is its parent.
        hwnd = user32.GetParent(win.winfo_id()) or win.winfo_id()

        fg_hwnd = user32.GetForegroundWindow()
        if fg_hwnd == hwnd:
            return

        target_tid = kernel32.GetCurrentThreadId()
        fg_tid = user32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(wintypes.DWORD()))

        attached = False
        if fg_tid and fg_tid != target_tid:
            attached = bool(user32.AttachThreadInput(fg_tid, target_tid, True))
        try:
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
            user32.SetActiveWindow(hwnd)
        finally:
            if attached:
                user32.AttachThreadInput(fg_tid, target_tid, False)
    except Exception:  # noqa: BLE001 -- ctypes, DLL, or the OS refusing
        pass


def _safe_untopmost(win):
    try:
        if win.winfo_exists():
            win.attributes("-topmost", False)
    except Exception:  # noqa: BLE001
        pass


def _label(parent, text, **kw):
    kw.setdefault("fg", FG)
    kw.setdefault("wraplength", 480)
    kw.setdefault("font", FONT_BODY)
    return tk.Label(parent, text=text, bg=WINDOW_BG, **kw)


def _entry(parent, **kw):
    kw.setdefault("font", FONT_BODY)
    return tk.Entry(parent, bg=FIELD_BG, fg=FG, insertbackground=FG,
                     relief="flat", highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=ACCENT, **kw)


def _textbox(parent, **kw):
    """A read-only-ish text box styled identically to _entry.

    Every tk.Text in this file used to be constructed by hand, and each one
    quietly omitted `highlightcolor`. Tk then falls back to its own default for
    the focus ring, so a box that had focus was outlined in a completely
    different colour from the entry beside it -- boxes that should look like
    siblings visibly did not. Centralising it means a new box cannot pick up a
    different palette by being written slightly differently.

    Defaults to wrapping rather than clipping: text that runs past the right
    edge should flow onto another line and make the dialog taller, never
    disappear off the side where the reader has no idea it exists. Callers that
    genuinely need fixed-column layout (the recovery key grid) pass wrap="none"
    and size the box to fit.
    """
    kw.setdefault("font", FONT_BODY)
    kw.setdefault("wrap", "word")
    kw.setdefault("fg", FG)  # setdefault, not a literal: callers override it
    return tk.Text(parent, bg=FIELD_BG, insertbackground=FG,
                    relief="flat", highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ACCENT,
                    selectbackground=ACCENT, **kw)


def _divider(parent):
    """A 1px horizontal rule in BORDER. Not a ttk.Separator: ttk widgets
    render through the OS theme engine regardless of surrounding tk
    widgets' colors, so a ttk.Separator here rendered as the same bright
    native-grey line that made the old scrollbars clash with everything
    around them -- same problem, same fix (draw it ourselves, in a color
    that's actually part of the palette)."""
    return tk.Frame(parent, bg=BORDER, height=1)


def _scrollbar(parent, **kw):
    """A tk.Scrollbar restyled to sit inside the dark theme. Left at its
    defaults, Scrollbar renders with the OS's light-grey scrollbar theme
    regardless of the surrounding widgets' colors -- a bright strip
    glued to the bottom of every command/path/variable-list box. This is
    the same widget, just told to actually use the dark palette."""
    kw.setdefault("troughcolor", WINDOW_BG)
    kw.setdefault("activebackground", BORDER)
    kw.setdefault("highlightthickness", 0)
    kw.setdefault("relief", "flat")
    kw.setdefault("elementborderwidth", 0)
    kw.setdefault("bd", 0)
    return tk.Scrollbar(parent, bg=FIELD_BG, **kw)


def _rounded_rect_points(x1, y1, x2, y2, r):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


class _RoundedButton(tk.Canvas):
    """A flat button with rounded corners, drawn on a Canvas instead of
    using tk.Button.

    On Windows, tk.Button always renders a visible 3D bevel border no
    matter what relief/bg/highlight options are set -- that native
    chrome, more than any single color choice, was what made the old
    dialogs read as a stock Windows prompt rather than something
    deliberately designed. Drawing the button directly matches
    thyra-ai.com's flat, rounded-corner button language, and (as a
    side effect) means every button auto-sizes to its own label instead
    of being stuck at a fixed character-width guess.
    """
    _PAD_X = 22
    _HEIGHT = 36
    _RADIUS = 9

    _COLORS = {
        "primary": (ACCENT, ACCENT_HOVER, "#FFFFFF", ACCENT),
        "danger": (DANGER, DANGER_HOVER, "#FFFFFF", DANGER),
        "secondary": (WINDOW_BG, FIELD_BG, FG, BORDER),
    }

    def __init__(self, parent, text, command=None, kind="secondary", parent_bg=None):
        font = tkfont.Font(family=FONT_FAMILY, size=FONT_BUTTON[1], weight="bold")
        width = font.measure(text) + self._PAD_X * 2
        height = self._HEIGHT
        super().__init__(parent, width=width, height=height,
                          bg=parent_bg if parent_bg is not None else WINDOW_BG,
                          highlightthickness=0, bd=0, cursor="hand2")
        self._command = command
        self._fill, self._hover, fg, outline = self._COLORS[kind]
        self._shape = self.create_polygon(
            _rounded_rect_points(1, 1, width - 1, height - 1, self._RADIUS),
            smooth=True, fill=self._fill, outline=outline, width=1)
        self.create_text(width / 2, height / 2, text=text, fill=fg, font=font)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)

    def _on_enter(self, _event):
        self.itemconfig(self._shape, fill=self._hover)

    def _on_leave(self, _event):
        self.itemconfig(self._shape, fill=self._fill)

    def _on_click(self, _event):
        if self._command is not None:
            self._command()


def _button(parent, text, command=None, kind="secondary"):
    try:
        parent_bg = parent.cget("bg")
    except tk.TclError:
        parent_bg = None
    return _RoundedButton(parent, text, command=command, kind=kind, parent_bg=parent_bg)


def _center(root):
    # Release any explicit geometry set by a previous step so the window's
    # requested size reflects the *current* content, not the last one.
    root.geometry("")
    root.update_idletasks()
    w, h = root.winfo_reqwidth(), root.winfo_reqheight()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")


def _branding_footer(parent):
    """Small, muted, static 'Powered by Thyra AI' label -- the one
    deliberate promotional touch in an otherwise strictly functional
    consent UI. Deliberately non-interactive: no click target, no cursor
    change, no hover feedback. A clickable link right below Allow/Deny in
    a password-entry dialog would train users to expect clickable content
    in these windows -- exactly the habit a lookalike phishing dialog
    could exploit -- and risks stealing focus mid-password-entry. Returns
    the frame un-packed/un-gridded; the caller places it with whichever
    geometry manager its own window already uses.
    """
    frame = tk.Frame(parent, bg=WINDOW_BG)
    label = tk.Label(frame, text="Powered by Thyra AI", font=(FONT_FAMILY, 9), fg=FG_MUTED, bg=WINDOW_BG)
    label.pack(pady=(4, 10))
    return frame


def _show_error(root, err_label, text):
    # _center() was already called once when this screen was first laid
    # out, based on whatever text `err_label` held then (usually empty).
    # An explicit geometry, once set, doesn't grow to fit later content --
    # a longer error message set afterward (e.g. a save failure with a
    # real exception message) would otherwise wrap past the window's
    # fixed height and clip itself, and the buttons below it, off-screen.
    err_label.config(text=text)
    _center(root)


def run_recovery_drill():
    """Generate a recovery key and make the human write it down. Returns the
    raw key bytes if they confirmed, or None if they declined or bailed out.

    Deliberately called while the human is choosing their PASSWORD, not after
    they have gone on to type a secret value. Setting up a recovery credential
    belongs with the other credential decisions; surfacing it several steps
    later, after an unrelated Allow, reads as though something went wrong.

    Nothing is written here. The caller passes the returned key to
    create_v2_vault, so declining simply produces a password-only vault --
    never a vault advertising a recovery slot whose key nobody holds.
    """
    raw = new_recovery_key()
    try:
        # slot_id is empty: the store assigns it at write time, and it carries
        # no staleness value at first run -- no earlier key exists yet.
        if show_recovery_key_dialog(format_recovery_key(bytes(raw)), ""):
            return bytes(raw)
        return None
    finally:
        # Best-effort in CPython; does not defeat a memory dump.
        for _i in range(len(raw)):
            raw[_i] = 0


def create_first_vault(password, recovery_raw, err_label, root):
    """Create the first-run v2 vault, optionally with a recovery slot whose
    key the human has already confirmed via run_recovery_drill()."""
    err_label.config(text="Working...", fg=FG_MUTED)
    root.update_idletasks()
    store.create_v2_vault(password, recovery_raw=recovery_raw)


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
    state = {"password": None, "secrets": None, "first_run": not store.vault_exists(),
             "offer_recovery": False, "recovery_raw": None}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        title = "Create Vault" if state["first_run"] else "Unlock Vault"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1

        verb = "update" if is_update else "add"
        _label(container, f"About to {verb} the secret for {_safe_display(var_name)}.",
               justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        if state["first_run"]:
            _label(container, f"No vault exists yet -- choose a master password\n"
                               f"(at least {MIN_PASSWORD_LEN} characters).", justify="left").grid(
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


            # Recovery key opt-in: honest framing — it increases attack surface
            # because it turns "needs something in your head" into "needs a piece
            # of paper". A password-only vault is a fully valid choice.
            rk_opt_var = tk.BooleanVar(value=False)
            tk.Checkbutton(
                container,
                text="Set up a paper recovery key (optional — increases attack surface)",
                variable=rk_opt_var, bg=WINDOW_BG, fg=FG_MUTED, font=FONT_BODY,
                selectcolor=FIELD_BG, activebackground=WINDOW_BG, activeforeground=FG,
                highlightthickness=0, wraplength=460, justify="left", anchor="w",
            ).grid(row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 4))
            row += 1
        else:
            rk_opt_var = None
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            pw2 = None

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_continue():
            password = pw1.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            if state["first_run"]:
                pw_reason = _password_rejection_reason(password)
                if pw_reason:
                    _show_error(root, err, pw_reason)
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["offer_recovery"] = rk_opt_var.get() if rk_opt_var is not None else False
                state["password"] = password
                state["secrets"] = {}
                # Recovery setup belongs with the password decision, not after
                # an unrelated Allow several steps later.
                if state["offer_recovery"]:
                    state["recovery_raw"] = run_recovery_drill()
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
        _button(btns, "Continue", command=on_continue, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw1.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        _label(container, "Confirm Change", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1

        verb = "Update" if is_update else "Add"
        _var = _safe_display(var_name)
        proposal = (
            f"Proposed change:\n"
            f"  {verb} secret for  {_var}\n"
            f'  llm.env will read:  {_var}="value {placeholder}"\n'
            f"  The real value below is encrypted and never shown to the AI."
        )
        _label(container, proposal, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        _divider(container).grid(row=row, column=0, columnspan=2, sticky="ew", padx=pad["padx"], pady=4)
        row += 1

        _label(container, f"Real value for {_var}:").grid(row=row, column=0, sticky="e", **pad)
        val = _entry(container, show="*", width=30)
        val.grid(row=row, column=1, **pad)
        row += 1

        if is_sensitive:
            _label(container,
                   f"Warning: {_var} overrides a system/runtime environment variable "
                   f"and could affect any command run_with_env launches later.",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_allow():
            value = val.get()
            if not value:
                _show_error(root, err, "Secret value cannot be empty.")
                return
            secrets_saved = False
            try:
                if state["first_run"]:
                    # Show a progress note before scrypt derivation — vault
                    # creation runs one to two scrypt rounds and will visibly
                    # freeze the window otherwise.
                    err.config(text="Working...", fg=FG_MUTED)
                    root.update_idletasks()
                    create_first_vault(state["password"],
                                       state.get("recovery_raw"), err, root)
                    err.config(text="", fg=DANGER)
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Back", command=on_back).pack(side="left", padx=6)
        _button(btns, "Deny", command=on_deny).pack(side="left", padx=6)
        _button(btns, "Allow", command=on_allow, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_deny())
        root.bind("<Return>", lambda e: on_allow())
        val.focus_force()
        _center(root)

    show_step1()
    _run_modal()
    return outcome


def remove_secret_dialog(var_name: str, placeholder: int):
    outcome = {"approved": False, "partial_failure": None}
    state = {"password": None, "secrets": None}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        _label(container, "Unlock Vault", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1
        _label(container, f"About to remove the secret for {_safe_display(var_name)}.").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
        pw = _entry(container, show="*", width=30)
        pw.grid(row=row, column=1, **pad)
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
        _button(btns, "Continue", command=on_continue, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        _label(container, "Confirm Removal", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1
        _var = _safe_display(var_name)
        proposal = (
            f"Proposed change:\n"
            f"  remove secret for  {_var}\n"
            f'  llm.env entry  {_var}="value {placeholder}"  will be deleted.'
        )
        _label(container, proposal, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Deny", command=on_deny).pack(side="left", padx=6)
        _button(btns, "Allow", command=on_allow, kind="danger").pack(side="left", padx=6)
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
    _run_modal()
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
    state = {"password": None, "secrets": None, "first_run": not store.vault_exists(),
             "offer_recovery": False, "recovery_raw": None}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        title = "Create Vault" if state["first_run"] else "Unlock Vault"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1
        if to_migrate:
            _label(container, f"About to migrate {len(to_migrate)} variable(s) out of:").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
        else:
            _label(container, "About to register for future resync_targets:").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        path_frame = tk.Frame(container, bg=WINDOW_BG)
        path_text = _textbox(path_frame, fg=FG, font=FONT_BODY, height=2, width=52)
        path_text.insert("end", _collapse_whitespace(str(target)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1

        if state["first_run"]:
            _label(container, f"No vault exists yet -- choose a master password\n"
                               f"(at least {MIN_PASSWORD_LEN} characters).", justify="left").grid(
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


            # Recovery key opt-in: honest framing — increases attack surface.
            # A password-only vault is a fully valid choice.
            rk_opt_var = tk.BooleanVar(value=False)
            tk.Checkbutton(
                container,
                text="Set up a paper recovery key (optional — increases attack surface)",
                variable=rk_opt_var, bg=WINDOW_BG, fg=FG_MUTED, font=FONT_BODY,
                selectcolor=FIELD_BG, activebackground=WINDOW_BG, activeforeground=FG,
                highlightthickness=0, wraplength=460, justify="left", anchor="w",
            ).grid(row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 4))
            row += 1
        else:
            rk_opt_var = None
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw1 = _entry(container, show="*", width=30)
            pw1.grid(row=row, column=1, **pad)
            row += 1
            pw2 = None

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_continue():
            password = pw1.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            if state["first_run"]:
                pw_reason = _password_rejection_reason(password)
                if pw_reason:
                    _show_error(root, err, pw_reason)
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["offer_recovery"] = rk_opt_var.get() if rk_opt_var is not None else False
                state["password"] = password
                state["secrets"] = {}
                # Recovery setup belongs with the password decision, not after
                # an unrelated Allow several steps later.
                if state["offer_recovery"]:
                    state["recovery_raw"] = run_recovery_drill()
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
        _button(btns, "Continue", command=on_continue, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw1.focus_force()
        _center(root)

    def show_step2():
        clear()
        row = 0
        title = "Confirm Migration" if to_migrate else "Confirm Registration"
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
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
        txt = _textbox(txt_frame, fg=FG, font=FONT_BODY, height=list_height, width=46)
        yscroll = _scrollbar(txt_frame, orient="vertical", command=txt.yview)
        txt.config(yscrollcommand=yscroll.set)
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
        txt_frame.grid_rowconfigure(0, weight=1)
        txt_frame.grid_columnconfigure(0, weight=1)
        txt_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        if list_count > list_height:
            _label(container, f"({list_count} total -- scroll to see the rest.)",
                   fg=FG_MUTED).grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
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
                   f"{_collapse_whitespace(', '.join(sorted(other_owner)))}",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        sensitive_in_migrate = sorted(n for n, _ in to_migrate if n in sensitive_names)
        if sensitive_in_migrate:
            _label(container,
                   f"Warning: {_collapse_whitespace(', '.join(sensitive_in_migrate))} "
                   f"override(s) system/runtime environment variable(s) -- any command "
                   f"run_with_env launches later will see the vaulted value instead of "
                   f"the real system value.",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        _label(container, "Deny (or close this window) cancels everything -- nothing is "
                           "written. Call resync_targets later to refresh this file "
                           "after future vault changes.",
               justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_allow():
            vault_saved = False
            try:
                if state["first_run"]:
                    # Show a progress note before scrypt derivation.
                    err.config(text="Working...", fg=FG_MUTED)
                    root.update_idletasks()
                    create_first_vault(state["password"],
                                       state.get("recovery_raw"), err, root)
                    err.config(text="", fg=DANGER)
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
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Back", command=on_back).pack(side="left", padx=6)
        _button(btns, "Deny", command=on_deny).pack(side="left", padx=6)
        _button(btns, "Allow", command=on_allow, kind="primary").pack(side="left", padx=6)
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
    _run_modal()
    return outcome


# ---------------------------------------------------------------------------
# Whole-file encryption dialogs
# ---------------------------------------------------------------------------
#
# Both follow remove_secret_dialog's two-step shape: unlock, then confirm a
# specific proposed change. Every path is shown in a scrollable, non-eliding
# textbox rather than through _safe_display -- consent-critical text must not
# be truncated, for the reason already written at _collapse_whitespace and in
# unlock_for_run_dialog. A path is exactly the kind of string an ellipsis
# ruins: "C:\\proj\\...\\server.pem" is not something a human can approve.
#
# All vault work happens inside on_allow, so the password and the file master
# key never leave this process, and nothing is written until the human clicks.


def _format_bytes(count) -> str:
    """Human-readable byte count for a consent dialog. Pure; unit-tested."""
    try:
        count = int(count)
    except (TypeError, ValueError):
        return "unknown size"
    if count < 1024:
        return f"{count} bytes"
    for unit in ("KiB", "MiB", "GiB"):
        count /= 1024.0
        if count < 1024 or unit == "GiB":
            return f"{count:.1f} {unit}"
    return f"{count:.1f} GiB"


def _path_box(parent, text, height=2, width=56):
    """A scrollable, read-only, non-eliding box for one filesystem path."""
    frame = tk.Frame(parent, bg=WINDOW_BG)
    box = _textbox(frame, fg=FG, font=FONT_BODY, height=height, width=width)
    box.insert("end", _collapse_whitespace(str(text)))
    box.config(state="disabled")
    box.grid(row=0, column=0, sticky="we")
    frame.grid_columnconfigure(0, weight=1)
    return frame


_OVERWRITE_CAVEAT = (
    "Overwriting is best-effort. On SSDs and journaling filesystems the "
    "original bytes may still exist in storage this program cannot reach -- "
    "wear-levelling, shadow copies, backups, your editor's swap file. If this "
    "file was ever exposed, rotate the credential; do not rely on this deletion."
)

_DURABILITY_CAVEAT = (
    "If vault.enc on this machine is lost, this file cannot be recovered. The "
    "recovery key alone is not enough -- it only works together with vault.enc. "
    "Back that file up."
)


def encrypt_file_dialog(path):
    """Confirm encrypting one file into a .levault sidecar and destroying it.

    Returns {"approved": bool, "partial_failure": str|None, "result": dict|None}.
    """
    outcome = {"approved": False, "partial_failure": None, "result": None}
    state = {"password": None, "info": None, "resume": False}
    pad = {"padx": 18, "pady": 7}
    path = Path(path)

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        _label(container, "Unlock Vault to Encrypt a File", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w",
            padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1
        _label(container, "File to encrypt:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, path).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
        pw = _entry(container, show="*", width=30)
        pw.grid(row=row, column=1, **pad)
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_continue():
            password = pw.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            try:
                # Verify by decrypting, the pattern every other dialog uses.
                # Deliberately NOT get_or_create_fmk: minting writes to the
                # vault, and nothing may be written before Allow.
                store.load_secrets(password)
                info = store.precheck_encrypt(path)
            except WrongPassword as e:
                _show_error(root, err, str(e))
                return
            except (FileNotFoundError, ValueError, OSError) as e:
                _show_error(root, err, str(e))
                return

            if info["sidecar_exists"]:
                # The crash-limbo case: a verified sidecar beside an intact
                # original. Offer to finish only if it really holds this file.
                if store._sidecar_matches(info["vault_path"], password,
                                          hashlib.sha256(
                                              info["path"].read_bytes()).hexdigest()):
                    state["resume"] = True
                else:
                    _show_error(root, err, (
                        f"{info['vault_path'].name} already exists and does not "
                        f"contain this file's current contents. Resolve that by "
                        f"hand -- one of the two files is not what you think."))
                    return

            state["password"] = password
            state["info"] = info
            show_step2()

        def on_cancel():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
        _button(btns, "Continue", command=on_continue, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw.focus_force()
        _center(root)

    def show_step2():
        clear()
        info = state["info"]
        row = 0
        title = ("Finish Encrypting File" if state["resume"] else "Confirm Encrypt File")
        _label(container, title, font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w",
            padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1

        if state["resume"]:
            _label(container, (
                "An encrypted copy of this file already exists and has been "
                "verified to contain exactly its current contents -- a previous "
                "run was interrupted before the original could be destroyed. "
                "Only the deletion below is left to do."), fg=WARNING,
                justify="left", wraplength=430).grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        _label(container, "File to encrypt:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, info["path"]).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(container,
               f"Size: {_format_bytes(info['size'])}     Permissions: {info['mode']}",
               fg=FG_MUTED).grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        _label(container, "Encrypted copy will be written to:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, info["vault_path"]).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1

        _label(container, "THE ORIGINAL FILE WILL BE DESTROYED.", fg=DANGER,
               font=FONT_BODY_BOLD).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(14, 2))
        row += 1
        _label(container, (
            f"After the encrypted copy is written and verified, "
            f"{_safe_display(info['path'].name, 60)} is overwritten with random "
            f"bytes and deleted. The only way back is this vault's master "
            f"password or its recovery key."), justify="left",
            wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1
        _label(container, _OVERWRITE_CAVEAT, fg=WARNING, justify="left",
               wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(8, 0))
        row += 1
        _label(container, _DURABILITY_CAVEAT, fg=WARNING, justify="left",
               wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(8, 0))
        row += 1
        _label(container, (
            "The .levault file is pure ciphertext and is safe to commit to git. "
            "Its filename still reveals the original filename."), fg=FG_MUTED,
            justify="left", wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(8, 0))
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_allow():
            try:
                result = store.encrypt_file_in_place(
                    state["info"]["path"], state["password"],
                    allow_resume=state["resume"])
            except Exception as e:  # noqa: BLE001
                _show_error(root, err, f"Encryption failed: {e}")
                return
            if not result.get("original_destroyed"):
                # The ciphertext is good and registered; only the removal
                # failed. WHICH half failed decides what the user should do,
                # and getting it wrong is dangerous: telling someone a
                # random-byte husk "still contains the real secret" invites
                # them to delete the .levault instead, which by then is the
                # only copy.
                if result.get("not_destroyed_reason"):
                    msg = result["not_destroyed_reason"]
                elif result.get("original_overwritten"):
                    msg = (
                        f"The encrypted copy was written and verified. The original "
                        f"{result['original_name']} was overwritten with random bytes "
                        f"but could not be deleted (it may be open in another "
                        f"program). It no longer contains your secret -- the "
                        f".levault file does. Delete the leftover yourself."
                    )
                else:
                    msg = (
                        f"The encrypted copy was written and verified, but the "
                        f"original {result['original_name']} could NOT be removed "
                        f"(it may be open in another program). It still contains "
                        f"the real secret -- close whatever is holding it and "
                        f"delete it yourself. Your data is safe either way: the "
                        f".levault file is complete and verified."
                    )
                outcome["partial_failure"] = msg
                outcome["result"] = result
                _show_error(root, err, msg)
                return
            outcome["approved"] = True
            outcome["result"] = result
            root.destroy()

        def on_deny():
            root.destroy()

        def on_back():
            state["resume"] = False
            show_step1()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Back", command=on_back).pack(side="left", padx=6)
        _button(btns, "Deny", command=on_deny).pack(side="left", padx=6)
        _button(btns, "Allow", command=on_allow, kind="danger").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_deny())
        # No <Return>-to-Allow: this screen has no input field gating it, and
        # an Enter carried over from step 1's password box would destroy a
        # file before the human had read a word of this. Rebind rather than
        # merely omit -- see remove_secret_dialog for why that distinction
        # matters (a live handler fires against destroyed widgets).
        root.bind("<Return>", lambda e: None)
        _center(root)

    show_step1()
    _run_modal()
    return outcome


def decrypt_file_dialog(vault_path, output_path=None):
    """Confirm restoring a .levault to a real plaintext file on disk.

    Returns {"approved": bool, "partial_failure": str|None, "result": dict|None}.
    """
    outcome = {"approved": False, "partial_failure": None, "result": None}
    state = {"password": None, "info": None, "meta": None, "size": None}
    pad = {"padx": 18, "pady": 7}
    vault_path = Path(vault_path)

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_step1():
        clear()
        row = 0
        _label(container, "Unlock Vault to Decrypt a File", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w",
            padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1
        _label(container, "Encrypted file:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, vault_path).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
        pw = _entry(container, show="*", width=30)
        pw.grid(row=row, column=1, **pad)
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_continue():
            password = pw.get()
            if not password:
                _show_error(root, err, "Password cannot be empty.")
                return
            try:
                info = store.precheck_decrypt(vault_path, output_path)
                # Open it now so step 2 can state the real size, permissions
                # and original name rather than the registry's version of them.
                file_bytes, meta = store.read_encrypted_file(info["vault_path"], password)
            except WrongPassword as e:
                _show_error(root, err, str(e))
                return
            except (FileNotFoundError, ValueError, OSError, VaultCorrupted) as e:
                _show_error(root, err, str(e))
                return
            state["password"] = password
            state["info"] = info
            state["meta"] = meta
            state["size"] = len(file_bytes)
            show_step2()

        def on_cancel():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
        _button(btns, "Continue", command=on_continue, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_cancel())
        root.bind("<Return>", lambda e: on_continue())
        pw.focus_force()
        _center(root)

    def show_step2():
        clear()
        info, meta = state["info"], state["meta"]
        row = 0
        _label(container, "Confirm Decrypt File", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w",
            padx=pad["padx"], pady=(pad["pady"], 14))
        row += 1

        _label(container, "Encrypted file:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, info["vault_path"]).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1

        _label(container, "Will write the real, decrypted contents to:").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _path_box(container, info["output_path"]).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(container, (
            f"Size: {_format_bytes(state['size'])}     "
            f"Permissions will be restored to: {meta.get('mode', 'unknown')}"),
            fg=FG_MUTED).grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

        stored_name = meta.get("name")
        if stored_name and stored_name != info["output_path"].name:
            _label(container, (
                f"Note: this was encrypted as {_safe_display(stored_name, 60)}, but "
                f"will be restored under the name above -- the output name comes "
                f"from the .levault file's name, not from what is stored inside it."),
                fg=WARNING, justify="left", wraplength=430).grid(
                row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
            row += 1

        _label(container, (
            "This writes a real secret to disk permanently. It is NOT cleaned "
            "up. The AI assistant can see this path and has been instructed not "
            "to read the file -- that instruction is not enforced."),
            fg=WARNING, justify="left", wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(12, 0))
        row += 1
        _label(container, (
            "The .levault file is left in place; this does not remove the file "
            "from the vault."), fg=FG_MUTED, justify="left", wraplength=430).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(8, 0))
        row += 1

        err = _label(container, "", fg=DANGER)
        err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

        def on_allow():
            try:
                result = store.decrypt_file_to(
                    state["info"]["vault_path"], state["password"],
                    output_path=str(state["info"]["output_path"]))
            except Exception as e:  # noqa: BLE001
                _show_error(root, err, f"Decryption failed: {e}")
                return
            outcome["approved"] = True
            outcome["result"] = result
            root.destroy()

        def on_deny():
            root.destroy()

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
        _button(btns, "Back", command=show_step1).pack(side="left", padx=6)
        _button(btns, "Deny", command=on_deny).pack(side="left", padx=6)
        # primary, not danger: this creates a file rather than destroying one.
        # The risk it does carry is carried by the amber warning above.
        _button(btns, "Allow", command=on_allow, kind="primary").pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: on_deny())
        root.bind("<Return>", lambda e: None)  # same reasoning as encrypt step 2
        _center(root)

    show_step1()
    _run_modal()
    return outcome


def confirm_abandon_files_dialog(outstanding: dict, registry_names: dict):
    """Second-stage confirm for retiring keys that files still depend on.

    *outstanding* is {generation_id: [file_id, ...]} from
    store.file_keys_outstanding; *registry_names* maps file_id -> a
    human-recognisable name where one is known.

    Exists because refusing forever is its own failure. A single crashed
    encrypt, or a file that genuinely no longer exists anywhere, would
    otherwise leave someone permanently unable to retire a key they believe is
    compromised -- and with no way to discover what was blocking it. This
    names exactly what is being given up, which is why it takes the specific
    identities rather than being a blanket "force" flag.

    Returns the list of file_ids the human confirmed abandoning, or None.
    """
    outcome = {"abandon": None}
    pad = {"padx": 18, "pady": 7}
    ids = [(gen, fid) for gen, group in sorted(outstanding.items()) for fid in group]

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    # container is not decoration: pack and grid must never share a parent.
    # The footer is packed onto root, so everything else grids into a frame,
    # exactly as the other two-step dialogs do. Mixing the two managers on one
    # widget makes Tk loop forever negotiating geometry -- it hangs inside
    # .grid() itself, which no amount of teardown guarding in the test harness
    # can rescue.
    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    row = 0
    _label(container, "Abandon Unreachable Files?", font=FONT_TITLE).grid(
        row=row, column=0, columnspan=2, sticky="w",
        padx=pad["padx"], pady=(pad["pady"], 14))
    row += 1

    _label(container, (
        f"{len(ids)} file(s) were encrypted by this vault and have not been moved "
        f"to the current key. Retiring the old key(s) makes them PERMANENTLY "
        f"UNREADABLE -- including any copy on another machine, in a backup, or in "
        f"git history."), fg=DANGER, justify="left", wraplength=430).grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    _label(container, "Only continue if you are certain these no longer exist anywhere:",
           justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    frame = tk.Frame(container, bg=WINDOW_BG)
    listing = _textbox(frame, fg=FG, font=FONT_BODY,
                       height=min(8, max(2, len(ids))), width=52)
    for gen, fid in ids:
        label = registry_names.get(fid)
        # The name is a hint from the registry, which an agent can edit, so it
        # is shown as supplementary to the identity rather than instead of it.
        shown = f"{label}  ({fid[:12]}...)" if label else f"unknown file  ({fid[:12]}...)"
        listing.insert("end", f"{shown}  [key {gen}]\n")
    listing.config(state="disabled")
    scroll = _scrollbar(frame, orient="vertical", command=listing.yview)
    listing.config(yscrollcommand=scroll.set)
    listing.grid(row=0, column=0, sticky="nsew")
    scroll.grid(row=0, column=1, sticky="ns")
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
    row += 1

    _label(container, (
        "If any of them might still exist, cancel: make it reachable and run "
        "rotation again instead."), fg=FG_MUTED, justify="left",
        wraplength=430).grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    confirm_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        container, text="These files are gone forever. Abandon them.",
        variable=confirm_var, bg=WINDOW_BG, fg=FG, font=FONT_BODY,
        selectcolor=FIELD_BG, activebackground=WINDOW_BG, activeforeground=FG,
        highlightthickness=0, wraplength=430, justify="left", anchor="w").grid(
        row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))
    row += 1

    err = _label(container, "", fg=DANGER)
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
    row += 1

    def on_allow():
        if not confirm_var.get():
            _show_error(root, err,
                        "Tick the box to confirm these files no longer exist.")
            return
        outcome["abandon"] = [fid for _gen, fid in ids]
        root.destroy()

    btns = tk.Frame(container, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
    _button(btns, "Cancel", command=root.destroy).pack(side="left", padx=6)
    _button(btns, "Abandon and Retire", command=on_allow, kind="danger").pack(
        side="left", padx=6)
    root.bind("<Escape>", lambda e: root.destroy())
    # Never Enter-to-confirm on a screen that destroys data irrecoverably.
    root.bind("<Return>", lambda e: None)
    _center(root)

    _run_modal()
    return outcome["abandon"]


def _disclosure_mismatch(disclosed_names, actual_secret_names) -> Optional[str]:
    """None if what was disclosed to the human matches what's actually in
    the vault; otherwise a human-facing message naming the difference.

    Exists because unlock_for_run_dialog's "Will expose N variable(s)" list
    (for the only_vars=None, "expose everything" case) is necessarily built
    from vault_index.json BEFORE the password is entered -- decrypting
    upfront just to compute a disclosure list would defeat the point of
    having a plaintext index at all. If vault.enc and vault_index.json have
    ever diverged (e.g. a prior add_secret call where save_secrets
    succeeded but save_index then failed -- reported as a partial_failure
    at the time, but the desync itself isn't auto-reconciled), a variable
    present in the vault but absent from the index would otherwise get
    injected into the child process without ever having appeared in what
    the human approved. This is the one point both sources are known --
    right after decryption, before injection -- so it's the one place this
    can be caught.

    Pure and Tkinter-free on purpose, so it's directly unit-testable
    without spinning up a real dialog."""
    disclosed, actual = set(disclosed_names), set(actual_secret_names)
    if disclosed == actual:
        return None
    parts = []
    extra = sorted(actual - disclosed)
    missing = sorted(disclosed - actual)
    if extra:
        parts.append(f"in the vault but not disclosed above: {', '.join(extra)}")
    if missing:
        parts.append(f"disclosed above but no longer in the vault: {', '.join(missing)}")
    return ("The vault and vault_index.json have diverged -- refusing to run until this "
            "is fixed (call sync_llm_env, or re-run add_secret/remove_secret for the "
            "affected name(s)): " + "; ".join(parts))


# ---------------------------------------------------------------------------
# Pure helpers — Tkinter-free, directly unit-testable
# ---------------------------------------------------------------------------

def _is_common_password(pw: str) -> bool:
    """True if pw is in the blocklist, compared case- and whitespace-insensitively."""
    return pw.strip().lower() in _COMMON_PASSWORDS


def _password_rejection_reason(pw: str) -> Optional[str]:
    """Why this password cannot be used, or None if it is acceptable.

    Single source of truth: every dialog that sets a password routes through
    here, so the blocklist cannot end up enforced in one flow and not another.
    """
    if not pw:
        return "Password cannot be empty."
    if len(pw) < MIN_PASSWORD_LEN:
        return f"Use at least {MIN_PASSWORD_LEN} characters."
    if _is_common_password(pw):
        return ("That is one of the most commonly used passwords in the world. "
                "Anyone who copies vault.enc would guess it within seconds, no "
                "matter how strong the encryption is. Please pick another.")
    return None


def _validate_password_fields(pw: str, confirm: str) -> Optional[str]:
    """Validate a new-password pair. Returns an error string or None.
    Pure and Tkinter-free so it can be unit-tested without a display."""
    reason = _password_rejection_reason(pw)
    if reason:
        return reason
    if pw != confirm:
        return "Passwords do not match."
    return None


def _parse_rk_input(text: str):
    """Try to parse and checksum-verify a recovery key string.

    Returns (bytearray, None) on success, (None, friendly_error_str) on
    failure.  The caller must zero the returned bytearray when done —
    best-effort in CPython, does not defeat a memory dump.

    The friendly error message for MalformedRecoveryKey deliberately says
    'that looks like a typo' so users can distinguish a transcription error
    from an entirely wrong key.  The raw exception message is included
    (it never contains key material — only character counts and
    mismatched checksum digests) to give actionable detail.

    Pure and Tkinter-free so it can be unit-tested without a display."""
    try:
        raw = parse_recovery_key(text)
        return raw, None
    except MalformedRecoveryKey as exc:
        return None, (
            f"That looks like a typo — check what you entered ({exc})."
        )
    except Exception:
        # Guard: never let unexpected exceptions surface key material.
        return None, "Could not read recovery key (unexpected format)."


def _applicable_manage_actions(info: dict, encrypted_file_count: int = 0) -> list:
    """Return the list of manage_vault_dialog action IDs that make sense for
    the current vault state described by *info* (from store.vault_info()).

    *encrypted_file_count* gates the two file-key actions: offering "rotate the
    key that protects your encrypted files" to someone who has never encrypted
    one is noise, and a menu of mostly-inapplicable options is how people stop
    reading menus.

    Ordering matches the recommended display order.
    Pure and Tkinter-free so it can be unit-tested without a display."""
    if "error" in info:
        return []
    actions = ["change_password"]
    fmt = info.get("format")
    if fmt == 1:
        actions.append("upgrade_v2")
    if fmt == 2:
        if info.get("recovery_slot"):
            actions.append("reissue_recovery")
        else:
            actions.append("setup_recovery")
        if encrypted_file_count:
            actions.append("rotate_file_key")
            actions.append("retire_file_keys")
    return actions


def _manage_action_result_keys(action: str) -> frozenset:
    """Return the frozenset of keys that manage_vault_dialog includes in its
    result dict for *action*.  Used to test the contract without a display."""
    base = {"action"}
    if action == "change_password":
        return frozenset(base | {"old_password", "new_password"})
    if action in ("setup_recovery", "reissue_recovery", "upgrade_v2",
                  "rotate_file_key", "retire_file_keys"):
        return frozenset(base | {"password"})
    return frozenset(base)


def unlock_for_run_dialog(command_str: str, materialize_path: str = None, only_vars=None,
                          trust_note: str = None, files=None):
    """Used by the run_with_env MCP tool. Returns an outcome dict:
    {"secrets": dict_or_None, "trust": bool}. secrets is None if
    denied/failed, in which case trust is always False. When only_vars is
    set, the returned secrets dict is already filtered to just those keys --
    the whole vault is still decrypted internally (unavoidable to get any
    of it), but only the requested subset is handed back to the caller.

    trust is True only if the human both allowed the run AND checked
    "Trust this exact command" -- see vault_lib/trust.py for what the
    caller does with that (an in-memory-only, this-session-only cache,
    never written to disk).

    files: optional list of (vault_path, restore_path) pairs to decrypt for
    the lifetime of this one command. When it is non-empty the outcome also
    carries "files": {vault_path_str: {"name", "mode", "bytes"}} -- the
    DECRYPTED CONTENTS, never the file master key, so key material stays
    inside store.py exactly as the vault DEK does. The trust checkbox is
    hidden in that case: writing a private key to disk unattended is a
    different risk from injecting a token into an environment, and this
    feature was designed for the latter. Every files= run is approved by a
    human, every time.

    trust_note: optional text shown above the command box, e.g. an
    explanation that a *previous* trust grant for this same command was
    just revoked because a file it references changed, or a warning about
    what trust monitoring covers. Shown in full (scrollable) rather than
    truncated -- consent-critical text must not be elided.

    No separate "Requested by" line here -- unlike the other dialogs, this
    one already shows exactly what's about to run in the Command box
    below, so a second line repeating the same command would just be a
    redundant wall of the same long text twice.
    """
    outcome = {"secrets": None, "trust": False}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
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
        row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
    row += 1

    if trust_note:
        # B3: scrollable, non-truncating -- consent-critical text must never
        # be elided. trust_note can carry a full warning about what trust
        # monitoring covers; cutting it at 300 chars would defeat the purpose.
        note_frame = tk.Frame(root, bg=WINDOW_BG)
        note_text = _textbox(note_frame, fg=WARNING, height=4, width=52)
        note_yscroll = _scrollbar(note_frame, orient="vertical", command=note_text.yview)
        note_text.config(yscrollcommand=note_yscroll.set)
        note_text.insert("end", _collapse_whitespace(trust_note))
        note_text.config(state="disabled")
        note_text.grid(row=0, column=0, sticky="nsew")
        note_yscroll.grid(row=0, column=1, sticky="ns")
        note_frame.grid_rowconfigure(0, weight=1)
        note_frame.grid_columnconfigure(0, weight=1)
        note_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1

    # B3: exposure list shown in a scrollable Text widget rather than a
    # Label truncated at 300 chars -- with a large vault and only_vars=None
    # the human would otherwise be approving an ellipsis, not a list.
    if var_names:
        _label(root, f"Will expose {len(var_names)} variable(s) to this command:",
               justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        list_count = len(var_names)
        list_height = min(8, max(2, list_count))
        vars_frame = tk.Frame(root, bg=WINDOW_BG)
        vars_txt = _textbox(vars_frame, fg=FG, font=FONT_BODY, height=list_height, width=46)
        vars_yscroll = _scrollbar(vars_frame, orient="vertical", command=vars_txt.yview)
        vars_txt.config(yscrollcommand=vars_yscroll.set)
        for name in var_names:
            vars_txt.insert("end", name + "\n")
        vars_txt.config(state="disabled")
        vars_txt.grid(row=0, column=0, sticky="nsew")
        vars_yscroll.grid(row=0, column=1, sticky="ns")
        vars_frame.grid_rowconfigure(0, weight=1)
        vars_frame.grid_columnconfigure(0, weight=1)
        vars_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        if list_count > list_height:
            _label(root, f"({list_count} total -- scroll to see the rest.)",
                   fg=FG_MUTED).grid(row=row, column=0, columnspan=2, sticky="w",
                                     padx=pad["padx"])
            row += 1
    else:
        _label(root, "Will expose 0 variable(s) to this command.").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

    # A1: disclose where this command's output goes.
    _label(root, "This command's output will be returned to the AI assistant.",
           fg=FG_MUTED, justify="left").grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    _label(root, "Command:").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    cmd_frame = tk.Frame(root, bg=WINDOW_BG)
    cmd_text = _textbox(cmd_frame, fg=FG, font=FONT_BODY, height=3, width=52)
    cmd_text.insert("end", _collapse_whitespace(command_str))
    cmd_text.config(state="disabled")
    cmd_text.grid(row=0, column=0, sticky="we")
    cmd_frame.grid_columnconfigure(0, weight=1)
    cmd_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
    row += 1

    if files:
        _label(root, f"Also decrypts {len(files)} file(s) to disk for the lifetime "
                     f"of this command:", fg=FG_MUTED, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(6, 0))
        row += 1
        files_frame = tk.Frame(root, bg=WINDOW_BG)
        files_txt = _textbox(files_frame, fg=FG, font=FONT_BODY,
                             height=min(6, max(2, len(files))), width=52)
        for _vault_path, _restore_path in files:
            files_txt.insert("end", f"{_collapse_whitespace(str(_restore_path))}\n")
        files_txt.config(state="disabled")
        files_yscroll = _scrollbar(files_frame, orient="vertical", command=files_txt.yview)
        files_txt.config(yscrollcommand=files_yscroll.set)
        files_txt.grid(row=0, column=0, sticky="nsew")
        files_yscroll.grid(row=0, column=1, sticky="ns")
        files_frame.grid_rowconfigure(0, weight=1)
        files_frame.grid_columnconfigure(0, weight=1)
        files_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(root, "(deleted the moment the command exits)", fg=FG_MUTED).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1
        _label(root, "File contents are NOT redacted from this command's output.",
               fg=WARNING, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
        row += 1

    if materialize_path:
        # A1: be explicit about what the file contains, not just that it's cleaned up.
        _label(root, "Also writes real secret values to disk for the lifetime of the command:",
               fg=FG_MUTED, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(6, 0))
        row += 1
        path_frame = tk.Frame(root, bg=WINDOW_BG)
        path_text = _textbox(path_frame, fg=FG, font=FONT_BODY, height=2, width=52)
        path_text.insert("end", _collapse_whitespace(str(materialize_path)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_frame.grid_columnconfigure(0, weight=1)
        path_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
        row += 1
        _label(root, "(file deleted the moment the command exits)", fg=FG_MUTED).grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

    _label(root, "Master password:").grid(row=row, column=0, sticky="e", **pad)
    pw = _entry(root, show="*", width=30)
    pw.grid(row=row, column=1, **pad)
    row += 1

    trust_var = tk.BooleanVar(value=False)
    if files:
        # No trust offer at all for a run that writes decrypted files to disk.
        # An 8-hour grant would mean a private key can be written out
        # repeatedly with no human present, which is not the risk this
        # checkbox was written for. Say why, rather than silently omitting it.
        _label(root, "This run decrypts files to disk, so it cannot be trusted "
                     "for later re-use -- you will be asked again every time.",
               fg=FG_MUTED, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))
        row += 1
    else:
        trust_check = tk.Checkbutton(
            # Hours derived from trust._TRUST_TTL_SECONDS rather than written out,
            # so the number the human consents to here can never drift from the
            # number check() actually enforces.
            root, text=f"Trust this exact command for the next "
                       f"{trust._TRUST_TTL_SECONDS // 3600} hours "
                       f"(auto-runs with no prompt until then, or until this "
                       f"server restarts -- whichever comes first)",
            variable=trust_var, bg=WINDOW_BG, fg=FG, font=FONT_BODY,
            selectcolor=FIELD_BG, activebackground=WINDOW_BG, activeforeground=FG,
            highlightthickness=0, wraplength=480, justify="left", anchor="w")
        trust_check.grid(row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))
        row += 1

    err = _label(root, "", fg=DANGER)
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
    row += 1

    def on_allow():
        password = pw.get()
        if not password:
            _show_error(root, err, "Password cannot be empty.")
            return
        try:
            secrets = store.load_secrets(password)
        except WrongPassword as e:
            _show_error(root, err, str(e))
            return
        except (FileNotFoundError, ValueError) as e:
            _show_error(root, err, f"Vault error: {e}")
            return
        if only_vars is None:
            # Only meaningful for the "expose everything" case -- when
            # only_vars is set, injection is already explicitly scoped by
            # the caller, so a desync in the unused rest of the vault is
            # irrelevant here. See _disclosure_mismatch's docstring for why
            # this check has to happen here (the one point both the
            # disclosed names and the real decrypted keys are known).
            mismatch = _disclosure_mismatch(var_names, secrets.keys())
            if mismatch:
                _show_error(root, err, mismatch)
                return
        # A3: filter to only_vars when the caller scoped the run -- the whole
        # vault was decrypted (unavoidable to get any key), but we must hand
        # back only what was disclosed and approved, not everything.
        if files:
            # Decrypt here, inside the Allow handler, and hand back only the
            # plaintext bytes. The file master key never crosses this boundary
            # -- the same contract the vault DEK has always had.
            decrypted = {}
            for _vault_path, _restore_path in files:
                try:
                    _bytes, _meta = store.read_encrypted_file(_vault_path, password)
                except Exception as e:  # noqa: BLE001
                    _show_error(root, err, f"Could not decrypt {_vault_path}: {e}")
                    return
                decrypted[str(_vault_path)] = {
                    "name": _meta.get("name"),
                    "mode": _meta.get("mode"),
                    "bytes": _bytes,
                    "restore_path": str(_restore_path),
                }
            outcome["files"] = decrypted

        if only_vars is not None:
            outcome["secrets"] = {k: v for k, v in secrets.items() if k in only_vars}
        else:
            outcome["secrets"] = secrets
        outcome["trust"] = trust_var.get()
        root.destroy()

    def on_deny():
        root.destroy()

    btns = tk.Frame(root, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
    _button(btns, "Cancel", command=on_deny).pack(side="left", padx=6)
    _button(btns, "Unlock && Run", command=on_allow, kind="primary").pack(side="left", padx=6)
    row += 1

    _branding_footer(root).grid(row=row, column=0, columnspan=2)

    root.bind("<Escape>", lambda e: on_deny())
    root.bind("<Return>", lambda e: on_allow())
    pw.focus_force()
    _center(root)
    _run_modal()
    return outcome


def change_password_dialog() -> dict:
    """Collect current and new master password from the human.
    Returns {"old": str|None, "new": str|None}. Both are None if cancelled.
    Does NOT call store.change_password -- returns the two strings and lets
    the MCP tool drive the vault I/O, keeping this dialog free of vault
    side-effects (same contract as the other dialogs in this module).
    Enforces MIN_PASSWORD_LEN on the new password and that the two new-
    password entries match before returning.
    """
    outcome = {"old": None, "new": None}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    row = 0
    _label(root, "Change Master Password", font=FONT_TITLE).grid(
        row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
    row += 1

    _label(root, "Current password:").grid(row=row, column=0, sticky="e", **pad)
    old_pw = _entry(root, show="*", width=30)
    old_pw.grid(row=row, column=1, **pad)
    row += 1

    _label(root, f"New password (at least {MIN_PASSWORD_LEN} characters):").grid(
        row=row, column=0, sticky="e", **pad)
    new_pw1 = _entry(root, show="*", width=30)
    new_pw1.grid(row=row, column=1, **pad)
    row += 1

    _label(root, "Confirm new password:").grid(row=row, column=0, sticky="e", **pad)
    new_pw2 = _entry(root, show="*", width=30)
    new_pw2.grid(row=row, column=1, **pad)
    row += 1

    err = _label(root, "", fg=DANGER)
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
    row += 1

    def on_change():
        old = old_pw.get()
        new = new_pw1.get()
        confirm = new_pw2.get()
        if not old:
            _show_error(root, err, "Current password cannot be empty.")
            return
        new_reason = _password_rejection_reason(new)
        if new_reason:
            _show_error(root, err, new_reason)
            return
        if new != confirm:
            _show_error(root, err, "New passwords do not match.")
            return
        outcome["old"] = old
        outcome["new"] = new
        root.destroy()

    def on_cancel():
        root.destroy()

    btns = tk.Frame(root, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
    row += 1
    _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
    _button(btns, "Change Password", command=on_change, kind="primary").pack(side="left", padx=6)

    _branding_footer(root).grid(row=row, column=0, columnspan=2)

    root.bind("<Escape>", lambda e: on_cancel())
    root.bind("<Return>", lambda e: on_change())
    old_pw.focus_force()
    _center(root)
    _run_modal()
    return outcome


def show_recovery_key_dialog(key_text: str, slot_id: str) -> bool:
    """Display a newly issued recovery key and run the setup drill.

    Security contract — enforced in code, not documentation:
      * No copy-to-clipboard button: the Windows clipboard is readable by
        every local process, and Clipboard History may sync to the cloud.
      * No save-to-file button.  No print button.
      * Returns bool, never the key text — callers cannot harvest it.
      * key_text is never written to stdout or stderr.
      * key_text never reaches an exception message (all key-using paths
        are wrapped in try/except that surfaces only non-secret diagnostics).
      * unlock_for_run_dialog is never involved; recovery-key entry lives
        only here, in a dialog that is visually and structurally distinct
        from the normal unlock prompt.
      * Nothing auto-shows: reaching this dialog requires a deliberate
        human action (requesting a recovery key from manage_vault_dialog
        or completing a first-run vault creation with the opt-in checked).

    The setup drill: the human must check 'I have written this down' AND
    re-enter the FULL key from their paper.  Retyping four of thirty-six
    characters proves nothing.  The re-entry is validated with
    parse_recovery_key (checksum verified) and compared byte-for-byte
    against the displayed key, so a bad transcription is caught here —
    the only cheap defence against a key that was never correctly copied.

    Returns True when both the checkbox and the full re-entry pass.
    Returns False if the human closes or clicks 'I'll Set It Up Later'.
    """
    result = [False]
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault — Recovery Key")
    root.resizable(True, True)
    _style(root)

    row = 0
    _label(root, "Save Your Recovery Key", font=FONT_TITLE).grid(
        row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"],
        pady=(pad["pady"], 14))
    row += 1

    _label(root,
           "Once this window closes the key cannot be shown again. "
           "Write it down on paper and store it safely — this is the only "
           "way to regain access if you forget your master password.",
           fg=WARNING, justify="left").grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    # slot_id is empty when the drill runs BEFORE the slot is committed (the
    # first-run path -- see add_secret_dialog/install_dialog), because the id
    # is assigned by the store at write time. Showing "Slot ID:" with nothing
    # after it would just look broken, and the id has no staleness value at
    # first run anyway: no earlier key has ever existed to confuse it with.
    if slot_id:
        slot_line = (f"Slot ID: {_safe_display(slot_id)}  "
                     f"— check this matches any saved printout to tell if it is stale.")
        _label(root, slot_line, fg=FG_MUTED, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad)
        row += 1

    # Key display: selectable (user can read letter-by-letter) but
    # deliberately NO copy-to-clipboard button — clipboard is readable
    # by every local process; Clipboard History syncs to the cloud.
    key_frame = tk.Frame(root, bg=WINDOW_BG)
    # Laid out for copying by hand, which is the only way this key is ever
    # meant to leave the screen. The canonical one-line form is 48 characters
    # and word-wraps after "RK1", which strands the prefix on its own line and
    # leaves an unbroken 44-character run underneath -- easy to lose your place
    # in halfway through. Three rows of three groups in a monospace face keeps
    # the columns aligned so the eye can track position.
    # Strip the RK1 PREFIX only. A blanket .replace("RK1", ...) also eats any
    # "RK1" that occurs inside the key data -- Crockford base32 produces those
    # by chance -- silently turning a 4-character group into a 1-character one.
    # The human then writes down a key that can never open the vault, and only
    # finds out when they need it. This must stay a prefix strip.
    _stripped = key_text.strip()
    _body = _stripped[3:] if _stripped.upper().startswith("RK1") else _stripped
    _groups = [g for g in _body.replace("-", " ").split() if g]
    # Self-check before showing it. Every group is 4 Crockford characters; if
    # the reformatting above ever produces anything else, the pretty form is
    # lying about what the key is, and a human copying it down would be storing
    # a key that cannot open the vault. Fall back to the canonical one-line
    # string rather than display something wrong.
    if all(len(g) == 4 for g in _groups) and _groups:
        _rows = ["  ".join(_groups[i:i + 3]) for i in range(0, len(_groups), 3)]
        _pretty = "RK1\n" + "\n".join(_rows)
    else:
        _rows = [_stripped]
        _pretty = _stripped
    key_disp = _textbox(key_frame, fg=ACCENT, font=("Consolas", 15, "bold"), height=len(_rows) + 1, width=24, wrap="none",
                       padx=12, pady=8)
    key_disp.insert("end", _pretty)
    key_disp.tag_configure("mid", justify="left")
    key_disp.config(state="disabled")
    key_disp.grid(row=0, column=0, sticky="we")
    key_frame.grid_columnconfigure(0, weight=1)
    key_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
    row += 1

    _label(root, "Groups of 4 characters separated by hyphens.  The last group is the checksum.",
           fg=FG_MUTED, justify="left").grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    # Copy to clipboard, with an automatic wipe.
    #
    # This was deliberately absent at first: the Windows clipboard is readable
    # by every process running as this user -- the agent included -- and
    # Clipboard History can sync it to the cloud. That reasoning still holds
    # and is why the clipboard is cleared again shortly after.
    #
    # It exists anyway because the alternative was worse in practice: without
    # it the human hand-types 36 characters into the confirm field, and a
    # transcription slip there reads as "the key does not work". A key nobody
    # can be bothered to confirm is a recovery path that silently does not
    # exist. Bounded exposure beats an unusable ceremony.
    copy_state = {"job": None}

    def _clear_clipboard():
        copy_state["job"] = None
        try:
            if root.winfo_exists() and root.clipboard_get() == _stripped:
                root.clipboard_clear()
                root.clipboard_append("")
                copy_hint.config(text="Clipboard cleared.", fg=FG_MUTED)
        except Exception:  # noqa: BLE001 -- clipboard may hold non-text or be owned elsewhere
            pass

    def on_copy():
        try:
            root.clipboard_clear()
            root.clipboard_append(_stripped)
            copy_hint.config(
                text=f"Copied. Clipboard clears in {_CLIPBOARD_CLEAR_SECONDS}s — "
                     f"paste it below, then still write it on paper.",
                fg=WARNING)
            if copy_state["job"] is not None:
                root.after_cancel(copy_state["job"])
            copy_state["job"] = root.after(_CLIPBOARD_CLEAR_SECONDS * 1000,
                                           _clear_clipboard)
        except Exception:  # noqa: BLE001 -- no clipboard on this display
            copy_hint.config(text="Could not access the clipboard on this system.",
                             fg=DANGER)

    _button(root, "Copy key", command=on_copy).grid(
        row=row, column=0, sticky="w", padx=pad["padx"], pady=(0, 2))
    copy_hint = _label(root, "", fg=FG_MUTED, justify="left")
    copy_hint.grid(row=row, column=1, sticky="w", padx=(0, pad["padx"]))
    row += 1

    _divider(root).grid(row=row, column=0, columnspan=2, sticky="ew",
                        padx=pad["padx"], pady=8)
    row += 1

    _label(root,
           "Step 1 — once you have written the full key on paper, check the box below.",
           justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    written_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        root, text="I have written this down on paper",
        variable=written_var, bg=WINDOW_BG, fg=FG, font=FONT_BODY,
        selectcolor=FIELD_BG, activebackground=WINDOW_BG, activeforeground=FG,
        highlightthickness=0, anchor="w",
    ).grid(row=row, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))
    row += 1

    _label(root,
           "Step 2 — re-enter the FULL key from your paper below to confirm it was "
           "written correctly.  Verifying only a few characters proves nothing.",
           justify="left").grid(row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    # Wide enough for the full 48-character canonical form: if the field
    # scrolls, the human cannot see what they typed and cannot spot their own
    # transcription error -- which is the entire point of this step.
    reentry = _entry(root, width=52, font=("Consolas", 11))
    reentry.grid(row=row, column=0, columnspan=2, padx=pad["padx"], pady=(4, 2))
    row += 1

    err = _label(root, "", fg=DANGER)
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
    row += 1

    def on_confirm():
        if not written_var.get():
            _show_error(root, err,
                        "Please check the box to confirm you have written the key down.")
            return
        typed = reentry.get()
        if not typed.strip():
            _show_error(root, err, "Please re-enter the recovery key from your paper.")
            return
        # Parse both the typed text and the displayed key; compare bytes.
        # All key material is held in bytearrays and zeroed after use —
        # best-effort in CPython, does not defeat a memory dump.
        typed_raw = None
        displayed_raw = None
        try:
            typed_raw, parse_err = _parse_rk_input(typed)
            if parse_err:
                _show_error(root, err, parse_err)
                return
            try:
                displayed_raw = parse_recovery_key(key_text)
            except MalformedRecoveryKey:
                # key_text came from format_recovery_key — should not be
                # malformed in practice, but never let an exception surface
                # key material.
                _show_error(root, err, "Internal error verifying key — contact support.")
                return
            if bytes(typed_raw) != bytes(displayed_raw):
                _show_error(root, err,
                            "The key you entered does not match the one shown above. "
                            "Check what you typed — every character must match.")
                return
            result[0] = True
            root.destroy()
        except Exception:
            _show_error(root, err, "Could not verify key (unexpected error).")
        finally:
            if typed_raw is not None:
                for _i in range(len(typed_raw)):
                    typed_raw[_i] = 0
            if displayed_raw is not None:
                for _i in range(len(displayed_raw)):
                    displayed_raw[_i] = 0

    def on_cancel():
        root.destroy()

    btns = tk.Frame(root, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
    _button(btns, "I'll Set It Up Later", command=on_cancel).pack(side="left", padx=6)
    _button(btns, "Confirm — I Have It", command=on_confirm, kind="primary").pack(
        side="left", padx=6)
    row += 1

    _branding_footer(root).grid(row=row, column=0, columnspan=2)

    root.bind("<Escape>", lambda e: on_cancel())
    reentry.focus_force()
    _center(root)
    _run_modal()
    return result[0]


def recover_dialog() -> dict:
    """Account recovery using the paper recovery key.

    Visually distinct from the normal unlock dialog — different title,
    amber heading, and an explicit warning so users are not trained to
    enter paper secrets into ordinary unlock prompts.  Recovery-key entry
    lives only here, never in unlock_for_run_dialog.

    Returns {"recovery_key": str|None, "new_password": str|None}.
    Both are None if cancelled.  The returned recovery_key has been
    checksum-verified by parse_recovery_key before this function returns,
    so the caller can pass it straight to store.recover_with_recovery_key
    without a second parse step.
    """
    outcome = {"recovery_key": None, "new_password": None}
    pad = {"padx": 18, "pady": 7}

    root, _run_modal = _new_window()
    root.title("llm-env-vault — Account Recovery")
    root.resizable(True, True)
    _style(root)

    row = 0
    _label(root, "Account Recovery", font=FONT_TITLE, fg=WARNING).grid(
        row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"],
        pady=(pad["pady"], 4))
    row += 1

    _label(root,
           "Use this only if you have forgotten your master password. "
           "Your paper recovery key lets you set a new master password.",
           fg=WARNING, justify="left").grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
    row += 1

    _divider(root).grid(row=row, column=0, columnspan=2, sticky="ew",
                        padx=pad["padx"], pady=6)
    row += 1

    _label(root, "Recovery key\n(from your paper):").grid(row=row, column=0, sticky="e", **pad)
    rk_entry = _entry(root, width=40)
    rk_entry.grid(row=row, column=1, **pad)
    row += 1

    _label(root, f"New master password\n(at least {MIN_PASSWORD_LEN} characters):").grid(
        row=row, column=0, sticky="e", **pad)
    pw1 = _entry(root, show="*", width=30)
    pw1.grid(row=row, column=1, **pad)
    row += 1

    _label(root, "Confirm new password:").grid(row=row, column=0, sticky="e", **pad)
    pw2 = _entry(root, show="*", width=30)
    pw2.grid(row=row, column=1, **pad)
    row += 1

    err = _label(root, "", fg=DANGER)
    err.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
    row += 1

    def on_recover():
        rk_text = rk_entry.get()
        pw = pw1.get()
        confirm = pw2.get()
        if not rk_text.strip():
            _show_error(root, err, "Recovery key cannot be empty.")
            return
        pw_err = _validate_password_fields(pw, confirm)
        if pw_err:
            _show_error(root, err, pw_err)
            return
        # Validate checksum before returning — gives a friendly message
        # for transcription errors instead of an opaque failure in the caller.
        # The parsed bytearray is zeroed after the check; best-effort in CPython.
        parsed = None
        try:
            parsed, parse_err = _parse_rk_input(rk_text)
            if parse_err:
                _show_error(root, err, parse_err)
                return
            # Return the raw text (the store API takes a string).
            # The checksum is already verified above.
            outcome["recovery_key"] = rk_text.strip()
            outcome["new_password"] = pw
            root.destroy()
        except Exception:
            _show_error(root, err, "Could not verify recovery key (unexpected error).")
        finally:
            if parsed is not None:
                for _i in range(len(parsed)):
                    parsed[_i] = 0

    def on_cancel():
        root.destroy()

    btns = tk.Frame(root, bg=WINDOW_BG)
    btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
    _button(btns, "Cancel", command=on_cancel).pack(side="left", padx=6)
    _button(btns, "Recover Account", command=on_recover, kind="primary").pack(
        side="left", padx=6)
    row += 1

    _branding_footer(root).grid(row=row, column=0, columnspan=2)

    root.bind("<Escape>", lambda e: on_cancel())
    root.bind("<Return>", lambda e: on_recover())
    rk_entry.focus_force()
    _center(root)
    _run_modal()
    return outcome


def manage_vault_dialog() -> dict:
    """Vault administration window.

    Shows current vault state (format version, recovery-slot presence and
    slot id) and offers the actions that apply to that state:
      change_password  — always available
      upgrade_v2       — only for v1 vaults
      setup_recovery   — v2 vault without a recovery slot
      reissue_recovery — v2 vault that already has a recovery slot

    Returns {"action": str|None, ...} where action is one of the strings
    above, or None if cancelled/closed.  Carries the credentials the
    chosen action needs:
      change_password:           old_password, new_password
      setup_recovery:            password
      reissue_recovery:          password
      upgrade_v2:                password

    The caller (MCP server) drives all vault I/O; this dialog is free of
    vault side-effects, matching the pattern of change_password_dialog.
    """
    outcome = {"action": None}
    pad = {"padx": 18, "pady": 7}

    try:
        info = store.vault_info()
    except Exception as exc:
        info = {"error": str(exc)}

    try:
        encrypted_file_count = len(store.load_file_registry())
    except (OSError, ValueError):
        encrypted_file_count = 0
    actions = _applicable_manage_actions(info, encrypted_file_count)
    fmt = info.get("format")
    has_rk = info.get("recovery_slot", False)
    rk_slot_id = info.get("recovery_slot_id", "")
    rk_created = info.get("recovery_slot_created", "")

    root, _run_modal = _new_window()
    root.title("llm-env-vault")
    root.resizable(True, True)
    _style(root)

    container = tk.Frame(root, bg=WINDOW_BG)
    container.pack()
    _branding_footer(root).pack(side="bottom", fill="x")

    def clear():
        for w in container.winfo_children():
            w.destroy()

    def show_main():
        clear()
        row = 0
        _label(container, "Vault Settings", font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"],
            pady=(pad["pady"], 14))
        row += 1

        # Status section
        if "error" in info:
            _label(container,
                   f"Vault status: {_safe_display(info['error'])}",
                   fg=DANGER).grid(row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
        else:
            fmt_str = f"Format: v{fmt}" if fmt else "Format: unknown"
            _label(container, fmt_str, fg=FG_MUTED).grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

            if fmt == 2:
                if has_rk:
                    rk_parts = ["Recovery slot: active"]
                    if rk_slot_id:
                        rk_parts.append(f"slot id: {_safe_display(rk_slot_id)}")
                    if rk_created:
                        rk_parts.append(f"created: {_safe_display(rk_created)}")
                    rk_status = "  |  ".join(rk_parts)
                else:
                    rk_status = "Recovery slot: not configured"
                _label(container, rk_status, fg=FG_MUTED).grid(
                    row=row, column=0, columnspan=2, sticky="w", **pad)
                row += 1

        _divider(container).grid(row=row, column=0, columnspan=2, sticky="ew",
                                  padx=pad["padx"], pady=6)
        row += 1

        action_defs = [
            ("change_password",  "Change Master Password"),
            ("upgrade_v2",       "Upgrade Vault to v2"),
            ("setup_recovery",   "Set Up Paper Recovery Key"),
            ("reissue_recovery", "Reissue Recovery Key"),
            ("rotate_file_key",  "Rotate Encrypted-File Key"),
            ("retire_file_keys", "Retire Old File Keys"),
        ]

        if not actions:
            _label(container, "No actions available for this vault state.").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
        else:
            for action_id, btn_label in action_defs:
                if action_id not in actions:
                    continue
                def _make_cb(a=action_id):
                    return lambda: show_action(a)
                _button(container, btn_label, command=_make_cb()).grid(
                    row=row, column=0, columnspan=2, pady=4)
                row += 1

        btns = tk.Frame(container, bg=WINDOW_BG)
        btns.grid(row=row, column=0, columnspan=2, pady=(12, 4))
        _button(btns, "Close", command=root.destroy).pack(side="left", padx=6)
        root.bind("<Escape>", lambda e: root.destroy())
        _center(root)

    def show_action(action):
        clear()
        row = 0

        titles = {
            "change_password":  "Change Master Password",
            "setup_recovery":   "Set Up Paper Recovery Key",
            "reissue_recovery": "Reissue Recovery Key",
            "upgrade_v2":       "Upgrade Vault to v2",
            "rotate_file_key":  "Rotate Encrypted-File Key",
            "retire_file_keys": "Retire Old File Keys",
        }
        _label(container, titles.get(action, action), font=FONT_TITLE).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"],
            pady=(pad["pady"], 14))
        row += 1

        if action == "upgrade_v2":
            _label(container,
                   "Warning: after upgrading, older versions of this plugin will "
                   "no longer be able to open the vault. An older build will "
                   "report 'Wrong password' for a correct password — there is no "
                   "data loss, but it is alarming if you are not expecting it. "
                   "Only upgrade if all your installations are current.",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        if action == "setup_recovery":
            _label(container,
                   "A paper recovery key lets you reset your master password if you "
                   "forget it. It genuinely increases attack surface: anyone who finds "
                   "the paper can reset your password. "
                   "A password-only vault is also a valid and secure choice.",
                   fg=FG_MUTED, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        if action == "rotate_file_key":
            _label(container,
                   f"Changing your master password does NOT change the key that "
                   f"protects your encrypted files -- that is deliberate, and it is "
                   f"why a .levault committed to git keeps working. Rotate that key "
                   f"here if you believe it may have been exposed.\n\n"
                   f"Every encrypted file this machine can find "
                   f"({encrypted_file_count} registered) is re-encrypted under a new "
                   f"key. Files that are missing -- on another machine, or not yet "
                   f"pulled from git -- are skipped and keep working under the old "
                   f"key, which is RETAINED. Nothing becomes unreadable until you "
                   f"separately retire the old keys.",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        if action == "retire_file_keys":
            _label(container,
                   "This permanently deletes every old file key from the vault. Any "
                   ".levault file still encrypted under one -- including copies on "
                   "other machines, in backups, or in git history -- becomes "
                   "PERMANENTLY UNREADABLE.\n\n"
                   "It is refused unless every registered file has already been "
                   "rotated onto the current key and is readable right now. Files "
                   "this vault has never been told about cannot be checked.",
                   fg=DANGER, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        if action == "reissue_recovery":
            _label(container,
                   "This generates a new recovery key. "
                   "Your old paper key stops working immediately.",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        err_lbl = _label(container, "", fg=DANGER)

        if action == "change_password":
            _label(container, "Current password:").grid(row=row, column=0, sticky="e", **pad)
            old_pw = _entry(container, show="*", width=30)
            old_pw.grid(row=row, column=1, **pad)
            row += 1

            _label(container, f"New password\n(at least {MIN_PASSWORD_LEN} chars):").grid(
                row=row, column=0, sticky="e", **pad)
            new_pw1 = _entry(container, show="*", width=30)
            new_pw1.grid(row=row, column=1, **pad)
            row += 1

            _label(container, "Confirm new password:").grid(row=row, column=0, sticky="e", **pad)
            new_pw2 = _entry(container, show="*", width=30)
            new_pw2.grid(row=row, column=1, **pad)
            row += 1

            err_lbl.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
            row += 1

            def on_change_pw():
                old = old_pw.get()
                pw_err = _validate_password_fields(new_pw1.get(), new_pw2.get())
                if not old:
                    _show_error(root, err_lbl, "Current password cannot be empty.")
                    return
                if pw_err:
                    _show_error(root, err_lbl, pw_err)
                    return
                outcome["action"] = "change_password"
                outcome["old_password"] = old
                outcome["new_password"] = new_pw1.get()
                root.destroy()

            btns = tk.Frame(container, bg=WINDOW_BG)
            btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
            _button(btns, "Back", command=show_main).pack(side="left", padx=6)
            _button(btns, "Change Password", command=on_change_pw, kind="primary").pack(
                side="left", padx=6)
            root.bind("<Escape>", lambda e: show_main())
            root.bind("<Return>", lambda e: on_change_pw())
            old_pw.focus_force()

        else:
            # setup_recovery, reissue_recovery, upgrade_v2 — all need the
            # current password; the caller drives the actual vault operation.
            _label(container, "Master password:").grid(row=row, column=0, sticky="e", **pad)
            pw_entry = _entry(container, show="*", width=30)
            pw_entry.grid(row=row, column=1, **pad)
            row += 1

            err_lbl.grid(row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"])
            row += 1

            confirm_labels = {
                "setup_recovery":   "Set Up Recovery Key",
                "reissue_recovery": "Reissue Recovery Key",
                "upgrade_v2":       "Upgrade to v2",
                "rotate_file_key":  "Rotate File Key",
                "retire_file_keys": "Retire Old Keys",
            }

            def on_confirm():
                pw = pw_entry.get()
                if not pw:
                    _show_error(root, err_lbl, "Password cannot be empty.")
                    return
                outcome["action"] = action
                outcome["password"] = pw
                root.destroy()

            btns = tk.Frame(container, bg=WINDOW_BG)
            btns.grid(row=row, column=0, columnspan=2, pady=(20, 4))
            _button(btns, "Back", command=show_main).pack(side="left", padx=6)
            _button(btns, confirm_labels.get(action, "Confirm"), command=on_confirm,
                    kind="danger" if action == "retire_file_keys" else "primary").pack(
                side="left", padx=6)
            root.bind("<Escape>", lambda e: show_main())
            if action == "retire_file_keys":
                # The one action here that can permanently destroy data the user
                # cannot get back. Everything else is recoverable or additive, so
                # Enter-to-confirm is a convenience; here it is a hazard.
                root.bind("<Return>", lambda e: None)
            else:
                root.bind("<Return>", lambda e: on_confirm())
            pw_entry.focus_force()

        _center(root)

    show_main()
    _run_modal()
    return outcome
