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
import re
# Aliased: several dialogs bind a local named `secrets` to the decrypted vault
# dict, which would shadow this module inside those scopes. They happen not to
# call secrets.choice() today, so the collision is latent rather than live --
# the alias keeps it that way permanently instead of leaving an UnboundLocalError
# waiting for whoever adds a passphrase call to one of those functions.
import secrets as _secrets
import sys
import tkinter as tk
import tkinter.font as tkfont
import unicodedata
from typing import Optional

from . import store, trust
from .crypto import (WrongPassword, MalformedRecoveryKey, NoRecoverySlot,
                     format_recovery_key, new_recovery_key, parse_recovery_key)


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
# existing vaults are never checked retroactively). 8 characters is roughly
# 25-30 bits of entropy for user-chosen passwords -- crackable in hours by
# anyone who copies vault.enc. 12 characters raises the floor to ~40 bits.
MIN_PASSWORD_LEN = 12

# Short built-in wordlist for the "Generate passphrase" convenience button in
# the create-vault flow. Four words from 256 gives ~32 bits of entropy --
# not Diceware, but more memorable than a random 12-char password and easily
# above MIN_PASSWORD_LEN. The list is entirely lowercase, no special chars,
# intentionally avoiding words that look like commands or path components.
_WORDLIST = [
    "apple", "beach", "birch", "blade", "blank", "blend", "block", "bloom",
    "blown", "blues", "board", "brave", "bread", "brick", "brief", "bring",
    "broad", "brook", "brush", "build", "bunny", "cable", "camel", "canoe",
    "carry", "cedar", "chain", "chair", "chalk", "charm", "chart", "chase",
    "cheap", "check", "cheek", "chess", "chief", "child", "chill", "chime",
    "chord", "civil", "claim", "clasp", "class", "clean", "clear", "clerk",
    "click", "cliff", "climb", "cloak", "clock", "close", "cloud", "clove",
    "coach", "coast", "cobra", "combo", "comet", "coral", "cover", "crane",
    "crate", "cream", "creek", "crisp", "cross", "crowd", "crown", "curve",
    "cycle", "daisy", "dance", "delta", "depot", "depth", "derby", "digit",
    "dingo", "disco", "ditch", "diver", "dodge", "dogma", "draft", "drain",
    "drama", "drape", "drawl", "dream", "drift", "drill", "drink", "drive",
    "drone", "drove", "drum", "dunce", "dusk", "eagle", "early", "earth",
    "elder", "elbow", "ember", "entry", "equal", "event", "exact", "fable",
    "facet", "fault", "feast", "fence", "ferry", "fetch", "fever", "fiber",
    "field", "fifth", "fifty", "filth", "final", "first", "fixed", "fjord",
    "flame", "flask", "fleet", "flesh", "flint", "float", "flood", "floor",
    "floss", "flour", "fluid", "flute", "focus", "force", "forge", "forth",
    "forty", "forum", "frank", "fresh", "front", "frost", "froze", "fully",
    "funny", "gauze", "gavel", "gecko", "ghost", "giant", "given", "gleam",
    "glide", "glint", "globe", "gloss", "glove", "glyph", "gnome", "goose",
    "grace", "grade", "grain", "grand", "grant", "grape", "grasp", "grass",
    "grave", "great", "green", "greet", "grind", "groan", "grove", "growl",
    "gruel", "guard", "guide", "guild", "gusto", "havoc", "hedge", "helix",
    "hertz", "hinge", "hippo", "holly", "honey", "honor", "horse", "hotel",
    "house", "human", "humor", "hyena", "index", "indie", "inert", "infix",
    "inner", "input", "ionic", "issue", "ivory", "jewel", "joust", "judge",
    "juice", "jumbo", "kayak", "kazoo", "knack", "kneel", "knife", "knock",
    "knoll", "label", "lance", "latch", "lemon", "lever", "light", "limit",
    "linen", "lingo", "liver", "llama", "lodge", "logic", "lotus", "lover",
    "lucid", "lunar", "lusty", "lyric", "maize", "manor", "maple", "march",
    "march", "marsh", "match", "maxim", "media", "merge", "merit", "metal",
    "metro", "micro", "minor", "mirage", "mirth", "mimic", "mixer", "model",
    "money", "mongo", "moose", "morse", "mossy", "motor", "mount", "mouse",
    "mouth", "mulch", "music", "myrrh", "naive", "nerve", "nexus", "night",
    "ninety", "noble", "noise", "north", "notch", "novel", "nymph", "ocean",
    "olive", "onset", "opera", "orbit", "order", "organ", "other", "otter",
    "outer", "oxide", "ozone", "panda", "panel", "paper", "patch", "pause",
    "peace", "pearl", "pedal", "perch", "photo", "piano", "pinch", "pixel",
    "pixel", "plain", "plane", "plant", "plaza", "plumb", "plump", "plunk",
    "point", "polar", "poppy", "portal", "power", "press", "price", "pride",
    "prime", "prism", "prize", "probe", "prone", "proof", "prose", "proxy",
    "pulse", "punch", "pupil", "quaff", "quail", "qualm", "quash", "quasi",
    "queen", "quest", "queue", "quick", "quiet", "quirk", "quota", "quote",
    "radar", "radio", "rainy", "rapid", "raven", "reach", "realm", "rebel",
    "relay", "remix", "renew", "repay", "rider", "ridge", "risky", "rival",
    "river", "robin", "robot", "rocky", "rodeo", "rouge", "rough", "round",
    "royal", "rugby", "ruler", "rural", "rusty", "sadly", "safer", "saint",
    "salsa", "sandy", "sauce", "savor", "scale", "scene", "scope", "score",
    "scout", "screw", "seize", "sense", "serum", "seven", "shade", "shaft",
    "shake", "shall", "shame", "shape", "share", "shark", "sharp", "sheep",
    "sheer", "shelf", "shell", "shift", "shiny", "shore", "short", "shout",
    "shown", "sight", "sigma", "silky", "silver", "since", "sixth", "sixty",
    "sized", "skate", "skirt", "skull", "slate", "sleek", "sleep", "sleet",
    "slick", "slide", "slime", "slimy", "slope", "sloth", "slump", "small",
    "smart", "smash", "smell", "smile", "smoke", "snack", "snail", "snake",
    "snowy", "solar", "solid", "solve", "sonic", "sorry", "south", "space",
    "spark", "spawn", "speak", "speed", "spend", "spice", "spike", "spill",
    "spine", "spite", "split", "spoke", "spore", "sport", "spout", "spray",
    "spray", "squad", "squid", "stack", "staff", "stage", "stain", "stair",
    "stake", "stale", "stall", "stamp", "stand", "stark", "start", "stash",
    "state", "stays", "steam", "steel", "steep", "steer", "stern", "stock",
    "stoic", "stone", "stood", "store", "storm", "story", "stout", "strap",
    "straw", "stray", "strum", "stuck", "study", "style", "sugar", "suite",
    "sunny", "super", "swamp", "swarm", "swear", "swept", "swift", "swirl",
    "sword", "syrup", "table", "tango", "tapir", "taste", "teach", "tease",
    "teeth", "tempo", "tense", "tenth", "tepid", "thank", "theme", "there",
    "thick", "thing", "thorn", "three", "throw", "tiger", "timed", "tired",
    "title", "tonal", "topic", "torch", "total", "tough", "tower", "track",
    "trade", "trail", "train", "trait", "tramp", "trawl", "tread", "trend",
    "triad", "tribe", "trick", "trout", "trove", "truce", "truck", "truly",
    "truss", "trust", "truth", "tumor", "tuner", "tuxedo", "tweed", "twice",
    "twist", "tying", "ultra", "uncle", "under", "unify", "union", "until",
    "urban", "usher", "utter", "vague", "valid", "valor", "value", "valve",
    "vapid", "vault", "verge", "vigor", "viola", "viper", "viral", "vista",
    "vivid", "vocal", "vodka", "voter", "vowel", "waltz", "watch", "water",
    "weave", "wedge", "weird", "whack", "whale", "wheat", "wheel", "where",
    "which", "while", "white", "whole", "whose", "widen", "witty", "world",
    "worse", "worst", "worth", "would", "wrath", "wreck", "wrist", "wrote",
    "yacht", "yearn", "yield", "young", "yours", "youth", "zebra", "zonal",
]


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


def _create_v2_with_drill(password: str, offer_recovery: bool, err_label, root) -> None:
    """Create the first-run v2 vault, running the write-it-down drill BEFORE
    the recovery slot is committed.

    The order is the point. The obvious flow -- create the vault with a
    recovery slot, then show the key -- leaves a vault whose header advertises
    recovery_slot: true even when the human bails out of the drill, for a key
    that was never written down and can never be shown again. vault_info()
    would then report protection the user does not have, and they would find
    that out at the one moment it matters. Nothing in normal operation ever
    exercises a recovery key, so the lie would keep indefinitely.

    Since the key is generated locally, drilling first costs nothing and makes
    the cancel path honest: no slot is written, and the vault is simply
    password-only -- a fully supported state, not a degraded one.
    """
    raw_rk = new_recovery_key() if offer_recovery else None
    try:
        keep = False
        if raw_rk is not None:
            # Blank the parent's status line so "Working..." isn't sitting
            # behind the drill window for however long the human takes.
            err_label.config(text="", fg=FG_MUTED)
            root.update_idletasks()
            # slot_id is empty here: the store assigns it at write time, and it
            # carries no staleness value at first run -- no earlier key exists
            # to confuse this one with.
            keep = show_recovery_key_dialog(format_recovery_key(bytes(raw_rk)), "")
        err_label.config(text="Working...", fg=FG_MUTED)
        root.update_idletasks()
        if keep:
            store.create_v2_vault(password, recovery_raw=bytes(raw_rk))
        else:
            store.create_v2_vault(password)
    finally:
        if raw_rk is not None:
            # Best-effort in CPython; does not defeat a memory dump.
            for _i in range(len(raw_rk)):
                raw_rk[_i] = 0


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
             "offer_recovery": False}
    pad = {"padx": 18, "pady": 7}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
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

            def gen_passphrase_add():
                phrase = " ".join(_secrets.choice(_WORDLIST) for _ in range(4))
                pw1.delete(0, "end")
                pw1.insert(0, phrase)
                pw2.delete(0, "end")
                pw2.insert(0, phrase)

            _button(container, "Generate passphrase", command=gen_passphrase_add).grid(
                row=row, column=0, columnspan=2, pady=(0, 4))
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
                if len(password) < MIN_PASSWORD_LEN:
                    _show_error(root, err, f"Use at least {MIN_PASSWORD_LEN} characters.")
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["offer_recovery"] = rk_opt_var.get() if rk_opt_var is not None else False
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
                    _create_v2_with_drill(state["password"],
                                          state.get("offer_recovery"), err, root)
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
    root.mainloop()
    return outcome


def remove_secret_dialog(var_name: str, placeholder: int):
    outcome = {"approved": False, "partial_failure": None}
    state = {"password": None, "secrets": None}
    pad = {"padx": 18, "pady": 7}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
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
    state = {"password": None, "secrets": None, "first_run": not store.vault_exists(),
             "offer_recovery": False}
    pad = {"padx": 18, "pady": 7}

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
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
        path_text = tk.Text(path_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            selectbackground=ACCENT, insertbackground=FG,
                            height=2, width=52, wrap="none")
        path_xscroll = _scrollbar(path_frame, orient="horizontal", command=path_text.xview)
        path_text.config(xscrollcommand=path_xscroll.set)
        path_text.insert("end", _collapse_whitespace(str(target)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_xscroll.grid(row=1, column=0, sticky="ew")
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

            def gen_passphrase_install():
                phrase = " ".join(_secrets.choice(_WORDLIST) for _ in range(4))
                pw1.delete(0, "end")
                pw1.insert(0, phrase)
                pw2.delete(0, "end")
                pw2.insert(0, phrase)

            _button(container, "Generate passphrase", command=gen_passphrase_install).grid(
                row=row, column=0, columnspan=2, pady=(0, 4))
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
                if len(password) < MIN_PASSWORD_LEN:
                    _show_error(root, err, f"Use at least {MIN_PASSWORD_LEN} characters.")
                    return
                if password != pw2.get():
                    _show_error(root, err, "Passwords do not match.")
                    return
                state["offer_recovery"] = rk_opt_var.get() if rk_opt_var is not None else False
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
        txt = tk.Text(txt_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                      highlightthickness=1, highlightbackground=BORDER,
                      selectbackground=ACCENT, insertbackground=FG,
                      height=list_height, width=46, wrap="none")
        yscroll = _scrollbar(txt_frame, orient="vertical", command=txt.yview)
        xscroll = _scrollbar(txt_frame, orient="horizontal", command=txt.xview)
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
                   f"{_safe_display(', '.join(sorted(other_owner)), 200)}",
                   fg=WARNING, justify="left").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1

        sensitive_in_migrate = sorted(n for n, _ in to_migrate if n in sensitive_names)
        if sensitive_in_migrate:
            _label(container,
                   f"Warning: {_safe_display(', '.join(sensitive_in_migrate), 200)} "
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
                    _create_v2_with_drill(state["password"],
                                          state.get("offer_recovery"), err, root)
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
    root.mainloop()
    return outcome


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

def _validate_password_fields(pw: str, confirm: str) -> Optional[str]:
    """Validate a new-password pair. Returns an error string or None.
    Pure and Tkinter-free so it can be unit-tested without a display."""
    if not pw:
        return "Password cannot be empty."
    if len(pw) < MIN_PASSWORD_LEN:
        return f"Use at least {MIN_PASSWORD_LEN} characters."
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


def _applicable_manage_actions(info: dict) -> list:
    """Return the list of manage_vault_dialog action IDs that make sense for
    the current vault state described by *info* (from store.vault_info()).

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
    return actions


def _manage_action_result_keys(action: str) -> frozenset:
    """Return the frozenset of keys that manage_vault_dialog includes in its
    result dict for *action*.  Used to test the contract without a display."""
    base = {"action"}
    if action == "change_password":
        return frozenset(base | {"old_password", "new_password"})
    if action in ("setup_recovery", "reissue_recovery", "upgrade_v2"):
        return frozenset(base | {"password"})
    return frozenset(base)


def unlock_for_run_dialog(command_str: str, materialize_path: str = None, only_vars=None,
                          trust_note: str = None):
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
        row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(pad["pady"], 14))
    row += 1

    if trust_note:
        # B3: scrollable, non-truncating -- consent-critical text must never
        # be elided. trust_note can carry a full warning about what trust
        # monitoring covers; cutting it at 300 chars would defeat the purpose.
        note_frame = tk.Frame(root, bg=WINDOW_BG)
        note_text = tk.Text(note_frame, bg=FIELD_BG, fg=WARNING, font=FONT_BODY,
                            relief="flat", highlightthickness=1,
                            highlightbackground=BORDER, selectbackground=ACCENT,
                            insertbackground=FG, height=4, width=52, wrap="word")
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
        vars_txt = tk.Text(vars_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                           highlightthickness=1, highlightbackground=BORDER,
                           selectbackground=ACCENT, insertbackground=FG,
                           height=list_height, width=46, wrap="none")
        vars_yscroll = _scrollbar(vars_frame, orient="vertical", command=vars_txt.yview)
        vars_xscroll = _scrollbar(vars_frame, orient="horizontal", command=vars_txt.xview)
        vars_txt.config(yscrollcommand=vars_yscroll.set, xscrollcommand=vars_xscroll.set)
        for name in var_names:
            vars_txt.insert("end", name + "\n")
        vars_txt.config(state="disabled")
        vars_txt.grid(row=0, column=0, sticky="nsew")
        vars_yscroll.grid(row=0, column=1, sticky="ns")
        vars_xscroll.grid(row=1, column=0, sticky="ew")
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
    cmd_text = tk.Text(cmd_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                        highlightthickness=1, highlightbackground=BORDER,
                        selectbackground=ACCENT, insertbackground=FG,
                        height=3, width=52, wrap="none")
    cmd_xscroll = _scrollbar(cmd_frame, orient="horizontal", command=cmd_text.xview)
    cmd_text.config(xscrollcommand=cmd_xscroll.set)
    cmd_text.insert("end", _collapse_whitespace(command_str))
    cmd_text.config(state="disabled")
    cmd_text.grid(row=0, column=0, sticky="we")
    cmd_xscroll.grid(row=1, column=0, sticky="ew")
    cmd_frame.grid_columnconfigure(0, weight=1)
    cmd_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
    row += 1

    if materialize_path:
        # A1: be explicit about what the file contains, not just that it's cleaned up.
        _label(root, "Also writes real secret values to disk for the lifetime of the command:",
               fg=FG_MUTED, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=pad["padx"], pady=(6, 0))
        row += 1
        path_frame = tk.Frame(root, bg=WINDOW_BG)
        path_text = tk.Text(path_frame, bg=FIELD_BG, fg=FG, font=FONT_BODY, relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            selectbackground=ACCENT, insertbackground=FG,
                            height=2, width=52, wrap="none")
        path_xscroll = _scrollbar(path_frame, orient="horizontal", command=path_text.xview)
        path_text.config(xscrollcommand=path_xscroll.set)
        path_text.insert("end", _collapse_whitespace(str(materialize_path)))
        path_text.config(state="disabled")
        path_text.grid(row=0, column=0, sticky="we")
        path_xscroll.grid(row=1, column=0, sticky="ew")
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
    root.mainloop()
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

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
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
        if not new:
            _show_error(root, err, "New password cannot be empty.")
            return
        if len(new) < MIN_PASSWORD_LEN:
            _show_error(root, err, f"Use at least {MIN_PASSWORD_LEN} characters.")
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
    root.mainloop()
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

    root = tk.Tk()
    root.title("llm-env-vault — Recovery Key")
    root.resizable(False, False)
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
    key_disp = tk.Text(key_frame, bg=FIELD_BG, fg=ACCENT,
                       font=(FONT_FAMILY, 13, "bold"), relief="flat",
                       highlightthickness=1, highlightbackground=BORDER,
                       selectbackground=ACCENT, insertbackground=FG,
                       height=3, width=46, wrap="word")
    key_disp.insert("end", key_text)
    key_disp.config(state="disabled")
    key_disp.grid(row=0, column=0, sticky="we")
    key_frame.grid_columnconfigure(0, weight=1)
    key_frame.grid(row=row, column=0, columnspan=2, sticky="we", padx=pad["padx"])
    row += 1

    _label(root, "Groups of 4 characters separated by hyphens.  The last group is the checksum.",
           fg=FG_MUTED, justify="left").grid(
        row=row, column=0, columnspan=2, sticky="w", **pad)
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

    reentry = _entry(root, width=46)
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
    root.mainloop()
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

    root = tk.Tk()
    root.title("llm-env-vault — Account Recovery")
    root.resizable(False, False)
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
    root.mainloop()
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

    actions = _applicable_manage_actions(info)
    fmt = info.get("format")
    has_rk = info.get("recovery_slot", False)
    rk_slot_id = info.get("recovery_slot_id", "")
    rk_created = info.get("recovery_slot_created", "")

    root = tk.Tk()
    root.title("llm-env-vault")
    root.resizable(False, False)
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
            _button(btns, confirm_labels.get(action, "Confirm"),
                    command=on_confirm, kind="primary").pack(side="left", padx=6)
            root.bind("<Escape>", lambda e: show_main())
            root.bind("<Return>", lambda e: on_confirm())
            pw_entry.focus_force()

        _center(root)

    show_main()
    root.mainloop()
    return outcome
