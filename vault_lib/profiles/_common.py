"""Shared mechanics for the "always allow" profiles (plan 2.4.0 section 4).

Everything the git, docker, kubectl and exact profiles have in common lives
here so that the security-relevant rules exist exactly once:

* binary pinning        ``resolve_pinned_binary`` / ``verify_pinned_binary``
* from-scratch env      ``pinned_path_dirs`` / ``build_env`` / ``is_tool_control_name``
* argv grammar helpers  ``FlagSpec`` / ``tokenize_argv`` / ``has_unsafe_text``
* version floors        ``parse_version`` / ``vercmp`` / ``Floor`` / ``version_problem``
* probes                ``run_probe`` / ``probe_cwd`` (structured result, no raw output)
* hashing + cwd         ``hash_file`` / ``hash_tree`` / ``canonical_cwd`` /
                        ``snapshot_cwd_dlls`` / ``verify_cwd_dlls``
* test relaxations      ``RELAXATIONS`` (strict by default; tests monkeypatch it)

Design rules
------------
* **Pure and light.**  This module imports only the standard library, and
  ``subprocess`` / ``tempfile`` / ``ctypes`` lazily.  ``store.py`` imports
  ``is_tool_control_name`` from here, so it must never import ``store``,
  ``trust`` or ``allowlist`` (import cycle) and must stay cheap to import.
* **Fail closed.**  Anything that cannot be verified (an ACL that cannot be
  read, an executable that cannot be hashed, an unparsable version) is a
  refusal, never a pass.
* **Never call back into the vault.**  Profile checks run under the vault lock,
  so every helper here is local and fast (file reads, a subprocess with a hard
  timeout).  Nothing here touches secrets.
* **Refusals are data.**  Helpers raise ``ProfileRefusal`` subclasses carrying a
  human-readable ``.reason``; a profile turns that into
  ``Verdict(ok=False, reason=...)`` or ineligibility.  Reasons never contain
  file contents or probe output.

Windows write-permission test (``writable_by_current_user``): the effective
rights of the *current process token* on the file's security descriptor are
computed with ``AccessCheck`` (so group membership, deny ACEs, ownership and
inheritance are all honoured by the OS rather than re-implemented).  Limits: a
process running elevated holds the Administrators group and therefore sees
``C:\\Program Files`` as writable, so nothing is eligible when the server runs
elevated (fail closed); network/UNC paths are refused outright; a TOCTOU window
exists between the check and the spawn (the file hash is re-checked right
before spawn, the directory ACL is re-checked at arm time and recheck).
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from vault_lib import envnames

_IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Test-only relaxations (plan section 4, last bullet)
# ---------------------------------------------------------------------------

class Relaxations:
    """Switches that exist only so the test suite can run on a developer
    machine (old git, local bare repositories, fake APIs).  The defaults are
    strict; they are changed ONLY by test monkeypatching -- there is no env
    var, config file or runtime switch, and ``tests/test_profiles_common.py``
    asserts the defaults stay strict (``is_strict()``)."""

    def __init__(self):
        self.git_allowed_protocols = "https"     # tests: "file:https"
        self.skip_https_only_check = False       # tests: True (local bare repo remotes)
        self.version_floors: Dict[str, "Floor"] = {}   # tests: {"git": Floor(...)}
        self.skip_exe_dir_writable_check = False  # tests: True
        self.kubectl_allow_http_loopback = False  # tests: True (fake API)

    def is_strict(self) -> bool:
        return (self.git_allowed_protocols == "https"
                and not self.skip_https_only_check
                and not self.version_floors
                and not self.skip_exe_dir_writable_check
                and not self.kubectl_allow_http_loopback)


RELAXATIONS = Relaxations()


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

class ProfileRefusal(Exception):
    """Base class: ``.reason`` is a short human-readable sentence."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class BinaryRefused(ProfileRefusal):
    """The program cannot be pinned (not native, not found, writable ...)."""


class ArgvRejected(ProfileRefusal):
    """The argv does not match the profile grammar (-> normal dialog)."""


class EnvNameRefused(ProfileRefusal):
    """A variable name collides with the tool-control denylist."""


# ---------------------------------------------------------------------------
# Text safety
# ---------------------------------------------------------------------------

_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def has_unsafe_text(text) -> bool:
    """True when *text* contains NUL/CR/LF or any other control (Cc), format
    (Cf: bidi controls, zero-width characters, BOM), surrogate (Cs),
    private-use (Co), unassigned (Cn) or line/paragraph-separator (Zl, Zp)
    character.  Non-str values are unsafe."""
    if not isinstance(text, str):
        return True
    return any(unicodedata.category(ch) in _UNSAFE_CATEGORIES
               or ch in ("\u2028", "\u2029") for ch in text)


# ---------------------------------------------------------------------------
# Tool-control name denylist (plan section 4)
# ---------------------------------------------------------------------------

def is_tool_control_name(name) -> bool:
    """True when a vault variable *name* could steer how a tool finds its
    config, plugins, helpers, proxies or libraries.  Such variables can never
    be injected by an always-allow entry (and ``add_secret`` refuses new ones).
    The list itself lives in ``vault_lib.envnames`` (the one canonical copy);
    this wrapper only adds the fail-closed rule that a non-str or empty name
    counts as a collision."""
    if not isinstance(name, str) or not name:
        return True
    return envnames.is_tool_control_name(name)


def injected_name_problem(names: Iterable[str]) -> Optional[str]:
    """First collision reason for *names*, or None."""
    for name in names:
        if is_tool_control_name(name):
            return (f"variable {name} is a tool-control name and cannot be "
                    f"injected by an always-allow entry")
    return None


# ---------------------------------------------------------------------------
# Hashing, cwd
# ---------------------------------------------------------------------------

MAX_HASH_BYTES = 512 * 1024 * 1024


def hash_file(path, max_bytes: int = MAX_HASH_BYTES) -> Optional[str]:
    """SHA-256 hex of a regular file, or None (missing, unreadable, directory,
    larger than *max_bytes*)."""
    try:
        path = os.fspath(path)
        if os.path.getsize(path) > max_bytes or not os.path.isfile(path):
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def is_reparse_point(path) -> bool:
    """True for a symlink or (Windows) any reparse point: junction, mount
    point, OneDrive placeholder ... ``False`` for a missing path."""
    try:
        st = os.lstat(os.fspath(path))
    except OSError:
        return False
    import stat as _stat
    if _stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def hash_tree(root, *, max_files: int = 2000, max_bytes_each: int = MAX_HASH_BYTES,
              allow_symlinks: bool = False) -> Dict[str, str]:
    """Fingerprint a directory tree: ``{relative posix path: "<sha256>:<size>"}``
    for every regular file, plus ``"<dir>/": "dir"`` for every directory (so an
    added empty directory is drift too).  Walks without following links.

    Raises ``ProfileRefusal`` when *root* is not a directory, has more than
    *max_files* entries, contains a file that cannot be hashed, or (unless
    *allow_symlinks*) contains a symlink/reparse point."""
    root = os.fspath(root)
    if not os.path.isdir(root) or (is_reparse_point(root) and not allow_symlinks):
        raise ProfileRefusal(f"{root} is not a plain directory")
    out: Dict[str, str] = {}
    pending = [root]
    while pending:
        here = pending.pop()
        try:
            names = sorted(os.listdir(here))
        except OSError as exc:
            raise ProfileRefusal(f"cannot list {here}: {exc.strerror or exc}")
        for name in names:
            full = os.path.join(here, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if len(out) >= max_files:
                raise ProfileRefusal(f"{root} has more than {max_files} entries")
            if is_reparse_point(full) and not allow_symlinks:
                raise ProfileRefusal(f"{full} is a link/reparse point")
            if os.path.isdir(full):
                out[rel + "/"] = "dir"
                pending.append(full)
            else:
                digest = hash_file(full, max_bytes_each)
                if digest is None:
                    raise ProfileRefusal(f"cannot hash {full}")
                out[rel] = f"{digest}:{os.path.getsize(full)}"
    return out


def canonical_cwd(cwd) -> str:
    """realpath (symlinks, junctions, 8.3 names resolved) then normcase, so two
    spellings of one directory compare equal.  Same rule as
    ``allowlist.canonical_cwd``."""
    return os.path.normcase(os.path.realpath(os.fspath(cwd)))


def snapshot_cwd_dlls(cwd, *, enabled: Optional[bool] = None) -> Dict[str, str]:
    """Windows only (``enabled=None`` means "only on Windows"): names and
    SHA-256 of the ``*.dll`` files directly inside *cwd*, casefolded names.
    Defends against DLL side-loading from the working directory (plan
    section 4).  Empty dict on POSIX.  Raises ``ProfileRefusal`` if a DLL
    cannot be hashed (fail closed)."""
    if not (_IS_WINDOWS if enabled is None else enabled):
        return {}
    out: Dict[str, str] = {}
    try:
        names = os.listdir(os.fspath(cwd))
    except OSError as exc:
        raise ProfileRefusal(f"cannot list the working directory: {exc.strerror or exc}")
    for name in names:
        if name.lower().endswith(".dll"):
            digest = hash_file(os.path.join(os.fspath(cwd), name))
            if digest is None:
                raise ProfileRefusal(f"cannot hash {name} in the working directory")
            out[name.casefold()] = digest
    return out


def verify_cwd_dlls(cwd, snapshot, *, enabled: Optional[bool] = None) -> Optional[str]:
    """Drift reason for the cwd DLL snapshot, or None when it still holds."""
    if not (_IS_WINDOWS if enabled is None else enabled):
        return None
    if not isinstance(snapshot, dict):
        return "the approved DLL record is malformed"
    try:
        now = snapshot_cwd_dlls(cwd, enabled=True)
    except ProfileRefusal as exc:
        return exc.reason
    if now == snapshot:
        return None
    changed = sorted((set(now) ^ set(snapshot))
                     | {k for k in now if k in snapshot and now[k] != snapshot[k]})
    return "the DLLs in the working directory changed: " + ", ".join(changed[:5])


# ---------------------------------------------------------------------------
# Version comparison and floors
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+)")


def parse_version(text) -> Optional[Tuple[int, ...]]:
    """First dotted numeric version in *text* as a tuple of ints, or None.

    ``"git version 2.45.1.windows.1"`` -> ``(2, 45, 1)`` (the ``.windows.N``
    suffix is not numeric-dotted so it stops the match), ``"v2.40.2-desktop.1"``
    -> ``(2, 40, 2)``, ``"Docker Desktop 4.88.1 (237512)"`` -> ``(4, 88, 1)``.
    Requires at least one dot, so a bare build number is not a version."""
    if isinstance(text, tuple):
        return tuple(text) if all(isinstance(p, int) for p in text) else None
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def vercmp(a, b) -> int:
    """-1/0/1 comparing two version tuples numerically, zero-padded
    (``(2, 40) == (2, 40, 0)``).  Never compares strings."""
    a, b = tuple(a), tuple(b)
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


@dataclass(frozen=True)
class Floor:
    """A minimum version: ``minimum`` or newer, OR a *patched maintenance
    line*: ``maintenance[(major, minor)] = min_patch`` accepts
    ``major.minor.patch`` for ``patch >= min_patch`` even though it is below
    ``minimum`` (backported fixes)."""
    minimum: Tuple[int, ...]
    maintenance: Mapping[Tuple[int, int], int] = field(default_factory=dict)

    def allows(self, version: Tuple[int, ...]) -> bool:
        if vercmp(version, self.minimum) >= 0:
            return True
        if len(version) >= 2:
            need = self.maintenance.get((version[0], version[1]))
            if need is not None:
                patch = version[2] if len(version) > 2 else 0
                return patch >= need
        return False

    def describe(self) -> str:
        text = ".".join(str(p) for p in self.minimum)
        if self.maintenance:
            lines = ", ".join(f"{a}.{b}.{c}+" for (a, b), c in sorted(self.maintenance.items()))
            text += f" (or a patched maintenance line: {lines})"
        return text


# One table for every floor (plan section 4).  Git for Windows numbers its
# backports like upstream plus ".windows.N"; that numbering is UNVERIFIED --
# only 2.50.1+ is certain to be accepted on Windows.  This machine's git is
# 2.45.1 (< 2.45.4), so git entries are refused here until it is upgraded.
FLOORS: Dict[str, Floor] = {
    "git": Floor((2, 50, 1), {(2, 43): 7, (2, 44): 4, (2, 45): 4, (2, 46): 4,
                              (2, 47): 3, (2, 48): 2, (2, 49): 1}),
    "compose": Floor((2, 40, 2)),
    "docker_desktop": Floor((4, 44, 3)),
    "buildkit": Floor((0, 12, 5)),
}


def floor_for(name: str) -> Floor:
    """The active floor for *name* (a test relaxation wins over ``FLOORS``)."""
    return RELAXATIONS.version_floors.get(name) or FLOORS[name]


def version_problem(name: str, text) -> Optional[str]:
    """None when *text* (raw tool output or a tuple) meets the floor named
    *name*; otherwise a human-readable reason.  An unparsable version fails."""
    version = parse_version(text)
    if version is None:
        return f"cannot determine the {name} version"
    floor = floor_for(name)
    if floor.allows(version):
        return None
    return (f"{name} {'.'.join(str(p) for p in version)} is older than the required "
            f"{floor.describe()}")


# ---------------------------------------------------------------------------
# Executable location: "not writable by the current user"
# ---------------------------------------------------------------------------

# Windows access-mask bits.
_FILE_WRITE_DATA = 0x2          # directory: add file
_FILE_APPEND_DATA = 0x4         # directory: add subdirectory
_FILE_DELETE_CHILD = 0x40
_DELETE = 0x10000
_WRITE_DAC = 0x40000
_WRITE_OWNER = 0x80000
_MASK_OBJECT = (_FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_DELETE_CHILD
                | _DELETE | _WRITE_DAC | _WRITE_OWNER)
# A parent directory only matters if the user can delete/replace or re-ACL the
# child (adding siblings to e.g. C:\ is harmless).
_MASK_PARENT = _FILE_DELETE_CHILD | _DELETE | _WRITE_DAC | _WRITE_OWNER

_win_token = None
_win_token_lock = threading.Lock()


def _win_api():
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE))
    advapi32.DuplicateTokenEx.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_int, ctypes.c_int,
                                          ctypes.POINTER(wintypes.HANDLE))
    advapi32.GetFileSecurityW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    advapi32.AccessCheck.argtypes = (ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD,
                                     ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(wintypes.DWORD),
                                     ctypes.POINTER(wintypes.DWORD),
                                     ctypes.POINTER(wintypes.BOOL))
    return ctypes, wintypes, advapi32, kernel32


def _win_impersonation_token():
    global _win_token
    with _win_token_lock:
        if _win_token is not None:
            return _win_token
        ctypes, wintypes, advapi32, kernel32 = _win_api()
        primary = wintypes.HANDLE()
        # TOKEN_DUPLICATE | TOKEN_QUERY
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x2 | 0x8,
                                         ctypes.byref(primary)):
            raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
        imp = wintypes.HANDLE()
        # TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, SecurityImpersonation,
        # TokenImpersonation
        if not advapi32.DuplicateTokenEx(primary, 0x8 | 0x4 | 0x2, None, 2, 2,
                                         ctypes.byref(imp)):
            raise OSError(ctypes.get_last_error(), "DuplicateTokenEx failed")
        _win_token = imp
        return _win_token


def _win_granted_rights(path: str) -> int:
    """Bitmask of rights the current token is granted on *path* (AccessCheck
    with MAXIMUM_ALLOWED).  Raises OSError when it cannot be determined."""
    ctypes, wintypes, advapi32, _k = _win_api()
    token = _win_impersonation_token()
    api_path = path
    if len(path) > 240 and not path.startswith("\\\\?\\"):
        api_path = "\\\\?\\" + path
    needed = wintypes.DWORD(0)
    advapi32.GetFileSecurityW(api_path, 0x7, None, 0, ctypes.byref(needed))  # owner|group|dacl
    if needed.value == 0:
        raise OSError(ctypes.get_last_error(), f"cannot read the ACL of {path}")
    sd = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetFileSecurityW(api_path, 0x7, sd, needed.value, ctypes.byref(needed)):
        raise OSError(ctypes.get_last_error(), f"cannot read the ACL of {path}")

    class GENERIC_MAPPING(ctypes.Structure):
        _fields_ = [("r", wintypes.DWORD), ("w", wintypes.DWORD),
                    ("x", wintypes.DWORD), ("a", wintypes.DWORD)]

    mapping = GENERIC_MAPPING(0x120089, 0x120116, 0x1200A0, 0x1F01FF)
    privileges = ctypes.create_string_buffer(1024)
    priv_len = wintypes.DWORD(1024)
    granted = wintypes.DWORD(0)
    status = wintypes.BOOL(0)
    ok = advapi32.AccessCheck(sd, token, 0x02000000, ctypes.byref(mapping), privileges,
                              ctypes.byref(priv_len), ctypes.byref(granted),
                              ctypes.byref(status))
    if not ok:
        raise OSError(ctypes.get_last_error(), f"AccessCheck failed for {path}")
    return granted.value if status.value else 0


def _posix_object_problem(st, path: str) -> Optional[str]:
    """POSIX rule for a file or a directory on the executable's path: owned by
    root and not writable by group or others."""
    if st.st_uid != 0:
        return f"{path} is not owned by root"
    if st.st_mode & 0o022:
        return f"{path} is writable by group or others"
    return None


def exe_location_problem(exe_path) -> Optional[str]:
    """Why the executable at *exe_path* may be replaced by the current user
    (or why that cannot be ruled out), or None when it is safe.

    Checks the file, its directory, and every ancestor: POSIX requires root
    ownership and no group/other write on all of them; Windows asks the OS
    (``AccessCheck`` on the current token) whether the user may write/replace
    the file or directory, or delete/re-ACL a parent.  Symlinks are resolved
    first.  Any failure to determine the answer is a problem (fail closed).
    ``RELAXATIONS.skip_exe_dir_writable_check`` (tests only) returns None."""
    if RELAXATIONS.skip_exe_dir_writable_check:
        return None
    try:
        real = os.path.realpath(os.fspath(exe_path))
        if _IS_WINDOWS:
            if real.startswith("\\\\"):
                return f"{real} is on a network path"
            chain = [(real, _MASK_OBJECT)]
            here = os.path.dirname(real)
            chain.append((here, _MASK_OBJECT))
            while True:
                parent = os.path.dirname(here)
                if not parent or parent == here:
                    break
                chain.append((parent, _MASK_PARENT))
                here = parent
            for path, mask in chain:
                if _win_granted_rights(path) & mask:
                    return f"{path} can be modified by the current user"
            return None
        problem = _posix_object_problem(os.stat(real), real)
        if problem:
            return problem
        here = os.path.dirname(real)
        while True:
            problem = _posix_object_problem(os.stat(here), here)
            if problem:
                return problem
            parent = os.path.dirname(here)
            if parent == here:
                return None
            here = parent
    except OSError as exc:
        return f"cannot verify that {exc.filename or exe_path} is protected ({exc.strerror or exc})"


def dir_not_user_writable(path) -> bool:
    """True only when *path* (a directory) is positively verified as not
    modifiable by the current user.  Used to filter PATH entries."""
    path = os.fspath(path)
    if RELAXATIONS.skip_exe_dir_writable_check:
        return os.path.isdir(path)
    try:
        real = os.path.realpath(path)
        return os.path.isdir(real) and _dir_chain_ok(real)
    except OSError:
        return False


def _dir_chain_ok(real: str) -> bool:
    # Same rule as exe_location_problem(), minus the file itself.
    try:
        if _IS_WINDOWS:
            if real.startswith("\\\\"):
                return False
            if _win_granted_rights(real) & _MASK_OBJECT:
                return False
            here = real
            while True:
                parent = os.path.dirname(here)
                if not parent or parent == here:
                    return True
                if _win_granted_rights(parent) & _MASK_PARENT:
                    return False
                here = parent
        here = real
        while True:
            if _posix_object_problem(os.stat(here), here):
                return False
            parent = os.path.dirname(here)
            if parent == here:
                return True
            here = parent
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Binary pinning
# ---------------------------------------------------------------------------

# Extensions that are launcher/script formats: refused whatever the content.
REFUSED_EXTENSIONS = frozenset({
    ".cmd", ".bat", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".msc", ".com", ".scr", ".lnk", ".sh", ".py", ".pl", ".rb",
})


@dataclass(frozen=True)
class PinnedBinary:
    """A program resolved once, to an absolute realpath, with its SHA-256.
    ``fmt`` is ``"pe"``, ``"elf"`` or ``"macho"``.  JSON round-trip with
    ``to_dict`` / ``PinnedBinary.from_dict``."""
    path: str
    sha256: str
    fmt: str
    size: int

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256, "fmt": self.fmt, "size": self.size}

    @staticmethod
    def from_dict(data) -> "PinnedBinary":
        if not isinstance(data, dict):
            raise BinaryRefused("the approved program record is malformed")
        try:
            pin = PinnedBinary(str(data["path"]), str(data["sha256"]),
                               str(data["fmt"]), int(data["size"]))
        except (KeyError, TypeError, ValueError):
            raise BinaryRefused("the approved program record is malformed")
        if not os.path.isabs(pin.path) or not re.fullmatch(r"[0-9a-f]{64}", pin.sha256):
            raise BinaryRefused("the approved program record is malformed")
        return pin


_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                 b"\xcf\xfa\xed\xfe")


def native_format(head: bytes, *, windows: Optional[bool] = None) -> Optional[str]:
    """``"pe"`` / ``"elf"`` / ``"macho"`` from the first bytes of a file (at
    least 4096 recommended), or None when it is not a native executable of the
    platform: Windows accepts PE only, POSIX accepts ELF and Mach-O.  A PE
    must carry the ``PE\\0\\0`` signature and not be flagged as a DLL."""
    windows = _IS_WINDOWS if windows is None else windows
    if windows:
        if head[:2] != b"MZ" or len(head) < 0x40:
            return None
        pe_off = int.from_bytes(head[0x3C:0x40], "little")
        if pe_off < 0x40 or pe_off + 24 > len(head):
            return None
        if head[pe_off:pe_off + 4] != b"PE\0\0":
            return None
        characteristics = int.from_bytes(head[pe_off + 22:pe_off + 24], "little")
        if characteristics & 0x2000:                      # IMAGE_FILE_DLL
            return None
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # Fat Mach-O (a Java class file shares the magic; its next field is a
        # version >= 45, a fat header's is a small architecture count).
        if 0 < int.from_bytes(head[4:8], "big") < 20:
            return "macho"
    return None


def _search_dirs(search_path: Optional[str]) -> List[str]:
    raw = os.environ.get("PATH", "") if search_path is None else search_path
    out = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or entry == "." or not os.path.isabs(entry):
            continue                      # never "." / relative: never cwd
        if _IS_WINDOWS and entry.startswith("\\\\"):
            continue
        out.append(entry)
    return out


def resolve_pinned_binary(program, *, search_path: Optional[str] = None) -> PinnedBinary:
    """Resolve *program* ONCE to a native executable and pin it.

    *program* is an absolute path or a bare name; a relative path with a
    separator is refused.  Bare names are searched in *search_path* (default
    the server's PATH) skipping ``.``/relative/empty/UNC entries -- the current
    directory is never searched.  Windows: ``.exe`` only (a name without
    extension gets ``.exe`` appended); ``.cmd .bat .ps1 .vbs .js ...`` and
    every other script extension are refused whatever the file contains.  The
    result is the symlink-free real path (multi-call binaries invoked through
    differently named links are therefore unsupported), whose first bytes must
    be a native image (PE on Windows, ELF/Mach-O on POSIX -- scripts and
    ``#!`` files fail), whose directory chain is not writable by the current
    user (``exe_location_problem``), and whose SHA-256 is recorded.

    Raises ``BinaryRefused``.  Callers execute ``pin.path`` and never resolve
    again; ``verify_pinned_binary`` re-hashes before each spawn."""
    if has_unsafe_text(program) or not program:
        raise BinaryRefused("the program name is empty or contains control characters")
    ext = os.path.splitext(program)[1].lower()
    if ext in REFUSED_EXTENSIONS:
        raise BinaryRefused(f"{os.path.basename(program)!r} is a script/launcher "
                            f"({ext}), not a native executable")
    has_sep = ("/" in program) or (os.sep in program) or (os.altsep and os.altsep in program)
    names = [program]
    if _IS_WINDOWS and ext != ".exe":
        names = [program + ".exe"]
    found = None
    if os.path.isabs(program):
        if _IS_WINDOWS and program.startswith("\\\\"):
            raise BinaryRefused("network paths are not supported")
        for candidate in names:
            if os.path.isfile(candidate):
                found = candidate
                break
    elif has_sep:
        raise BinaryRefused("a relative program path is not accepted; use a bare name "
                            "or an absolute path")
    else:
        for directory in _search_dirs(search_path):
            for candidate in names:
                full = os.path.join(directory, candidate)
                if os.path.isfile(full) and (_IS_WINDOWS or os.access(full, os.X_OK)):
                    found = full
                    break
            if found:
                break
    if found is None:
        raise BinaryRefused(f"{program!r} could not be found")
    try:
        real = os.path.realpath(found)
    except OSError as exc:
        raise BinaryRefused(f"cannot resolve {program!r}: {exc.strerror or exc}")
    real_ext = os.path.splitext(real)[1].lower()
    if real_ext in REFUSED_EXTENSIONS or (_IS_WINDOWS and real_ext != ".exe"):
        raise BinaryRefused(f"{os.path.basename(real)!r} is not a native .exe executable")
    try:
        with open(real, "rb") as handle:
            head = handle.read(4096)
        size = os.path.getsize(real)
    except OSError as exc:
        raise BinaryRefused(f"cannot read {real}: {exc.strerror or exc}")
    fmt = native_format(head)
    if fmt is None:
        raise BinaryRefused(f"{os.path.basename(real)!r} is not a native executable "
                            f"(scripts and interpreters' files are refused)")
    problem = exe_location_problem(real)
    if problem:
        raise BinaryRefused(f"the program's location is not protected: {problem}")
    digest = hash_file(real)
    if digest is None:
        raise BinaryRefused(f"cannot hash {real}")
    return PinnedBinary(real, digest, fmt, size)


def verify_pinned_binary(pin, *, check_location: bool = True) -> Optional[str]:
    """Drift reason (None = unchanged): the file exists, still hashes to the
    recorded SHA-256 (hence still has the same native image) and, unless
    *check_location* is False, still sits in a protected location.  *pin* is a
    ``PinnedBinary`` or its dict.  Call right before every spawn."""
    try:
        if not isinstance(pin, PinnedBinary):
            pin = PinnedBinary.from_dict(pin)
    except BinaryRefused as exc:
        return exc.reason
    digest = hash_file(pin.path)
    if digest is None:
        return f"the program {pin.path} is missing or unreadable"
    if digest != pin.sha256:
        return f"the program {pin.path} changed since it was approved"
    if check_location:
        problem = exe_location_problem(pin.path)
        if problem:
            return f"the program's location is no longer protected: {problem}"
    return None


# ---------------------------------------------------------------------------
# Environment built from scratch
# ---------------------------------------------------------------------------

_ESSENTIALS_WINDOWS = (
    "SystemRoot", "windir", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOME",
    "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "LANG",
    # Harmless identity/locale facts many CLIs expect to exist.
    "SystemDrive", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
    "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
    "ALLUSERSPROFILE", "USERNAME", "USERDOMAIN", "COMPUTERNAME", "OS",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
)
_ESSENTIALS_POSIX = (
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "TZ",
)


def system_essentials(source: Optional[Mapping[str, str]] = None, *,
                      windows: Optional[bool] = None) -> Dict[str, str]:
    """The allowlisted system variables from *source* (default ``os.environ``),
    names in canonical case.  Windows: ``COMSPEC`` is kept only when it points
    inside ``%SystemRoot%``; otherwise it is rebuilt as
    ``%SystemRoot%\\System32\\cmd.exe``."""
    source = os.environ if source is None else source
    windows = _IS_WINDOWS if windows is None else windows
    names = _ESSENTIALS_WINDOWS if windows else _ESSENTIALS_POSIX
    lookup = {k.casefold(): v for k, v in source.items()} if windows else dict(source)
    out: Dict[str, str] = {}
    for name in names:
        value = lookup.get(name.casefold() if windows else name)
        if isinstance(value, str) and value and "\0" not in value:
            out[name] = value
    if windows:
        root = out.get("SystemRoot") or out.get("windir")
        if root:
            expected = os.path.join(root, "System32", "cmd.exe")
            current = out.get("COMSPEC")
            if not current or os.path.normcase(os.path.abspath(current)) != \
                    os.path.normcase(expected):
                out["COMSPEC"] = expected
        else:
            out.pop("COMSPEC", None)
    return out


def pinned_path_dirs(base_path: Optional[str] = None, extra: Iterable[str] = (), *,
                     windows: Optional[bool] = None) -> List[str]:
    """The approval-time PATH list: absolute, existing, de-duplicated
    directories from *base_path* (default the server PATH) that are NOT
    modifiable by the current user (``dir_not_user_writable``), preceded by
    *extra* (profile-owned directories, e.g. the pinned program's own
    directory, which must pass the same test).  Windows always gets
    ``%SystemRoot%\\System32`` and ``%SystemRoot%``.  Record the result in the
    snapshot and pass it back to ``build_env`` at run time; never re-derive it."""
    windows = _IS_WINDOWS if windows is None else windows
    candidates = list(extra) + _search_dirs(base_path)
    if windows:
        root = os.environ.get("SystemRoot") or os.environ.get("windir")
        if root:
            candidates += [os.path.join(root, "System32"), root]
    seen, out, memo = set(), [], {}
    for entry in candidates:
        if not os.path.isabs(entry):
            continue
        spelled = os.path.normpath(entry)
        real = os.path.normpath(os.path.realpath(entry))
        # A link (or a link somewhere in the chain) is never recorded: the
        # approval covers where it points NOW, and it could be retargeted later.
        # Record the resolved directory, and require the link's own parent to be
        # protected too (the name was chosen by whoever can write there).
        is_link = os.path.normcase(real) != os.path.normcase(spelled)
        key = os.path.normcase(real)
        if key in seen:
            continue
        seen.add(key)
        if key not in memo:
            memo[key] = dir_not_user_writable(real) and (
                not is_link or dir_not_user_writable(os.path.dirname(spelled)))
        if memo[key]:
            out.append(real if is_link else spelled)
    return out


def build_env(path_dirs: Iterable[str], *, injected: Optional[Mapping[str, str]] = None,
              extra: Optional[Mapping[str, str]] = None,
              source: Optional[Mapping[str, str]] = None,
              windows: Optional[bool] = None) -> Dict[str, str]:
    """A complete child environment built from scratch (never scrubbed):
    ``system_essentials`` + ``PATH`` = *path_dirs* joined + *injected* (vault
    values or sentinels; every name is checked against
    ``is_tool_control_name`` and a collision raises ``EnvNameRefused``) +
    *extra* (the profile's own pins such as ``GIT_ALLOW_PROTOCOL``; applied
    last, exempt from the denylist because the profile owns them).  Pass
    ``injected=None`` for a verdict env (the caller adds the vault values on
    top, ``replace_env=True``)."""
    env = system_essentials(source, windows=windows)
    env["PATH"] = os.pathsep.join(os.fspath(d) for d in path_dirs)
    for name, value in (injected or {}).items():
        problem = injected_name_problem([name])
        if problem:
            raise EnvNameRefused(problem)
        if not isinstance(value, str) or "\0" in value:
            raise EnvNameRefused(f"variable {name} has a value that cannot be passed")
        env[name] = value
    for name, value in (extra or {}).items():
        if not isinstance(name, str) or not name or "=" in name or "\0" in name \
                or not isinstance(value, str) or "\0" in value:
            raise EnvNameRefused(f"invalid pinned variable {name!r}")
        env[name] = value
    return env


# ---------------------------------------------------------------------------
# Argv grammar
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FlagSpec:
    """One allowlisted flag.  ``long`` is ``"--name"``, ``short`` is ``"-x"``.

    Spellings are fixed: a long value flag only as ``--name=value``; a short
    value flag only as ``-x VALUE`` (two tokens).  Everything else (``-xVALUE``,
    ``-x=VALUE``, ``--name VALUE``, abbreviations, combined shorts) is
    rejected.  Canonical output prefers the long form."""
    long: Optional[str] = None
    short: Optional[str] = None
    value: bool = False
    pattern: Optional[str] = None                    # re.fullmatch on the value
    check: Optional[Callable[[str], Optional[str]]] = None   # -> error text or None
    repeatable: bool = False
    allow_empty: bool = False

    def __post_init__(self):
        if not (self.long or self.short):
            raise ValueError("a FlagSpec needs a long or a short name")
        if self.long and not re.fullmatch(r"--[A-Za-z0-9][A-Za-z0-9-]*", self.long):
            raise ValueError(f"bad long flag {self.long!r}")
        if self.short and not re.fullmatch(r"-[A-Za-z0-9]", self.short):
            raise ValueError(f"bad short flag {self.short!r}")

    @property
    def key(self) -> str:
        return self.long or self.short

    def canonical(self, value=None) -> List[str]:
        if not self.value:
            return [self.key]
        if self.long:
            return [f"{self.long}={value}"]
        return [self.short, value]


@dataclass
class ParsedArgv:
    """Result of ``tokenize_argv``.  ``flags`` maps ``FlagSpec.key`` to the list
    of values given (``[True]`` for a boolean flag), ``positionals`` are the
    non-flag tokens in order.  ``canonical_flag_tokens()`` is deterministic
    (declaration order of the specs, not the agent's order)."""
    specs: Tuple[FlagSpec, ...]
    flags: Dict[str, list] = field(default_factory=dict)
    positionals: List[str] = field(default_factory=list)

    def has(self, key: str) -> bool:
        return key in self.flags

    def value(self, key: str, default=None):
        values = self.flags.get(key)
        return values[0] if values else default

    def canonical_flag_tokens(self) -> List[str]:
        out: List[str] = []
        for spec in self.specs:
            for value in self.flags.get(spec.key, ()):
                out.extend(spec.canonical(value))
        return out


def tokenize_argv(tokens, specs: Iterable[FlagSpec], *, max_positionals: Optional[int] = None,
                  min_positionals: int = 0) -> ParsedArgv:
    """Parse *tokens* (the argv AFTER the subcommand) against *specs*.

    Every token must be a flag from *specs* in its fixed spelling or a
    positional.  Rejected (``ArgvRejected``, which a profile maps to "show the
    normal dialog"): non-str, empty, NUL/CR/LF/bidi/zero-width/non-printable
    text, ``--``, a lone ``-``, any other token starting with ``-`` that is not
    an allowlisted spelling, ``@file`` tokens or values, a missing / dash-led /
    empty value, a repeated flag (unless ``repeatable``), a value failing
    ``pattern`` / ``check``, and positional counts outside the bounds."""
    specs = tuple(specs)
    by_long = {s.long: s for s in specs if s.long}
    by_short = {s.short: s for s in specs if s.short}
    out = ParsedArgv(specs)
    tokens = list(tokens)
    i = 0

    def reject(why):
        raise ArgvRejected(why)

    def check_value(spec: FlagSpec, value: str):
        if has_unsafe_text(value):
            reject(f"{spec.key} has a value with control or non-printable characters")
        if value == "" and not spec.allow_empty:
            reject(f"{spec.key} has an empty value")
        if value.startswith("@"):
            reject(f"{spec.key} has an @file value")
        if spec.pattern and not re.fullmatch(spec.pattern, value):
            reject(f"the value of {spec.key} is not allowed: {value!r}")
        if spec.check:
            problem = spec.check(value)
            if problem:
                reject(problem)

    def record(spec: FlagSpec, value):
        if spec.key in out.flags and not spec.repeatable:
            reject(f"{spec.key} is repeated")
        out.flags.setdefault(spec.key, []).append(value)

    while i < len(tokens):
        token = tokens[i]
        i += 1
        if not isinstance(token, str):
            reject("an argument is not text")
        if token == "":
            reject("an argument is empty")
        if has_unsafe_text(token):
            reject(f"an argument has control or non-printable characters: {token!r}")
        if token == "--":
            reject("'--' is not accepted from the agent")
        if token.startswith("@"):
            reject(f"@file arguments are not accepted: {token!r}")
        if not token.startswith("-"):
            out.positionals.append(token)
            continue
        if token.startswith("--"):
            name, eq, value = token.partition("=")
            spec = by_long.get(name)
            if spec is None:
                reject(f"flag {name!r} is not allowed")
            if spec.value:
                if not eq:
                    reject(f"{name} must be written {name}=VALUE")
                check_value(spec, value)
                record(spec, value)
            else:
                if eq:
                    reject(f"{name} takes no value")
                record(spec, True)
            continue
        spec = by_short.get(token)
        if spec is None:
            reject(f"flag {token!r} is not allowed (fused or unknown short flag)")
        if spec.value:
            if i >= len(tokens):
                reject(f"{token} needs a value")
            value = tokens[i]
            i += 1
            if not isinstance(value, str) or value.startswith("-"):
                reject(f"{token} needs a plain value")
            check_value(spec, value)
            record(spec, value)
        else:
            record(spec, True)
    if len(out.positionals) < min_positionals:
        reject("too few arguments")
    if max_positionals is not None and len(out.positionals) > max_positionals:
        reject("too many arguments")
    return out


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

PROBE_TIMEOUT = 10.0
PROBE_MAX_OUTPUT = 256 * 1024

_probe_dir: Optional[str] = None
_probe_dir_lock = threading.Lock()


def probe_cwd() -> str:
    """A vault-owned EMPTY directory to run probes in (also defeats Windows DLL
    side-loading from the caller's cwd).  Created once per process under the
    temp directory with a random name and mode 0700; re-checked for emptiness
    on every call and recreated if anything appeared.  Limit: it lives in the
    user's temp area, so same-user code can still write to it between the
    emptiness check and the spawn."""
    import tempfile
    global _probe_dir
    with _probe_dir_lock:
        if _probe_dir and os.path.isdir(_probe_dir) and not os.listdir(_probe_dir) \
                and not is_reparse_point(_probe_dir):
            return _probe_dir
        _probe_dir = os.path.realpath(tempfile.mkdtemp(prefix="llm-env-vault-probe-"))
        return _probe_dir


class ProbeResult:
    """Outcome of ``run_probe``.  Holds the child's output for the *profile*
    to derive hashes/verdicts from; it is deliberately not printable (``repr``
    shows sizes only) and must never be returned to the agent or logged.

    ``ok`` -- the process started, exited 0 within the timeout and its output
    fit the cap.  ``error`` is a short reason when it did not run at all."""
    __slots__ = ("returncode", "timed_out", "truncated", "error", "_stdout", "_stderr")

    def __init__(self, returncode=None, stdout=b"", stderr=b"", timed_out=False,
                 truncated=False, error=None):
        self.returncode = returncode
        self.timed_out = timed_out
        self.truncated = truncated
        self.error = error
        self._stdout = stdout
        self._stderr = stderr

    @property
    def ok(self) -> bool:
        return (self.error is None and not self.timed_out and not self.truncated
                and self.returncode == 0)

    @property
    def stdout(self) -> bytes:
        return self._stdout

    @property
    def stderr(self) -> bytes:
        return self._stderr

    def stdout_text(self) -> str:
        return self._stdout.decode("utf-8", "replace")

    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", "replace")

    def stdout_sha256(self) -> str:
        return hashlib.sha256(self._stdout).hexdigest()

    def failure_reason(self) -> str:
        """A safe one-line reason (never includes output)."""
        if self.error:
            return self.error
        if self.timed_out:
            return "the check timed out"
        if self.truncated:
            return "the check produced too much output"
        return f"the check exited with status {self.returncode}"

    def __repr__(self):
        return (f"<ProbeResult ok={self.ok} rc={self.returncode} timed_out={self.timed_out} "
                f"truncated={self.truncated} stdout={len(self._stdout)}B "
                f"stderr={len(self._stderr)}B>")

    __str__ = __repr__


def run_probe(argv, env, *, cwd: Optional[str] = None, timeout: float = PROBE_TIMEOUT,
              max_output: int = PROBE_MAX_OUTPUT, stdin_bytes: Optional[bytes] = None,
              expect_sha256: Optional[str] = None,
              forbidden_values: Iterable[str] = ()) -> ProbeResult:
    """Run one read-only helper command and return a structured result.

    ``argv[0]`` must be an absolute path (the pinned binary; pass its SHA-256
    as *expect_sha256* to have it re-hashed first).  *env* is the COMPLETE
    environment (``build_env``; ``None`` is refused so a probe can never
    inherit the server's own).  *forbidden_values* are vault secret values that
    must not appear among the env values (probes use sentinels).  cwd defaults
    to ``probe_cwd()``.  stdin is closed (or fed *stdin_bytes*), stdout/stderr
    are captured up to *max_output* bytes each (more sets ``truncated``), the
    wall-clock *timeout* kills the child, no console window opens.

    Never raises for operational failures: returns ``ProbeResult(error=...)``."""
    import subprocess
    from ..procs import NO_WINDOW

    argv = list(argv)
    if not argv or not isinstance(argv[0], str) or not os.path.isabs(argv[0]):
        return ProbeResult(error="the probe program is not an absolute path")
    if any(not isinstance(a, str) or "\0" in a for a in argv):
        return ProbeResult(error="the probe arguments are invalid")
    if env is None or not isinstance(env, Mapping):
        return ProbeResult(error="a probe needs an explicit environment")
    forbidden = {v for v in forbidden_values if isinstance(v, str) and v}
    if forbidden and any(v in forbidden for v in env.values()):
        return ProbeResult(error="a probe environment must not contain vault values")
    if expect_sha256 is not None and hash_file(argv[0]) != expect_sha256:
        return ProbeResult(error="the probe program changed since it was approved")
    kill_tree = close_job = None
    try:
        run_cwd = cwd if cwd is not None else probe_cwd()
        extra = {} if os.name == "nt" else {"start_new_session": True}
        proc = subprocess.Popen(
            argv, env=dict(env), cwd=run_cwd, shell=False, creationflags=NO_WINDOW,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, **extra)
    except (OSError, ValueError) as exc:
        return ProbeResult(error=f"the probe could not start ({getattr(exc, 'strerror', None) or exc})")
    # Everything the probe spawned must die with it: a Job object (reusing
    # procs._windows_job, KILL_ON_JOB_CLOSE) on Windows, the process group the
    # child leads on POSIX.
    job_terminate = None
    if os.name == "nt":
        try:
            from ..procs import _windows_job
            assign, job_terminate, close_job, _handle = _windows_job()
            if assign is None or not assign(int(proc._handle)):
                job_terminate = None
        except Exception:  # noqa: BLE001 -- ctypes trouble must not break a probe
            job_terminate = None

    def kill_tree():
        if job_terminate is not None:
            try:
                job_terminate()
            except Exception:  # noqa: BLE001
                pass
        elif os.name != "nt":
            import signal
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass

    buffers = {"out": bytearray(), "err": bytearray()}
    overflow = {"out": False, "err": False}

    def pump(stream, key):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                room = max_output - len(buffers[key])
                if room > 0:
                    buffers[key].extend(chunk[:room])
                if len(chunk) > room:
                    overflow[key] = True
        except (OSError, ValueError):
            return

    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
    for t in threads:
        t.start()
    if stdin_bytes is not None:
        def feed():
            try:
                proc.stdin.write(stdin_bytes)
            except (OSError, ValueError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_tree()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    import time
    deadline = time.monotonic() + 2
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    # A reader still alive means a descendant keeps the pipe open: whatever was
    # read is partial.  End the tree, give the readers one more moment, and report
    # the probe as failed whatever the exit status was (fail closed).
    incomplete = any(t.is_alive() for t in threads)
    if incomplete:
        kill_tree()
        deadline = time.monotonic() + 2
        for t in threads:
            t.join(timeout=max(0.0, deadline - time.monotonic()))
    if close_job is not None:
        try:
            close_job()
        except Exception:  # noqa: BLE001
            pass
    for stream, t in zip((proc.stdout, proc.stderr), threads):
        if t.is_alive():
            continue                      # close() would wait on the reader's lock
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    return ProbeResult(returncode=None if timed_out else proc.returncode,
                       stdout=bytes(buffers["out"]), stderr=bytes(buffers["err"]),
                       timed_out=timed_out,
                       truncated=overflow["out"] or overflow["err"],
                       error=("the check left a process holding its output open"
                              if incomplete else None))
