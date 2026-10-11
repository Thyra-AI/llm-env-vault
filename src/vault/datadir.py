"""Where the vault lives on disk.

Resolution order, first match wins:

  1. THYRA_VAULT_HOME   an explicit directory, used as given.
  2. CLAUDE_PLUGIN_DATA the Claude Code plugin data dir; the vault is its
                        ``vault`` subdirectory (the one place documented to
                        survive ``claude plugin update``).
  3. A source checkout  next to the module, as it always was for a manual/dev
                        run (and what the existing tests rely on).
  4. The user's data directory, when installed as a package or frozen into an
                        executable: ``~/.local/share/thyra-vault`` (XDG),
                        ``~/Library/Application Support/Thyra Vault`` or
                        ``%LOCALAPPDATA%\\Thyra Vault``.

Step 4 exists because a package install (``uvx``, ``pipx``, a PyInstaller
executable) has no checkout to sit next to: the module lives in a cache or a
temporary extraction directory that is thrown away, and a vault created there
would vanish with it.

Pure functions of their arguments, so each rule is testable without touching
the real environment.
"""
import os
import stat
import sys
from pathlib import Path
from typing import Mapping, Optional

APP_DIRNAME_POSIX = "thyra-vault"
APP_DIRNAME_DESKTOP = "Thyra Vault"


def is_installed_copy(module_file: Path, frozen: bool) -> bool:
    """True when this code runs from a package install or a frozen executable."""
    if frozen:
        return True
    return any(part in ("site-packages", "dist-packages") for part in module_file.parts)


def user_data_dir(platform: str, env: Mapping[str, str], home: Path) -> Path:
    if platform == "win32":
        base = env.get("LOCALAPPDATA") or env.get("APPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / APP_DIRNAME_DESKTOP
    if platform == "darwin":
        return home / "Library" / "Application Support" / APP_DIRNAME_DESKTOP
    xdg = env.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg and os.path.isabs(xdg) else home / ".local" / "share"
    return base / APP_DIRNAME_POSIX


def resolve_root(env: Mapping[str, str], module_file: Path, *, frozen: bool,
                 platform: str, home: Path) -> Path:
    explicit = (env.get("THYRA_VAULT_HOME") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    plugin_data = env.get("CLAUDE_PLUGIN_DATA")
    if plugin_data:
        return Path(plugin_data).resolve() / "vault"
    if is_installed_copy(module_file, frozen):
        return user_data_dir(platform, env, home)
    return _checkout_root(module_file)


def _checkout_root(module_file: Path) -> Path:
    """The folder that contains the `src` package, wherever this module sits inside it."""
    here = module_file.resolve()
    for parent in here.parents:
        if parent.name == "src":
            return parent.parent
    return here.parent.parent


def explicit_home_given(env: Mapping[str, str]) -> bool:
    """Whether THYRA_VAULT_HOME names the directory (then nothing is adopted)."""
    return bool((env.get("THYRA_VAULT_HOME") or "").strip())


def explicit_location_given(env: Mapping[str, str]) -> bool:
    """Whether the environment names the vault directory (rules 1 or 2)."""
    return bool((env.get("THYRA_VAULT_HOME") or "").strip() or env.get("CLAUDE_PLUGIN_DATA"))


def current_root(module_file: Path) -> Path:
    return resolve_root(os.environ, module_file, frozen=bool(getattr(sys, "frozen", False)),
                        platform=sys.platform, home=Path.home())


def make_private_dir(path: Path) -> None:
    """Create the vault directory; a NEW one is owner-only (0700 on POSIX)."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed and os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


# --- adopting a vault left by the old plugin id ------------------------------
#
# The plugin used to be called llm-env-vault, so Claude Code gave it a data
# directory like ``.../plugins/data/llm-env-vault-<marketplace>/``. Under the
# new id the directory is different, and without this step an existing user
# would open Thyra Vault and find an empty, "first run" vault while the real one
# sits next door. The old vault is COPIED, never moved or deleted: if anything
# here goes wrong, the original is exactly where it was.
#
# This runs at import time on a directory name an outsider could imitate, so it
# is deliberately narrow: the exact legacy id, real (non-link) directories owned
# by this user, a fixed list of file names, no overwriting, and every failure
# leaves the new data directory as it was.

LEGACY_DIR_PREFIX = "llm-env-vault-"
ADOPTED_NOTE = "migrated-from.txt"
AMBIGUOUS_NOTE = "migrate-ambiguous.txt"
# Only these are copied: the vault and the bookkeeping that belongs with it.
ADOPT_ALLOWLIST = ("vault_index.json", "targets.json", "files.json", "placeholder_shapes.json",
                   "target_styles.json", "vault.format.txt", "vault.salt", "vault.enc")
_ADOPT_LAST = ("vault.salt", "vault.enc")  # the files that make a vault "exist", copied last
_MAX_ADOPT_BYTES = 64 * 1024 * 1024


def _mine(st) -> bool:
    return not hasattr(os, "getuid") or st.st_uid == os.getuid()


def _is_plain_dir(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and _mine(st)


def find_legacy_vault(plugin_data: Path) -> Optional[Path]:
    """The one ``<legacy plugin data dir>/vault`` that holds a vault.enc, or None.

    With several candidates there is no safe way to tell the real one from a
    decoy someone planted next to it, so none is adopted: a note is left in
    ``plugin_data`` (best-effort) and the user can copy the right one by hand.
    """
    parent = plugin_data.parent
    try:
        siblings = sorted(parent.iterdir())
    except OSError:
        return None
    found = []
    for d in siblings:
        if not d.name.startswith(LEGACY_DIR_PREFIX) or d.name == plugin_data.name:
            continue
        vault = d / "vault"
        enc = vault / "vault.enc"
        try:
            if not (_is_plain_dir(d) and _is_plain_dir(vault)):
                continue
            st = enc.lstat()
            if not (stat.S_ISREG(st.st_mode) and _mine(st)):
                continue
        except OSError:
            continue
        found.append(vault)
    if len(found) > 1:
        try:
            plugin_data.mkdir(parents=True, exist_ok=True)
            (plugin_data / AMBIGUOUS_NOTE).write_text(
                "More than one old vault was found, so none was copied:\n"
                + "".join(f"  {v}\n" for v in found), encoding="utf-8")
        except OSError:
            pass
        return None
    return found[0] if found else None


def _copy_nofollow(src: Path, dst: Path) -> None:
    """Copy a regular file without following a link swapped in after the check."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(src), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not _mine(st) or st.st_size > _MAX_ADOPT_BYTES:
            raise OSError(f"{src.name}: not a plain file of ours")
        out_fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "rb", closefd=False) as fin, os.fdopen(out_fd, "wb") as fout:
            while True:
                chunk = fin.read(1 << 20)
                if not chunk:
                    break
                fout.write(chunk)
    finally:
        os.close(fd)


def _same_file(a: Path, b: Path) -> bool:
    """True when ``b`` is a plain file whose bytes equal ``a``'s."""
    try:
        if b.is_symlink() or not b.is_file() or b.stat().st_size != a.stat().st_size:
            return False
        return _read_all(a) == _read_all(b)
    except OSError:
        return False


def _read_all(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(_MAX_ADOPT_BYTES + 1)


def adopt_legacy_vault(root: Path, plugin_data: Optional[str]) -> Optional[Path]:
    """Copy a vault from the old plugin's data directory into ``root``.

    Does nothing -- returns None -- unless ``root`` has no vault.enc and has not
    adopted one before. Returns the source directory when files were copied.
    Never overwrites a file that is already in ``root``, never touches the
    source, copies only ADOPT_ALLOWLIST, and swallows every failure (a failed
    adoption must not stop the vault from loading).
    """
    if not plugin_data:
        return None
    try:
        return _adopt_legacy_vault(root, Path(plugin_data))
    except (OSError, ValueError):
        return None


def _adopt_legacy_vault(root: Path, plugin_data: Path) -> Optional[Path]:
    if (root / "vault.enc").exists() or (root / ADOPTED_NOTE).exists():
        return None
    source = find_legacy_vault(plugin_data)
    if source is None:
        return None
    names = [n for n in ADOPT_ALLOWLIST if (source / n).is_file() and not (source / n).is_symlink()]
    if "vault.enc" not in names:
        return None
    names.sort(key=lambda n: (n in _ADOPT_LAST, _ADOPT_LAST.index(n) if n in _ADOPT_LAST else 0, n))
    import shutil
    stage = root / ".adopting"
    if stage.is_symlink():
        stage.unlink()
    else:
        shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(mode=0o700)
    try:
        for name in names:
            _copy_nofollow(source / name, stage / name)
        for name in names:
            dest = root / name
            if not dest.exists() and not dest.is_symlink():
                continue
            if name not in _ADOPT_LAST:
                continue  # never overwrite what is already here
            # A crash after vault.salt landed but before vault.enc must not
            # wedge adoption: a leftover from our own earlier copy is
            # byte-identical to the source; anything else is not ours.
            if not _same_file(stage / name, dest):
                raise OSError(f"{name} already exists")
        for name in names:  # vault.enc last: until it lands, a retry starts over
            if not (root / name).exists():
                os.replace(stage / name, root / name)
        with open(root / ADOPTED_NOTE, "x", encoding="utf-8") as note:
            note.write(f"Copied from {source}. The original was left untouched.\n")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return source
