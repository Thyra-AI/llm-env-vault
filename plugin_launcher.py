#!/usr/bin/env python3
"""Bootstrap launcher for llm-env-vault as a Claude Code plugin.

This is what .mcp.json actually runs (via bare `python`) instead of
mcp_server.py directly. Reasons a launcher is needed at all:

- A plugin can't ship a committed virtualenv: .venv/ is gitignored on
  purpose (platform-specific binaries have no business in git), but
  every *installed* copy of this plugin still needs cryptography and
  mcp[cli] importable.
- Claude Code auto-installs a plugin's Node.js dependencies into the
  cache when it installs/updates the plugin (see "Node.js package
  dependencies" in the plugins reference), but there is no equivalent
  automatic step for Python. The documented pattern for exactly this
  case is: provision it yourself into ${CLAUDE_PLUGIN_DATA} -- the
  persistent directory that survives plugin updates -- and the Node.js
  example in that same doc section (installing node_modules from a
  SessionStart hook) is the direct analog of what this script does for
  a venv, just inline in the launcher instead of a separate hook.

CLAUDE_PLUGIN_ROOT and CLAUDE_PLUGIN_DATA are exported by Claude Code
into every MCP server subprocess's environment automatically -- this
script doesn't need them passed as args, and doesn't do anything if
they're absent (falls back to running next to itself, so `python
plugin_launcher.py` still works for local testing outside a plugin
install).

If the plugin's tools never show up as available, check
${CLAUDE_PLUGIN_DATA}/provision.log first. Confirmed to happen in
practice: an MCP client's server-startup timeout can kill this launcher
mid-install (venv created, but `pip install` never finishes) -- from the
outside that looks identical to the server simply never having started,
with no error visible anywhere else. provision.log captures the exact pip
output for whichever attempt ran last, successful or not.
"""
import contextlib
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("CLAUDE_PLUGIN_DATA", PLUGIN_ROOT / ".venv-data"))
VENV_DIR = DATA_DIR / "venv"
INSTALL_LOG = DATA_DIR / "provision.log"

# The hash-pinned lockfile is Windows-only (the platform pywin32 -- a
# transitive mcp[cli] dependency -- actually has wheels for, and this
# project's tested/primary platform). Falls back to the unpinned
# requirements.txt everywhere else rather than risk a hash-pinned file
# that silently can't resolve on a platform it wasn't verified against.
_LOCKFILE = PLUGIN_ROOT / "requirements-lock.txt"
REQUIREMENTS = _LOCKFILE if sys.platform == "win32" and _LOCKFILE.exists() \
    else PLUGIN_ROOT / "requirements.txt"

STAMP_FILE = DATA_DIR / "requirements.sha256"
# Written before an attempt starts (unlike STAMP_FILE, which is only
# written after one succeeds) -- see _ensure_venv for why this exists
# separately: it's what lets a retry tell "this is the same target as the
# last, interrupted attempt" apart from "the target itself changed."
ATTEMPT_FILE = DATA_DIR / "requirements.attempt"
LOCK_FILE = DATA_DIR / "provision.lock"

# Only set when actually running as an installed plugin (Claude Code
# exports it into every MCP server subprocess automatically).
_IS_INSTALLED_PLUGIN = "CLAUDE_PLUGIN_ROOT" in os.environ


def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _requirements_hash() -> str:
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()


def _log(message: str) -> None:
    """Appends a timestamped line to provision.log. Best-effort -- a
    logging failure (e.g. DATA_DIR unwritable) must never take down
    provisioning itself, so this only ever swallows OSError, never raises."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(INSTALL_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def _reset_log() -> None:
    """Starts a fresh provision.log for this attempt instead of appending
    forever -- across a machine's lifetime of repeated interrupted
    installs (the exact scenario this file exists to diagnose), an
    append-only log would grow unbounded. Only the most recent attempt is
    ever relevant to "why isn't this working right now," so that's all
    that's kept."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        INSTALL_LOG.write_text("", encoding="utf-8")
    except OSError:
        pass


@contextlib.contextmanager
def _provision_lock():
    """Cross-process lock around an entire provisioning attempt. Two
    Claude Code sessions can trigger first-run provisioning against the
    same persistent CLAUDE_PLUGIN_DATA at the same time (e.g. two project
    windows opened right after installing the plugin) -- without this,
    concurrent `pip install` calls into the same venv, and concurrent
    writers to the same (now truncate-on-start) provision.log, can
    interleave or clobber each other. Blocks rather than failing fast: if
    another process is genuinely mid-install, the right thing to do is
    wait for it to finish (then re-check whether provisioning is even
    still needed -- see _ensure_venv), not duplicate the work.

    Self-contained (no import from vault_lib, which has its own
    dependencies plugin_launcher's whole job is to install in the first
    place -- it cannot import anything not-yet-installed itself)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR)
    try:
        if sys.platform == "win32":
            import msvcrt
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.2)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _venv_is_functional(python: Path) -> bool:
    """python.exists() alone isn't proof the venv is usable: `python -m
    venv` copies the interpreter binary before running ensurepip, so an
    attempt interrupted between those two steps -- the same startup-
    timeout failure mode this whole module defends against, just landing
    one step earlier -- leaves a python.exe with no pip module. The retry
    path skips recreating the venv when it's already functional (the slow
    part was never venv creation); skipping it based on python.exists()
    alone would get permanently stuck on that half-built state instead --
    every retry would keep failing the dependency-install step with 'No
    module named pip' and never repair itself, since nothing would ever
    re-run `python -m venv`."""
    if not python.exists():
        return False
    try:
        result = subprocess.run([str(python), "-m", "pip", "--version"],
                                 capture_output=True, timeout=10)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_logged(cmd: list[str], step: str) -> None:
    """Runs `cmd`, logs its full output to provision.log regardless of
    outcome, and raises a clean RuntimeError pointing at that log on
    failure -- never a bare, unlogged CalledProcessError. Used for BOTH
    venv creation and the pip install, so a venv-creation failure (disk
    full, missing ensurepip, permission denied on DATA_DIR) gets the same
    diagnosable trail as a dependency-install failure, not a raw traceback
    while the log stays empty.

    `text=True` decoding is pinned to UTF-8 with errors replaced rather
    than the platform default (on Windows, the ANSI codepage) -- otherwise
    non-ASCII bytes in the subprocess's own output (an accented username
    in a path, non-ASCII text in a dependency's error message) could raise
    an uncaught UnicodeDecodeError before this function ever gets a chance
    to log anything, defeating the entire point of it existing."""
    _log(f"Running ({step}): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
    if result.stdout:
        _log(result.stdout.rstrip())
    if result.returncode != 0:
        if result.stderr:
            _log(result.stderr.rstrip())
        _log(f"FAILED ({step}) with exit code {result.returncode}")
        raise RuntimeError(
            f"llm-env-vault: {step} failed (exit code {result.returncode}). "
            f"Full output in {INSTALL_LOG}."
        )


def _rmtree_best_effort(path: Path) -> None:
    """Remove a directory tree silently. On Windows, files still held open by
    another process raise WinError 32 inside shutil.rmtree -- swallowing that
    here is intentional: the caller handles the failure case."""
    try:
        shutil.rmtree(path)
    except OSError:
        pass


def _find_uv() -> str | None:
    """Return the absolute path to the `uv` binary if it's on PATH, else None.
    uv (https://github.com/astral-sh/uv) is 10-50x faster than pip for the
    install step that dominates first-run provisioning time -- the main reason
    the launcher can be killed by MCP startup timeouts before it finishes."""
    return shutil.which("uv")


def _install_marker() -> str:
    """What decides whether the venv needs (re)provisioning.

    Installed plugin (CLAUDE_PLUGIN_ROOT set): keyed on CLAUDE_PLUGIN_ROOT's
    own resolved path, NOT requirements.txt's content hash. A real `claude
    plugin update` always moves the plugin to a new version-scoped
    directory -- that's the same fact behind vault_lib/store.py's ROOT
    relocation: an update orphans whatever was in the OLD version's
    directory precisely because it creates a new one. So a path change IS
    a genuine update event, and requirements.txt's content is replaced
    wholesale as part of that same update -- nothing legitimate is missed
    by keying off the path instead of the hash. What this closes: content-
    hash-based triggering meant an agent with filesystem write access to
    an *installed* plugin's requirements.txt could get it automatically
    pip-installed on the very next server restart, with no real update
    having happened at all -- an auto-triggered, persistent code-execution
    path a red-team audit flagged as sharper than "the agent can edit this
    tool's source" plainly implies. Editing requirements.txt alone, with
    no update, no longer triggers anything.

    Manual/dev install (no CLAUDE_PLUGIN_ROOT): unchanged, still the
    content hash. There's no "version" to key off in a local checkout, and
    immediate reinstall-on-edit is exactly the iterative workflow a
    developer testing a dependency change wants -- this is the
    maintainer's own trusted working copy, not the threat this is about.
    """
    if _IS_INSTALLED_PLUGIN:
        return str(PLUGIN_ROOT)
    return _requirements_hash()


def _ensure_venv() -> Path:
    """Creates (or recreates, if the install marker -- see _install_marker
    -- changed since last time) the venv in the plugin's persistent data
    directory. A no-op stat check on every normal startup once it's
    already provisioned.

    Confirmed in practice (not hypothetical): an MCP client's server-
    startup timeout can kill this process mid-install -- the venv gets
    created (fast) but `pip install` never finishes, and no error surfaces
    anywhere a user would think to look. STAMP_FILE only being written
    AFTER a successful install already meant the next run would retry
    rather than silently trust a half-finished venv. A venv that's
    _venv_is_functional (not just python.exists()) is skipped on retry
    instead of being recreated (faster, and the actual slow part was never
    venv creation) -- but one interrupted even earlier, mid ensurepip, IS
    recreated rather than left permanently stuck failing "No module named
    pip" forever.

    Reuse is gated on more than "is the venv functional," though: it only
    ever applies when this attempt targets the exact same marker as the
    last (incomplete) one, via ATTEMPT_FILE. Without that check, reusing a
    functional-but-stale venv across a genuine target change (a real
    update, or a real requirements.txt edit in dev mode) would run plain
    `pip install -r requirements` against it -- which only adds/upgrades,
    never uninstalls a package the NEW requirements.txt no longer lists --
    silently breaking the "requirements.txt's content is replaced
    wholesale" guarantee _install_marker's own docstring makes. So: same
    target as last attempt -> safe to reuse a functional venv. Different
    target (or no prior attempt at all) -> always a full wipe/recreate,
    exactly like before this retry optimization existed.

    provision.log is reset at the start of each attempt and captures that
    attempt's full output -- success or failure -- so a repeatedly-
    interrupted install is diagnosable without inspecting internal files
    by hand, and doesn't grow unbounded over the plugin's lifetime.
    """
    python = _venv_python()
    current_marker = _install_marker()
    if _is_up_to_date(python, current_marker):
        return python

    with _provision_lock():
        # Re-check after acquiring: another process may have finished
        # provisioning while this one waited for the lock.
        if _is_up_to_date(python, current_marker):
            return python
        _provision(python, current_marker)
    return python


def _is_up_to_date(python: Path, current_marker: str) -> bool:
    return (
        python.exists()
        and STAMP_FILE.exists()
        and STAMP_FILE.read_text().strip() == current_marker
    )


def _provision(python: Path, current_marker: str) -> None:
    """The actual (re)install, called with _provision_lock held."""
    _reset_log()
    last_attempt_marker = ATTEMPT_FILE.read_text().strip() if ATTEMPT_FILE.exists() else None
    same_target_as_last_attempt = last_attempt_marker == current_marker
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        ATTEMPT_FILE.write_text(current_marker)
    except OSError:
        pass
    venv_functional = same_target_as_last_attempt and _venv_is_functional(python)

    # Always log WHY this attempt is happening -- not just for the
    # interrupted-attempt case. The most common real trigger is actually a
    # genuine update (a completed prior install, now targeting something
    # different), and that case has to explain itself too: otherwise, if
    # the update's own pip install then fails, the log shows the pip
    # output with no line saying why a full wipe/recreate was attempted in
    # the first place, which is exactly the "leave a diagnosable trail"
    # goal this whole feature exists for.
    stamped_marker = STAMP_FILE.read_text().strip() if STAMP_FILE.exists() else None
    if stamped_marker is not None:
        _log("A prior install completed successfully, but this attempt targets a "
             "different install (a real update, or an edited requirements.txt) -- "
             "wiping and recreating from scratch so nothing stale from the "
             "previous target can survive.")
    elif python.exists() and same_target_as_last_attempt:
        _log("Found a venv with no completed-install stamp -- a previous "
             "provisioning attempt for this exact target likely didn't finish "
             "(killed by a startup timeout, ran out of disk, etc.). " +
             ("Reinstalling dependencies." if venv_functional else
              "The interpreter itself looks incomplete too (no working pip) "
              "-- recreating the venv from scratch."))
    elif python.exists():
        _log("Found an existing venv, but this attempt targets a different "
             "install than whatever last touched it -- wiping and recreating "
             "from scratch rather than reusing it.")
    else:
        _log("No existing venv found -- first-time setup.")

    print(f"[llm-env-vault] Setting up its Python environment in {VENV_DIR} "
          f"(first run, or dependencies changed since last run) -- this "
          f"can take a little while the first time. Progress: {INSTALL_LOG}",
          file=sys.stderr, flush=True)

    uv = _find_uv()

    if not venv_functional:
        if sys.platform == "win32" and VENV_DIR.exists():
            # On Windows, `python -m venv --clear` removes old site-packages
            # files one by one. If the previous server process still holds any
            # of those files open (a normal race when a plugin update triggers
            # a rebuild mid-session), each DeleteFile call fails with
            # WinError 32 and the venv is left half-destroyed.
            #
            # Fix: build into a sibling directory, then swap with a directory
            # rename. Renaming a directory moves only its filesystem entry --
            # it never touches individual files -- so it succeeds even with
            # open handles. Best-effort removal of the old tree follows; if
            # the old server is still running, that rmtree may partially fail,
            # which is harmless: the orphaned venv-old is cleaned up at the
            # start of the next update via the same _rmtree_best_effort calls
            # below.
            venv_next = DATA_DIR / "venv-next"
            venv_old = DATA_DIR / "venv-old"
            _rmtree_best_effort(venv_next)
            _rmtree_best_effort(venv_old)
            venv_cmd = ([uv, "venv", "--seed", "--python", sys.executable, str(venv_next)]
                        if uv else [sys.executable, "-m", "venv", str(venv_next)])
            _run_logged(venv_cmd, "venv creation")
            try:
                VENV_DIR.rename(venv_old)
            except OSError as exc:
                _log(f"Error: could not rename old venv aside: {exc}")
                _rmtree_best_effort(venv_next)
                raise
            venv_next.rename(VENV_DIR)
            _rmtree_best_effort(venv_old)
        else:
            # --clear: `python -m venv` on an already-existing directory does
            # NOT wipe previously-installed packages on its own -- it only
            # ensures the core venv structure (interpreter, pip) is present,
            # leaving old site-packages alone. Without --clear, "recreate
            # from scratch" for a genuine target change would be a no-op for
            # already-installed packages, silently defeating the whole point
            # of not reusing a stale venv across an update (confirmed by
            # actually testing it: a package removed from requirements.txt
            # stayed importable after a simulated update without this flag).
            if uv:
                # uv has no --clear flag; delete the tree first (same effect).
                _rmtree_best_effort(VENV_DIR)
                venv_cmd = [uv, "venv", "--seed", "--python", sys.executable, str(VENV_DIR)]
            else:
                venv_cmd = [sys.executable, "-m", "venv", "--clear", str(VENV_DIR)]
            _run_logged(venv_cmd, "venv creation")

    # uv pip install --python <path> targets the venv without needing
    # activation and is typically 10-50x faster than `python -m pip install`,
    # which matters on first run where the full pip install is what pushes
    # provisioning past MCP startup timeouts and causes silent failures.
    if uv:
        pip_cmd = [uv, "pip", "install", "--python", str(python)]
    else:
        pip_cmd = [str(python), "-m", "pip", "install"]
    if REQUIREMENTS is _LOCKFILE:
        pip_cmd.append("--require-hashes")
    pip_cmd += ["-r", str(REQUIREMENTS)]
    _run_logged(pip_cmd, "dependency install")

    _log("Provisioning succeeded.")
    STAMP_FILE.write_text(current_marker)


def main() -> None:
    python = _ensure_venv()
    server = str(PLUGIN_ROOT / "mcp_server.py")
    if sys.platform == "win32":
        # On Windows, os.execv is not a true exec: CPython implements it via
        # the CRT's _wexecv -> _wspawnv(_P_OVERLAY, ...) which starts a new
        # process then terminates the caller (spawn-and-die). The stdio relay
        # across that hop is unreliable when the grandparent is a Node.js
        # process (the Claude Code CLI) -- mcp_server.py ends up with
        # miswired std handles that block rather than EOF, so the MCP client
        # never receives the initialize response and times out after 30 s.
        #
        # subprocess.call with no stdio args lets the child inherit stdio
        # through Python's own CreateProcess call, which propagates the pipe
        # handles correctly regardless of the grandparent's runtime. The
        # launcher stays alive as a thin wrapper while mcp_server.py runs;
        # the overhead is negligible for a long-lived server. The MCP
        # invariant is maintained: nothing in the launcher writes to stdout
        # (which would corrupt the JSON-RPC stream), and mcp_server.py is the
        # sole reader of stdin.
        sys.exit(subprocess.call([str(python), server]))
    else:
        # On POSIX, execv is a true process replacement: same PID, same stdio
        # file descriptors -- no wrapper overhead at all.
        os.execv(str(python), [str(python), server])


if __name__ == "__main__":
    main()
