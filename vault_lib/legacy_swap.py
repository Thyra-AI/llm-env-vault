"""One-way recovery of `swap=` journals written by llm-env-vault 1.6.0-1.7.x.

`run_with_env(swap=)` is retired in 2.0.0: it wrote real secret values into
the project's own registered .env for the lifetime of a command, which is
the one thing the vault exists to prevent. What cannot be retired with it
is the cleanup. A user can install 2.0 while a .env on their disk still
holds real values, because:

  * a 1.6-1.7 server died mid-swap (crash, TerminateProcess from the MCP
    host, machine reset) and never ran its restore; or
  * a 1.6-1.7 server is STILL RUNNING a long command in another session.

The two need opposite treatment, and getting the second one wrong is how a
"cleanup" corrupts a live run:

  dead owner -> rewrite every managed line unconditionally. Nothing can now
                distinguish a value the vault wrote from one the user typed,
                and leaving a secret on disk is the worse error.
  live owner -> do not touch it. Report it and wait for the pid to go.

Everything here is DEPRECATED and scheduled for removal in 3.0. Nothing in
2.x writes a journal, so this module only ever reads state left by an
older install. Do not build on it, and do not "simplify" the liveness
logic -- `_entry_is_live` distinguishes our own pid from a dead
predecessor that Windows handed the same pid, and that distinction is what
keeps a live run safe. tests/test_legacy_swap_recovery.py pins the whole
contract against golden bytes captured from the real 1.7.1 writers.
"""
import contextlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Optional

from . import procs, store

# Names of the two journal files, kept here rather than in store because
# nothing outside this module writes them any more. Both resolve against
# store.ROOT at call time so the suites' store.ROOT isolation covers them.
SWAP_JOURNAL_NAME = "swap.journal.json"
SWAP_JOURNAL_LOCK_NAME = "swap.journal.lock"


class SwapInProgress(ValueError):
    """Another live server process has real values written into this file."""


def _journal_path() -> Path:
    return store.ROOT / SWAP_JOURNAL_NAME


def _journal_lock_path() -> Path:
    return store.ROOT / SWAP_JOURNAL_LOCK_NAME


@contextlib.contextmanager
def _journal_lock():
    with store._json_lock(_journal_lock_path(), "swap.journal.json"):
        yield


def _load_journal() -> dict:
    """{path: entry} -- the validated entries only. See _load_journal_ex."""
    return _load_journal_ex()[0]


def _load_journal_ex() -> tuple:
    """(entries, rejected). Raises ValueError on a malformed journal --
    unlike the styles file, a journal that cannot be read means real values
    may be on disk with no way to find them, and that has to be said out
    loud. Entries whose path or names fail store.validate_target_key are returned
    in `rejected` as {path, reason} and are never acted on."""
    path = _journal_path()
    if not path.exists():
        return {}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"swap.journal.json is corrupted: {e}") from None
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        raise ValueError("swap.journal.json is malformed: expected {\"entries\": {...}}.")
    entries = {}
    for key, entry in data["entries"].items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            raise ValueError("swap.journal.json is malformed: bad entry.")
        names = entry.get("names")
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise ValueError("swap.journal.json is malformed: bad names.")
        for n in names:
            store.validate_var_name(n)
        if not isinstance(entry.get("pid"), int) or not isinstance(entry.get("server_id"), str):
            raise ValueError("swap.journal.json is malformed: bad pid/server_id.")
        if not isinstance(entry.get("started"), (int, float)):
            raise ValueError("swap.journal.json is malformed: bad started.")
        pid_start = entry.get("pid_start")
        if pid_start is not None and not isinstance(pid_start, (int, float)):
            raise ValueError("swap.journal.json is malformed: bad pid_start.")
        if entry.get("state") not in ("active", "restore_failed"):
            raise ValueError("swap.journal.json is malformed: bad state.")
        entries[key] = entry
    # Path/name validation against the registry, per entry. targets.json
    # being unreadable is fatal here on purpose: without it nothing can be
    # confirmed as a registered file, so nothing is safe to touch.
    targets = store.load_targets()
    valid, rejected = {}, []
    for key, entry in entries.items():
        try:
            registry_key = store.validate_target_key(key, entry["names"], targets)
        except ValueError as e:
            rejected.append({"path": key, "reason": str(e), "entry": entry})
            continue
        valid[registry_key] = entry
    return valid, rejected


def _save_journal(entries: dict, rejected: Optional[list] = None) -> None:
    """Rejected entries are QUARANTINED, not dropped: they stay in the file
    under their original key so every later call reports them again. The
    case that matters is a target that was removed from targets.json while
    it held real values -- forgetting it after one report would be exactly
    the wrong reflex, and a journal the agent can edit must not offer a
    one-shot way to make a record disappear. `python mcp_server.py
    --recover --drop-rejected` is the human's way to clear them."""
    path = _journal_path()
    merged = dict(entries)
    for item in rejected or ():
        if item["path"] not in merged:
            merged[item["path"]] = item["entry"]
    if not merged:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    store._atomic_write_text(path, json.dumps({"version": 1, "entries": merged},
                                        indent=2, sort_keys=True) + "\n")


def _entry_is_live(entry: dict) -> bool:
    """Is the server that wrote this entry still running? Our own pid with
    a foreign server_id is a dead predecessor that was handed our pid."""
    if entry["pid"] == os.getpid():
        return entry["server_id"] == store.SERVER_ID
    return procs.pid_alive(entry["pid"], entry.get("pid_start"))


def _file_is_all_placeholders(path: Path, names) -> bool:
    """True if no line for `names` holds anything but a placeholder.

    Deliberately NOT store.placeholder_state, which this used to call: that is
    forward swap code and it is deleted in 2.0. The quarantine has to stand
    on its own, so this re-derives the one fact it needs from the parsing
    primitives store keeps. Semantics match placeholder_state's `not_placeholder`
    being empty: a name is only a problem if it has a line that is neither a
    numbered placeholder nor the pending marker, and no placeholder line
    elsewhere in the file.
    """
    names = set(names)
    try:
        _bom, _lines, texts = store._scan_env_bytes(path)
    except (OSError, ValueError):
        return False
    placeholder, other = set(), set()
    for text in texts:
        m = store.ENV_LINE_RE.match(text)
        if not m or m.group("name") not in names:
            continue
        value = m.group("value").strip()
        if store.PENDING_VALUE_RE.match(value) or store.PLACEHOLDER_VALUE_RE.match(value):
            placeholder.add(m.group("name"))
        else:
            other.add(m.group("name"))
    return not (other - placeholder)


def journal_remove(path_key: str) -> None:
    with _journal_lock():
        entries, rejected = _load_journal_ex()
        if path_key in entries:
            del entries[path_key]
        _save_journal(entries, rejected)


def journal_mark_restore_failed(path_key: str) -> None:
    """The in-process restore gave up. Flip the entry so every later tool
    call in any server retries the restore regardless of whether this
    process is still alive."""
    with _journal_lock():
        entries, rejected = _load_journal_ex()
        if path_key in entries:
            entries[path_key]["state"] = "restore_failed"
        _save_journal(entries, rejected)


def live_swaps() -> dict:
    """{path: entry} for every file some live server currently has real
    values written into. Cheap when no journal exists."""
    if not _journal_path().exists():
        return {}
    with _journal_lock():
        entries = _load_journal()
    return {k: e for k, e in entries.items()
            if e["state"] == "active" and _entry_is_live(e)}


def recover_swap_file(path: Path, names, index: dict, started: float) -> dict:
    """Crash recovery: the process that swapped `names` into `path` is gone,
    and with it the record of what it wrote. Rewrite every line for those
    names whose value is not already a placeholder -- unconditionally,
    because nothing can now tell a value the vault wrote from one the user
    typed during the run, and leaving a secret on disk is the worse error.
    The report says so. Also removes any temp file _atomic_write_bytes could
    have left beside the target if the crash hit between its write and its
    rename -- that temp file holds the real values too."""
    report = {"path": str(path), "restored": [], "cleared": [], "temp_files_removed": [],
              "error": None, "missing": False}
    names = set(names)
    # Every `.<name>.<random>.tmp` beside the target is ours and holds a
    # full copy of the file as it was being written. There is no legitimate
    # one to preserve, so age is not a criterion -- the earlier mtime check
    # broke on FAT/exFAT's 2-second granularity.
    try:
        pattern = f".{path.name}.*.tmp"
        for tmp in path.parent.glob(pattern):
            try:
                if tmp.is_file():
                    tmp.unlink()
                    report["temp_files_removed"].append(str(tmp))
            except OSError:
                pass
    except OSError:
        pass
    if not path.exists():
        report["missing"] = True
        return report
    try:
        bom, lines, texts = store._scan_env_bytes(path)
    except (OSError, ValueError) as e:
        report["error"] = str(e)
        return report
    out = list(lines)
    changed = False
    for i, text in enumerate(texts):
        m = store.ENV_LINE_RE.match(text)
        if not m or m.group("name") not in names:
            continue
        if store.PLACEHOLDER_VALUE_RE.match(m.group("value").strip()):
            continue
        name = m.group("name")
        prefix = f'{m.group("indent")}{m.group("export") or ""}'
        out[i] = store._placeholder_line(prefix, name, index).encode("utf-8") + store._terminator(lines[i])
        if index and name in index:
            report["restored"].append(name)
        else:
            # `NAME="value ?"`: the secret is gone from the line and the
            # next resync numbers it (or comments it out if the name really
            # left the vault). Either way nothing needs a human's editor.
            report["cleared"].append(name)
        changed = True
    if changed:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            mode = 0o644
        err = store._write_with_retries(path, bom + b"".join(out), mode, allow_in_place=True)
        if err:
            report["error"] = err
            report["restored"], report["cleared"] = [], []
    report["restored"] = sorted(set(report["restored"]))
    report["cleared"] = sorted(set(report["cleared"]))
    return report


def recover_stale_swaps(force: bool = False, drop_rejected: bool = False) -> list:
    """Restore every journaled swap whose owner is gone or whose own restore
    failed. Returns one report per entry handled (empty when there is
    nothing to do -- the common case, answered by a single stat). Live
    entries are left strictly alone: another chat's command is running
    against that file right now.

    Every entry point that could observe a stale swap calls this first --
    run_with_env, vault_status, resync_targets, install_migrate and server
    start -- so the window between a crash and the restore is one tool
    call, whichever tool that is.

    force: treat every entry as stale (`python mcp_server.py --recover
    --force`). The human's exit from an entry whose owner pid exists but
    cannot be inspected: journal_add refuses, resync skips, migrate refuses
    and a plain recover waits forever. Worst case is clobbering a run that
    really is live -- never a leak -- and a person at a terminal is the
    right authority for that call.

    Entries that fail store.validate_target_key are reported as rejected and
    dropped: they were never something this vault could act on, and keeping
    them would only re-report forever. An unreadable vault index is
    retried for ~2 s (a transient lock from another server or an indexer);
    if it stays unreadable the lines are rewritten to the pending marker
    rather than left holding real values -- leaking is the worse error --
    and reported so the user knows a resync will finish the job.
    """
    if not _journal_path().exists():
        return []
    reports = []
    with _journal_lock():
        entries, rejected = _load_journal_ex()
        for item in rejected:
            reports.append({"path": item["path"], "rejected": True, "reason": item["reason"],
                            "names": list(item["entry"].get("names", [])),
                            "restored": [], "cleared": [], "temp_files_removed": [],
                            "error": None, "missing": False,
                            "note": "quarantined: not acted on; check this file by hand, "
                                    "then clear with `python mcp_server.py --recover "
                                    "--drop-rejected`"})
        if drop_rejected:
            rejected = []
        index, index_error = None, None
        for _attempt in range(20):
            try:
                index = store.load_index()
                index_error = None
                break
            except (OSError, UnicodeDecodeError, ValueError) as e:
                index_error = str(e)
                time.sleep(0.1)
        for key in sorted(entries):
            entry = entries[key]
            if entry["state"] == "active" and not force and _entry_is_live(entry):
                if entry["pid"] == os.getpid() and _file_is_all_placeholders(Path(key),
                                                                              entry["names"]):
                    # Our own leftover: the restore succeeded but the
                    # bookkeeping after it did not (lock contention). Drop it
                    # now, or the other server refuses this file until we
                    # exit.
                    del entries[key]
                    reports.append({"path": key, "leftover_entry_removed": True,
                                    "restored": [], "cleared": [], "temp_files_removed": [],
                                    "error": None, "missing": False})
                continue
            report = recover_swap_file(Path(key), entry["names"], index, entry["started"])
            report["names"] = list(entry["names"])
            report["owner_pid"] = entry["pid"]
            report["reason"] = ("forced" if force else
                                "its restore had failed" if entry["state"] == "restore_failed"
                                else "the server that wrote it is no longer running")
            if index_error:
                report["pending_index"] = (
                    f"vault_index.json could not be read ({index_error}); the lines were "
                    f"written as NAME=\"value ?\" -- call resync_targets once it is readable "
                    f"to number them")
            if report["error"]:
                # Keep the entry so the next call tries again; flag it so
                # liveness of the (possibly reused) pid is never consulted.
                entries[key]["state"] = "restore_failed"
            else:
                del entries[key]
            reports.append(report)
        _save_journal(entries, rejected)
    return reports
