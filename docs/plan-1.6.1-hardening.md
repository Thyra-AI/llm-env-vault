# Plan: 1.6.1 hardening — closing the super-thinker's findings on the 1.6.0 swap

> **Superseded by 2.0.0.** This is the hardening plan for `run_with_env(swap=)`, which is
> retired. Kept because the review findings behind it are the clearest record of why: four
> releases of fixes in eight days, several found only by adversarial review rather than by
> the suite.

Status: WP1–WP6 SHIPPED in 1.6.1; WP8 (single-view) SHIPPED in 1.7.0, Windows-only, with pipe
mode and background+swap deferred per the pre-implementation review. Deviations from
the text below are recorded in CHANGELOG 1.6.1. Source: the hostile second read of `docs/security-posture-1.6.0.md`
(27 findings; 4 disputed and verified wrong against the code, 23 accepted). This plan turns the
23 into seven work packages, ordered by what each one takes away from an agent versus what it
merely tidies. Every item names the function it touches, the test that proves it, and what
could go wrong with the fix itself.

The organising rule, stated once: **the server must never act on agent-chosen input without a
human gate, and a real value must never sit on disk without something that will notice.** Every
item below is a place where 1.6.0 violates one of those two sentences.

---

## Decisions this plan needs from the owner

| # | Question | Recommendation | Why |
|---|---|---|---|
| D1 | Default time limit for a `swap` run? | **60 minutes**, shown in the dialog, overridable per call via a new `timeout` argument (which is part of the trust signature) | A foreground swap with no limit is real values in `.env` for as long as `npm run dev` lives. Plain runs keep today's behaviour (no limit) so nothing changes for them. |
| D2 | Refuse `swap` when the command itself is `git`? | **Yes** | `git add -A` / `git commit` / `git stash` need no secrets and are the one-dialog path to committing real values. A refusal costs nothing. |
| D3 | Cloud-synced folder (OneDrive etc.) — warn or refuse? | **Warn in amber**, not refuse | Many projects live under `Documents\`, which OneDrive syncs by default on Windows; refusing would block the feature for them. The warning is the honest thing: the sync client can upload the swapped file inside the run. |
| D4 | Recovery when `vault_index.json` cannot be read: leave the real value on disk, or clear it? | **Retry ~2 s, then clear** the value to a recognisable pending marker `NAME="value ?"` that `resync_targets` turns back into the right placeholder once the index is readable | Leaking is the worse error for a secrets tool. Today's code clears with an opaque comment and no way back; the marker makes it self-healing. |
| D5 | Keep the git probe *before* the dialog (hardened) or move it after Allow? | **Keep it before, hardened** | The warning is only useful *in* the dialog. Hardening (fixed executable path, config neutralised) removes the code-execution path; moving the probe would remove the warning. |
| D6 | Windows Job object so the command dies with the server? | **Yes** | It is what makes "the server died" not also mean "an orphan is still reading the file the recovery is about to rewrite". ~40 lines of ctypes; POSIX gets a process group. Also the attribution primitive WP8 needs. |
| D7 | Single-view real values (WP8): ship in 1.6.1 or as 1.7.0 after it? | **1.7.0**, unless the owner wants WP3.2 + WP8 pulled forward together | WP1–WP6 are small and close known holes; WP8 is a new mechanism with its own review cycle. Shipping the small fixes first means the marketplace gets the safe version within a day. |
| D8 | With `max_reads`, allow `background=True` + `swap`? | **Yes, only when `max_reads` is set** | The 1.6.0 refusal was because a detached process has no restore moment; the first read *is* that moment, with the timeout as backstop. |

---

## WP1 — Remove the two capabilities 1.6.0 handed the agent (ship first)

### 1.1 Git probe: fixed executable, neutralised config

**Finding.** `_git_tracks` / `_git_ignores` run a bare `git` with `cwd` = the file's directory,
before any dialog. `.git/config` (`core.fsmonitor = <program>`) or a `.git` *file* with
`gitdir:` gives an agent with file-write code execution inside the vault server, on a schedule it
chooses. On Windows, `CreateProcess` searches the server's current directory — the open project
— before `PATH`, so a planted `git.exe` runs as "git".

**Change** (`mcp_server.py`, the two helpers → one `_git(args, cwd)` helper):
- Resolve the git executable **once at import** by walking `PATH` entries ourselves: skip empty
  entries and anything equal to the current directory; on Windows try each `PATHEXT` suffix;
  keep the first regular file. Never `shutil.which` (it prepends cwd on Windows in some Python
  versions). If nothing is found, the probe answers `None` — the dialog then says "git status
  unknown" rather than running anything.
- Invoke by absolute path with a scrubbed environment: inherit `PATH`, `SYSTEMROOT`, `HOME`,
  `USERPROFILE`, `TEMP`; add `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<os.devnull>`,
  `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`, and `GIT_CONFIG_COUNT=2` with
  `core.fsmonitor=false` and `core.hooksPath=<empty directory created at import>`. Those two
  keys are the only repo-config values `ls-files`/`check-ignore` can be made to execute.
- `timeout=10` stays. `encrypt_file` / `decrypt_file` get the hardened helper for free.

**Tests** (`tests/test_git_probe.py`): a temp repo whose `.git/config` sets `core.fsmonitor` to
a script that writes a sentinel file — the sentinel must not appear; on Windows, a fake `git.exe`
in cwd is not what runs (assert the resolved path is under `PATH`, not cwd); no git on `PATH` →
`None` and the dialog still builds.

**Risk of the fix.** A user with git only reachable through the current directory (nobody) loses
the warning. `GIT_CONFIG_GLOBAL=nul` also disables their global `.gitignore`
(`core.excludesFile`) for the `check-ignore` answer, so "not ignored" may be reported for a file
their global ignore covers — acceptable, and the dialog wording says "by this repo's rules".

### 1.2 Journal and `swap=` paths: validated before anything touches them

**Finding.** `recover_stale_swaps` rewrites non-placeholder lines for any path/names in the
agent-writable `swap.journal.json`, unconditionally, with no registry check and no guard; a UNC
path (`\\attacker\share\.env`) in the journal or in `swap=` makes the server open SMB with the
user's NTLM credentials at `Path.exists()` / `Path.resolve()` time — before the registry check.

**Change** (`store.py`, new `validate_target_key(key, names, targets)`):
- A path is acceptable only if: a `str`, absolute, **not** UNC (`\\`/`//` prefix, `\\?\`,
  `\\.\`), no control characters, and equal (normcase) to a key of `targets.json`; `names` must
  be a subset of that target's registered names.
- `_load_journal` applies it per entry: a failing entry is **dropped from the working set and
  reported** as `swap_journal_rejected: [{path, reason}]` — never acted on, never silently kept.
- `journal_add` applies it (belt and braces).
- `_resolve_swap_plan` applies the *string* checks to the raw argument **before** `Path.resolve()`
  (so no network I/O on an attacker-chosen string), then the registry check on the resolved
  path, then rejects if the resolved path is UNC (a junction can point at one).
- `recover_swap_file` and `preview_swap` are only ever called with validated keys.

**Tests:** journal entries with a UNC path, a relative path, an unregistered path, names outside
the registry → each rejected and reported, file untouched, and — for UNC — `Path.exists` is
monkeypatched to raise if called, proving no probe happened. `swap=["\\\\srv\\share\\.env"]` is
refused before `resolve`.

**Risk of the fix.** A project on a mapped network drive (`Z:\proj\.env`) is a drive letter, not
UNC, and stays allowed; a project addressed *by* UNC path could never be swapped. Say so in the
error text.

---

## WP2 — Make "restored" mean restored

### 2.1 Verify and tier 2 look for the *value*, not the rendering

**Finding.** A formatter or linter that re-quotes `SECRET="abc"` to `SECRET=abc` during the run
defeats tier 1 (bytes differ) and tier 2 (stripped value ≠ rendered form), so the line is
released as a "conflict" and verify — which also compares against the rendered form — stays
silent. Real secret on disk, journal entry gone, no warning.

**Change** (`store.unswap_target_file`):
- Tier 2 becomes: a line for the name whose `_unquote(value) == secret` **or** whose stripped
  value equals the rendered form → it is still ours → canonical placeholder. Only a line whose
  unquoted value differs from the secret is a conflict (that is the user's edit).
- Verify becomes: any line for a swapped name whose raw text contains the secret bytes, or whose
  `_unquote` equals the secret → `verify_failed`. Values under 8 characters are still checked by
  equality (substring search on `2525` would false-positive on `PORT=25250`).

**Tests:** re-quoted-during-run (three styles) → restored, not conflict; a genuinely edited value
→ still a conflict; a re-quoted secret written back after restore → `verify_failed`.

### 2.2 Restore write: atomic first, in-place last

**Finding.** On Windows `os.replace` fails while any process holds `.env` open without
`FILE_SHARE_DELETE` (CPython's `open()` does not grant it). An orphaned dev server spawned by the
command makes the restore fail ten times, flags `restore_failed`, and every later recovery fails
the same way — real values stay until the orphan exits.

**Change** (`store._write_with_retries`): after the atomic attempts are exhausted, open the file
`r+b`, truncate, write, fsync. Non-atomic, but for a *restore* success is the property that
matters; a torn placeholder line is far better than a whole real one. Used by unswap and
recover only — never by the swap write, which must stay atomic (a torn real value is the worst
of both).

**Test:** hold the file open from a child process during restore; assert the placeholders land.

### 2.3 Recovery with an unreadable index (D4)

**Change** (`store.recover_stale_swaps`): retry `load_index()` up to 20× over ~2 s. If it still
fails, rewrite each journaled non-placeholder line to `NAME="value ?"` and report
`swap_recovery_pending_index: [names]`. Extend `PLACEHOLDER_VALUE_RE` to accept `value ?` so
`resync_targets` (and the next recovery) renumbers it from the index once readable. The same
marker replaces today's "value cleared" comment for names that left the index — a line, not a
comment, so nothing has to be un-commented by hand.

**Tests:** index locked for 500 ms → recovery succeeds after retry; index corrupt → marker
written, then a resync with a repaired index restores the numbered placeholder.

### 2.4 Trailing backslash rendering

**Change** (`store.render_swap_value`): a `"`-style value ending in an odd run of `\` would
render as `"abc\"` — unterminated for every parser. Fall back to single quotes when the value
has no `'`; otherwise double the backslashes and note it. **Test:** table entries for `abc\`,
`abc\\`, `a'b\`.

### 2.5 Temp-file sweep by name

**Change** (`store.recover_swap_file`): drop the `mtime ≥ started-1` condition. There is no
legitimate `..env.<random>.tmp` to preserve, and FAT/exFAT's 2-second mtime granularity made the
window unreliable. **Test:** an old-dated temp file is swept.

### 2.6 Own-pid leftovers after a failed `journal_remove`

**Change** (`store.recover_stale_swaps`): for an `active` entry owned by *this* process whose
file already holds placeholders for every journaled name, remove the entry — it is the residue
of a bookkeeping failure under lock contention, and leaving it blocks the other server's
resync/migrate for this process's lifetime. **Test:** simulate the failed removal, call
recovery, entry gone, file untouched.

---

## WP3 — Bound the window in time and bind the child to the server

### 3.1 `timeout` argument (D1)

**Change** (`run_with_env`): new `timeout: Optional[int] = None` (seconds). Plain runs: `None`
keeps today's behaviour. Swap runs: default **3600**; the dialog states "the command is killed
and placeholders restored after N minutes". `subprocess.run(timeout=)` already kills the child
on expiry; the result gains `timed_out: true`. `timeout` joins the trust signature (a grant for
60 minutes must not cover a call asking for 6 hours). `background=True` ignores it (already
refused with swap).

**Tests:** a `sleep 30` child with `timeout=1` under swap → killed, restored, `timed_out`;
signature differs by timeout.

### 3.2 Job object / process group (D6)

**Change** (`mcp_server.py`, new `vault_lib/procs.run_bound(...)`): on Windows, create a Job
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, start the child with `Popen`, assign it, then wait —
when the server process dies the kernel closes the job handle and kills the whole tree. On
POSIX, `start_new_session=True` and `killpg` on our own SIGTERM. This is what makes recovery's
"the owner is dead, rewrite the file" safe: a dead owner now implies a dead command.

**Test:** spawn a child that spawns a grandchild; kill the parent; assert the grandchild is gone
(Windows only in CI; POSIX branch covered by the process-group unit).

### 3.3 The real-kill test

**Change** (`tests/test_swap.py`): a child interpreter performs a genuine swap + journal against
an isolated vault dir passed by env var, then sleeps; the test `TerminateProcess`es it and calls
`recover_stale_swaps()` from the test process — the path every Windows session actually exits
through. A second test keeps the child alive and asserts recovery does *not* touch the file.

---

## WP4 — Visibility that does not depend on the journal

### 4.1 `vault_status` reports managed lines that are not placeholders

**Change** (`_vault_status_core`): for every registered target, scan its managed names and
report `targets_holding_non_placeholders: {path: [names]}` (names only, never values). This is
the journal-independent detector: a crash whose journal was later deleted by a concurrent
session, or a real value left by any means, becomes visible on the next status call. It reuses
`preview_swap`; cost is one small-file read per target.

### 4.2 `--recover --force`

**Change** (`__main__`, `recover_stale_swaps(force=False)`): `--force` treats every entry as
stale. It is the human's escape from the "owner pid exists but cannot be inspected" deadlock,
where `journal_add` refuses, resync skips, migrate refuses and plain `--recover` waits forever.
Worst case is clobbering a genuinely live run — never a leak — and a human at a terminal is the
right authority for that.

### 4.3 Forged live entries (DoS) — document only

An agent that reads the live `server_id` during a run can forge `active` entries for every
registered path and deny swap/resync/migrate for the server's lifetime. `--force` is the exit;
the posture doc gets a line under "what the journal cannot see".

---

## WP5 — Refusals and disclosures before the dialog

### 5.1 Refuse `swap` when the command is `git` (D2)

**Change** (`_resolve_swap_plan`): if `os.path.basename(command[0]).lower()` in
`{"git", "git.exe"}` → refuse: "a git command needs no secrets; running it with real values in
.env is how they get committed". **Test:** refused before the dialog.

### 5.2 Cloud-sync detection (D3)

**Change** (`mcp_server.py`, `_cloud_synced(path) -> Optional[str]`): Windows — walk the path
and its ancestors and check `st_file_attributes` for `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`
(0x400000), `FILE_ATTRIBUTE_RECALL_ON_OPEN` (0x40000) or a reparse point with a cloud tag; also
match the `%OneDrive%`, `%OneDriveConsumer%`, `%OneDriveCommercial%` roots. All platforms —
match `~/Dropbox`, `~/Google Drive`, `~/iCloud Drive`, `~/Library/Mobile Documents`. The dialog
gets an amber line naming the provider. **Test:** attribute set on a temp file → detected;
env-root match → detected.

### 5.3 Untracked-and-unignored line

**Change** (`gui.unlock_for_run_dialog`): the plan already computes `git_ignored`; show a muted
line when the file is neither tracked nor ignored ("`git add -A` would stage it").

### 5.4 Duration line

**Change** (dialog): "Real values stay in the file until the command exits or N minutes pass,
whichever is first" — the timeout from 3.1, so the human sees the actual bound.

---

## WP6 — Posture document corrections

- §2: replace the `--recover` sentence with what recovery actually does (rewrites non-placeholder
  lines for journaled names, now confined to registered files).
- §4: "no ordering without an entry" → restate as "no ordering in which the vault's own bytes
  are on disk without an entry; a third party rewriting the line is caught by the value-based
  verify (2.1)". "never a clobber" → "never a clobber of a process this machine can identify;
  cross-namespace (WSL/host) and orphaned-command cases are covered by 3.2".
- §5: promote "verify blind to re-quoting" (now fixed) and "cloud sync" (now detected); move
  macOS liveness to §6 as a missing branch; add the DoS note; add "recovery is triggered, not
  timed" with 4.1 as the answer.
- §3: add the plain sentence "trusting a run is trusting the agent with those values for the
  grant's lifetime; redaction covers captured output only".
- §8: delete the "two reviewers caught what one did not" sentence; replace the test count with
  what the swap tests assert.
- Top of the doc: the threat-model ceiling (an agent can read a swapped or materialized file
  during the run; no software on the same account prevents it) as the framing sentence.

---

## WP8 — Single-view real values: restore after the first read, not after the command exits

**Owner's request.** The file holding real values (a `swap` target or a `materialize` file)
should be readable exactly once — by the consumer the run was started for — and revert the
moment that read completes, so the exposure is contained to that one read rather than to the
command's lifetime. This is Doppler's `--mount --mount-max-reads 1`, done with what a user-mode
Python process has on each platform.

**Feasibility, verified by two spikes on this machine (Windows 11, no driver, stdlib ctypes):**

1. *Detecting "another process opened this file" and "it closed it".* Open our own handle
   with **share mode 0** and request a **Read + Handle oplock** (`FSCTL_REQUEST_OPLOCK`). Any
   other process's open would normally fail with a sharing violation; with the H oplock held,
   the filesystem instead **breaks our oplock** (our pending `DeviceIoControl` completes) and
   holds their open until we close. So: break = "someone is opening it"; we close; their open
   proceeds and they read the real content. Then we poll an exclusive re-open: it fails with
   `ERROR_SHARING_VIOLATION` while their handle is open and succeeds the instant they close =
   "the read is over". Measured: reader opened at t=1.03 s, held 0.50 s, got the real value; with
   no reader the watch times out cleanly; `os.stat` (attribute-only opens) does *not* trigger it.
2. *Attributing the open to the command.* The Restart Manager (`RmGetList`) returns the PIDs
   holding the file — 289 ms per call, once per open. The spike also showed why attribution must
   be by *process tree*: a venv `python.exe` is a launcher, and the holder was its child. The
   Job object from WP3.2 answers "is this PID in the command's tree" with one
   `IsProcessInJob` call. An open by anything **outside** the job — Defender, the indexer, an
   editor, an agent's `Read` — is not counted as the read, the watch is re-armed, and the
   foreign opener's app name is reported in the result (`single_read_foreign_opens`), which is
   new and useful evidence in its own right.

**Design.**
- New `run_with_env` argument `max_reads: Optional[int] = None`. `None` = today's behaviour.
  `1` (or N) = the real values are restored/deleted as soon as the command's process tree has
  opened-and-closed the file N times, or when the command exits, whichever comes first. Applies
  to every `swap` target and to the `materialize` file. Part of the trust signature; shown in the
  dialog ("restored after the first read by the command; foreign opens are reported").
- Why `max_reads` and not a boolean: Compose opens `.env` **twice** (once for interpolation, once
  for `env_file:`); Vite/Next open each env file once but several files; a test harness may
  spawn several children that each load `.env`. `max_reads=1` is right for `docker run
  --env-file`, kubectl, `source .env`, python-dotenv, pydantic-settings, Node `--env-file`; the
  research doc gets a column saying which consumers need 2. The first-open-wins rule is the
  honest limit: after N counted reads the file reverts, and a consumer that reads once more sees
  placeholders — the result says so (`single_read_restored_early: true` plus the count).
- **Windows:** the oplock watcher runs on a thread per file; on each break it queries Restart
  Manager, filters holders by `IsProcessInJob`, waits for the exclusive re-open, decrements the
  count, and at zero performs the normal restore (WP2.2 write path) — while nobody holds the
  file, so the atomic replace cannot fail on a share violation. If the oplock cannot be granted
  (some network filesystems refuse), the run proceeds without single-read and the result says so
  before the dialog would have claimed it — i.e. the capability is checked pre-dialog and the
  dialog only promises it when it will hold.
- **Linux:** `inotify` (`IN_OPEN` / `IN_CLOSE_NOWRITE` via ctypes) for the open/close events;
  attribution by scanning `/proc/<pid>/fd` for the PIDs in the command's process group. Same
  semantics, no Restart Manager needed.
- **macOS:** no open notifications from user mode without an Endpoint Security entitlement.
  `max_reads` is refused there pre-dialog with a clear message; nothing silently degrades.
- **`materialize` on Windows and Linux gets a stronger option for free:** serve it as a **named
  pipe / FIFO** instead of a file (`materialize_mode="pipe"`): the content is written once into
  `\\.\pipe\llm-env-vault-<random>` (or a FIFO in a private temp dir) and the path is handed to
  the command; a second open finds no server. Never on disk, read-once by construction, no
  watcher. Works for consumers that `open()` the path (`docker run --env-file`, Node
  `--env-file`, python-dotenv); refused pre-dialog for consumers known to `stat` for a regular
  file. `.env` itself cannot be a pipe on Windows, so `swap` keeps the oplock design.

**What it changes elsewhere in this plan.**
- WP3.1's timeout becomes the *fallback* bound; with `max_reads`, the window is "until the
  loader has read", typically milliseconds after start, regardless of how long the command runs.
- It reopens the 1.6.0 decision to refuse `background=True` with `swap`: with `max_reads` the
  detached process's startup read is the natural restore moment, with the timeout as the backstop
  if it never reads. Proposed: allow `background=True` + `swap` **only** with `max_reads` set,
  restored by the watcher thread, journaled exactly like a foreground run.

**Tests.** The two spikes become unit tests (real second process, real oplock/Restart Manager);
`max_reads=1` against a python-dotenv child → restored before the child exits, child got the
real value, file already holds placeholders when the child is still running (assert from inside
the child after its read); a foreign open (a test-spawned process outside the job) is reported
and not counted; Compose-style double read with `max_reads=1` → second read sees placeholders and
the result says `single_read_restored_early`; oplock refused (monkeypatched) → run proceeds,
result states single-read was unavailable.

**Risks of the fix.** The watcher is ~200 lines of ctypes and a thread per file; it must never
hold the file itself while the command wants it (the design closes our handle on break, before
the opener proceeds). Antivirus scan-on-write happens at our write's close, *before* the oplock
is armed, so it cannot be counted; a scan-on-open during the run is attributed as foreign and
reported. A consumer that memory-maps or re-reads lazily is a documented `max_reads>1` case.

**Size.** Medium — larger than any single WP1–5 item, comparable to WP3.2 which it builds on.
Ship it as **1.7.0** after 1.6.1, or fold WP3.2 + WP8 together if the owner wants them sooner.

---

## WP7 — Deferred, with reasons

| Item | Why not now |
|---|---|
| Journal `materialize` and `files=` (recovery deletes) | Needs the inode-match guard (record dev/ino/size/ctime at write, delete only on full match) so a forged entry can never delete a file the vault did not create. Right design, separate release. |
| Background-log journaling | Same mechanism, lower exposure (log is in temp, redacted on exit). After the above. |
| macOS liveness via `proc_pidinfo` | ~15 lines of ctypes; no CI runner to prove it. Do it, but flagged untested. |
| Showing the *resolved* argv0 in the dialog | The command string is what the human approves; a planted `python.exe` in the project resolves first on Windows. Real, pre-existing, unrelated to swap. Note in the posture doc for 1.7. |
| Shape-preserving placeholders | Product decision, deferred in 1.6.0; unchanged. |

---

## Order of work, and why

1. **WP1** — the only two items that give the agent something it did not have. Ship before
   anything else; they are also the smallest.
2. **WP2.1 + 3.3** — the verify blind spot is a silent leak in a *normal* editor setup, and the
   real-kill test is the proof the journal's headline claim rests on.
3. **WP3.1 + 3.2** — time bound and process binding; together they make "one command" mean
   what the doc says.
4. **WP2.2–2.6, WP4, WP5** — each independent, each small, each with its own test.
5. **WP6** — last, because the sentences must describe the code that exists.

Every step runs the full suite (pytest + every standalone runner + the Tk check), then the
push-time review gate, then `claude plugin marketplace update` / `plugin update`. Version 1.6.1;
one CHANGELOG entry under **Security**.

## Acceptance

- No `subprocess` call in the pre-dialog path resolves an executable through the current
  directory or honours repo-controlled git config.
- No file outside `targets.json`'s keys is ever opened, stat'ed or rewritten by recovery or by
  `swap=`, and no UNC path is ever passed to the filesystem.
- A secret re-quoted during the run is restored, and a secret present after restore is reported.
- A swap run cannot outlive its timeout; a dead server cannot leave a live command.
- `vault_status` reports a real value in a managed line even when the journal is gone.
- The posture doc contains no sentence the code does not back.
