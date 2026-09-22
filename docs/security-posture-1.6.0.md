# Security posture after 1.6.0 / 1.6.1 / 1.7.0 — what changed, what is new, what to watch

> **Superseded by 2.0.0.** This documents the posture of 1.6.0-1.7.1, whose central new
> feature -- `run_with_env(swap=)` -- is retired. Its own 1.7.0 addendum states the ceiling
> that decided it: an agent with filesystem read access can read a swapped file while the
> command runs, and no software under the same OS account prevents it. 2.0.0 has one
> standing exception to the invariant (`materialize`, a fresh path, never the project's own
> file) rather than four. Kept as the record of what was built and why it was not enough;
> read docs/security-posture-2.0.0.md for what is true now.

This is a maintainer-facing map of the system as it stands after the in-place swap landed
(1.6.0, `3dabd7e`) and its hardening (1.6.1). It is organised around one question: **where can
a real secret value be, who can reach it there, and what puts it back.** Everything the swap
added is marked **NEW**; everything else is the standing model, restated so the additions can
be judged against it. Paragraphs marked **1.6.1** record what the hostile review of the 1.6.0
version of this document changed.

**1.7.0 — `max_reads`.** The window is now bounded by *reads*, not time: with an oplock held on
an exclusive handle, every open of the file is observed the instant it happens, and after N the
placeholders go back while the command still runs. Attribution uses the Restart Manager and the
run's Job object; an open too fast to be named is counted while the command is running and
labelled `unattributed` — an early revert the command notices is a reported correctness
failure, never a leak. What it does *not* change: a concurrent same-user reader is held, reads,
and is counted; the file is a new set of bytes but the same inode (restored in place, so no
hardlink is severed and no `os.replace` race exists); and the exposure in the paragraph below
is unchanged in kind, only shorter. Windows only; refused pre-dialog elsewhere. §9 is the
1.7.0 addendum: the new surface, the failure modes its reviews found, and what remains.

**The ceiling of the threat model, stated first.** An agent with filesystem read access can
read a swapped or materialized file while the command runs — from a batched tool call, or from
a second session — and no software running under the same OS account prevents it. Trusting a
run for eight hours is trusting the agent with those values for eight hours: the approved
command receives them and can write them anywhere; output redaction covers captured stdio only.
Everything below is about the *accidental* class — commits, sync, crashes, orphans — which a
`.env` path makes far more likely than a fresh materialize path ever did.

---

## 1. The invariant, and its one deliberate exception

**Invariant:** real values live in `vault.enc` (ciphertext) and in the memory of a process a
human explicitly unlocked via a native dialog the agent cannot see or type into. No file an
agent can read holds a real value — placeholders only.

**Standing exceptions, all bounded to one foreground command and always disclosed in the
dialog:**

| Where a real value is on disk | Since | Bound | Cleanup | Recovery if the server dies |
|---|---|---|---|---|
| `materialize` target (a fresh path that must not exist) | 1.0 | one command | `finally`: unlink | none — the file stays; result would have warned only if the tool returned |
| `files=` restored plaintext (a decrypted `.levault`) | 1.5.0 | one command | `finally`: secure_delete, survivors named | none — same |
| background run log (`llm-env-vault-run-*.log`) | 1.0 | until process exit | redacted in place by a watcher thread | none — log stays unredacted if the server dies first |
| **NEW `swap` target — the project's own registered `.env`** | 1.6.0 | one command — or, with **`max_reads` (1.7.0)**, until the command has read the file N times: typically milliseconds | `finally`: two-tier restore, retried, verified from disk; with `max_reads`, restored mid-run through the exclusive handle the server holds | **journal-driven restore by the next tool call in any session, server start, or `--recover`** |

The swap is the same exposure class as `materialize`, at a path far more likely to be
committed, synced or open in an editor. That is why it got the journal and the verification the
older exceptions never had — and why those older exceptions now look comparatively under-served
(see §6).

---

## 2. Entry points, before and after

### Tool surface (what an agent can call)

| Tool | Password? | Writes real values to disk? | Change in 1.6.0 |
|---|---|---|---|
| `vault_status` | no | no | **NEW side effect:** runs stale-swap recovery first (rewrites journaled files to placeholders); reports `swap_recovered` and `swaps_in_progress` |
| `sync_llm_env` | no | no | — |
| `add_secret`, `remove_secret` | yes | no | — |
| `install_migrate` | yes | no | **NEW:** refuses a file another live server has swapped; records `target_styles.json`; runs recovery first |
| `resync_targets` | no | no | **NEW:** skips live-swapped files (`swap_in_progress`); runs recovery first |
| `run_with_env` | yes (or trust) | `materialize`, `files`, **NEW `swap`** | **NEW `swap` parameter;** runs recovery first; rendered forms added to redaction |
| `encrypt_file`, `decrypt_file` | yes | `decrypt_file` yes | — |
| `change_password`, `manage_vault`, `recover_vault` | yes / recovery key | no | — |

### Process entry points

| Entry | Change |
|---|---|
| `python mcp_server.py` (server start) | **NEW:** runs stale-swap recovery before `mcp.run()`; stashes the report for the first tool result; prints a one-line notice to stderr |
| **NEW** `python mcp_server.py --recover [--force] [--drop-rejected]` | runs recovery, prints JSON, exits. No password, no dialog. **1.6.1 correction:** recovery is *not* what `resync_targets` could already do — it rewrites the non-placeholder lines of journaled names unconditionally, which resync never does. What confines it (1.6.1) is `validate_target_key`: only a registered, local, drive-letter path with names inside that file's registered set is ever opened; anything else is quarantined and reported. `--force`/`--drop-rejected` require an interactive terminal. |

### Agent-readable / agent-writable plaintext state in the vault directory

| File | Purpose | Agent-writable consequence | Validated on read? |
|---|---|---|---|
| `vault_index.json` | name → placeholder number | can renumber placeholders; caught by resync's conflict rule | yes (names, ints) |
| `targets.json` | which files, which names | can add names/paths → a resync could rewrite more lines; **1.6.0: could have widened a trusted swap — closed, see §3** | yes |
| `files.json` | encrypted-file inventory | can hide a file from key retirement → refused when registry empty / inconsistent | yes |
| **NEW `target_styles.json`** | original quoting per line | can only change the quoting of a line the agent could rewrite wholesale; cannot move a value out of its line | yes, entries dropped silently |
| **NEW `swap.journal.json`** | which files a live server has real values in | see §4. **1.6.1:** every entry's path and names are validated against `targets.json` before any stat; failing entries are quarantined in the file and reported on every call | yes, malformed → error reported, not swallowed |

**1.6.1: the registry is the trust anchor, and the registry is agent-writable.** `targets.json`
is what confines recovery and `swap=`; an agent that edits it can register any local file. The
check that remains is the dialog, which shows the resolved path and the variable names every
time — the human, not the registry, is the last gate. Signing the registry with the vault key is
a possible future step; it is not in 1.6.1.

**Nothing new is agent-*readable* that contains a secret.** The journal holds names, pids and
timestamps; the styles file holds quote characters. The first draft carried a salted digest of
each swapped line in the journal — dropped before implementation, because `sha256(salt ||
'PASSWORD="hunter2"\n')` with the salt beside it is an offline dictionary attack on the very
thing the vault protects.

---

## 3. Trust — what a grant now binds

| Signature element | Since | Why it is there |
|---|---|---|
| argv, cwd, `only_vars` (None ≠ ()), `materialize`, `background` | 1.2 | different authorisations |
| `files` (normalised paths) | 1.5.0 | so a files=None grant can never match a files=[...] call |
| **NEW `swap`: per file, the path AND the exact set of names that would be swapped** | 1.6.0 | `targets.json` is agent-writable. Keyed on paths alone, an 8-hour grant for "swap two values into `.env`" would auto-allow "swap twenty" after the agent appended eighteen names to the registry. The swappable set is recomputed each call from registry ∩ index ∩ `only_vars` ∩ *lines currently holding a placeholder*, so adding a name, or adding a placeholder line for an absent name, is a new signature. |

Drift monitoring: the swap target itself is now hashed alongside the command's own files, so
**any** edit to a swapped `.env` — a comment, a new variable — revokes the grant. Restore is
byte-exact precisely so that a normal swap cycle does *not* self-revoke; the suite asserts the
hash before and after a round trip is identical.

Swap runs **can** be trusted (materialize class, not files class). Argument for keeping it that
way: the exposure is a value in a file for one command, not a private key written unattended.
Argument to revisit: the file is the project's own `.env` and the human is not present for
auto-allowed runs; if the editor-write-back scenario in §5 ever shows up in practice, making
swap untrustable is a one-line change in `_run_with_env_core` (mirror the `file_pairs` branch).

---

## 4. The journal — failure modes it closes and the ones it cannot

**Ordering:** journal entry written (atomic, fsynced) → real bytes written → command → restore →
entry removed. A crash between the first two steps leaves an entry whose recovery finds only
placeholders and does nothing: the harmless direction. A crash between the last two leaves an
entry for a file that is already restored: same. There is no ordering in which *the vault's own
bytes* are on disk without an entry. A third party rewriting the line during the run (a
formatter re-quoting it) is the case the 1.6.0 verify missed; **1.6.1** compares values rather
than renderings and scans every line for the raw value, so that case is restored or reported.

**Leftover temp file.** `_atomic_write_bytes` writes `..env.<random>.tmp` beside the target and
renames it. A hard kill between write and rename leaves the temp file with real values and no
rename ever happens. Recovery now sweeps `..env.*.tmp` newer than the entry's start time. Only
the swap path sweeps; `materialize` and `write_restored_file` have the same window and no sweep
(§6).

**Liveness.** An entry is live if the pid exists AND (when both sides know it) the process
creation time matches, AND — for our own pid — the per-process `SERVER_ID` matches. This closes:
a recycled pid masquerading as the owner (Windows reuses pids within minutes); a restarted server
handed its dead predecessor's pid; and, in the conservative direction, a process we cannot
inspect (`ERROR_ACCESS_DENIED`) is treated as alive, never dead. Platforms without a creation-time
source degrade to "pid exists" — a delayed recovery. **1.6.1 correction to "never a clobber":**
across pid namespaces (a server in WSL2 and a recovery on the Windows host over the same files)
the pid is meaningless and a live run *can* be rewritten; and before 1.6.1 a `taskkill /F` of the
server left the command running while recovery rewrote its file. The Job object (1.6.1) makes a
dead server imply a dead command on Windows; the WSL/host case remains and is documented.

**Two servers.** `journal_add` refuses while another live server has an active entry for the
same file; `resync_targets` and `install_migrate` skip/refuse such files. Without this, a second
chat's resync would report every real-value line as a conflict (names only — verified the payload
never carries values) and a migrate would re-capture the real values as new secrets.

**Restore failed.** The restore write is retried ten times with backoff, then (**1.6.1**)
rewritten in place — `os.replace` fails on Windows while any process holds the file open, and an
orphan holding `.env` used to defeat every retry. On final failure the entry is flagged
`restore_failed`, the result says the file still holds REAL values, and every later tool call
retries regardless of whether the owner is alive. **The same flag is set when
the post-restore verification finds a swapped value still in the file** (the push-time review
caught that this case originally released the entry — a confirmed secret with no retry). A
conflict alone does *not* keep the entry: recovery rewrites journaled lines unconditionally
and would destroy the edit the restore deliberately preserved; the result names the variable.

**Unreadable journal fails closed.** `install_migrate` and `resync_targets` refuse to touch any
target while `swap.journal.json` cannot be parsed (the review's second finding: the first cut
returned "nothing swapped" on a parse error, which is the state in which a file is most likely
to be mid-swap with nobody watching). `vault_status` reports `swap_journal_error`; every tool
result carries the parse error via `swap_recovered` until the file is fixed or deleted.

**What the journal cannot see:** anything that copies the file while it is swapped — see §5.

---

## 5. Exposure windows that no code path closes (disclosed, not solved)

These are stated in the dialog's muted text, the README security notes and known limitations,
and the agent instructions. They are the residual risk of the feature.

1. **The agent can read the swapped file during the run.** Same as a materialize target. The
   agent instructions forbid it; that is policy, not a boundary. A batched `run_with_env` +
   `Read(.env)` in one agent turn would work. Mitigation is disclosure plus `only_vars` — and,
   in 1.6.1, a time bound (default 60 minutes for swap runs).
2. **Git during the run.** `git add -A`, `commit`, `stash` — by the user or by the command
   itself — capture real values into history. **1.6.1:** a bare git command is refused as the
   swap's command; the dialog warns in amber for a tracked file and for an untracked-unignored
   one; a file that became tracked during the run is reported afterwards. A wrapped git call
   (`npm run release`) is still possible and is the disclosure line's job.
3. **Editor write-back after restore.** An editor that auto-reloaded the swapped content and
   saves its buffer *after* the restore writes secrets back with no journal entry. Post-restore
   verification catches only write-backs that land before the tool returns; **1.6.1:**
   `vault_status` now scans every registered file for managed lines holding non-placeholders,
   so the next status call sees it even with no journal.
4. **IDE local history / VS Code timeline / cloud sync.** External changes are snapshotted into
   the IDE's own storage; a sync client can upload the swapped file inside the command's
   lifetime. Nothing on this machine can recall either. **1.6.1:** a cloud-synced folder is
   detected (Cloud Filter sync roots, provider roots, recall attributes) and named in the dialog.
5. **Hot reloaders.** A dev server watching `.env` reloads on swap and again on restore, the
   second time with placeholders. Swap is foreground-only for this reason.
6. **Recovery is triggered, not timed.** After a crash the real bytes stay until the next tool
   call in some session, or server start, or `--recover`. A week of not using the tool is a
   week. There is no daemon; the journal-independent scan in `vault_status` (1.6.1) is the
   detector, not a timer.
7. **Forged live journal entries (DoS).** A concurrent session that reads the live `server_id`
   during a run can plant `active` entries for every registered path: never recovered,
   `journal_add` refuses, resync skips, migrate refuses, for the server's lifetime. Denial only;
   `--recover --force` from a terminal is the exit.
8. **WSL2 / host over the same files.** Liveness cannot cross pid namespaces; a recovery on one
   side can rewrite a live run on the other. Documented, not solved.

---

## 6. Gaps the new work makes more visible

Not regressions — pre-existing behaviour that now looks inconsistent next to the swap path.

| Gap | Where | Suggested fix | Size |
|---|---|---|---|
| **`materialize` and `files=` have no crash recovery.** A server killed mid-run leaves a real-values file with no record. **1.6.1:** they are now bound to the server's lifetime on Windows (Job object) and killed on timeout, so at least nothing keeps *using* the file; the file itself still stays. | `_run_with_env_core` | Journal them with the same mechanism, but with an inode-match guard (record dev/ino/size/ctime at write; delete only on a full match, overwrite-then-unlink), so a forged entry can never delete a file the vault did not create. | small — the primitives exist now |
| **`materialize` / `write_restored_file` temp-file window.** Same `..name.tmp` leftover on hard kill, no sweep. | `store.write_materialized_env`, `write_restored_file` | Include in the journal recovery above. | small |
| **Background log unredacted if the server dies first.** | background path | Journal the log path; recovery redacts it (needs no password: values are gone, so it can only delete). | medium |
| **`--recover` accepts no confirmation.** **1.6.1:** it is confined to registered local files by `validate_target_key`; `--force` and `--drop-rejected` require an interactive terminal. A confirmation prompt would be useless (headless at server start) — scope, not consent, is the control. | `__main__` | done | — |
| **Agent-batched read during a run.** | policy | Cannot be closed in software without a filesystem filter; the README says so. | out of scope |
| **Recovery hooks add a `stat()` to every tool call.** | `_with_swap_recovery` | Free on the common path (no journal → single stat, no lock). | none |

---

## 7. What the tests now prove (and what they do not)

Proven by `tests/test_swap.py` (33) and `tests/test_consumption_matrix.py` (14), all against a
real isolated vault with real child processes:

- byte-exact swap/restore across BOM, CRLF, missing final newline, indent, `export`, duplicate
  names; no whole-file normalisation
- the two-tier restore: exact bytes → same value under a re-indented line → conflict, never a
  clobber; post-restore verification catching a write-back
- journal before bytes; refusal on a live entry; own pid + foreign server id is stale; pid with
  wrong start time is stale; dead owner and `restore_failed` both recovered; corrupted journal
  reported not swallowed; temp-file sweep
- every pre-dialog refusal (background, unregistered, unknown var, only_vars contradiction,
  nothing swappable, another live server)
- trust: identical call auto-allows after a round trip (hash unchanged), wider `only_vars` is a
  new signature, appended registry names change the signature, any edit to the file revokes
- a scrubbed-environment child reads the real value from disk; the rendered (quoted) form is
  redacted from output
- each of the six consumption mechanisms with the real `python-dotenv`, `pydantic-settings`,
  Node `--env-file` and bash

Not proven: a real Tk dialog interaction beyond construction (the harness snapshots widgets in a
fresh interpreter — it confirms the swap section builds and its labels say what they must);
macOS/Linux liveness (no CI runner); behaviour under a *real* `taskkill /F` (the finally-block
claims rest on Python getting to run it — the journal is the answer for when it does not, and
that path *is* tested by simulating a dead owner).

---

## 8. Reviews this went through

- Design: super-thinker adversarial pass on plan v1 — 18 findings, of which the material ones
  (trust escalation via `targets.json`, salted-digest leak, 24h age rule clobbering live runs,
  pid reuse, BOM/`splitlines` byte-inexactness, temp-file leftover, duplicate-line handling,
  brittle exact-match restore) are all reflected above.
- Implementation: bug-hunter pass over the five touched source files — 0 findings. That pass
  missed the three defects the push gate then found, so its "0 findings" is not evidence.
- Push gate (review-gate, independent model): 1 high (verify_failed dropped the journal entry),
  2 medium (fail-open on a corrupted journal; bookkeeping failure reported as a leak), 1 low
  (formatting) — all fixed in the follow-up commit with a regression test each.
- **1.6.1:** super-thinker hostile read of this document (27 findings, 4 disputed and verified
  wrong against the code) and a second pass on the 1.6.1 mechanics before implementation (46
  items; the material ones — `-c` flags for old git, DLL search from cwd, `gitdir:` redirects,
  quarantining rather than dropping rejected entries, name-agnostic verify, the pipe-holder
  deadlock in the Job runner, `os.replace` vs open handles, UTF-8 output decoding, binding only
  runs that put values on disk — are all in the shipped code). `tests/test_hardening_161.py` has
  one test per accepted finding, including a real `TerminateProcess` of a swapping server.
- Suite: 595 tests, pytest and every standalone runner, plus the Tk check in a fresh interpreter.
- **1.7.0:** see §9.8.

---

## 9. 1.7.0 addendum — single-view (`max_reads`)

Shipped in `ed7de9c`, hardened in `6029601` and `73f83eb` (the push-time reviews of each).
Plan and mechanics: `docs/plan-1.6.1-hardening.md` WP8, D7/D8. This section is written to the
same question as the rest of the document: where can a real value be, who reaches it, what puts
it back — and now also *when*.

### 9.1 What changed about "when"

Before 1.7.0 a real value was on disk for the command's lifetime (bounded by `timeout`). With
`max_reads=N` it is on disk from the moment the run starts until the command's process tree has
**opened the file N times** — for every dotenv-style loader, once, at startup, so the window is
the loader's read plus ~10 ms. The mechanism is not polling: the server holds the file on one
exclusive handle (share mode 0) with a Read-Write-Handle oplock, so the kernel reports every
open the instant it happens and *holds the opener* until the server has re-armed. The real
values are written in and the placeholders written back **through that handle**, so "armed" and
"on disk" are the same instant and the restore is in place — same inode, no `os.replace`, no
temp file, no hardlink severed.

Nothing about the ceiling of the threat model moves: an approved command still receives the
values and can do anything with them. What moves is the *accidental* class — a commit, a sync
upload, an IDE snapshot, a crash — which now has milliseconds to happen instead of the run.

### 9.2 New surface

| Item | What it is | Agent-reachable? | What confines it |
|---|---|---|---|
| **`run_with_env(max_reads=N)`** | a new parameter, not a new tool | yes, like every parameter | requires `swap=` or `materialize=`; refused with `background=True`; 1 ≤ N ≤ 1000; Windows only (`singleview.unsupported_reason`); refused before the dialog if the file's `self_test` fails; the dialog states "reverted after the first N open(s)". Part of the trust signature (9-tuple), so a trusted run with a different N is a new grant |
| **`vault_lib/singleview.py`** | the kernel primitives: `CreateFileW` share=0, `FSCTL_REQUEST_OPLOCK`, Restart Manager (`RmGetList`), `IsProcessInJob`, `QueryInformationJobObject` | no direct path; used only inside the run | every call is a query except three writes, all to the swapped file: real values in, placeholders back, and `trim_padded_tail` (path-based, after the handle is released, only if the file still matches the padded write byte-for-byte) |
| **`self_test(path)`** | before the dialog, on the placeholder file: proves an oplock is granted and a foreign open is held | runs on every `max_reads` call | touches placeholders only; a holder already on the file (an editor, an AV scanner) is a refusal, not a warning — the feature cannot promise anything on a file it cannot hold |
| **`procs.run_bound(on_start)`** | hands the run's Job handle to the watcher so opens can be attributed to the command's tree | no | the handle is only ever queried; the observer is told the handle is going away *before* it is closed (`6029601`) |
| **new result fields** | `single_read` (per file: `reads`, `attribution`, `restored_early`, `reads_after_restore`, `foreign_opens`/`foreign_apps`, `watch_gap_seconds`, `restore_attempts`/`restore_error`, `mapped_view_tail_*`), `single_read_note`, `single_read_restored_early` | yes — this is the point | counts and app names only; never bytes |
| **new on-disk state** | none | — | no new file in the vault directory; the journal entry is the 1.6.x one, and a watcher restore folds into it |

### 9.3 Attribution — who is counted

A break says *something opened the file*, not who. The Restart Manager names holders that are
still there ~300 ms later; a dotenv loader is long gone. The rule shipped is:

- a named holder inside the run's Job → counted (`job`);
- a named holder outside it (an editor, the agent's own `Read`, a sync client) → **not counted**,
  reported as `foreign_opens` with the app names;
- nobody nameable while the command is still running → counted (`unattributed`);
- the open that was in flight when the command exited (a read as its last act) → counted
  (`unattributed-at-exit`).

The failure direction is what matters. Counting too early (an AV scanner racing the loader)
reverts too soon: the command reads placeholders, fails, and the result says
`reads_after_restore` — a **correctness failure the user sees, never a leak**. Counting too late
(a foreign holder that was in fact the command's, mis-named) leaves the values until the next
open or until exit — the 1.6.x window, never worse than before. There is no rule that turns a
mistake into a longer exposure than the feature replaced.

### 9.4 What the reviews found, and what each meant for the posture

Push gate on the first 1.7.0 commit (`747a104`; blocked, six findings, fixed and amended into
`ed7de9c` before anything reached the remote):

1. **Multi-target failure left earlier targets armed** — the rollback's file-based restore could
   not open a file the watcher still held; the values stayed with a journal entry (recovery-class,
   not silent). Watchers are closed before the rollback.
2. **Short write accepted** — a restore that wrote fewer bytes than asked would have left the
   tail of a real value between the prefix and the truncation point and reported success. The
   only finding in the set that was a leak class; `write_all` refuses a short write.
3. **Verification read failure counted as a failed restore** — the placeholders *were* on disk,
   but the end-of-run restore would have run again, seen placeholders where it expected values,
   and reported every line as a conflict. False alarm, not a leak; now reported as unverified.
4. **Main thread closing a handle a live watcher owned** after a failed join — a race, not an
   exposure; the thread owns the handle until it is gone.
5. **Oplock IRP not drained on close** — the kernel could complete into a freed `OVERLAPPED`.
   Memory safety; `close()` waits on the event after `CloseHandle`.
6. A stray CR in the agent instructions.

Push gate on the pushed `ed7de9c` (warn, three findings, fixed in `6029601`):

7. **A failed early restore was never retried** (high). One transient I/O error on the revert
   left the real values on disk for the rest of the run, silently until the final report — the
   exact window `max_reads` exists to close, reopened by a disk hiccup. Every later counted open
   now retries until one succeeds; `restore_attempts`/`restore_error` are reported; the end-of-run
   restore still covers a run in which none succeeded. The regression test fails on the pre-fix
   watcher.
8. **Mapped-view padding never trimmed** (medium). When a reader holds a memory-mapped view the
   truncate is refused (`ERROR_USER_MAPPED_FILE`); `write_all` pads the tail with newlines so no
   byte of a real value survives — that property held — but the promised exact-length retry did
   not exist, so the file stayed longer than it should. `trim_padded_tail()` runs once the handle
   is released, only if the file still matches the padded write; otherwise the result says
   `mapped_view_tail_error` and the note says what to do. The pad write is now checked like the
   main one. Tested with a real `mmap` view.
9. **Job handle closed before the watcher was told** (medium). A break processed in that gap
   queried a closed — possibly recycled — handle: a mis-attribution (delayed revert, §9.3), not a
   leak. Order is now notify, then close.

Push gate on `6029601` (warn, two small findings, fixed in `73f83eb`; final gate: pass): the
padded-tail note wrongly covered the materialize watcher, whose file is unlinked regardless; the
trim did not fsync.

### 9.5 Exposure windows (§5) revisited

1. **Agent read during the run.** A `Read(.env)` batched after the command's own read now gets
   placeholders. Batched *before* it — a race the agent can win — it gets real values, is held
   for ~10 ms, and is **visible in the result** either way: named (`foreign_opens`,
   `foreign_apps`) if it was still holding the file when the Restart Manager looked, since the
   host process is outside the Job; or, too fast to name, counted as `unattributed` — which
   reverts the file under the command and shows up as `reads_after_restore`. Still policy, not
   a boundary; but no longer silent.
2. **Git during the run.** Unchanged in kind; the window a `git add` can fall into is now
   milliseconds.
3. **Editor write-back.** Unchanged. An editor that is already holding the file is a `self_test`
   refusal, so the common case (file open in VS Code) never starts a `max_reads` run.
4. **IDE history / cloud sync.** Unchanged in kind; the upload has to land inside the loader's
   read. A sync client that opens the file is a foreign holder and is named.
5. **Hot reloaders.** Now reload twice within the same second; a watcher-driven reload *is* a
   consumer that reads more than once — `max_reads` is the wrong tool for it and the result says
   so (`reads_after_restore`).
6. **Recovery is triggered, not timed.** Unchanged — but a server killed after the first read
   has already restored; the crash window is now the same milliseconds.
7. **Forged journal entries.** Unchanged.
8. **WSL2 / host.** Unchanged; the oplock is a Windows-side fact and says nothing about a Linux
   reader on the same files.

New residuals, disclosed in the README:

- **Windows only.** Linux `fanotify` (permission events) is the equivalent and is deferred.
- **`background=True` + `max_reads`** is refused: no process to hold the handle after return.
- **Pipe-mode materialize** (a FIFO instead of a file) is deferred.
- **A consumer that reads more than N times** sees placeholders after the revert. Fail-closed,
  reported, and the fix is a larger N — never a smaller window that leaks.

### 9.6 Gaps (§6) — what 1.7.0 changes

- **`materialize` crash recovery**: a `max_reads` materialize file is emptied through the handle
  at the first read and unlinked at exit; a crash after the first read leaves an empty file, not
  a real-values one. Before the first read, the 1.6.1 status stands.
- Everything else in §6 is unchanged.

### 9.7 What the tests prove (14 in `tests/test_single_view.py`)

Every test runs a real child in a real Job against a real oplock — there is no fake for the
kernel's answer to "did someone open this file":

- the headline: the child reads the real value, sleeps, reads again while still running, gets
  the placeholder; `max_reads=2` serves both reads
- `stat()`/`isfile`/`getsize` are not reads; a foreign holder is reported and not counted; a
  run that never reads restores at exit with zero reads
- the materialize file is emptied after the first read
- every pre-dialog refusal, and `self_test` refusing when a holder exists
- the watcher thread is gone and the handle released after the run (an exclusive open succeeds)
- a failure on a later target rolls back an armed earlier one; a short write is refused
- **`6029601`:** a failed restore is retried on the next read (fails on the pre-fix watcher); a
  real `mmap` view forces the padding path and the tail is trimmed after release, and a file
  changed meanwhile is left alone; the Job handle is still valid when the observer is told

Not proven: attribution against a *hostile* reader that times its open to be nameable and in
the Job's pid range (it would need to be in the Job, which only the command's tree is); the
Linux path (none exists); behaviour of the Restart Manager under load beyond the ~300 ms
settle window (a slower answer is a `foreign-unattributed`/`unattributed` label, not a wrong
count).

### 9.8 Reviews 1.7.0 went through

- Design: super-thinker pass on the concrete mechanics (oplock kind, share mode, attribution
  rule, settle window, in-handle restore, mapped-view padding, Job-handle hand-off) before
  implementation; every accepted item is in the shipped code or in the deferred list above.
- Spikes: oplock break on a foreign open, no break on `stat`, no break on an own write through
  the RWH handle, reopen-as-rearm timing, in-handle restore, `IsProcessInJob` with limited
  rights, `RmGetList` naming latency.
- Push gate: 6 findings on the first commit (blocked; fixed pre-push), 3 on the pushed one
  (1 high: the retry), 2 on the follow-up (1 medium, 1 low), then pass — §9.4 has each one.
- Suite: 640 tests, pytest and all 17 standalone runners, plus the Tk check; the single-view
  suite run three times back-to-back with no flake.
