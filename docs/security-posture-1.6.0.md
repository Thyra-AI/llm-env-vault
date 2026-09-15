# Security posture after 1.6.0 — what changed, what is new, what to watch

This is a maintainer-facing map of the system as it stands after the in-place swap landed
(commit `3dabd7e`). It is organised around one question: **where can a real secret value be,
who can reach it there, and what puts it back.** Everything 1.6.0 added is marked **NEW**;
everything else is the standing model, restated so the additions can be judged against it.

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
| **NEW `swap` target — the project's own registered `.env`** | 1.6.0 | one command | `finally`: two-tier restore, retried, verified from disk | **journal-driven restore by the next tool call in any session, server start, or `--recover`** |

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
| **NEW** `python mcp_server.py --recover` | runs recovery, prints JSON, exits. No password, no dialog — it only ever writes placeholders into registered files' managed lines, which `resync_targets` could already do |

### Agent-readable / agent-writable plaintext state in the vault directory

| File | Purpose | Agent-writable consequence | Validated on read? |
|---|---|---|---|
| `vault_index.json` | name → placeholder number | can renumber placeholders; caught by resync's conflict rule | yes (names, ints) |
| `targets.json` | which files, which names | can add names/paths → a resync could rewrite more lines; **1.6.0: could have widened a trusted swap — closed, see §3** | yes |
| `files.json` | encrypted-file inventory | can hide a file from key retirement → refused when registry empty / inconsistent | yes |
| **NEW `target_styles.json`** | original quoting per line | can only change the quoting of a line the agent could rewrite wholesale; cannot move a value out of its line | yes, entries dropped silently |
| **NEW `swap.journal.json`** | which files a live server has real values in | see §4 | yes, malformed → error reported, not swallowed |

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
entry for a file that is already restored: same. There is no ordering in which real bytes are on
disk without an entry, except the one below.

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
source degrade to "pid exists" — a delayed recovery, never a clobber.

**Two servers.** `journal_add` refuses while another live server has an active entry for the
same file; `resync_targets` and `install_migrate` skip/refuse such files. Without this, a second
chat's resync would report every real-value line as a conflict (names only — verified the payload
never carries values) and a migrate would re-capture the real values as new secrets.

**Restore failed.** The restore write is retried ten times with backoff; on final failure the
entry is flagged `restore_failed`, the result says the file still holds REAL values, and every
later tool call retries regardless of whether the owner is alive. **The same flag is set when
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
   `Read(.env)` in one agent turn would work. Mitigation is disclosure plus `only_vars`.
2. **Git during the run.** `git add -A`, `commit`, `stash` — by the user or by the command
   itself — capture real values into history. The dialog warns in amber when the file is
   tracked. Not refused, because the README endorses committing placeholder files.
3. **Editor write-back after restore.** An editor that auto-reloaded the swapped content and
   saves its buffer *after* the restore writes secrets back with no journal entry. Post-restore
   verification catches only write-backs that land before the tool returns.
4. **IDE local history / VS Code timeline / cloud sync.** External changes are snapshotted into
   the IDE's own storage; a sync client can upload the swapped file inside the command's
   lifetime. Nothing on this machine can recall either.
5. **Hot reloaders.** A dev server watching `.env` reloads on swap and again on restore, the
   second time with placeholders. Swap is foreground-only for this reason.
6. **pid reuse on platforms without process start times.** A stale entry whose pid was
   recycled is treated as live until that process exits or `--recover` is run by hand. Windows
   and Linux are covered; macOS falls into this bucket.

---

## 6. Gaps the new work makes more visible

Not regressions — pre-existing behaviour that now looks inconsistent next to the swap path.

| Gap | Where | Suggested fix | Size |
|---|---|---|---|
| **`materialize` and `files=` have no crash recovery.** A server killed mid-run leaves a real-values file with no record. | `_run_with_env_core` | Journal them with the same mechanism (`journal_add` with a `kind`), recovery deletes rather than restores. | small — the primitives exist now |
| **`materialize` / `write_restored_file` temp-file window.** Same `..name.tmp` leftover on hard kill, no sweep. | `store.write_materialized_env`, `write_restored_file` | Include in the journal recovery above. | small |
| **Background log unredacted if the server dies first.** | background path | Journal the log path; recovery redacts it (needs no password: values are gone, so it can only delete). | medium |
| **`--recover` accepts no confirmation.** It rewrites registered files' managed lines to placeholders. Same authority as `resync_targets`, but from a terminal. | `__main__` | Acceptable as-is; document that it is equivalent to resync. | none |
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
- Implementation: bug-hunter pass over the five touched source files — 0 findings.
- Push gate (review-gate, independent model): 1 high (verify_failed dropped the journal entry),
  2 medium (fail-open on a corrupted journal; bookkeeping failure reported as a leak), 1 low
  (formatting) — all fixed in the follow-up commit with a regression test each. Worth noting
  that the bug-hunter missed all three; two reviewers with different framings caught what one
  did not.
- Suite: 595 tests, pytest and every standalone runner, plus the Tk check in a fresh interpreter.
