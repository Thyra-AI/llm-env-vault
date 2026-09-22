# Security posture, 2.0.0

What this tool promises, what it does not, and what changed when
`run_with_env(swap=)` was retired.

---

## 1. The invariant

**Real values live in `vault.enc` (ciphertext) and in the memory of a process a human
explicitly unlocked via a native dialog the agent cannot see or type into. No file an agent can
read holds a real value — placeholders only.**

### The standing exceptions, in full

There are two, both bounded to one foreground command and both disclosed in the dialog before a
human approves anything.

| Where a real value is on disk | Since | Bound | Cleanup | If the server dies |
|---|---|---|---|---|
| `materialize` target — a **fresh path that must not already exist** | 1.0 | one command, or with `max_reads=N` until the command has read it N times (typically milliseconds) | `finally`: unlink | none — the file stays |
| `files=` restored plaintext (a decrypted `.levault`) | 1.5.0 | one command | `finally`: secure_delete, survivors named | none — same |

A third path is not an exception but is worth naming: a **background run's log**
(`llm-env-vault-run-*.log`) holds whatever the command printed, unredacted, until the process
exits and a watcher thread redacts it in place. If the server dies first, it stays unredacted.

1.6.0–1.7.1 had a fourth: `swap`, which wrote real values into the project's **own registered
`.env`**. That is gone. §3 says why.

---

## 2. The ceiling of the threat model, stated first

**An agent with filesystem read access can read a materialized file while the command runs** —
from a batched tool call, or from a second session — and no software running under the same OS
account prevents it. Trusting a run for eight hours is trusting the agent with those values for
eight hours: the approved command receives them and can write them anywhere. Output redaction
covers captured stdio only, is skipped for values under 8 characters, and a command that
transforms what it prints can still emit a real value.

The agent instructions forbid reading a materialize target. That is policy, not a boundary.

What the design can do — and does — is make the *accidental* class rare: commits, syncs,
crashes, orphans. That is why the remaining exception writes to a path you choose, that must
not already exist, and never to a file git is tracking.

---

## 3. What changed in 2.0.0, and why

### `run_with_env(swap=)` is removed

It rewrote the project's own registered `.env` with real values for the lifetime of one command
and restored the placeholders afterwards. Four reasons it went:

1. **It suspended the invariant against precisely the party the invariant protects against.**
   The agent that calls the tool is the agent that can then read the file. 1.7.0's own addendum
   conceded this in its opening paragraph.
2. **At the worst possible path.** The same exposure class as `materialize`, but at a file far
   more likely to be committed, synced, or open in an editor. The mitigations — a journal, a
   two-tier restore, post-restore verification, git and cloud-folder warnings — existed because
   the path was dangerous, and could not close a commit made *during* the run, an editor buffer
   saved after the restore, or IDE local history.
3. **It never stabilised.** Four releases in eight days (2026-09-15 to 2026-09-16 for the
   features, through 2026-09-22 for the fixes): the swap journal, the process watchdog, a
   failed early restore, mapped-view padding, an fsync, a short-write test. Several were found
   only by adversarial review, not by the suite. The defect-discovery rate never flattened.
4. **It was structurally unreachable for its most common trigger.** A `git push` whose pre-push
   hook runs tests is refused a swap — correctly, because `git add -A` with real values in
   `.env` is the one-dialog path to committing them. So the case that most often needed it
   could never use it.

### What replaces it

| Mechanism (see `env-consumption-research.md`) | 1.7.1 | 2.0.0 |
|---|---|---|
| B-when-scrubbed — a harness builds the child env from an allowlist, so the file is the only source | `swap` | **typed placeholders** — the file parses; nothing on disk |
| F — a settings library validates types at load | unfixed (deferred) | **typed placeholders** |
| E — a reader that takes an env-file path | `materialize` or `swap` | `materialize` (unchanged) |
| C, D — a loader that lets the file win; a shell that sources it | `swap` | **not supported** |

C and D are the honest loss. They need the real value in the canonical file, and 2.0 declines to
put it there. That is a smaller product and a bigger guarantee.

---

## 4. Typed placeholders: what they disclose

A typed placeholder preserves the **shape** of a value so the file can be parsed, and nothing
else. `SMTP_PORT=17`, `SMTP_USE_SSL=false`, `DATABASE_URL=postgres://placeholder-3.invalid`.

**Disclosed:** the type of each value, and a URL's scheme.

**Not disclosed:** any content. A variable that is really `true` renders `false`; a `0`/`1` bit
renders `0`; a port renders its index number. The rendering is a function of the shape and the
index number only — there is a test that asserts exactly this, over pairs of different real
values that must produce identical placeholders.

**Opt-out:** `placeholder_style: "opaque"` keeps the untyped `"value N"` form. A vault created
before 2.0 is opaque until a human runs `retype_placeholders`, so upgrading rewrites nobody's
`.env`.

**Where the type lives:** `placeholder_shapes.json`, plaintext and agent-writable like
`targets.json` and `vault_index.json`, validated on read. An unrecognised shape falls back to
`"value N"` rather than being interpolated into a line. The file is **never pruned** when a
secret is removed — the entry is a tombstone, and without it a typed placeholder left behind for
a departed name is indistinguishable from a real value, which would silently disarm
`resync_targets`' data-loss guard.

---

## 5. Agent-writable state, and what each forgery buys

Everything in the vault directory except `vault.enc`, `vault.salt` and the format file is
plaintext the agent can rewrite. All of it is validated on read.

| File | A forged entry can… | Bounded by |
|---|---|---|
| `vault_index.json` | renumber placeholders | duplicate numbers refused; resync's conflict rule |
| `targets.json` | register another local file for rewriting | the dialog shows the resolved path; only placeholder text is ever written without a password |
| `target_styles.json` | change the quoting of a line | a line the agent could already rewrite wholesale |
| `placeholder_shapes.json` | change how a placeholder renders, or raise the number high-water mark | shapes validated; unknown ones fall back; a raised mark only wastes numbers |
| `files.json` | hide a file from key retirement | refused when the registry is empty or inconsistent |
| `swap.journal.json` (legacy) | trigger a restore of placeholders into a registered file | `validate_target_key`: registered, local, drive-letter paths only; anything else quarantined and reported |

The registry is the trust anchor and the registry is agent-writable. What remains is the dialog,
which shows the resolved path and the variable names every time.

---

## 6. Legacy swap recovery

2.0 writes no journals. It still **reads** one, because a user can upgrade while a `.env` on
disk holds real values — a 1.6–1.7 server crashed mid-swap, or one is still running right now in
another session. Those need opposite treatment:

- **Dead owner** → rewrite every managed line unconditionally. Nothing can now distinguish a
  value the vault wrote from one the user typed, and leaving a secret on disk is the worse
  error. The report says so.
- **Live owner** → do not touch it. Another session's command is reading that file. It is
  reported as `legacy_swap_live` and left until the pid goes.

Liveness is decided by pid **and** process start time, so a recycled pid is not mistaken for the
original server; our own pid with a foreign server id is a dead predecessor. `vault_lib/
legacy_swap.py` is deprecated and scheduled for removal in 3.0.

With no journal at all — deleted, or never written — nothing can restore the file automatically.
Re-running `/llm-env-vault:protect` is the documented path: it treats the real values as real
values and re-vaults them.

---

## 7. Residual risks, unmitigated

- **The materialize window.** §2. An agent, or anything else on the account, can read the file
  while the command runs.
- **A crashed server leaves a materialize target behind.** There is no journal for it, unlike
  the swap path that had one. This is the one place the retired feature was better served, and
  it is disclosed rather than fixed: a fresh path you chose is far less likely to be committed
  than `.env`, which is the trade.
- **A background run's log is unredacted until the process exits.**
- **Typed placeholders disclose types.** §4.
- **Range validators still reject a typed placeholder.** `port: int = Field(ge=2000)` fails on a
  small index number; preserving the magnitude would leak it.
- **Filesystem forensics.** A value that was ever on disk may persist in the USN journal, Volume
  Shadow Copy, a resident MFT record, the search indexer, AV quarantine or a sync client's
  storage. Rotate anything you believe was exposed; deleting the file is not erasure.
- **Trust is a convenience, not a boundary.** It lives in one process's memory and is forgotten
  on exit, but within a session it lets an approved command re-run without a dialog.

---

## 8. What a reviewer should check first

1. That the exceptions table in §1 still has two rows.
2. That nothing writes a real value to a path derived from `targets.json` (`grep` for
   `write_materialized_env` and confirm its only caller resolves a fresh, non-existent path).
3. That `is_placeholder` is the only answer to "is this line ours", and that no call site has
   drifted back to matching `PLACEHOLDER_VALUE_RE` directly — a permissive answer there is how a
   real value gets overwritten, and an over-permissive one is how a placeholder gets vaulted as
   a secret.
4. That `tests/test_legacy_swap_recovery.py` still calls no swap writer. The moment it does, it
   will die with them and take the recovery coverage with it.
