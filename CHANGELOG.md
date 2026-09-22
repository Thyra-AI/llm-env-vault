# Changelog

All notable changes to llm-env-vault are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note that
`master` is the release channel: the marketplace entry uses a `"./"` source, which tracks the
default branch rather than a tag, so tags here are for reference and rollback rather than for
pinning what a user installs.

## [2.0.6] — 2026-09-23

### Fixed

- **Reverts 2.0.5's chain-following, which made the thing it was fixing worse.** Following a
  junction's target meant `os.lstat()` on the full multi-component path that `readlink()`
  returned -- and the OS transparently follows the *intermediate* components of any path handed
  to a stat call. So a guard whose entire purpose is to avoid touching the network acquired a
  new way to touch it, on a path whose prefixes had never been validated. The outer component
  walk is only safe because it checks each prefix before descending; the chain hop skipped that
  entirely.

  Back to the one-hop check, and the residual is documented rather than papered over: a chained
  junction is still caught after resolution by the containment check, so real values are never
  written to the share, but `resolve()` will have reached it first. Closing that properly means
  validating every prefix of every target, which is a different piece of work from the one-line
  loop 2.0.5 shipped.

- **The UNC test no longer refuses legitimate local junctions.** A junction's target comes back
  in the NT namespace, where the local form (`\??\C:\dir`) begins with the same backslash pair
  as the network one (`\??\UNC\server\share`), so the plain "starts with two backslashes" test
  called every long-path junction a share -- and the `"UNC" in target[:8]` test it was paired
  with called `C:\Uncommon` one too. Both errors block a legitimate local path, and a guard
  people have to turn off protects nothing. `_target_is_unc` now distinguishes the namespaces
  precisely, with the eleven forms pinned in a test.

## [2.0.5] — 2026-09-23

### Fixed

- **The network-path guard followed only one hop of indirection.** `_reparse_points_to_share`
  read each reparse point's own target once and checked that single string, so a chain --
  `proj/link` to a plain local path, which is *itself* a junction to `\share` -- looked
  innocent at every step: the first link's target is local, and the component walk never visits
  the second link, because it only ever steps through components of the original path. The
  chain is now followed to its end (bounded; a loop or an implausibly long chain is refused).
  Every step is an `lstat`/`readlink` on a local path, so following costs nothing on the wire,
  which is the point -- `resolve()` is what the guard exists to avoid reaching.

  Pre-existing since 1.6.1, but it only started mattering in 2.0.4, which gave the helper a new
  caller in `materialize`.

- A comment left as a broken sentence by 2.0.4's edit, and an invalid escape sequence in a
  docstring added the same day (`DeprecationWarning` on import).

## [2.0.4] — 2026-09-23

### Added

- **`materialize` refuses a network location.** A UNC path, a mapped network drive, or a path
  reached through a junction or symlink pointing at a share. `materialize` writes REAL values
  to that path for the lifetime of the command; on a network location they cross the wire and
  land on the server's storage -- backups, snapshots, another machine's disk -- where the unlink
  on exit cannot reach any copy it has already made.

  The guards themselves are not new: `_drive_is_remote` and `_reparse_points_to_share` were
  written for `swap=` in 1.6.1 and were left orphaned when 2.0.0 deleted its only caller.
  `materialize` never had them. The UNC and junction checks run *before* the path is resolved,
  because resolving is the step that opens SMB with the user's credentials -- and on Windows an
  absolute segment wins a join, so a UNC value would otherwise be resolved before the
  containment check could refuse it.

### Changed

- **The oplock-probe staleness window is a flat hour**, not a value derived from `self_test`'s
  `timeout`. The sweep's only risk is deleting a probe another server is using right now, so the
  question is "could a live probe possibly be this old?" -- and a live one lives for the length
  of one `self_test`, three seconds by default. Tying the window to an argument made the answer
  depend on a parameter, which is how 2.0.2 and 2.0.3 each shipped a version of the same bug.

- `self_test_for_new_file`'s docstring now records why the probe cannot live somewhere tidier,
  so it is not re-litigated: oplock-with-handle-caching is a property of a VOLUME, and a project
  can sit on any of them, so probing the plugin's own data directory would pass on C:\ and then
  silently fail the feature elsewhere. `FILE_FLAG_DELETE_ON_CLOSE`, which would remove the probe
  even on `TerminateProcess`, was tested and does not work either -- `self_test`'s final
  assertion is that the held foreign open *completes* once we release, and it cannot if the file
  is deleted at that moment.

## [2.0.3] — 2026-09-22

Documentation and a latent coupling in the same function 2.0.1 and 2.0.2 fixed. No behaviour
change for any current caller.

### Fixed

- **The probe staleness threshold is derived from the call's `timeout`, not assumed.** 2.0.2
  used a flat 60 seconds, on the stated assumption that "a live probe's whole life is bounded by
  self_test's timeout, which is seconds". Nothing enforced it: `self_test` runs for roughly
  2*timeout plus overhead, so the first caller to pass a timeout above ~25s would have had its
  own live probe swept. No caller does today -- the default is 3s -- so this was latent. The
  window is now `max(60s, timeout * 4)`.
- `self_test_for_new_file`'s docstring said an older probe "is swept first" without the age
  qualification, which is the exact misconception the inline comment below it exists to correct.

## [2.0.2] — 2026-09-22

Fixes a regression in 2.0.1's own fix, found by the push-time review of 2.0.1.

### Fixed

- **The stale-probe sweep could delete a concurrent server's live probe.** 2.0.1 swept every
  file matching `.{target}.*.oplock-probe` before creating its own -- but the live probe uses
  that same name shape, so a second server running `self_test_for_new_file` against the same
  target could remove the first one's probe and make it fail with a spurious refusal. Holding
  the file is not the protection it appears to be: the probe is closed after it is written and
  only re-opened by `self_test`, leaving a real unprotected gap between the two.

  A probe is now removed only if it is older than 60 seconds. A live one exists for the length
  of one `self_test` -- seconds -- so age separates the two cleanly, while a crash survivor from
  any earlier run is still swept.

## [2.0.1] — 2026-09-22

Fixes a defect introduced by 2.0.0's own new code, plus the stale prose that
shipped with it. All three were found by the push-time review of 2.0.0, after the tag.

### Fixed

- **A crash could permanently disable `max_reads` for a materialize target.**
  `self_test_for_new_file` (new in 2.0.0) proves the filesystem grants an oplock by creating a
  throwaway probe beside the target and removing it in a `finally`. The name was fixed, so a
  process killed before reaching that `finally` left the file behind -- and every later
  `max_reads` run against the same target then hit the exclusive-create and was refused. One
  crash turned into a permanent, self-inflicted refusal of the feature.

  The probe name now carries random bytes, so a survivor can never collide, and older ones are
  swept first -- including the fixed name 2.0.0 shipped, which is the survivor most likely to
  exist. 2.0.0's test asserted the refusal as correct behaviour, which is how the bug got
  through; it now asserts the opposite.

- **Stale swap prose in `vault_lib/store.py`.** A design-comment block still described
  `run_with_env(swap=[...])` in the present tense as this module's "deliberate, bounded
  exception", in the same file whose swap code 2.0.0 deleted. `SWAP_JOURNAL_NAME` and
  `SWAP_JOURNAL_LOCK_NAME` were left behind as dead duplicates of the ones in
  `vault_lib/legacy_swap.py`, which is where the only remaining reader lives.
  `validate_target_key`'s docstring still gated "a swap= argument" that no longer exists.

## [2.0.0] — 2026-09-22

`run_with_env(swap=)` is removed. It wrote real secret values into the project's own registered
`.env` for the lifetime of a command — the one thing this tool exists to prevent — and it was
refused for `git` commands, which is the most common trigger there is. Typed placeholders
replace it for the cases that never needed a real value, and `materialize` keeps the ones that
do.

**Upgrading rewrites none of your files.** A vault created before 2.0 keeps the untyped
`"value N"` placeholders and produces byte-identical output until you run `retype_placeholders`
yourself. The cost of that choice, stated plainly: an existing project stays unparseable by a
typed settings loader until you run it once.

### Removed

- **`run_with_env(swap=)`**, and with it `max_reads` for swap targets, the swap section of the
  unlock dialog, the swap parameters of the trust signature, and the git refusal (there is no
  longer a swap for git to be refused).

  Why, in short: it suspended the invariant against precisely the party the invariant protects
  against — the agent that calls the tool is the agent that can then read the file, which
  1.7.0's own addendum conceded in its opening paragraph. It did so at a path far more likely to
  be committed, synced or open in an editor than a materialize target. It never stabilised:
  four releases in eight days, several of the fixes found only by adversarial review rather than
  by the suite. And it was structurally unreachable for its most common trigger, a pre-push hook
  whose tests read `.env`, because a swap is refused for `git`.

  See `docs/security-posture-2.0.0.md` §3, and the status banner on
  `docs/env-consumption-research.md`.

- **Not supported any more:** a loader that lets the file win (`load_dotenv(override=True)`,
  `godotenv.Overload`, `dotenvx --overload`, tox `set_env = file|.env`, `direnv`), a shell that
  sources `.env`, and a reader hard-wired to the canonical `.env` (Compose `env_file: .env`, an
  IDE's `envFile`). These need the real value in that exact file, and 2.0 declines to put it
  there. Point the tool at a `materialize` path if it accepts one.

### Added

- **Typed ("shape-preserving") placeholders.** `SMTP_PORT="value 17"` is not an `int` and
  `SMTP_USE_SSL="value 38"` is not a `bool`, so a placeholder-only `.env` could not be LOADED by
  pydantic-settings, django-environ or Spring — with the vault not involved in the run at all.
  A typed placeholder preserves the shape and nothing else, so the file parses:

  | Real value | Placeholder for index N |
  |---|---|
  | an integer | `N` |
  | `0` / `1` | `0` — never the real bit |
  | true/false/yes/no/on/off | `false` — never the real truthiness |
  | a float | `N.0` |
  | `<scheme>://…` | `<scheme>://placeholder-N.invalid` |
  | an email address | `placeholder-N@example.invalid` |
  | `[…]` / `{…}` | `[]` / `{}` |
  | anything else | `"value N"` — an opaque string has no shape to preserve |

  This closes mechanism F and mechanism B-when-scrubbed from
  `docs/env-consumption-research.md` — the latter being the case that kept failing: a test
  harness that builds its child's environment from an allowlist, so nothing injected survives
  and the file is the only source.

  It discloses the TYPE of each value, and a URL's scheme. Never content.

- **`retype_placeholders(only_vars=None)`.** Password-gated, because a value's type can only be
  read from the real value. Lists every line exactly as it will end up, states what it
  discloses, records the shapes and rewrites the registered files. A line that does not
  currently hold one of our placeholders is reported under `conflicts` and left untouched.

- **`placeholder_shapes.json`** in the vault directory: each variable's shape, the highest
  placeholder number ever issued, and whether this vault is typed. Plaintext and agent-writable
  like the index, validated on read, gitignored. Never pruned when a secret is removed — the
  entry is a tombstone, without which a typed placeholder left behind for a departed name is
  indistinguishable from a real value.

- **A header line in managed files** of a typed vault (`# Managed by llm-env-vault -- the values
  below are PLACEHOLDERS, not real secrets.`). `SMTP_PORT=17` reads like real configuration
  where `"value 17"` announced itself. Whole-line only: `docker run --env-file` treats
  everything after `=` as the value.

- **`docs/security-posture-2.0.0.md`** — the invariant, its two remaining exceptions, the
  ceiling of the threat model, and what a reviewer should check first.

### Changed

- **Placeholder numbers are never reused.** A freed number handed to a different variable is the
  only way a placeholder already written into a file can come to mean something else, and for a
  typed one that drift is unrecoverable — `SMTP_PORT=17` where 17 is now someone else's number
  cannot be told from a real port. A high-water mark retires numbers instead. `next_placeholder`
  stays a question rather than a reservation, so a dialog you cancel burns nothing.

- **`vault_status`** reports `placeholder_style` and `untyped_vars`, and renames
  `swaps_in_progress` to `legacy_swap_live`.

- **Placeholder detection is index-aware and exact.** `PLACEHOLDER_VALUE_RE` is unchanged — a
  pattern loose enough to match `17` cannot tell a placeholder from a real port. A line is one
  of ours if it matches the legacy regex, or if it equals the one string this name's number and
  shape render to. Stricter than 1.x for a typed name, identical for an untyped one.

- **`retype_placeholders` revokes trusted commands** that drift-hash a managed file, because
  retyping changes its bytes. That is the trust feature working, not a fault.

- `store.preview_swap` → `store.placeholder_state` and `store.render_swap_value` →
  `store.render_value_in_style`. Neither was ever swap-specific: the first is what
  `vault_status` uses for its journal-independent "which managed lines hold a real value"
  report, and the second is what keeps a rewrite in the quoting a file's consumers already
  parse.

### Fixed

- **A managed line that was missing entirely was appended as `"value N"`** regardless of the
  vault's style, which on a typed vault wrote a line the file's own loader could not parse. It
  goes through the single renderer now.

- **The test suite wrote vault state into the repository.** Seven suites redirected store's
  named file globals but not `ROOT`, and `target_styles.json`, `swap.journal.json` and
  `placeholder_shapes.json` all derive from `ROOT` at call time. A plugin install is a git
  clone, so a tracked file of that kind would ship one developer's variable names to every user.
  Fixed at the source by isolating `ROOT`; `placeholder_shapes.json` is gitignored alongside its
  siblings.

### Deprecated

- **`vault_lib/legacy_swap.py` and `python mcp_server.py --recover`.** Nothing in 2.x writes a
  journal; these exist only so a crash from 1.6–1.7 can still be cleaned up. Removal in 3.0.

### Upgrading from 1.6–1.7

| You used swap for… | Now |
|---|---|
| a test harness that scrubs the child environment; anything that only needs `.env` to *parse* | `retype_placeholders()` once. Nothing at run time. |
| `docker run --env-file`, Compose `env_file:`, `kubectl --from-env-file` | `materialize=".env.runtime"` with `max_reads=1` (2 for compose) |
| `load_dotenv(override=True)`, `source .env`, a tool hard-wired to `.env` | Not supported — see Removed |

If a pre-2.0 server crashed with real values swapped into a `.env`, 2.0 still cleans it up: on
server start, on the next tool call in any session, or with `python mcp_server.py --recover`. A
pre-2.0 server that is **still running** is left alone and reported as `legacy_swap_live` until
it exits. With no journal at all, re-run `/llm-env-vault:protect`.

## [1.7.1] — 2026-09-22

No behaviour change. Test-only fix; released so existing installs move off the 1.7.0 tree,
since `claude plugin update` compares versions rather than commits.

### Fixed

- `tests/test_single_view.py::test_short_write_is_refused` patched only `GetOverlappedResult`,
  on the premise that an overlapped write always reports its byte count there. A handle opened
  `FILE_FLAG_OVERLAPPED` may complete the write inline instead, and then `WriteFile` returns
  TRUE and fills the count itself, so the patch never fired and a full count reached the guard.
  The developer machine takes the async path, CI's disk does not -- every Windows job failed
  from 61756a0 on. `WriteFile` is now patched alongside `GetOverlappedResult`, and the test
  asserts the byte count was actually shaved so it cannot pass for the wrong reason again.
  The `write_all` short-write guard itself was correct and is unchanged.

## [1.7.0] — 2026-09-16

### Added

- **Single-view real values: `run_with_env(..., max_reads=N)`.** With `swap=` or
  `materialize=`, the real values are reverted as soon as the command's process tree has opened
  and closed the file N times -- a dotenv loader reads once at startup -- instead of when the
  command exits. The window with real values on disk shrinks from the command's lifetime to
  milliseconds. This is Doppler's `--mount-max-reads 1`, built from what a user-mode process on
  Windows has:

  - One exclusive handle (share mode 0) held for the whole run, with a **Read+Write+Handle
    oplock**. The real values are written *through* that handle, so "armed" and "on disk" are
    never two separate moments. Any other process's open breaks the oplock -- and is held until
    we release -- so an open is observed the instant it happens; attribute-only opens
    (`os.stat`, `exists`) do not break it and are not reads.
  - On a break the handle is released (the reader proceeds), then re-opened exclusively in a
    tight loop: the reopen succeeds the moment the reader closes, and that success is the
    re-arm. The **Restart Manager** names any holder that persists; a holder inside the run's
    Job object is the command's read, a named holder outside it (editor, indexer, antivirus)
    is foreign -- reported in the result, not counted. A reader too fast to be named (every
    dotenv loader) is counted while the command is running and labelled `unattributed`; that
    default is deliberate, because refusing to count fast readers would make the feature dead
    for exactly the loaders it exists for, and the failure it risks -- an early revert the
    command notices -- is reported, never a leak.
  - At N the placeholders go back **through the held handle** (value-based restore, verified),
    the journal entry is released, and the watch stays armed so a read that arrives *after* the
    revert is reported as `single_read_restored_early` rather than silently seeing placeholders.
  - Checked before the dialog: `max_reads` is refused where opens cannot be observed (Linux for
    now; macOS has no such facility without an Endpoint Security entitlement) and refused per
    file when the filesystem grants no oplock or another process already holds the file -- a
    self-test on the placeholder file proves that a foreign open is *held* until release, the
    property everything rests on. Part of the trust signature; stated in the dialog.
  - Use `1` for `docker run --env-file`, kubectl, `source`, python-dotenv, pydantic-settings,
    Node `--env-file`; `2` for docker compose (interpolation plus `env_file:`); more for a
    harness that starts several loaders. Every mechanism is exercised by
    `tests/test_single_view.py` with real child processes in a real Job against real oplocks --
    the headline test reads the real value, sleeps, reads again while still running, and gets
    the placeholder.

  Not in this release, deferred with reasons in `docs/plan-1.6.1-hardening.md` §WP8: Linux
  (fanotify `FAN_OPEN`, which names the opener natively), a named-pipe `materialize` mode
  (a dotenv loader's `isfile()` check would consume a single-instance pipe), and
  `background=True` + `swap` + `max_reads` (needs a non-killing Job and a status query).

### Changed

- `store.swap_target_file` / `unswap_target_file` are now thin wrappers over pure
  `compute_swap_bytes` / `compute_unswap_bytes` / `verify_unswap_bytes`, so the watcher can
  restore through its own handle with exactly the logic the file-based path uses.
- `procs.run_bound` takes an `on_start(job_handle, pid)` observer so the watcher can attribute
  opens to the command's tree; the handle is only ever queried.

### Fixed (post-push review of 1.7.0)

- A failed early restore (a transient I/O error, a short write) was never retried: the watcher
  kept counting opens but the real values stayed on disk until the command exited. Every later
  counted open now retries until one succeeds; the report carries `restore_attempts` and, if
  none succeeded, `restore_error`, and the end-of-run restore still covers that case.
- When a reader's memory-mapped view blocked the in-handle truncate (`ERROR_USER_MAPPED_FILE`),
  the newline padding `write_all` leaves was never cut. `Watcher.trim_padded_tail()` now runs
  once the handle is released; the report says `mapped_view_tail_trimmed` or, if the file was
  changed meanwhile, `mapped_view_tail_error` with a note in `single_read_note`. The padding
  write itself is now checked like the main one.
- `run_bound` told the watcher the Job handle was gone *after* closing it; the order is now
  notify, then close, so no break processed in between queries a closed handle.

## [1.6.1] — 2026-09-15

### Security

A hostile review of the 1.6.0 posture document (`docs/security-posture-1.6.0.md`) found two
things the swap feature had handed an agent that it did not have before, and a set of ways the
"real values never stay on disk unnoticed" promise could be broken. All are closed here; the
plan and its reasoning are in `docs/plan-1.6.1-hardening.md`.

- **The git probe can no longer execute repo-controlled code.** `run_with_env(swap=...)`
  asks git whether the file is tracked *before* the dialog opens. That ran a bare `git` --
  which Windows resolves through the server's current directory, the open project -- with the
  project's own `.git/config`, where `core.fsmonitor = <program>` runs on every index read. Git
  is now located once at import from `PATH` alone (never the current directory or anything
  under it, `.exe`/`.com` only), invoked by absolute path with its own directory as cwd (no DLL
  search through the project), with system and global config off, hooks pointed at an empty
  directory and `core.fsmonitor` forced off -- both as `-c` arguments and as `GIT_CONFIG_*`
  environment, for git older than 2.31. A `.git` *file* whose `gitdir:` points at a share or a
  device path makes the probe answer "unknown" instead of connecting.
- **Recovery and `swap=` act only on registered, local files.** A path from `swap.journal.json`
  or from a `swap=` argument must be absolute, on a local drive (no UNC, no `\?\`, no mapped
  network drive, no junction to a share) and a key of `targets.json`, with the names a subset
  of that file's registered set -- checked as a string **before** anything on disk is touched,
  because resolving or stat-ing a UNC path opens SMB with the user's credentials. The same
  string check now guards `cwd` and the command's executable on every run. Journal entries that
  fail are quarantined and reported on every call, never acted on and never silently dropped;
  `python mcp_server.py --recover --drop-rejected` clears them from a terminal.
- **A secret re-quoted during the run is restored, not mistaken for a user edit.** The restore
  and the post-restore verification compared against the exact quoted form the vault wrote, so
  a formatter that turned `SECRET="abc"` into `SECRET=abc` made the line look edited (left
  alone, journal released) while verification, comparing the same form, stayed silent. Both now
  compare the *value* -- what a dotenv parser would deliver -- and verification also scans every
  line for the raw value, reporting a copy under another name or in a comment by line number
  (`swap_secret_seen_elsewhere`), never by content.
- **Swap runs are bounded in time and their process tree dies with them.** New `timeout`
  argument (seconds, part of the trust signature, shown in the dialog); swap runs default to
  3600. On Windows the command runs inside a Job object with kill-on-close, so a server that is
  `TerminateProcess`-ed -- how every Windows session actually ends -- takes the whole tree with
  it, a timeout kills descendants too, and a descendant a command leaves behind cannot outlive
  it. Recovery's inference "the owner is dead, rewrite the file" is now safe because a dead
  owner implies a dead command. Plain injection runs are deliberately not bound (a script that
  starts a daemon and exits keeps working). A watchdog ends the tree two seconds after the
  direct child exits, so an orphan holding the output pipe can no longer hang the tool with
  real values on disk. Output is decoded as UTF-8 with replacement, so a child printing
  cp1252-hostile bytes no longer turns a finished run into a `UnicodeDecodeError`.
- **`vault_status` reports real values without trusting the journal.** Every registered file is
  scanned for managed lines that are not placeholders (`targets_holding_non_placeholders`,
  names only) and for `value ?` lines still waiting for a number
  (`targets_with_pending_placeholders`). A crash whose journal was later deleted becomes visible
  on the next status call.
- **`swap` is refused for a git command** (`git add -A` with real values in `.env` is how they
  get committed), and if a swapped file *became* tracked during the run, the result says so
  (`swap_target_committed`) and tells you to rotate. The dialog names a cloud-synced folder
  (OneDrive and every Cloud Filter sync root on Windows, Dropbox/Google Drive/iCloud roots
  everywhere, macOS CloudStorage) and an untracked-and-unignored file, in amber.
- **Recovery with an unreadable vault index no longer clears values into a comment.** The index
  is retried for ~2 s; if it stays unreadable the lines become `NAME="value ?"`, a placeholder
  whose number `resync_targets` fills in once the index is readable -- no hand editing. The same
  marker replaces the comment previously written for a name that had left the vault.
- **The restore can write in place.** On Windows `os.replace` fails while any process holds the
  file open without `FILE_SHARE_DELETE` (every CPython `open()`); a restore that had exhausted
  its retries stayed failed for as long as an orphan kept `.env` open. After the atomic
  attempts, a restore now truncates and rewrites in place -- a torn placeholder line beats an
  intact real one. The swap write itself stays strictly atomic.
- **Smaller:** `python mcp_server.py --recover --force` treats every journal entry as stale (the
  human's exit from an entry whose owner pid exists but cannot be inspected; requires an
  interactive terminal); a `"`-style value ending in a backslash no longer renders as an
  unterminated string; leftover temp files are swept by name regardless of age (FAT/exFAT
  mtime granularity); an own-pid journal entry left by a failed bookkeeping step is cleared on
  the next call; the placeholder regex no longer accepts asymmetric quotes; `preview_swap`
  refuses files over 1 MiB.

### Fixed

- A dialog that raised during construction left a live Tk root behind, so the next dialog
  opened as a modal Toplevel and blocked forever -- a real window on the desktop waiting for a
  click, until the test's timeout killed the process. The dialog-check harness now destroys a
  live root after a failed construction; one broken dialog fails one check.

## [1.6.0] — 2026-09-15

### Added

- **`run_with_env(swap=[...])` — real values in the project's own `.env` for one command.**
  Every mainstream loader lets the process environment win over the file by default, so plain
  injection was already enough for most consumers. Four classes it never reached: loaders with
  override/overload semantics (`load_dotenv(override=True)`, `godotenv.Overload`, tox
  `set_env = file|.env`, `direnv`), shell sourcing (`source .env`, `make include .env`), tools
  hard-wired to the filename (Compose `env_file: .env`, `docker run --env-file .env`,
  `kubectl --from-env-file`, an IDE's `envFile`), and test harnesses that scrub the child
  environment before a loader runs — the case that started this: a suite that builds its
  subprocess environment from an allowlist and parses `.env` from disk could only ever see
  `"value 17"`. `swap` rewrites the placeholder lines of a registered target with the real values,
  runs the foreground command, and restores the file byte-for-byte. Opt-in per call, scoped by
  `only_vars`, refused with `background=True`, disclosed in the dialog (every file, the count of
  values, what is skipped, and an amber line when git tracks the file).

- **The original quoting of every migrated line is recorded** (`target_styles.json`) and
  replayed by `swap`, because there is no quoting every parser agrees on: `docker run
  --env-file`, `kubectl` and `make` keep quote characters literally, every dotenv-family loader
  strips them, and `$` is interpolated by most of them. The form the user's tools were already
  parsing is the only one known to be right. Files migrated earlier fall back to a conservative
  policy and the result says so.

- **A swap journal with process-liveness recovery.** `swap.journal.json` is written before the
  first real byte lands and removed after the restore is verified from disk. If the server dies
  mid-run, or the restore fails after retries, the next tool call in any session — or server
  start, or `python mcp_server.py --recover` — restores the file and reports `swap_recovered`.
  Liveness is pid **plus** process creation time (`GetProcessTimes` on Windows, `/proc` on
  Linux) plus a per-process server id, so a recycled pid never masquerades as a live server; a
  second server is refused a swap on a file another live one has open, and `resync_targets` /
  `install_migrate` skip such files instead of rewriting them.

- **Trust binds the swapped names, and the swapped file is drift-monitored.** `targets.json` is
  agent-writable, so a signature keyed on paths alone would let an 8-hour grant for "swap two
  values" auto-allow "swap twenty" once the registry grew. The names that would actually be
  swapped — computed from the registry, the index and the file's current placeholder lines —
  are part of the signature, and any edit to the file revokes the grant.

- **`docs/env-consumption-research.md`** — the survey behind all of this: six consumption
  mechanisms, per-tool precedence and parsing rules with primary-source citations, and the
  quoting divergence. **`tests/test_consumption_matrix.py`** is its executable form: one real
  child process per mechanism, using the `python-dotenv` and `pydantic-settings` that ship with
  `mcp[cli]`, Node's `--env-file`, and bash. It already earned its keep — it caught the draft
  document's claim that single quotes stop python-dotenv interpolating, which the installed
  1.2.2 source disproves.

### Changed

- The unlock dialog gained a swap section; `unlock_for_run_dialog` takes a keyword-only `swap`
  argument, defaulting to `None`, so existing callers and test wrappers are unaffected.
- `run_with_env` output redaction also masks each value in its as-written form (quoted or
  escaped), so a command that prints the swapped file cannot hand the value back through the
  rendering.
- A launch failure (`could not run …`) now reports a materialize file or restored whole file
  that could not be cleaned up, as a normal exit already did.

### Fixed (pre-release, from the push-time review)

- A swap whose post-restore verification still found a real value on disk released its journal
  entry, so nothing ever retried; it is now flagged `restore_failed` like a failed write. A
  conflict alone (a line the user edited during the run) still releases the entry, because
  recovery would overwrite that edit.
- `install_migrate` and `resync_targets` failed *open* on a corrupted `swap.journal.json` —
  they treated "cannot read the journal" as "nothing is swapped". Both now refuse until it is
  readable, and `vault_status` reports the error.
- A failure to update the journal *after* a successful restore was reported as if real values
  were still on disk. It is now a separate `swap_journal_warning`.

## [1.5.1] — 2026-09-13

### Fixed

- **MCP server now starts when the installed plugin is used in a project other than its own repo.**
  1.4.5 switched `.mcp.json`'s `args` from `${CLAUDE_PLUGIN_ROOT}/plugin_launcher.py` to the bare
  filename `plugin_launcher.py`, reasoning that Claude Code resolves relative paths against the
  directory containing `.mcp.json`. That's false: Claude Code always spawns MCP servers with cwd
  set to whatever project is currently open, never the plugin's own directory and never relative
  to `.mcp.json` itself — confirmed upstream in
  [anthropics/claude-code#17565](https://github.com/anthropics/claude-code/issues/17565), which
  also shows the documented `cwd` field in `.mcp.json` is silently ignored, so it can't be used to
  pin it either. The installed plugin only ever worked by coincidence, when the open project
  happened to be this repo (whose root happens to contain `plugin_launcher.py`); opening any other
  project produced an immediate `FileNotFoundError` in the child process — no traceback visible
  anywhere a user would look, just `CONNECTION_CLOSED` from the client. Fixed by routing through
  `python -c "..."`, which resolves the launcher via `CLAUDE_PLUGIN_ROOT` when set (the
  installed-plugin case, regardless of which project is open) and falls back to the bare filename
  against cwd when it isn't (the project-level dev case, where cwd is the repo root either way).

## [1.5.0] — 2026-08-21

### Added

- **Whole-file encryption.** `encrypt_file(path)` moves any file — a certificate, a private key, a
  kubeconfig, a service-account JSON, a `.p12` bundle — into the vault under the same master
  password. `certs/server.pem` becomes `certs/server.pem.levault` beside it and the original is
  destroyed once the encrypted copy has been written and verified. Granularity is deliberately the
  whole file rather than per-variable: these are opaque blobs, and one unlock should return the
  whole thing. The `.levault` is pure ciphertext and is meant to be committed.

  `decrypt_file(vault_path, output_path=None)` restores one permanently. `run_with_env(...,
  files=[...])` restores them only for the lifetime of one command and deletes them when it exits.
  `vault_status()` lists every encrypted file by path, original name, size and date — never
  contents.

- **A file master key that survives credential changes.** Every credential operation rotates the
  DEK, so file ciphertext could not ride on it: one password change would have orphaned every
  `.levault`, including ones already pushed to a remote where they cannot be re-encrypted. Instead a
  32-byte file master key lives *inside* the encrypted body, which `change_password`,
  `reissue_recovery_key` and `recover_with_recovery_key` all carry through verbatim. A file
  encrypted a year ago opens after any number of password changes, and the recovery key reaches it
  too. An old password cannot, because it can no longer open the vault to reach the key.

- **`LEVFILE` envelope format,** domain-separated from the vault's own `LEVAULT` magic. AES-256-GCM
  with the header bytes as AAD; a random per-file key wrapped under HKDF-SHA256(file master key,
  salt, file id), which binds the wrapped key to that one file so it cannot be transplanted to
  another. The original filename and permissions live *inside* the ciphertext, not the header — a
  `.levault` is designed to be pushed to a public repo, and a header-embedded `aws-root-key.pem`
  would be a permanent leak the user cannot rename away. The in-ciphertext name is never used to
  construct a filesystem path, which removes the entire path-traversal class rather than sanitising
  it. Files are capped at 16 MiB: `AESGCM` is one-shot, and a correct segmented AEAD is the most
  bug-prone code this feature could have contained for artifacts that are almost always under
  100 KiB.

- **File key rotation,** as two `manage_vault` actions. Changing the master password deliberately
  does not change the file key — that is what makes a committed `.levault` durable — so a leaked
  file key needs its own answer. **Rotate Encrypted-File Key** mints a new generation and
  re-encrypts every file this machine can find; files it cannot reach are reported and keep working,
  because the old key is retained. **Retire Old File Keys** deletes the old generations, and is
  refused unless every registered file is verified as already rotated. That precondition reads each
  file's *envelope header*, not `files.json`, so restoring an older `.levault` from git history
  cannot trick it into destroying the only key that opens it.

- **Git-awareness warnings.** `encrypt_file` reports when the plaintext was tracked by git —
  encrypting it now protects nothing if it is already in history, which needs `git filter-repo` and
  a credential rotation. `decrypt_file` reports when the restored path is not covered by a
  `.gitignore` rule.

### Changed

- `load_secrets`/`load_secrets_ex` now return user variables only, and `save_secrets` re-reads the
  on-disk body and merges vault-internal keys back in. Every existing call site is correct with no
  edits; raw access lives behind the deliberately unlovely `load_vault_body`/`save_vault_body`. The
  hazard this closes is not a leak but a deletion: every mutation here is load → mutate → save, and
  a single site saving a variables-only dict would have silently deleted the file master key,
  surfacing weeks later on a file whose plaintext was already destroyed. `save_secrets` now raises
  rather than accepting an internal key, so the mistake fails loudly instead of half-working.

- `run_with_env` gained `files`, which is part of the trust signature but never trusted: a run that
  decrypts files is never auto-allowed and never grants trust, and the checkbox is not offered.
  An unattended 8-hour grant to inject a token into an environment is a different thing from one to
  write a private key into a directory, and the feature was designed for the first. It is also
  refused outright with `background=True` — a detached process has no reliable moment at which a
  decrypted key could be cleaned up.

- Every read-modify-write of `vault.enc` now holds a lock file, `save_secrets` included. The
  `expect_fingerprint` compare-and-swap compares and *then* replaces with nothing in between, and
  what sits in between is a full scrypt derivation (~100 ms) — a TOCTOU window wide enough to drive
  a truck through. Two Claude Code sessions are two server processes: one could mint a file key
  while the other was mid-`save_secrets`, and the stale body would overwrite it. Since
  `encrypt_file` had already destroyed the plaintext by then, every file under that key became
  permanently unopenable, silently. A safety audit reproduced this before release. The lock is
  re-entrant per thread, because the operations that need it naturally nest. The compare-and-swap
  is kept as a second layer, `encrypt_file` re-checks that its key generation is still on disk
  before destroying anything, and `rotate_file_key` re-checks after its walk rather than reporting
  a success it cannot back up.

- The four credential operations (`change_password`, `upgrade_to_v2`, `reissue_recovery_key`,
  `recover_with_recovery_key`) hold the vault lock too. An earlier version of this work exempted
  them, on the reasoning that they carry the body plaintext through verbatim rather than
  reconstructing it. Carrying it verbatim is precisely the hazard: they read the body, spend ~250 ms
  in two scrypt derivations and a backup write, then write that stale plaintext back — erasing a
  file key another session minted in between exactly as `save_secrets` did. A follow-up audit pass
  destroyed a private key through `change_password` this way, after the first fix had landed.
  Backup-and-rollback does not help, because nothing fails: the credential change succeeds and the
  loss is silent.

- The `#fmk` record tracks **which files** are sealed under each key generation — a list of the
  `file_id`s baked into each envelope, not a count. `retire_file_keys` refuses while any are
  outstanding. This is the only guard here that is machine-independent: every other check is scoped
  to paths `files.json` names, so a `.levault` in a directory this vault was never told about —
  pulled from git on a second machine — was invisible to all of them.

  Identities rather than counts, because a count can be driven wrong in three ways that a set
  cannot, all found by the audit after the counting version was written: two registry entries
  pointing at copies of one envelope decremented it twice while one file moved; a crash-then-resume
  incremented it twice and stranded the user permanently; and a resumed encryption credited the
  active generation instead of the one that actually sealed the file. Removals are idempotent and
  the identity is bound into both the wrapped-DEK AAD and the body AAD, so it cannot be forged
  without the file key. The record's storage travels inside `vault.enc` and no agent can edit it,
  though its inputs still come from disk — a strong backstop, not an oracle.

- Retiring keys that files still depend on now opens a confirmation listing each file by name and
  requiring an explicit tick before abandoning it. Refusing forever is its own failure mode: one
  interrupted encryption could otherwise leave a user unable to retire a key they believe is
  compromised, with no way to discover what was blocking it. Only the identities shown are waived,
  so this names what is being destroyed instead of acting as a blanket override.

- `retire_file_keys` — the one irreversible operation here — now refuses when it cannot account for
  what the old keys protect: an empty registry, or a `.levault` sitting beside a registered one that
  `files.json` has no record of. Its per-file generation check already read envelope headers rather
  than the registry, but every check was *scoped* to the paths the registry named, so an absent
  `files.json` silently removed the safety net entirely. That state needs no adversary — copying
  `vault.enc` to a second machine to open files pulled from git produces it.

- `encrypt_file` re-verifies the plaintext immediately before destroying it (hash, symlink and
  hard-link re-check). Two hundred milliseconds elapse between reading the file and deleting it, and
  it used to delete whatever was at that path by then — losing an editor's autosave, or shredding
  whatever a swapped-in hard link pointed at.

- "Could not delete the original" now distinguishes overwritten-but-not-unlinked from
  untouched. The old message told the user a random-byte husk "still contains the real secret",
  which pointed them at deleting the `.levault` — by then the only copy.

### Fixed

- The dialog test harness now destroys its Tk root unconditionally. A failure while driving a
  dialog previously left a live root behind, which both leaked a real modal window onto the user's
  screen with nothing able to answer it, and caused the next harness call to bypass the auto-closing
  root entirely (`_new_window()` returns a `Toplevel` when a root is already alive).

## [1.4.6] — 2026-08-20

### Fixed

- **Vault tools now appear in Claude Code sessions on Windows.**
  `os.execv` on Windows (implemented via MSVCRT `_execv`) creates a new process but does not
  correctly transfer inherited pipe handles from a Node.js parent (Claude Code's CLI is a Node.js
  process using libuv/IOCP for I/O). The result: `mcp_server.py` starts but its stdin/stdout are
  disconnected from Claude Code, so no MCP response ever arrives and the client times out after
  30 s. Fixed by using `subprocess.call` on Windows instead, which uses Python's own
  `CreateProcess` call and correctly inherits the Windows pipe handles. POSIX platforms continue
  to use `os.execv` (a true process replacement with zero overhead).

## [1.4.5] — 2026-08-20

### Fixed

- **MCP server now starts when working inside the plugin's own repository.**
  The project-level `.mcp.json` used `${CLAUDE_PLUGIN_ROOT}/plugin_launcher.py` in its args.
  Claude Code only substitutes `${CLAUDE_PLUGIN_ROOT}` when starting the server as an *installed
  plugin*; when it reads the same file as a project-level MCP config (i.e. when the repo is your
  working directory), the literal string is passed to Python, which exits immediately with "no
  such file or directory." The fix: use the bare filename `plugin_launcher.py` — Claude Code
  resolves it relative to the directory containing `.mcp.json`, which is the repo root in the
  project context and the version-cached directory in the installed-plugin context. Both are
  correct.

## [1.4.4] — 2026-08-20

### Fixed

- **`uv venv` now always uses the same Python as the launcher itself.**
  Both `uv venv` calls introduced in 1.4.3 omitted `--python sys.executable`,
  letting `uv` fall back to its own interpreter-discovery order (PATH / `.python-version` /
  uv-managed toolchains). That could produce a venv built from a different Python than
  `plugin_launcher.py` is running under, breaking the `_venv_is_functional` check and
  `python -m pip` fallback which both assume `sys.executable` built the venv.
  Fixed by passing `--python sys.executable` to every `uv venv` invocation.

## [1.4.3] — 2026-08-20

### Fixed

- **First-run provisioning no longer times out under MCP startup constraints.**
  On a clean install, `pip install` of the plugin's 39 dependencies took long
  enough that Claude Code's MCP server startup timeout would kill the launcher
  partway through. Each restart began provisioning from zero and was killed
  again — a self-reinforcing failure with no visible error. The fix: use `uv`
  for both venv creation (`uv venv --seed`) and package installation
  (`uv pip install --python <venv>`), falling back to `python -m venv` /
  `python -m pip install` if `uv` is not on PATH. `uv` is 10–50× faster than
  pip on a cold cache, which keeps total provisioning time well within the
  startup timeout.

## [1.4.2] — 2026-08-20

### Fixed

- **Windows: venv rebuild no longer fails with WinError 32 when the old server is still running.**
  `claude plugin update` during a live session triggered a venv rebuild. On Windows, `python -m
  venv --clear` deletes old site-package files one by one; if the previous server process still
  held any of them open, each `DeleteFile` call failed with "The process cannot access the file
  because it is being used by another process," leaving the venv half-destroyed and the server
  unable to start. The fix builds the replacement venv in a sibling directory (`venv-next`) and
  then renames the old venv aside (`venv-old`) before renaming the new one into place. A directory
  rename moves only the filesystem entry — it never touches individual files — so it succeeds even
  with open handles. The orphaned `venv-old` is removed best-effort afterward; if the old server
  is still holding files at that point, the removal silently skips and the directory is cleaned up
  on the next update.

## [1.4.1] — 2026-08-17

Follow-up to 1.4.0 from hands-on use: the executable-only trust warning fired on almost every
command, and a warning nobody reads is a warning that is not there.

### Added

- **Implicit config files are now drift-monitored.** Tools that read configuration from the working
  directory without naming it on the command line — `docker`/`docker compose` (compose files,
  `.env`, `Dockerfile`), `make` (`Makefile`), `npm`/`pnpm`/`yarn` (`package.json`), `cargo`, `go`,
  `terraform`, `pytest`, `poetry`, `gradle`, `mvn` and others — have those files hashed alongside
  the executable. Editing one now revokes trust. This closes the B1 gap itself rather than only
  reporting it: previously `docker compose up` monitored the `docker` binary and nothing else, so
  the file that decides what the command actually does could be rewritten under a live grant.

### Changed

- **The amber "only the executable is monitored" warning is now reserved for cases that warrant
  it.** Executable-only coverage is unremarkable for `ls`, `git push` or `python -c "..."` — none
  read project configuration, so there is nothing a human could wrongly believe is protected.
  Alarming on all of them trains people to dismiss the warning, and then it is gone for the one
  case it exists for. It now fires only when a tool known to read config is run with no config file
  found to monitor, which means either the command is running somewhere unexpected or its config
  lives somewhere not covered. **The grant note still enumerates exactly what is monitored for
  every command** — quieting the alarm does not cost accuracy, only volume.

Honest limit: a custom tool with its own config file gets no amber warning, because it cannot be
recognised. That is the price of not crying wolf, and why the enumeration stays unconditional.

## [1.4.0] — 2026-08-16

**Vault format change.** v2 is the format for all new vaults. Existing v1 vaults keep working
unchanged until the human opts into an upgrade via `manage_vault`.

### Added

- **Versioned vault format (v2).** `vault.enc` gains a structured header:
  `magic || version || hdr_len || header-JSON || nonce || body`. The header bytes as read from disk
  are the body's AES-256-GCM **AAD**, binding format metadata to the ciphertext — tamper with any
  header field and the body fails to authenticate before decryption is attempted.
- **AES-256-GCM replaces Fernet for v2.** Fernet has no AAD slot, and a bolt-on HMAC could only be
  checked after unwrapping — too late to protect the header that says how to unwrap. v1 vaults keep
  the original Fernet path, frozen and byte-identical.
- **scrypt for new vaults** (`n=2**16, r=8, p=1`, 64 MiB, ~114 ms on modern hardware). One notch
  below OWASP's recommendation to stay clear of low-memory failure modes on interactive unlock.
  Against a GPU rig this buys roughly one to two orders of magnitude over PBKDF2-480k — meaningful,
  but worth less than a strong password.
- **Envelope encryption.** A random data key (DEK) encrypts the vault body and is wrapped once per
  credential — master password and recovery key can both open one vault without storing the body
  twice. Every credential change rotates the DEK: a copied vault is ciphertext locked to the moment
  of the copy and does not become an oracle for future bodies.
- **Paper recovery key (opt-in).** 160 bits of entropy, Crockford base32, shown as `RK1` plus 8
  groups of 4 characters and a 4-character checksum, with a 4-character slot id so a stale printout
  is identifiable. Displayed only in a native dialog with no copy, save, or print control; the setup
  ceremony requires re-entering the full key from paper before it is accepted. **Changing the master
  password issues a new recovery key and invalidates the old printout.**
- **`manage_vault()` tool.** Change master password, set up or reissue a recovery key, or upgrade a
  v1 vault to v2. Each sub-operation opens its own consent dialog.
- **`recover_vault()` tool.** The only entry point that does not require the master password — enter
  the paper recovery key, set a new password, and access is restored. The printout keeps working:
  the data key is rotated, but the recovery slot is re-wrapped with the same key the human just
  supplied — the one credential operation that can do this, because it alone has the key in hand.
  `change_password` cannot, which is why that one does issue a replacement.
- **`vault_status()` additions:** `format_version`, and a non-secret `recovery_key` object
  (`present`, `id`, `created`) when a recovery key is configured. `vault_id` is not exposed — it
  would be a stable fingerprint correlating vault copies, with no agent use case.
- **KDF parameter validation.** Parameters embedded in the v2 header are range-checked before use;
  a hostile `n` is rejected rather than allowed to exhaust memory (ceiling: 256 MiB).
- **`vault.enc.bak`** is written before every credential change and deleted once read-back
  verification passes. Now gitignored.

### Changed

- **Common-password blocklist.** Roughly 220 of the most-guessed passwords and infrastructure
  defaults — `password`, `123456`, `qwerty`, `admin`, `root`, `changeme`, `docker`, `postgres`,
  `vault` — are refused at any length, compared case-insensitively. This is the compensating
  control for the lower length floor below: length and dictionary rank are separate axes, and a
  top-of-wordlist password is opened in a handful of guesses however expensive the KDF is. It is
  deliberately not a strength meter — no complexity rules, no scoring, no nagging.
- **Master-password minimum lowered from 12 characters to 5.** A deliberate product decision
  favouring memorability. The adversary this tool is built against is an AI agent, which can
  neither see nor drive the native dialog and therefore cannot attack the password at all — every
  attempt is simply an error — while a password the human cannot remember is a certain, permanent
  loss of the vault. The trade-off is explicit and holds only while `vault.enc` stays on the
  machine: a copy taken off it is attacked offline, where a short user-chosen password falls to a
  wordlist in seconds regardless of the KDF. If offline attack is in your threat model, choose a
  long passphrase of your own. Existing vaults are unaffected; the floor applies only at creation
  and password change.
- **The "Generate passphrase" button was removed.** It filled the two masked password fields, so
  the value it produced was never visible to the person who had to remember it — a generator whose
  output you cannot read is a data-loss trap, not a convenience.
- **`cryptography` floor raised to `>=42`.** Older OpenSSL builds defaulted scrypt's `maxmem` to
  32 MiB; the v2 KDF asks for 64 MiB, so an older pin fails at runtime on some installs.

### Fixed

- Stale README claim: "a paper recovery key is planned for 1.4.0" — it shipped.

## [1.3.0] — 2026-08-15

Security hardening pass. No change to the vault format, the crypto, or the consent model —
an existing vault is read by this version unchanged.

### Added

- **`change_password` tool and dialog.** Rotates the master password: re-derives a new key from
  a fresh salt, re-encrypts the vault, and writes both `vault.enc` and `vault.salt` atomically.
  Honest limit: rotation protects secrets stored *after* the change. Anyone who copied `vault.enc`
  and `vault.salt` before the change, and who later learns the old password, can still decrypt
  that earlier snapshot.
- **Output redaction in `run_with_env`.** Secret values injected into a command's environment are
  now redacted to `[REDACTED:VAR_NAME]` in the result returned to the AI — the exact value, its
  base64 encoding, and its URL encoding are all matched. The unlock dialog now discloses that
  output goes back to the AI. Honest limits: redaction is accident-prevention, not adversarial
  defence. A command line chosen by the agent can transform output (gzip, chunk, re-encode) in
  ways that defeat string matching. Two paths are explicitly not covered: a `background=True`
  run's temp log file is only redacted after the process exits (it is unredacted while the process
  is still running), and a `materialize` target is real values on disk by design.
- **Trusted-command TTL.** Trust grants now expire after 8 hours (absolute wall-clock time, also
  verified against monotonic clock so neither a suspend nor a clock change extends them).
- **Scrollable variable list in the unlock dialog.** The "will expose N variables" list is now a
  scrollable box instead of being truncated at 300 characters with an ellipsis.
- **Variable-name length cap.** Variable names are capped at 128 characters, preventing an
  absurdly long name from pushing the Allow/Deny buttons off the non-resizable dialog.
- **Password floor raised to 12 characters**, with a generated 4-word passphrase offered at vault
  creation. Applies at `create` and `change_password`; existing vaults are unaffected.

### Changed

- **Trusted-command "session-only" framing replaced with an explicit TTL.** The trust-grant note
  now says "8 hours" rather than "rest of this session". The MCP server process can live for days
  across many conversations in one Claude Code Desktop window, which made "session" misleading.
- **Trust-grant note now accurately enumerates what is monitored.** For a command like
  `docker compose up`, no config file appears on the command line, so only the resolved executable
  is hashed. The note warns explicitly when the monitored set is executable-only.
- **argv0 drift-detection no longer searches the working directory on macOS/Linux**, where `exec`
  itself does not search the working directory.
- **Dialog text sanitizers** now strip Unicode `Cf`-category characters (zero-width joiners and
  bidi directional controls) and C0/C1 control characters in addition to the previous checks.

### Fixed

- **`run_with_env` no longer returns the full vault to its caller when `only_vars` is given.**
  The unlock dialog now scopes the decrypted values it passes back to the `only_vars` set before
  returning; the rest of the vault is not present in the returned structure.

## [1.2.0] — 2026-08-14

Release-readiness pass. No change to the vault format, the crypto, or the consent model — an
existing vault is read by this version unchanged.

### Added

- Two slash commands. `/llm-env-vault:protect` discovers every `.env` in a project and walks each
  one through `install_migrate`; its `allowed-tools` deliberately excludes every file-reading tool,
  so the discovery path cannot pull a live credential into context. `/llm-env-vault:doctor`
  diagnoses a server that failed to start — the one case no tool can report on, since a failed
  start removes every tool.
- Standing agent policy is now passed to `FastMCP` as an `instructions` string, so it applies
  unconditionally to every connecting client instead of depending on documentation being read.
- A Troubleshooting section and a Commands section in the README.
- `CHANGELOG.md` and a minimal `pyproject.toml` (pytest config only — this is not a packaged
  distribution).
- `license: MIT` declared in both manifests. It was already in `LICENSE`, just undeclared.

### Changed

- **Windows is now stated as the tested and supported platform**, in the plugin description, the
  installation section, and Known limitations. This is documentation catching up with reality:
  `.mcp.json` launches a bare `python`, which many macOS and Linux systems don't provide, and the
  hash-pinned lockfile was already Windows-only.
- Tests moved from the repo root into `tests/`, so the plugin's installed directory contains only
  the files the server actually loads.

### Fixed

- **Bytecode is no longer written into the plugin install directory.** `mcp_server.py` now sets
  `sys.dont_write_bytecode` before importing `vault_lib`, which previously dropped a
  `__pycache__` into the version-scoped directory the plugin manager owns and treats as immutable.
- `llm.env` is no longer tracked in git. Plugin installs are clones and ignore `.gitignore`, so a
  tracked copy shipped one developer's variable names to every user.
- Three stale claims in the README: the test count (said 32, actually 66), the scope of
  `test_install_migrate_robustness.py` (said "4 OSError tests", actually also covers the resync
  mass-removal guard and credential redaction), and background run logs (said "never
  auto-deleted", actually reaped after 7 days).
- Documented that non-Windows installs get **unpinned, unverified** dependencies — the security
  cost of the Windows-only lockfile, previously mentioned only in a lockfile header comment.

## [1.1.0] — 2026-08-14

- Diagnosed and hardened the real cause of the "MCP not connected" failures found in two red-team
  rounds: venv provisioning interrupted by the client's MCP startup timeout, leaving a half-built
  venv that never recovered.
- Provisioning now logs why every attempt is happening, not just interrupted ones, and detects a
  functional-but-stale venv separately from a corrupt one.
- Hash-pinned `requirements-lock.txt` with `pip install --require-hashes` on Windows, and the
  reinstall trigger re-keyed onto `CLAUDE_PLUGIN_ROOT`'s path so editing `requirements.txt` alone
  no longer triggers an install.
- Vault storage moved out of the version-scoped plugin cache into `${CLAUDE_PLUGIN_DATA}/vault`,
  which survives `claude plugin update`, with a guard that refuses to create a vault in a
  plugin-cache layout if that variable is missing.
- `vault.enc` ciphertext length coarsened so the file size stops leaking secret sizes; stale
  background-run logs cleaned up.
- `resync_targets` now refuses a single call that would wipe every managed line at once.

## [1.0.0] — 2026-08-13

- Packaged as a real Claude Code plugin: `.claude-plugin/plugin.json`, a single-plugin
  `marketplace.json`, and `.mcp.json` wiring `plugin_launcher.py`, which provisions its own venv
  because Claude Code auto-installs Node dependencies but has no Python equivalent.
- Trusted-command auto-allow for `run_with_env`, in-memory and session-only, keyed to the exact
  command shape and to SHA-256 hashes of every referenced file, revoked silently on drift.
- Dark-themed consent dialogs.
- MIT license, README.

### Earlier

Pre-1.0.0 history is a long series of security fixes found by repeated red-team and review passes
— targets.json write races, `materialize` path-traversal containment, TOCTOU gaps, redaction of
credential-shaped text in parse warnings, consent before registering unowned targets, and honest
reporting of partial writes. See `git log` for the full sequence.

[1.5.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.5.0
[1.4.6]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.6
[1.4.5]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.5
[1.4.4]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.4
[1.4.3]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.3
[1.4.2]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.2
[1.4.1]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.1
[1.4.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.0
[1.3.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.3.0
[1.2.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.2.0
[1.1.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.1.0
[1.0.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.0.0
