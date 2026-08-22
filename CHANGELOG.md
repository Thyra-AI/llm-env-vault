# Changelog

All notable changes to llm-env-vault are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note that
`master` is the release channel: the marketplace entry uses a `"./"` source, which tracks the
default branch rather than a tag, so tags here are for reference and rollback rather than for
pinning what a user installs.

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
