# Changelog

All notable changes to llm-env-vault are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note that
`master` is the release channel: the marketplace entry uses a `"./"` source, which tracks the
default branch rather than a tag, so tags here are for reference and rollback rather than for
pinning what a user installs.

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

[1.4.1]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.1
[1.4.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.4.0
[1.3.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.3.0
[1.2.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.2.0
[1.1.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.1.0
[1.0.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.0.0
