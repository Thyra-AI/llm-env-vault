# Changelog

All notable changes to llm-env-vault are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note that
`master` is the release channel: the marketplace entry uses a `"./"` source, which tracks the
default branch rather than a tag, so tags here are for reference and rollback rather than for
pinning what a user installs.

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

[1.3.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.3.0
[1.2.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.2.0
[1.1.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.1.0
[1.0.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.0.0
