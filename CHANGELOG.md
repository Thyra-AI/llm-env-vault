# Changelog

All notable changes to llm-env-vault are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note that
`master` is the release channel: the marketplace entry uses a `"./"` source, which tracks the
default branch rather than a tag, so tags here are for reference and rollback rather than for
pinning what a user installs.

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

[1.2.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.2.0
[1.1.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.1.0
[1.0.0]: https://github.com/Thyra-AI/llm-env-vault/releases/tag/v1.0.0
