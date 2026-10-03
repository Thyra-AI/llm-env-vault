# Privacy

llm-env-vault is a local tool. This document says what it stores, where, and what leaves your
machine. It describes the plugin's own code; it was checked against the source.

## Short version

- Your secrets and your master password are **never transmitted anywhere** by this plugin.
- The authors **collect no data**: no telemetry, analytics, crash reports, usage statistics, or
  update checks. There is no server operated by the authors for the plugin to talk to.
- The one network use is installing the plugin's Python dependencies from PyPI on first run (see
  below).

## What is stored, and where

| Data | Location | Notes |
|---|---|---|
| Encrypted vault (`vault.enc`, `vault.salt`, recovery slot if you opt in) | `${CLAUDE_PLUGIN_DATA}/vault` (plugin install) or the repo directory (manual setup) | Real secret values exist on disk only in encrypted form. |
| Placeholder index and bookkeeping (`llm.env`, `vault_index.json`, `targets.json`, `files.json`, `target_styles.json`, `placeholder_shapes.json`) | Same directory | Variable names, placeholder numbers and types, and local file paths. No secret values. |
| Python virtualenv, `provision.log` | `${CLAUDE_PLUGIN_DATA}` | The log holds the output of the dependency install. |
| Background-run logs (`llm-env-vault-run-*.log`) | OS temp directory | Output of commands you approved with `background=True`. Real values are redacted when the process exits; stale logs are deleted automatically. |
| `.levault` files | Next to the file you encrypted, in your project | Ciphertext. |

Held in memory only, never written to disk: the master password (for the duration of one dialog)
and the 8-hour "trusted command" cache.

Your `.env` files are read and rewritten only for the paths you explicitly migrate, and only after
you click Allow in a native dialog.

## What the AI assistant sees

The assistant sees variable **names**, placeholder values (`value 3`, or a type-shaped stand-in),
and the output of commands you run through the vault with real values replaced by
`[REDACTED:NAME]` on a best-effort basis (see the README's Security notes for its limits). It
never sees the master password or the recovery key; both are entered and shown only in native
dialogs. What your assistant's own provider does with the conversation is governed by that
provider's policy, not this plugin.

## Network access

- **Dependency install (first run, and after a plugin update).** `plugin_launcher.py` installs
  `cryptography` and `mcp[cli]`, and their dependencies, from PyPI using `pip` (or `uv`, if on
  your `PATH`). PyPI and your network see an ordinary package download from your IP address; on
  Windows the packages are verified against the hashes in `requirements-lock.txt`. Nothing about
  your vault or your project is sent.
- **Commands you approve.** A command you allow through `run_with_env` runs with whatever network
  access your machine gives it. That is your command, not this plugin.
- Nothing else. The plugin's code contains no HTTP, socket, or URL-fetching calls.

## Third parties

The plugin shares data with no third party. Claude Code itself, and PyPI as described above, are
separate services with their own policies.

## Deleting your data

Uninstalling the plugin and deleting `${CLAUDE_PLUGIN_DATA}` removes the vault, the virtualenv and
the logs. `.levault` files and any migrated `.env` files live in your projects and are yours to
decrypt or delete. **Decrypt or back up anything you still need first: without the master
password (or recovery key) the vault cannot be recovered by anyone, including the authors.**

## Changes and contact

Changes to this policy are recorded in [CHANGELOG.md](CHANGELOG.md). Questions: open an issue at
<https://github.com/Thyra-AI/llm-env-vault/issues>.
