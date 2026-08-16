# llm-env-vault

**Keep your real `.env` secrets out of your AI coding agent's reach — without breaking your workflow.**

llm-env-vault is an MCP server that replaces the secret values in your `.env` files with harmless numbered placeholders, stores the real values in a password-encrypted local vault, and lets you run real commands with real secrets injected — each time gated by a native GUI password prompt that only *you* can answer.

Your AI agent sees `DATABASE_URL="value 3"`. Your app, when you deliberately run it through the vault, sees the real thing.

---

## Why this exists

AI coding agents (Claude Code, Cursor, and friends) routinely read your project files — including `.env`. Every API key, database password, and token in those files ends up in the model's context, in transcripts, possibly in logs. Telling the agent "don't read `.env`" is a suggestion, not a control.

llm-env-vault takes a different approach: **the real values simply aren't in any file the agent can read.** The files it *can* read contain only placeholders. Real values live in an encrypted vault (`vault.enc`) that can only be opened by typing your master password into a GUI dialog — a dialog the agent cannot see or type into.

### What is MCP?

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/) is an open standard that lets AI assistants call external tools. An MCP *server* is a small local program that exposes tools; the assistant can invoke them, but only through the tool interface. llm-env-vault is an MCP server: the agent can *request* things like "run this command with secrets injected," but the human-facing password dialog is what actually authorizes it.

---

## How it works

```
your-project/.env          →  install_migrate  →   placeholders only
                                                        │
                              vault.enc  ←──────  real values (encrypted)
                                                        │
run_with_env(["docker", "compose", "up"])  →  GUI password prompt  →  real env vars injected
```

The vault lives as a small set of files, in one of two places depending on how you installed: for a **manual setup**, next to this repo; for the **Claude Code plugin**, under `${CLAUDE_PLUGIN_DATA}/vault` — the one directory Claude Code documents as surviving `claude plugin update` (the same directory `plugin_launcher.py` already uses for its venv). This matters: a version-scoped plugin install directory does *not* survive an update, so the vault deliberately never lives there.

| File | Contains | Safe to commit? | Agent may read? |
|---|---|---|---|
| `llm.env` | `VAR_NAME="value N"` placeholders, auto-generated | No secrets — but gitignored here, see below | Yes |
| `vault_index.json` | `VAR_NAME → placeholder number` map (no secrets) | No secrets — but gitignored here, see below | Yes |
| `vault.enc` | Encrypted vault (v1: Fernet; v2: AES-256-GCM with a versioned header) | No (gitignored) | **No** |
| `vault.enc.bak` | Pre-change backup, deleted once read-back verification passes | No (gitignored) | **No** |
| `vault.salt` | 16-byte KDF salt (kept after a v2 upgrade — deleting it bricks v1 backups) | No (gitignored) | **No** |
| `targets.json` | Paths of migrated `.env` files | No (gitignored — machine-local paths, not secret) | No |

`llm.env` and `vault_index.json` contain no secrets, and a migrated project's own placeholder-only
`.env` is genuinely safe (and often useful) to commit — it documents which variables the project
needs. **This repo** gitignores its own copies anyway, because here they are generated artifacts of
whichever vault happens to be local: committing them would ship one developer's variable names to
everyone who installs the plugin.

Key properties:

- **The master password never touches disk.** It's never a CLI argument, never an env var, and only lives in the GUI dialog's memory for the duration of one prompt.
- **Encryption (v2):** scrypt (`n=2**16, r=8, p=1`, 64 MiB) for key derivation; AES-256-GCM for the
  body with the on-disk header bytes as AAD — any header change fails authentication before decryption.
  v1 vaults keep PBKDF2-HMAC-SHA256 (480,000 iterations) and Fernet (AES-128-CBC + HMAC) unchanged.
- **Envelope encryption (v2):** a random data key (DEK) encrypts the body and is wrapped once per
  credential — master password and optional recovery key can both open one vault without storing the
  body twice. Every credential change rotates the DEK.
- **All vault file writes are atomic** (temp file + fsync + atomic replace) — a crash or power loss mid-write can't leave a corrupted file.
- **Nothing happens silently.** Every operation that touches a real value opens a dialog showing exactly what will change, and nothing is written until you click Allow.

---

## Installation

### As a Claude Code plugin (recommended)

The repo is a real Claude Code plugin and doubles as its own single-plugin marketplace. Inside Claude Code:

```
/plugin marketplace add Thyra-AI/llm-env-vault
/plugin install llm-env-vault@llm-env-vault
```

Or non-interactively:

```bash
claude plugin marketplace add Thyra-AI/llm-env-vault
claude plugin install llm-env-vault@llm-env-vault --scope user
```

`--scope user` (the default) makes it available in **every** project you open — which is the point, since it protects other projects' `.env` files, not just this repo's.

**Platform support: Windows is the tested and supported platform.** That's where the test suite runs and the only platform where dependencies install from the hash-pinned lockfile. The plugin's `.mcp.json` launches the launcher with a bare `python`, so on macOS and Linux you need a **`python`** on your PATH — `python3` alone is not enough, and if that's all you have the server fails to start with an unhelpful "MCP server not connected". Everything else is cross-platform (the dialogs are stdlib Tkinter), but treat non-Windows as untested. `/llm-env-vault:doctor` diagnoses exactly this case.

**Restart Claude Code Desktop (CCD) after installing.** A running CCD session doesn't pick up newly-registered MCP servers automatically — restart CCD (or reload the window) after `/plugin install`, or `llm-env-vault`'s tools won't show up as available yet.

**First run is slower on purpose:** Claude Code auto-installs Node.js plugin dependencies but has no equivalent for Python, so the plugin ships a launcher (`plugin_launcher.py`) that, on first run, creates a venv in the plugin's persistent data directory (`${CLAUDE_PLUGIN_DATA}`, survives updates), installs dependencies into it (from `requirements-lock.txt` on Windows — hash-pinned via `pip install --require-hashes` — or `requirements.txt` elsewhere), and then execs the real server from that venv. A stamp file means it only reinstalls when the plugin is actually updated (a new version-scoped install directory) — every subsequent run is instant, and a plain local edit to the requirements file doesn't trigger anything on its own. The only prerequisite is a `python` on your PATH — see the platform note above, since on macOS/Linux that specifically means `python` and not just `python3`.

Update / remove like any plugin:

```bash
claude plugin update llm-env-vault@llm-env-vault
claude plugin uninstall llm-env-vault@llm-env-vault
```

### Manual setup

For working on this repo itself, or for an MCP client without plugin support:

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

Then point your MCP client's standard `mcpServers` config at the venv's Python running `mcp_server.py`:

```json
{
  "mcpServers": {
    "llm-env-vault": {
      "command": "C:\\path\\to\\llm-env-vault\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\llm-env-vault\\mcp_server.py"]
    }
  }
}
```

For Claude Code specifically:

```bash
claude mcp add llm-env-vault --scope user -- "C:\path\to\llm-env-vault\.venv\Scripts\python.exe" "C:\path\to\llm-env-vault\mcp_server.py"
```

You can also run it directly with no client for local testing: `python mcp_server.py`.

---

## Quick start

1. **Migrate an existing project:** ask your agent to call `install_migrate` on the project's `.env`. A dialog shows exactly which variable *names* will move (never values); on Allow, real values go into the vault and the file is rewritten with placeholders in place.
2. **Add a one-off secret:** `add_secret("STRIPE_KEY")` — you type the real value into the GUI, never into chat.
3. **Run your app for real:** `run_with_env(command=["python", "manage.py", "runserver"])` — password prompt, then the command runs with real values in its environment.

---

## Tools

All GUI dialogs run synchronously on the server's main thread by design (Tkinter isn't safe off its owning thread), so only one dialog/tool call is in flight at a time — fine for the single-agent, one-call-at-a-time usage this is built for.

### `vault_status()`

No password, no GUI. Returns what the vault knows: whether it exists, the managed variable names and
their placeholder numbers, the path to `llm.env`, and which external files are registered as sync
targets. As of 1.4.0, also returns `format_version` and, if a recovery key is configured, a
non-secret `recovery_key` object with `present`, `id` (4-character slot identifier), and `created`
timestamp. `vault_id` is deliberately not exposed — it would be a stable fingerprint correlating vault
copies across machines, with no agent use case. Never returns real values.

### `sync_llm_env()`

No password. Regenerates `llm.env` from `vault_index.json` (useful if `llm.env` was deleted or corrupted). Errors if no vault index exists yet.

### `add_secret(var_name)`

Adds one secret. The dialog has two steps: master password (this also *creates* the vault on first-ever use), then a confirmation showing the proposed change (`VAR_NAME → "value N"` in `llm.env`) with a field where **you** type the real value. If the name matches common secret-name patterns (contains PASSWORD, SECRET, TOKEN, KEY, etc.), the dialog shows an amber warning above the value field as an extra "are you sure this is going where you think" check. Nothing is written until you click Allow. On Allow: encrypted vault updated, index updated, `llm.env` regenerated automatically.

### `change_password()`

Opens a two-step dialog: master password to decrypt the vault (same as any other vault-touching
operation), then a new-password field. The new password must be at least 12 characters. On Allow,
derives a new key from the new password and a fresh salt, re-encrypts the vault, and writes both
`vault.enc` and `vault.salt` atomically.

**v2 vaults:** credential changes rotate the DEK — a copy of `vault.enc` made before the change
cannot be used to decrypt future bodies. For v2 vaults, changing the password also issues a new
recovery key and invalidates the old printout; the dialog says so before writing. **v1 vaults:** the
older limit applies — anyone who copied `vault.enc` and `vault.salt` before the change, and who later
learns the old password, can still decrypt that earlier snapshot.

### `manage_vault()`

Password-gated hub for vault credential management: change the master password, set up or reissue a
paper recovery key, or upgrade the vault from v1 to v2 format. Each sub-operation opens its own
consent dialog; nothing is written until you allow.

**Password change:** re-derives a new wrapping key from a fresh salt and rotates the DEK — a copy of
`vault.enc` made before the change cannot decrypt future bodies. For v2 vaults, this also issues a new
recovery key and invalidates the old printout; the dialog says so before writing. A `vault.enc.bak` is
written before the change and deleted once read-back verification passes.

**Recovery key setup:** generates 160 bits of entropy, displayed as `RK1` plus 8 groups of 4 Crockford
base32 characters and a 4-character checksum. A 4-character slot id makes a stale printout
identifiable. The setup ceremony requires re-entering the full key from paper before it is accepted.
Shown only in a native dialog with no copy, save, or print controls.

**v1 → v2 upgrade:** rewrites `vault.enc` with the versioned header, AES-256-GCM body, and envelope
encryption. See [Vault format upgrade](#vault-format-upgrade-v1--v2) below for the full implications.

### `recover_vault()`

The only entry point that does not require the master password — this is what makes the paper recovery
key useful in practice. Enter the full key from your printout; if valid, a new master password is set
and vault access is restored. A new recovery key is issued on completion; the old printout is
invalidated immediately.

**Honest limits:** a recovery key cannot recover the password — the password is never stored. It
recovers *access* and the flow sets a new credential. Lose the paper AND forget the password and the
data is gone.

### `remove_secret(var_name)`

Same password-then-confirm flow, no value field. If the vault files are in an inconsistent state (e.g. `vault.enc`/`vault.salt` missing but the name still in the index), it **refuses and reports the problem** rather than silently auto-pruning the index — inconsistencies get surfaced to a human, not papered over.

### `install_migrate(target_path)`

Point it at a project's real `.env`. It parses the file with a multi-line-aware parser (unterminated-quote continuations are tracked correctly, so a PEM key body isn't misparsed as bogus variables) and classifies every line: new secret to migrate, already migrated (skipped), invalid name, unsupported multi-line value (left alone with a warning), duplicate, stale placeholder, and so on. It also warns if a variable name is already claimed by a *different* previously-migrated project.

The confirmation dialog lists exactly which variable **names** will move (selectable/copyable — but never values), plus every warning, before anything happens. On Allow it:

1. Re-reads the target file fresh (in case it changed while the dialog sat open),
2. Migrates real values into the encrypted vault,
3. Rewrites the target file in place with placeholders only — preserving comments, indentation, `export` prefixes, and CRLF/LF line endings,
4. Registers the file + its variable names in `targets.json` so `resync_targets` can maintain it later.

Safe to re-run on the same file (already-migrated variables are skipped). If everything is already migrated but the file isn't registered yet, a lighter dialog still opens just to confirm registration — it never registers silently. Migration is one-shot; ongoing maintenance is `resync_targets`.

### `resync_targets()`

No password (only placeholder numbers move, never real values). Refreshes every registered target file against the current vault index — run it after `add_secret`/`remove_secret` changes something a migrated file should reflect.

Conservative by construction: a line is only rewritten if it's a managed variable name **and** its current value already looks like one of this tool's own placeholders. Anything that looks like a real, hand-typed value is left completely alone and reported as a conflict. A variable removed from the vault gets its line commented out — never deleted, never left as a misleading literal placeholder.

Two known quirks (see [Known limitations](#known-limitations)): this ongoing path is not multi-line-aware, and a resync normalizes the file's line endings even when nothing else changed.

### `run_with_env(command, materialize=None, background=False, cwd=None, only_vars=None)`

The consumption side: runs a real command with the vault's real values injected as environment variables. Since `llm.env` never contains real values, this is how your app actually gets its secrets.

```python
run_with_env(command=["python", "manage.py", "migrate"])
run_with_env(command=["docker", "compose", "up"], background=True)
```

**`only_vars`** — restricts which vault variables get injected, instead of the whole vault:

```python
run_with_env(command=["python", "send_mail.py"], only_vars=["SMTP_HOST", "SMTP_PASSWORD"])
```

- Validated against the vault index **before** any password prompt (a typo'd name fails fast).
- `only_vars` omitted / `None` → inject everything. `only_vars=[]` → inject *nothing*. These are deliberately distinct cases — a zero-secret run and a full-vault run are very different authorizations.
- Strongly recommended whenever the command doesn't need the whole vault: it limits both what a misbehaving command can see and what its output can leak (see Security notes).

**`materialize`** — for tools that read a real `.env` *file* rather than inheriting process environment, mainly Docker's `--env-file` / Compose's `env_file:`:

```python
run_with_env(
    command=["docker", "run", "--rm", "--env-file", ".env.runtime", "myimage"],
    materialize=".env.runtime",
)
```

- Writes a short-lived real file at that path (mode 0600) and deletes it the instant the command exits — including on error, Ctrl+C, or a graceful SIGTERM. (A hard `taskkill /F` can't be caught by any process on any platform; that one edge case can't be closed.)
- **Refuses to run if the path already exists** — it only ever creates and destroys its own file, never overwrites yours. Note Compose's default env file is literally `.env`, which usually exists — point `materialize` at a fresh, gitignored path like `.env.runtime` instead.
- The path is resolved relative to the `cwd` argument (not the server's directory) and containment-checked: absolute paths or `..` escapes are rejected before the password dialog even opens. Pre-existence is re-checked right after the dialog too, since dialogs can sit open for minutes.
- Values are written **unquoted** (`NAME=value`) — this matches how `docker run --env-file` actually parses the file (it takes everything after the first `=` literally and does not strip quotes). A value containing a newline is refused outright.
- Not compatible with `background=True` (no reliable moment to clean the file up).
- If your `docker-compose.yml` only uses `${VAR}` interpolation and no explicit env file, you don't need `materialize` at all — Compose reads variables from the parent process environment.

**`background=True`** — starts the process detached (stdin closed, stdout/stderr redirected to a temp log file — never the MCP server's own stdio, which is the JSON-RPC channel) and returns immediately with the `pid` and `log_file` path. For long-running things like dev servers. The tool does not track or stop the process afterward — use your own process manager. Foreground calls block and return stdout/stderr (truncated to the last 4000 chars each) plus the exit code.

Every result includes an `auto_allowed` flag, plus a `trust_note` whenever trust was used, granted, or revoked — an auto-allowed run is never silent even though no dialog appeared.

---

## Vault format upgrade (v1 → v2)

New vaults created with 1.4.0 or later use v2 format. Existing v1 vaults keep working unchanged
until you choose to upgrade via `manage_vault`.

**What changes:** `vault.enc` gains a structured header (`magic || version || hdr_len ||
header-JSON || nonce || body`); AES-256-GCM replaces Fernet for the body; scrypt replaces PBKDF2
for key derivation; a random DEK is introduced, which is what allows a second credential (the
optional recovery key) without storing the body twice.

**What stays:** `vault.salt` is kept forever after the upgrade — deleting 16 bytes to tidy up
would permanently destroy decryptability of every v1 `vault.enc` backup you hold.

**It is permanent for that file.** Once upgraded, older plugin builds (pre-1.4.0) cannot read the
vault and will report an incorrect-password error for a correct password. The upgrade dialog warns
before writing.

**It is opt-in.** A v1 vault is fully functional and not degraded. Upgrade when you want the
stronger KDF and AES-256-GCM authentication, or to enable the recovery key.

---

## Commands

Two slash commands ship with the plugin. Everything else is done by asking normally — the tools
above are the interface, and wrapping each one in a command would just make it longer to type.

### `/llm-env-vault:protect`

Finds every `.env` in the current project and walks them through `install_migrate` one at a time.
This exists because `install_migrate` takes one path and does no discovery of its own — and
because "just check my `.env` files" is exactly the request that would otherwise have an agent
open a file still full of live credentials. The command's `allowed-tools` deliberately excludes
every file-reading tool, so its discovery path *cannot* read a candidate's contents even if asked
to. It reports paths, migrates each one behind the usual dialog, resyncs if more than one file
moved, and tells you which now-placeholder-only files are safe to commit.

### `/llm-env-vault:doctor`

Diagnoses a server that didn't start: checks whether the tools are present at all, finds and reads
`provision.log`, verifies there's a usable `python` on PATH and that it has `tkinter`, and
explains the two known startup failures (provisioning interrupted by a startup timeout, and CCD
not restarted after install). This is the one thing that can't be a tool — when provisioning
fails, every tool disappears, and nothing that runs *through* the server can report on the
server's own absence. Commands are read by Claude Code directly, so this still works.

## Trusted commands (8-hour auto-allow)

Typing your password twenty times a session for the same `docker compose up` gets old. The
`run_with_env` unlock dialog has a checkbox: **"Trust this exact command for the next 8 hours."**
Check it, click Allow once, and identical future calls auto-run with no dialog. Trust expires
8 hours after it was granted — verified on both wall clock and monotonic clock, so neither
a machine suspend nor a clock adjustment extends it.

**"Exact" means exact.** The full argument list, `cwd`, `only_vars`, `materialize`, and `background` together form the trusted signature — change any one and a fresh Allow is required. `only_vars=[]` and `only_vars` omitted are deliberately different signatures even though both are falsy in Python, because they authorize very different exposure.

**Drift detection.** Trust also records the SHA-256 hash of every file named directly as an
argument on the command line (a `docker-compose.yml` after `-f`, a script path), **and of the
program being executed itself** — resolved the same way your OS's PATH/PATHEXT search would find
it (best-effort, via Python's `shutil.which`; not a guaranteed match to the OS's own search in
every edge case), so a bare `docker` or `python` is covered the same as a file named explicitly
on the command line. Files are hashed *before* the dialog opens — trust binds to what you
actually reviewed, even if the dialog sat open a while. If a tracked file changes (or disappears)
before the next trusted run, trust for that command is silently revoked and the dialog reappears
with a note explaining why (e.g. "docker-compose.yml changed since it was approved"). Honest
boundaries of the tracking, surfaced in the trust note when they apply:

- Files over 64 MiB or unreadable are skipped from hashing (with a one-time warning at grant
  time).
- Only the first 20 distinct referenced files are tracked.
- Only files named *directly on the command line* are tracked — a Dockerfile pulled in indirectly
  via a compose file's `context:` isn't and can't be followed.
- **For commands like `docker compose up`, where no config file is named on the command line, the
  only thing monitored is the resolved executable.** The trust-grant note warns explicitly when
  the monitored set is executable-only, so you can decide whether that coverage is enough for your
  use case.
- If the executed program can't be resolved to a concrete file at all (an unusual PATH/PATHEXT
  setup, a shell builtin), it isn't drift-monitored — the trust-grant note says so explicitly
  when it applies.

**The vault matters too.** Adding, removing, or rotating any secret drops the *entire* trust cache immediately — the cached decrypted values a trusted command would inject are now stale. The next trusted run needs the password again. Cached values are also scoped to exactly what each trusted command was approved to see (a command trusted with a narrow `only_vars` doesn't leave the rest of the vault resident in memory too) and kept obfuscated in memory, not as plain, greppable text — see `vault_lib/trust.py`'s own comments for exactly what that obfuscation does and doesn't protect against (short version: it raises the bar against passive exposure like crash dumps, not against a targeted attacker who can already read this process's memory).

**This is a convenience feature, not a security boundary — deliberately.** Everything is
time-limited (8-hour TTL), in-memory, and gone on restart. Making it survive a restart with zero prompts would require persisting something capable of decrypting the vault (the password, the derived key, or equivalent), which breaks the one real invariant this project is built on: the master password never touches disk. Any persisted equivalent would ultimately be usable in plaintext-equivalent form by any process running under your OS account — the same account the AI agent runs as. Against an actively malicious agent with local code execution, no purely local/software mechanism is a real boundary; genuine protection there would need a separate, more-privileged OS principal gated by hardware-backed human presence (e.g. Windows Hello), which is out of scope. Use trusted commands to stop re-typing your password; don't rely on them to stop an agent already working against you.

One more honest limit: an auto-allowed run hashes referenced files, then runs the command — there's a small window between the check and whatever the command itself later reads from disk. Irrelevant against the adversarial case above; against an ordinary cause (an editor autosaving mid-run), it means the check is a point-in-time snapshot, not a live guarantee.

---

## Security notes

- **Threat model:** protects against an AI agent (or anyone with filesystem read access) harvesting real values from files. Does **not** protect against someone who already has your master password, or an agent granted the ability to type into GUI windows on your behalf (e.g. computer-use tooling) — don't grant that.
- **"The agent can edit this tool's own source" is a sharper non-boundary than it sounds — mitigated, not eliminated.** `plugin_launcher.py` used to re-run `pip install -r requirements.txt` automatically whenever that file's content hash changed, on every server start — meaning an agent with filesystem write access to an *installed* plugin's `requirements.txt` (the same access the "don't protect against editing source" threat model already excludes) could get it silently pip-installed on the very next restart, with no real `claude plugin update` involved. Two reductions, both confirmed by a red-team audit: (1) the installed-plugin trigger is now keyed on `CLAUDE_PLUGIN_ROOT`'s own path, not the requirements content — a real update always moves the plugin to a new version-scoped directory, so editing `requirements.txt` alone no longer triggers anything; (2) on Windows, dependencies install from `requirements-lock.txt`, a hash-pinned lockfile (every package and transitive dependency pinned to an exact version with sha256 hashes for every published artifact) via `pip install --require-hashes`, closing the separate supply-chain risk of a compromised/typosquatted PyPI upload being pulled in silently. Neither makes "an agent can edit this tool's own source" a real boundary — an agent with that access can still edit `plugin_launcher.py` itself, or any other file — but both shrink the auto-triggered, no-real-event attack surface that existed on top of it.
- **Dependency pinning is Windows-only.** The hash-pinned `requirements-lock.txt` described above is scoped to Windows, because `pywin32` (a transitive `mcp[cli]` dependency) only publishes wheels there and a lockfile that can't resolve is worse than none. On macOS and Linux the launcher installs from the unpinned `requirements.txt` instead, so **those installs get no hash verification** and the supply-chain mitigation above does not apply to them. This is the concrete security cost of the Windows-first scoping, not just a packaging detail.
- **Assume `vault.enc` is exfiltratable.** An agent — or anyone with filesystem read access —
  can copy `vault.enc` and `vault.salt`. Decryption then depends entirely on the master password,
  which is why the minimum was raised to 12 characters. A long, random passphrase (the 4-word
  generated option offered at creation) is strongly recommended.
- **The recovery key is a real increase in attack surface.** It converts "compromise requires
  something in a human's head" into "compromise requires a piece of paper" — screenshots, phone
  photos, a filing cabinet. It is opt-in for exactly that reason; a password-only vault is fully
  supported and not degraded.
- **A recovery key cannot recover the password** — the password is never stored. It recovers
  *access*, and the flow sets a new password immediately.
- **Every credential change rotates the DEK.** Re-wrapping alone would be theater: an adversary
  who copied `vault.enc` today and later learned the old password could unwrap a DEK that still
  decrypts future bodies. DEK rotation means the copy is ciphertext locked to the moment it was
  made.
- **KDF parameters live in an attacker-writable header** for v2 vaults, and are validated before
  use — a hostile `n` is rejected rather than allowed to exhaust memory (ceiling: 256 MiB). The
  header bytes are bound as AES-256-GCM AAD, so a tampered parameter also fails body authentication.
- **Rollback is undetectable in-file.** Someone with write access can swap in an older valid
  `vault.enc` and reinstate a revoked secret. The in-session trust fingerprint catches only the
  live case.
- **Never paste the master password (or any secret value) into chat with an AI assistant.** Type
  them only into the vault's own GUI windows.
- **`run_with_env` output is redacted before it reaches the AI, but this is accident-prevention,
  not adversarial defence.** The exact injected value, its base64 encoding, and its URL encoding
  are matched and replaced with `[REDACTED:VAR_NAME]`. Two paths are not covered: a
  `background=True` run's temp log file is only redacted after the process exits (it is unredacted
  while the process is still running), and a `materialize` target is real values on disk by design.
  An agent that chooses the command line can also transform output (gzip, chunk, re-encode) in
  ways that defeat string matching. `only_vars` remains the first line of defence — scope
  injection to what the command actually needs.
- This is not an "intercept every file access" system — that would require a kernel-level filter driver or virtual filesystem (elevated install, fragile). Instead: files are placeholder-only by default, and real values only exist at moments a human deliberately triggered, each gated by the password prompt.
- `vault_index.json` is validated on every read, not just write — a hand-edited or tampered entry can't inject unexpected content into a synced target file.
- **Crypto details:** v2 vaults use scrypt (`n=2**16, r=8, p=1`, 64 MiB) for key derivation,
  AES-256-GCM for the body (header bytes as AAD), and envelope encryption (a random DEK wrapped once
  per credential). v1 vaults use PBKDF2-HMAC-SHA256 at 480,000 iterations and Fernet (AES-128-CBC +
  HMAC), frozen and unchanged. If `vault.salt` exists but `vault.enc` doesn't, the code refuses to
  regenerate a new salt — that would permanently brick any surviving `vault.enc` backup.

## Known limitations

- **Mode 0600 is not a real guarantee on Windows.** `os.chmod` there can only toggle the read-only attribute; the vault and any materialized file inherit their directory's ACL. On a shared machine, keep the vault (and any `materialize` target) somewhere only your account can read.
- **`resync_targets` needs no password and trusts `targets.json`/`vault_index.json`.** Both are validated on read (types, names, no control characters), but a sufficiently crafted plaintext file could still point it at an unintended path. Treat write access to this repo's directory as equivalent to write access to the vault.
- **`resync_targets`' line-matcher isn't multi-line-aware** (unlike `install_migrate`'s initial parser). A managed variable name that also appears inside an unrelated real multi-line value in the same file (a PEM body, embedded JSON) could get that line incorrectly rewritten.
- **A resync normalizes the whole file's line endings** to its dominant terminator and ensures a trailing newline, even when nothing else changed — harmless to meaning, but can show up as a full-file diff under strict VCS line-ending settings.
- **Background run logs linger for up to 7 days.** Each `background=True` call leaves an `llm-env-vault-run-*.log` file in the system temp directory. These are reaped opportunistically once they're older than 7 days, but only when a later run happens to trigger the sweep — so a log can sit there indefinitely if you stop using the tool. Since a log can contain the process's real environment if the command prints its config, clear old ones out yourself if that matters to you.
- **Windows is the only tested platform.** The suite runs on Windows and dependencies are hash-pinned only there (see Security notes). The code is stdlib-portable and the dialogs are plain Tkinter, but macOS and Linux are untested — and the plugin's `.mcp.json` launches a bare `python`, which many such systems don't provide at all. Run `/llm-env-vault:doctor` if the tools don't appear.
- **One dialog at a time.** GUI prompts run on the server's main thread; concurrent tool calls
  queue behind an open dialog.
- **The master password and decrypted vault values are Python `str` objects, and CPython provides
  no way to wipe them from memory.** They may be interned, referenced from tracebacks, or held
  alive by the garbage collector beyond the immediate operation. "The password only lives for the
  duration of one prompt" should not be read as a stronger guarantee than CPython can deliver.
- **Do not store the vault in a synced folder (OneDrive, Dropbox, Syncthing, etc.).** A
  `materialize` target written by `run_with_env` is a real-values file on disk for the duration
  of the command. A sync client can upload that file within the command's lifetime, and deleting
  the file afterward does not recall it from the sync provider's servers or any device that already
  received it.
- **Lose the paper AND forget the password and the data is gone.** That is the design working as
  intended. `manage_vault` offers an opt-in recovery key, but a password-only vault has no recovery
  path — and even with a recovery key, losing both the paper and the password means the vault is
  unrecoverable.
- **Downgrading to an older plugin build after upgrading to v2** produces an incorrect-password
  error for a correct password. The upgrade dialog warns before writing; there is no way to make an
  old build understand the new format.
- **Any header bit-flip in a v2 vault makes the file unopenable** — the price of binding the
  header as AES-256-GCM AAD. `vault.enc.bak` is written before credential changes and deleted once
  read-back verification passes.
- **Tampering with the password slot is indistinguishable from a wrong password.** Only the
  DEK-keyed body tag authenticates the header; you need a working slot to get the DEK — so that
  error still surfaces as "incorrect master password (or the vault file is corrupted)".

## Troubleshooting

Run `/llm-env-vault:doctor` first — it performs every check below and reports one diagnosis.

**The tools don't appear at all.** In order of likelihood:

1. **CCD wasn't restarted after install.** A running session doesn't pick up newly-registered MCP
   servers. Restart it.
2. **No bare `python` on PATH.** The plugin's `.mcp.json` launches `python`, not `python3`. On
   macOS and Linux that often doesn't resolve, and the server never starts. See the platform note
   under Installation.
3. **Provisioning was interrupted.** The first run builds a venv and pip-installs into it; if the
   client's MCP startup timeout fired mid-install, the venv is left half-built. The launcher
   detects this and rebuilds on the next start, so restart and give it time. `provision.log` in
   the plugin's data directory records every attempt, including full pip output.

**The tools appear, but anything touching a secret fails.** Almost always a Python without
`tkinter` — the consent dialogs are Tkinter, so the server starts fine and then fails at the
moment of use. `python -c "import tkinter"` confirms it; on Debian/Ubuntu install `python3-tk`.

**A trusted command started prompting again.** That's by design: trust is revoked when a file the
command references changes, when the executable itself changes, or when the vault's contents
change. The dialog says which. See Trusted commands above.

## Tests

The suite is hand-rolled test scripts (no pytest required, though they also run under pytest),
plus additional pytest-only files:

- `tests/test_trust.py` — trusted-commands / drift-detection feature, vault storage and padding
  behaviour, and plugin-launcher venv provisioning logic. Includes two true end-to-end tests that
  spawn a real child process and assert secret injection on both the fresh-unlock and auto-allowed
  paths. Fully isolates the real vault (temp dir, no real Tkinter window).
- `tests/test_install_migrate_robustness.py` — OSError robustness (UNC paths, nonexistent paths,
  physical drive paths all return clean error dicts), `sync_target_file`'s mass-removal guard, and
  assertion that credential-shaped text is redacted rather than leaked in parse warnings.
- `tests/test_trust_hardening.py`, `tests/test_store_hardening.py`, `tests/test_gui_helpers.py`,
  `tests/test_redaction.py` — 1.3.0 security-hardening coverage: TTL enforcement, output
  redaction, dialog sanitizers, and store scoping.
- `tests/test_crypto_v2.py`, `tests/test_vault_format.py`, `tests/test_store_v2.py`,
  `tests/test_gui_v2.py`, `tests/test_manage_vault.py`, `tests/test_integration_v2.py` — 1.4.0
  coverage: v2 format round-trips, AES-256-GCM authentication, scrypt KDF, envelope encryption,
  DEK rotation, recovery key setup and use, manage_vault / recover_vault flows, and end-to-end
  tests across both format versions.

All tests fully isolate the real vault — running the suite never touches your actual vault. Run
from the project venv:

```bash
python tests/test_trust.py
python tests/test_install_migrate_robustness.py
```

Or all at once with `pytest` from the repo root.

---

## For AI agents

If you are an AI assistant with this MCP server available:

- The tool descriptions in your schemas are authoritative — this section supplements them.
- **Never open, cat, or read `vault.enc`, `vault.enc.bak`, or `vault.salt`.** They are encrypted,
  but treat them as off-limits entirely. Don't read `targets.json` either — it holds machine-local
  paths and there is no reason for you to read it.
- Only `llm.env` and `vault_index.json` are meant for you to read directly.
- **Never ask the human to paste a secret value or the master password into chat.** Route secrets through `add_secret` / `install_migrate` and let the human type values into the GUI themselves.
- Prefer `only_vars` on `run_with_env` whenever you know which variables the command needs.
