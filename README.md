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
| `llm.env` | `VAR_NAME="value N"` placeholders, auto-generated | Yes | Yes |
| `vault_index.json` | `VAR_NAME → placeholder number` map (no secrets) | Yes | Yes |
| `vault.enc` | Real values, Fernet-encrypted | No (gitignored) | **No** |
| `vault.salt` | 16-byte PBKDF2 salt | No (gitignored) | **No** |
| `targets.json` | Paths of migrated `.env` files | No (gitignored — machine-local paths, not secret) | No |

Key properties:

- **The master password never touches disk.** It's never a CLI argument, never an env var, and only lives in the GUI dialog's memory for the duration of one prompt.
- **Encryption:** PBKDF2-HMAC-SHA256 (480,000 iterations) key derivation; Fernet (AES-128-CBC + HMAC) for the vault itself.
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

**Restart Claude Code Desktop (CCD) after installing.** A running CCD session doesn't pick up newly-registered MCP servers automatically — restart CCD (or reload the window) after `/plugin install`, or `llm-env-vault`'s tools won't show up as available yet.

**First run is slower on purpose:** Claude Code auto-installs Node.js plugin dependencies but has no equivalent for Python, so the plugin ships a launcher (`plugin_launcher.py`) that, on first run, creates a venv in the plugin's persistent data directory (`${CLAUDE_PLUGIN_DATA}`, survives updates), installs `requirements.txt` into it, and then execs the real server from that venv. A content-hash stamp file means it only reinstalls when `requirements.txt` actually changes — every subsequent run is instant. The only prerequisite is a `python` on your PATH.

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

No password, no GUI. Returns what the vault knows: whether it exists, the managed variable names and their placeholder numbers, the path to `llm.env`, and which external files are registered as sync targets. Never returns real values.

### `sync_llm_env()`

No password. Regenerates `llm.env` from `vault_index.json` (useful if `llm.env` was deleted or corrupted). Errors if no vault index exists yet.

### `add_secret(var_name)`

Adds one secret. The dialog has two steps: master password (this also *creates* the vault on first-ever use), then a confirmation showing the proposed change (`VAR_NAME → "value N"` in `llm.env`) with a field where **you** type the real value. If the name matches common secret-name patterns (contains PASSWORD, SECRET, TOKEN, KEY, etc.), the dialog shows an amber warning above the value field as an extra "are you sure this is going where you think" check. Nothing is written until you click Allow. On Allow: encrypted vault updated, index updated, `llm.env` regenerated automatically.

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

## Trusted commands (session-only auto-allow)

Typing your password twenty times a session for the same `docker compose up` gets old. The `run_with_env` unlock dialog has a checkbox: **"Trust this exact command for the rest of this session."** Check it, click Allow once, and identical future calls auto-run with no dialog.

**"Exact" means exact.** The full argument list, `cwd`, `only_vars`, `materialize`, and `background` together form the trusted signature — change any one and a fresh Allow is required. `only_vars=[]` and `only_vars` omitted are deliberately different signatures even though both are falsy in Python, because they authorize very different exposure.

**Drift detection.** Trust also records the SHA-256 hash of every file named directly as an argument on the command line (a `docker-compose.yml` after `-f`, a script path), **and of the program being executed itself** — resolved the same way your OS's PATH/PATHEXT search would find it (best-effort, via Python's `shutil.which`; not a guaranteed match to the OS's own search in every edge case), so a bare `docker` or `python` is covered the same as a file named explicitly on the command line. Files are hashed *before* the dialog opens — trust binds to what you actually reviewed, even if the dialog sat open a while. If a tracked file changes (or disappears) before the next trusted run, trust for that command is silently revoked and the dialog reappears with a note explaining why (e.g. "docker-compose.yml changed since it was approved"). Honest boundaries of the tracking, surfaced in the trust note when they apply:

- Files over 64 MiB or unreadable are skipped from hashing (with a one-time warning at grant time).
- Only the first 20 distinct referenced files are tracked.
- Only files named *directly on the command line* are tracked — a Dockerfile pulled in indirectly via a compose file's `context:` isn't and can't be followed.
- If the executed program can't be resolved to a concrete file at all (an unusual PATH/PATHEXT setup, a shell builtin), it isn't drift-monitored — the trust-grant note says so explicitly when it applies.

**The vault matters too.** Adding, removing, or rotating any secret drops the *entire* trust cache immediately — the cached decrypted values a trusted command would inject are now stale. The next trusted run needs the password again. Cached values are also scoped to exactly what each trusted command was approved to see (a command trusted with a narrow `only_vars` doesn't leave the rest of the vault resident in memory too) and kept obfuscated in memory, not as plain, greppable text — see `vault_lib/trust.py`'s own comments for exactly what that obfuscation does and doesn't protect against (short version: it raises the bar against passive exposure like crash dumps, not against a targeted attacker who can already read this process's memory).

**This is a convenience feature, not a security boundary — deliberately.** Everything is session-only, in-memory, gone on restart. Making it survive a restart with zero prompts would require persisting something capable of decrypting the vault (the password, the derived key, or equivalent), which breaks the one real invariant this project is built on: the master password never touches disk. Any persisted equivalent would ultimately be usable in plaintext-equivalent form by any process running under your OS account — the same account the AI agent runs as. Against an actively malicious agent with local code execution, no purely local/software mechanism is a real boundary; genuine protection there would need a separate, more-privileged OS principal gated by hardware-backed human presence (e.g. Windows Hello), which is out of scope. Use trusted commands to stop re-typing your password; don't rely on them to stop an agent already working against you.

One more honest limit: an auto-allowed run hashes referenced files, then runs the command — there's a small window between the check and whatever the command itself later reads from disk. Irrelevant against the adversarial case above; against an ordinary cause (an editor autosaving mid-run), it means the check is a point-in-time snapshot, not a live guarantee.

---

## Security notes

- **Threat model:** protects against an AI agent (or anyone with filesystem read access) harvesting real values from files. Does **not** protect against someone who already has your master password, or an agent granted the ability to type into GUI windows on your behalf (e.g. computer-use tooling) — don't grant that.
- **"The agent can edit this tool's own source" is a sharper non-boundary than it sounds.** `plugin_launcher.py` re-runs `pip install -r requirements.txt` automatically whenever that file's content changes, on every server start, in the persistent plugin data directory — a change survives a restart and a plugin update, not just the current process. An agent with filesystem write access to the installed plugin's files (the same access the "don't protect against editing source" threat model already excludes) can use that as a standing, auto-triggered code-execution path into the process that holds decrypted secrets, not a one-off edit. Confirmed by a red-team audit; not a new gap in the model, just worth naming explicitly.
- **Never paste the master password (or any secret value) into chat with an AI assistant.** Type them only into the vault's own GUI windows.
- **`run_with_env` output can contain real secrets.** Secrets are in the command's real environment; a command that echoes its environment or prints its config on error leaks them into the result — and into the client's transcript. Use `only_vars` to scope injection, and know what your command prints.
- This is not an "intercept every file access" system — that would require a kernel-level filter driver or virtual filesystem (elevated install, fragile). Instead: files are placeholder-only by default, and real values only exist at moments a human deliberately triggered, each gated by the password prompt.
- `vault_index.json` is validated on every read, not just write — a hand-edited or tampered entry can't inject unexpected content into a synced target file.
- Crypto details: PBKDF2-HMAC-SHA256 at 480,000 iterations for key derivation; Fernet (AES-128-CBC + HMAC) for the vault. If `vault.salt` exists but `vault.enc` doesn't, the code refuses to silently regenerate a new salt — that would permanently brick decryption of any surviving `vault.enc` backup keyed to the old salt.

## Known limitations

- **Mode 0600 is not a real guarantee on Windows.** `os.chmod` there can only toggle the read-only attribute; the vault and any materialized file inherit their directory's ACL. On a shared machine, keep the vault (and any `materialize` target) somewhere only your account can read.
- **`resync_targets` needs no password and trusts `targets.json`/`vault_index.json`.** Both are validated on read (types, names, no control characters), but a sufficiently crafted plaintext file could still point it at an unintended path. Treat write access to this repo's directory as equivalent to write access to the vault.
- **`resync_targets`' line-matcher isn't multi-line-aware** (unlike `install_migrate`'s initial parser). A managed variable name that also appears inside an unrelated real multi-line value in the same file (a PEM body, embedded JSON) could get that line incorrectly rewritten.
- **A resync normalizes the whole file's line endings** to its dominant terminator and ensures a trailing newline, even when nothing else changed — harmless to meaning, but can show up as a full-file diff under strict VCS line-ending settings.
- **Background run logs aren't cleaned up.** Each `background=True` call leaves an `llm-env-vault-run-*.log` file in the system temp directory, never auto-deleted. Since a log can contain the process's real environment if it prints its config, periodically clear old ones out yourself.
- **One dialog at a time.** GUI prompts run on the server's main thread; concurrent tool calls queue behind an open dialog.

## Tests

32 tests across two hand-rolled test scripts (no pytest required, though they also run under pytest):

- `test_trust.py` — 28 tests covering the trusted-commands / drift-detection feature, including two true end-to-end tests that spawn a real child process and assert the actual secret value is injected on both the fresh-unlock and auto-allowed paths. Fully isolates the real vault (temp dir, no real Tkinter window) — running the tests never touches your actual vault.
- `test_install_migrate_robustness.py` — 4 regression tests for OSError robustness (unreachable UNC paths, nonexistent paths, physical drive paths on Windows all return clean error dicts instead of crashing).

Run from the project venv:

```bash
python test_trust.py
python test_install_migrate_robustness.py
```

Both pass 100%.

---

## For AI agents

If you are an AI assistant with this MCP server available:

- The tool descriptions in your schemas are authoritative — this section supplements them.
- **Never open, cat, or read `vault.enc` or `vault.salt`.** They are encrypted, but treat them as off-limits entirely. Don't read `targets.json` either — it holds machine-local paths and there is no reason for you to read it.
- Only `llm.env` and `vault_index.json` are meant for you to read directly.
- **Never ask the human to paste a secret value or the master password into chat.** Route secrets through `add_secret` / `install_migrate` and let the human type values into the GUI themselves.
- Prefer `only_vars` on `run_with_env` whenever you know which variables the command needs.
