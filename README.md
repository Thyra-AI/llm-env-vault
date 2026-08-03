# llm-env-vault

An MCP server that lets an AI coding assistant work with your `.env`
variable *names* without ever seeing the real *values*.

## The idea

- `llm.env` — auto-generated, safe to hand to an AI agent or commit to
  git. Every value is a placeholder: `API_KEY="value 1"`.
- `vault.enc` — the real values, encrypted with a master password you
  choose. Nobody (including the AI) can read it without that password.
- `vault_index.json` — plaintext map of `VAR_NAME -> placeholder number`.
  No secrets in it, which is why `llm.env` can be regenerated without
  ever touching the password.

Every operation that touches a real value is an MCP **tool** the
assistant calls directly (structured arguments, structured results --
no more shelling out to a script and parsing its stdout). Every
mutating tool still pops up the same small Tkinter GUI window it always
did: the human types the master password and, where relevant, the real
value, sees the exact proposed change, and only something they click
**Allow** for actually gets written. The password is never passed as a
tool argument, never printed, and never stored anywhere — the AI only
ever sees the tool's structured result (e.g. `{"applied": true,
"message": "API_KEY -> \"value 1\" in llm.env"}`), never the real value
or the password.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

## Registering the MCP server

Add an entry pointing at this venv's Python and `mcp_server.py`. The
exact registration command can vary by client version -- check
`claude mcp --help` -- but the underlying config is the standard MCP
`mcpServers` shape used by most clients:

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

Register it globally (available from any project you open, since the
whole point is protecting *other* projects' `.env` files) rather than
scoped to this repo alone. For Claude Code, that's typically:

```bash
claude mcp add llm-env-vault --scope user -- "C:\path\to\llm-env-vault\.venv\Scripts\python.exe" "C:\path\to\llm-env-vault\mcp_server.py"
```

You can also run it directly for local testing without any client:

```bash
python mcp_server.py
```

## Tools

### `vault_status()`
Read-only snapshot: which variables are managed, their `llm.env`
placeholder numbers, and which project files are registered for
`resync_targets`. No password needed.

### `add_secret(var_name)`
Add or update one secret. Opens a window: first the master password
(or, the very first time, creating one), then the proposed change and
a field for the real value. Nothing is written until the human clicks
**Allow**.

### `remove_secret(var_name)`
Remove one secret. Same password-then-confirm flow, no value field.

### `install_migrate(target_path)`
Point this at a project's real `.env` and pull every real value out of
it into the encrypted vault, rewriting that file in place so it only
ever contains placeholders afterward. The confirmation screen lists
exactly which variable *names* (never values, selectable/copyable)
will move, and calls out any that would overwrite another registered
project's vault entry. Comments, indentation, `export` prefixes, and
line endings (CRLF/LF) in the target file are preserved; multi-line or
unterminated-quote values (PEM keys, certs) are left alone with a
warning rather than corrupted. Safe to call again later on the same
file -- already-migrated variables are skipped automatically. Does
**not** keep auto-syncing that file on every later change elsewhere in
the vault -- see `resync_targets` for why, and how to refresh it
explicitly.

### `resync_targets()`
Refresh every file previously migrated with `install_migrate` against
the current vault index -- call this after `add_secret`/`remove_secret`
changes something elsewhere in the vault. No password needed (only
placeholder numbers move, never values). Conservative by construction:
a line is only rewritten if it already looks like one of this tool's
own placeholders; something that looks like a real, hand-typed value is
left completely alone and reported instead of overwritten. A variable
removed from the vault gets its line commented out, not deleted or left
as a misleading literal `"value N"`.

### `sync_llm_env()`
Regenerate this repo's own `llm.env` from `vault_index.json`. No
password needed. Useful if `llm.env` gets deleted or hand-edited.

### `run_with_env(command, materialize=None, background=False, cwd=None)`
Run a real command with the vault's real secret values injected as
environment variables. Prompts once for the master password and
returns the command's exit code, stdout, and stderr (not secret --
that's the app's own output, same as running it in a terminal).

Since `llm.env` never holds real secrets, an app can't just load it
directly -- this is how it actually runs for real:

```
run_with_env(command=["python", "manage.py", "migrate"])
run_with_env(command=["docker", "compose", "up"])
```

For tools that read a real `.env` **file** directly instead of
inheriting process environment variables — mainly Docker's
`--env-file` / Compose's `env_file:` — pass `materialize`:

```
run_with_env(
  command=["docker", "run", "--rm", "--env-file", ".env.runtime", "myimage"],
  materialize=".env.runtime",
)
```

This writes a short-lived real file at that path and deletes it the
instant the command exits, even on error, Ctrl+C, or a graceful
SIGTERM (a hard `taskkill /F` can't be caught by any process, on any
platform). It refuses to run if the path already exists — it will only
ever create and destroy a file of its own, never overwrite something
already there (Compose's default env file is literally `.env`, which
usually already exists). Point it at a fresh, gitignored path. Values
are written **unquoted** (`NAME=value`) to match how `docker run
--env-file` actually parses the file — it takes the whole remainder of
the line after the first `=` literally and does not strip quotes the
way `python-dotenv` does; quoting was tried first and confirmed wrong
against a real container. A value containing a newline is refused
outright.

If your `docker-compose.yml` only uses `${VAR}` interpolation (no
explicit `--env-file`), you don't need `materialize` — Compose already
reads variables from the parent process environment.

`background=True` starts the process detached and returns immediately
with its PID and a `log_file` path (its stdout/stderr, stdin closed),
for long-running commands (a dev server) instead of blocking until it
exits. Not compatible with `materialize` (there's no reliable moment to
clean the file up if the process is left running). This tool does not
track or stop the process afterward — use your own process manager.

One dialog at a time: tool calls that open the GUI block until it's
answered (Tkinter isn't safe to run outside the thread that owns it, so
these deliberately don't run concurrently with each other) — normal for
the single-agent, one-call-at-a-time usage this is built for.

## Security notes

- `vault.enc`, `vault.salt`, and `targets.json` are gitignored (the
  last one only because it holds machine-local absolute paths, not
  because it's secret). `llm.env` and `vault_index.json` are safe to
  commit — they contain no secrets.
- This protects against an AI agent (or anyone with filesystem/read
  access) harvesting real values from files it's allowed to read. It
  does **not** protect against someone who already has your master
  password, or against an agent that has been granted the ability to
  type into GUI windows on your behalf (e.g. via computer-use tooling)
  — don't grant that.
- It's also not a true "intercept every file access" system — that
  would require a kernel-level filter driver or a virtual filesystem
  (WinFsp), which needs elevated/admin install and is fragile. Instead,
  the file stays placeholder-only by default, and the only moments a
  real value exists are ones a human deliberately triggers through one
  of these tools, each gated by the same password prompt.
- Never paste the master password into a chat with an AI assistant.
  Type it only into the vault's own GUI window.
- `PBKDF2` (480k iterations, SHA-256) derives the encryption key from
  your password; values are encrypted with Fernet (AES-128-CBC + HMAC).
- All writes to vault files are atomic (temp file + `os.replace`), so a
  crash or power loss mid-write can never leave a truncated vault.

## Known limitations

- **`run_with_env`'s stdout/stderr can contain real secrets.** They're
  injected into the command's environment; a command that echoes its
  own environment, or prints its config on error, will leak them into
  the result you get back (and into the client's transcript). Use
  `only_vars` to scope injection to just what the command needs, and be
  aware of what the command you're running actually prints.
- **Mode 0600 isn't a real guarantee on Windows.** `os.chmod` there can
  only toggle the read-only attribute, not restrict which local
  accounts can read a file — the materialized real-values file and the
  vault itself inherit their directory's ACL instead. On a shared or
  multi-user machine, put the vault (and any `materialize` target)
  somewhere only your account can read.
- **`resync_targets` needs no password and trusts `targets.json`/
  `vault_index.json`.** Both are validated on read (types, variable
  names, no embedded control characters in paths), but a sufficiently
  crafted plaintext file could still point `resync_targets` at an
  unintended path. Treat write access to this repo the same as write
  access to the vault itself.
- **`sync_target_file` isn't multi-line-aware.** Unlike
  `install_migrate`'s parser, the ongoing resync path matches lines
  independently; a managed variable name that happens to also appear
  inside a real multi-line value elsewhere in the same file (a PEM
  body, embedded JSON) could get its line rewritten incorrectly. Avoid
  reusing a managed variable's name inside an unrelated multi-line
  block in the same file.
- **A resync normalizes the whole file's line endings**, even when
  nothing else changed — it always rewrites every line with the file's
  dominant terminator and ensures a trailing newline. Harmless for the
  file's meaning, but shows up as a full-file diff if that file is
  under version control with strict line-ending settings.
- **No automated test suite yet.** Correctness for the trickier parsing
  cases (escaped quotes, BOM, CRLF, multi-line values, inline comments)
  has been verified by hand against real files and a real Docker
  container, not by a pinned regression suite — a future change could
  reintroduce a bug one of those manual passes already caught.
- **Background run logs aren't cleaned up.** Each `background=True`
  call leaves a log file in the system temp directory; they aren't
  size-bounded or auto-deleted. Since the process's real environment
  can end up in that file if it prints its config, periodically clear
  out old `llm-env-vault-run-*.log` files yourself.

## For AI agents

The tool descriptions above are what you see directly as MCP tool
schemas — call them the same way you'd call any other tool. Never open,
cat, or otherwise read `vault.enc` or `vault.salt` (they're encrypted,
but treat them as off-limits) or `targets.json` (machine-local paths,
no reason to read it). Only `llm.env` and `vault_index.json` are meant
for you to read directly. Never ask the human to paste a secret value
or the master password into chat — always route through `add_secret` /
`install_migrate` and let them type it into the GUI themselves.
