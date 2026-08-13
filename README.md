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

## Trusted commands

The unlock dialog has a checkbox: **"Trust this exact command for the
rest of this session."** Check it, click Allow once, and every later
call to `run_with_env` with the exact same `command`, `cwd`, `only_vars`,
`materialize`, and `background` auto-runs with **no dialog at all** —
you're not asked for the password again. Every result from `run_with_env`
still tells you what happened: an `"auto_allowed": true` flag and a
`"trust_note"` message whenever trust was used, newly granted, or
revoked, so an auto-allowed run is never silent even though nothing
popped up.

**What counts as "the exact same command."** Trust is keyed on the full
argument list, `cwd`, `only_vars`, `materialize`, and `background`
together — changing any of them (a different flag, a different working
directory, asking for a different subset of variables, foreground vs.
detached) is a different command and needs a fresh Allow.
`only_vars=[]` (inject nothing) and `only_vars` omitted (inject the
whole vault) are deliberately treated as different too, even though both
are "falsy" in Python — they authorize very different exposure, so
conflating them would let a zero-secret approval silently cover a
full-vault run. This is all deliberately strict: a broader match (e.g.
"any `docker compose` subcommand") would let one approval silently cover
commands you never actually saw.

**Drift detection.** On top of the exact-match check, trust also tracks
the content of every file named directly as a whole argument on the
command line — e.g. `docker-compose.yml` named after a `-f` flag, or a
script path. Files are hashed *before* the dialog opens, not after you
click Allow, so trust binds to what you actually reviewed even if the
dialog sat open for a while. If a tracked file's content changes (or it
disappears) before the next trusted run, trust for that command is
silently revoked and the dialog reappears with a note explaining why,
e.g. *"Trust for this exact command was revoked — docker-compose.yml
changed (or appeared/disappeared) since it was approved."* This catches
the common case — someone edited the compose file since you approved it
— automatically, without you having to remember to re-check.

Two things this can't see, and the trust note will tell you when they
apply: a referenced file **larger than 64 MiB or unreadable** is skipped
from hashing entirely (drift in it is simply never detected — you'll get
a one-time "too large/unreadable to monitor" note when trust is
granted), and only the **first 20 distinct referenced files** are
tracked if a command names more than that. And by design, this only
looks at files named *directly on the command line* — it does not (and
structurally cannot) follow indirect references, most notably a
`Dockerfile` pulled in only via a compose file's `context:` and never
mentioned in the command itself. If your build depends on a Dockerfile
changing, that drift won't revoke trust; changing the compose file
itself still will.

**The vault matters too, not just the command.** If you add, remove, or
rotate a secret (or otherwise change the vault) after trusting a
command, the cached secrets that command would auto-inject are now
stale relative to the vault — so the *entire* trust cache is dropped the
next time anything checks it, not just the one command you changed, and
the next run of any trusted command needs the password again to refresh
it.

**It's session-only, and it's a convenience feature, not a security
boundary.** Everything this feature tracks — which commands are trusted,
and the decrypted secrets used to skip re-prompting — lives only in this
one MCP server process's memory. Nothing new is ever written to disk.
Restarting the server (or Claude Desktop, or your editor) forgets all of
it, and the very next run needs the master password again, trusted or
not.

That last part is a deliberate design choice, not a missing feature.
This tool's real security invariant, unchanged since before this feature
existed, is documented in `vault_lib/crypto.py`: **the master password
never touches disk.** Making a trusted command survive a server restart
with zero prompts would require persisting *something* capable of
decrypting the vault — the password, the derived key, or an
equivalent — which breaks that invariant no matter how it's protected
(encrypted-at-rest, OS keychain, a compiled binary, an obfuscated key).
Any of those still have to become usable, in plaintext-equivalent form,
to a process running as your own Windows account — which is exactly the
same account the AI agent using this tool runs as. Against that
attacker, nothing purely local and purely software-based is a real
boundary: it can read that process's memory, decompile a protected
binary, or simply edit this repo's own Python to skip whatever check it
doesn't like. (If you want genuine protection against a compromised or
malicious agent rather than just fewer password prompts for an honest
one, that requires a fundamentally different architecture — a separate,
more-privileged OS principal holding the key, gated by a hardware-backed
human-presence check like Windows Hello, that this repo's own code
cannot read or impersonate. That's a distinct, much larger project, not
something bolted onto the vault as it exists today.)

One more honest limit, unrelated to the attacker discussion above: an
auto-allowed run checks referenced files, then runs the command --
there's a small window between that check and whatever the command
itself reads from disk. Against the attacker this whole section is
about, that window is irrelevant (it doesn't need it). Against an
everyday, non-adversarial cause -- an editor autosaving the compose file
mid-run, a background build touching it -- it means the check is a
point-in-time snapshot, not a live guarantee about what the command
actually reads. Nothing practical closes that gap for an external
process like `docker compose`, and it isn't worth trying.

So: use trust to stop re-typing your password for the `docker compose
up` you run twenty times a session. Don't rely on it to stop an agent
that's already working against you — the one thing standing between an
AI assistant and your real secret values has always been a human
consciously typing the master password, and this feature's entire
design goal is to disturb that as little as possible while still saving
you the repetition.

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
- The "Trusted commands" feature (see above) reduces password prompts
  for repeated `run_with_env` calls but is explicitly **not** a security
  boundary — it's in-memory and session-only by design. Read that
  section before relying on it for anything more than convenience.
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
