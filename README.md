# llm-env-vault

A small local middleware that lets an AI coding assistant work with your
`.env` variable *names* without ever seeing the real *values*.

## The idea

- `llm.env` — auto-generated, safe to hand to an AI agent or commit to
  git. Every value is a placeholder: `API_KEY="value 1"`.
- `vault.enc` — the real values, encrypted with a master password you
  choose. Nobody (including the AI) can read it without that password.
- `vault_index.json` — plaintext map of `VAR_NAME -> placeholder number`.
  No secrets in it, which is why `llm.env` can be regenerated without
  ever touching the password.

The master password is typed once per change, directly into a Tkinter
GUI window. It is never passed as a CLI argument, never printed, and
never stored anywhere — so a calling process (including an LLM driving
this tool via shell commands) only ever observes the exit code and a
non-secret confirmation line such as:

```
Applied: API_KEY -> "value 1" in llm.env
```

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

## Adding / updating a secret

```bash
python add_secret.py API_KEY
```

A window opens showing the proposed change (which env var, which
placeholder number it will get in `llm.env`) plus fields for the master
password and the real value. Nothing is written until you click
**Allow**; clicking **Deny** (or closing the window) discards it.

The first time you run this, there's no vault yet, so the window also
asks you to create the master password.

## Removing a secret

```bash
python remove_secret.py API_KEY
```

Same Allow/Deny flow, no value field.

## Rebuilding llm.env

```bash
python sync_env.py
```

Regenerates `llm.env` from `vault_index.json`. No password needed —
useful if `llm.env` gets deleted or hand-edited.

## Running your actual app with the real values

Since `llm.env` never holds real secrets, your app can't just load it
directly. Instead, run your app through the vault:

```bash
python run_with_env.py -- python manage.py runserver
python run_with_env.py -- node app.js
```

This prompts once for the master password, decrypts the vault
in-memory, and launches your command with the real values merged into
its environment — never written to disk.

## Security notes

- `vault.enc` and `vault.salt` are gitignored. `llm.env` and
  `vault_index.json` are safe to commit — they contain no secrets.
- This protects against an AI agent (or anyone with filesystem/read
  access) harvesting real values from files it's allowed to read. It
  does **not** protect against someone who already has your master
  password, or against an agent that has been granted the ability to
  type into GUI windows on your behalf (e.g. via computer-use tooling)
  — don't grant that.
- Never paste the master password into a chat with an AI assistant.
  Type it only into the vault's own GUI window.
- `PBKDF2` (480k iterations, SHA-256) derives the encryption key from
  your password; values are encrypted with Fernet (AES-128-CBC + HMAC).

## For AI agents working in a repo that uses this tool

Only read `llm.env`. Never open, cat, or otherwise read `vault.enc` or
`vault.salt` — they're encrypted, but treat them as off-limits. To add
a variable, run `python add_secret.py VAR_NAME` and let the human
approve it in the GUI; do not ask the human to paste the secret value
into chat.
