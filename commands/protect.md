---
description: Find every .env in this project and move its real values into the vault
argument-hint: "[path to a .env or project dir — omit to scan the current project]"
allowed-tools: Glob, Bash(git check-ignore:*), mcp__llm-env-vault__install_migrate, mcp__llm-env-vault__vault_status, mcp__llm-env-vault__resync_targets
---

# Protect this project's .env files

The `allowed-tools` list above is a **security control, not boilerplate**. It deliberately
omits `Read`, `Grep`, and `Bash(cat:*)`. This command's whole job is to handle files that are
still full of live credentials, so the discovery path must be structurally incapable of pulling
one into context. **Do not add a file-reading tool to that list.** If a step below seems to need
one, the step is wrong.

$ARGUMENTS

## What to do

**1. Discover candidates.**

If the user named a specific path, use it. Otherwise use `Glob` to find `**/.env` and
`**/.env.*`.

Exclude:
- `.env.example`, `.env.sample`, `.env.template` — these are meant to be committed and hold no
  real values.
- anything under `node_modules/`, `.venv/`, `venv/`, `.git/`, `dist/`, `build/`.

**2. Report the paths — and only the paths.**

List what you found as file paths. Do **not** open, read, cat, head, tail, or grep the contents
of any candidate. You do not need to know what is inside them, and looking is the one failure
this command exists to prevent. If there are no candidates, say so and stop.

**3. Migrate each one.**

Call `install_migrate(target_path=...)` on each candidate, **one at a time**.

Do not try to summarise or pre-confirm what will move — the native dialog that `install_migrate`
opens already lists the variable names, flags collisions with other projects, and writes nothing
until the human clicks Allow. That dialog is the confirmation surface. Adding your own is
redundant at best and misleading at worst.

If the user declines a dialog, that file simply stays as it is. Move on to the next one; do not
retry and do not ask why.

**4. Reconcile.**

- Call `vault_status()` to confirm the final state.
- If **more than one** file was migrated, call `resync_targets()`. A later migration can renumber
  the placeholders that an earlier file already carries, and resync is what brings every
  previously-migrated file back in line.

**5. Report what is now safe to commit.**

For each file that was migrated, run `git check-ignore -q <path>` to see whether git is currently
ignoring it. A migrated `.env` holds only placeholders, so it is safe to commit — and often
*useful* to commit, since it documents which variables the project needs.

Tell the user which migrated files are currently gitignored, and note that they can now be
committed safely if they want that. Do not modify `.gitignore` yourself.

## Reporting

Close with a short summary: which files were migrated, which were skipped (and whether the user
declined or the file was already migrated), how many variables the vault now manages, and any
file whose gitignore status the user may want to revisit.
