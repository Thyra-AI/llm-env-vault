---
description: Diagnose why thyra-vault's tools aren't showing up
allowed-tools: Glob, Read(~/.claude/**/provision.log), Bash(python --version), Bash(python3 --version), mcp__plugin_thyra-vault_thyra-vault__vault_status
---

# Diagnose thyra-vault

This command exists for one situation: **the MCP server did not start, so none of its tools are
available.** When that happens there is nothing to ask — no tool call can report on the absence
of the tools themselves. Slash commands ship inside the plugin directory and are read by Claude
Code directly, so this one still works when the server does not.

Work through the checks below and report a single diagnosis at the end.

## 1. Are the tools actually present?

State plainly whether the `thyra-vault` MCP tools are available to you in this session
(`vault_status`, `add_secret`, `run_with_env`, and the rest).

If they **are** present, the server is healthy. Say so, run `vault_status()` to confirm it
responds, and stop — the remaining checks are for a server that failed to start.

## 2. Find the provisioning log

The plugin provisions its own Python venv on first run and logs the attempt to `provision.log`.
That log is the single most informative artifact when startup fails.

**Do not try to read `$CLAUDE_PLUGIN_DATA` from a Bash call.** Claude Code exports that variable
into the MCP server's *subprocess* environment, not into the shell you get from the Bash tool —
it will be empty and you will conclude the wrong thing. Instead, `Glob` for `**/provision.log`
under the user's `.claude` directory.

If you find it, read it. It records why each provisioning attempt happened and the full stdout
and stderr of the `venv` and `pip` commands.

`Read` is pre-approved for `provision.log` only. Never read `vault.enc`, `vault.salt`,
`llm.env`, or any `.env` file while diagnosing; none of them is needed, and the log is the only
file this command inspects.

## 3. Is there a usable Python?

```
python3 --version
```

The plugin's `.mcp.json` runs `sh launch.sh`, which uses the first of `python3`, `python` or
`py -3` it finds, so any Python 3.10+ on PATH is enough. If `python3 --version` fails, try
`python --version`; if both fail there is no Python, which is the diagnosis. If they work but the
tools still do not appear, the likely cause is that there is no `sh` on PATH (native Windows
without Git for Windows): report that and stop; the checks below will not add anything.

## 4. Can a dialog be shown?

Every operation that touches a real secret opens a consent dialog, which is a small local
browser page (in a Chromium-based browser — Chrome, Edge, Brave, Chromium — it opens as a small
window; in any other browser it opens as a tab). So the server can start fine and then fail at
the moment of use on a machine with **no display** (an SSH session, a container): nothing can
open the page. Ask the user whether they are on such a machine. If so, the link to open is
printed to the MCP server's log, and the dialog times out after three minutes if nobody opens
it. Nothing needs to be installed for the dialogs themselves.

## 5. Known failure narratives

If the log or the checks above don't explain it, consider these two, both documented:

- **Provisioning was interrupted.** If the client's MCP startup timeout fired while `pip install`
  was still running, the venv is left half-built and the server never comes up. The launcher
  detects this on the next start and rebuilds from scratch, so the first fix to try is simply
  restarting and giving it time to finish. `provision.log` will show the truncated attempt.
- **The client was not restarted after install.** A running Claude Code Desktop session does not
  pick up newly registered MCP servers. If the plugin was installed during this session, that
  alone explains the missing tools — restart CCD.

## Reporting

Give one clear diagnosis and one concrete next action. If several checks failed, lead with the
one that is upstream of the others (no Python beats no display). If everything passed and the
tools are still missing, say so explicitly and point at `provision.log` — do not invent a cause.
