---
description: Open the Thyra Vault app (for you to use, not the assistant)
disable-model-invocation: true
---

# Open the Thyra Vault app

The Thyra Vault app is a small window where **the person** unlocks the vault, browses and edits
secrets and personal items, and copies a value. It is opened only by this command, never by a
tool call, because it can put a secret on the clipboard.

Run exactly this one command with the Bash tool, with `run_in_background` set to true (the app
stays open until the person closes it, longer than a Bash call may run), and nothing else:

```
CLAUDE_PLUGIN_DATA="${CLAUDE_PLUGIN_DATA}" sh "${CLAUDE_PLUGIN_ROOT}/launch.sh" app
```

Then tell the person, in one sentence, that the Thyra Vault window is opening (the first run
sets up its Python environment and can take a few seconds) and that they use it themselves.

Do not read the app's output beyond confirming it started. Do not read `vault.enc`, `vault.salt`
or any file in the plugin's data directory, do not try to open the link the app may print, and do
not try to operate the window: nothing in it is meant for you.

If the command fails because there is no Python 3 on PATH, say so and point at `/thyra-vault:doctor`.
