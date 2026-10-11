#!/bin/sh
# Starts plugin_launcher.py with whichever Python 3 this machine has. Many systems ship only `python3`
# (no bare `python`), so the plugin cannot name one interpreter. Run it as `sh launch.sh [args]`.
# stdout belongs to the MCP protocol: every message here goes to stderr.
case $0 in */*) here=${0%/*} ;; *) here=. ;; esac
for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        exec "$py" "$here/plugin_launcher.py" "$@"
    fi
done
if command -v py >/dev/null 2>&1; then
    exec py -3 "$here/plugin_launcher.py" "$@"
fi
echo "Thyra Vault needs Python 3.10 or newer on PATH (tried python3, python, py). Run /thyra-vault:doctor." >&2
exit 127
