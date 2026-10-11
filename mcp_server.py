"""Entry point the plugin launcher runs (`python mcp_server.py`).

It stays at the top of the repository on purpose: running a *script* puts the script's own folder on
sys.path, whereas `python -m` would put the current directory (the user's project) there, where a hostile
project could shadow the `thyra_vault` package. The server itself lives in thyra_vault/mcp_server.py.
"""
from thyra_vault.mcp_server import main

if __name__ == "__main__":
    main()
