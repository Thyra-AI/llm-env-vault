"""Shared pytest setup."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# mcp_server limits how fast consent dialogs may open (a defence against a looping
# assistant). The suite opens far more than eight FAKE dialogs in one process, so it
# runs unlimited; tests/test_security_review_fixes.py exercises the limiter itself.
os.environ.setdefault("THYRA_VAULT_DIALOG_LIMIT", "0")
