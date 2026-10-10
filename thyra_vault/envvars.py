"""Environment variables: ``THYRA_VAULT_*``, with the old ``LLM_ENV_VAULT_*`` still honoured.

The product was renamed from llm-env-vault to Thyra Vault. Anyone who already
set ``LLM_ENV_VAULT_UI=tk`` in a shell profile or an MCP config keeps that
behaviour; the new name wins when both are set.
"""
import os
from typing import Mapping, Optional

PREFIX = "THYRA_VAULT_"
LEGACY_PREFIX = "LLM_ENV_VAULT_"


def names(suffix: str):
    """Both spellings of one variable, new first (``names("UI")``)."""
    return PREFIX + suffix, LEGACY_PREFIX + suffix


def get(suffix: str, default: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    env = os.environ if env is None else env
    for name in names(suffix):
        value = env.get(name)
        if value:  # an empty variable counts as unset, as it always did here
            return value
    return default
