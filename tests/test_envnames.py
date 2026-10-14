"""Tool-control env-name denylist (plan 2.4.0 section 4) and its enforcement
at add_secret: NEW names are refused before any dialog; names already in the
vault keep working."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
from vault_lib import envnames, gui  # noqa: E402
from test_trust import isolated_vault  # noqa: E402

REFUSED = [
    "PATH", "path", "PATHEXT", "HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "APPDATA",
    "LOCALAPPDATA", "TMP", "TEMP", "SystemRoot", "WINDIR", "COMSPEC",
    "REQUESTS_CA_BUNDLE", "KUBECONFIG", "KUBERC", "CURL_CA_BUNDLE",
    "GIT_SSH_COMMAND", "git_askpass", "GCM_INTERACTIVE", "DOCKER_HOST", "DOCKER_TEST_TOKEN",
    "COMPOSE_FILE", "BUILDKIT_HOST", "BUILDX_CONFIG", "KUBE_TOKEN", "KUBECACHEDIR",
    "KUBERNETES_SERVICE_HOST", "DOTNET_ROOT", "XDG_CONFIG_HOME", "LD_PRELOAD",
    "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "PYTHONSTARTUP",
    "NODE_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_HOME", "SSH_AUTH_SOCK",
    "HTTP_PROXY", "https_proxy", "ALL_PROXY", "No_Proxy",
]
ALLOWED = [
    "API_TOKEN", "DB_PASSWORD", "MYAPP_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN", "HOMEPAGE_URL",
    "PATHOLOGY_KEY", "TEMPLATE_ID", "TMPL", "OPENAI_API_KEY", "PROXY_URL", "NODEJS_KEY",
    "SSHKEY", "LDAP_PASSWORD", "DOCKERHUB_TOKEN", "STRIPE_SECRET",
]


@pytest.mark.parametrize("name", REFUSED)
def test_tool_control_names_detected(name) -> None:
    assert envnames.is_tool_control_name(name) is True


@pytest.mark.parametrize("name", ALLOWED)
def test_ordinary_names_not_flagged(name) -> None:
    assert envnames.is_tool_control_name(name) is False


def test_non_string_is_not_flagged() -> None:
    assert envnames.is_tool_control_name(None) is False


def _spy_dialog(monkeypatch):
    calls = []

    def fake(var_name, is_update, placeholder, is_sensitive=False):
        calls.append((var_name, is_update))
        return {"approved": False, "partial_failure": None}

    monkeypatch.setattr(gui, "add_secret_dialog", fake)
    return calls


def test_add_secret_refuses_new_tool_control_name_without_dialog(monkeypatch) -> None:
    calls = _spy_dialog(monkeypatch)
    with isolated_vault({"EXISTING_SECRET": "existing-value-123"}):
        for name in ("GIT_ASKPASS", "https_proxy", "KUBECONFIG", "PATH"):
            result = mcp_server._add_secret_impl(name)
            assert result["applied"] is False
            assert name in result["error"] and "refused" in result["error"]
    assert calls == []


def test_add_secret_still_accepts_ordinary_new_name(monkeypatch) -> None:
    calls = _spy_dialog(monkeypatch)
    with isolated_vault({"EXISTING_SECRET": "existing-value-123"}):
        result = mcp_server._add_secret_impl("MYAPP_TOKEN")
    assert result == {"applied": False, "message": "Denied by user."}
    assert calls == [("MYAPP_TOKEN", False)]


def test_add_secret_keeps_updating_existing_tool_control_name(monkeypatch) -> None:
    calls = _spy_dialog(monkeypatch)
    with isolated_vault({"DOCKER_TEST_TOKEN": "tok-abc-123"}):
        result = mcp_server._add_secret_impl("DOCKER_TEST_TOKEN")
    assert result == {"applied": False, "message": "Denied by user."}
    assert calls == [("DOCKER_TEST_TOKEN", True)]


def test_allowlist_uses_envnames_by_default() -> None:
    from vault_lib import allowlist, store
    assert not hasattr(store, "is_tool_control_name") or \
        store.is_tool_control_name is envnames.is_tool_control_name
    assert allowlist.envnames is envnames
