"""The dependency install must not be steerable by the folder the assistant is working in, and an
installed plugin must refuse to install without its hash-pinned lockfile."""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import plugin_launcher  # noqa: E402


def test_every_uv_command_ignores_project_configuration():
    """The MCP server's working directory is the user's project, and uv reads uv.toml / pyproject.toml
    from there (it could point installs at another package index)."""
    source = Path(plugin_launcher.__file__).read_text(encoding="utf-8")
    calls = re.findall(r"\[uv,\s*([^\]]*?)\]", source)
    assert calls, "expected uv invocations in the launcher"
    assert all(c.lstrip().startswith('"--no-config"') for c in calls), calls


def test_installs_run_from_the_data_directory_not_the_callers_folder(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cwd"] = kwargs.get("cwd")

        class Done:
            stdout, stderr, returncode = "", "", 0
        return Done()

    monkeypatch.setattr(plugin_launcher, "DATA_DIR", tmp_path)
    monkeypatch.setattr(plugin_launcher, "INSTALL_LOG", tmp_path / "provision.log")
    monkeypatch.setattr(plugin_launcher.subprocess, "run", fake_run)
    plugin_launcher._run_logged(["true"], "test step")
    assert seen["cwd"] == str(tmp_path)


def test_an_installed_plugin_without_its_lockfile_refuses_to_install(monkeypatch, tmp_path):
    monkeypatch.setattr(plugin_launcher, "_IS_INSTALLED_PLUGIN", True)
    monkeypatch.setattr(plugin_launcher, "REQUIREMENTS", tmp_path / "requirements.txt")  # not the lockfile
    with pytest.raises(RuntimeError, match="requirements-lock.txt is missing"):
        plugin_launcher._provision(Path(sys.executable), "marker")
