"""Opening the Thyra Vault app from an installed plugin (/thyra-vault:open).

The app must see the vault the assistant's tools use. That vault lives under CLAUDE_PLUGIN_DATA, which
Claude Code exports to the MCP server but NOT to a shell, so the command passes it in explicitly and the
launcher refuses to guess when it is missing.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import plugin_launcher  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
COMMAND = (REPO / "commands" / "open.md").read_text(encoding="utf-8")


def test_the_app_runs_in_the_plugins_own_venv_as_a_module():
    command = plugin_launcher._app_command(Path("/data/venv/bin/python"), ["--where"])
    assert command == ["/data/venv/bin/python", "-m", "thyra_vault.app", "--where"]


def test_an_installed_plugin_refuses_to_guess_the_data_directory(monkeypatch, capsys):
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setattr(plugin_launcher, "PLUGIN_ROOT",
                        Path("/home/me/.claude/plugins/cache/thyra-vault/thyra-vault/3.0.0"))
    with pytest.raises(SystemExit) as stop:
        plugin_launcher._require_data_dir_for_app()
    assert stop.value.code == 2
    assert "/thyra-vault:open" in capsys.readouterr().err


def test_it_proceeds_when_the_data_directory_is_given(monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "/home/me/.claude/plugins/data/thyra-vault-thyra-vault")
    monkeypatch.setattr(plugin_launcher, "PLUGIN_ROOT",
                        Path("/home/me/.claude/plugins/cache/thyra-vault/thyra-vault/3.0.0"))
    plugin_launcher._require_data_dir_for_app()  # no exception


def test_a_source_checkout_may_run_it_without_the_variable(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setattr(plugin_launcher, "PLUGIN_ROOT", Path("/home/me/code/thyra-vault"))
    plugin_launcher._require_data_dir_for_app()  # a developer's checkout keeps its own vault


def test_only_the_user_can_run_the_open_command():
    frontmatter = COMMAND.split("---")[1]
    assert re.search(r"^disable-model-invocation:\s*true\s*$", frontmatter, re.M), (
        "the assistant must not be able to open the app: it can put a secret on the clipboard")


def test_the_open_command_passes_the_data_dir_and_runs_the_app_mode():
    assert ('CLAUDE_PLUGIN_DATA="${CLAUDE_PLUGIN_DATA}" sh '
            '"${CLAUDE_PLUGIN_ROOT}/launch.sh" app') in COMMAND


def test_the_open_command_does_not_grant_blanket_shell_access():
    """allowed-tools is a security control: this command needs no pre-approved Bash at all (the person
    sees and approves the one command), so none is granted."""
    frontmatter = COMMAND.split("---")[1]
    assert "allowed-tools" not in frontmatter


def test_the_open_command_tells_the_assistant_to_stay_out_of_the_vault():
    flat = " ".join(COMMAND.split()).lower()   # the sentence wraps across lines
    assert "vault.enc" in flat and "do not try to operate the window" in flat


def _probe(env_overrides, expression):
    import os
    import subprocess
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "CLAUDE_PLUGIN_ROOT")}
    env.update(env_overrides)
    done = subprocess.run([sys.executable, "-c", f"import plugin_launcher; print({expression})"], cwd=str(REPO),
                          env=env, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def test_an_empty_data_directory_variable_is_treated_as_unset_not_as_the_current_directory():
    """`--plugin-dir` mode may not export the data directory, and a command substituting it yields an empty
    string. Path("") is the current directory: a venv created there would litter whatever folder is open."""
    assert _probe({"CLAUDE_PLUGIN_DATA": ""}, "plugin_launcher.DATA_DIR.name") == ".venv-data"
    assert _probe({"CLAUDE_PLUGIN_ROOT": ""}, "plugin_launcher.PLUGIN_ROOT == plugin_launcher.Path(plugin_launcher.__file__).resolve().parent") == "True"


def test_an_empty_data_directory_is_refused_for_an_installed_plugin(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "")
    monkeypatch.setattr(plugin_launcher, "PLUGIN_ROOT",
                        Path("/home/me/.claude/plugins/cache/thyra-vault/thyra-vault/3.0.0"))
    with pytest.raises(SystemExit):
        plugin_launcher._require_data_dir_for_app()
