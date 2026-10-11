"""Regression tests for the consent-dialog / trust-cache hardening.

Each test is named for what the adversarial assistant could do before the fix.
"""
import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from test_security_review_fixes import (_allow, _project, _run, fake_dialog,  # noqa: E402
                                        isolated_vault)

import mcp_server  # noqa: E402
from thyra_vault import trust  # noqa: E402
from thyra_vault.uihelpers import (command_display_lines, command_refusal_reason,  # noqa: E402
                                   escape_argument)
from thyra_vault.webui import flows, schema  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX files and links")


# --- 1. trust cache poisoning ------------------------------------------------

def test_same_size_edit_with_restored_mtime_changes_the_fingerprint(tmp_path):
    proj = _project(tmp_path / "proj")
    target = proj / "lib.py"
    before = trust.project_fingerprint(proj)
    st = target.stat()
    data = target.read_bytes()
    target.write_bytes(bytes([data[0] ^ 1]) + data[1:])           # same size
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))            # touch -r
    assert target.stat().st_size == st.st_size and target.stat().st_mtime_ns == st.st_mtime_ns
    assert trust.project_fingerprint(proj) != before


@pytest.mark.parametrize("rel", [".venv/lib/site-packages/evil.pth",
                                 ".venv/lib/site-packages/sitecustomize.py",
                                 "node_modules/pkg/usercustomize.py",
                                 ".git/hooks/pre-commit",
                                 ".git/config"])
def test_planting_code_loading_files_in_skipped_dirs_changes_the_fingerprint(tmp_path, rel):
    proj = _project(tmp_path / "proj")
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".venv" / "lib" / "site-packages").mkdir(parents=True)
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    before = trust.project_fingerprint(proj)
    (proj / rel).write_text("import os\n")
    after = trust.project_fingerprint(proj)
    assert after != before
    (proj / rel).write_text("import ox\n")                           # same size, new content
    assert trust.project_fingerprint(proj) != after


def test_other_files_in_skipped_dirs_are_still_ignored(tmp_path):
    proj = _project(tmp_path / "proj")
    (proj / ".venv").mkdir()
    before = trust.project_fingerprint(proj)
    (proj / ".venv" / "data.bin").write_text("x")
    assert trust.project_fingerprint(proj) == before


def test_a_planted_pyc_in_pycache_changes_the_fingerprint(tmp_path):
    proj = _project(tmp_path / "proj")
    (proj / "__pycache__").mkdir()
    before = trust.project_fingerprint(proj)
    (proj / "__pycache__" / "lib.cpython-312.pyc").write_bytes(b"\0" * 16)
    assert trust.project_fingerprint(proj) != before


@posix_only
def test_symlinks_in_skipped_dirs_are_not_followed_but_their_target_counts(tmp_path):
    proj = _project(tmp_path / "proj")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.pth").write_text("x")
    (proj / ".venv").mkdir()
    (proj / ".venv" / "dirlink").symlink_to(outside)
    before = trust.project_fingerprint(proj)
    (outside / "evil.pth").write_text("changed")                      # behind a link: not walked
    assert trust.project_fingerprint(proj) == before
    (proj / ".venv" / "a.pth").symlink_to("/etc/hostname")
    with_link = trust.project_fingerprint(proj)
    (proj / ".venv" / "a.pth").unlink()
    (proj / ".venv" / "a.pth").symlink_to("/etc/hosts")
    assert trust.project_fingerprint(proj) != with_link


def test_exceeding_the_byte_budget_means_ask_every_time(tmp_path, monkeypatch):
    proj = _project(tmp_path / "proj")
    monkeypatch.setattr(trust, "_HASH_BYTE_BUDGET", 3)
    assert trust.project_fingerprint(proj) != trust.project_fingerprint(proj)


def test_big_files_use_size_mtime_and_inode(tmp_path, monkeypatch):
    proj = _project(tmp_path / "proj")
    monkeypatch.setattr(trust, "_HASH_FILE_LIMIT", 4)
    before = trust.project_fingerprint(proj)
    big = proj / "lib.py"
    st = big.stat()
    big.write_bytes(b"Y" * st.st_size)
    os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns + 5))
    assert trust.project_fingerprint(proj) != before


# --- 2. re-baselining --------------------------------------------------------

def test_an_edit_before_a_run_is_not_adopted_by_the_rebaseline(tmp_path):
    proj = _project(tmp_path / "proj")
    sig = ("sig",)
    trust.trust(sig, {}, trust.project_fingerprint(proj))
    approved = trust._trusted[sig]["tree"]
    before_run = trust.project_fingerprint(proj)
    (proj / "lib.py").write_text("X = 'evil'\n")
    trust.refresh_project_fingerprint(sig, proj, before="not-the-approved-state")
    assert trust._trusted[sig]["tree"] == approved
    trust.refresh_project_fingerprint(sig, proj, before=before_run)
    assert trust._trusted[sig]["tree"] == trust.project_fingerprint(proj)
    trust._trusted.pop(sig)


def test_an_assistant_edit_between_calls_is_not_adopted_through_a_later_run(tmp_path):
    proj = _project(tmp_path / "proj")
    cmd = [sys.executable, "app.py"]
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            _run(cmd, proj)
            (proj / "lib.py").write_text("X = 'evil'\n")
            _run(cmd, proj)                                           # dialog again; denied-or-not
            assert len(calls) == 2
            # the 2nd approval (trust_it) baselined the edited tree at ITS approval time,
            # so a third edit must bring the dialog back once more.
            (proj / "lib.py").write_text("X = 'worse'\n")
            _run(cmd, proj)
            assert len(calls) == 3


# --- 3. the command shown is the command that runs --------------------------

def test_every_argument_is_shown_with_visible_escapes():
    lines = command_display_lines(["sh", "-c", "echo a\n\techo b", 'q"\\x'])
    assert lines == ['0: "sh"', '1: "-c"', '2: "echo a\\n\\techo b"', '3: "q\\"\\\\x"']


def test_whitespace_runs_and_lookalike_spaces_are_visible():
    assert escape_argument("a  b") == "a \\x20b"
    assert "\\u00A0" in escape_argument("a b")


@pytest.mark.parametrize("bad", ["a‮b", "a​b", "a\x00b", "a\rb", "a\x1bb", "a\x85b"])
def test_commands_with_format_or_control_characters_are_refused(bad):
    assert command_refusal_reason(["echo", bad]) is not None


def test_newline_and_tab_alone_are_allowed():
    assert command_refusal_reason(["echo", "a\nb\tc"]) is None


def test_an_overlong_command_is_refused_not_truncated():
    assert command_refusal_reason(["echo", "x" * 5000]) is not None
    assert command_refusal_reason(["echo", "x" * 100]) is None


def test_refusal_happens_before_any_dialog(tmp_path):
    proj = _project(tmp_path / "proj")
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            result = _run([sys.executable, "-c", "pass", "a‮b"], proj)
            assert "error" in result and calls == []


def test_the_dialog_receives_the_escaped_argument_lines(tmp_path):
    proj = _project(tmp_path / "proj")
    with isolated_vault():
        with fake_dialog(_allow(trust_it=False)) as calls:
            _run([sys.executable, "-c", "pass\n"], proj)
            assert calls[0]["command_lines"][-1] == '2: "pass\\n"'


def test_schema_never_truncates_silently():
    block = schema.code("x" * (schema._RAW_CAP + 50))
    assert "NOT shown" in block["text"]
    verbatim = schema.code_lines(["a  b"], verbatim=True)
    assert verbatim["lines"] == ["a  b"]


# --- 4. background notice ----------------------------------------------------

def _screen(background):
    gen = flows.unlock_for_run({}, "x", None, set(), None, None, None,
                               command_lines=['0: "x"'], background=background)
    return next(gen)


def test_background_run_dialog_warns_the_output_is_unredacted():
    def keys(s):
        return [b["msg"]["key"] for b in s["blocks"] if b.get("type") == "notice"]
    assert "unlockRun.backgroundUnredacted" in keys(_screen(True))
    assert "unlockRun.backgroundUnredacted" not in keys(_screen(False))


def test_the_background_flag_reaches_the_dialog(tmp_path):
    proj = _project(tmp_path / "proj")
    with isolated_vault():
        with fake_dialog(_allow(trust_it=False)) as calls:
            mcp_server._run_with_env_impl([sys.executable, "-c", "pass"], None, True, str(proj))
            assert calls[0]["background"] is True


def test_the_new_i18n_key_exists_in_every_locale():
    import json
    base = Path(__file__).parent.parent / "web" / "packages" / "i18n" / "src" / "locales"
    for loc in ("en", "it", "fr", "de", "es", "pt-PT", "pt-BR"):
        data = json.loads((base / loc / "translation.json").read_text(encoding="utf-8"))
        assert data["unlockRun"]["backgroundUnredacted"]


# --- 5. redaction ------------------------------------------------------------

def _redacted(text, value, name="K"):
    return mcp_server._redact_secrets(text, {name: value})[0]


def test_base64_wrapped_at_76_columns_is_redacted():
    value = "s3cr3t-value-" + "abcdefghij" * 12
    encoded = base64.encodebytes(value.encode()).decode()             # wrapped at 76
    assert "\n" in encoded.strip()
    out = _redacted("out:\n" + encoded, value)
    assert "REDACTED:K" in out
    for chunk in encoded.split():
        assert chunk not in out


def test_crlf_wrapped_base64_is_redacted():
    value = "s3cr3t-value-" + "abcdefghij" * 12
    encoded = base64.encodebytes(value.encode()).decode().replace("\n", "\r\n")
    out = _redacted(encoded, value)
    assert all(chunk not in out for chunk in encoded.split())


def test_pem_style_lines_are_redacted_individually():
    lines = ["-----BEGIN KEY-----", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "Aw8AMIIBCgKCAQEAu1SU1LfVLPHCozMx", "-----END KEY-----"]
    value = "\n".join(lines)
    printed = "  " + lines[1] + "\r\n" + lines[2] + "\n"                # indented / CRLF / partial
    out = _redacted(printed, value)
    assert lines[1] not in out and lines[2] not in out


def test_short_values_keep_the_existing_skip_policy():
    text, skipped = mcp_server._redact_secrets("pw=abc", {"S": "abc"})
    assert text == "pw=abc" and skipped == ["S"]
