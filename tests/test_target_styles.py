"""
Quoting-style capture and faithful value rendering.

These outlive `swap=`. store.parse_env_file_with_styles / record_target_styles
record how each migrated line was originally quoted, and render_value_in_style
puts a value back in that exact form -- because no single quoting works for
every .env parser, and a rewrite that changes one silently changes what the
consumer reads.

Swap was the first caller. The typed placeholders in 2.0 are the next one:
SMTP_USE_SSL=false and SMTP_USE_SSL="false" are not the same value to every
parser either, so the styles-preserving writer is what keeps a placeholder
rewrite faithful. Rescued out of the 1.7.1 swap suite for that reason --
deleting them with swap would have dropped the spec for a writer 2.0 still
needs.
"""
import contextlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import store, trust  # noqa: E402

TEST_PASSWORD = "styles-suite-password-123"
_FAST_PARAMS = crypto.ScryptParams(n=2 ** 12, r=8, p=1)
SECRETS = {
    "API_TOKEN": "tok-abcdefgh-123456",
    "DB_PASSWORD": "p$ss w#rd 'quoted' \"dq\"",
    "PLAIN": "justletters123",
}
INDEX = {"API_TOKEN": 1, "DB_PASSWORD": 2, "PLAIN": 3}
PLACEHOLDER_ENV = (b"# project config\r\n"
                   b"export API_TOKEN=\"value 1\"\r\n"
                   b"  DB_PASSWORD=\"value 2\"  \r\n"
                   b"PLAIN=\"value 3\"\r\n"
                   b"OTHER=untouched\r\n")


def _isolate(tmp_dir: Path) -> dict:
    names = ("SALT_FILE", "SECRETS_FILE", "INDEX_FILE", "ENV_FILE", "BAK_FILE",
             "FORMAT_FILE", "VAULT_LOCK_FILE", "FILES_FILE", "FILES_LOCK_FILE",
             "TARGETS_FILE", "TARGETS_LOCK_FILE", "ROOT")
    originals = {n: getattr(store, n) for n in names}
    vault_dir = tmp_dir / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    store.ROOT = vault_dir
    for attr, name in (("SALT_FILE", "vault.salt"), ("SECRETS_FILE", "vault.enc"),
                       ("INDEX_FILE", "vault_index.json"), ("ENV_FILE", "llm.env"),
                       ("BAK_FILE", "vault.enc.bak"), ("FORMAT_FILE", "vault.format.txt"),
                       ("VAULT_LOCK_FILE", "vault.enc.lock"), ("FILES_FILE", "files.json"),
                       ("FILES_LOCK_FILE", "files.json.lock"),
                       ("TARGETS_FILE", "targets.json"),
                       ("TARGETS_LOCK_FILE", "targets.json.lock")):
        setattr(store, attr, vault_dir / name)
    return originals


def _reset_trust() -> None:
    trust._trusted.clear()
    trust._cached_secrets.clear()
    trust._cache_keys.clear()
    trust._cached_vault_fingerprint = None


@contextlib.contextmanager
def workspace(env_bytes=PLACEHOLDER_ENV, styles=None, register=True):
    """A v2 vault holding SECRETS plus a project dir whose .env is a
    registered target already rewritten with placeholders."""
    with tempfile.TemporaryDirectory(prefix="llm_swap_test_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        _reset_trust()
        project = tmp_path / "project"
        project.mkdir()
        env_path = project / ".env"
        env_path.write_bytes(env_bytes)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(SECRETS))
            store.save_index(dict(INDEX))
            if register:
                store.add_target(str(env_path), sorted(SECRETS))
                if styles:
                    store.record_target_styles(str(env_path), styles)
            yield project, env_path
        finally:
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def test_render_faithful_styles_are_exact_inverses_of_unquote() -> None:
    # Double-quoted: only the quote is re-escaped; a literal backslash-n the
    # user wrote stays two characters, exactly as their loader always saw.
    assert store.render_value_in_style('a"b\\n', '"') == ('"a\\"b\\n"', None)
    assert store.render_value_in_style("it's", "'") == ("'it\\'s'", None)
    assert store.render_value_in_style("p$ss word", "") == ("p$ss word", None)


def test_render_unquoted_style_falls_back_when_value_would_misparse() -> None:
    # A leading space or an inline-comment sequence cannot be raw.
    text, _ = store.render_value_in_style(" lead", "")
    assert text == "' lead'"
    text, _ = store.render_value_in_style("x #y", "")
    assert text == "'x #y'"


def test_render_unknown_style_policy() -> None:
    assert store.render_value_in_style("tok-abc_123", None) == ("tok-abc_123", None)
    text, note = store.render_value_in_style("p$ss w#rd", None)
    assert text == "'p$ss w#rd'" and "single-quoted" in note
    text, note = store.render_value_in_style("it's \"q\"", None)
    assert text == '"it\'s \\"q\\""' and "node" in note


def test_render_refuses_newlines() -> None:
    for style in ('"', "'", "", None):
        try:
            store.render_value_in_style("a\nb", style)
        except ValueError:
            continue
        raise AssertionError(f"newline accepted for style {style!r}")


def test_parse_env_file_with_styles_reports_each_lines_quoting() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_text('A="x"\nB=\'y\'\nC=z\nD="unterminated\n', encoding="utf-8")
        parsed, styles = store.parse_env_file_with_styles(p)
        assert styles == {"A": '"', "B": "'", "C": ""}
        # The plain accessor is unchanged in shape for every existing caller.
        assert store.parse_env_file(p) == parsed
        assert all(len(item) in (2, 3) for item in parsed)


def test_target_styles_round_trip_and_validation() -> None:
    with workspace() as (project, env_path):
        store.record_target_styles(str(env_path), {"API_TOKEN": '"', "PLAIN": ""})
        store.record_target_styles(str(env_path), {"DB_PASSWORD": "'"})
        assert store.load_target_styles()[str(env_path)] == {
            "API_TOKEN": '"', "PLAIN": "", "DB_PASSWORD": "'"}
        # Malformed entries are dropped, never raised: a bad styles file
        # costs fidelity, not a run.
        store._styles_path().write_text(json.dumps({
            str(env_path): {"API_TOKEN": "```", "bad name": '"', "PLAIN": ""},
            "junk": "not a dict", 7: {}}), encoding="utf-8")
        assert store.load_target_styles() == {str(env_path): {"PLAIN": ""}}
        store._styles_path().write_text("{not json", encoding="utf-8")
        assert store.load_target_styles() == {}


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
