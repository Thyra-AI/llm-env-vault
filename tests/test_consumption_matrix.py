"""
The executable half of docs/env-consumption-research.md.

Every way a program obtains a value from a .env file is one of six
mechanisms (A-F in the doc). This suite runs a real child process through
run_with_env for each one and records, as a passing test, what the vault
delivers: the real value, the placeholder, or a refusal -- and which mode
(plain injection, materialize, swap) is needed to get the real one.

Real loaders are used where they ship with the server: python-dotenv and
pydantic-settings are transitive dependencies of mcp[cli], so they are on
the tested path, not optional. Node's built-in --env-file and bash's
`source` are used when the binaries are on PATH and skipped otherwise. The
literal parsers (docker run --env-file, kubectl --from-env-file) are
simulated with the exact rule their sources document: everything after the
first `=` is the value, quotes included.

A test named test_<letter>_... is the mechanism from the doc. The assertion
in each is the documented outcome, so this file is also the regression
suite for that document: if a loader changes its precedence, the matching
test breaks here before a user finds out.

Runs under pytest or standalone (`python tests/test_consumption_matrix.py`).
"""
import contextlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import store, trust  # noqa: E402
from test_swap import _isolate, _reset_trust, fake_dialog, TEST_PASSWORD, _FAST_PARAMS  # noqa: E402

SECRETS = {
    "API_TOKEN": "tok-matrix-abcdef0123",
    "SMTP_PORT": "2525",
    "DOLLAR_PASS": "p$ss$HOME-w0rd-xyz",   # interpolation bait (bare $NAME)
    "SPACED": "two words here",
}
INDEX = {"API_TOKEN": 1, "SMTP_PORT": 2, "DOLLAR_PASS": 3, "SPACED": 4}
# What the user's original file looked like: the styles their tools parsed.
ORIGINAL_STYLES = {"API_TOKEN": '"', "SMTP_PORT": "", "DOLLAR_PASS": "'", "SPACED": '"'}
PLACEHOLDER_ENV = (b'API_TOKEN="value 1"\n'
                   b'SMTP_PORT="value 2"\n'
                   b"DOLLAR_PASS=\"value 3\"\n"
                   b'SPACED="value 4"\n')


@contextlib.contextmanager
def project():
    with tempfile.TemporaryDirectory(prefix="llm_matrix_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        _reset_trust()
        proj = tmp_path / "project"
        proj.mkdir()
        env_path = proj / ".env"
        env_path.write_bytes(PLACEHOLDER_ENV)
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(SECRETS))
            store.save_index(dict(INDEX))
            store.add_target(str(env_path), sorted(SECRETS))
            store.record_target_styles(str(env_path), ORIGINAL_STYLES)
            yield proj
        finally:
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


def run(proj: Path, command: list, *, swap=None, materialize=None, only_vars=None) -> dict:
    """run_with_env with the dialog faked; secrets stay redacted in the result
    so a test asserts on the [REDACTED:NAME] marker, never on a value."""
    with fake_dialog():
        return mcp_server._run_with_env_impl(command, materialize, False, str(proj),
                                             only_vars, None, swap=swap)


def py(code: str) -> list:
    return [sys.executable, "-c", code]


# The child scripts. SCRUB builds a child env from an allowlist the way a
# hermetic test harness does, so nothing injected survives into the grandchild.
SCRUB = ("import os,subprocess,sys\n"
         "keep={k:v for k,v in os.environ.items() if k.upper() in "
         "('PATH','SYSTEMROOT','TEMP','TMP','PATHEXT','COMSPEC','HOME','USERPROFILE','LANG')}\n"
         "r=subprocess.run([sys.executable,'-c',CODE],env=keep,capture_output=True,text=True)\n"
         "sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); sys.exit(r.returncode)\n")


def scrubbed(inner: str) -> str:
    return f"CODE={inner!r}\n" + SCRUB


NODE = shutil.which("node")
BASH = shutil.which("bash")
if BASH:
    try:  # a WSL launcher with no distro fails here; skip rather than fail
        if subprocess.run([BASH, "-c", "echo ok"], capture_output=True, text=True,
                          timeout=20).stdout.strip() != "ok":
            BASH = None
    except (OSError, subprocess.SubprocessError):
        BASH = None


def _skip(reason: str) -> None:
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print(f"  SKIP: {reason}")


# ---------------------------------------------------------------------------
# A. Inherit the process environment -- works with plain injection
# ---------------------------------------------------------------------------

def test_A_child_reading_os_environ_gets_real_value_with_plain_injection() -> None:
    with project() as proj:
        r = run(proj, py("import os; print(os.environ['API_TOKEN'])"), only_vars=["API_TOKEN"])
        assert r["exit_code"] == 0 and r["stdout"].strip() == "[REDACTED:API_TOKEN]"
        assert "swapped" not in r


# ---------------------------------------------------------------------------
# B. Loader with env-wins default -- works while the var is in the env
# ---------------------------------------------------------------------------

def test_B_python_dotenv_default_keeps_injected_env_over_placeholder_file() -> None:
    with project() as proj:
        r = run(proj, py("from dotenv import load_dotenv; import os; load_dotenv(); "
                         "print(os.environ['API_TOKEN'])"), only_vars=["API_TOKEN"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]", r


def test_B_pydantic_settings_env_file_lets_injected_env_win() -> None:
    with project() as proj:
        code = ("from pydantic_settings import BaseSettings, SettingsConfigDict\n"
                "class S(BaseSettings):\n"
                "    model_config = SettingsConfigDict(env_file='.env', extra='ignore')\n"
                "    api_token: str\n"
                "    smtp_port: int\n"
                "s = S(); print(s.api_token); print(s.smtp_port)\n")
        r = run(proj, py(code), only_vars=["API_TOKEN", "SMTP_PORT"])
        assert r["exit_code"] == 0, r
        assert r["stdout"].splitlines()[0] == "[REDACTED:API_TOKEN]"
        # 4-char value: under the redactor's minimum, so it comes back raw.
        assert r["stdout"].splitlines()[1] == SECRETS["SMTP_PORT"]


def test_B_node_env_file_lets_process_env_win() -> None:
    if not NODE:
        return _skip("node not on PATH")
    with project() as proj:
        r = run(proj, [NODE, "--env-file=.env", "-e", "console.log(process.env.API_TOKEN)"],
                only_vars=["API_TOKEN"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]", r


def test_B_scrubbed_harness_sees_placeholder_without_swap_and_real_value_with_it() -> None:
    inner = ("from dotenv import load_dotenv; import os; load_dotenv(); "
             "print(os.environ['API_TOKEN'])")
    with project() as proj:
        r = run(proj, py(scrubbed(inner)), only_vars=["API_TOKEN"])
        assert r["stdout"].strip() == "value 1", r
        r = run(proj, py(scrubbed(inner)), only_vars=["API_TOKEN"], swap=[".env"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]", r
        assert (proj / ".env").read_bytes() == PLACEHOLDER_ENV


def test_B_python_dotenv_swapped_value_with_dollar_survives_default_interpolation() -> None:
    """DOLLAR_PASS was single-quoted in the user's file and contains a bare
    `$HOME`. python-dotenv's default interpolate=True only expands the
    `${NAME}` form, so the swapped line comes back intact -- the same value
    the user's app always got from that file."""
    inner = ("from dotenv import dotenv_values; v = dotenv_values('.env'); "
             "print(v['DOLLAR_PASS'] == " + repr(SECRETS["DOLLAR_PASS"]) + ")")
    with project() as proj:
        r = run(proj, py(scrubbed(inner)), only_vars=["DOLLAR_PASS"], swap=[".env"])
        assert r["stdout"].strip() == "True", r


def test_B_python_dotenv_expands_brace_form_in_every_quoting_style() -> None:
    """Characterisation, no vault involved: python-dotenv resolves `${NAME}`
    after parsing, with no knowledge of how the value was quoted (see
    dotenv/main.py resolve_variables). A secret containing `${...}` is
    mangled by python-dotenv in a real .env too; the vault neither causes
    nor can fix that. Recorded here so the research doc stays honest."""
    import os
    from dotenv import dotenv_values
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_text("A='x${PATH}y'\nB=\"x${PATH}y\"\nC=x${PATH}y\nD='x$PATH'\n",
                     encoding="utf-8")
        v = dotenv_values(p)
        expanded = "x" + os.environ["PATH"] + "y"
        assert v["A"] == v["B"] == v["C"] == expanded
        assert v["D"] == "x$PATH"
        assert dotenv_values(p, interpolate=False)["A"] == "x${PATH}y"


# ---------------------------------------------------------------------------
# C. Loader with file-wins override -- placeholder clobbers the env; needs swap
# ---------------------------------------------------------------------------

def test_C_python_dotenv_override_true_clobbers_injection_unless_swapped() -> None:
    code = ("from dotenv import load_dotenv; import os; load_dotenv(override=True); "
            "print(os.environ['API_TOKEN'])")
    with project() as proj:
        r = run(proj, py(code), only_vars=["API_TOKEN"])
        assert r["stdout"].strip() == "value 1", r
        r = run(proj, py(code), only_vars=["API_TOKEN"], swap=[".env"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]", r


# ---------------------------------------------------------------------------
# D. Shell-sourcing the file -- needs swap
# ---------------------------------------------------------------------------

def test_D_bash_source_delivers_real_values_only_with_swap() -> None:
    if not BASH:
        return _skip("bash not on PATH")
    script = "set -a; . ./.env; set +a; printf '%s|%s\\n' \"$API_TOKEN\" \"$SPACED\""
    with project() as proj:
        r = run(proj, [BASH, "-c", script], only_vars=["API_TOKEN", "SPACED"])
        assert r["stdout"].strip() == "value 1|value 4", r
        r = run(proj, [BASH, "-c", script], only_vars=["API_TOKEN", "SPACED"], swap=[".env"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]|[REDACTED:SPACED]", r


# ---------------------------------------------------------------------------
# E. File-only consumers -- materialize for a chosen path, swap for `.env`
# ---------------------------------------------------------------------------

# docker run --env-file and kubectl --from-env-file: "everything after the
# first '=' is the value; quotes are part of it" (docker/cli pkg/kvfile,
# kubectl pkg/generate/versioned/env_file.go).
LITERAL_PARSER = ("import sys\n"
                  "vals={}\n"
                  "for line in open(sys.argv[1], encoding='utf-8'):\n"
                  "    line=line.strip()\n"
                  "    if not line or line.startswith('#') or '=' not in line: continue\n"
                  "    k,v=line.split('=',1); vals[k]=v\n"
                  "print(vals.get('SMTP_PORT')); print(vals.get('API_TOKEN'))\n")


def test_E_materialize_serves_literal_env_file_readers_unquoted() -> None:
    with project() as proj:
        r = run(proj, [sys.executable, "-c", LITERAL_PARSER, ".env.runtime"],
                materialize=".env.runtime", only_vars=["SMTP_PORT", "API_TOKEN"])
        lines = r["stdout"].splitlines()
        assert lines == [SECRETS["SMTP_PORT"], "[REDACTED:API_TOKEN]"], r
        assert not (proj / ".env.runtime").exists()


def test_E_swap_serves_literal_readers_in_the_original_style() -> None:
    """SMTP_PORT was unquoted in the user's file, so a literal reader gets
    it clean. API_TOKEN was double-quoted, so the same reader gets the
    quotes -- exactly as it did before the vault, which is the documented
    limit: no quoting works for both parser families."""
    with project() as proj:
        r = run(proj, [sys.executable, "-c", LITERAL_PARSER, ".env"], swap=[".env"],
                only_vars=["SMTP_PORT", "API_TOKEN"])
        lines = r["stdout"].splitlines()
        assert lines[0] == SECRETS["SMTP_PORT"]
        assert lines[1] == "[REDACTED:API_TOKEN (as written to .env)]", r


def test_E_node_env_file_with_scrubbed_env_needs_swap() -> None:
    if not NODE:
        return _skip("node not on PATH")
    inner = ("import subprocess,sys\n"
             "r=subprocess.run([" + repr(NODE) + ",'--env-file=.env','-e',"
             "'console.log(process.env.API_TOKEN)'],env={'PATH':__import__('os').environ['PATH'],"
             "'SYSTEMROOT':__import__('os').environ.get('SYSTEMROOT','')},"
             "capture_output=True,text=True)\n"
             "sys.stdout.write(r.stdout); sys.stderr.write(r.stderr)\n")
    with project() as proj:
        r = run(proj, py(inner), only_vars=["API_TOKEN"])
        assert r["stdout"].strip() == "value 1", r
        r = run(proj, py(inner), only_vars=["API_TOKEN"], swap=[".env"])
        assert r["stdout"].strip() == "[REDACTED:API_TOKEN]", r


# ---------------------------------------------------------------------------
# F. Typed parsing of the placeholder -- the deferred limitation, characterised
# ---------------------------------------------------------------------------

def test_F_typed_settings_reject_placeholder_file_and_accept_swapped_one() -> None:
    inner = ("from pydantic_settings import BaseSettings, SettingsConfigDict\n"
             "class S(BaseSettings):\n"
             "    model_config = SettingsConfigDict(env_file='.env', extra='ignore')\n"
             "    smtp_port: int\n"
             "try:\n"
             "    print(S().smtp_port)\n"
             "except Exception as e:\n"
             "    print('VALIDATION_ERROR', type(e).__name__)\n")
    with project() as proj:
        r = run(proj, py(scrubbed(inner)), only_vars=["SMTP_PORT"])
        assert r["stdout"].startswith("VALIDATION_ERROR"), r
        r = run(proj, py(scrubbed(inner)), only_vars=["SMTP_PORT"], swap=[".env"])
        assert r["stdout"].strip() == SECRETS["SMTP_PORT"], r


# ---------------------------------------------------------------------------
# Cross-cutting: the file is the same before and after, and trust survives
# ---------------------------------------------------------------------------

def test_swap_round_trip_is_byte_exact_so_a_trusted_docker_style_run_stays_trusted() -> None:
    with project() as proj:
        before = (proj / ".env").read_bytes()
        cmd = py("print('ok')")
        sig = trust.make_signature(cmd, str(proj), None, None, False, None,
                                   swap=[(str(proj / ".env"), sorted(SECRETS))])
        hashes_before = trust.referenced_file_hashes(cmd, str(proj), [str(proj / ".env")])
        r = run(proj, cmd, swap=[".env"])
        assert r["applied"] and (proj / ".env").read_bytes() == before
        assert trust.referenced_file_hashes(cmd, str(proj), [str(proj / ".env")]) == hashes_before
        assert sig  # the signature form is stable and hashable


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = []
    for test in tests:
        print(f"Running {test.__name__} ...")
        try:
            test()
            print("  PASS")
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL: {exc}")
            failures.append((test.__name__, exc))
    print(f"\nResults: {len(tests) - len(failures)}/{len(tests)} passed")
    if failures:
        for name, exc in failures:
            print(f"  FAILED {name}: {exc}")
        sys.exit(1)
    print("All tests passed.")
