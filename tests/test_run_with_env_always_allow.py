"""
run_with_env x always-allow (2.4.0): the wiring in mcp_server._run_with_env_core
and _run_command, with a fake profile registered through
profiles.register_profile and a real throwaway vault (same fixture as
tests/test_allowlist.py). The unlock dialog is faked with the **kwargs wrapper
pattern from tests/test_trust.py, so the always_allow / hide_trust / arm_report
keywords mcp_server passes are recorded and can be asserted on.

The profile's Verdict.argv is a python child, because the request itself
(argv0 "fake") must stay eligible for always-allow, and python is not.

Covered: auto-allow with no dialog and its trust_info keys; drift falling back
to the dialog; a failing recheck refusing; empty only_vars refused first; a
denial calling record_denial (and the cool-down it feeds); the offer /
hide_trust / arm_report reaching the dialog; an entry created in the dialog
beating the 8 h trust; strict redaction of every encoding; the output cap and
the raw-capture cap; stdin_bytes; Verdict wall_clock / cleanup_paths /
stderr_fatal_markers; inject_secrets=False; replace_env=True.

Runs under pytest only (the conftest fixtures isolate the rollback sidecar and
forbid real windows).
"""
import base64
import contextlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
import test_allowlist as ta  # noqa: E402
from vault_lib import allowlist, gui, profiles, store, trust  # noqa: E402
from vault_lib.profiles import Request, Verdict  # noqa: E402

PW = ta.PW
TOKEN = ta.SECRETS["API_TOKEN"]
SPECIAL = "p@ss/w0rd+=&x y"
PY = sys.executable


@dataclass(frozen=True)
class XVerdict(Verdict):
    """A KubectlVerdict-style verdict: the extras are read via getattr."""
    wall_clock: Optional[float] = None
    cleanup_paths: tuple = ()
    stderr_fatal_markers: tuple = ()


class ScriptProfile:
    """Claims argv0 'fake'; verify() returns a python child (argv from
    ``script``) unless a test swaps ``make`` or sets ``drift`` / ``fail_from``."""
    kind = "fake"

    def __init__(self):
        self.script = "print('ok')"
        self.drift = None
        self.fail_from = None       # verify call number from which verify refuses
        self.verify_calls = 0
        self.make = None            # (req, call_number) -> Verdict

    def match(self, req):
        if req.command and req.command[0] == "fake":
            return {"argv": list(req.command)}
        return None

    def snapshot(self, req, candidate):
        return {"state": "approved", "hash": "abc123def456"}

    def describe(self, req, candidate):
        return "fake " + " ".join(req.command[1:]) + "\nfindings: none"

    def check_snapshot(self, entry):
        return (True, None)

    def verify(self, entry, req):
        self.verify_calls += 1
        if entry["shape"] != self.match(req):
            return Verdict(ok=False, reason=None)
        if self.drift:
            return Verdict(ok=False, reason=self.drift)
        if self.make is not None:
            return self.make(req, self.verify_calls)
        if self.fail_from is not None and self.verify_calls >= self.fail_from:
            return Verdict(ok=False, reason="the binary was swapped")
        return Verdict(ok=True, argv=[PY, "-c", self.script], env=None)


@contextlib.contextmanager
def aa_env():
    with ta._env() as e:
        secrets = dict(ta.SECRETS, SPECIAL=SPECIAL)
        store.save_secrets(PW, secrets)
        store.save_index({name: i + 1 for i, name in enumerate(sorted(secrets))})
        prof = ScriptProfile()
        profiles.register_profile("fake", prof)
        e.prof = prof
        try:
            yield e
        finally:
            profiles.unregister_profile("fake")


@contextlib.contextmanager
def dialog(respond=None):
    """Fake gui.unlock_for_run_dialog. Yields the recorded calls (every keyword
    received, including the always-allow ones). With no ``respond`` the dialog
    must not open at all."""
    original = gui.unlock_for_run_dialog
    calls = []

    def wrapper(command_str, materialize_path=None, only_vars=None, trust_note=None,
                **kwargs):
        calls.append({"command_str": command_str, "materialize_path": materialize_path,
                      "only_vars": only_vars, "trust_note": trust_note, **kwargs})
        if respond is None:
            raise AssertionError("the unlock dialog must not open for this call")
        return respond(calls[-1])

    gui.unlock_for_run_dialog = wrapper
    try:
        yield calls
    finally:
        gui.unlock_for_run_dialog = original


def allow(trust_it=False, always=False, commit=False):
    def respond(call):
        names = call["only_vars"] or []
        if commit:
            call["always_allow"].commit(PW)
        return {"secrets": {n: dict(ta.SECRETS, SPECIAL=SPECIAL)[n] for n in names},
                "trust": trust_it, "always_allow": always}
    return respond


def deny(call):
    return {"secrets": None, "trust": False, "always_allow": False}


def run(e, *command, only=("API_TOKEN",), timeout=None, tail_chars=4000):
    command = command or ("fake", "go")
    return mcp_server._run_with_env_impl(list(command), None, False, e.cwd, list(only),
                                         None, timeout, None, False, tail_chars)


def armed(e, only=("API_TOKEN",), *command):
    """Approve the fake command and unlock once, like a real session would."""
    eid = e.approve(*(command or ("fake", "go")), only=only)
    e.unlock()
    return eid


# ---------------------------------------------------------------------------
# Auto-allow, drift, recheck, scope
# ---------------------------------------------------------------------------

def test_auto_allow_runs_without_dialog_and_reports_trust_info() -> None:
    with aa_env() as e:
        e.prof.script = "import os; print('hello', len(os.environ['API_TOKEN']))"
        eid = armed(e)
        with dialog() as calls:
            result = run(e)
        assert calls == []
        assert result["applied"] is True and result["exit_code"] == 0
        assert result["stdout"].strip() == f"hello {len(TOKEN)}"
        assert result["auto_allowed"] is True
        assert result["always_allow"] == eid
        assert result["trust_note"].startswith("Auto-allowed by always-allow entry")
        assert eid in result["trust_note"]
        assert "invalidated_reason" not in result


def test_drift_falls_back_to_the_dialog_with_invalidated_reason() -> None:
    with aa_env() as e:
        armed(e)
        e.prof.drift = "the pinned config changed"
        with dialog(allow()) as calls:
            result = run(e)
        assert len(calls) == 1
        assert "the pinned config changed" in calls[0]["trust_note"]
        assert calls[0]["always_allow"] is not None        # re-offered after the disarm
        assert result["invalidated_reason"] == "the pinned config changed"
        assert "auto_allowed" not in result
        assert allowlist.describe_state()["armed"] == 0


def test_recheck_failure_refuses_and_runs_nothing() -> None:
    with aa_env() as e:
        marker = e.root / "ran.txt"
        e.prof.script = f"open({str(marker)!r}, 'w').write('x')"
        armed(e)
        e.prof.fail_from = e.prof.verify_calls + 2         # lookup ok, recheck refuses
        with dialog() as calls:
            result = run(e)
        assert calls == []
        assert result["applied"] is False
        assert "no longer applies" in result["error"]
        assert result["invalidated_reason"] == "the binary was swapped"
        assert not marker.exists()
        assert allowlist.describe_state()["armed"] == 0


def test_empty_only_vars_refused_first_even_when_an_entry_would_match() -> None:
    with aa_env() as e:
        armed(e)
        before = e.prof.verify_calls
        with dialog() as calls:
            result = run(e, only=())
        assert calls == []
        assert "only_vars is empty" in result["error"]
        assert e.prof.verify_calls == before                # never reached the matcher
        assert "auto_allowed" not in result


# ---------------------------------------------------------------------------
# Denial, the offer and what the dialog is given
# ---------------------------------------------------------------------------

def test_denial_calls_record_denial(monkeypatch) -> None:
    with aa_env() as e:
        seen = []
        real = allowlist.record_denial
        monkeypatch.setattr(allowlist, "record_denial", lambda req: (seen.append(req), real(req)))
        with dialog(deny):
            result = run(e)
        assert result == {"applied": False, "message": "Denied by user."}
        assert len(seen) == 1 and isinstance(seen[0], Request)
        assert seen[0].command == ("fake", "go") and seen[0].only_vars == ("API_TOKEN",)


def test_repeated_denials_hide_the_offer() -> None:
    with aa_env() as e:
        with dialog(deny) as calls:
            for _ in range(allowlist.DENIAL_LIMIT):
                run(e)
            assert allowlist.cooldown_remaining(e.req("fake", "go")) > 0
            run(e)
        assert calls[0]["always_allow"] is not None
        assert calls[-1]["always_allow"] is None


def test_offer_hide_trust_and_arm_report_reach_the_dialog() -> None:
    with aa_env() as e:
        armed(e, ("API_TOKEN",), "fake", "other")           # a different, armed entry
        with dialog(deny) as calls:
            run(e)                                          # ("fake", "go"): no entry
        call = calls[0]
        offer = call["always_allow"]
        assert offer is not None and offer.kind == "fake"
        assert offer.pattern.splitlines()[0] == "fake go"
        assert call["hide_trust"] is False
        assert call["arm_report"] == mcp_server._always_allow_arm_report()
        assert "Always-allow armed: fake other" in call["arm_report"]


def test_hide_trust_for_script_commands() -> None:
    with aa_env() as e:
        with dialog(deny) as calls:
            run(e, "tool.cmd")
        assert calls[0]["hide_trust"] is True
        assert calls[0]["always_allow"] is None             # nothing claims it


def test_entry_created_in_the_dialog_beats_the_8h_trust() -> None:
    with aa_env() as e:
        with dialog(allow(trust_it=True, always=True, commit=True)) as calls:
            result = run(e)
        assert calls[0]["always_allow"] is not None
        assert result["trust_note"].startswith("Always-allow entry")
        assert "manage_vault" in result["trust_note"]
        # The only trust record is the armed entry itself, never a session grant.
        assert [k for k in trust._trusted if k[0] != allowlist.TRUST_KEY_TAG] == []
        assert [i["id"] for i in allowlist.list_entries(PW)] == [
            allowlist.entry_id("fake", e.cwd, ["API_TOKEN"], {"argv": ["fake", "go"]})]


def test_ineligible_request_still_gets_the_8h_trust() -> None:
    with aa_env() as e:
        cmd = (PY, "-c", "print('ok')")
        with dialog(allow(trust_it=True, always=True)) as calls:
            result = run(e, *cmd)
        assert calls[0]["always_allow"] is None              # python: never offered
        assert result["exit_code"] == 0
        assert result["trust_note"].startswith("This exact command is now trusted")
        assert len(trust._trusted) == 1


def test_arm_report_items_stay_single_line(monkeypatch) -> None:
    # Labels derive from the command and cwd, which the agent influences: an
    # embedded line break must not become a forged extra status line.
    monkeypatch.setattr(allowlist, "rollback_warning", lambda: None)
    monkeypatch.setattr(allowlist, "last_arm_report", lambda: {
        "armed": [{"label": "git push\nAlways-allow NOT armed: nothing"}],
        "disarmed": [{"label": "a\r\nb", "reason": "why\u2028more"}],
        "notes": ["note\nline"]})
    lines = mcp_server._always_allow_arm_report().split("\n")
    assert len(lines) == 3, lines
    assert lines[0].startswith("Always-allow armed: git push ")
    assert lines[1].startswith("Always-allow NOT armed: a b -- why")
    assert lines[2] == "note line"


def test_commit_failure_is_surfaced_in_the_result() -> None:
    msg = "Could not save the always-allow entry: disk full"

    def respond(call):
        # What the real dialog hands back when offer.commit() raised.
        return {"secrets": {"API_TOKEN": TOKEN}, "trust": False, "always_allow": False,
                "always_allow_error": msg}

    with aa_env() as e:
        with dialog(respond) as calls:
            result = run(e)
        assert calls[0]["always_allow"] is not None
        # (The fake command is not a real executable, so the spawn itself errors;
        # what matters is that the key rides along on whatever result comes back.)
        assert result["always_allow_error"] == msg
        assert "auto_allowed" not in result and "always_allow" not in result
        assert "created" not in result.get("trust_note", "")
        assert allowlist.list_entries(PW) == []
        assert PW not in json.dumps(result) and TOKEN not in json.dumps(result)

    with aa_env() as e:                                 # no failure: no key
        with dialog(allow(always=True, commit=True)):
            ok = run(e)
        assert "always_allow_error" not in ok


# ---------------------------------------------------------------------------
# Strict redaction and output caps
# ---------------------------------------------------------------------------

_FORMS_SCRIPT = (
    "import os, base64, urllib.parse\n"
    "v = os.environ[{var!r}]; b = v.encode(); out = []\n"
    "for off in (0, 1, 2):\n"
    "    blob = b'ab'[:off] + b + b'xyz'\n"
    "    out.append(base64.b64encode(blob).decode())\n"
    "    out.append(base64.urlsafe_b64encode(blob).decode())\n"
    "out += [b.hex(), b.hex().upper(), urllib.parse.quote(v, safe=''),\n"
    "        urllib.parse.quote_plus(v), v.upper(), v.lower(),\n"
    "        base64.b64encode(b).decode().rstrip('=')]\n"
    "print(chr(10).join(out))\n")


@pytest.mark.parametrize("var,value", [("API_TOKEN", TOKEN), ("SPECIAL", SPECIAL)])
def test_strict_redaction_catches_encoded_forms(var, value) -> None:
    with aa_env() as e:
        e.prof.script = _FORMS_SCRIPT.format(var=var)
        armed(e, (var,))
        with dialog():
            result = run(e, only=(var,))
        assert result["auto_allowed"] is True and result["exit_code"] == 0
        out = result["stdout"]
        b = value.encode()
        forms = [value.upper(), value.lower(), b.hex(), b.hex().upper(),
                 urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
                 base64.b64encode(b).decode().rstrip("=")]
        for off in (0, 1, 2):
            blob = b"ab"[:off] + b + b"xyz"
            forms += [base64.b64encode(blob).decode(), base64.urlsafe_b64encode(blob).decode()]
        for form in forms:
            assert form not in out, f"{form!r} leaked in strict output"
        assert f"[REDACTED:{var}]" in out
        # Enough of the value's middle to be unambiguous, in plain and base64 form.
        assert value[2:-2] not in out


def test_output_beyond_256_kib_is_truncated_and_flagged() -> None:
    with aa_env() as e:
        e.prof.script = "import sys; sys.stdout.write('x' * (300 * 1024))"
        armed(e)
        with dialog():
            result = run(e)
        assert result["output_truncated"] is True
        assert "truncation_note" in result
        assert result["streams"]["stdout"]["chars"] <= mcp_server.STRICT_OUTPUT_CAP_BYTES + 300
        assert result["streams"]["stderr"]["chars"] == 0


def test_dialog_approved_run_is_not_capped_or_flagged() -> None:
    with aa_env() as e:
        with dialog(allow()):
            result = run(e, PY, "-c", "import sys; sys.stdout.write('x' * (300 * 1024))")
        assert "output_truncated" not in result
        assert result["streams"]["stdout"]["chars"] == 300 * 1024


def test_raw_capture_is_bounded_and_keeps_the_tail() -> None:
    script = ("import sys\n"
              "for i in range(20000):\n"
              "    sys.stdout.write('line %06d out\\n' % i)\n"
              "    sys.stderr.write('line %06d err\\n' % i)\n")
    result = mcp_server._run_command([PY, "-c", script], os.environ.copy(), None, 120,
                                     bind=False, capture_limit=5000)
    assert result.returncode == 0 and result.timed_out is False
    assert result.raw_truncated == ("stdout", "stderr")
    for stream, tag in ((result.stdout, "out"), (result.stderr, "err")):
        assert len(stream.encode()) <= 5000
        assert stream.rstrip().endswith(f"line 019999 {tag}")


_GRANDCHILD = ("import sys, time\n"
               "end = time.time() + 25\n"
               "while time.time() < end:\n"
               "    with open(sys.argv[1], 'a') as f:\n"
               "        f.write('x')\n"
               "    time.sleep(0.2)\n")


def _spawn_grandchild_script(alive_file: str, then: str) -> str:
    """A child that starts a grandchild inheriting its stdout/stderr pipes (the
    grandchild appends to *alive_file* every 0.2 s for up to 25 s), then runs
    *then*."""
    return ("import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {_GRANDCHILD!r}, {alive_file!r}])\n"
            "time.sleep(1.0)\n" + then)


def _grandchild_is_dead(alive_file: str) -> bool:
    assert os.path.getsize(alive_file) > 0, "the grandchild never started"
    time.sleep(0.6)
    first = os.path.getsize(alive_file)
    time.sleep(1.2)
    return os.path.getsize(alive_file) == first


def test_capped_timeout_kills_the_whole_process_tree(tmp_path) -> None:
    alive = str(tmp_path / "alive.txt")
    script = _spawn_grandchild_script(alive, "time.sleep(60)\n")
    start = time.monotonic()
    result = mcp_server._run_command([PY, "-c", script], os.environ.copy(), None, 3,
                                     bind=False, capture_limit=5000)
    assert result.timed_out is True
    assert time.monotonic() - start < 20
    assert _grandchild_is_dead(alive), "a grandchild survived the timeout"


def test_capped_run_does_not_hang_on_a_descendant_holding_the_pipe(tmp_path) -> None:
    alive = str(tmp_path / "alive.txt")
    script = _spawn_grandchild_script(alive, "print('parent done')\n")
    start = time.monotonic()
    result = mcp_server._run_command([PY, "-c", script], os.environ.copy(), None, 60,
                                     bind=False, capture_limit=5000)
    assert time.monotonic() - start < 15, "the reader join waited for the straggler"
    assert result.returncode == 0 and "parent done" in result.stdout
    assert _grandchild_is_dead(alive), "the straggler holding the pipe was left running"


def test_capped_timeout_note_claims_the_tree_and_plain_run_note_does_not() -> None:
    # Auto-allowed run: _run_capped kills the whole tree, and says so.
    with aa_env() as e:
        e.prof.make = lambda req, n: XVerdict(
            ok=True, argv=[PY, "-c", "import time; time.sleep(60)"], wall_clock=1.5)
        armed(e)
        with dialog():
            result = run(e)
        assert "whole process tree" in result["timeout_note"]
    # Plain unbound run (subprocess.run): only the direct child is killed, and
    # the note must not claim more.
    with aa_env() as e:
        with dialog(allow()):
            result = run(e, PY, "-c", "import time; time.sleep(60)", timeout=1)
        assert result["timed_out"] is True
        assert "whole process tree" not in result["timeout_note"]
        assert "the command itself only" in result["timeout_note"]


def test_kills_tree_matches_the_paths_that_really_kill_it() -> None:
    assert mcp_server._kills_tree(True, None, None) is True
    assert mcp_server._kills_tree(False, 100, None) is True
    assert mcp_server._kills_tree(False, None, b"x") is True
    assert mcp_server._kills_tree(False, None, None) is False


def test_uncapped_stdin_bytes_timeout_kills_the_whole_process_tree(tmp_path) -> None:
    alive = str(tmp_path / "alive.txt")
    script = _spawn_grandchild_script(alive, "time.sleep(60)\n")
    start = time.monotonic()
    result = mcp_server._run_command([PY, "-c", script], os.environ.copy(), None, 3,
                                     bind=False, stdin_bytes=b"ignored")
    assert result.timed_out is True
    assert time.monotonic() - start < 20
    assert _grandchild_is_dead(alive), "a grandchild survived the timeout"


def test_raw_capture_under_the_limit_is_untouched() -> None:
    result = mcp_server._run_command([PY, "-c", "print('small')"], os.environ.copy(), None, 60,
                                     bind=False, capture_limit=5000)
    assert result.stdout.strip() == "small" and result.raw_truncated == ()


def test_capture_limit_refuses_bound_runs() -> None:
    with pytest.raises(ValueError):
        mcp_server._run_command([PY, "-c", "pass"], os.environ.copy(), None, 5,
                                bind=True, capture_limit=100)


def test_raw_truncation_flags_the_run_and_drops_a_split_value(monkeypatch) -> None:
    # The value straddles the raw cut: only its last 5 characters survive at the
    # start of the capture, where no redaction pattern can match them.
    monkeypatch.setattr(mcp_server, "STRICT_RAW_CAPTURE_BYTES", 800)
    monkeypatch.setattr(mcp_server, "STRICT_OUTPUT_CAP_BYTES", 5000)
    with aa_env() as e:
        e.prof.script = ("import os, sys\n"
                         "sys.stdout.write('A' * 500 + os.environ['API_TOKEN'] + 'B' * 795)")
        armed(e)
        with dialog():
            result = run(e, tail_chars=200_000)
        assert result["output_truncated"] is True
        out = result["stdout"]
        assert out.startswith(mcp_server.STRICT_TRUNCATION_PREFIX)
        assert TOKEN[-5:] + "BBB" not in out
        assert TOKEN not in out
        assert len(out) < 1000


# ---------------------------------------------------------------------------
# stdin, wall clock, cleanup, fatal stderr markers
# ---------------------------------------------------------------------------

_ECHO_STDIN = "import sys; sys.stdout.write(sys.stdin.read())"


def test_run_command_writes_stdin_bytes_to_the_child() -> None:
    for kwargs in ({}, {"capture_limit": 100_000}):
        result = mcp_server._run_command([PY, "-c", _ECHO_STDIN], os.environ.copy(), None, 60,
                                         bind=False, stdin_bytes=b"hello-in \xc3\xa9", **kwargs)
        assert result.returncode == 0
        assert result.stdout == "hello-in é"


def test_run_command_without_stdin_bytes_closes_stdin() -> None:
    result = mcp_server._run_command([PY, "-c", _ECHO_STDIN], os.environ.copy(), None, 60,
                                     bind=False, capture_limit=1000)
    assert result.returncode == 0 and result.stdout == ""


def test_run_command_stdin_bytes_refuses_bound_runs() -> None:
    with pytest.raises(ValueError):
        mcp_server._run_command([PY, "-c", "pass"], os.environ.copy(), None, 5,
                                bind=True, stdin_bytes=b"x")


def test_verdict_stdin_reaches_the_child_and_is_redacted() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: Verdict(
            ok=True, argv=[PY, "-c", _ECHO_STDIN], stdin=b"manifest: " + TOKEN.encode())
        armed(e)
        with dialog():
            result = run(e)
        assert result["exit_code"] == 0
        assert result["stdout"] == "manifest: [REDACTED:API_TOKEN]"


def test_verdict_wall_clock_kills_the_child() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: XVerdict(
            ok=True, argv=[PY, "-c", "import time; time.sleep(60)"], wall_clock=1.5)
        armed(e)
        start = time.monotonic()
        with dialog():
            result = run(e)
        assert time.monotonic() - start < 30
        assert result["timed_out"] is True
        assert "1.5 seconds" in result["timeout_note"]


def test_wall_clock_never_extends_the_callers_timeout() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: XVerdict(
            ok=True, argv=[PY, "-c", "import time; time.sleep(60)"], wall_clock=3600)
        armed(e)
        start = time.monotonic()
        with dialog():
            result = run(e, timeout=2)
        assert time.monotonic() - start < 30
        assert result["timed_out"] is True and "2 seconds" in result["timeout_note"]


def _make_dir() -> str:
    path = tempfile.mkdtemp(prefix="llm_aa_cleanup_")
    Path(path, "cache.bin").write_bytes(b"x")
    return path


def test_cleanup_paths_deleted_after_a_normal_run() -> None:
    with aa_env() as e:
        path = _make_dir()
        loose = Path(path).parent / (Path(path).name + ".file")
        loose.write_bytes(b"y")
        try:
            e.prof.make = lambda req, n: XVerdict(
                ok=True, argv=[PY, "-c", "print('ok')"], cleanup_paths=(path, str(loose)))
            armed(e)
            with dialog():
                result = run(e)
            assert result["exit_code"] == 0
            assert not Path(path).exists() and not loose.exists()
        finally:
            shutil.rmtree(path, ignore_errors=True)
            loose.unlink(missing_ok=True)


def test_cleanup_paths_deleted_when_the_recheck_refuses() -> None:
    with aa_env() as e:
        first, second = _make_dir(), _make_dir()
        try:
            def make(req, n):
                if n <= 1:
                    return XVerdict(ok=True, argv=[PY, "-c", "pass"], cleanup_paths=(first,))
                return XVerdict(ok=False, reason="moved", cleanup_paths=(second,))
            e.prof.make = make
            armed(e)
            e.prof.verify_calls = 0
            with dialog():
                result = run(e)
            assert result["applied"] is False and "no longer applies" in result["error"]
            assert not Path(first).exists() and not Path(second).exists()
        finally:
            shutil.rmtree(first, ignore_errors=True)
            shutil.rmtree(second, ignore_errors=True)


def test_cleanup_paths_deleted_when_the_spawn_fails() -> None:
    with aa_env() as e:
        path = _make_dir()
        try:
            e.prof.make = lambda req, n: XVerdict(
                ok=True, argv=["definitely-not-a-real-program-xyzzy"], cleanup_paths=(path,))
            armed(e)
            with dialog():
                result = run(e)
            assert result["applied"] is False and "could not run" in result["error"]
            assert not Path(path).exists()
        finally:
            shutil.rmtree(path, ignore_errors=True)


def test_stderr_fatal_marker_turns_success_into_an_error() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: XVerdict(
            ok=True,
            argv=[PY, "-c", "import sys; print('done'); "
                            "sys.stderr.write('WARNING: policy was NOT applied')"],
            stderr_fatal_markers=("policy was not applied",))
        armed(e)
        with dialog():
            result = run(e)
        assert result["exit_code"] == 0
        assert result["stderr_fatal"] is True
        assert "error" in result and "fatal" in result["error"]


def test_stderr_without_a_marker_is_not_an_error() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: XVerdict(
            ok=True, argv=[PY, "-c", "import sys; sys.stderr.write('just noise')"],
            stderr_fatal_markers=("policy was not applied",))
        armed(e)
        with dialog():
            result = run(e)
        assert "error" not in result and "stderr_fatal" not in result


# ---------------------------------------------------------------------------
# Environment shaping
# ---------------------------------------------------------------------------

_DUMP_ENV = "import os, json; print(json.dumps(dict(os.environ)))"


def test_inject_secrets_false_keeps_the_var_out_but_still_redacts() -> None:
    with aa_env() as e:
        script = ("import os, json; print(json.dumps({'has': 'API_TOKEN' in os.environ, "
                  "'carried': os.environ['CARRIED']}))")
        e.prof.make = lambda req, n: Verdict(
            ok=True, argv=[PY, "-c", script], env={"CARRIED": TOKEN}, inject_secrets=False)
        armed(e)
        with dialog():
            result = run(e)
        assert result["exit_code"] == 0
        assert json.loads(result["stdout"]) == {"has": False, "carried": "[REDACTED:API_TOKEN]"}
        assert TOKEN not in result["stdout"]


def test_default_env_is_os_environ_plus_secrets() -> None:
    with aa_env() as e:
        e.prof.script = _DUMP_ENV
        armed(e)
        with dialog():
            result = run(e, tail_chars=200_000)
        child = json.loads(result["stdout"])
        assert child["API_TOKEN"] == "[REDACTED:API_TOKEN]"
        assert "SPECIAL" not in child                       # only_vars scopes it
        assert child.get("PATH") == os.environ.get("PATH")


def test_verdict_env_merges_onto_os_environ() -> None:
    with aa_env() as e:
        e.prof.make = lambda req, n: Verdict(
            ok=True, argv=[PY, "-c", _DUMP_ENV], env={"FROM_PROFILE": "1"})
        armed(e)
        with dialog():
            result = run(e, tail_chars=200_000)
        child = json.loads(result["stdout"])
        assert child["FROM_PROFILE"] == "1"
        assert child.get("PATH") == os.environ.get("PATH")


def test_replace_env_child_gets_exactly_verdict_env_plus_secrets() -> None:
    with aa_env() as e:
        base = {"FROM_PROFILE": "1", "OTHER": "two"}
        if os.name == "nt":
            base["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        e.prof.make = lambda req, n: Verdict(
            ok=True, argv=[PY, "-c", _DUMP_ENV], env=dict(base), replace_env=True)
        armed(e)
        with dialog():
            result = run(e, tail_chars=200_000)
        child = {k.upper(): v for k, v in json.loads(result["stdout"]).items()}
        expected = {k.upper(): v for k, v in base.items()}
        expected["API_TOKEN"] = "[REDACTED:API_TOKEN]"
        assert child == expected
