"""
2.3.0: run_with_env scope is explicit, output size is the caller's choice, and
the whole redacted output of recent runs is searchable.

Covers:

  * only_vars / all_vars: a call with neither is refused (naming both
    options) before any dialog; both together is refused; all_vars=True is
    the old whole-vault behaviour; the trust signature still tells whole-vault
    from scoped.
  * tail_chars: bounded, applied AFTER redaction, absent from the trust
    signature; every foreground result carries run_id and per-stream
    chars / lines / truncated.
  * the in-memory store: a bounded ring (oldest run evicted), a per-stream cap
    that keeps the tail and says so, nothing on disk.
  * read_run_output: a secret that sits far outside the inline tail is
    redacted in a search and in a window; unknown / evicted run_id; bad and
    runaway regexes; background runs registered once their log is redacted.

Every test runs against an isolated throwaway vault (see test_trust.py) and a
monkeypatched dialog, so nothing touches this repo's real vault.

Runs under pytest or standalone (`python tests/test_run_output.py`).
"""
import contextlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import mcp_server  # noqa: E402
from vault_lib import runstore, trust  # noqa: E402
from test_trust import (BASE_SECRETS, _allow, _py, fake_dialog,  # noqa: E402
                        isolated_vault)

TOKEN = BASE_SECRETS["DOCKER_TEST_TOKEN"]      # tok-abc-123 (11 chars, redactable)
OTHER = BASE_SECRETS["OTHER_SECRET"]


def _cmd(code: str) -> list:
    return [sys.executable, "-c", code]


def _run(cmd, only_vars=("DOCKER_TEST_TOKEN",), **kw):
    return mcp_server._run_with_env_impl(list(cmd), None, False, None,
                                         list(only_vars) if only_vars is not None else None,
                                         **kw)


@contextlib.contextmanager
def small_store(**kw):
    original = mcp_server._RUN_OUTPUT
    mcp_server._RUN_OUTPUT = runstore.RunOutputStore(**kw)
    try:
        yield mcp_server._RUN_OUTPUT
    finally:
        mcp_server._RUN_OUTPUT = original


# A secret at the very start, then far more output than the inline tail holds.
_BIG = ("import os; t = os.environ['DOCKER_TEST_TOKEN']; print('leading', t); "
        "print('line-with-token-again ' + t); "
        "[print('filler line %d' % i) for i in range(1500)]; "
        "print('final line')")


# --------------------------------------------------------------------------
# only_vars / all_vars
# --------------------------------------------------------------------------

def test_neither_only_vars_nor_all_vars_is_refused_before_any_dialog() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_py(), None, False, None)
        assert calls == [], "a refused call must not open a dialog"
        assert "error" in r and not r.get("applied")
        assert "only_vars" in r["error"] and "all_vars=True" in r["error"]


def test_none_only_vars_without_all_vars_is_refused_even_when_passed_explicitly() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_py(), None, False, None, None, all_vars=False)
        assert calls == [] and "all_vars=True" in r["error"]


def test_all_vars_together_with_only_vars_is_refused() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_py(), None, False, None, ["DOCKER_TEST_TOKEN"],
                                              all_vars=True)
            r2 = mcp_server._run_with_env_impl(_py(), None, False, None, [], all_vars=True)
        assert calls == []
        assert "not both" in r["error"] and "not both" in r2["error"]


def test_empty_only_vars_is_refused_before_any_dialog() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_py(), None, False, None, [])
            r2 = mcp_server._run_with_env_impl(_py(), None, True, None, [])
        assert calls == [], "an empty scope must not cost a password prompt"
        assert "error" in r and not r.get("applied") and "empty" in r["error"]
        assert "error" in r2 and "empty" in r2["error"]


def test_all_vars_must_be_a_real_bool() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_py(), None, False, None, None, all_vars="yes")
        assert calls == [] and "all_vars" in r["error"]


def test_all_vars_true_injects_the_whole_vault() -> None:
    code = ("import os; print(os.environ.get('DOCKER_TEST_TOKEN') is not None, "
            "os.environ.get('OTHER_SECRET') is not None)")
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            r = mcp_server._run_with_env_impl(_cmd(code), None, False, None, all_vars=True)
        assert r["applied"] is True
        assert r["stdout"].strip() == "True True"
        assert calls[0]["only_vars"] is None, "the dialog must list the whole vault"


def test_only_vars_still_scopes_injection() -> None:
    code = ("import os; print(os.environ.get('DOCKER_TEST_TOKEN') is not None, "
            "os.environ.get('OTHER_SECRET') is not None)")
    with isolated_vault():
        with fake_dialog(_allow()):
            r = _run(_cmd(code))
        assert r["stdout"].strip() == "True False"


def test_signature_still_separates_whole_vault_from_scoped() -> None:
    whole = trust.make_signature(_py(), None, None, None, False)
    scoped = trust.make_signature(_py(), None, ["DOCKER_TEST_TOKEN"], None, False)
    nothing = trust.make_signature(_py(), None, [], None, False)
    assert len({whole, scoped, nothing}) == 3
    # The whole-vault key is the key it has always had: None in the only_vars slot.
    assert whole[2] is None


def test_whole_vault_grant_does_not_cover_a_scoped_call_and_vice_versa() -> None:
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            mcp_server._run_with_env_impl(_py(), None, False, None, all_vars=True)
            assert len(calls) == 1
            r = mcp_server._run_with_env_impl(_py(), None, False, None, ["DOCKER_TEST_TOKEN"])
            assert len(calls) == 2 and not r.get("auto_allowed")
            r = mcp_server._run_with_env_impl(_py(), None, False, None, all_vars=True)
            assert len(calls) == 2 and r.get("auto_allowed") is True


# --------------------------------------------------------------------------
# tail_chars + per-stream info
# --------------------------------------------------------------------------

def test_default_tail_is_4000_and_result_describes_each_stream() -> None:
    code = "import sys; print('x' * 9999); sys.stderr.write('e1\\ne2\\n')"
    with isolated_vault():
        with fake_dialog(_allow()):
            r = _run(_cmd(code))
    assert len(r["stdout"]) == 4000
    assert r["run_id"].startswith("run-")
    out, err = r["streams"]["stdout"], r["streams"]["stderr"]
    assert out == {"chars": 10000, "lines": 1, "truncated": True}
    assert err == {"chars": 6, "lines": 2, "truncated": False}
    assert r["stderr"] == "e1\ne2\n"


def test_tail_chars_picks_the_inline_tail_and_is_applied_after_redaction() -> None:
    code = "import os; print('a' * 50 + os.environ['DOCKER_TEST_TOKEN'] + 'b' * 5)"
    with isolated_vault():
        with fake_dialog(_allow()):
            r = _run(_cmd(code), tail_chars=30)
    assert r["stdout"] == "[REDACTED:DOCKER_TEST_TOKEN]bbbbb\n"[-30:]
    assert TOKEN not in json.dumps(r)
    # The info describes the whole redacted stream, not the tail.
    assert r["streams"]["stdout"]["chars"] > 30 and r["streams"]["stdout"]["truncated"]


def test_tail_chars_zero_returns_nothing_inline() -> None:
    with isolated_vault():
        with fake_dialog(_allow()):
            r = _run(_py(), tail_chars=0)
    assert r["applied"] is True
    assert r["stdout"] == ""
    assert r["streams"]["stdout"]["truncated"] is True and r["streams"]["stdout"]["chars"] == 3


def test_tail_chars_max_is_accepted_and_returns_everything_small() -> None:
    with isolated_vault():
        with fake_dialog(_allow()):
            r = _run(_py(), tail_chars=mcp_server.MAX_TAIL_CHARS)
    assert r["applied"] is True and r["stdout"] == "ok\n"
    assert r["streams"]["stdout"]["truncated"] is False


def test_tail_chars_out_of_range_is_rejected_before_any_dialog() -> None:
    with isolated_vault():
        with fake_dialog(_allow()) as calls:
            for bad in (-1, mcp_server.MAX_TAIL_CHARS + 1, True, "10", 1.5, None):
                r = _run(_py(), tail_chars=bad)
                assert "error" in r and "tail_chars" in r["error"], (bad, r)
        assert calls == []


def test_tail_chars_is_not_part_of_the_trust_signature() -> None:
    import inspect
    assert "tail_chars" not in inspect.signature(trust.make_signature).parameters
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            r1 = _run(_py(), tail_chars=10)
            assert r1["applied"] is True and len(calls) == 1
            r2 = _run(_py(), tail_chars=150000)
            assert len(calls) == 1, "a different tail_chars must not need a new approval"
            assert r2.get("auto_allowed") is True
            assert r2["run_id"] != r1["run_id"]


# --------------------------------------------------------------------------
# read_run_output: redaction beyond the inline tail
# --------------------------------------------------------------------------

def test_secret_beyond_the_tail_is_redacted_in_tail_search_and_window() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()):
                r = _run(_cmd(_BIG))
            assert r["streams"]["stdout"]["chars"] > 4000
            assert "leading" not in r["stdout"], "setup: the secret line is outside the tail"
            assert TOKEN not in json.dumps(r)

            hits = mcp_server._read_run_output_impl(r["run_id"], "stdout", pattern="token|leading",
                                                    context_lines=1)
            text = hits["streams"]["stdout"]["text"]
            assert "1: leading [REDACTED:DOCKER_TEST_TOKEN]" in text
            assert "2: line-with-token-again [REDACTED:DOCKER_TEST_TOKEN]" in text
            assert "3- filler line 0" in text, "context lines use '-'"
            assert TOKEN not in json.dumps(hits)

            win = mcp_server._read_run_output_impl(r["run_id"], "stdout", offset=0, limit=3)
            assert win["streams"]["stdout"]["text"].splitlines() == [
                "1: leading [REDACTED:DOCKER_TEST_TOKEN]",
                "2: line-with-token-again [REDACTED:DOCKER_TEST_TOKEN]",
                "3: filler line 0"]
            assert win["streams"]["stdout"]["next_offset"] == 3
            assert TOKEN not in json.dumps(win)


def test_window_paging_and_totals() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()):
                r = _run(_cmd(_BIG))
            win = mcp_server._read_run_output_impl(r["run_id"], "stdout", offset=1500, limit=100)
            s = win["streams"]["stdout"]
            assert s["total_lines"] == 1503 and s["total_chars"] == r["streams"]["stdout"]["chars"]
            assert s["text"].splitlines()[-1] == "1503: final line"
            assert s["next_offset"] is None


def test_search_limit_context_and_next_offset() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()):
                r = _run(_cmd("[print('hit %d' % i) if i % 10 == 0 else print('miss') "
                              "for i in range(100)]"))
            res = mcp_server._read_run_output_impl(r["run_id"], "stdout", pattern=r"^hit",
                                                   context_lines=1, limit=2)["streams"]["stdout"]
            lines = res["text"].splitlines()
            assert lines[0] == "1: hit 0" and lines[1] == "2- miss"
            assert "--" in lines and "11: hit 10" in lines
            assert res["matches_returned"] == 2
            assert res["next_offset"] is not None
            more = mcp_server._read_run_output_impl(r["run_id"], "stdout", pattern=r"^hit",
                                                    offset=res["next_offset"], limit=1)
            assert more["streams"]["stdout"]["text"].startswith("21: hit 20")


def test_max_chars_cuts_the_text_and_offers_a_way_to_continue() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()):
                r = _run(_cmd(_BIG))
            res = mcp_server._read_run_output_impl(r["run_id"], "stdout", offset=0, limit=1000,
                                                   max_chars=100)["streams"]["stdout"]
            assert len(res["text"]) <= 100
            assert res["next_offset"] is not None and res["next_offset"] < 1000


def test_stream_both_returns_each_stream() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()):
                r = _run(_cmd("import sys; print('to-out'); sys.stderr.write('to-err\\n')"))
            both = mcp_server._read_run_output_impl(r["run_id"])
            assert set(both["streams"]) == {"stdout", "stderr"}
            assert "to-out" in both["streams"]["stdout"]["text"]
            assert "to-err" in both["streams"]["stderr"]["text"]
            one = mcp_server._read_run_output_impl(r["run_id"], "stderr")
            assert set(one["streams"]) == {"stderr"}


def test_read_needs_no_dialog() -> None:
    with isolated_vault():
        with small_store():
            with fake_dialog(_allow()) as calls:
                r = _run(_py())
                n = len(calls)
                mcp_server._read_run_output_impl(r["run_id"], pattern="ok")
                assert len(calls) == n


def test_parameter_bounds_are_rejected() -> None:
    with small_store() as store:
        rid = store.put({"stdout": "a\nb\n", "stderr": ""})
        bad = [dict(stream="both2"), dict(context_lines=-1), dict(context_lines=21),
               dict(offset=-1), dict(limit=0), dict(limit=5001), dict(max_chars=0),
               dict(max_chars=200001), dict(limit=True), dict(max_chars="5")]
        for kw in bad:
            r = mcp_server._read_run_output_impl(rid, **kw)
            assert "error" in r, kw


# --------------------------------------------------------------------------
# unknown run_id, bad / runaway regex
# --------------------------------------------------------------------------

def test_unknown_run_id_is_a_clear_error() -> None:
    with small_store():
        r = mcp_server._read_run_output_impl("run-doesnotexist")
        assert "Unknown run_id" in r["error"] and "evicted" in r["error"]
        assert "error" in mcp_server._read_run_output_impl("")


def test_bad_regex_is_rejected_cleanly() -> None:
    with small_store() as store:
        rid = store.put({"stdout": "hello\n", "stderr": ""})
        for bad in ("(", "[a-", "*abc", "(?P<n>"):
            r = mcp_server._read_run_output_impl(rid, pattern=bad)
            assert "error" in r and "regular expression" in r["error"], (bad, r)


def test_catastrophic_patterns_are_refused_not_run() -> None:
    with small_store() as store:
        rid = store.put({"stdout": ("a" * 60 + "\n") * 50 + "ok\n", "stderr": ""})
        for bad in ("(a+)+$", "(a*)*b", "(a|aa)+$", "(.*)*x", "(\\d+,?)+;",
                    "a*a*a*a*b", "x" * 201):
            t0 = time.monotonic()
            r = mcp_server._read_run_output_impl(rid, pattern=bad)
            assert "error" in r, bad
            assert time.monotonic() - t0 < 1.0, f"{bad!r} was not refused up front"
        # Ordinary patterns still work.
        for good in (r"error|warn", r"(?i)fail(ed|ure)?", r"\d{3}-\d+", r"^ok$", r".*ok"):
            assert "error" not in mcp_server._read_run_output_impl(rid, pattern=good), good


def test_nested_and_alternated_repeats_are_refused_whatever_the_bound() -> None:
    with small_store() as store:
        rid = store.put({"stdout": ("a" * 40 + "\n") * 20, "stderr": ""})
        for bad in ("(a{0,50})+!", "(a{0,50})*!", "(a{1,2}){2,}!", "(a?)+!", "(a|a){0,99}!",
                    "(a|b|ab){2,5}!", "(?:ab|cd)*", "(?:x(a|aa))+", "((a+))+", "(?:a+b?){3}",
                    "(?=(a|aa)+)a"):
            t0 = time.monotonic()
            r = mcp_server._read_run_output_impl(rid, pattern=bad)
            assert "error" in r and "restricts" in r["error"], (bad, r)
            assert time.monotonic() - t0 < 1.0, f"{bad!r} was not refused up front"
        # A bounded repeat on its own, or an alternation of single characters
        # (a character set to the regex engine), is fine.
        for ok in (r"a{0,50}!", r"(a{0,2})?", r"[ab]{0,99}", r"(a|b){0,99}", r"fail(ed|ure)?"):
            assert "error" not in mcp_server._read_run_output_impl(rid, pattern=ok), ok


def test_common_legit_patterns_still_work() -> None:
    text = ("test_login PASSED\nFAILED tests/test_a.py::test_x\nERROR collecting b\n"
            "E   assert 1 == 2\n12 passed, 1 failed\nplain\n")
    with small_store() as store:
        rid = store.put({"stdout": text, "stderr": ""})
        for pat, expect in ((r"FAILED|ERROR", ["FAILED tests", "ERROR collecting"]),
                            (r"test_\w+", ["test_login", "test_a"]),
                            (r"^E\s+.*", ["assert 1 == 2"]),
                            (r"\d+ passed", ["12 passed"]),
                            (r"(?i)fail(ed|ure)?", ["FAILED", "1 failed"]),
                            (r"^plain$", ["plain"]),
                            (r".*assert.*", ["assert 1 == 2"])):
            res = mcp_server._read_run_output_impl(rid, "stdout", pattern=pat)
            assert "error" not in res, (pat, res)
            got = res["streams"]["stdout"]["text"]
            for e in expect:
                assert e in got, (pat, e, got)


def test_variable_width_repeats_are_capped_at_three_in_total() -> None:
    for bad in (".{0,100}" * 25, ".{0,100}" * 24 + "!", ".*.*.*.*!", r"\w+ \d+ \w+ \d+", "a?b?c?d?",
                "a{1,2}b{1,2}c{1,2}d{1,2}"):
        with pytest.raises(ValueError, match="variable-width"):
            runstore.validate_pattern(bad)
    # Fixed counts are free; three variable ones are fine.
    for ok in (r"FAILED|ERROR", r"test_\w+", r"^E\s+.*", r"\d+ passed", r"\w+ \d+ \w+",
               r"\d{4}-\d{2}-\d{2} \w+ .*", r"a{0,100}b{0,100}c{0,100}!"):
        runstore.validate_pattern(ok)


def test_slowest_accepted_pattern_on_a_long_line_is_fast() -> None:
    line = "a" * 1000
    s = runstore.RunOutput("r", {"stdout": line + "\n", "stderr": ""},
                           10_000_000).streams["stdout"]
    for pat in ("a*a*a*b", "a+a+a+b"):
        rx = runstore.validate_pattern(pat)
        t0 = time.monotonic()
        res = runstore.search(s, rx, 0, 0, 10, 1000)
        assert time.monotonic() - t0 < 2.0, pat
        assert res["matches_returned"] == 0 and not res.get("search_timed_out"), pat


def test_match_deep_in_a_long_line_is_found() -> None:
    line = "x" * 700 + "NEEDLE42" + "y" * 400
    s = runstore.RunOutput("r", {"stdout": "short\n" + line + "\nend\n", "stderr": ""},
                           10_000_000).streams["stdout"]
    res = runstore.search(s, runstore.validate_pattern(r"NEEDLE\d+"), 0, 0, 10, 5000)
    assert res["matches_returned"] == 1 and "NEEDLE42" in res["text"] and "2:" in res["text"]
    # `^` still means the start of the line, not the start of a window.
    res = runstore.search(s, runstore.validate_pattern(r"^NEEDLE"), 0, 0, 10, 5000)
    assert res["matches_returned"] == 0


def test_search_has_a_deadline() -> None:
    rx = runstore.validate_pattern("a.*b.*c")
    s = runstore.RunOutput("r", {"stdout": ("a" * 900 + "\n") * 2000, "stderr": ""},
                           10_000_000).streams["stdout"]
    t0 = time.monotonic()
    res = runstore.search(s, rx, 0, 0, 10, 1000, time_budget=0.05)
    assert time.monotonic() - t0 < 5
    assert res.get("search_timed_out") or res["next_offset"] is None


# --------------------------------------------------------------------------
# paging always advances
# --------------------------------------------------------------------------

def test_window_first_line_longer_than_max_chars_still_advances() -> None:
    with small_store() as store:
        rid = store.put({"stdout": "x" * 500 + "\nsecond\nthird\n", "stderr": ""})
        offset, seen, steps = 0, [], 0
        while offset is not None and steps < 10:
            res = mcp_server._read_run_output_impl(rid, "stdout", offset=offset,
                                                   max_chars=60)["streams"]["stdout"]
            assert res["text"] and len(res["text"]) <= 60, res
            assert res["lines_returned"] >= 1
            assert res["next_offset"] is None or res["next_offset"] > offset
            seen.append(res["text"])
            offset, steps = res["next_offset"], steps + 1
        assert offset is None, "paging never reached the end"
        assert "[line truncated]" in seen[0]
        assert any("second" in t for t in seen) and any("third" in t for t in seen)
        first = mcp_server._read_run_output_impl(rid, "stdout", offset=0,
                                                 max_chars=60)["streams"]["stdout"]
        assert first["line_truncated"] is True and first["next_offset"] == 1
        # Even a one-character budget makes progress.
        tiny = mcp_server._read_run_output_impl(rid, "stdout", offset=0,
                                                max_chars=1)["streams"]["stdout"]
        assert tiny["text"] and tiny["next_offset"] == 1


def test_search_first_match_larger_than_max_chars_still_advances() -> None:
    text = "x" * 400 + " hit one\nmiddle\nhit two\nhit three\n"
    with small_store() as store:
        rid = store.put({"stdout": text, "stderr": ""})
        offset, found, steps = 0, [], 0
        while offset is not None and steps < 10:
            res = mcp_server._read_run_output_impl(rid, "stdout", pattern="hit", context_lines=1,
                                                   offset=offset, max_chars=50)["streams"]["stdout"]
            assert res["text"] and res["matches_returned"] >= 1, res
            assert res["next_offset"] is None or res["next_offset"] > offset
            found.append(res["text"])
            offset, steps = res["next_offset"], steps + 1
        assert offset is None, "paging never reached the end"
        assert "[line truncated]" in found[0]
        joined = "\n".join(found)
        assert "hit two" in joined and "hit three" in joined


# --------------------------------------------------------------------------
# the store: ring buffer, per-stream cap, memory only
# --------------------------------------------------------------------------

def test_ring_buffer_evicts_the_oldest_run() -> None:
    store = runstore.RunOutputStore(max_runs=3)
    ids = [store.put({"stdout": f"run {i}\n", "stderr": ""}) for i in range(5)]
    assert store.ids() == ids[2:]
    for gone in ids[:2]:
        try:
            store.get(gone)
            raise AssertionError("evicted run still readable")
        except runstore.RunNotFound:
            pass
    assert store.get(ids[4]).streams["stdout"].text == "run 4\n"


def test_pending_reservation_survives_finished_runs_coming_and_going() -> None:
    store = runstore.RunOutputStore(max_runs=3)
    pending = store.reserve()
    done = [store.put({"stdout": f"run {i}\n", "stderr": ""}) for i in range(6)]
    assert pending in store.ids(), "a running background command lost its slot"
    assert store.ids() == [pending] + done[-2:]
    assert store.fulfil(pending, {"stdout": "late output\n"}) is True
    assert store.get(pending).streams["stdout"].text == "late output\n"


def test_pending_entries_are_bounded_separately_oldest_goes_first() -> None:
    store = runstore.RunOutputStore(max_runs=10, max_pending=3)
    kept = store.put({"stdout": "finished\n", "stderr": ""})
    pend = [store.reserve() for _ in range(5)]
    assert store.ids() == [kept] + pend[-3:], "finished runs are not evicted by pending ones"
    assert store.fulfil(pend[0], {"stdout": "x"}) is False
    assert store.fulfil(pend[1], {"stdout": "x"}) is False
    assert store.fulfil(pend[4], {"stdout": "ok\n"}) is True
    try:
        store.get(pend[0])
        raise AssertionError("evicted reservation is readable")
    except runstore.RunNotFound:
        pass


def test_all_pending_ring_still_respects_max_runs_and_keeps_the_new_entry() -> None:
    store = runstore.RunOutputStore(max_runs=2, max_pending=5)
    a, b, c = store.reserve(), store.reserve(), store.reserve()
    assert store.ids() == [b, c]
    d = store.put({"stdout": "now\n", "stderr": ""})
    assert store.ids() == [c, d]
    assert runstore.MAX_PENDING == 20


def test_default_ring_is_twenty_runs_and_evicted_id_errors_through_the_tool() -> None:
    assert runstore.MAX_RUNS == 20 and runstore.MAX_STREAM_CHARS == 10_000_000
    with isolated_vault():
        with small_store(max_runs=2):
            with fake_dialog(_allow(trust_it=True)):
                first = _run(_py())
                _run(_py())
                _run(_py())
            r = mcp_server._read_run_output_impl(first["run_id"])
            assert "Unknown run_id" in r["error"]


def test_stream_cap_keeps_the_tail_and_marks_it() -> None:
    text = "".join(f"line {i}\n" for i in range(1, 1001))
    store = runstore.RunOutputStore(max_stream_chars=500)
    rid = store.put({"stdout": text, "stderr": "small\n"})
    s = store.get(rid).streams["stdout"]
    assert s.retention_truncated and len(s.text) <= 500
    assert s.text.endswith("line 1000\n")
    assert s.text.startswith(f"line {s.first_line}\n"), "starts on a line boundary, numbers kept"
    assert not store.get(rid).streams["stderr"].retention_truncated
    with small_store(max_stream_chars=500) as st:
        rid = st.put({"stdout": text, "stderr": ""})
        res = mcp_server._read_run_output_impl(rid, "stdout", pattern="line 1000")["streams"]["stdout"]
        assert "1000: line 1000" in res["text"]
        assert res["retention_truncated"] is True and res["total_lines"] == 1000
        assert res["total_chars"] == len(text)


def test_nothing_is_written_to_disk() -> None:
    import os
    import tempfile
    marker = "unique-run-output-marker-4f9c2d"
    before = set(os.listdir(tempfile.gettempdir()))
    with isolated_vault() as tmp:
        with small_store():
            with fake_dialog(_allow()):
                _run(_cmd(f"print('{marker}')"))
        for root, _dirs, files in os.walk(tmp):
            for f in files:
                data = Path(root, f).read_bytes()
                assert marker.encode() not in data
    new = set(os.listdir(tempfile.gettempdir())) - before
    for name in new:
        p = Path(tempfile.gettempdir(), name)
        if p.is_file():
            assert marker.encode() not in p.read_bytes()


# --------------------------------------------------------------------------
# background runs
# --------------------------------------------------------------------------

def test_background_run_is_registered_only_after_its_log_is_redacted() -> None:
    code = "import os, time; time.sleep(0.5); print('bg', os.environ['DOCKER_TEST_TOKEN'])"
    with isolated_vault():
        with small_store() as store:
            with fake_dialog(_allow()):
                r = mcp_server._run_with_env_impl(_cmd(code), None, True, None,
                                                  ["DOCKER_TEST_TOKEN"])
            assert r["started"] is True and r["run_id"]
            early = mcp_server._read_run_output_impl(r["run_id"])
            assert "not exited yet" in early["error"], early
            deadline = time.time() + 20
            while time.time() < deadline:
                try:
                    store.get(r["run_id"])
                    break
                except runstore.RunPending:
                    time.sleep(0.1)
            res = mcp_server._read_run_output_impl(r["run_id"], "stdout", pattern="bg")
            assert "bg [REDACTED:DOCKER_TEST_TOKEN]" in res["streams"]["stdout"]["text"]
            assert TOKEN not in json.dumps(res)
            Path(r["log_file"]).unlink(missing_ok=True)


def test_background_run_that_fails_to_redact_is_never_registered() -> None:
    store = runstore.RunOutputStore()
    rid = store.reserve()
    store.abandon(rid)
    try:
        store.get(rid)
        raise AssertionError("abandoned run is readable")
    except runstore.RunNotFound:
        pass
    assert store.fulfil(rid, {"stdout": "late"}) is False


# --------------------------------------------------------------------------
# the standing instructions and the tool surface
# --------------------------------------------------------------------------

def test_agent_instructions_describe_the_new_contract() -> None:
    text = mcp_server._AGENT_INSTRUCTIONS
    for needle in ("all_vars=True", "only_vars", "read_run_output", "tail_chars"):
        assert needle in text, needle


def test_tool_signatures() -> None:
    import inspect
    p = inspect.signature(mcp_server.run_with_env).parameters
    assert p["all_vars"].default is False and p["tail_chars"].default == 4000
    q = inspect.signature(mcp_server.read_run_output).parameters
    assert list(q) == ["run_id", "stream", "pattern", "context_lines", "offset", "limit",
                       "max_chars"]


# ---------------------------------------------------------------------------
# Standalone runner (matches test_trust.py's convention)
# ---------------------------------------------------------------------------

def _run_one(fn) -> bool:
    print(f"Running {fn.__name__} ...")
    try:
        fn()
        print("  PASS")
        return True
    except Exception as exc:
        import traceback
        print(f"  FAIL: {exc}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = [t for t in tests if _run_one(t)]
    failed = [t for t in tests if t not in passed]
    print()
    print(f"Results: {len(passed)}/{len(tests)} passed")
    if failed:
        print(f"FAILED: {[f.__name__ for f in failed]}")
        sys.exit(1)
    print("All tests passed.")
