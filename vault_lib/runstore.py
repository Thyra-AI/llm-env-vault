"""In-memory store of the REDACTED output of recent run_with_env calls.

run_with_env hands an agent only the tail of a command's output (default
4000 characters), which is rarely the part that matters for a long build or
test run. This module keeps the whole of each run's output -- after the server
has redacted vault values from it -- so the agent can search it and read windows
of it through the read_run_output tool instead of re-running the command (which
means another password prompt) just to see a different part.

What lives here is deliberately narrow:

  * Only redacted text is ever put in. Callers redact first and truncate
    second; nothing in this module sees an unredacted value, so nothing it
    returns can contain one.
  * Memory only. Nothing here is ever written to disk, and the whole store is
    gone when the server process exits.
  * Bounded. A ring of MAX_RUNS runs (oldest evicted first) and a per-stream
    cap of MAX_STREAM_CHARS characters (the TAIL is kept, and the stream is
    marked so a reader knows the start is missing).

The regular-expression search is bounded too. Python's `re` cannot be
interrupted, and the wall-clock deadline below is only checked between lines,
so a single rx.search call on a pathological pattern could hang the server.
validate_pattern therefore DELIBERATELY RESTRICTS what a pattern may contain,
rather than trying to time it out: no repeat of any kind inside a repeat that
can match more than once, no alternation inside such a repeat, at most
MAX_UNBOUNDED_REPEATS unbounded repeats, and a length cap. Literals, classes,
`.*`, anchors, single-level repeats like \\d+, and top-level alternation
(`FAILED|ERROR`) all still work. The search matches each line against only its
first MATCH_LINE_CAP characters and stops at a deadline between lines.
"""
import re
import secrets
import threading
import time
from collections import OrderedDict
from typing import Optional

MAX_RUNS = 20
# Reservations for background runs that have not exited yet. Bounded on their
# own so a burst of long-running background commands cannot crowd every
# finished run out of the ring (and finished runs cannot evict a reservation
# whose output is still to come).
MAX_PENDING = 20
MAX_STREAM_CHARS = 10_000_000

# Bounds for the search tool. Together they keep a hostile or careless pattern
# from holding the server: the pattern is small, shapes that are exponential
# are refused, a line is matched on a bounded prefix, and the whole scan has
# a deadline.
MAX_PATTERN_LEN = 200
MAX_UNBOUNDED_REPEATS = 3
MATCH_LINE_CAP = 1000
SEARCH_TIME_BUDGET = 5.0
# A counted repeat above this (x{1,5000}) is as unbounded as * for the purpose
# of blow-up, so it is treated that way.
_BIG_REPEAT = 100

STREAMS = ("stdout", "stderr")


class RunNotFound(KeyError):
    """The run_id is unknown, has been evicted, or never existed."""


class RunPending(Exception):
    """The run is registered but its (background) output is not final yet."""


def split_lines(text: str) -> list:
    """Lines of text, split on '\\n' only, with no phantom empty last line.
    One definition used for counting, numbering and rendering, so a number
    reported in one place means the same line in another."""
    if not text:
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _cap(text: str, limit: int) -> tuple:
    """(kept, dropped_chars, first_line) -- keeps the tail, starting on a line
    boundary where it can, so the result does not open mid-line."""
    if len(text) <= limit:
        return text, 0, 1
    cut = len(text) - limit
    kept = text[cut:]
    if text[cut - 1] != "\n":
        nl = kept.find("\n")
        if nl != -1:
            cut += nl + 1
            kept = text[cut:]
    return kept, cut, text.count("\n", 0, cut) + 1


class _Stream:
    __slots__ = ("text", "dropped_chars", "first_line")

    def __init__(self, text: str, max_chars: int):
        self.text, self.dropped_chars, self.first_line = _cap(text, max_chars)

    @property
    def retention_truncated(self) -> bool:
        return self.dropped_chars > 0


class RunOutput:
    __slots__ = ("run_id", "streams", "pending")

    def __init__(self, run_id: str, streams: Optional[dict], max_chars: int):
        self.run_id = run_id
        self.pending = streams is None
        self.streams = {name: _Stream((streams or {}).get(name, ""), max_chars)
                        for name in STREAMS}


class RunOutputStore:
    def __init__(self, max_runs: int = MAX_RUNS, max_stream_chars: int = MAX_STREAM_CHARS,
                 max_pending: int = MAX_PENDING):
        self.max_runs = max_runs
        self.max_pending = max_pending
        self.max_stream_chars = max_stream_chars
        self._runs: "OrderedDict[str, RunOutput]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def new_id() -> str:
        return "run-" + secrets.token_hex(6)

    def _oldest(self, pending: bool, skip: Optional[str] = None) -> Optional[str]:
        for rid, r in self._runs.items():
            if r.pending == pending and rid != skip:
                return rid
        return None

    def _insert(self, run: RunOutput) -> None:
        """Add a run (lock held). The ring evicts the oldest FINISHED run first,
        so the reservation of a still-running background command survives
        finished runs coming and going. Pending entries have their own cap; one
        pushed out by it is gone, and its fulfil() then returns False. Only when
        nothing else can go (the ring is all pending) does a pending one yield
        to the ring size -- never the entry being inserted."""
        self._runs[run.run_id] = run
        if run.pending:
            while sum(1 for r in self._runs.values() if r.pending) > self.max_pending:
                victim = self._oldest(True, skip=run.run_id) or run.run_id
                del self._runs[victim]
                if victim == run.run_id:
                    return
        while len(self._runs) > self.max_runs:
            victim = (self._oldest(False, skip=run.run_id)
                      or self._oldest(True, skip=run.run_id)
                      or run.run_id)
            del self._runs[victim]
            if victim == run.run_id:
                return

    def put(self, streams: dict, run_id: Optional[str] = None) -> str:
        """Register a finished run's redacted streams. Returns its run_id."""
        run_id = run_id or self.new_id()
        run = RunOutput(run_id, streams, self.max_stream_chars)
        with self._lock:
            self._insert(run)
        return run_id

    def reserve(self, run_id: Optional[str] = None) -> str:
        """Register a run whose output is not final yet (a background run)."""
        run_id = run_id or self.new_id()
        with self._lock:
            self._insert(RunOutput(run_id, None, self.max_stream_chars))
        return run_id

    def fulfil(self, run_id: str, streams: dict) -> bool:
        """Fill in a reserved run. False if it was evicted meanwhile."""
        run = RunOutput(run_id, streams, self.max_stream_chars)
        with self._lock:
            existing = self._runs.get(run_id)
            if existing is None or not existing.pending:
                return False
            self._runs[run_id] = run
            return True

    def abandon(self, run_id: str) -> None:
        """Drop a reserved run that will never have redacted output."""
        with self._lock:
            existing = self._runs.get(run_id)
            if existing is not None and existing.pending:
                del self._runs[run_id]

    def get(self, run_id: str) -> RunOutput:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None:
            raise RunNotFound(run_id)
        if run.pending:
            raise RunPending(run_id)
        return run

    def ids(self) -> list:
        with self._lock:
            return list(self._runs)


# -- pattern validation ------------------------------------------------------

def _sre_parse():
    # `re._parser` from 3.11, `sre_parse` before; both are internal, so the
    # analysis below is skipped (leaving the other bounds in force) if neither
    # is importable.
    parser = getattr(re, "_parser", None)
    if parser is not None:
        return parser
    try:
        import sre_parse  # noqa: WPS433
        return sre_parse
    except ImportError:
        return None


def _is_unbounded(max_count, maxrepeat) -> bool:
    return max_count >= maxrepeat or max_count > _BIG_REPEAT


def _walk(node, parser, in_multi: bool, counter: list) -> Optional[str]:
    """Returns a problem description, or None. counter[0] counts unbounded
    repeats. in_multi is true inside a repeat whose max is more than 1 (the
    only kind that can re-enter its body and so multiply the ways to match).

    Deliberately strict: inside such a repeat NO other repeat is allowed,
    whatever its bound ((a{0,50})+ is as bad as (a+)+ for the price of being
    harder to spot), and no alternation ((a|a){0,99} backtracks exponentially
    despite the small bound). A character set like [ab] is not an alternation
    and stays fine."""
    SubPattern = parser.SubPattern
    repeat_ops = {parser.MAX_REPEAT, parser.MIN_REPEAT}
    possessive = getattr(parser, "POSSESSIVE_REPEAT", None)
    if possessive is not None:
        repeat_ops.add(possessive)
    branch_ops = {parser.BRANCH}
    conditional = getattr(parser, "GROUPREF_EXISTS", None)
    if conditional is not None:
        branch_ops.add(conditional)     # (?(1)a|b) is an alternation in all but name
    for op, av in node:
        if op in repeat_ops:
            lo, hi, body = av
            if in_multi:
                return "a repeat nested inside another repeat"
            if _is_unbounded(hi, parser.MAXREPEAT):
                counter[0] += 1
            problem = _walk(body, parser, hi > 1, counter)
            if problem:
                return problem
            continue
        if op in branch_ops and in_multi:
            return "an alternation inside a repeat"
        # Descend into anything else that carries sub-patterns (groups,
        # lookarounds, branches, conditionals, atomic groups).
        stack = [av]
        while stack:
            item = stack.pop()
            if isinstance(item, SubPattern):
                problem = _walk(item, parser, in_multi, counter)
                if problem:
                    return problem
            elif isinstance(item, (list, tuple)):
                stack.extend(item)
    return None


def validate_pattern(pattern: str) -> "re.Pattern":
    """Compile a search pattern, refusing the shapes that can run away. Python's
    `re` cannot be interrupted, so this static check is the only protection
    against a single rx.search call hanging, and it is deliberately strict:
    patterns are RESTRICTED, not merely screened for known-bad shapes.
    Raises ValueError with a message meant for the agent."""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string.")
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError(f"pattern is too long ({len(pattern)} characters; the limit is "
                         f"{MAX_PATTERN_LEN}).")
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"pattern is not a valid regular expression: {e}") from None
    except (OverflowError, RecursionError):
        raise ValueError("pattern is too complex to compile.") from None
    parser = _sre_parse()
    if parser is not None:
        try:
            tree = parser.parse(pattern)
            counter = [0]
            problem = _walk(tree, parser, False, counter)
        except Exception:  # internal API drifted: fall back to the other bounds
            problem, counter = None, [0]
        if problem:
            raise ValueError(
                f"pattern rejected: it contains {problem}, which can take exponential time "
                f"on a long line, so read_run_output deliberately restricts patterns. Use a "
                f"simpler one (a literal, a character class, `.*`, a single-level repeat such "
                f"as \\d+, or an alternation that is not inside a repeat, e.g. FAILED|ERROR).")
        if counter[0] > MAX_UNBOUNDED_REPEATS:
            raise ValueError(
                f"pattern rejected: it has {counter[0]} unbounded repeats (*, +, or a large "
                f"{{n,m}}); the limit is {MAX_UNBOUNDED_REPEATS}.")
    return rx


# -- rendering ---------------------------------------------------------------

TRUNCATION_MARK = "…[line truncated]"


class _Budget:
    def __init__(self, chars: int):
        self.left = chars
        self.exhausted = False
        self.truncated_line = False
        self.parts: list = []

    def add(self, line: str, force: bool = False) -> bool:
        """Append a rendered line (a newline is added). False once full.

        A line that does not fit is cut to the budget and ends in a truncation
        marker. With force=True something is appended even when the budget is
        down to its last character or two -- used for the first line of a
        page, which must always be shown so that paging can advance past it.
        """
        if self.exhausted:
            return False
        need = len(line) + 1
        if need > self.left:
            if force or self.left > 1:
                room = max(self.left - 1, 0)
                if room >= len(TRUNCATION_MARK) + 20:
                    self.parts.append(line[:room - len(TRUNCATION_MARK)] + TRUNCATION_MARK)
                else:
                    self.parts.append(line[:max(room - 1, 0)] + "…")
                self.truncated_line = True
            self.exhausted = True
            self.left = 0
            return False
        self.parts.append(line)
        self.left -= need
        return True

    def text(self) -> str:
        return "\n".join(self.parts)


def _fmt(num: int, line: str, is_match: bool) -> str:
    return f"{num}{':' if is_match else '-'} {line.rstrip(chr(13))}"


def read_window(stream: _Stream, offset: int, limit: int, max_chars: int) -> dict:
    """A window of `limit` lines starting at absolute 0-based line `offset`."""
    lines = split_lines(stream.text)
    first = stream.first_line
    start = max(offset - (first - 1), 0)
    budget = _Budget(max_chars)
    emitted = 0
    for i in range(start, min(start + limit, len(lines))):
        # The first line is always emitted (cut to the budget if it is longer),
        # so a line longer than max_chars cannot leave paging stuck on it.
        if not budget.add(_fmt(first + i, lines[i], True), force=(emitted == 0)):
            if emitted == 0:
                emitted = 1
            break
        emitted += 1
    end = start + emitted
    out = {
        "mode": "window",
        "total_lines": first - 1 + len(lines),
        "lines_returned": emitted,
        "text": budget.text(),
        "next_offset": (first - 1 + end) if end < len(lines) else None,
        "first_line_available": first,
    }
    if budget.truncated_line and emitted == 1:
        out["line_truncated"] = True
    return out


def search(stream: _Stream, rx: "re.Pattern", context: int, offset: int, limit: int,
           max_chars: int, time_budget: float = SEARCH_TIME_BUDGET) -> dict:
    """Matching lines (at most `limit`) from absolute 0-based line `offset`,
    each with `context` lines either side, numbered grep-style (`N: match`,
    `N- context`)."""
    lines = split_lines(stream.text)
    first = stream.first_line
    start = max(offset - (first - 1), 0)
    deadline = time.monotonic() + time_budget
    matches: list = []
    scanned_to = start
    timed_out = False
    long_lines = False
    for i in range(start, len(lines)):
        if len(matches) >= limit:
            break
        if time.monotonic() > deadline:
            timed_out = True
            break
        line = lines[i]
        if len(line) > MATCH_LINE_CAP:
            long_lines = True
            line = line[:MATCH_LINE_CAP]
        if rx.search(line):
            matches.append(i)
        scanned_to = i + 1
    budget = _Budget(max_chars)
    shown = set()
    match_set = set(matches)
    prev = None
    emitted_matches = 0
    for m in matches:
        lo, hi = max(m - context, 0), min(m + context, len(lines) - 1)
        for i in range(lo, hi + 1):
            if i in shown:
                continue
            if prev is not None and i > prev + 1 and not budget.exhausted:
                if not budget.add("--"):
                    break
            if not budget.add(_fmt(first + i, lines[i], i in match_set)):
                break
            shown.add(i)
            prev = i
        if budget.exhausted:
            break
        emitted_matches += 1
    forced_cut = False
    if matches and emitted_matches == 0:
        # The first match's block does not fit in max_chars. Show the match
        # line alone, cut to the budget, and move past it -- otherwise the
        # caller would be handed the same next_offset forever.
        budget = _Budget(max_chars)
        budget.add(_fmt(first + matches[0], lines[matches[0]], True), force=True)
        forced_cut = budget.truncated_line
        emitted_matches = 1
    out = {
        "mode": "search",
        "total_lines": first - 1 + len(lines),
        "matches_returned": emitted_matches,
        "text": budget.text(),
        "next_offset": None,
        "first_line_available": first,
    }
    if emitted_matches < len(matches):
        # The character budget ran out part-way: resume at the first match
        # that was not (fully) shown.
        out["next_offset"] = first - 1 + matches[emitted_matches]
    elif timed_out or (len(matches) >= limit and scanned_to < len(lines)):
        out["next_offset"] = first - 1 + scanned_to
    if forced_cut:
        out["line_truncated"] = True
    if timed_out:
        out["search_timed_out"] = True
    if long_lines:
        out["long_lines_note"] = (f"Lines longer than {MATCH_LINE_CAP} characters were "
                                  f"matched on their first {MATCH_LINE_CAP} only.")
    return out
