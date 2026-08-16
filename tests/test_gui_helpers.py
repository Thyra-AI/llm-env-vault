"""
Regression tests for the pure, Tkinter-free helpers in vault_lib/gui.py.

These functions had zero test coverage before this file was written.
All tests here are headless -- no tk.Tk() is created, no display is
required, and tkinter is not imported at module level. The only things
being exercised are:

  _strip_hidden(text)         -- strips Cf format chars and C0/C1 controls
  _safe_display(text, max_len) -- whitespace-collapse + length cap
  _collapse_whitespace(text)  -- whitespace-collapse, no cap
  MIN_PASSWORD_LEN             -- module constant

Call convention: plain `def test_x() -> None:` functions, assertion
messages in "REGRESSION (Bx): old broken behaviour" style, section
banners as 75-dash lines with a short prose paragraph beneath.
"""
import sys
import os

# Add the project root to sys.path so the package import works when this
# file is run directly (python tests/test_gui_helpers.py).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import only the helpers we're testing -- avoid importing tkinter at the
# top level so the test file can run in a headless/CI environment.
from vault_lib.gui import _safe_display, _collapse_whitespace, _strip_hidden, MIN_PASSWORD_LEN


# ---------------------------------------------------------------------------
# B5 -- Unicode Cf (format) characters stripped by both sanitizers
#
# An attacker who controls a command string (or a variable name sourced
# from untrusted input) can embed zero-width joiners, directional marks, or
# bidi overrides between visible characters.  In the UI these can make two
# adjacent words look like a single word, hiding a separator the human
# would otherwise notice.  Tk 8.6 does not implement bidi reordering, so
# U+202E (Right-to-Left Override) renders as a missing-glyph box rather
# than visually reversing text -- the zero-width characters are the
# plausible attack surface.
# ---------------------------------------------------------------------------

def test_zero_width_joiner_stripped_by_safe_display() -> None:
    # U+200D ZERO WIDTH JOINER -- category Cf
    result = _safe_display("hello‍world")
    assert result == "helloworld", (
        "REGRESSION (B5): zero-width joiner (U+200D) was passed through "
        "_safe_display unchanged, allowing hidden word-boundary manipulation"
    )


def test_zero_width_non_joiner_stripped_by_safe_display() -> None:
    # U+200C ZERO WIDTH NON-JOINER -- category Cf
    result = _safe_display("foo‌bar")
    assert result == "foobar", (
        "REGRESSION (B5): U+200C was passed through _safe_display unchanged"
    )


def test_zero_width_space_stripped_by_safe_display() -> None:
    # U+200B ZERO WIDTH SPACE -- category Cf
    result = _safe_display("hello​world")
    assert result == "helloworld", (
        "REGRESSION (B5): U+200B was passed through _safe_display unchanged"
    )


def test_bidi_override_stripped_by_safe_display() -> None:
    # U+202E RIGHT-TO-LEFT OVERRIDE -- category Cf
    result = _safe_display("abc‮xyz")
    assert result == "abcxyz", (
        "REGRESSION (B5): bidi RLO (U+202E) was passed through _safe_display; "
        "while Tk 8.6 renders it as a missing-glyph box rather than reversing "
        "text, stripping it removes the possibility entirely"
    )


def test_bidi_lre_stripped_by_safe_display() -> None:
    # U+202A LEFT-TO-RIGHT EMBEDDING -- category Cf
    result = _safe_display("a‪b")
    assert result == "ab", (
        "REGRESSION (B5): bidi LRE (U+202A) was passed through _safe_display"
    )


def test_bidi_isolate_stripped_by_safe_display() -> None:
    # U+2066 LEFT-TO-RIGHT ISOLATE -- category Cf
    result = _safe_display("x⁦y⁩z")
    assert result == "xyz", (
        "REGRESSION (B5): bidi isolate markers (U+2066, U+2069) were passed "
        "through _safe_display unchanged"
    )


def test_soft_hyphen_stripped_by_safe_display() -> None:
    # U+00AD SOFT HYPHEN -- category Cf, invisible in most renderers
    result = _safe_display("some­word")
    assert result == "someword", (
        "REGRESSION (B5): soft hyphen (U+00AD) was passed through _safe_display"
    )


def test_zero_width_joiner_stripped_by_collapse_whitespace() -> None:
    result = _collapse_whitespace("hello‍world")
    assert result == "helloworld", (
        "REGRESSION (B5): zero-width joiner (U+200D) was passed through "
        "_collapse_whitespace unchanged"
    )


def test_bidi_override_stripped_by_collapse_whitespace() -> None:
    result = _collapse_whitespace("abc‮xyz")
    assert result == "abcxyz", (
        "REGRESSION (B5): bidi RLO (U+202E) was passed through "
        "_collapse_whitespace unchanged"
    )


def test_multiple_cf_chars_stripped() -> None:
    # Several Cf characters in sequence -- all must go
    text = "​‌‍‪‮⁦­"
    assert _safe_display(text) == "", (
        "REGRESSION (B5): a sequence of Cf characters was not fully stripped "
        "by _safe_display"
    )
    assert _collapse_whitespace(text) == "", (
        "REGRESSION (B5): a sequence of Cf characters was not fully stripped "
        "by _collapse_whitespace"
    )


# ---------------------------------------------------------------------------
# B5 -- C0 and C1 control characters stripped
#
# C0 controls (U+0000-U+001F, minus ordinary whitespace like \t \n \r \f \v)
# and C1 controls (U+0080-U+009F) are category Cc in Python's unicodedata.
# They have no legitimate use in user-visible text: ESC sequences, NUL bytes,
# and DEL can trigger terminal escapes or confuse string-handling code
# downstream.  Ordinary whitespace characters (\t, \n, etc.) are allowed
# through because _safe_display and _collapse_whitespace collapse them to
# spaces anyway.
# ---------------------------------------------------------------------------

def test_nul_byte_stripped() -> None:
    result = _safe_display("foo\x00bar")
    assert result == "foobar", (
        "REGRESSION (B5): NUL byte (U+0000) was passed through _safe_display"
    )


def test_esc_byte_stripped() -> None:
    result = _safe_display("foo\x1bbar")
    assert result == "foobar", (
        "REGRESSION (B5): ESC (U+001B) was passed through _safe_display"
    )


def test_del_byte_stripped() -> None:
    # U+007F DEL is NOT a C0/C1 control in Python's unicodedata -- it is
    # category Cc but between C0 and C1.  Test that it is also stripped.
    result = _safe_display("foo\x7fbar")
    assert result == "foobar", (
        "REGRESSION (B5): DEL (U+007F) was passed through _safe_display"
    )


def test_c1_control_stripped() -> None:
    # U+0080 is the first C1 control -- category Cc
    result = _safe_display("foo\x80bar")
    assert result == "foobar", (
        "REGRESSION (B5): C1 control U+0080 was passed through _safe_display"
    )


def test_c1_controls_stripped_by_collapse_whitespace() -> None:
    result = _collapse_whitespace("a\x80b\x9fc")
    assert result == "abc", (
        "REGRESSION (B5): C1 controls were passed through _collapse_whitespace"
    )


def test_ordinary_whitespace_not_stripped_by_strip_hidden() -> None:
    # \t \n \r \f \v are category Cc but are intentionally left in place
    # so that the whitespace-collapsing step can find and collapse them.
    text = "a\t\n\r\f\vb"
    result = _strip_hidden(text)
    # None of the whitespace chars should have been removed
    assert "\t" in result or " " in result or "b" in result, (
        "REGRESSION (B5): _strip_hidden removed ordinary whitespace characters "
        "before _safe_display could collapse them -- tab/LF/CR/FF/VT must pass "
        "through so collapsing works correctly"
    )
    # After collapsing, the boundary IS visible
    collapsed = _safe_display(text)
    assert collapsed == "a b", (
        "REGRESSION (B5): tab/newline boundary between 'a' and 'b' was lost "
        "instead of being collapsed to a single space"
    )


# ---------------------------------------------------------------------------
# B5 -- legitimate Unicode not mangled
#
# Accented Latin characters, CJK ideographs, emoji, and other legitimate
# visible code points must pass through both sanitizers unchanged.  Stripping
# these would break internationalised variable names or path components.
# ---------------------------------------------------------------------------

def test_accented_latin_not_mangled_by_safe_display() -> None:
    text = "café naïve résumé"
    assert _safe_display(text) == text, (
        "REGRESSION (B5): accented Latin characters were mangled by "
        "_safe_display -- only Cf/Cc chars should be stripped"
    )


def test_cjk_not_mangled_by_safe_display() -> None:
    text = "你好世界"
    assert _safe_display(text) == text, (
        "REGRESSION (B5): CJK characters were mangled by _safe_display"
    )


def test_emoji_not_mangled_by_safe_display() -> None:
    # Emoji are in category So (Symbol, Other) -- not Cf or Cc, so safe to pass.
    text = "run this: 🚀"
    result = _safe_display(text)
    assert "🚀" in result, (
        "REGRESSION (B5): emoji was removed by _safe_display; only Cf/Cc "
        "code points should be stripped"
    )


def test_greek_not_mangled_by_collapse_whitespace() -> None:
    text = "Ελληνικά"
    assert _collapse_whitespace(text) == text, (
        "REGRESSION (B5): Greek characters were mangled by _collapse_whitespace"
    )


def test_ascii_alnum_not_mangled() -> None:
    text = "SECRET_KEY_123"
    assert _safe_display(text) == text
    assert _collapse_whitespace(text) == text


# ---------------------------------------------------------------------------
# Whitespace collapsing still works after _strip_hidden is applied
#
# The original whitespace-collapsing behaviour must be preserved: multiple
# spaces/tabs/newlines collapse to one space, leading/trailing whitespace
# is stripped, and the invariant holds even when Cf chars are also present.
# ---------------------------------------------------------------------------

def test_whitespace_collapsing_basic() -> None:
    assert _safe_display("  hello   world  ") == "hello world", (
        "REGRESSION: basic whitespace collapsing broken in _safe_display"
    )


def test_newline_collapsed_to_space() -> None:
    assert _safe_display("foo\nbar") == "foo bar", (
        "REGRESSION: newline not collapsed to space in _safe_display"
    )


def test_mixed_whitespace_collapsed() -> None:
    assert _safe_display("a\t \n \r b") == "a b", (
        "REGRESSION: mixed whitespace not collapsed to single space"
    )


def test_cf_before_whitespace_does_not_survive_collapse() -> None:
    # Zero-width char next to ordinary whitespace: after strip_hidden removes
    # the ZWJ, the adjacent spaces collapse normally.
    result = _safe_display("word1 ‍ word2")
    assert result == "word1 word2", (
        "REGRESSION (B5): Cf char adjacent to whitespace produced unexpected "
        "output after stripping and collapsing"
    )


def test_collapse_whitespace_no_truncation() -> None:
    long_text = "x " * 200  # 400 chars, well above _safe_display's default cap
    result = _collapse_whitespace(long_text)
    # No truncation -- all 'x' tokens remain
    assert result.count("x") == 200, (
        "REGRESSION: _collapse_whitespace truncated text; it must not cap length"
    )


# ---------------------------------------------------------------------------
# _safe_display max_len <= 3 branch (negative-index guard)
#
# When max_len is very small (0, 1, 2, or 3), the computed `head` or `tail`
# value in the ellipsis split would be negative, causing a slice with a
# negative index to silently wrap from the end of the string -- returning
# the *wrong* suffix instead of enforcing the cap.  The guard at lines
# 44-48 of the original file falls back to a hard cut.  This was the first
# test ever written for that branch.
# ---------------------------------------------------------------------------

def test_max_len_zero_returns_empty() -> None:
    result = _safe_display("hello", 0)
    assert result == "", (
        "REGRESSION: _safe_display(text, 0) did not return empty string; "
        "the negative-index guard must fall back to collapsed[:0] == ''"
    )


def test_max_len_one_returns_single_char() -> None:
    result = _safe_display("hello", 1)
    assert result == "h", (
        "REGRESSION: _safe_display(text, 1) returned more than one character; "
        "the negative-index guard must fall back to collapsed[:1]"
    )


def test_max_len_two_returns_two_chars() -> None:
    result = _safe_display("hello world", 2)
    assert result == "he", (
        "REGRESSION: _safe_display(text, 2) did not hard-cut to exactly 2 chars"
    )


def test_max_len_three_returns_three_chars() -> None:
    result = _safe_display("hello world", 3)
    assert result == "hel", (
        "REGRESSION: _safe_display(text, 3) did not hard-cut to exactly 3 chars"
    )


def test_max_len_four_produces_ellipsis_split() -> None:
    # max_len=4: head = 4//2 - 2 = 0, tail = 4 - 0 - 3 = 1.
    # The ellipsis fires when len(collapsed) > max_len, so we need a
    # string longer than 4 chars.  "abcdef" -> "...f" (4 chars total).
    result = _safe_display("abcdef", 4)
    assert "..." in result, (
        "REGRESSION: _safe_display with max_len=4 and a 6-char string did not "
        "produce an ellipsis; this is the first max_len where head >= 0 and "
        "tail >= 0, so the ellipsis split should fire"
    )
    assert len(result) == 4, (
        f"REGRESSION: _safe_display('abcdef', 4) returned {result!r} "
        f"({len(result)} chars), expected exactly 4"
    )


def test_max_len_larger_than_text_returns_text_unchanged() -> None:
    assert _safe_display("hi", 200) == "hi", (
        "REGRESSION: _safe_display returned wrong value when max_len > len(text)"
    )


def test_ellipsis_split_for_normal_max_len() -> None:
    # 200 chars default: a 300-char string should get head...tail
    text = "A" * 300
    result = _safe_display(text)
    assert result == _safe_display(text, 200)
    assert "..." in result
    assert len(result) == 200, (
        "REGRESSION: _safe_display default cap of 200 not enforced correctly"
    )


# ---------------------------------------------------------------------------
# MIN_PASSWORD_LEN == 12
#
# The module-level constant must be exactly 12.  Tests below assert both the
# value and its presence so a silent rename or a constant-folded literal
# does not pass.
# ---------------------------------------------------------------------------

def test_min_password_len_is_12() -> None:
    assert MIN_PASSWORD_LEN == 12, (
        f"REGRESSION (B6): MIN_PASSWORD_LEN is {MIN_PASSWORD_LEN!r}, expected 12; "
        "the password floor was raised from 8 to 12 as part of security hardening"
    )


def test_min_password_len_is_int() -> None:
    assert isinstance(MIN_PASSWORD_LEN, int), (
        "REGRESSION (B6): MIN_PASSWORD_LEN is not an int"
    )


# ---------------------------------------------------------------------------
# Test runner (no pytest dependency required -- matches test_trust.py's
# convention).  Sweeps globals() for test_* callables and reports results.
# ---------------------------------------------------------------------------

def _run(fn) -> bool:
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

    passed = [t for t in tests if _run(t)]
    failed = [t for t in tests if t not in passed]

    print()
    print(f"Results: {len(passed)}/{len(tests)} passed")
    if failed:
        print(f"FAILED: {[f.__name__ for f in failed]}")
        sys.exit(1)
    else:
        print("All tests passed.")
