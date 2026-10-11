"""Server-side clipboard: the value goes to a tool on stdin, never on a command line,
and is wiped only if it is still what we put there."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from thyra_vault.webui import clipboard  # noqa: E402

SECRET = "tok-abcdefgh-123456"


def _writer_backend(target: Path):
    """A stand-in clipboard tool: a Python one-liner that stores its stdin in a file."""
    code = f"import sys; open({str(target)!r}, 'wb').write(sys.stdin.buffer.read())"
    return ([sys.executable, "-c", code], None)


def test_the_value_reaches_the_tool_on_stdin_and_never_on_its_command_line(tmp_path, monkeypatch):
    out = tmp_path / "clip.bin"
    backend = _writer_backend(out)
    monkeypatch.setattr(clipboard, "backends", lambda *a, **k: [backend])
    assert clipboard.copy(SECRET) is None
    assert out.read_bytes() == SECRET.encode()
    assert all(SECRET not in part for part in backend[0])


def test_non_ascii_values_survive(tmp_path, monkeypatch):
    out = tmp_path / "clip.bin"
    monkeypatch.setattr(clipboard, "backends", lambda *a, **k: [_writer_backend(out)])
    assert clipboard.copy("pässwörd-€-🔑") is None
    assert out.read_bytes().decode("utf-8") == "pässwörd-€-🔑"


def test_no_tool_means_unavailable(monkeypatch):
    monkeypatch.setattr(clipboard, "backends", lambda *a, **k: [])
    assert clipboard.copy(SECRET) == "unavailable"


def test_a_tool_that_fails_means_failed(monkeypatch):
    monkeypatch.setattr(clipboard, "backends", lambda *a, **k: [([sys.executable, "-c", "raise SystemExit(3)"], None)])
    assert clipboard.copy(SECRET) == "failed"


def test_a_missing_binary_falls_through_to_the_next_tool(tmp_path, monkeypatch):
    out = tmp_path / "clip.bin"
    monkeypatch.setattr(clipboard, "backends", lambda *a, **k: [(["/nonexistent/clip-tool"], None), _writer_backend(out)])
    assert clipboard.copy(SECRET) is None
    assert out.read_bytes() == SECRET.encode()


def test_backend_choice_by_platform_and_session():
    have_all = lambda name: f"/usr/bin/{name}"  # noqa: E731
    assert clipboard.backends("darwin", {}, have_all)[0][0] == ["pbcopy"]
    win = clipboard.backends("win32", {}, have_all)[0][0]
    assert win[0] == "powershell" and "Set-Clipboard" in win[-1]
    wayland = clipboard.backends("linux", {"WAYLAND_DISPLAY": "wayland-0"}, have_all)
    assert wayland[0][0][0] == "wl-copy"
    x11 = clipboard.backends("linux", {}, have_all)
    assert x11[0][0][0] == "xclip"
    assert clipboard.backends("linux", {}, lambda name: None) == []


def test_clear_empties_the_clipboard_only_if_it_still_holds_our_value():
    written = []
    assert clipboard.clear_if_unchanged(SECRET, reader=lambda: SECRET, writer=lambda t: written.append(t)) is True
    assert written == [" "]


def test_clear_leaves_something_the_user_copied_since():
    written = []
    assert clipboard.clear_if_unchanged(SECRET, reader=lambda: "something else", writer=lambda t: written.append(t)) is False
    assert written == []


def test_clear_ignores_a_trailing_newline_some_tools_add():
    written = []
    clipboard.clear_if_unchanged(SECRET, reader=lambda: SECRET + "\n", writer=lambda t: written.append(t))
    assert written == [" "]


def test_clear_when_the_clipboard_cannot_be_read_still_wipes():
    written = []
    clipboard.clear_if_unchanged(SECRET, reader=lambda: None, writer=lambda t: written.append(t))
    assert written == [" "]


def test_clear_later_is_a_cancellable_daemon_timer():
    timer = clipboard.clear_later(SECRET, 3600)
    try:
        assert timer.daemon and timer.is_alive()
    finally:
        timer.cancel()
