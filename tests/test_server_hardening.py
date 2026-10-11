"""Hardening of the loopback dialog server (see src/webui/server.py)."""
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.webui import server  # noqa: E402
from tests.test_webui_server import Harness, assets, _restore_seams  # noqa: E402,F401


def test_the_launch_code_is_never_printed_only_a_private_link_file(assets, capsys):
    hold = {}

    def on_ready(url, session):
        hold["url"], hold["session"] = url, session

    server._on_ready = on_ready
    server._open_url = lambda url: False  # no browser could be opened
    t = threading.Thread(target=lambda: server.run_flow(_one_screen()),
                         daemon=True)
    t.start()
    deadline = time.time() + 5
    while "url" not in hold and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.4)
    err = capsys.readouterr().err
    code = hold["url"].split("#c=")[1]
    assert code not in err and "127.0.0.1" not in err
    path = Path(err.rsplit(": ", 1)[1].strip())
    assert path.read_text().strip() == hold["url"]
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    hold["session"].cancel("closed")
    t.join(8)
    assert not path.parent.exists()  # removed when the dialog ended


def _one_screen():
    from src.webui import schema
    yield schema.screen("unlock.title", fields=[], actions=[schema.action("cancel", "common.cancel")])


def test_no_browser_env_goes_through_the_file_not_stderr(monkeypatch):
    monkeypatch.setenv("THYRA_VAULT_NO_BROWSER", "1")
    assert server._default_open("http://127.0.0.1:1/#c=X") is False
    path = server._write_link_file("http://127.0.0.1:1/#c=X")
    try:
        assert Path(path).read_text().strip().endswith("#c=X")
    finally:
        server._forget_link_file("http://127.0.0.1:1/#c=X")
    assert not Path(path).exists()


def test_concurrent_requests_with_the_valid_code_yield_one_token(assets):
    h = Harness()
    n = 12
    barrier = threading.Barrier(n)
    results = []

    def go():
        barrier.wait()
        results.append(h.request("POST", "/api/exchange", {"code": h.code})[0])

    threads = [threading.Thread(target=go) for _ in range(n)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert sorted(results) == [200] + [403] * (n - 1)
    h.session.cancel("closed")
    h.finish()


def test_bad_codes_back_off_with_growing_delay(assets):
    h = Harness(server.Limits(launch_timeout=30, max_bad_codes=1, lockout_base=0.2, lockout_max=5))
    h.request("POST", "/api/exchange", {"code": "a"})        # free guess
    h.request("POST", "/api/exchange", {"code": "b"})        # 403, locks for 0.2s
    first = h.session.lockout_until
    time.sleep(0.3)
    h.request("POST", "/api/exchange", {"code": "c"})        # locks for 0.4s
    assert h.session.lockout_until - time.monotonic() > 0.2 and h.session.lockout_until > first
    h.session.cancel("closed")
    h.finish()


def test_the_valid_code_still_connects_while_the_exchange_is_locked_out(assets):
    """A local process must not be able to keep the human out of their own dialog with bad codes."""
    h = Harness(server.Limits(launch_timeout=30, max_bad_codes=1, lockout_base=30, lockout_max=30))
    for _ in range(3):
        h.request("POST", "/api/exchange", {"code": "guess"})
    assert h.request("POST", "/api/exchange", {"code": "guess"})[0] == 429
    assert h.request("POST", "/api/exchange", {"code": h.code})[0] == 200
    h.session.cancel("closed")
    h.finish()


def test_a_slow_dribbling_request_is_cut_off_by_the_overall_deadline(assets, monkeypatch):
    monkeypatch.setattr(server, "REQUEST_DEADLINE", 0.8)
    h = Harness()
    s = socket.create_connection(("127.0.0.1", h.port), timeout=5)
    start = time.time()
    closed = False
    try:
        for ch in b"GET / HTTP/1.1\r\nHost: x\r\nX-A: aaaaaaaaaaaaaaaaaaaaaaaaa\r\n":
            s.sendall(bytes([ch]))
            time.sleep(0.15)  # each recv is far under the per-recv timeout
    except OSError:
        closed = True
    else:
        closed = s.recv(10) == b""
    s.close()
    assert closed and time.time() - start < 4
    h.session.cancel("closed")
    h.finish()


def test_connections_beyond_the_cap_are_closed_immediately(assets, monkeypatch):
    monkeypatch.setattr(server, "MAX_CONNECTIONS", 3)
    h = Harness()
    held = [socket.create_connection(("127.0.0.1", h.port)) for _ in range(3)]
    time.sleep(0.3)
    extra = socket.create_connection(("127.0.0.1", h.port), timeout=3)
    try:
        assert extra.recv(10) == b""  # closed with no thread and no response
    except ConnectionError:
        pass
    extra.close()
    [c.close() for c in held]
    time.sleep(0.3)
    h.connect()  # slots were released
    h.session.cancel("closed")
    h.finish()


def test_signal_tree_skips_a_child_that_already_exited(monkeypatch):
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    calls = []
    monkeypatch.setattr(server.os, "killpg", lambda *a: calls.append(a))
    server.AppWindow(proc, "/nonexistent", tracked=True)._signal_tree(hard=True)
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="posix launch path")
def test_a_browser_that_exits_zero_at_once_is_a_failed_launch(monkeypatch):
    class Quick:
        pid = 1
        def wait(self, timeout=None): return 0
        def poll(self): return 0

    monkeypatch.setattr(server, "find_app_browser", lambda: "/bin/true")
    monkeypatch.setattr(server.subprocess, "Popen", lambda *a, **k: Quick())
    made = []
    real = server.tempfile.mkdtemp
    monkeypatch.setattr(server.tempfile, "mkdtemp", lambda **k: made.append(real(**k)) or made[-1])
    assert server._launch_app_window("file:///x") is None
    assert made and not os.path.exists(made[0])  # profile cleaned up


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux-only")
def test_the_browser_is_started_with_parent_death_signal_and_own_session(monkeypatch):
    seen = {}

    class Fake:
        pid = 1
        def wait(self, timeout=None): raise subprocess.TimeoutExpired("x", 1)
        def poll(self): return None

    def popen(argv, **kw):
        seen.update(kw)
        return Fake()

    monkeypatch.setattr(server, "find_app_browser", lambda: "/bin/true")
    monkeypatch.setattr(server.subprocess, "Popen", popen)
    win = server._launch_app_window("file:///x")
    try:
        assert seen["start_new_session"] is True and seen["preexec_fn"] is server._die_with_parent
    finally:
        import shutil
        shutil.rmtree(win.profile, ignore_errors=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux-only")
def test_die_with_parent_sets_the_signal_in_the_child():
    code = ("import ctypes,signal,sys; sys.path.insert(0,%r)\n"
            "from src.webui import server\n"
            "server._die_with_parent()\n"
            "v=ctypes.c_int(0); ctypes.CDLL(None).prctl(2, ctypes.byref(v))\n"
            "print(v.value==signal.SIGKILL)") % str(Path(__file__).parent.parent)
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True
                          ).stdout.strip() == "True"


def test_the_window_is_closed_when_the_server_thread_dies(assets, monkeypatch):
    h = Harness()
    h.connect()
    # Simulate the serve thread dying: shut the server loop down under run_flow.
    import gc
    srv = next(o for o in gc.get_objects()
               if isinstance(o, server._BoundedServer) and o.server_address[1] == h.port)
    srv.shutdown()
    h.finish(timeout=8)  # run_flow noticed and tore everything down
    assert h.session.reason == "error"


def test_stale_temp_dirs_of_ours_are_swept_and_fresh_or_foreign_ones_are_not(tmp_path, monkeypatch):
    monkeypatch.setattr(server.tempfile, "gettempdir", lambda: str(tmp_path))
    old = tmp_path / "thyra-vault-start-old"
    old2 = tmp_path / "thyra-vault-window-old"
    fresh = tmp_path / "thyra-vault-start-fresh"
    other = tmp_path / "unrelated-old"
    target = tmp_path / "real"
    for d in (old, old2, fresh, other, target):
        d.mkdir()
    link = tmp_path / "thyra-vault-start-link"
    link.symlink_to(target, target_is_directory=True)
    ancient = time.time() - 3 * 24 * 3600
    for d in (old, old2, other, target):
        os.utime(d, (ancient, ancient))
    os.utime(link, (ancient, ancient), follow_symlinks=False)
    server._sweep_stale_temp()
    assert not old.exists() and not old2.exists()
    assert fresh.exists() and other.exists() and target.exists() and link.is_symlink()
