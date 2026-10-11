"""Idle auto-lock on every screen, and the clipboard wipe on SIGTERM / SIGHUP."""
import signal
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import workspace  # noqa: E402
from test_appflow_items import ItemApp, LOGIN_PASSWORD  # noqa: E402

from thyra_vault.webui import clipboard  # noqa: E402


@pytest.fixture()
def app():
    with workspace():
        a = ItemApp()
        a.unlock()
        yield a


def _locked(app):
    assert app.screen["app"]["view"] == "lock"


def _item_id(app):
    app.allow = {LOGIN_PASSWORD}
    app.add("login", name="github", username="ana", password=LOGIN_PASSWORD)
    app.allow = set()
    return app.row("github")["id"]


def test_idle_lock_from_the_item_view_drops_a_revealed_secret(app):
    item = _item_id(app)
    app.act(f"view:{item}")
    app.allow = {LOGIN_PASSWORD}
    app.act("menu:reveal:password")
    assert app.field("password")["revealed"]
    app.allow = set()
    app.act("autolock")  # from the page's idle timer, no click on the item
    _locked(app)
    assert app.flow.gi_frame is not None  # the app itself keeps running
    app.unlock()
    assert app.title == "vaultApp.title"


def test_idle_lock_from_an_entry_form(app):
    app.act("add")
    app.act("menu:type:login")
    app.act("autolock")
    _locked(app)


def test_idle_lock_from_the_delete_confirmation(app):
    item = _item_id(app)
    app.act(f"idelete:{item}")
    app.act("autolock")
    _locked(app)
    app.unlock()
    assert app.row("github")  # nothing was deleted


def test_idle_lock_from_the_choose_type_screen(app):
    app.act("add")
    app.act("autolock")
    _locked(app)


def test_idle_lock_from_the_home_screen(app):
    app.act("autolock")
    _locked(app)


def test_exit_signal_handler_wipes_then_exits(monkeypatch):
    wiped = []
    monkeypatch.setattr(clipboard, "wipe_now", lambda: wiped.append(True) or 1)
    with pytest.raises(SystemExit) as stop:
        clipboard._on_exit_signal(signal.SIGTERM, None)
    assert wiped == [True] and stop.value.code == 128 + int(signal.SIGTERM)


def test_install_sets_and_restores_the_handlers():
    sigs = clipboard._exit_signals()
    before = {s: signal.getsignal(s) for s in sigs}
    restore = clipboard.install_signal_handlers()
    try:
        assert all(signal.getsignal(s) is clipboard._on_exit_signal for s in sigs)
    finally:
        restore()
    assert {s: signal.getsignal(s) for s in sigs} == before


def test_install_is_a_no_op_off_the_main_thread():
    got = []
    t = threading.Thread(target=lambda: got.append(clipboard.install_signal_handlers()))
    t.start()
    t.join()
    got[0]()  # callable, does nothing
    assert signal.getsignal(signal.SIGTERM) is not clipboard._on_exit_signal


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_real_sigterm_wipes_the_clipboard_in_a_subprocess(tmp_path):
    import subprocess
    marker = tmp_path / "wiped"
    code = (
        "import os, signal, sys, time\n"
        f"sys.path.insert(0, {str(Path(__file__).parent.parent)!r})\n"
        "from thyra_vault.webui import clipboard\n"
        f"clipboard.wipe_now = lambda: open({str(marker)!r}, 'w').write('x')\n"
        "clipboard.install_signal_handlers()\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    assert proc.stdout.readline().strip() == b"ready"
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 128 + int(signal.SIGTERM)
    assert marker.exists()
