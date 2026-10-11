"""Regression tests for the findings of the five-agent security review.

One test (at least) per finding that was fixed, named for what an attacker could
do before. Findings that needed a design decision live in the sections at the end.
"""
import os
import socket
import stat
import sys
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from _vault_workspace import SECRETS, TEST_PASSWORD, workspace  # noqa: E402
from test_appflow import App, Clock, FakeClipboard  # noqa: E402
from test_webui_server import Harness, _restore_seams, assets  # noqa: E402,F401

import mcp_server  # noqa: E402
from thyra_vault import clipboard, crypto, datadir, store  # noqa: E402
from thyra_vault.webui import prefs, server  # noqa: E402

IDLE = 15 * 60 + 5
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX files and links")


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

def _enc_size():
    return store.SECRETS_FILE.stat().st_size


def test_the_vault_file_length_does_not_track_the_content_closely():
    with workspace():
        small = _enc_size()
        secrets = store.load_secrets(TEST_PASSWORD)
        secrets.update({f"EXTRA_{i}": "v" * 40 for i in range(20)})
        store.save_secrets(TEST_PASSWORD, secrets)
        assert _enc_size() == small                    # same 4 KiB bucket
        secrets["BIG"] = "x" * 6000
        store.save_secrets(TEST_PASSWORD, secrets)
        assert _enc_size() > small                     # a larger bucket, not a smooth ramp
        assert store.load_secrets(TEST_PASSWORD) == secrets  # and the padding is invisible


def test_padding_is_a_reserved_key_nobody_sees():
    with workspace():
        body = store.load_vault_body(TEST_PASSWORD)
        assert store.PAD_KEY in body and store.is_reserved_key(store.PAD_KEY)
        assert store.PAD_KEY not in store.load_secrets(TEST_PASSWORD)
        with pytest.raises(ValueError):
            store.save_secrets(TEST_PASSWORD, {**store.load_secrets(TEST_PASSWORD), store.PAD_KEY: "x"})


def test_a_missing_vault_enc_is_not_silently_replaced_by_a_weaker_v1_vault():
    with workspace():
        store.SECRETS_FILE.unlink()
        store.SALT_FILE.write_bytes(os.urandom(16))  # vault.salt survives an upgrade to v2
        with pytest.raises(RuntimeError):
            store.save_secrets(TEST_PASSWORD, {"A": "b"})
        assert not store.SECRETS_FILE.exists()


def test_creating_a_v1_vault_on_purpose_still_works():
    with workspace():
        store.SECRETS_FILE.unlink()
        store.create_secrets_vault(TEST_PASSWORD)
        assert store.SECRETS_FILE.exists() and not crypto.is_v2(store.SECRETS_FILE.read_bytes())
        assert store.load_secrets(TEST_PASSWORD) == {}


@posix_only
def test_a_symlink_swapped_in_for_a_lock_file_is_not_followed(tmp_path):
    with workspace():
        target = tmp_path / "somebody-elses-file"
        target.write_text("precious")
        store.VAULT_LOCK_FILE.unlink(missing_ok=True)
        store.VAULT_LOCK_FILE.symlink_to(target)
        with pytest.raises(OSError):
            with store._vault_lock():
                pass
        assert target.read_text() == "precious"


@posix_only
def test_a_fifo_at_the_lock_path_does_not_hang_the_server():
    with workspace():
        store.VAULT_LOCK_FILE.unlink(missing_ok=True)
        os.mkfifo(store.VAULT_LOCK_FILE)
        started = time.monotonic()
        with pytest.raises((RuntimeError, OSError)):
            with store._vault_lock():
                pass
        assert time.monotonic() - started < 3


@posix_only
def test_a_fifo_or_a_huge_file_as_an_env_target_is_refused_not_read(tmp_path):
    fifo = tmp_path / "pipe.env"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        store._read_raw(fifo)
    big = tmp_path / "big.env"
    big.write_bytes(b"A=1\n" * (store._MAX_ENV_FILE_BYTES // 4 + 10))
    with pytest.raises(ValueError):
        store._read_raw(big)
    ok = tmp_path / "ok.env"
    ok.write_text("A=1\n")
    assert store._read_raw(ok) == "A=1\n"


# --------------------------------------------------------------------------
# Adopting a vault from the old plugin id
# --------------------------------------------------------------------------

def _legacy(parent, name="llm-env-vault-llm-env-vault", files=None):
    vault = parent / name / "vault"
    vault.mkdir(parents=True)
    for fname, content in (files or {"vault.enc": b"ENC", "vault.salt": b"SALT"}).items():
        (vault / fname).write_bytes(content)
    return vault


def _fresh(parent, name="thyra-vault-thyra-vault"):
    data = parent / name
    root = data / "vault"
    root.mkdir(parents=True)
    return data, root


def test_only_the_exact_legacy_id_is_adopted(tmp_path):
    _legacy(tmp_path, "llm-env-vaultX")           # no dash: not the legacy id
    _legacy(tmp_path, "llm-env-vault")            # no marketplace suffix
    data, root = _fresh(tmp_path)
    assert datadir.adopt_legacy_vault(root, str(data)) is None
    assert not (root / "vault.enc").exists()


@posix_only
def test_a_symlinked_vault_directory_or_vault_file_is_not_adopted(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "vault.enc").write_bytes(b"FOREIGN")
    (tmp_path / "llm-env-vault-evil").mkdir()
    (tmp_path / "llm-env-vault-evil" / "vault").symlink_to(elsewhere)
    real = _legacy(tmp_path, "llm-env-vault-linkfile", {"vault.salt": b"S"})
    (real / "vault.enc").symlink_to(elsewhere / "vault.enc")
    data, root = _fresh(tmp_path)
    assert datadir.adopt_legacy_vault(root, str(data)) is None
    assert not (root / "vault.enc").exists()


def test_adoption_never_overwrites_a_file_already_there(tmp_path):
    _legacy(tmp_path, files={"vault.enc": b"ENC", "targets.json": b'{"old": 1}'})
    data, root = _fresh(tmp_path)
    (root / "targets.json").write_bytes(b'{"mine": 1}')
    assert datadir.adopt_legacy_vault(root, str(data)) is not None
    assert (root / "targets.json").read_bytes() == b'{"mine": 1}'
    assert (root / "vault.enc").read_bytes() == b"ENC"


def test_adoption_copies_only_the_known_files(tmp_path):
    _legacy(tmp_path, files={"vault.enc": b"ENC", "vault_index.json": b"{}", "authorized_keys": b"ssh-rsa AAA",
                             "vault.enc.bak": b"OLD", "notes.txt": b"hi"})
    data, root = _fresh(tmp_path)
    datadir.adopt_legacy_vault(root, str(data))
    assert sorted(p.name for p in root.iterdir()) == sorted(["vault.enc", "vault_index.json", datadir.ADOPTED_NOTE])


@posix_only
def test_a_planted_staging_link_never_breaks_the_import_or_deletes_its_target(tmp_path):
    _legacy(tmp_path)
    data, root = _fresh(tmp_path)
    (root / ".adopting").symlink_to(tmp_path)               # used to raise FileExistsError
    assert datadir.adopt_legacy_vault(root, str(data)) is not None
    assert tmp_path.exists() and (tmp_path / "llm-env-vault-llm-env-vault").exists()


@posix_only
def test_an_unreadable_source_file_makes_adoption_a_no_op_not_an_exception(tmp_path):
    broken = _legacy(tmp_path, files={"vault.enc": b"E", "vault_index.json": b"{}"})
    os.chmod(broken / "vault_index.json", 0)
    data, root = _fresh(tmp_path)
    try:
        datadir.adopt_legacy_vault(root, str(data))          # must not raise
        assert not (root / "vault.enc").exists() or os.geteuid() == 0
    finally:
        os.chmod(broken / "vault_index.json", 0o600)


# --------------------------------------------------------------------------
# The clipboard
# --------------------------------------------------------------------------

def test_wipe_now_clears_what_is_still_pending(monkeypatch):
    wiped = []
    monkeypatch.setattr(clipboard, "clear_if_unchanged", lambda value, **kw: wiped.append(value) or True)
    clipboard.wipe_now()   # drop anything an earlier test left pending
    wiped.clear()
    clipboard.clear_later("secret-one", 3600)
    clipboard.clear_later("secret-two", 3600)
    assert clipboard.wipe_now() == 2
    assert sorted(wiped) == ["secret-one", "secret-two"]
    assert clipboard.wipe_now() == 0                        # nothing left, no second wipe


def test_copying_the_same_text_twice_restarts_one_timer_instead_of_wiping_early(monkeypatch):
    monkeypatch.setattr(clipboard, "clear_if_unchanged", lambda value, **kw: True)
    clipboard.wipe_now()
    first = clipboard.clear_later("same", 3600)
    second = clipboard.clear_later("same", 3600)
    time.sleep(0.05)
    assert not first.is_alive()                              # the first was cancelled
    assert second.is_alive()
    assert clipboard.wipe_now() == 1


class WipingClipboard(FakeClipboard):
    def __init__(self):
        super().__init__()
        self.wipes = 0

    def wipe_now(self):
        self.wipes += 1
        return 0


def test_quitting_the_app_wipes_the_clipboard():
    with workspace():
        clip = WipingClipboard()
        app = App(clip=clip)
        app.unlock()
        app.act("copy:API_TOKEN")
        before = clip.wipes
        app.act("lock")
        assert clip.wipes > before                          # locking wipes
        app.act("quit")
        assert app.done and clip.wipes >= before + 2        # and so does leaving


def test_a_window_closed_mid_session_still_wipes():
    with workspace():
        clip = WipingClipboard()
        app = App(clip=clip)
        app.unlock()
        app.act("copy:API_TOKEN")
        before = clip.wipes
        app.flow.close()                                     # what the server does when the window goes away
        assert clip.wipes > before


def test_the_generators_output_is_copied_through_the_server_with_the_same_wipe():
    with workspace():
        app = App()
        app.unlock()
        app.act("gcopy", text="Gen3rated-Pa55word")
        assert app.clip.copied == ["Gen3rated-Pa55word"] and len(app.clip.cleared) == 1
        app.act("gcopy", text="x" * 5000)                    # absurd: ignored
        app.act("gcopy", text="")
        assert app.clip.copied == ["Gen3rated-Pa55word"]


# --------------------------------------------------------------------------
# Auto-lock on every screen
# --------------------------------------------------------------------------

def test_the_manage_screen_does_not_answer_after_the_idle_limit_and_nothing_is_changed():
    with workspace():
        clock = Clock()
        app = App(clock=clock)
        app.unlock()
        app.act("manage")
        app.act("menu:change_password")
        clock.now += IDLE
        app.act("confirm", old=TEST_PASSWORD, new="A-brand-new-passphrase-7", confirm="A-brand-new-passphrase-7")
        assert app.title == "vaultApp.lock.title"
        assert store.load_secrets(TEST_PASSWORD) == SECRETS  # the password was NOT changed


def test_setting_the_clock_back_locks_instead_of_keeping_the_vault_open():
    with workspace():
        clock = Clock()
        app = App(clock=clock)
        app.unlock()
        clock.now -= 3 * 3600
        app.act("copy:API_TOKEN")
        assert app.title == "vaultApp.lock.title" and app.clip.copied == []


def test_the_app_measures_idle_time_with_wall_clock_time():
    import inspect
    from thyra_vault.webui import appflow
    assert inspect.signature(appflow.vault_app).parameters["clock"].default is time.time


# --------------------------------------------------------------------------
# Preferences
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [True, False, 15.0, 5.5, "15", None, [15], {"a": 1}])
def test_a_bool_or_float_is_not_accepted_where_an_int_is_required(bad):
    cleaned = prefs.clean({"autoLockMinutes": bad, "clipboardSeconds": bad})
    assert cleaned["autoLockMinutes"] == prefs.DEFAULTS["autoLockMinutes"]
    assert cleaned["clipboardSeconds"] == prefs.DEFAULTS["clipboardSeconds"]
    assert type(cleaned["autoLockMinutes"]) is int


# --------------------------------------------------------------------------
# The loopback server (the unlock throttle file is covered in test_unlock_throttle.py)
# --------------------------------------------------------------------------

def test_failed_exchanges_cannot_end_a_session_that_is_already_connected(assets):
    h = Harness(server.Limits(launch_timeout=30, heartbeat_timeout=30, max_bad_codes=3))
    h.connect()
    for _ in range(20):
        status, _body, _raw, _r = h.request("POST", "/api/exchange", {"code": "guess"})
        assert status == 403
    assert h.screen()["screen"]["title"]["key"] == "unlock.title"   # still alive
    h.act("cancel")
    h.finish()


def test_before_anyone_connects_too_many_wrong_codes_only_lock_the_exchange_out(assets):
    h = Harness(server.Limits(launch_timeout=30, max_bad_codes=3, lockout_base=30, lockout_max=30))
    for _ in range(3):
        h.request("POST", "/api/exchange", {"code": "guess"})
    assert h.request("POST", "/api/exchange", {"code": "guess"})[0] == 429
    assert h.thread.is_alive()  # a stranger's guesses cannot cancel the dialog
    h.session.cancel("closed")
    h.finish()


def _raw_exchange(port, payload: bytes, wait=1.5):
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.sendall(payload)
    chunks = []
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    except (socket.timeout, ConnectionError):
        pass
    finally:
        s.close()
    return b"".join(chunks)


def test_an_unauthenticated_post_is_refused_before_its_body_is_read_and_the_connection_closes(assets):
    h = Harness()
    request = (f"POST /api/action HTTP/1.1\r\nHost: 127.0.0.1:{h.port}\r\nContent-Type: application/json\r\n"
               f"Content-Length: 500000\r\n\r\n").encode()
    started = time.monotonic()
    reply = _raw_exchange(h.port, request)               # we never send the 500000 bytes
    assert reply.startswith(b"HTTP/1.0 401") or reply.startswith(b"HTTP/1.1 401")
    assert time.monotonic() - started < 1.4              # closed by the server, not by our timeout
    h.connect()
    h.act("cancel")
    h.finish()


def test_the_unauthenticated_exchange_body_is_small(assets):
    h = Harness()
    status, _b, _r, _resp = h.request("POST", "/api/exchange", {"code": "x" * 10_000})
    assert status == 400
    h.connect()
    h.act("cancel")
    h.finish()


def test_an_authenticated_action_may_carry_a_whole_item(assets):
    h = Harness()
    h.connect()
    status, body, _raw, _r = h.act("go", password="p" * 200_000)   # far over the old 64 KiB limit
    assert status == 200 and body["screen"]["error"]
    h.act("cancel")
    h.finish()


def test_a_connection_that_stalls_is_dropped(assets, monkeypatch):
    monkeypatch.setattr(server, "SOCKET_TIMEOUT", 0.5)
    h = Harness()
    request = (f"POST /api/exchange HTTP/1.1\r\nHost: 127.0.0.1:{h.port}\r\nContent-Type: application/json\r\n"
               f"Content-Length: 100\r\n\r\n{{").encode()
    started = time.monotonic()
    _raw_exchange(h.port, request, wait=5)
    assert time.monotonic() - started < 4                # the server gave up on us first
    h.connect()
    h.act("cancel")
    h.finish()


def test_a_dropped_connection_does_not_print_a_traceback(assets, capfd):
    h = Harness()
    s = socket.create_connection(("127.0.0.1", h.port))
    s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{h.port}\r\n\r\n".encode())
    s.close()                                              # hang up before reading the page
    time.sleep(0.3)
    h.connect()
    h.act("cancel")
    h.finish()
    assert "Traceback" not in capfd.readouterr().err


# --------------------------------------------------------------------------
# mcp_server
# --------------------------------------------------------------------------

def test_a_timed_out_run_reports_bytes_as_text():
    assert mcp_server._as_text(b"partial \xff output") == "partial � output"
    assert mcp_server._as_text(None) == "" and mcp_server._as_text("ok") == "ok"


def test_an_assistant_cannot_bury_the_human_in_consent_dialogs(monkeypatch):
    monkeypatch.setenv("THYRA_VAULT_DIALOG_LIMIT", "3")
    opened = []
    inner = types.SimpleNamespace(add_secret_dialog=lambda *a: opened.append(a) or {"approved": False}, flag=5)
    pacer = mcp_server._DialogPacer(inner)
    for _ in range(3):
        pacer.add_secret_dialog("X")
    with pytest.raises(RuntimeError, match="Too many consent dialogs"):
        pacer.add_secret_dialog("X")
    assert len(opened) == 3                                  # the fourth window never opened
    assert pacer.flag == 5                                   # everything else passes straight through


def test_the_dialog_limit_can_be_lifted_for_tests_and_ci(monkeypatch):
    monkeypatch.setenv("THYRA_VAULT_DIALOG_LIMIT", "0")
    pacer = mcp_server._DialogPacer(types.SimpleNamespace(x_dialog=lambda: 1))
    assert [pacer.x_dialog() for _ in range(50)] == [1] * 50


def test_the_real_dialog_object_is_paced():
    assert isinstance(mcp_server.gui, mcp_server._DialogPacer)
    assert mcp_server._DialogPacer.MAX_DIALOGS == 8


# --------------------------------------------------------------------------
# The trusted-command cache is bound to the project folder (finding: trust once,
# let the assistant edit a file the command loads, rerun with no dialog)
# --------------------------------------------------------------------------

from test_trust import _allow, _deny, fake_dialog, isolated_vault  # noqa: E402
from thyra_vault import trust  # noqa: E402


def _project(path):
    path.mkdir(parents=True, exist_ok=True)
    (path / "app.py").write_text("import lib\nprint(lib.X)\n")
    (path / "lib.py").write_text("X = 1\n")
    return path


def _run(cmd, cwd):
    return mcp_server._run_with_env_impl(list(cmd), None, False, str(cwd), None)


def test_editing_a_file_the_command_loads_but_does_not_name_revokes_trust(tmp_path):
    proj = _project(tmp_path / "proj")
    cmd = [sys.executable, "app.py"]
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            assert _run(cmd, proj)["applied"]
            assert _run(cmd, proj).get("auto_allowed") is True and len(calls) == 1
            (proj / "lib.py").write_text("X = 2  # edited by the assistant\n")
            again = _run(cmd, proj)
            assert len(calls) == 2, "the edit must bring the dialog back"
            assert "folder" in (again.get("trust_note") or "")


def test_a_new_file_in_the_folder_also_revokes_trust(tmp_path):
    proj = _project(tmp_path / "proj")
    cmd = [sys.executable, "app.py"]
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            _run(cmd, proj)
            (proj / "sitecustomize.py").write_text("print('injected')\n")
            _run(cmd, proj)
            assert len(calls) == 2


def test_the_commands_own_output_does_not_revoke_its_trust(tmp_path):
    proj = _project(tmp_path / "proj")
    (proj / "writer.py").write_text("open('out.log', 'a').write('line\\n')\n")
    cmd = [sys.executable, "writer.py"]
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            _run(cmd, proj)
            for _ in range(3):
                assert _run(cmd, proj).get("auto_allowed") is True   # it wrote out.log each time
            assert len(calls) == 1


def test_a_denied_call_does_not_adopt_the_assistants_edit(tmp_path):
    proj = _project(tmp_path / "proj")
    cmd = [sys.executable, "app.py"]
    with isolated_vault():
        with fake_dialog(_allow(trust_it=True)) as calls:
            _run(cmd, proj)
        (proj / "lib.py").write_text("X = 'evil'\n")
        with fake_dialog(_deny()) as denied:
            refused = _run(cmd, proj)
            assert refused["applied"] is False and refused["message"] == "Denied by user."
            assert "folder" in refused["trust_note"]            # the human is told why they were asked
            assert len(denied) == 1
        with fake_dialog(_allow(trust_it=False)) as third:
            result = _run(cmd, proj)
            assert len(third) == 1 and not result.get("auto_allowed"), \
                "the edit must not have become the trusted baseline"


def test_a_project_too_large_to_watch_is_always_asked_about(tmp_path, monkeypatch):
    proj = _project(tmp_path / "proj")
    monkeypatch.setattr(trust, "_MAX_PROJECT_FILES", 1)
    assert trust.project_fingerprint(proj) != trust.project_fingerprint(proj)


def test_dependency_and_vcs_folders_are_not_part_of_the_fingerprint(tmp_path):
    proj = _project(tmp_path / "proj")
    for name in (".git", "node_modules", ".venv", "__pycache__"):
        (proj / name).mkdir()
    before = trust.project_fingerprint(proj)
    for name in (".git", "node_modules", ".venv", "__pycache__"):
        (proj / name / "x.js").write_text("changed")
    assert trust.project_fingerprint(proj) == before
    (proj / "src").mkdir()
    assert trust.project_fingerprint(proj) != before        # but a normal folder counts


@posix_only
def test_swapping_a_symlink_target_changes_the_fingerprint(tmp_path):
    proj = _project(tmp_path / "proj")
    (proj / "link").symlink_to("lib.py")
    before = trust.project_fingerprint(proj)
    (proj / "link").unlink()
    (proj / "link").symlink_to("app.py")
    assert trust.project_fingerprint(proj) != before


# --------------------------------------------------------------------------
# The consent dialog says where the command runs and what program it is
# --------------------------------------------------------------------------

def test_the_consent_dialog_is_told_the_folder_and_the_real_program(tmp_path):
    proj = _project(tmp_path / "proj")
    with isolated_vault():
        with fake_dialog(_deny()) as calls:
            _run([sys.executable, "app.py"], proj)
    assert calls[0]["cwd"] == str(proj)
    assert calls[0]["executable"] == str(Path(sys.executable).resolve()) or calls[0]["executable"].endswith(Path(sys.executable).name)


def test_a_relative_program_is_shown_with_the_path_it_resolves_to_in_that_folder(tmp_path):
    proj = _project(tmp_path / "proj")
    (proj / "run.sh").write_text("#!/bin/sh\necho hi\n")
    with isolated_vault():
        with fake_dialog(_deny()) as calls:
            _run(["./run.sh"], proj)
    assert calls[0]["executable"] == str((proj / "run.sh").resolve())   # NOT some other run.sh


def test_the_browser_dialog_shows_both_lines():
    from thyra_vault.webui import flows
    flow = flows.unlock_for_run({"secrets": None, "trust": False}, "make test", None, ["A"], None, None, None,
                                "/work/proj", "/usr/bin/make")
    scr = next(flow)
    codes = [b for b in scr["blocks"] if b["type"] == "code"]
    assert [c["label"]["key"] for c in codes] == ["fields.command", "unlockRun.cwd", "unlockRun.executable"]
    assert codes[1]["text"] == "/work/proj" and codes[2]["text"] == "/usr/bin/make"


def test_a_forged_index_cannot_hide_variables_from_the_dialog():
    """Finding F2 (partly): the names shown come from the plaintext index, so after unlocking
    the dialog compares them with what is really in the vault and refuses a mismatch."""
    from thyra_vault.uihelpers import _disclosure_mismatch
    assert _disclosure_mismatch(["A"], ["A", "SECRET_THE_INDEX_DID_NOT_LIST"])
    assert _disclosure_mismatch(["A", "B"], ["A", "B"]) is None


def test_a_relative_program_path_is_resolved_against_the_commands_folder_not_the_servers(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "run.sh").write_text("#!/bin/sh\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "run.sh").write_text("#!/bin/sh\necho decoy\n")
    here = os.getcwd()
    os.chdir(elsewhere)                                    # the SERVER's cwd holds a decoy of the same name
    try:
        assert trust._resolve_argv0(["./run.sh"], str(proj)) == (proj / "run.sh").resolve()
    finally:
        os.chdir(here)


# --------------------------------------------------------------------------
# Forged state files (targets.json / the swap journal) cannot rewrite or destroy files
# --------------------------------------------------------------------------

from thyra_vault import legacy_swap  # noqa: E402


def test_a_forged_target_pointing_at_an_ordinary_file_is_not_touched(tmp_path):
    rc = tmp_path / ".bashrc"
    original = "export PATH=/usr/bin:$PATH\nalias ll='ls -l'\n"
    rc.write_text(original)
    with workspace():
        index = store.load_index()
        index["PATH"] = 9                                   # the forger also adds the name to the index
        with pytest.raises(ValueError, match="nothing in it shows"):
            store.sync_target_file(rc, index, {"PATH", "API_TOKEN"})
    assert rc.read_text() == original                       # not rewritten, no header, no appended lines


def test_a_file_the_vault_really_migrated_still_resyncs():
    with workspace() as (_project, env_path):
        index = store.load_index()
        index["NEW_ONE"] = 7
        store.sync_target_file(env_path, index, {"API_TOKEN", "DB_PASSWORD", "PLAIN", "NEW_ONE"})
        assert b"NEW_ONE=" in env_path.read_bytes()          # its managed names gained a line


def test_a_file_being_migrated_right_now_is_accepted_through_force_names(tmp_path):
    env = tmp_path / ".env"
    env.write_text('API_KEY="sk-real-value"\nOTHER=1\n')
    with workspace():
        index = {"API_KEY": 5}
        store.sync_target_file(env, index, {"API_KEY"}, force_names={"API_KEY"})
    assert "sk-real-value" not in env.read_text()


def test_recovering_a_swap_keeps_the_original_in_the_vault_folder(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(b'API_TOKEN="real-value-123"\nDB_PASSWORD="value 2"\n')
    with workspace():
        report = legacy_swap.recover_swap_file(env, {"API_TOKEN", "DB_PASSWORD"}, store.load_index(), time.time())
        assert report["error"] is None and report["restored"] == ["API_TOKEN"]
        assert b"real-value-123" not in env.read_bytes()
        backup = Path(report["backup"])
        assert backup.parent == store.ROOT / legacy_swap.RECOVERY_BACKUP_DIR
        assert b"real-value-123" in backup.read_bytes()      # nothing is irrecoverably lost
        if os.name == "posix":
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
            assert stat.S_IMODE(backup.parent.stat().st_mode) == 0o700


def test_if_the_backup_cannot_be_written_the_file_is_left_alone(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_bytes(b'API_TOKEN="real-value-123"\n')
    with workspace():
        monkeypatch.setattr(legacy_swap, "_backup_before_recovery", lambda p, b: (None, "disk full"))
        report = legacy_swap.recover_swap_file(env, {"API_TOKEN"}, store.load_index(), time.time())
    assert report["error"] == "disk full" and b"real-value-123" in env.read_bytes()


# --------------------------------------------------------------------------
# The launch code is not in the browser's command line
# --------------------------------------------------------------------------

def test_a_cross_site_navigation_may_load_the_static_page_and_nothing_else(assets):
    h = Harness()
    nav = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
    assert h.request("GET", "/", headers=nav)[0] == 200                       # the start page forwards here
    h.connect()
    assert h.api("GET", "/api/screen", headers=nav)[0] == 403                  # but never the API
    assert h.api("POST", "/api/ping", {}, headers=nav)[0] == 403
    assert h.request("GET", "/assets/app.js", headers={**nav, "Sec-Fetch-Dest": "script"})[0] == 403
    assert h.request("GET", "/", headers={**nav, "Sec-Fetch-Mode": "no-cors"})[0] == 403
    assert h.request("GET", "/", headers={**nav, "Sec-Fetch-Dest": "iframe"})[0] == 403
    h.act("cancel")
    h.finish()


def test_the_start_page_carries_the_code_but_the_url_given_to_the_browser_does_not(tmp_path):
    url = "http://127.0.0.1:45678/#c=SECRET-CODE-123"
    start = server._write_start_page(url)
    try:
        uri, folder = start
        assert "SECRET-CODE-123" not in uri and uri.startswith("file://")
        page = Path(folder) / "start.html"
        assert "SECRET-CODE-123" in page.read_text()
        if os.name == "posix":
            assert stat.S_IMODE(page.stat().st_mode) == 0o600
            assert stat.S_IMODE(Path(folder).stat().st_mode) == 0o700
    finally:
        shutil_rmtree = __import__("shutil").rmtree
        shutil_rmtree(start[1], ignore_errors=True)


def test_the_real_opener_hands_the_browser_the_start_page_not_the_code(monkeypatch):
    launched = []
    monkeypatch.setattr(server, "_launch_app_window", lambda target, size_key=None: launched.append(target) or None)
    monkeypatch.setattr(server.webbrowser, "open", lambda target, new=1: launched.append(target) or True)
    monkeypatch.delenv("THYRA_VAULT_NO_BROWSER", raising=False)
    monkeypatch.delenv("LLM_ENV_VAULT_NO_BROWSER", raising=False)
    url = "http://127.0.0.1:45679/#c=ANOTHER-SECRET"
    try:
        assert server._default_open(url) is True
        assert launched and all("ANOTHER-SECRET" not in t for t in launched)
        assert all(t.startswith("file://") for t in launched)
        assert url in server._bootstraps
    finally:
        server._forget_start_page(url)
    assert url not in server._bootstraps


def test_the_start_page_is_deleted_once_the_page_has_connected(assets, monkeypatch):
    forgotten = []
    real_forget = server._forget_start_page
    monkeypatch.setattr(server, "_forget_start_page", lambda u: forgotten.append(u) or real_forget(u))
    h = Harness()
    server._bootstraps[h.url] = str(Path(h.url.split("#")[0].replace("http://127.0.0.1:", "/nonexistent-")))
    h.connect()
    deadline = time.time() + 3
    while h.url not in forgotten and time.time() < deadline:
        time.sleep(0.1)
    assert h.url in forgotten
    h.act("cancel")
    h.finish()


# --------------------------------------------------------------------------
# The output redactor knows more spellings of a secret
# --------------------------------------------------------------------------

import base64  # noqa: E402
import urllib.parse  # noqa: E402

SECRET = "p@ss w0rd/with+odd\"chars-0xCAFE"


def _redacted(text):
    out, _skipped = mcp_server._redact_secrets(text, {"TOKEN": SECRET})
    return out


@pytest.mark.parametrize("prefix,suffix", [("", ""), ("x", "yz"), ("xy", "z"), ("xyz", ""), ("q", "q")])
def test_base64_is_caught_at_every_alignment_inside_a_larger_stream(prefix, suffix):
    stream = base64.b64encode((prefix + SECRET + suffix).encode()).decode()
    assert SECRET not in stream
    out = _redacted(f"payload={stream}")
    assert "[REDACTED:TOKEN]" in out
    # whatever remains of the stream must not still decode back to the secret
    assert base64.b64encode(SECRET.encode()).decode()[:12] not in out


def test_urlsafe_base64_hex_json_and_percent_forms_are_caught():
    raw = SECRET.encode()
    spellings = {
        "urlsafe b64": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "hex": raw.hex(),
        "HEX": raw.hex().upper(),
        "json": __import__("json").dumps(SECRET)[1:-1],
        "percent": urllib.parse.quote(SECRET, safe=""),
        "percent lower": __import__("re").sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), urllib.parse.quote(SECRET, safe="")),
        "plus for space": urllib.parse.quote_plus(SECRET, safe=""),
    }
    for label, spelled in spellings.items():
        assert "[REDACTED:TOKEN]" in _redacted(f"seen: {spelled} end"), label


def test_ordinary_text_is_left_alone_and_short_values_are_still_reported_as_skipped():
    out, skipped = mcp_server._redact_secrets("hello world 12345", {"PIN": "1234", "TOKEN": SECRET})
    assert out == "hello world 12345" and skipped == ["PIN"]


# --------------------------------------------------------------------------
# Page-side guard rails (the review found no XSS sink; keep it that way)
# --------------------------------------------------------------------------

WEB_SRC = Path(__file__).parent.parent / "web" / "apps" / "web" / "src"
FORBIDDEN_IN_PAGE = ("dangerouslySetInnerHTML", "innerHTML", "outerHTML", "document.write", "eval(",
                     "new Function(", "href=", "javascript:")
TRANS_COMPONENT = __import__("re").compile(r"<Trans[\s>/]")   # i18next's <Trans>, not <TransitionPanel>


def test_the_page_source_has_no_html_injection_or_link_sinks():
    """Item names, notes and the `uri` field are free text from the vault. i18next runs with
    escapeValue=false (safe only because React escapes and nothing renders HTML), and a `uri`
    of `javascript:...` is harmless only because nothing turns it into a link. If you add
    links, allow-list the scheme first and update this test."""
    offenders = []
    for path in WEB_SRC.rglob("*.ts*"):
        text = path.read_text(encoding="utf-8")
        for bad in FORBIDDEN_IN_PAGE:
            if bad in text:
                offenders.append(f"{path.relative_to(WEB_SRC)}: {bad}")
        if TRANS_COMPONENT.search(text):
            offenders.append(f"{path.relative_to(WEB_SRC)}: <Trans>")
    assert not offenders, offenders
