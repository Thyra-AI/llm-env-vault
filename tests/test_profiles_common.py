"""Tests for vault_lib/profiles/_common.py (shared always-allow helpers)."""
import hashlib
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib.profiles import _common as c  # noqa: E402

WIN = os.name == "nt"


def _native_exe() -> str:
    if WIN:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "hostname.exe")
    return shutil.which("true") or "/bin/true"


@pytest.fixture
def relaxed(monkeypatch):
    monkeypatch.setattr(c.RELAXATIONS, "skip_exe_dir_writable_check", True)


def test_relaxations_default_strict():
    assert c.RELAXATIONS.is_strict()
    assert c.RELAXATIONS.git_allowed_protocols == "https"


@pytest.mark.parametrize("name,expected", [
    ("PATH", True), ("path", True), ("Home", True), ("GIT_DIR", True), ("git_ssh", True),
    ("DOCKER_HOST", True), ("KUBECONFIG", True), ("KUBE_X", True), ("PYTHONPATH", True),
    ("LD_PRELOAD", True), ("HTTP_PROXY", True), ("https_proxy", True), ("SSL_CERT_FILE", True),
    ("API_TOKEN", False), ("DB_PASSWORD", False), ("MY_GITHUB", False), ("", True),
])
def test_tool_control_names(name, expected):
    assert c.is_tool_control_name(name) is expected


@pytest.mark.parametrize("text,bad", [
    ("plain", False), ("a b", False), ("a\0b", True), ("a\nb", True), ("a\rb", True),
    ("a\u202eb", True), ("a\u200bb", True), ("a\u2028b", True), ("a\ue000b", True),
    ("caf\u00e9", False),
])
def test_unsafe_text(text, bad):
    assert c.has_unsafe_text(text) is bad


@pytest.mark.parametrize("text,expected", [
    ("git version 2.45.1.windows.1", (2, 45, 1)), ("v2.40.2-desktop.1", (2, 40, 2)),
    ("Docker Desktop 4.88.1 (237512)", (4, 88, 1)), ("5.0.0", (5, 0, 0)), ("abc", None),
    ("7", None),
])
def test_parse_version(text, expected):
    assert c.parse_version(text) == expected


def test_vercmp_numeric_not_string():
    assert c.vercmp((2, 9), (2, 10)) == -1
    assert c.vercmp((2, 40), (2, 40, 0)) == 0
    assert c.vercmp((5, 0, 0), (2, 40, 2)) == 1


@pytest.mark.parametrize("text,ok", [
    ("git version 2.50.1", True), ("git version 2.50.0", False), ("2.51.0", True),
    ("2.49.1", True), ("2.49.0", False), ("2.48.2", True), ("2.48.1", False),
    ("2.47.3", True), ("2.46.4", True), ("2.45.4.windows.1", True), ("2.45.1.windows.1", False),
    ("2.44.4", True), ("2.43.7", True), ("2.43.6", False), ("2.42.9", False), ("1.9.9", False),
])
def test_git_floor(text, ok):
    assert (c.version_problem("git", text) is None) is ok


@pytest.mark.parametrize("text,ok", [("v2.40.2", True), ("2.40.1", False), ("5.1.0", True),
                                     ("v2.39.9-desktop.1", False), ("garbage", False)])
def test_compose_floor(text, ok):
    assert (c.version_problem("compose", text) is None) is ok


def test_floor_relaxation_wins(monkeypatch):
    monkeypatch.setitem(c.RELAXATIONS.version_floors, "git", c.Floor((2, 0, 0)))
    assert c.version_problem("git", "2.45.1") is None


SPECS = [
    c.FlagSpec(long="--namespace", short="-n", value=True, pattern=r"[a-z0-9-]+"),
    c.FlagSpec(long="--quiet", short="-q"),
    c.FlagSpec(short="-f", value=True, repeatable=True),
    c.FlagSpec(long="--depth", value=True, pattern=r"\d+"),
]


def test_tokenize_canonical_form():
    parsed = c.tokenize_argv(["-n", "prod", "web", "-q", "-f", "a.yml", "-f", "b.yml"], SPECS)
    assert parsed.positionals == ["web"]
    assert parsed.canonical_flag_tokens() == ["--namespace=prod", "--quiet", "-f", "a.yml",
                                              "-f", "b.yml"]
    again = c.tokenize_argv(["--quiet", "--namespace=prod"], SPECS)
    assert again.canonical_flag_tokens() == ["--namespace=prod", "--quiet"]


@pytest.mark.parametrize("tokens", [
    ["-nprod"], ["-n=prod"], ["--namespace", "prod"], ["--names=prod"], ["-qn", "prod"],
    ["--quiet=1"], ["-n"], ["-n", "-q"], ["--namespace="], ["--"], ["-"], ["--unknown"],
    ["-n", "a", "-n", "b"], ["--quiet", "--quiet"], ["@file"], ["-f", "@x"], ["a\nb"],
    ["x\0"], ["a\u202eb"], ["--namespace=Bad"], ["--depth=1x"], [""], [5],
])
def test_tokenize_rejects(tokens):
    with pytest.raises(c.ArgvRejected):
        c.tokenize_argv(tokens, SPECS)


def test_tokenize_positional_bounds():
    with pytest.raises(c.ArgvRejected):
        c.tokenize_argv(["a", "b"], SPECS, max_positionals=1)
    with pytest.raises(c.ArgvRejected):
        c.tokenize_argv([], SPECS, min_positionals=1)


def test_build_env_from_scratch_and_collisions():
    source = {"SystemRoot": r"C:\Windows", "PATH": "evil", "GIT_DIR": "x", "HOME": "/h",
              "AWS_SECRET": "s", "LANG": "C"}
    env = c.build_env([r"C:\bin", r"C:\bin2"], injected={"API_TOKEN": "v"},
                      extra={"GIT_TERMINAL_PROMPT": "0"}, source=source, windows=False)
    assert env["PATH"] == os.pathsep.join([r"C:\bin", r"C:\bin2"])
    assert env["API_TOKEN"] == "v" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert "AWS_SECRET" not in env and "GIT_DIR" not in env and env["HOME"] == "/h"
    with pytest.raises(c.EnvNameRefused):
        c.build_env([], injected={"PATH": "x"}, source=source, windows=False)
    with pytest.raises(c.EnvNameRefused):
        c.build_env([], injected={"HTTP_PROXY": "x"}, source=source, windows=False)


def test_comspec_rebuilt_inside_systemroot():
    env = c.system_essentials({"SystemRoot": r"C:\Windows", "ComSpec": r"C:\evil\cmd.exe"},
                              windows=True)
    assert os.path.normcase(env["COMSPEC"]) == os.path.normcase(r"C:\Windows\System32\cmd.exe")


@pytest.mark.parametrize("head,windows,expected", [
    (b"MZ" + b"\0" * 0x3A + (0x80).to_bytes(4, "little") + b"\0" * 0x40 + b"PE\0\0" + b"\0" * 18
     + (0x0102).to_bytes(2, "little") + b"\0" * 64, True, "pe"),
    (b"MZ" + b"\0" * 0x3A + (0x80).to_bytes(4, "little") + b"\0" * 0x40 + b"PE\0\0" + b"\0" * 18
     + (0x2102).to_bytes(2, "little") + b"\0" * 64, True, None),            # DLL
    (b"MZ" + b"\0" * 200, True, None),
    (b"#!/bin/sh\n", True, None), (b"\x7fELF\2\1\1", False, "elf"), (b"\x7fELF", True, None),
    (b"\xcf\xfa\xed\xfe", False, "macho"), (b"\xca\xfe\xba\xbe\0\0\0\x02", False, "macho"),
    (b"\xca\xfe\xba\xbe\0\0\0\x34", False, None), (b"#!/bin/sh\n", False, None),
])
def test_native_format(head, windows, expected):
    assert c.native_format(head, windows=windows) == expected


def test_resolve_pin_native_and_verify(tmp_path, relaxed):
    exe = tmp_path / ("tool.exe" if WIN else "tool")
    shutil.copyfile(_native_exe(), exe)
    os.chmod(exe, 0o755)
    pin = c.resolve_pinned_binary(str(exe))
    assert pin.sha256 == hashlib.sha256(exe.read_bytes()).hexdigest()
    assert c.PinnedBinary.from_dict(pin.to_dict()) == pin
    assert c.verify_pinned_binary(pin) is None
    exe.write_bytes(exe.read_bytes() + b"x")
    assert "changed" in c.verify_pinned_binary(pin)
    exe.unlink()
    assert "missing" in c.verify_pinned_binary(pin)


def test_resolve_refuses_scripts_and_relative(tmp_path, relaxed):
    for name in ("a.cmd", "a.bat", "a.ps1", "a.vbs", "a.js"):
        (tmp_path / name).write_text("echo hi", encoding="utf-8")
        with pytest.raises(c.BinaryRefused):
            c.resolve_pinned_binary(str(tmp_path / name))
    script = tmp_path / ("s.exe" if WIN else "s")
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    os.chmod(script, 0o755)
    with pytest.raises(c.BinaryRefused, match="native"):
        c.resolve_pinned_binary(str(script))
    with pytest.raises(c.BinaryRefused, match="relative"):
        c.resolve_pinned_binary("sub" + os.sep + "tool")
    with pytest.raises(c.BinaryRefused, match="found"):
        c.resolve_pinned_binary("definitely-not-a-program-xyz", search_path=str(tmp_path))


def test_bare_name_never_searches_cwd_or_relative_path(tmp_path, relaxed, monkeypatch):
    exe = tmp_path / ("tool.exe" if WIN else "tool")
    shutil.copyfile(_native_exe(), exe)
    os.chmod(exe, 0o755)
    monkeypatch.chdir(tmp_path)
    for sp in ("", ".", os.pathsep.join([".", "relative"])):
        with pytest.raises(c.BinaryRefused, match="found"):
            c.resolve_pinned_binary("tool", search_path=sp)
    assert c.resolve_pinned_binary("tool", search_path=str(tmp_path)).path


def test_strict_location_refuses_user_writable_dir(tmp_path):
    exe = tmp_path / ("tool.exe" if WIN else "tool")
    shutil.copyfile(_native_exe(), exe)
    os.chmod(exe, 0o755)
    with pytest.raises(c.BinaryRefused, match="location"):
        c.resolve_pinned_binary(str(exe))


def test_strict_location_accepts_system_binary():
    exe = _native_exe()
    if not os.path.exists(exe) or c.exe_location_problem(exe):
        pytest.skip("no protected native executable available (elevated or unusual host)")
    assert c.resolve_pinned_binary(exe).path


def test_posix_object_rule():
    class St:
        def __init__(self, uid, mode):
            self.st_uid, self.st_mode = uid, mode
    assert c._posix_object_problem(St(0, 0o100755), "/x") is None
    assert "root" in c._posix_object_problem(St(1000, 0o100755), "/x")
    assert "writable" in c._posix_object_problem(St(0, 0o100775), "/x")
    assert "writable" in c._posix_object_problem(St(0, 0o100757), "/x")


def test_pinned_path_dirs_filters_writable(tmp_path):
    writable = tmp_path / "w"
    writable.mkdir()
    dirs = c.pinned_path_dirs(os.pathsep.join([str(writable), ".", "rel"]))
    assert str(writable) not in dirs and all(os.path.isabs(d) for d in dirs)


def _symlink_or_skip(link, target):
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def test_pinned_path_dirs_records_the_resolved_path_of_a_link(tmp_path, relaxed):
    # B3-01: the link itself must never be recorded (it can be retargeted later).
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    _symlink_or_skip(link, real)
    dirs = c.pinned_path_dirs(str(link))
    assert os.path.normcase(os.path.realpath(real)) in [os.path.normcase(d) for d in dirs]
    assert os.path.normcase(str(link)) not in [os.path.normcase(d) for d in dirs]


def test_pinned_path_dirs_requires_the_links_parent_to_be_protected(tmp_path, relaxed,
                                                                    monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    holder = tmp_path / "holder"
    holder.mkdir()
    link = holder / "link"
    _symlink_or_skip(link, real)
    original = c.dir_not_user_writable
    monkeypatch.setattr(c, "dir_not_user_writable",
                        lambda p: False if os.path.normcase(os.fspath(p)) ==
                        os.path.normcase(str(holder)) else original(p))
    dirs = c.pinned_path_dirs(str(link))
    assert not any(os.path.normcase(d) in (os.path.normcase(str(link)),
                                           os.path.normcase(os.path.realpath(real)))
                   for d in dirs)


def test_hash_tree_and_dlls(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "sub" / "b.txt").write_text("b", encoding="utf-8")
    first = c.hash_tree(tmp_path)
    assert set(first) == {"a.txt", "sub/", "sub/b.txt"}
    (tmp_path / "sub" / "b.txt").write_text("c", encoding="utf-8")
    assert c.hash_tree(tmp_path) != first
    with pytest.raises(c.ProfileRefusal):
        c.hash_tree(tmp_path, max_files=1)
    (tmp_path / "X.DLL").write_bytes(b"1")
    snap = c.snapshot_cwd_dlls(tmp_path, enabled=True)
    assert list(snap) == ["x.dll"] and c.verify_cwd_dlls(tmp_path, snap, enabled=True) is None
    (tmp_path / "X.DLL").write_bytes(b"2")
    assert c.verify_cwd_dlls(tmp_path, snap, enabled=True)
    (tmp_path / "X.DLL").unlink()
    assert c.snapshot_cwd_dlls(tmp_path, enabled=False) == {}


def _probe_env():
    return c.build_env(c.pinned_path_dirs(extra=[]))


def test_probe_success_and_hides_output(relaxed):
    exe = _native_exe()
    result = c.run_probe([exe], _probe_env())
    assert result.ok and result.stdout
    assert result.stdout_text().strip() not in repr(result)
    assert result.stdout_sha256() == hashlib.sha256(result.stdout).hexdigest()


def test_probe_refuses_bad_inputs():
    exe = _native_exe()
    assert c.run_probe(["relative-tool"], {}).error
    assert c.run_probe([exe], None).error
    assert c.run_probe([exe], {"X": "sekret"}, forbidden_values=["sekret"]).error
    assert c.run_probe([exe], {}, expect_sha256="0" * 64).error
    assert not c.run_probe([exe + ".missing"], {}).ok


def test_probe_truncation_and_nonzero(relaxed):
    exe = _native_exe()
    small = c.run_probe([exe], _probe_env(), max_output=2)
    assert small.truncated and not small.ok
    bad = c.run_probe([exe, "--definitely-not-a-flag"], _probe_env())
    assert not bad.ok and "status" in bad.failure_reason()


@pytest.mark.skipif(not WIN, reason="uses a Windows console tool to sleep")
def test_probe_timeout():
    ping = os.path.join(os.environ["SystemRoot"], "System32", "ping.exe")
    result = c.run_probe([ping, "-n", "6", "127.0.0.1"], _probe_env(), timeout=0.5)
    assert result.timed_out and not result.ok


def test_probe_cwd_is_empty_and_owned():
    first = c.probe_cwd()
    assert os.path.isdir(first) and os.listdir(first) == []
    Path(first, "planted.dll").write_bytes(b"x")
    second = c.probe_cwd()
    assert second != first and os.listdir(second) == []


# --- run_probe: process-tree kill and incomplete output (B3-02 / B3-03) -----------

_HOLDER = """
import subprocess, sys, time
grand, parent, marker = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
child = "import sys, time; time.sleep(float(sys.argv[1])); open(sys.argv[2], chr(119)).write(chr(120))"
subprocess.Popen([sys.executable, "-c", child, str(grand), marker],
                 stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stderr)
print("partial", flush=True)
time.sleep(parent)
"""


def _holder_script(sleep_grandchild: float, sleep_parent: float, marker: Path) -> list:
    return [sys.executable, "-c", _HOLDER, str(sleep_grandchild), str(sleep_parent), str(marker)]


def _wait_gone(marker: Path, seconds: float) -> bool:
    import time
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if marker.exists():
            return False
        time.sleep(0.2)
    return True


def test_probe_timeout_kills_the_whole_tree_and_returns(tmp_path):
    import time
    marker = tmp_path / "grandchild-ran"
    started = time.monotonic()
    result = c.run_probe(_holder_script(4, 60, marker), _probe_env(), timeout=1.0)
    elapsed = time.monotonic() - started
    assert result.timed_out and not result.ok
    assert elapsed < 3.9, f"run_probe blocked on the pipe holder ({elapsed:.1f}s)"
    assert _wait_gone(marker, 5.5), "the grandchild survived the timeout"


def test_probe_with_a_lingering_pipe_holder_is_not_ok(tmp_path):
    import time
    marker = tmp_path / "grandchild-ran"
    started = time.monotonic()
    # The direct child exits 0 at once, a grandchild keeps the output pipe open.
    result = c.run_probe(_holder_script(4, 0, marker), _probe_env(), timeout=20)
    elapsed = time.monotonic() - started
    assert result.returncode == 0 and not result.ok          # fail closed: output may be partial
    assert result.error and "output" in result.failure_reason()
    assert elapsed < 3.9
    assert _wait_gone(marker, 5.5), "the grandchild survived"
