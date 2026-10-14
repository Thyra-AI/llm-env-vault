"""Tests for vault_lib/profiles/exact.py and trust.persistent_or_8h_refusal
(2.4.0 always-allow, plan section 5.0): native-only, denylist, .cmd/.bat/.ps1
refusal, every drift case, env built from scratch."""
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib import trust  # noqa: E402
from vault_lib.profiles import Request, exact  # noqa: E402
from vault_lib.profiles import _common as c  # noqa: E402

WIN = os.name == "nt"


def _native_exe() -> str:
    if WIN:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "hostname.exe")
    return shutil.which("true") or "/bin/true"


class Ctx:
    def __init__(self, root: Path):
        self.root = root
        self.bin = root / "bin"
        self.cwd = root / "work"
        self.bin.mkdir()
        self.cwd.mkdir()
        self.cwd_str = os.path.normcase(os.path.realpath(self.cwd))

    def make_exe(self, name: str = "tool") -> str:
        dest = self.bin / (name + (".exe" if WIN else ""))
        shutil.copy(_native_exe(), dest)
        return str(dest.resolve())

    def req(self, *command, only=("API_TOKEN",)):
        return Request(tuple(command), self.cwd_str, tuple(only), None)

    def approve(self, *command, only=("API_TOKEN",)):
        req = self.req(*command, only=only)
        cand = exact.match(req)
        assert cand is not None
        entry = {"kind": "exact", "cwd": req.cwd, "only_vars": list(req.only_vars),
                 "shape": cand, "snapshot": exact.snapshot(req, cand)}
        return req, entry


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(c.RELAXATIONS, "skip_exe_dir_writable_check", True)
    # An empty fake home so the built-in monitored table never sees the real one.
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE", "APPDATA", "GH_CONFIG_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData"))
    root = tmp_path / "ctx"
    root.mkdir()
    return Ctx(root.resolve())


def _verdict_reason(entry, req):
    v = exact.verify(entry, req)
    assert v.ok is False
    return v.reason


# ---------------------------------------------------------------------------
# match: denylist, interpreters, scripts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("program", [
    "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh", "py", "node", "perl", "ruby",
    "wsl", "python", "python3", "python3.12", "pythonw", "Python.EXE", "BASH.exe",
    "/usr/bin/bash", r"C:\Windows\System32\cmd.exe", r"C:\Python312\python.exe",
    "npm", "npx", "yarn", "pnpm", "bun", "deno", "pytest", "tox", "nox", "cargo", "make",
    "cmake", "ninja", "gradle", "gradlew", "mvn", "mvnw", "dotnet", "go", "uv", "poetry",
    "pipx", "pre-commit", "just", "task", "rake", "bundle", "composer", "java",
    "Cargo.EXE", "/opt/x/bin/Java",
])
def test_match_refuses_shells_interpreters_and_launchers(program):
    assert exact.match(Request((program, "-c", "x"), os.getcwd())) is None
    assert exact.denied_program(program)


@pytest.mark.parametrize("program", [
    "rundll32", "RUNDLL32.EXE", r"C:\Windows\System32\rundll32.exe", "regsvr32", "wscript",
    "cscript.exe", "mshta", "msiexec", "forfiles", "cmstp", "installutil", "msbuild",
])
def test_match_refuses_windows_proxy_execution_launchers(program):
    # B4-01: `rundll32 tool.dll,Run` runs the DLL named inside one argument.
    assert exact.match(Request((program, r"C:\repo\tool.dll,Run"), os.getcwd())) is None
    assert exact.denied_program(program)


@pytest.mark.parametrize("program", [
    "git", "git.exe", "GIT.EXE", r"C:\Program Files\Git\cmd\git.exe", "/usr/bin/git",
    "docker", "Docker.exe", "docker-compose", "kubectl", "kubectl.exe", "helm", "helm.EXE",
    "git-credential-manager", "git-credential-store", "docker-credential-desktop.exe",
    "gh-credential-helper",
])
def test_match_refuses_tools_with_their_own_profile(program):
    assert exact.match(Request((program, "push", "--force", "origin", "main"), os.getcwd())) is None
    assert exact.denied_program(program)


@pytest.mark.parametrize("program", ["gh", "hostname", "gofmt", "/bin/true"])
def test_match_accepts_ordinary_programs(program):
    cand = exact.match(Request((program, "a"), os.getcwd()))
    assert cand is not None and cand["signature"][0] == [program, "a"]


@pytest.mark.parametrize("program", ["build.cmd", "BUILD.BAT", "x.ps1", "tool.cmd.", "x.cmd "])
def test_match_refuses_cmd_bat_ps1(program):
    assert exact.match(Request((program,), os.getcwd())) is None
    assert trust.persistent_or_8h_refusal([program], os.getcwd())


def test_match_refuses_bare_name_resolving_to_cmd(tmp_path, monkeypatch):
    script = tmp_path / "wrapper.cmd"
    script.write_text("@echo hi", encoding="utf-8")
    if not WIN:
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    if WIN:
        monkeypatch.setenv("PATHEXT", ".CMD;.EXE")
    # On POSIX the bare name "wrapper" does not find "wrapper.cmd" (no PATHEXT):
    # the predicate then has nothing to refuse, the extension test covers the path form.
    name = "wrapper" if WIN else "wrapper.cmd"
    assert exact.match(Request((name,), str(tmp_path))) is None
    assert trust.persistent_or_8h_refusal([name], str(tmp_path))


def test_ordinary_program_has_no_trust_refusal():
    assert trust.persistent_or_8h_refusal([_native_exe(), "x"], os.getcwd()) is None
    assert trust.persistent_or_8h_refusal([], os.getcwd()) is None


# ---------------------------------------------------------------------------
# snapshot: native only, pinning
# ---------------------------------------------------------------------------

def test_snapshot_refuses_non_native_program(ctx):
    fake = ctx.bin / ("fake.exe" if WIN else "fake")
    fake.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    if not WIN:
        fake.chmod(0o755)
    req = ctx.req(str(fake))
    cand = exact.match(req)
    assert cand is not None
    with pytest.raises(c.ProfileRefusal):
        exact.snapshot(req, cand)


def test_snapshot_refuses_unresolvable_and_relative_program(ctx):
    for program in ("definitely-not-a-real-program-xyz", os.path.join("sub", "tool.exe")):
        req = ctx.req(program)
        with pytest.raises(c.ProfileRefusal):
            exact.snapshot(req, exact.match(req))


def test_snapshot_never_searches_cwd(ctx, monkeypatch):
    ctx.make_exe("localtool")
    shutil.copy(_native_exe(), ctx.cwd / ("localtool" + (".exe" if WIN else "")))
    monkeypatch.setenv("PATH", str(ctx.root / "nowhere"))
    req = ctx.req("localtool")
    with pytest.raises(c.ProfileRefusal):
        exact.snapshot(req, exact.match(req))


def test_snapshot_shape_and_pin(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe, "-s")
    snap = entry["snapshot"]
    assert snap["pin"]["path"] == exe and snap["pin"]["fmt"] in ("pe", "elf", "macho")
    assert snap["pin"]["sha256"] == c.hash_file(exe)
    assert isinstance(snap["path_dirs"], list) and snap["cwd_dlls"] == {} \
        or WIN                                          # DLLs are snapshotted on Windows only
    assert set(snap["files"].values()) <= {"absent"}    # "-s" is not a file: recorded as absent
    assert snap["monitored"] == []
    import json
    assert json.loads(json.dumps(entry)) == entry       # round-trips through the vault
    assert exact.check_snapshot(entry) == (True, None)


def test_describe_and_label(ctx):
    exe = ctx.make_exe()
    req = ctx.req(exe, "-s", "x" * 300)
    text = exact.describe(req, exact.match(req))
    assert text.splitlines()[0].startswith("Exact command: '")
    assert exact.WARNING_LINE in text.splitlines()
    assert "agent can obtain these values" in text
    label = exact.label(req, exact.match(req))
    assert label.startswith("exact: ") and len(label) <= 100 and "\n" not in label
    assert "\n" not in exact.label(ctx.req(exe, "a\nb"), {})


# ---------------------------------------------------------------------------
# verify: happy path and the environment
# ---------------------------------------------------------------------------

def test_verify_ok_runs_pinned_absolute_path_with_scratch_env(ctx, monkeypatch):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe, "-s")
    monkeypatch.setenv("LEAKY_AMBIENT", "ambient-value")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    monkeypatch.setenv("PATH", str(ctx.root / "attacker-bin"))
    v = exact.verify(entry, req)
    assert v.ok and v.replace_env is True
    assert v.argv == [exe, "-s"]
    assert os.path.isabs(v.argv[0])
    assert "LEAKY_AMBIENT" not in v.env and "GIT_SSH_COMMAND" not in v.env
    assert str(ctx.root / "attacker-bin") not in v.env["PATH"].split(os.pathsep)
    assert v.env["PATH"].split(os.pathsep) == entry["snapshot"]["path_dirs"]
    assert "API_TOKEN" not in v.env                    # the caller adds vault values
    extra = set(v.env) - set(c.system_essentials()) - {"PATH"}
    assert extra == set() or WIN and all(k.upper() in {n.upper() for n in c.system_essentials()}
                                         for k in extra)


def test_verify_only_vars_may_be_a_subset_and_tool_control_names_are_refused(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe, only=("API_TOKEN", "DB_PASSWORD"))
    assert exact.verify(entry, ctx.req(exe, only=("API_TOKEN",))).ok
    reason = _verdict_reason(entry, ctx.req(exe, only=("PATH",)))
    assert "PATH" in reason and "tool-control" in reason


def test_verify_other_command_or_cwd_or_timeout_is_not_applicable(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe, "-s")
    assert exact.verify(entry, ctx.req(exe, "-f")).reason is None
    assert exact.verify(entry, ctx.req(exe)).ok is False
    other = Request(req.command, str(ctx.root), req.only_vars, None)
    assert exact.verify(entry, other).reason is None
    assert exact.verify(entry, Request(req.command, req.cwd, req.only_vars, 30)).reason is None
    assert exact.verify({"shape": "junk"}, req).reason is None


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------

def test_drift_program_changed(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    with open(exe, "ab") as handle:
        handle.write(b"\0tampered")
    assert "changed since it was approved" in _verdict_reason(entry, req)
    ok, reason = exact.check_snapshot(entry)
    assert ok is False and "changed" in reason


def test_drift_program_deleted_or_made_non_native(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    os.remove(exe)
    assert "missing" in _verdict_reason(entry, req)
    Path(exe).write_text("#!/bin/sh\n", encoding="utf-8")
    assert _verdict_reason(entry, req)                  # hash differs


def test_drift_program_location_no_longer_protected(ctx, monkeypatch):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    monkeypatch.setattr(c.RELAXATIONS, "skip_exe_dir_writable_check", False)
    reason = _verdict_reason(entry, req)                # tmp is user-writable
    assert "no longer protected" in reason


def test_drift_referenced_file_changed_deleted_and_appeared(ctx):
    exe = ctx.make_exe()
    present = ctx.cwd / "present.txt"
    present.write_text("v1", encoding="utf-8")
    req, entry = ctx.approve(exe, str(present), "later.txt")
    assert entry["snapshot"]["files"][str(present.resolve())] == c.hash_file(present)
    assert list(entry["snapshot"]["files"].values()).count("absent") == 1
    assert exact.verify(entry, req).ok
    present.write_text("v2", encoding="utf-8")
    assert "changed" in _verdict_reason(entry, req)
    present.write_text("v1", encoding="utf-8")
    assert exact.verify(entry, req).ok
    (ctx.cwd / "later.txt").write_text("surprise", encoding="utf-8")
    assert "appeared" in _verdict_reason(entry, req)
    assert "appeared" in exact.check_snapshot(entry)[1]
    (ctx.cwd / "later.txt").unlink()
    present.unlink()
    assert "no longer readable" in _verdict_reason(entry, req)


@pytest.mark.parametrize("make_arg", [
    lambda p: f"--var-file={p}",              # option=file
    lambda p: f"-d@{p}",                      # curl style
    lambda p: f"@{p}",                        # response file
    lambda p: f"{p},Entry",                   # rundll32 style, comma suffix
])
def test_file_inside_an_option_token_is_hashed_and_drift_detected(ctx, make_arg):
    # B4-02: the file the program reads is named inside the token, not the token.
    exe = ctx.make_exe()
    target = ctx.cwd / "prod.tfvars"
    target.write_text("v1", encoding="utf-8")
    rel = make_arg("prod.tfvars")
    req, entry = ctx.approve(exe, rel)
    assert entry["snapshot"]["files"][str(target.resolve())] == c.hash_file(target)
    assert exact.verify(entry, req).ok
    target.write_text("v2", encoding="utf-8")
    assert "changed" in _verdict_reason(entry, req)


def test_file_inside_an_option_token_absent_then_appears_is_drift(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe, "--var-file=later.tfvars")
    assert exact.verify(entry, req).ok
    (ctx.cwd / "later.tfvars").write_text("x", encoding="utf-8")
    assert "appeared" in _verdict_reason(entry, req)


def _symlink_or_skip(link: Path, target: Path):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def test_symlink_retarget_is_drift(ctx):
    # B4-04: the hash was keyed on the link target only.
    exe = ctx.make_exe()
    a, b = ctx.cwd / "a.txt", ctx.cwd / "b.txt"
    a.write_text("same", encoding="utf-8")
    b.write_text("same", encoding="utf-8")
    link = ctx.cwd / "config.json"
    _symlink_or_skip(link, a)
    req, entry = ctx.approve(exe, "config.json")
    assert exact.verify(entry, req).ok
    link.unlink()
    os.symlink(b, link)
    assert "link" in _verdict_reason(entry, req)


def test_dangling_symlink_is_recorded_and_retarget_is_drift(ctx):
    exe = ctx.make_exe()
    link = ctx.cwd / "config.json"
    _symlink_or_skip(link, ctx.cwd / "missing.txt")
    req, entry = ctx.approve(exe, "config.json")
    assert entry["snapshot"]["files"]            # not silently skipped
    assert exact.verify(entry, req).ok
    (ctx.cwd / "other.txt").write_text("x", encoding="utf-8")
    link.unlink()
    os.symlink(ctx.cwd / "other.txt", link)
    assert "link" in _verdict_reason(entry, req)


def test_argv0_is_not_in_the_file_record(ctx):
    exe = ctx.make_exe()
    _req, entry = ctx.approve(exe, exe)
    assert entry["snapshot"]["files"] == {}


def test_implicit_config_file_appearing_is_drift(ctx):
    docker = ctx.make_exe("podman")           # trust._IMPLICIT_CONFIG_FILES knows this stem
    req, entry = ctx.approve(docker, "version")
    assert exact.verify(entry, req).ok
    (ctx.cwd / "compose.yml").write_text("services: {}", encoding="utf-8")
    assert "appeared" in _verdict_reason(entry, req)


@pytest.mark.skipif(not WIN, reason="cwd DLL snapshot is Windows-only")
def test_drift_cwd_dll_added_and_changed(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    assert exact.verify(entry, req).ok
    dll = ctx.cwd / "evil.dll"
    dll.write_bytes(b"MZ-not-really")
    assert "DLLs in the working directory" in _verdict_reason(entry, req)
    assert exact.check_snapshot(entry)[0] is False
    dll.unlink()
    assert exact.verify(entry, req).ok


@pytest.mark.skipif(not WIN, reason="cwd DLL snapshot is Windows-only")
def test_existing_cwd_dll_recorded_and_changes_detected(ctx):
    dll = ctx.cwd / "ok.dll"
    dll.write_bytes(b"one")
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    assert list(entry["snapshot"]["cwd_dlls"]) == ["ok.dll"]
    dll.write_bytes(b"two")
    assert "ok.dll" in _verdict_reason(entry, req)


def test_drift_monitored_paths_changed_and_appeared(ctx):
    home = Path(os.environ["HOME"])
    exe = ctx.make_exe("aws")
    req, entry = ctx.approve(exe, "s3", "ls")
    mon = {m["path"]: m for m in entry["snapshot"]["monitored"]}
    cred = str(home / ".aws" / "credentials")
    assert os.path.normcase(cred) in {os.path.normcase(p) for p in mon}
    assert all(m["state"] == "absent" for m in mon.values())
    assert exact.verify(entry, req).ok
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text("[default]\nkey=1\n", encoding="utf-8")
    assert "monitored path" in _verdict_reason(entry, req)
    # Re-approve with the file present, then edit it.
    req, entry = ctx.approve(exe, "s3", "ls")
    assert exact.verify(entry, req).ok
    (home / ".aws" / "credentials").write_text("[default]\nkey=2\n", encoding="utf-8")
    assert "monitored path" in _verdict_reason(entry, req)
    assert "monitored path" in exact.check_snapshot(entry)[1]


def test_monitored_gh_config_dir_tree_and_state_yml_ignored(ctx):
    home = Path(os.environ["HOME"])
    cfg = home / ".config" / "gh"
    cfg.mkdir(parents=True)
    (cfg / "hosts.yml").write_text("github.com: {}", encoding="utf-8")
    exe = ctx.make_exe("gh")
    req, entry = ctx.approve(exe, "pr", "list")
    assert exact.verify(entry, req).ok
    (cfg / "state.yml").write_text("checked: now", encoding="utf-8")   # gh churns this file
    assert exact.verify(entry, req).ok
    (cfg / "config.yml").write_text("editor: evil", encoding="utf-8")
    assert "monitored path" in _verdict_reason(entry, req)


def test_monitored_terraform_plugins_listing_and_curl_netrc(ctx):
    home = Path(os.environ["HOME"])
    exe = ctx.make_exe("terraform")
    req, entry = ctx.approve(exe, "plan")
    plugins = home / ".terraform.d" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "provider").write_bytes(b"x")
    assert "monitored path" in _verdict_reason(entry, req)
    curl = ctx.make_exe("curl")
    req, entry = ctx.approve(curl, "https://example.test")
    names = {os.path.basename(m["path"]) for m in entry["snapshot"]["monitored"]}
    assert {".curlrc", "_curlrc", ".netrc"} <= names
    (home / ".netrc").write_text("machine x login y password z", encoding="utf-8")
    assert "monitored path" in _verdict_reason(entry, req)


def test_az_monitors_two_files_not_the_whole_directory(ctx):
    home = Path(os.environ["HOME"])
    exe = ctx.make_exe("az")
    req, entry = ctx.approve(exe, "account", "show")
    names = sorted(os.path.basename(m["path"]) for m in entry["snapshot"]["monitored"])
    assert names == ["clouds.config", "config"]
    (home / ".azure").mkdir()
    (home / ".azure" / "msal_token_cache.json").write_text("churn", encoding="utf-8")
    assert exact.verify(entry, req).ok


def test_malformed_snapshot_fails_closed(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    for broken in (None, {}, {"pin": {"path": "x"}}, {**entry["snapshot"], "files": []},
                   {**entry["snapshot"], "monitored": {}}, {**entry["snapshot"], "path_dirs": 3}):
        e = dict(entry, snapshot=broken)
        assert exact.verify(e, req).ok is False
        assert exact.check_snapshot(e)[0] is False
    assert exact.check_snapshot({"shape": {}, "cwd": "x", "snapshot": entry["snapshot"]})[0] is False


def test_verify_refuses_after_denylist_growth_or_cmd_swap(ctx):
    exe = ctx.make_exe()
    req, entry = ctx.approve(exe)
    # An entry whose command was later turned into a refused program must not run.
    bad = dict(entry, shape={"signature": [["build.cmd"], req.cwd, None, None, False, None,
                                           None, None]})
    assert exact.check_snapshot(bad)[0] is False


# ---------------------------------------------------------------------------
# trust: .cmd/.bat/.ps1 never trusted (8 h tier)
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_trust():
    def clear():
        trust._trusted.clear()
        trust._cached_secrets.clear()
        trust._cache_keys.clear()
        trust._cached_vault_fingerprint = None
    clear()
    yield
    clear()


def test_trust_check_refuses_and_deletes_cmd_entries(clean_trust, tmp_path):
    command = ["build.cmd", "--x"]
    sig = trust.make_signature(command, str(tmp_path), ("A",), None)
    trust._trusted[sig] = {"hashes": {}, "granted_wall": 1e18, "granted_mono": 1e18}
    trust._cached_secrets[sig] = {}
    trust._cache_keys[sig] = b"k"
    ok, reason = trust.check(sig, command, str(tmp_path))
    assert ok is False and ".cmd" in reason
    assert sig not in trust._trusted and sig not in trust._cached_secrets \
        and sig not in trust._cache_keys


def test_trust_check_unaffected_for_native_programs(clean_trust, tmp_path):
    command = [_native_exe(), "x"]
    sig = trust.make_signature(command, str(tmp_path), ("A",), None)
    trust.trust(sig, trust.referenced_file_hashes(command, str(tmp_path)))
    trust.cache_secrets(sig, {"A": "value-12345678"})
    assert trust.check(sig, command, str(tmp_path)) == (True, None)


@pytest.mark.parametrize("name", ["x.bat", "x.PS1", "x.Cmd"])
def test_trust_refusal_by_extension(name, clean_trust, tmp_path):
    command = [name]
    sig = trust.make_signature(command, str(tmp_path), ("A",), None)
    trust._trusted[sig] = {"hashes": {}, "granted_wall": 1e18, "granted_mono": 1e18}
    trust._cached_secrets[sig] = {}
    assert trust.check(sig, command, str(tmp_path))[0] is False
    assert sig not in trust._trusted
