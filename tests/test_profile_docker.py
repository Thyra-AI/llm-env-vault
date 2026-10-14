"""Tests for vault_lib/profiles/docker.py (2.4.0 always-allow, plan section 5.2).

Pure unit tests (grammar tables, image references, raw-YAML scan, model lint,
env, versions, endpoint, plugin shadowing) plus integration tests that run the
real ``docker compose config`` (needs the docker CLI and the compose plugin, no
daemon, no containers; skipped when they are unavailable).  The user's real
``~/.docker`` is never read: ``user_docker_dir`` points at a scratch directory.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib.profiles import Request, Verdict  # noqa: E402
from vault_lib.profiles import _common as c  # noqa: E402
from vault_lib.profiles import docker as d  # noqa: E402

WIN = os.name == "nt"

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

needs_yaml = pytest.mark.skipif(not HAVE_YAML, reason="PyYAML is not installed")

BASE = ("docker", "compose", "-f", "c.yaml", "-p", "demo")


def P(*tail, base=BASE):
    return d.parse_command(tuple(base) + tuple(tail))


# ---------------------------------------------------------------------------
# Argv grammar: compose
# ---------------------------------------------------------------------------

UP_OK = [["-d"], ["--detach"], ["--wait"], ["--wait-timeout=30"], ["--no-build"], ["--build"],
         ["--pull=always"], ["--pull=missing"], ["--pull=never"], ["--no-recreate"],
         ["--force-recreate"], ["--no-deps"], ["--quiet-pull"], ["--no-color"],
         ["-t", "10"], ["--timeout=10"], ["--remove-orphans"], ["-d", "web", "db"]]
DOWN_OK = [["-t", "5"], ["--timeout=5"], ["--remove-orphans"], []]
LOGS_OK = [["--tail=10"], ["-n", "10"], ["--tail=all"], ["--since=1h"], ["--until=2024-01-01T00:00:00"],
           ["-t"], ["--timestamps"], ["--no-color"], ["--no-log-prefix"], ["web"]]
PULL_OK = [["-q"], ["--quiet"], ["--policy=always"], ["--policy=missing"],
           ["--ignore-pull-failures"], ["web"]]
PS_OK = [["-a"], ["--all"], ["--format=json"], ["--format=table"], ["--status=running"], []]
BUILD_OK = [["--pull"], ["--no-cache"], ["-q"], ["--quiet"], ["web"], ["--pull", "--no-cache", "web"]]


@pytest.mark.parametrize("sub,tail", [("up", t) for t in UP_OK] + [("down", t) for t in DOWN_OK]
                         + [("logs", t) for t in LOGS_OK] + [("pull", t) for t in PULL_OK]
                         + [("ps", t) for t in PS_OK] + [("build", t) for t in BUILD_OK])
def test_compose_allowlisted_flags_parse(sub, tail):
    cmd = P(sub, *tail)
    assert isinstance(cmd, d.ComposeCommand) and cmd.sub == sub
    assert cmd.project == "demo" and cmd.files == ["c.yaml"]


UP_BAD = [["--watch"], ["-w"], ["--menu"], ["-y"], ["--scale=web=2"], ["--exit-code-from=web"],
          ["--abort-on-container-exit"], ["--abort-on-container-failure"],
          ["--always-recreate-deps"], ["--attach=web"], ["--attach-dependencies"],
          ["--no-attach=web"], ["--no-log-prefix"], ["--no-start"], ["--quiet-build"], ["-V"],
          ["--timestamps"], ["--pull", "always"], ["--pull=weird"], ["--wait-timeout=abc"],
          ["-t", "-5"], ["-t", "10s"], ["-d=true"], ["-dt", "5"], ["--"], ["@args"], ["-"],
          ["--detach", "--detach"], ["--no-ansi"]]
DOWN_BAD = [["-v"], ["--volumes"], ["--rmi=all"], ["--rmi", "all"], ["--timeout", "5"]]
LOGS_BAD = [["-f"], ["--follow"], ["--index=1"], ["--tail=-1"], ["--tail=10;x"], ["--since=$(x)"]]
PULL_BAD = [["--include-deps"], ["--ignore-buildable"], ["--policy=never"], ["-a"]]
PS_BAD = [["--filter=status=running"], ["--no-trunc"], ["-q"], ["--services"], ["--orphans"],
          ["--format=weird"], ["--status=bogus"]]
BUILD_BAD = [["--push"], ["--print"], ["--ssh=default"], ["--secret=id=x"], ["--builder=x"],
             ["--build-arg=A=1"], ["--with-dependencies"], ["--check"], ["-m", "1g"],
             ["--provenance=false"], ["--sbom=true"], ["--pull=always"]]


@pytest.mark.parametrize("sub,tail", [("up", t) for t in UP_BAD] + [("down", t) for t in DOWN_BAD]
                         + [("logs", t) for t in LOGS_BAD] + [("pull", t) for t in PULL_BAD]
                         + [("ps", t) for t in PS_BAD] + [("build", t) for t in BUILD_BAD])
def test_compose_rejected_flags(sub, tail):
    with pytest.raises(c.ArgvRejected):
        P(sub, *tail)


GLOBAL_BAD = [["--env-file=x"], ["--env-file", "x"], ["--project-directory=/tmp"],
              ["--project-directory", "/tmp"], ["--compatibility"], ["-H", "tcp://evil:2375"],
              ["--host=tcp://evil"], ["--context=other"], ["--config=/tmp/x"], ["--tls"],
              ["--tlsverify"], ["--tlscacert=x"], ["--parallel=1"], ["--all-resources"],
              ["--ansi", "always"], ["--progress=bogus"], ["--ansi=weird"]]


@pytest.mark.parametrize("flags", GLOBAL_BAD)
def test_compose_rejected_global_flags(flags):
    with pytest.raises(c.ArgvRejected):
        d.parse_command(("docker", "compose", "-f", "c.yaml", "-p", "demo", *flags, "up"))


def test_compose_global_flags_accepted_and_canonicalised():
    cmd = d.parse_command(("docker", "compose", "--file=a.yaml", "-f", "b.yaml", "--project-name=demo",
                           "--profile=dev", "--profile=app", "--ansi=never", "--progress=plain",
                           "--dry-run", "up", "-t", "10", "web"))
    assert cmd.files == ["a.yaml", "b.yaml"] and cmd.profiles == ["app", "dev"]
    assert cmd.flags.canonical_flag_tokens() == ["--timeout=10"]
    assert d._compose_global_tokens(cmd) == ["--ansi=never", "--progress=plain", "--dry-run"]
    assert cmd.services == ["web"]


@pytest.mark.parametrize("command", [
    ("docker", "compose", "-p", "demo", "up"),                       # no -f
    ("docker", "compose", "-f", "c.yaml", "up"),                      # no -p
    ("docker", "compose", "-f", "c.yaml", "-p", "Bad_Name", "up"),    # uppercase
    ("docker", "compose", "-f", "c.yaml", "-p", "-x", "up"),
    ("docker", "compose", "-f", "c.yaml", "-p", "demo"),              # no subcommand
    ("docker", "compose", "-f", "c.yaml", "-p", "demo", "--profile=-bad", "up"),
    ("docker", "compose", "-f", "c.yaml", "-p", "demo", "up", "web;rm"),
    ("docker", "compose", "-f", "c.yaml", "-p", "demo", "up", "web", "web"),
    ("docker", "compose", "-f", "c.yaml", "-p", "demo", "up", "-x"),
    ("docker", "-H", "tcp://evil:2375", "compose", "-f", "c.yaml", "-p", "demo", "up"),
    ("docker", "--context", "evil", "compose", "-f", "c.yaml", "-p", "demo", "up"),
    ("/usr/bin/docker", "compose", "-f", "c.yaml", "-p", "demo", "up"),
    ("podman", "compose", "-f", "c.yaml", "-p", "demo", "up"),
    ("docker", "build", "."),
    ("docker", "run", "alpine"),
    ("docker", "pull"),
    ("docker",),
])
def test_compose_malformed_commands_rejected(command):
    with pytest.raises(c.ArgvRejected):
        d.parse_command(command)


@pytest.mark.parametrize("sub", ["run", "exec", "cp", "config", "restart", "kill", "rm", "start",
                                 "stop", "create", "watch", "events", "push", "top", "version"])
def test_compose_other_subcommands_rejected(sub):
    with pytest.raises(c.ArgvRejected):
        P(sub)


@pytest.mark.parametrize("program", ["docker", "docker.exe", "DOCKER.EXE"])
def test_program_spellings(program):
    assert isinstance(d.parse_command((program, "compose", "-f", "c", "-p", "d", "ps")),
                      d.ComposeCommand)


@pytest.mark.parametrize("bad", ["docker\n", "up\x00", "ba\u202ed", "a\u200bb"])
def test_unsafe_text_rejected(bad):
    with pytest.raises(c.ArgvRejected):
        d.parse_command(("docker", "compose", "-f", "c.yaml", "-p", "demo", "up", bad))


# ---------------------------------------------------------------------------
# Image references (docker pull / push)
# ---------------------------------------------------------------------------

DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize("text,registry,path,tag,digest", [
    ("alpine", "docker.io", "library/alpine", None, None),
    ("alpine:3.20", "docker.io", "library/alpine", "3.20", None),
    ("library/alpine", "docker.io", "library/alpine", None, None),
    ("docker.io/alpine", "docker.io", "library/alpine", None, None),
    ("index.docker.io/library/alpine:3", "docker.io", "library/alpine", "3", None),
    ("registry-1.docker.io/foo/bar:1", "docker.io", "foo/bar", "1", None),
    ("registry.hub.docker.com/foo/bar", "docker.io", "foo/bar", None, None),
    ("DOCKER.IO/foo/bar", "docker.io", "foo/bar", None, None),
    ("myorg/app:v1.2_3-rc.1", "docker.io", "myorg/app", "v1.2_3-rc.1", None),
    ("ghcr.io/org/team/app:1", "ghcr.io", "org/team/app", "1", None),
    ("localhost/app", "localhost", "app", None, None),
    ("localhost:5000/app:2", "localhost:5000", "app", "2", None),
    ("registry.example.com:5443/a/b.c/d__e/f--g", "registry.example.com:5443", "a/b.c/d__e/f--g",
     None, None),
    (f"alpine@{DIGEST}", "docker.io", "library/alpine", None, DIGEST),
    (f"ghcr.io/org/app:1@{DIGEST}", "ghcr.io", "org/app", "1", DIGEST),
])
def test_parse_reference_accepts(text, registry, path, tag, digest):
    ref = d.parse_reference(text)
    assert (ref.registry, ref.path, ref.tag, ref.digest) == (registry, path, tag, digest)


@pytest.mark.parametrize("text", [
    "", "-alpine", "--platform=x", " alpine", "alpine ", "Alpine", "alpine:", "alpine:-x",
    "alpine:" + "a" * 129, "alpine@sha256:abc", "alpine@sha512:" + "a" * 128,
    f"alpine@{DIGEST.upper()}", "alpine@", "ghcr.io/Org/app", "ghcr.io//app", "ghcr.io/",
    "ghcr.io/org/app/", "ghcr.io/org/.app", "ghcr.io/org/app.", "ghcr.io/org/_app",
    "ghcr.io/org/a___b", "ghcr.io/org/a b", "ghcr.io/org/a;b", "ghcr.io/org/a\nb",
    "-bad.example.com/app", "bad_host.example.com/app", "host..com/app", "a" * 300,
    "http://ghcr.io/app", "ghcr.io/org/app:tag:tag2", "alpine\u202e", "alpine\x00",
])
def test_parse_reference_rejects(text):
    with pytest.raises(c.ArgvRejected):
        d.parse_reference(text)


def test_parse_reference_uppercase_first_component_is_a_registry_not_hub():
    # distribution/reference: an uppercase first component counts as a domain
    ref = d.parse_reference("Registry.Example/app")
    assert ref.registry == "registry.example" and ref.path == "app"


def _img(op, *args):
    cmd = d.parse_command(("docker", op) + args)
    return cmd, d.parse_reference(cmd.image)


def test_image_commands_and_flags():
    cmd, ref = _img("pull", "--platform=linux/amd64", "-q", "ghcr.io/org/app:1")
    assert cmd.op == "pull" and ref.registry == "ghcr.io"
    assert cmd.flags.canonical_flag_tokens() == ["--platform=linux/amd64", "--quiet"]
    for bad in (["-a", "alpine"], ["--all-tags", "alpine"], ["--platform", "linux/amd64", "alpine"],
                ["--platform=LINUX/AMD64", "alpine"], ["--disable-content-trust", "alpine"],
                ["alpine", "busybox"], [], ["--", "alpine"], ["--platform=linux/amd64"]):
        with pytest.raises(c.ArgvRejected):
            d.parse_command(("docker", "pull", *bad))


def test_image_shape_and_clamp():
    cmd, ref = _img("push", "ghcr.io/org/app:1")
    shape = d.image_shape(cmd, ref)
    assert shape == {"family": "image", "op": "push", "registry": "ghcr.io", "namespace": "org",
                     "tag_pattern": d.DEFAULT_TAG_PATTERN, "allow_latest": False}

    def problem(op, text):
        cmd2, ref2 = _img(op, text)
        return d.image_problem(shape, cmd2, ref2)

    assert problem("push", "ghcr.io/org/other:2") is None
    assert problem("push", "ghcr.io/org/team/other:2") is None          # sub-namespace
    assert problem("push", "ghcr.io/org/app") is not None               # implicit latest
    assert problem("push", "ghcr.io/org/app:latest") is not None
    assert problem("push", "ghcr.io/orgx/app:1")                        # prefix is not a path boundary
    assert problem("push", "ghcr.io/app:1")                             # outside namespace
    assert problem("push", "quay.io/org/app:1")                         # other registry
    assert problem("pull", "ghcr.io/org/app:1")                         # other op
    assert problem("push", f"ghcr.io/org/app@{DIGEST}")                 # push takes no digest


def test_image_clamp_hub_aliases_root_namespace_and_latest():
    cmd, ref = _img("pull", "alpine:3")
    shape = d.image_shape(cmd, ref)
    assert shape["registry"] == "docker.io" and shape["namespace"] == "library"
    for text in ("docker.io/library/busybox:1", "index.docker.io/library/busybox:1", "busybox:1"):
        cmd2, ref2 = _img("pull", text)
        assert d.image_problem(shape, cmd2, ref2) is None, text
    cmd2, ref2 = _img("pull", "someone/app:1")
    assert d.image_problem(shape, cmd2, ref2)
    cmd2, ref2 = _img("pull", f"alpine@{DIGEST}")
    assert d.image_problem(shape, cmd2, ref2) is None                   # digest pull, no tag test
    cmd3, ref3 = _img("pull", "localhost:5000/tool:1")
    root_shape = d.image_shape(cmd3, ref3)
    assert root_shape["namespace"] == ""
    cmd4, ref4 = _img("pull", "localhost:5000/other:1")
    assert d.image_problem(root_shape, cmd4, ref4) is None
    cmd5, ref5 = _img("pull", "localhost:5000/x/other:1")
    assert d.image_problem(root_shape, cmd5, ref5)
    cmd6, ref6 = _img("pull", "alpine")                                  # latest approved when asked
    latest = d.image_shape(cmd6, ref6)
    assert latest["allow_latest"] is True
    assert d.image_problem(latest, *reversed((ref6, cmd6))) is None


def test_image_tag_pattern_is_enforced_and_bad_pattern_fails_closed():
    cmd, ref = _img("pull", "ghcr.io/org/app:v1")
    shape = dict(d.image_shape(cmd, ref), tag_pattern=r"v[0-9]+")
    assert d.image_problem(shape, *reversed((ref, cmd))) is None
    cmd2, ref2 = _img("pull", "ghcr.io/org/app:dev")
    assert d.image_problem(shape, cmd2, ref2)
    assert d.image_problem(dict(shape, tag_pattern="("), cmd, ref)


# ---------------------------------------------------------------------------
# Versions, endpoint, env
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,ok", [
    ("5.4.0", True), ("v5.4.0", True), ("5.0.0\n", True), ("2.40.2", True), ("v2.40.2-desktop.1", True),
    ("2.41.0", True), ("2.100.0", True), ("2.40.1", False), ("2.9.9", False), ("2.39.9", False),
    ("1.29.2", False), ("", False), ("garbage", False), (None, False),
])
def test_compose_version_floor_is_numeric(text, ok):
    assert (d.compose_version_problem(text) is None) is ok


def test_desktop_floor_only_applies_to_docker_desktop():
    assert d.desktop_problem("Docker Desktop 4.88.1 (237512)") is None
    assert d.desktop_problem("Docker Desktop 4.44.3 (1)") is None
    assert d.desktop_problem("Docker Desktop 4.9.0 (1)")
    assert d.desktop_problem("Docker Desktop 4.44.2 (1)")
    assert d.desktop_problem("Docker Engine - Community") is None
    assert d.desktop_problem(None) is None


@pytest.mark.parametrize("endpoint,ok", [
    ("npipe:////./pipe/docker_engine", True),
    ("npipe:////./pipe/dockerDesktopLinuxEngine", True),
    ("unix:///var/run/docker.sock", True),
    ("unix:///run/user/1000/docker.sock", True),
    ("unix:///run/user/1000/../../docker.sock", False),
    ("unix:///run/user//docker.sock", False),
    ("tcp://127.0.0.1:2375", False), ("tcp://evil:2375", False), ("ssh://user@host", False),
    ("npipe:////./pipe/other", False), ("unix:///tmp/docker.sock", False),
    ("npipe:////./pipe/docker_engine ", False), ("", False), (None, False),
])
def test_endpoint_allowlist(endpoint, ok):
    assert d.endpoint_allowed(endpoint) is ok


def _probe_result(stdout=b"", rc=0):
    return c.ProbeResult(returncode=rc, stdout=stdout)


def test_resolve_endpoint_refuses_a_disallowed_endpoint(monkeypatch):
    pin = c.PinnedBinary(os.path.abspath("docker.exe"), "0" * 64, "pe", 1)
    monkeypatch.setattr(d, "user_docker_dir", lambda: str(Path(tempfile.gettempdir())))
    for text, ok in (("npipe:////./pipe/docker_engine\n", True), ("tcp://10.0.0.1:2375\n", False),
                     ("\n", False)):
        monkeypatch.setattr(d, "_probe_text", lambda *a, _t=text, **k: _t)
        if ok:
            assert d._resolve_endpoint(pin, []) == "npipe:////./pipe/docker_engine"
        else:
            with pytest.raises(c.ProfileRefusal):
                d._resolve_endpoint(pin, [])


def test_env_is_built_from_scratch_and_drops_docker_compose_buildkit_proxies():
    source = {
        "SystemRoot": r"C:\Windows", "HOME": "/home/u", "USERPROFILE": r"C:\Users\u",
        "DOCKER_HOST": "tcp://evil:2375", "DOCKER_CONTEXT": "evil", "DOCKER_CONFIG": "/evil",
        "DOCKER_CONTENT_TRUST": "0", "DOCKER_TLS_VERIFY": "0",
        "COMPOSE_FILE": "evil.yaml", "COMPOSE_PROJECT_NAME": "evil", "COMPOSE_PROFILES": "x",
        "BUILDKIT_HOST": "tcp://x", "BUILDX_BUILDER": "evil", "BUILDX_CONFIG": "/x",
        "HTTP_PROXY": "http://p", "HTTPS_PROXY": "http://p", "http_proxy": "http://p",
        "NO_PROXY": "x", "ALL_PROXY": "x", "API_TOKEN": "real-value", "LD_PRELOAD": "x",
    }
    env = d.docker_env(["/safe/bin"], "/vault/cfg", source=source, windows=False)
    assert env["DOCKER_CONFIG"] == "/vault/cfg"
    assert env["PATH"] == "/safe/bin"
    for name in env:
        upper = name.upper()
        assert not upper.startswith(("COMPOSE_", "BUILDKIT_", "BUILDX_")), name
        assert "PROXY" not in upper, name
        assert upper == "DOCKER_CONFIG" or not upper.startswith("DOCKER_"), name
    assert "API_TOKEN" not in env and "LD_PRELOAD" not in env


def test_env_injected_values_are_checked_and_extra_wins():
    env = d.docker_env(["/b"], "/cfg", injected={"API_TOKEN": "v"}, source={}, windows=False)
    assert env["API_TOKEN"] == "v" and env["DOCKER_CONFIG"] == "/cfg"
    for name in ("DOCKER_HOST", "COMPOSE_FILE", "HTTPS_PROXY", "BUILDX_BUILDER"):
        with pytest.raises(c.EnvNameRefused):
            d.docker_env(["/b"], "/cfg", injected={name: "x"}, source={}, windows=False)


def test_sentinels_are_distinct_per_variable_and_constant():
    s = d._sentinels(["A", "B", "API_TOKEN"])
    assert len(set(s.values())) == 3
    assert s["A"] == d.SENTINEL_PREFIX + "A__" and s == d._sentinels(["A", "B", "API_TOKEN"])
    assert all(v.startswith(d.SENTINEL_PREFIX) for v in s.values())


# ---------------------------------------------------------------------------
# Vault-owned DOCKER_CONFIG
# ---------------------------------------------------------------------------

def test_sanitise_keeps_only_hosts_store_and_helpers():
    cfg = {"auths": {"ghcr.io": {}, "docker.io": {"email": "x"}}, "credsStore": "desktop",
           "credHelpers": {"gcr.io": "gcloud"}, "currentContext": "evil", "plugins": {"a": {}},
           "proxies": {"default": {"httpProxy": "http://p"}}, "HttpHeaders": {"X": "y"},
           "cliPluginsExtraDirs": ["/evil"], "features": {"x": "y"}}
    out = d.sanitise_docker_config(cfg)
    assert out.vault_doc == {"auths": {"docker.io": {}, "ghcr.io": {}}, "credsStore": "desktop",
                             "credHelpers": {"gcr.io": "gcloud"}}
    assert out.helpers == ["desktop", "gcloud"]
    joined = " ".join(out.findings)
    for key in ("currentContext", "plugins", "proxies", "HttpHeaders", "cliPluginsExtraDirs"):
        assert key in joined
    text = d.config_text(out.vault_doc)
    assert "cli-plugins" not in text and "evil" not in text


@pytest.mark.parametrize("cfg", [
    {"auths": {"ghcr.io": {"auth": "dXNlcjpwYXNz"}}},
    {"auths": {"ghcr.io": {"identitytoken": "t"}}},
    {"auths": {"ghcr.io": {"password": "p"}}},
    {"auths": [1]}, {"credsStore": "../evil"}, {"credsStore": "a b"}, {"credsStore": 3},
    {"credHelpers": {"gcr.io": "x/../y"}}, {"credHelpers": {"gcr.io": ""}},
    {"credHelpers": []}, [], "text",
])
def test_sanitise_refuses_inline_credentials_and_odd_helpers(cfg):
    with pytest.raises(c.ProfileRefusal):
        d.sanitise_docker_config(cfg)


def test_sanitise_none_is_empty():
    assert d.sanitise_docker_config(None).vault_doc == {}


def test_vault_config_dir_holds_only_config_json_and_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    doc = {"auths": {"ghcr.io": {}}, "credsStore": "desktop"}
    base = d.ensure_config_dir(doc)
    assert os.listdir(base) == ["config.json"]
    assert json.loads(Path(base, "config.json").read_text()) == doc
    assert d.ensure_config_dir(doc) == base
    assert d.ensure_config_dir({"auths": {}}) != base                    # content-addressed
    os.makedirs(os.path.join(base, "cli-plugins"))
    Path(base, "cli-plugins", "docker-compose.exe").write_bytes(b"x")
    with pytest.raises(c.ProfileRefusal):
        d.ensure_config_dir(doc)
    shutil.rmtree(os.path.join(base, "cli-plugins"))
    Path(base, "config.json").write_text('{"proxies": {}}')
    with pytest.raises(c.ProfileRefusal):
        d.ensure_config_dir(doc)


def test_user_cli_plugins_dir_with_compose_plugin_is_refused(tmp_path, monkeypatch):
    pin_dict = {"path": str(tmp_path / "docker.exe"), "sha256": "0" * 64, "fmt": "pe", "size": 1}
    pin = c.PinnedBinary.from_dict(pin_dict)
    plugin_dir = tmp_path / "cli-plugins"
    plugin_dir.mkdir()
    monkeypatch.setattr(d, "_plugin_search_dirs", lambda config_dir: [str(plugin_dir)])
    plugins = json.dumps([{"Name": "compose", "Path": str(tmp_path / "docker-compose.exe")}])
    monkeypatch.setattr(d, "_probe_text", lambda *a, **k: plugins)
    resolved = []
    monkeypatch.setattr(c, "resolve_pinned_binary",
                        lambda path, **k: resolved.append(path) or pin)
    # empty dir: fine whatever its permissions
    monkeypatch.setattr(c, "dir_not_user_writable", lambda p: False)
    assert d._resolve_compose_plugin(pin, [], str(tmp_path), "ep") is pin
    # user-writable dir holding docker-compose*: shadowing risk -> refused
    (plugin_dir / "docker-compose.exe").write_bytes(b"x")
    with pytest.raises(c.ProfileRefusal, match="shadow"):
        d._resolve_compose_plugin(pin, [], str(tmp_path), "ep")
    # the same dir when protected is acceptable
    monkeypatch.setattr(c, "dir_not_user_writable", lambda p: True)
    assert d._resolve_compose_plugin(pin, [], str(tmp_path), "ep") is pin
    # no compose plugin reported at all
    monkeypatch.setattr(d, "_probe_text", lambda *a, **k: "[]")
    with pytest.raises(c.ProfileRefusal):
        d._resolve_compose_plugin(pin, [], str(tmp_path), "ep")


def test_vault_config_dir_is_never_a_plugin_search_dir_with_content(tmp_path):
    dirs = d._plugin_search_dirs(str(tmp_path))
    assert dirs[0] == os.path.join(str(tmp_path), "cli-plugins")


# ---------------------------------------------------------------------------
# Path normalisation and bind classification
# ---------------------------------------------------------------------------

HOME = "C:\\Users\\alice" if WIN else "/home/alice"
BS = chr(92)


def _bs(text):
    return text.replace("/", BS)


@pytest.mark.parametrize("path,danger", [
    ("/", True), ("//", True), ("C:\\", True), ("c:/", True), ("D:", True),
    (HOME, True), (HOME + "/", True), (HOME.replace("\\", "/").upper(), True),
    (os.path.dirname(HOME.replace("\\", "/")), True),
    ("/var/run/docker.sock", True), ("//var/run/docker.sock", True),
    ("\\\\var\\run\\docker.sock", True), ("/VAR/RUN/Docker.sock", True),
    ("/run/user/1000/docker.sock", True),
    ("\\\\.\\pipe\\docker_engine", True), ("\\.\\pipe\\docker_engine", True),
    ("//./pipe/docker_engine", True), ("\\\\.\\pipe\\dockerDesktopLinuxEngine", True),
    ("/srv/project", False), (HOME + "/project", False), ("C:\\work\\app", False),
    ("/var/run/other.sock", False),
    # B5-01: a directory that contains the socket exposes it as well
    ("/var", True), ("/var/", True), ("/var/run", True), ("/VAR/Run/", True), ("//var//run", True),
    ("/run", True), ("/run/user", True), ("/run/user/1000", True), ("/run/user/1000/", True),
    ("/var/run/../run", True),
    (HOME.replace(BS, "/") + "/.docker/run", True), (HOME.replace(BS, "/") + "/.docker", True),
    (_bs("//./pipe"), True), ("//./pipe", True), ("//./pipe/", True),
    # B5-02: four (or more) leading slashes unify with the pipe form
    ("////./pipe/docker_engine", True), (_bs("////./pipe/docker_engine"), True),
    ("///./pipe/dockerDesktopLinuxEngine", True), ("/////./pipe/docker_engine/", True),
    ("/run/other", False), ("/run/user/1000/other", False), ("/var/lib", False), ("/srv", False),
])
def test_bind_danger(path, danger):
    assert bool(d.bind_danger(path, home=HOME)) is danger


def test_norm_host_path_unifies_every_pipe_spelling():
    want = "//./pipe/docker_engine"
    for text in (_bs("//./pipe/docker_engine"), _bs("/./pipe/docker_engine"), "//./pipe/docker_engine",
                 "/./pipe/docker_engine", "///./pipe/docker_engine", "////./pipe/docker_engine",
                 _bs("////./pipe/Docker_Engine/")):
        assert d.norm_host_path(text) == want, text


def test_bind_danger_expands_tilde(monkeypatch):
    monkeypatch.setenv("HOME", "/home/bob")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\bob")
    assert d.bind_danger("~", home=d.norm_host_path(os.path.expanduser("~")))
    assert d.norm_host_path("~/x") == d.norm_host_path(os.path.join(os.path.expanduser("~"), "x"))


# ---------------------------------------------------------------------------
# Raw-YAML scan (pure; before any `compose config`)
# ---------------------------------------------------------------------------

def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


@needs_yaml
def test_scan_accepts_a_local_chain_and_records_files_and_env_files(tmp_path):
    _write(tmp_path / "sub" / "inc.yaml", "services:\n  b:\n    image: x\n    extends:\n      file: ../ext.yaml\n      service: base\n")
    _write(tmp_path / "ext.yaml", "services:\n  base:\n    image: y\n")
    top = _write(tmp_path / "compose.yaml",
                 "include:\n  - sub/inc.yaml\n  - path: [sub/inc.yaml]\n    env_file: inc.env\n"
                 "services:\n  a:\n    build: .\n    env_file:\n      - app.env\n      - path: opt.env\n"
                 "        required: false\n")
    res = d.scan_compose_files([top])
    assert res.ok, res.problems
    assert [os.path.basename(f) for f in res.files] == ["compose.yaml", "inc.yaml", "ext.yaml"]
    assert {os.path.basename(f) for f in res.env_files} == {"inc.env", "app.env", "opt.env"}


@needs_yaml
@pytest.mark.parametrize("body", [
    "    env_file: '${ENVF_PATH}'\n",
    "    env_file: '$ENVF'\n",
    "    env_file:\n      - ok.env\n      - dir/$X.env\n",
    "    env_file:\n      - path: ${P}\n        required: false\n",
])
def test_scan_refuses_env_file_paths_with_a_variable(tmp_path, body):
    # B5-04: interpolation would point compose at an unscanned, untracked file
    top = _write(tmp_path / "compose.yaml", "services:\n  a:\n    image: x\n" + body)
    res = d.scan_compose_files([top])
    assert not res.ok and any("env_file" in p and "variable" in p for p in res.problems), res.problems


@needs_yaml
@pytest.mark.parametrize("value", ["[1]", "{}", "''"])
def test_scan_refuses_unusable_env_file_entries(tmp_path, value):
    top = _write(tmp_path / "compose.yaml", f"services:\n  a:\n    image: x\n    env_file: {value}\n")
    assert not d.scan_compose_files([top]).ok


@needs_yaml
@pytest.mark.parametrize("ref", [
    "oci://docker.io/library/x:1", "https://example.com/x.yaml", "http://example.com/x.yaml",
    "git+https://example.com/x.git", "git@github.com:org/repo.git", "github.com/org/repo",
    "https://example.com/repo.git#main:sub/c.yaml", "ssh://git@host/x",
    "GitLab.com/org/repo", "bitbucket.com/org/repo", "x.git", "repo.git#main",
])
def test_scan_refuses_remote_includes_and_extends(tmp_path, ref):
    short = _write(tmp_path / "a" / "compose.yaml", f"include:\n  - '{ref}'\n")
    pathform = _write(tmp_path / "b" / "compose.yaml", f"include:\n  - path: ['{ref}']\n")
    ext = _write(tmp_path / "c" / "compose.yaml",
                 f"services:\n  s:\n    image: x\n    extends:\n      file: '{ref}'\n      service: b\n")
    for f in (short, pathform, ext):
        res = d.scan_compose_files([f])
        assert not res.ok and "remote" in " ".join(res.problems), (f, res.problems)


@needs_yaml
def test_scan_recurses_through_local_chains_to_find_a_remote_reference(tmp_path):
    _write(tmp_path / "l3.yaml", "include:\n  - oci://docker.io/library/x:1\n")
    _write(tmp_path / "l2.yaml", "services:\n  s:\n    image: x\n    extends:\n      file: l3.yaml\n      service: s\n")
    _write(tmp_path / "l1.yaml", "include:\n  - l2.yaml\n")
    top = _write(tmp_path / "compose.yaml", "include:\n  - path: l1.yaml\n")
    res = d.scan_compose_files([top])
    assert not res.ok and any("l3.yaml" in p and "remote" in p for p in res.problems)


@needs_yaml
@pytest.mark.parametrize("build,bad", [
    ("build: https://example.com/repo.git", True), ("build: git@host:org/repo.git", True),
    ("build: github.com/org/repo", True), ("build: oci://reg/x", True), ("build: ./app", False),
    ("build: .", False),
    ("build:\n      context: https://example.com/ctx.tar.gz", True),
    ("build:\n      context: git@host:repo.git", True),
    ("build:\n      context: ./app", False),
    ("build:\n      context: .\n      additional_contexts:\n        a: https://example.com/x.tar", True),
    ("build:\n      context: .\n      additional_contexts:\n        a: docker-image://alpine", True),
    ("build:\n      context: .\n      additional_contexts:\n        a: oci-layout://./x", True),
    ("build:\n      context: .\n      additional_contexts:\n        a: github.com/foo/bar", True),
    ("build:\n      context: .\n      additional_contexts:\n        a: service:other", True),
    ("build:\n      context: .\n      additional_contexts:\n        - a=https://example.com/x.tar", True),
    ("build:\n      context: .\n      additional_contexts:\n        a: ../libs", False),
    ("build:\n      context: .\n      additional_contexts:\n        - a=./libs", False),
    ("build:\n      context: .\n      additional_contexts:\n        a: C:\\libs", False),
    ("build: 42", True),
])
def test_scan_remote_build_contexts_and_additional_contexts(tmp_path, build, bad):
    f = _write(tmp_path / "compose.yaml", f"services:\n  s:\n    image: x\n    {build}\n")
    res = d.scan_compose_files([f])
    assert (not res.ok) is bad, res.problems


@needs_yaml
@pytest.mark.parametrize("text", [
    "include:\n  - ${DIR}/x.yaml\n",                     # variable: cannot be verified
    "services: [1]\n", "- a\n- b\n", "a: 1\na: 2\n", "include: [1]\n", "---\na: 1\n---\nb: 2\n",
    "services:\n  s:\n    extends:\n      file: ''\n      service: x\n",
])
def test_scan_refuses_unverifiable_files(tmp_path, text):
    f = _write(tmp_path / "compose.yaml", text)
    assert not d.scan_compose_files([f]).ok


@needs_yaml
def test_scan_missing_file_cycle_and_limits(tmp_path):
    assert not d.scan_compose_files([str(tmp_path / "missing.yaml")]).ok
    _write(tmp_path / "a.yaml", "include:\n  - b.yaml\n")
    _write(tmp_path / "b.yaml", "include:\n  - a.yaml\n")
    assert d.scan_compose_files([str(tmp_path / "a.yaml")]).ok           # cycles terminate
    for i in range(6):
        _write(tmp_path / f"n{i}.yaml", f"include:\n  - n{i + 1}.yaml\n")
    _write(tmp_path / "n6.yaml", "services: {}\n")
    assert not d.scan_compose_files([str(tmp_path / "n0.yaml")], max_depth=3).ok
    assert not d.scan_compose_files([str(tmp_path / "n0.yaml")], max_files=3).ok
    small = _write(tmp_path / "small.yaml", "x: " + "a" * 100)
    assert d.scan_compose_files([small]).ok
    big = _write(tmp_path / "big.yaml", "x: " + "a" * (d.MAX_YAML_BYTES + 1))
    assert not d.scan_compose_files([big]).ok                             # over the 2 MiB read limit


@needs_yaml
def test_scan_accepts_compose_tags_and_merge_keys(tmp_path):
    f = _write(tmp_path / "compose.yaml",
               "x-base: &base\n  image: x\nservices:\n  a:\n    <<: *base\n    ports: !reset []\n"
               "    environment: !override\n      A: b\n")
    assert d.scan_compose_files([f]).ok


@needs_yaml
def test_scan_runs_before_any_compose_config(tmp_path, monkeypatch):
    _write(tmp_path / "inner.yaml", "include:\n  - oci://docker.io/library/x:1\n")
    top = _write(tmp_path / "compose.yaml", "include:\n  - inner.yaml\n")

    def boom(*a, **k):
        raise AssertionError("compose config must not run before the raw scan passes")

    monkeypatch.setattr(d, "_run_config", boom)
    ctx = d.Ctx(pin=c.PinnedBinary(os.path.abspath("docker"), "0" * 64, "pe", 1), endpoint="ep",
                path_dirs=[], config_dir="cfg")
    shape = {"family": "compose", "project": "demo", "profiles": [], "files": [top],
             "project_dir": str(tmp_path)}
    with pytest.raises(c.ProfileRefusal, match="remote"):
        d._compose_snapshot({}, ctx, shape, Request(("docker",), str(tmp_path), ("A",)))


@pytest.mark.parametrize("value,remote", [
    ("oci://x", True), ("https://x", True), ("git+ssh://x", True), ("git@h:o/r", True),
    ("github.com/o/r", True), ("a/b.git", True), ("a/b.git#main", True), ("./app", False),
    ("../app", False), ("C:\\app", False), (".", False), ("app.github.io", False), (5, True),
])
def test_is_remote_reference(value, remote):
    assert d.is_remote_reference(value) is remote


# ---------------------------------------------------------------------------
# Dockerfile directives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,bad", [
    ("# syntax=docker/dockerfile:1\nFROM x\n", True),
    ("#syntax=evil/frontend\nFROM x\n", True),
    ("# SYNTAX = evil\nFROM x\n", True),
    ("\ufeff# syntax=evil\nFROM x\n", True),
    ("# syntax=evil\r\nFROM x\r\n", True),
    ("# escape=`\n# syntax=evil\nFROM x\n", True),
    ("\n\n# check=skip=all\n# syntax=evil\nFROM x\n", True),
    ("# just a comment\n# syntax=evil\nFROM x\n", True),            # conservative
    ("# syntax=evil\rFROM x", True),
    ("FROM x\n# syntax=evil\n", False),                           # after an instruction: inert
    ("FROM x\nRUN true\n", False), ("# comment only\nFROM x\n", False), ("", False),
    ("# syntactic sugar\nFROM x\n", False),
])
def test_dockerfile_syntax_directive(text, bad):
    assert bool(d.dockerfile_syntax_problem(text)) is bad


# ---------------------------------------------------------------------------
# Model lint on JSON fixtures
# ---------------------------------------------------------------------------

def _svc(**extra):
    return dict({"image": "x"}, **extra)


def lint(model, vars_=("API_TOKEN",), dockerfile="FROM x\n"):
    return d.lint_model(model, vars_, read_dockerfile=lambda path: dockerfile, home=HOME)


def test_lint_clean_model_has_no_findings():
    out = lint({"services": {"web": _svc(environment={"A": "b"}, ports=[{"target": 80}])}})
    assert out.class_a == [] and out.class_b == [] and out.buildable == []
    assert out.services == ["web"] and not out.refused


@pytest.mark.parametrize("field,value,needle", [
    ("privileged", True, "privileged"),
    ("cap_add", ["SYS_ADMIN"], "cap_add"),
    ("devices", [{"source": "/dev/sda", "target": "/dev/sda"}], "devices"),
    ("device_cgroup_rules", ["c 1:3 mr"], "device_cgroup_rules"),
    ("gpus", [{"count": 1}], "gpus"),
    ("network_mode", "host", "network_mode: host"),
    ("network_mode", "HOST", "network_mode: host"),
    ("pid", "host", "pid: host"),
    ("ipc", "host", "ipc: host"),
    ("uts", "host", "uts: host"),
    ("userns_mode", "host", "userns_mode: host"),
    ("cgroup", "host", "cgroup: host"),
    ("security_opt", ["seccomp=unconfined"], "security_opt"),
    ("runtime", "nvidia", "runtime"),
    ("cgroup_parent", "/x", "cgroup_parent"),
    ("sysctls", {"net.ipv4.ip_forward": "1"}, "sysctls"),
    ("volumes_from", ["other"], "volumes_from"),
    ("credential_spec", {"file": "x"}, "credential_spec"),
    ("use_api_socket", True, "use_api_socket"),
    ("provider", {"type": "x", "options": {}}, "provider"),
    ("models", {"m": {}}, "models"),
    ("post_start", [{"command": ["sh"]}], "post_start"),
    ("pre_stop", [{"command": ["sh"]}], "pre_stop"),
    ("develop", {"watch": [{"action": "sync+exec", "path": ".", "exec": {"command": "x"}}]},
     "develop.watch exec"),
])
def test_lint_class_b_service_fields(field, value, needle):
    out = lint({"services": {"web": _svc(**{field: value})}})
    assert out.class_a == []
    assert any(needle in item for item in out.class_b), out.class_b


@pytest.mark.parametrize("field,value", [
    ("privileged", False), ("network_mode", "bridge"), ("pid", "service:x"), ("cap_add", []),
    ("security_opt", None), ("develop", {"watch": [{"action": "sync", "path": "."}]}),
])
def test_lint_benign_values_do_not_flag(field, value):
    assert lint({"services": {"web": _svc(**{field: value})}}).class_b == []


@pytest.mark.parametrize("source,dangerous", [
    ("/", True), (HOME, True), ("C:\\", True), ("/var/run/docker.sock", True),
    ("//var/run/docker.sock", True), ("\\\\.\\pipe\\docker_engine", True),
    ("/srv/data", False),
])
def test_lint_bind_mounts(source, dangerous):
    out = lint({"services": {"web": _svc(volumes=[
        {"type": "bind", "source": source, "target": "/mnt"}])}})
    assert len(out.class_b) == 1 and "code reaches secrets" in out.class_b[0]
    assert ("DANGEROUS" in out.class_b[0]) is dangerous


def test_lint_volume_types():
    out = lint({"services": {"web": _svc(volumes=[
        {"type": "volume", "source": "data", "target": "/d"},
        {"type": "tmpfs", "target": "/t"},
        {"type": "npipe", "source": "\\\\.\\pipe\\docker_engine", "target": "\\\\.\\pipe\\docker_engine"},
    ])}})
    assert len(out.class_b) == 1 and "named pipe" in out.class_b[0]


def test_lint_named_volume_driver_opts_bind_of_root():
    out = lint({"services": {"web": _svc(volumes=[{"type": "volume", "source": "v", "target": "/h"}])},
                "volumes": {"v": {"driver": "local",
                                  "driver_opts": {"type": "none", "o": "bind", "device": "/"}},
                            "plain": {}, "named": {"name": "x"}}})
    assert any("volume v" in i and "DANGEROUS" in i for i in out.class_b)
    assert not any("plain" in i or "named" in i for i in out.class_b)
    out = lint({"services": {}, "volumes": {"v": {"driver": "rexray/s3fs"}}})
    assert any("volume v" in i for i in out.class_b)
    assert lint({"services": {}, "volumes": {"v": {"driver": "local"}}}).class_b == []


def test_lint_top_level_secrets_configs_files_and_models():
    out = lint({"services": {}, "secrets": {"s": {"file": "/home/u/.ssh/id_rsa"}, "e": {"environment": "X"}},
                "configs": {"c": {"file": "/etc/passwd"}, "inl": {"content": "x"}},
                "models": {"m": {"model": "x"}}})
    assert any("secret s" in i for i in out.class_b) and any("config c" in i for i in out.class_b)
    assert not any("secret e" in i or "inl" in i for i in out.class_b)
    assert "top-level models" in out.class_b


def test_lint_malformed_models_fail_closed():
    assert lint([]).refused
    assert lint({"services": []}).refused
    assert lint({"services": {}, "secrets": []}).refused
    assert lint({"services": {}, "volumes": ["a"]}).refused


# ---- Class A / build tier ---------------------------------------------------

def sentinel(name="API_TOKEN"):
    return d.sentinel_for(name)


def _build(**build):
    return {"services": {"app": _svc(build=dict({"context": "/p"}, **build))}}


def test_lint_buildable_services_and_string_build():
    out = lint({"services": {"a": _svc(build={"context": "/p"}), "b": _svc(), "c": {"build": "/q"}}})
    assert out.buildable == ["a", "c"] and out.services == ["a", "b", "c"] and out.class_a == []


@pytest.mark.parametrize("build", [
    {"args": {"T": sentinel()}},
    {"args": {"T": "prefix-" + sentinel("API_TOKEN") + "-suffix"}},
    {"labels": {"x": sentinel()}},
    {"target": sentinel()},
    {"dockerfile": sentinel()},
    {"args": {"NAME": sentinel("API_TOKEN")}},                        # valueless `args: [NAME]` resolves to this
])
def test_lint_sentinel_anywhere_under_build_is_class_a(build):
    out = lint(_build(**build))
    assert out.refused and any("vault variable is used under build" in i for i in out.class_a)


def test_lint_sentinel_in_context_string_build():
    out = lint({"services": {"app": _svc(build="/p/" + sentinel())}})
    assert out.refused


def test_lint_sentinel_outside_build_is_fine():
    out = lint({"services": {"app": _svc(environment={"T": sentinel()}, build={"context": "/p"})}})
    assert not out.refused


@pytest.mark.parametrize("build,needle", [
    ({"privileged": True}, "build.privileged"),
    ({"entitlements": ["network.host"]}, "build.entitlements"),
    ({"network": "host"}, "build.network is host"),
    ({"context": "https://example.com/x.git"}, "remote build context"),
    ({"context": "git@host:org/repo.git"}, "remote build context"),
    ({"additional_contexts": {"a": "https://example.com/x.tar"}}, "additional_contexts"),
    ({"additional_contexts": ["a=docker-image://alpine"]}, "additional_contexts"),
    ({"additional_contexts": {"a": "oci-layout://./x"}}, "additional_contexts"),
])
def test_lint_class_a_build_fields(build, needle):
    out = lint(_build(**build))
    assert any(needle in i for i in out.class_a), out.class_a


def test_lint_allows_directory_additional_contexts_and_bridge_network():
    out = lint(_build(additional_contexts={"a": "/libs"}, network="bridge"))
    assert not out.refused


def test_lint_build_secrets_from_vault_env_or_file_are_class_a():
    def model(top, svc_secrets=("s1",)):
        m = _build(secrets=list(svc_secrets))
        m["secrets"] = top
        return m

    out = lint(model({"s1": {"environment": "API_TOKEN"}}))
    assert any("reads a vault variable" in i for i in out.class_a)
    assert lint(model({"s1": {"environment": "api_token"}})).refused          # case-insensitive
    out = lint(model({"s1": {"file": "/home/u/.npmrc"}}))
    assert any("reads a host file" in i for i in out.class_a)
    out = lint({**_build(secrets=[{"source": "s1", "target": "t"}]),
                "secrets": {"s1": {"environment": "API_TOKEN"}}})
    assert out.refused
    assert not lint(model({"s1": {"environment": "OTHER_VAR"}})).refused
    # a runtime (non-build) secret from the vault variable is not Class A
    out = lint({"services": {"app": _svc(secrets=["s1"])}, "secrets": {"s1": {"environment": "API_TOKEN"}}})
    assert not out.refused


def test_lint_dockerfile_syntax_directive_named_and_inline():
    assert lint(_build(), dockerfile="# syntax=evil/frontend\nFROM x\n").refused
    assert lint(_build(dockerfile="Other.Dockerfile"), dockerfile="# SYNTAX=evil\nFROM x\n").refused
    assert not lint(_build(), dockerfile="FROM x\n").refused
    assert lint(_build(dockerfile_inline="# syntax=evil\nFROM x\n")).refused
    assert lint(_build(dockerfile_inline="\ufeff#syntax=evil\r\nFROM x\r\n")).refused
    assert not lint(_build(dockerfile_inline="FROM x\nRUN true\n")).refused
    seen = []
    d.lint_model(_build(dockerfile="sub/D"), ["API_TOKEN"], read_dockerfile=lambda p: seen.append(p) or "FROM x\n")
    assert [os.path.normpath(p) for p in seen] == [os.path.normpath("/p/sub/D")]
    missing = d.lint_model(_build(), ["API_TOKEN"], read_dockerfile=lambda p: None)
    assert any("cannot be read" in i for i in missing.class_a)


def test_read_dockerfile_head_missing_and_present(tmp_path):
    assert d._read_dockerfile_head(str(tmp_path / "nope")) is None
    f = tmp_path / "Dockerfile"
    f.write_text("# syntax=evil\nFROM x\n")
    assert "syntax=evil" in d._read_dockerfile_head(str(f))


def test_read_dockerfile_head_refuses_an_oversized_all_comment_head(tmp_path):
    # B5-03: a '# syntax=' after the scan window must not be silently missed
    f = tmp_path / "Dockerfile"
    filler = "# " + "x" * 78 + "\n"
    f.write_text(filler * (d.DOCKERFILE_HEAD_BYTES // len(filler) + 10) + "# syntax=evil\nFROM x\n")
    assert os.path.getsize(f) > d.DOCKERFILE_HEAD_BYTES
    assert d._read_dockerfile_head(str(f)) is None
    out = d.lint_model({"services": {"a": {"build": {"context": str(tmp_path)}}}}, ["API_TOKEN"], home=HOME)
    assert out.refused and any("Dockerfile cannot be read" in i for i in out.class_a)
    # an instruction inside the window ends the directive area: a long file is fine
    g = tmp_path / "Big"
    g.write_text("FROM x\n" + "RUN true\n" * (d.DOCKERFILE_HEAD_BYTES // 5))
    assert os.path.getsize(g) > d.DOCKERFILE_HEAD_BYTES
    assert d._read_dockerfile_head(str(g)).startswith("FROM x")
    # exactly at the window is complete, not truncated
    h = tmp_path / "Exact"
    h.write_bytes(b"#" * d.DOCKERFILE_HEAD_BYTES)
    assert d._read_dockerfile_head(str(h)) is not None


def test_json_contexts_helper():
    model = {"services": {"a": {"build": {"context": "git@h:r.git"}}, "b": {"build": "str"}, "c": {}}}
    assert d._json_contexts(model) == ["git@h:r.git"]


# ---------------------------------------------------------------------------
# describe / label
# ---------------------------------------------------------------------------

def _fake_snap(family="compose"):
    snap = {"endpoint": "npipe:////./pipe/docker_engine", "compose_version": "5.4.0",
            "desktop": "Docker Desktop 4.88.1 (237512)",
            "config": {"vault": {}, "findings": ["the user's docker config.json has 'proxies'"]}}
    if family == "compose":
        snap["compose"] = {"buildable": ["app"], "class_b": ["web: privileged"]}
    return snap


def test_describe_compose_warns_unpinned_images_and_agent_read_access():
    import time
    req = Request(BASE + ("up",), os.getcwd(), ("API_TOKEN",))
    shape = {"family": "compose", "project": "demo", "profiles": ["dev"], "files": [os.path.join(os.getcwd(), "c.yaml")],
             "project_dir": os.getcwd()}
    d._snapshot_cache[d._cache_key(req, shape)] = (time.monotonic(), _fake_snap())
    try:
        text = d.describe(req, shape)
    finally:
        d._snapshot_cache.clear()
    first = text.splitlines()[0]
    assert first.startswith("docker compose -f ") and "-p demo --profile dev" in first
    assert "does not pin" in text and "agent can read container env and logs" in text
    assert "test-grade credentials" in text
    assert "Build tier: services that may be built: app" in text
    assert "WARNING: web: privileged" in text and "Note: the user's docker config.json" in text
    assert "only for 'up'" in text and "npipe:////./pipe/docker_engine" in text
    assert d.label(req, shape) == "docker compose demo (c.yaml)"
    assert d.label(req, dict(shape, files=shape["files"] * 2)) == "docker compose demo (c.yaml +1)"


def test_describe_image_entry_and_label():
    import time
    req = Request(("docker", "pull", "ghcr.io/org/app:1"), os.getcwd(), ("API_TOKEN",))
    cmd = d.parse_command(req.command)
    shape = d.image_shape(cmd, d.parse_reference(cmd.image))
    d._snapshot_cache[d._cache_key(req, shape)] = (time.monotonic(), _fake_snap("image"))
    try:
        text = d.describe(req, shape)
    finally:
        d._snapshot_cache.clear()
    assert text.splitlines()[0] == ("docker pull [--platform=...] [-q] ghcr.io/org/* "
                                    "(any tag except 'latest')")
    assert "does not pin" in text and "agent can read container env and logs" in text
    assert d.label(req, shape) == "docker pull ghcr.io/org/*"


def test_match_rejects_reserved_names_and_foreign_commands(tmp_path):
    req = Request(("docker", "pull", "alpine"), str(tmp_path), ("DOCKER_HOST",))
    assert d.match(req) is None
    assert d.match(Request(("docker", "pull", "alpine"), str(tmp_path), ("TOKEN",)))["family"] == "image"
    assert d.match(Request(("docker", "run", "alpine"), str(tmp_path), ("TOKEN",))) is None
    assert d.match(Request(BASE + ("up",), str(tmp_path), ("TOKEN",))) is None   # compose file missing
    f = tmp_path / "c.yaml"
    f.write_text("services: {}\n")
    shape = d.match(Request(BASE + ("up",), str(tmp_path), ("TOKEN",)))
    assert shape["family"] == "compose" and shape["project_dir"] == os.path.dirname(shape["files"][0])
    outside = tmp_path.parent / "other.yaml"
    outside.write_text("services: {}\n")
    assert d.match(Request(("docker", "compose", "-f", str(outside), "-p", "demo", "up"),
                           str(tmp_path), ("TOKEN",))) is None
    assert d.match(Request(("docker", "compose", "-f", "c.yaml", "-f", "c.yaml", "-p", "demo", "up"),
                           str(tmp_path), ("TOKEN",))) is None


# ---------------------------------------------------------------------------
# Integration: real `docker compose config` (no daemon, no containers)
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        out = subprocess.run([exe, "compose", "version", "--short"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


integration = pytest.mark.skipif(not (HAVE_YAML and _docker_available()),
                                 reason="docker CLI with the compose plugin (and PyYAML) required")

REAL = "REAL-TOKEN-VALUE-0123456789"


class Project:
    def __init__(self, root: Path):
        self.root = root
        self.dir = root / "proj"
        self.dir.mkdir()
        self.dir = Path(os.path.realpath(self.dir))
        self.secrets = {"API_TOKEN": REAL}

    def write(self, name, text):
        return _write(self.dir / name, text)

    def req(self, *tail, only=("API_TOKEN",), files=("compose.yaml",), project="demo", profiles=()):
        command = ["docker", "compose"]
        for f in files:
            command += ["-f", f]
        command += ["-p", project] + [f"--profile={p}" for p in profiles] + list(tail)
        return Request(tuple(command), str(self.dir), tuple(only))

    def approve(self, req):
        cand = d.match(req)
        assert cand is not None
        snap = d.snapshot(req, cand)
        entry = {"id": "e1", "kind": "docker", "cwd": req.cwd, "only_vars": list(req.only_vars),
                 "shape": cand, "snapshot": snap}
        return entry

    def anchor(self, *tail, **kw):
        return self.approve(self.req(*tail, **kw))["snapshot"]["compose"]["anchor_yaml"]


BASIC = "services:\n  web:\n    image: nginx:1.27\n    environment:\n      TOKEN: ${API_TOKEN}\n"


@pytest.fixture
def proj(tmp_path, monkeypatch):
    scratch_cfg = tmp_path / "dockercfg"
    scratch_cfg.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(scratch_cfg))
    monkeypatch.setattr(d, "user_docker_dir", lambda: str(scratch_cfg))
    scratch_tmp = tmp_path / "tmp"
    scratch_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch_tmp))
    p = Project(tmp_path)
    monkeypatch.setattr(d, "_load_run_secrets", lambda entry, req: {n: p.secrets[n] for n in req.only_vars})
    d._snapshot_cache.clear()
    p.write("compose.yaml", BASIC)
    # Environment preconditions (docker location, plugin, version) -> skip, not fail.
    try:
        d.snapshot(p.req("up"), d.match(p.req("up")))
    except c.ProfileRefusal as exc:
        pytest.skip(f"docker environment not eligible here: {exc.reason}")
    return p


def _mutations():
    return {}


@integration
def test_integration_snapshot_records_endpoint_versions_and_anchors(proj):
    entry = proj.approve(proj.req("up", "-d"))
    snap = entry["snapshot"]
    assert d.endpoint_allowed(snap["endpoint"])
    assert d.compose_version_problem(snap["compose_version"]) is None
    assert len(snap["compose"]["anchor_yaml"]) == 64 and len(snap["compose"]["anchor_json"]) == 64
    assert snap["compose"]["services"] == ["web"] and snap["compose"]["buildable"] == []
    assert os.listdir(d.ensure_config_dir(snap["config"]["vault"])) == ["config.json"]
    assert d.check_snapshot(entry) == (True, None)
    text = d.describe(proj.req("up", "-d"), entry["shape"])
    assert "does not pin" in text and "agent can read container env and logs" in text


@integration
def test_integration_up_pipes_real_model_and_ps_pipes_sentinel_only(proj):
    entry = proj.approve(proj.req("up", "-d"))
    v = d.verify(entry, proj.req("up", "-d", "web"))
    assert isinstance(v, Verdict) and v.ok, v.reason
    # the mechanism W3 must use: v.stdin is piped to `docker compose ... -f - up`
    assert REAL.encode() in v.stdin and d.SENTINEL_PREFIX.encode() not in v.stdin
    assert v.replace_env is True and v.inject_secrets is False
    assert v.argv[1:3] == ["-H", entry["snapshot"]["endpoint"]]
    assert v.argv[3] == "compose" and v.argv[4] == "--project-directory"
    assert v.argv[5] == entry["shape"]["project_dir"]
    assert v.argv[6:8] == ["-p", "demo"] and v.argv[8:10] == ["-f", "-"]
    assert v.argv[10:] == ["up", "--detach", "web"]
    assert not any(REAL in str(x) for x in v.argv) and REAL not in "".join(map(str, v.env.values()))
    assert v.env["DOCKER_CONFIG"] == d.ensure_config_dir(entry["snapshot"]["config"]["vault"])
    for sub in ("ps", "logs", "down", "pull"):
        v2 = d.verify(entry, proj.req(sub))
        assert v2.ok, (sub, v2.reason)
        assert v2.inject_secrets is False
        assert REAL.encode() not in v2.stdin
        assert d.sentinel_for("API_TOKEN").encode() in v2.stdin
        assert v2.argv[10] == sub
        assert "API_TOKEN" not in v2.env
    assert REAL not in repr(v) and "stdin" not in repr(v)             # repr hides the bytes


@integration
def test_integration_non_up_never_loads_secrets(proj, monkeypatch):
    entry = proj.approve(proj.req("up"))

    def boom(entry, req):
        raise AssertionError("secrets must not be loaded")

    monkeypatch.setattr(d, "_load_run_secrets", boom)
    for sub in ("ps", "logs", "down", "pull"):
        assert d.verify(entry, proj.req(sub)).ok
    image = d.match(Request(("docker", "pull", "ghcr.io/org/app:1"), str(proj.dir), ("API_TOKEN",)))
    assert image["family"] == "image"


@integration
def test_integration_image_entry_has_no_stdin_and_clamps_requests(proj):
    req = Request(("docker", "pull", "-q", "ghcr.io/org/app:1"), str(proj.dir), ("API_TOKEN",))
    cand = d.match(req)
    snap = d.snapshot(req, cand)
    entry = {"id": "i1", "kind": "docker", "cwd": req.cwd, "only_vars": ["API_TOKEN"],
             "shape": cand, "snapshot": snap}
    v = d.verify(entry, req)
    assert v.ok and v.stdin is None and v.inject_secrets is False
    assert v.argv[1:4] == ["-H", snap["endpoint"], "pull"] and v.argv[-1] == "ghcr.io/org/app:1"
    other = Request(("docker", "pull", "ghcr.io/org/other:2"), str(proj.dir), ("API_TOKEN",))
    assert d.verify(entry, other).ok
    for text in ("ghcr.io/elsewhere/x:1", "quay.io/org/app:1", "ghcr.io/org/app:latest"):
        got = d.verify(entry, Request(("docker", "pull", text), str(proj.dir), ("API_TOKEN",)))
        assert got.ok is False and got.reason is None, text
    push = d.verify(entry, Request(("docker", "push", "ghcr.io/org/app:1"), str(proj.dir), ("API_TOKEN",)))
    assert push.ok is False and push.reason is None


@integration
def test_integration_verify_does_not_apply_to_other_shapes(proj):
    entry = proj.approve(proj.req("up"))
    for req in (proj.req("up", project="other"), proj.req("up", profiles=("dev",)),
                proj.req("up", "nosuchservice"), proj.req("up", "--watch"),
                proj.req("up", only=("API_TOKEN", "EXTRA")),
                Request(("docker", "run", "alpine"), str(proj.dir), ("API_TOKEN",))):
        got = d.verify(entry, req)
        assert got.ok is False and got.reason is None, req.command


@integration
def test_integration_distinct_sentinel_per_variable(proj):
    proj.write("compose.yaml", "services:\n  web:\n    image: x\n    environment:\n"
                               "      A: ${TOKEN_A}\n      B: ${TOKEN_B}\n")
    proj.secrets.update({"TOKEN_A": "aaaaaaaaaaaa1", "TOKEN_B": "bbbbbbbbbbbb2"})
    entry = proj.approve(proj.req("ps", only=("TOKEN_A", "TOKEN_B")))
    v = d.verify(entry, proj.req("ps", only=("TOKEN_A", "TOKEN_B")))
    assert v.ok, v.reason
    text = v.stdin.decode()
    assert d.sentinel_for("TOKEN_A") in text and d.sentinel_for("TOKEN_B") in text
    assert d.sentinel_for("TOKEN_A") != d.sentinel_for("TOKEN_B")


@integration
def test_integration_anchor_ignores_real_value_but_tracks_every_input(proj):
    base = proj.anchor("up")
    assert proj.anchor("up") == base                                    # deterministic
    proj.secrets["API_TOKEN"] = "a-completely-different-real-value"
    assert proj.anchor("up") == base                                    # the real value never enters
    proj.write(".env", "API_TOKEN=from-dotenv-1\n")                     # sentinel in env beats .env
    dotenv_base = proj.anchor("up")
    assert dotenv_base == base
    proj.write(".env", "API_TOKEN=x\nOTHER=1\nIMG=nginx:1.26\n")
    proj.write("compose.yaml", BASIC.replace("nginx:1.27", "${IMG}"))
    with_img = proj.anchor("up")
    assert with_img != base
    proj.write(".env", "API_TOKEN=x\nIMG=nginx:1.28\n")
    assert proj.anchor("up") != with_img                                 # .env
    proj.write("compose.yaml", BASIC)
    base2 = proj.anchor("up")
    proj.write("app.env", "FILEVAR=one\n")
    proj.write("compose.yaml", BASIC + "    env_file: app.env\n")
    envf1 = proj.anchor("up")
    assert envf1 != base2                                                # env_file added
    proj.write("app.env", "FILEVAR=two\n")
    assert proj.anchor("up") != envf1                                    # env_file content
    proj.write("compose.yaml", BASIC)
    proj.write("inc.yaml", "services:\n  db:\n    image: postgres:16\n")
    proj.write("compose.yaml", "include:\n  - inc.yaml\n" + BASIC)
    inc1 = proj.anchor("up")
    assert inc1 != base2                                                 # include added
    proj.write("inc.yaml", "services:\n  db:\n    image: postgres:17\n")
    assert proj.anchor("up") != inc1                                     # included file
    proj.write("compose.yaml", BASIC)
    proj.write("ext.yaml", "services:\n  base:\n    image: busybox:1\n")
    proj.write("compose.yaml", BASIC + "  other:\n    extends:\n      file: ext.yaml\n      service: base\n")
    ext1 = proj.anchor("up")
    proj.write("ext.yaml", "services:\n  base:\n    image: busybox:2\n")
    assert proj.anchor("up") != ext1                                     # extends.file


@integration
def test_integration_override_and_parent_compose_are_not_picked_up_with_explicit_f(proj):
    base = proj.anchor("up")
    proj.write("compose.override.yaml", "services:\n  web:\n    image: evil:1\n")
    _write(proj.dir.parent / "compose.yaml", "services:\n  evil:\n    image: evil\n")
    assert proj.anchor("up") == base           # explicit -f: only the approved files count


@integration
@pytest.mark.parametrize("mutate", ["env", "env_file", "include", "extends", "compose"])
def test_integration_tracked_input_drift_is_refused_at_arm_and_run_time(proj, mutate):
    proj.write("app.env", "FILEVAR=one\n")
    proj.write("inc.yaml", "services:\n  db:\n    image: postgres:16\n")
    proj.write("ext.yaml", "services:\n  base:\n    image: busybox:1\n")
    proj.write("compose.yaml", "include:\n  - inc.yaml\n" + BASIC
               + "    env_file: app.env\n  other:\n    extends:\n      file: ext.yaml\n      service: base\n")
    entry = proj.approve(proj.req("up"))
    assert d.check_snapshot(entry) == (True, None)
    assert d.verify(entry, proj.req("ps")).ok
    if mutate == "env":
        proj.write(".env", "API_TOKEN=changed\n")
    elif mutate == "env_file":
        proj.write("app.env", "FILEVAR=two\n")
    elif mutate == "include":
        proj.write("inc.yaml", "services:\n  db:\n    image: postgres:17\n")
    elif mutate == "extends":
        proj.write("ext.yaml", "services:\n  base:\n    image: busybox:2\n")
    else:
        text = (proj.dir / "compose.yaml").read_text()
        proj.write("compose.yaml", text.replace("nginx:1.27", "nginx:1.28"))
    ok, reason = d.check_snapshot(entry)
    assert ok is False and "changed" in reason
    got = d.verify(entry, proj.req("ps"))
    assert got.ok is False and "changed" in got.reason


@integration
def test_integration_anchor_mismatch_blocks_every_subcommand(proj):
    entry = proj.approve(proj.req("up"))
    entry["snapshot"]["compose"]["anchor_yaml"] = "0" * 64
    for sub in ("up", "ps", "down"):
        got = d.verify(entry, proj.req(sub))
        assert got.ok is False and "changed since it was approved" in got.reason, sub
    entry = proj.approve(proj.req("up"))
    entry["snapshot"]["compose"]["anchor_json"] = "0" * 64
    got = d.verify(entry, proj.req("ps"))
    assert got.ok is False and "JSON form" in got.reason


@integration
def test_integration_s_prime_twin_mismatch_refuses_up(proj, monkeypatch):
    entry = proj.approve(proj.req("up"))
    calls = []
    real_run = d._run_config

    def flaky(ctx, values, fmt):
        calls.append((fmt, tuple(values.values())))
        out = real_run(ctx, values, fmt)
        # the third config run is the sentinel twin S'; make the files "change back"
        if len([x for x in calls if x[0] == "yaml"]) == 3:
            out += b"# drift\n"
        return out

    monkeypatch.setattr(d, "_run_config", flaky)
    got = d.verify(entry, proj.req("up"))
    assert got.ok is False and "changed while the model was being read" in got.reason
    assert got.stdin is None
    order = [("S" if REAL not in v else "R") for f, v in calls if f == "yaml"]
    assert order == ["S", "R", "S"]


@integration
def test_integration_real_model_with_a_leftover_sentinel_is_refused(proj, monkeypatch):
    entry = proj.approve(proj.req("up"))
    monkeypatch.setattr(d, "_load_run_secrets",
                        lambda e, r: {"API_TOKEN": d.sentinel_for("API_TOKEN")})
    got = d.verify(entry, proj.req("up"))
    assert got.ok is False and "sentinel" in got.reason


@integration
def test_integration_missing_armed_values_refuse_up_only(proj, monkeypatch):
    entry = proj.approve(proj.req("up"))

    def none(e, r):
        raise c.ProfileRefusal("the armed values are unavailable")

    monkeypatch.setattr(d, "_load_run_secrets", none)
    got = d.verify(entry, proj.req("up"))
    assert got.ok is False and "unavailable" in got.reason
    assert d.verify(entry, proj.req("ps")).ok


@integration
def test_integration_sentinel_in_typed_field_fails_closed(proj):
    proj.write("compose.yaml", "services:\n  web:\n    image: x\n    ports:\n      - '${PORTV}:80'\n")
    proj.secrets["PORTV"] = "8080"
    req = proj.req("up", only=("PORTV",))
    with pytest.raises(c.ProfileRefusal):
        d.snapshot(req, d.match(req))


@integration
@pytest.mark.parametrize("ref", ["oci://docker.io/library/x:1", "https://example.com/x.git",
                                 "git@github.com:org/repo.git"])
def test_integration_remote_include_is_refused_before_config(proj, monkeypatch, ref):
    proj.write("inner.yaml", f"include:\n  - {ref}\n")
    proj.write("compose.yaml", "include:\n  - inner.yaml\n" + BASIC)
    monkeypatch.setattr(d, "_run_config", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("config ran before the scan")))
    req = proj.req("up")
    with pytest.raises(c.ProfileRefusal, match="remote"):
        d.snapshot(req, d.match(req))


@integration
def test_integration_remote_build_context_refused(proj):
    proj.write("compose.yaml", "services:\n  app:\n    build: https://example.com/repo.git\n")
    req = proj.req("up", only=("API_TOKEN",))
    with pytest.raises(c.ProfileRefusal):
        d.snapshot(req, d.match(req))


BUILD_BASIC = ("services:\n  web:\n    image: nginx:1.27\n    environment:\n      TOKEN: ${API_TOKEN}\n"
               "  app:\n    build: ./app\n")


def _app_dockerfile(proj, text="FROM busybox:1\nRUN true\n"):
    proj.write("app/Dockerfile", text)


@integration
def test_integration_build_tier_lists_buildable_services_and_clamps(proj):
    _app_dockerfile(proj)
    proj.write("compose.yaml", BUILD_BASIC)
    entry = proj.approve(proj.req("up"))
    assert entry["snapshot"]["compose"]["buildable"] == ["app"]
    assert entry["snapshot"]["compose"]["services"] == ["app", "web"]
    assert "services that may be built: app" in d.describe(proj.req("up"), entry["shape"])
    v = d.verify(entry, proj.req("build", "--no-cache", "app"))
    assert v.ok and v.argv[-3:] == ["build", "--no-cache", "app"]
    assert REAL.encode() not in v.stdin and "API_TOKEN" not in v.env          # builds get no secrets
    assert d.verify(entry, proj.req("build")).ok
    assert d.verify(entry, proj.req("up", "--build", "app")).ok
    assert d.verify(entry, proj.req("up", "--no-build", "web")).ok
    for req in (proj.req("build", "web"), proj.req("up", "--build", "web")):
        got = d.verify(entry, req)
        assert got.ok is False and got.reason is None, req.command


@integration
def test_integration_build_and_up_build_need_an_approved_buildable_service(proj):
    entry = proj.approve(proj.req("up"))                                      # BASIC: nothing to build
    assert entry["snapshot"]["compose"]["buildable"] == []
    for req in (proj.req("build"), proj.req("up", "--build")):
        got = d.verify(entry, req)
        assert got.ok is False and got.reason is None


@integration
def test_integration_buildable_set_growth_is_refused(proj):
    _app_dockerfile(proj)
    entry = proj.approve(proj.req("up"))
    entry["snapshot"]["compose"]["buildable"] = []
    proj.write("compose.yaml", BUILD_BASIC)
    # re-record everything except the (stale) buildable list
    fresh = proj.approve(proj.req("up"))
    fresh["snapshot"]["compose"]["buildable"] = []
    got = d.verify(fresh, proj.req("up"))
    assert got.ok is False and "buildable" in got.reason


@integration
@pytest.mark.parametrize("build", [
    "build:\n      context: ./app\n      args:\n        T: ${API_TOKEN}",
    "build:\n      context: ./app\n      args:\n        - API_TOKEN=${API_TOKEN}",
    "build:\n      context: ./app\n      args:\n        - API_TOKEN",                    # valueless: pulled from env
    "build:\n      context: ./app\n      labels:\n        x: ${API_TOKEN}",
    "build:\n      context: ./app\n      target: ${API_TOKEN}",
    "build:\n      context: ./app\n      secrets: [s1]",
    "build:\n      context: ./app\n      privileged: true",
    "build:\n      context: ./app\n      network: host",
    "build:\n      context: ./app\n      entitlements: [network.host]",
    "build:\n      context: ./app\n      additional_contexts:\n        a: https://example.com/x.tar",
    "build:\n      context: ./app\n      dockerfile_inline: |\n        # syntax=evil/frontend\n        FROM x",
])
def test_integration_class_a_build_content_refuses_the_entry(proj, build):
    _app_dockerfile(proj)
    top = "secrets:\n  s1:\n    environment: API_TOKEN\n" if "secrets: [s1]" in build else ""
    proj.write("compose.yaml", f"services:\n  app:\n    image: x\n    {build}\n{top}")
    req = proj.req("up")
    with pytest.raises(c.ProfileRefusal, match="not eligible|non-directory"):
        d.snapshot(req, d.match(req))


@integration
def test_integration_dockerfile_syntax_directive_refuses_the_entry(proj):
    for text in ("# syntax=docker/dockerfile:1\nFROM busybox\n", "\ufeff#syntax=evil\r\nFROM busybox\r\n"):
        _app_dockerfile(proj, text)
        proj.write("compose.yaml", BUILD_BASIC)
        req = proj.req("up")
        with pytest.raises(c.ProfileRefusal, match="not eligible"):
            d.snapshot(req, d.match(req))
    _app_dockerfile(proj, "FROM busybox:1\n")
    d.snapshot(req, d.match(req))                                            # a plain one is fine


@integration
def test_integration_class_b_findings_are_recorded_for_the_dialog(proj):
    proj.write("compose.yaml", BASIC + "    privileged: true\n    cap_add: [SYS_ADMIN]\n"
                                      "    network_mode: host\n    volumes:\n      - /:/host\n")
    entry = proj.approve(proj.req("up"))
    findings = " ".join(entry["snapshot"]["compose"]["class_b"])
    for needle in ("privileged", "cap_add", "network_mode: host", "DANGEROUS"):
        assert needle in findings
    text = d.describe(proj.req("up"), entry["shape"])
    assert "WARNING: web: privileged" in text


def test_every_ok_verdict_withholds_the_vault_values_from_the_child_env():
    """Contract (commit 65810cc): the `up` values live inside stdin R and no other
    subcommand may get them, so no `ok=True` verdict may leave inject_secrets on."""
    import inspect
    source = inspect.getsource(d)
    parts = source.split("Verdict(ok=True")[1:]
    assert len(parts) >= 2
    assert all("inject_secrets=False" in part[:200].split("Verdict(")[0] for part in parts)


# ---------------------------------------------------------------------------
# Bug-hunt B6 (verify / shape)
# ---------------------------------------------------------------------------

def test_compose_shape_refuses_a_linked_compose_file(tmp_path):
    # B6-01: the link check ran on the already-resolved path and could never fire
    target = tmp_path / "real.yaml"
    target.write_text("services: {}\n")
    link = tmp_path / "c.yaml"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    cmd = d.parse_command(BASE + ("up",))
    with pytest.raises(d._Unsupported, match="link"):
        d._compose_shape(cmd, str(tmp_path))
    link.unlink()
    target.rename(link)
    assert d._compose_shape(cmd, str(tmp_path))["files"] == [os.path.realpath(link)]


class _Ctx:
    pin = None
    endpoint = "ep"

    def env(self):
        return {}


def test_best_effort_desktop_refuses_when_an_approved_desktop_cannot_be_probed(monkeypatch):
    # B6-04: a failed probe must not skip the floor for an entry approved on Docker Desktop
    monkeypatch.setattr(d, "_desktop_name", lambda *a, **k: None)
    with pytest.raises(c.ProfileRefusal, match="Docker Desktop"):
        d._best_effort_desktop(_Ctx(), "Docker Desktop 4.88.1 (237512)")
    d._best_effort_desktop(_Ctx(), None)                          # approved on a plain engine
    d._best_effort_desktop(_Ctx(), "Docker Engine - Community")
    monkeypatch.setattr(d, "_desktop_name", lambda *a, **k: "Docker Desktop 4.9.0 (1)")
    with pytest.raises(c.ProfileRefusal):
        d._best_effort_desktop(_Ctx(), "Docker Desktop 4.88.1 (237512)")
    monkeypatch.setattr(d, "_desktop_name", lambda *a, **k: "Docker Desktop 4.88.1 (237512)")
    d._best_effort_desktop(_Ctx(), "Docker Desktop 4.88.1 (237512)")


def test_real_model_requires_the_full_approved_variable_set(monkeypatch):
    # B6-03: a subset leaves approved variables unset in R while S/S' cover all of them
    def boom(*a, **k):
        raise AssertionError("nothing may run for a partial request")

    monkeypatch.setattr(d, "_load_run_secrets", boom)
    monkeypatch.setattr(d, "_run_config", boom)
    entry = {"id": "e1", "only_vars": ["DB_PASS", "API_KEY"]}
    req = Request(BASE + ("up",), os.getcwd(), ("API_KEY",))
    with pytest.raises(d.ArgvRejected):
        d._real_model(entry, _Ctx(), req, b"", {"anchor_yaml": "0" * 64})
