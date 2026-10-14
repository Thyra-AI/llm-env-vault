"""Tests for vault_lib/profiles/git.py (2.4.0 always-allow, plan section 5.1).

Layers:
* pure tables: argv grammar, remote/branch slots, URL normalisation, the config
  -z parser, the local-key allowlist, effective credential helpers, version
  floors, argv/env construction;
* real git (the machine's git, isolated HOME, no system config, local bare
  repositories): snapshot / verify / every drift case, the URL check, and the
  behavioural proofs that the command-scope pins really beat hostile local
  config (fsmonitor, hooksPath + pre-push, pull.rebase, credential helpers).

Helper scripts for the behavioural tests deliberately bypass
``resolve_helpers`` (it only accepts native executables) and use ``pin_pairs``
directly.  Relaxations (tests only): ``file:https`` protocols, any printable
remote string, no exe-dir ACL check, git floor 2.0.0 (this machine has 2.45.1).
"""
import http.server
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib.profiles import Request  # noqa: E402
from vault_lib.profiles import _common as c  # noqa: E402
from vault_lib.profiles import git  # noqa: E402

WIN = os.name == "nt"

if shutil.which("git") is None:  # pragma: no cover
    pytest.skip("git is not installed", allow_module_level=True)


# ---------------------------------------------------------------------------
# Pure tables
# ---------------------------------------------------------------------------

def _p(*tokens, prog="git"):
    return git._parse((prog,) + tuple(tokens))


@pytest.mark.parametrize("tokens,sub,flags,remote,branches", [
    (("push", "origin", "main"), "push", [], "origin", ("main",)),
    (("push", "-u", "origin", "main"), "push", ["--set-upstream"], "origin", ("main",)),
    (("push", "--set-upstream", "origin", "main"), "push", ["--set-upstream"], "origin", ("main",)),
    (("push", "--dry-run", "origin", "a", "b/c"), "push", ["--dry-run"], "origin", ("a", "b/c")),
    (("push", "--porcelain", "--dry-run", "-u", "origin", "x"), "push",
     ["--set-upstream", "--dry-run", "--porcelain"], "origin", ("x",)),
    (("push", "--atomic", "origin", "main"), "push", [], "origin", ("main",)),
    (("push", "origin", "feature/x-1.2_y"), "push", [], "origin", ("feature/x-1.2_y",)),
    (("push", "origin", "main", "--dry-run"), "push", ["--dry-run"], "origin", ("main",)),
    (("pull", "origin"), "pull", [], "origin", ()),
    (("pull", "origin", "main"), "pull", [], "origin", ("main",)),
    (("fetch", "origin"), "fetch", [], "origin", ()),
    (("fetch", "--no-tags", "origin"), "fetch", ["--no-tags"], "origin", ()),
    (("fetch", "--tags", "origin"), "fetch", ["--tags"], "origin", ()),
    (("fetch", "--depth=10", "origin"), "fetch", ["--depth"], "origin", ()),
    (("ls-remote", "origin"), "ls-remote", [], "origin", ()),
    (("ls-remote", "--heads", "--tags", "--refs", "origin"), "ls-remote",
     ["--heads", "--tags", "--refs"], "origin", ()),
])
def test_grammar_accepts(tokens, sub, flags, remote, branches):
    parsed = _p(*tokens)
    assert parsed.sub == sub
    assert list(parsed.flag_keys) == flags
    assert parsed.remote == remote
    assert parsed.branches == branches


@pytest.mark.parametrize("prog", ["git", "Git", "GIT.EXE", "git.exe"])
def test_program_name_variants(prog):
    assert _p("fetch", "origin", prog=prog).sub == "fetch"


_PUSH_REJECTS = [
    # flags the plan names
    ("--force",), ("-f",), ("--force-with-lease",), ("--force-with-lease=main",),
    ("--force-with-lease=main:abc",), ("--force-if-includes",), ("--delete",), ("-d",),
    ("--mirror",), ("--all",), ("--prune",), ("--tags",), ("--follow-tags",),
    ("--repo=other",), ("--receive-pack=evil",), ("--exec=evil",), ("--signed",),
    ("--signed=yes",), ("--signed=if-asked",), ("-o", "ci.skip"), ("-oci.skip",),
    ("--push-option=ci.skip",), ("--push-option", "ci.skip"), ("--recurse-submodules=check",),
    ("--recurse-submodules=on-demand",), ("--recurse-submodules",), ("--no-verify",),
    ("--verify",), ("--no-thin",), ("--thin",), ("--progress",), ("-q",), ("-v",),
    ("--quiet",), ("--verbose",), ("-n",), ("--no-atomic",), ("--no-signed",),
    # glued / abbreviated / valued boolean flags
    ("-uf",), ("-fu",), ("-u=x",), ("--dry-run=1",), ("--atomic=1",), ("--dry",),
    ("--set-up",), ("--porcelain=1",), ("--set-upstream=origin",),
    # repeated flags
    ("-u", "-u"), ("--dry-run", "--dry-run"), ("-u", "--set-upstream"),
    ("--atomic", "--atomic"),
    # separators / files
    ("--",), ("-",), ("@file",), ("-c", "core.hooksPath=/x"), ("--config=x",),
]


@pytest.mark.parametrize("extra", _PUSH_REJECTS, ids=lambda e: " ".join(e))
def test_push_flags_rejected(extra):
    with pytest.raises(c.ArgvRejected):
        _p("push", *extra, "origin", "main")
    # the same token after the positionals is rejected too
    with pytest.raises(c.ArgvRejected):
        _p("push", "origin", "main", *extra)


@pytest.mark.parametrize("slots", [
    ("origin",),                                  # no branch
    (),                                           # nothing
    ("origin", "+main"), ("origin", ":main"), ("origin", "main:main"),
    ("origin", "refs/heads/main:refs/heads/main"), ("origin", "*"), ("origin", "main*"),
    ("origin", "refs/heads/*"), ("origin", "refs/heads/*:refs/heads/*"),
    ("origin", "+refs/heads/main"), ("origin", "HEAD"), ("origin", "@"),
    ("origin", "HEAD:main"), ("origin", "-b"), ("origin", "--main"), ("origin", ""),
    ("origin", "a..b"), ("origin", "a//b"), ("origin", "a/.b"), ("origin", ".a"),
    ("origin", "x@{1}"), ("origin", "x.lock"), ("origin", "a.lock/b"), ("origin", "x/"),
    ("origin", "x."), ("origin", "../x"), ("origin", "/x"), ("origin", "a b"),
    ("origin", "a~1"), ("origin", "a^"), ("origin", "a?"), ("origin", "a[1]"),
    ("origin", "a\\b"), ("origin", "a:b"), ("origin", "ma\u202ein"), ("origin", "main\n"),
    ("origin", "main\x00"), ("origin", "main\r"), ("origin", "m\u200bain"), ("origin", "\u00e9"),
    ("origin", "main", "main"),                  # duplicate
    ("origin",) + tuple(f"b{i}" for i in range(17)),   # too many
    # remote slot
    ("-x", "main"), ("--origin", "main"), ("", "main"), (".", "main"), ("..", "main"),
    ("a..b", "main"), ("a.lock", "main"), ("origin.", "main"), ("a/b", "main"),
    ("../x", "main"), (".x", "main"), ("x" * 65, "main"), ("a b", "main"), ("a:b", "main"),
    ("https://github.com/o/r.git", "main"), ("git@github.com:o/r.git", "main"),
    ("file:///etc", "main"), ("/tmp/repo", "main"), ("C:\\repo", "main"),
    ("ext::sh -c x", "main"), ("or\nigin", "main"), ("origin\x00", "main"),
])
def test_push_slots_rejected(slots):
    with pytest.raises(c.ArgvRejected):
        _p("push", *slots)


def test_push_sixteen_branches_accepted():
    assert len(_p("push", "origin", *[f"b{i}" for i in range(16)]).branches) == 16


@pytest.mark.parametrize("tokens", [
    ("pull", "--rebase", "origin"), ("pull", "-r", "origin"), ("pull", "--ff", "origin"),
    ("pull", "--ff-only", "origin"), ("pull", "--no-ff", "origin"), ("pull", "--squash", "origin"),
    ("pull", "--no-verify", "origin"), ("pull", "--no-rebase", "origin"),
    ("pull", "--recurse-submodules", "origin"), ("pull", "-s", "ours", "origin"),
    ("pull", "-X", "theirs", "origin"), ("pull", "--autostash", "origin"),
    ("pull", "--upload-pack=x", "origin"), ("pull", "--all", "origin"),
    ("pull", "origin", "a", "b"), ("pull",), ("pull", "+main"), ("pull", "origin", "+main"),
    ("pull", "origin", "main:main"), ("pull", "origin", "--"), ("pull", "--", "origin"),
    ("pull", "origin", "refs/heads/*"),
])
def test_pull_rejected(tokens):
    with pytest.raises(c.ArgvRejected):
        _p(*tokens)


@pytest.mark.parametrize("tokens", [
    ("fetch",), ("fetch", "--tags", "--no-tags", "origin"), ("fetch", "--depth", "5", "origin"),
    ("fetch", "--depth", "origin"), ("fetch", "--depth=0", "origin"),
    ("fetch", "--depth=abc", "origin"), ("fetch", "--depth=1000000", "origin"),
    ("fetch", "--depth=-1", "origin"), ("fetch", "--depth=", "origin"),
    ("fetch", "--depth=5", "--depth=6", "origin"), ("fetch", "--depth=05x", "origin"),
    ("fetch", "--upload-pack=x", "origin"), ("fetch", "--recurse-submodules", "origin"),
    ("fetch", "--multiple", "origin"), ("fetch", "--all"), ("fetch", "--all", "origin"),
    ("fetch", "--refmap=x", "origin"), ("fetch", "--prune", "origin"), ("fetch", "-p", "origin"),
    ("fetch", "--force", "origin"), ("fetch", "-f", "origin"), ("fetch", "--update-head-ok", "origin"),
    ("fetch", "origin", "main"), ("fetch", "origin", "+refs/heads/*:refs/heads/*"),
    ("fetch", "--tags=x", "origin"), ("fetch", "--no-tags", "--no-tags", "origin"),
    ("fetch", "--dep=1", "origin"),
])
def test_fetch_rejected(tokens):
    with pytest.raises(c.ArgvRejected):
        _p(*tokens)


@pytest.mark.parametrize("tokens", [
    ("ls-remote",), ("ls-remote", "--upload-pack=x", "origin"), ("ls-remote", "--exec=x", "origin"),
    ("ls-remote", "origin", "main"), ("ls-remote", "origin", "refs/heads/*"),
    ("ls-remote", "--get-url", "origin"), ("ls-remote", "-q", "origin"),
    ("ls-remote", "--symref", "origin"), ("ls-remote", "--heads", "--heads", "origin"),
    ("ls-remote", "--sort=refname", "origin"), ("ls-remote", "-t", "origin"),
    ("ls-remote", "--server-option=x", "origin"), ("ls-remote", "-o", "x", "origin"),
])
def test_ls_remote_rejected(tokens):
    with pytest.raises(c.ArgvRejected):
        _p(*tokens)


@pytest.mark.parametrize("command", [
    (), ("git",), ("git", "clone", "origin"), ("git", "status"), ("git", "remote", "add", "x", "y"),
    ("git", "config", "--list"), ("git", "submodule", "update"), ("git", "pushall", "origin", "x"),
    ("git", "-c", "core.hooksPath=/x", "push", "origin", "main"),
    ("git", "--git-dir=/x", "fetch", "origin"), ("git", "-C", "/x", "fetch", "origin"),
    ("git", "--no-pager", "fetch", "origin"), ("git", "-h"), ("git", "--exec-path=/x", "fetch", "origin"),
    ("git", "PUSH", "origin", "main"), ("git", "co", "x"), ("git", ""),
    ("/usr/bin/git", "fetch", "origin"), ("C:\\Git\\git.exe", "fetch", "origin"),
    ("gitk", "fetch", "origin"), ("git-lfs", "fetch", "origin"), ("sh", "-c", "git fetch origin"),
    (None, "fetch", "origin"), ("git", None, "origin"), ("git", "fetch", None), ("git", "fetch", 5),
])
def test_command_shapes_rejected(command):
    with pytest.raises(c.ArgvRejected):
        git._parse(command)
    assert git.match(Request(command, os.getcwd(), (), None)) is None if command else True


@pytest.mark.parametrize("name", ["origin", "up", "a", "A1", "my-remote", "my_remote", "r.1", "x" * 64])
def test_remote_problem_accepts(name):
    assert git.remote_problem(name) is None


@pytest.mark.parametrize("name", [
    "", ".", "..", "-x", "_x", ".x", "a..b", "a.lock", "a.lock.b", "a.", "a/b", "a b", "a:b", "a\\b",
    "x" * 65, "or\nigin", "origin\x00", "a@{b", "a~", "a*", "\u00e9", None, 5, b"origin",
])
def test_remote_problem_rejects(name):
    assert git.remote_problem(name)


@pytest.mark.parametrize("name", [
    "main", "a", "A1", "feature/x", "release-1.2.3", "a/b/c", "x_y", "v1.0", "a.b", "x" * 201,
])
def test_branch_problem_accepts(name):
    assert git.branch_problem(name) is None


@pytest.mark.parametrize("name", [
    "", "-x", "/x", ".x", "_x", "a..b", "a//b", "a/.b", "x@{1}", "x.lock", "a.lock/b", "x/", "x.",
    "HEAD", "@", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[b", "a\\b", "main\n", "x" * 202,
    None, 3, b"main",
])
def test_branch_problem_rejects(name):
    assert git.branch_problem(name)


def test_head_like_names_only_exact_head_rejected():
    assert git.branch_problem("HEAD") and git.branch_problem("@")
    assert git.branch_problem("HEAD2") is None
    assert git.branch_problem("feature/HEAD") is None


# --- argv / env construction --------------------------------------------------

GITP = "C:/pinned/git.exe"


def test_build_argv_push_rewrites_and_adds_atomic():
    argv = git.build_argv(GITP, _p("push", "origin", "main", "feature/x"))
    assert argv == [GITP, "push", "--atomic", "--", "origin",
                    "refs/heads/main:refs/heads/main", "refs/heads/feature/x:refs/heads/feature/x"]


def test_build_argv_push_flags_in_declaration_order_one_atomic():
    argv = git.build_argv(GITP, _p("push", "--porcelain", "--atomic", "--dry-run", "-u", "origin", "m"))
    assert argv == [GITP, "push", "--set-upstream", "--dry-run", "--atomic", "--porcelain", "--",
                    "origin", "refs/heads/m:refs/heads/m"]
    assert argv.count("--atomic") == 1


def test_build_argv_pull_forces_ff_only_no_rebase():
    assert git.build_argv(GITP, _p("pull", "origin", "main")) == [
        GITP, "pull", "--ff-only", "--no-rebase", "--no-edit", "--no-recurse-submodules",
        "--", "origin", "main"]
    assert git.build_argv(GITP, _p("pull", "origin"))[-2:] == ["--", "origin"]


def test_build_argv_fetch_and_ls_remote():
    assert git.build_argv(GITP, _p("fetch", "--tags", "--depth=3", "origin")) == [
        GITP, "fetch", "--tags", "--depth=3", "--", "origin"]
    assert git.build_argv(GITP, _p("ls-remote", "--heads", "origin")) == [
        GITP, "ls-remote", "--heads", "--", "origin"]


def test_shape_excludes_atomic_and_branches():
    a = git.match(Request(("git", "push", "--atomic", "origin", "x"), "/w", (), None))
    b = git.match(Request(("git", "push", "origin", "y"), "/w", (), None))
    assert a == b == {"sub": "push", "flags": [], "remote": "origin", "branch_glob": "*"}


def test_label_is_short():
    req = Request(("git", "fetch", "origin"), "/w", (), None)
    assert git.label(req, git.match(req)) == "git fetch origin"


def test_pin_pairs_contents_and_order():
    pairs = git.pin_pairs("C:\\Hooks\\dir", ["C:/h/mgr.exe"])
    assert pairs[0] == ("credential.helper", "")
    assert pairs[1] == ("credential.helper", "C:/h/mgr.exe")
    d = dict(pairs[2:])
    assert d["core.fsmonitor"] == "false"
    assert d["core.sshCommand"] == ""
    assert d["core.hooksPath"] == "C:/Hooks/dir"
    assert d["core.pager"] == "cat" and d["core.editor"] == "true" and d["core.askPass"] == ""
    assert d["protocol.allow"] == "never" and d["protocol.https.allow"] == "always"
    assert d["http.proxy"] == "" and d["http.extraHeader"] == ""
    assert d["submodule.recurse"] == "false" and d["push.recurseSubmodules"] == "no"
    assert d["fetch.recurseSubmodules"] == "no" and d["push.pushOption"] == ""
    assert d["pull.rebase"] == "false" and d["push.gpgSign"] == "false"
    assert d["transfer.credentialsInUrl"] == "die"
    assert d["gc.auto"] == "0" and d["maintenance.auto"] == "false"
    assert [p for p in git.pin_pairs("/h")[:1]] == [("credential.helper", "")]


def test_command_env_is_from_scratch(monkeypatch, tmp_path):
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_TRACE",
                 "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL", "GCM_INTERACTIVE", "SSH_ASKPASS",
                 "http_proxy", "HTTPS_PROXY", "GIT_PAGER", "PAGER", "EDITOR", "VISUAL",
                 "GIT_INDEX_FILE", "XDG_CONFIG_HOME", "LD_PRELOAD", "GH_HOST", "SSL_CERT_FILE"):
        monkeypatch.setenv(name, "evil")
    pairs = git.pin_pairs(str(tmp_path))
    env = git.command_env([str(tmp_path)], pairs)
    assert env["PATH"] == str(tmp_path)
    assert env["GIT_CONFIG_COUNT"] == str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        assert env[f"GIT_CONFIG_KEY_{i}"] == k and env[f"GIT_CONFIG_VALUE_{i}"] == v
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_PROTOCOL_FROM_USER"] == "0"
    assert env["GIT_ALLOW_PROTOCOL"] == c.RELAXATIONS.git_allowed_protocols
    allowed_git = {"GIT_ALLOW_PROTOCOL", "GIT_TERMINAL_PROMPT", "GIT_PROTOCOL_FROM_USER",
                   "GIT_CONFIG_COUNT"}
    for name in env:
        upper = name.upper()
        if upper.startswith("GIT_CONFIG_KEY_") or upper.startswith("GIT_CONFIG_VALUE_"):
            continue
        if upper.startswith(("GIT_", "GCM_", "SSH_", "LD_", "GH_", "SSL_", "XDG_")):
            assert name in allowed_git or name in git._TEST_EXTRA_ENV, name
    for name in ("PAGER", "EDITOR", "VISUAL", "http_proxy", "HTTPS_PROXY"):
        assert name not in env


def test_command_env_without_pairs_has_no_config_count():
    env = git.command_env(["/x"])
    assert "GIT_CONFIG_COUNT" not in env
    assert env["GIT_ALLOW_PROTOCOL"] == "https"


def test_command_env_refuses_tool_control_injection():
    with pytest.raises(c.EnvNameRefused):
        git.command_env(["/x"], injected={"GIT_DIR": "x"})
    assert git.command_env(["/x"], injected={"API_TOKEN": "t"})["API_TOKEN"] == "t"


def test_production_defaults_are_strict():
    assert git._TEST_EXTRA_ENV == {}
    assert c.RELAXATIONS.is_strict()


def test_describe_contains_hook_warning():
    req = Request(("git", "push", "origin", "main"), "/not/snapshotted", (), None)
    text = git.describe(req, git.match(req))
    assert git.HOOK_WARNING in text
    assert text.splitlines()[0] == "git push origin <branch>..."
    assert "the agent can obtain these values" in text
    pull = Request(("git", "pull", "origin"), "/x", (), None)
    assert git.describe(pull, dict(git.match(pull), branch_glob="feature/*")).splitlines()[0] == \
        "git pull origin [<branch matching feature/*>]"


# --- URL normalisation ---------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://github.com/owner/repo.git", "https://github.com/owner/repo.git"),
    ("https://GitHub.COM/Owner/Repo.git", "https://github.com/Owner/Repo.git"),
    ("https://example.org", "https://example.org"),
    ("https://git.example.org/a/b/c", "https://git.example.org/a/b/c"),
])
def test_normalise_url_accepts(url, expected):
    assert git.normalise_url(url) == expected


@pytest.mark.parametrize("url", [
    "http://github.com/o/r", "ssh://git@github.com/o/r", "git@github.com:o/r.git", "git://x/y",
    "file:///tmp/r", "/tmp/r", "C:/r", "ext::sh -c x", "https://u@github.com/o/r",
    "https://u:p@github.com/o/r", "https://github.com:443/o/r", "https://github.com:8443/o/r",
    "https://github.com:abc/o/r", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
    "https://github.com/o/%72", "https://github.com/o r", "https://github.com\\o", "https://",
    "https:///o/r", "https://-bad.com/x", "https://exa_mple.com/x", " https://github.com/o/r",
    "https://github.com/o/r ", "https://github.com/o/r\n", "https://github.com/\u202ex",
    "https://github.com/\x00", "", None, 5, "https://" + "a" * 2050,
])
def test_normalise_url_rejects_strict(url):
    assert git.normalise_url(url) is None


def test_normalise_url_relaxation_accepts_local_paths_only_when_set(monkeypatch):
    assert git.normalise_url("C:/tmp/remote.git") is None
    monkeypatch.setattr(c.RELAXATIONS, "skip_https_only_check", True)
    assert git.normalise_url("C:/tmp/remote.git") == "C:/tmp/remote.git"
    assert git.normalise_url("/tmp/a b/remote.git") == "/tmp/a b/remote.git"
    assert git.normalise_url("/tmp/r\n") is None
    assert git.normalise_url(" /tmp/r") is None
    assert git.normalise_url("") is None


# --- config -z parser ---------------------------------------------------------

def _rec(scope, origin, entry):
    return b"\0".join([scope.encode(), origin.encode(), entry.encode()]) + b"\0"


def test_parse_config_z_basic_shapes():
    data = (_rec("global", "file:C:/u/.gitconfig", "user.name\nJos\u00e9")
            + _rec("local", "file:.git/config", "x.bare")
            + _rec("local", "file:.git/config", "x.emptyv\n")
            + _rec("local", "file:.git/config", "x.multi\nline1\nline2\n")
            + _rec("command", "command line:", "credential.helper\n")).replace(
        "Jos\u00e9".encode("latin-1", "ignore"), "Jos\u00e9".encode())
    recs = git.parse_git_config_z(data)
    assert [(r.scope, r.origin, r.key, r.value) for r in recs] == [
        ("global", "file:C:/u/.gitconfig", "user.name", "Jos\u00e9"),
        ("local", "file:.git/config", "x.bare", None),
        ("local", "file:.git/config", "x.emptyv", ""),
        ("local", "file:.git/config", "x.multi", "line1\nline2\n"),
        ("command", "command line:", "credential.helper", ""),
    ]
    assert recs[1].value is None and recs[2].value == "" and recs[1].value != recs[2].value


def test_parse_config_z_empty_and_malformed():
    assert git.parse_git_config_z(b"") == []
    with pytest.raises(c.ProfileRefusal):
        git.parse_git_config_z(b"global\0file:x\0")
    with pytest.raises(c.ProfileRefusal):
        git.parse_git_config_z(b"global\0file:x\0a.b\nc\0local\0")


def test_parse_config_z_value_with_nul_free_equals_signs_kept():
    recs = git.parse_git_config_z(_rec("local", "file:.git/config", "a.b\nx=y = z"))
    assert recs[0].value == "x=y = z"


def test_last_values_last_wins_and_keeps_none_vs_empty():
    recs = [git.ConfigRecord("system", "o", "a.b", "1"), git.ConfigRecord("global", "o", "a.b", "2"),
            git.ConfigRecord("local", "o", "a.c", None), git.ConfigRecord("local", "o", "a.d", ""),
            git.ConfigRecord("command", "o", "a.b", None)]
    out = git.last_values(recs)
    assert out == {"a.b": None, "a.c": None, "a.d": ""}
    assert out["a.d"] == "" and out["a.c"] is None


@pytest.mark.parametrize("key", [
    "core.filemode", "core.bare", "core.repositoryformatversion", "core.logallrefupdates",
    "core.symlinks", "core.ignorecase", "core.autocrlf", "remote.origin.url", "remote.origin.fetch",
    "remote.my.remote.url", "branch.main.remote", "branch.feature/x.merge", "user.name",
    "user.email", "user.signingkey", "extensions.worktreeconfig", "extensions.objectformat",
])
def test_local_key_allowlist_accepts(key):
    assert git._local_key_ok(key)


@pytest.mark.parametrize("key", [
    "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.pager", "core.editor",
    "core.worktree", "core.gitproxy", "core.askpass", "core.excludesfile", "core.attributesfile",
    "core.filemode.x", "alias.x", "filter.x.smudge", "filter.x.clean", "filter.x.process",
    "diff.x.command", "diff.external", "merge.x.driver", "mergetool.x.cmd", "url.x.insteadof",
    "url.x.pushinsteadof", "remote.origin.pushurl", "remote.origin.proxy", "remote.origin.vcs",
    "remote.origin.receivepack", "remote.origin.uploadpack", "remote.origin.pushoption",
    "remote.url", "remote.origin.mirror", "branch.main.rebase", "branch.main.pushremote",
    "branch.remote", "user.x.name", "credential.helper", "credential.https://x.helper",
    "include.path", "includeif.gitdir:/x.path", "submodule.x.update", "submodule.recurse",
    "pull.rebase", "push.default", "http.proxy", "http.extraheader", "safe.directory",
    "gpg.program", "sendemail.smtpserver", "extensions", "core", "x", "", "protocol.allow",
    "uploadpack.packobjectshook", "receive.denycurrentbranch", "gc.auto", "color.ui", "init.templatedir",
])
def test_local_key_allowlist_rejects(key):
    assert not git._local_key_ok(key)


def _r(scope, key, value):
    return git.ConfigRecord(scope, "file:x", key, value)


def test_effective_helpers_order_reset_and_url_scoping():
    url = "https://github.com/o/r.git"
    recs = [
        _r("system", "credential.helper", "sys"),
        _r("global", "credential.helper", ""),
        _r("global", "credential.helper", "mgr"),
        _r("global", "credential.https://github.com.helper", "urlhelper"),
        _r("global", "credential.https://example.org.helper", "otherhost"),
        _r("global", "credential.https://github.com/o.helper", "pathhelper"),
        _r("global", "credential.https://github.com/other.helper", "otherpath"),
        _r("global", "credential.http://github.com.helper", "otherscheme"),
        _r("local", "credential.helper", None),
        _r("command", "credential.helper", "cmdhelper"),
    ]
    assert git.effective_helpers(recs, url) == ["mgr", "urlhelper", "pathhelper"]


def test_effective_helpers_later_reset_clears_earlier_url_helpers():
    url = "https://github.com/o/r.git"
    recs = [_r("global", "credential.https://github.com.helper", "u"),
            _r("local", "credential.helper", ""),
            _r("local", "credential.helper", "mine")]
    assert git.effective_helpers(recs, url) == ["mine"]
    assert git.effective_helpers([_r("global", "credential.helper", "a"),
                                  _r("local", "credential.helper", "")], url) == []
    assert git.effective_helpers([_r("global", "core.helper", "x")], url) == []


# ---------------------------------------------------------------------------
# Real git
# ---------------------------------------------------------------------------

def _script(path: Path, body: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="\n") as handle:
        handle.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.bare = root / "remote.git"
        self.work = root / "work"
        self.other = root / "other"
        self.url = self.bare.as_posix()
        self.cwd = os.path.normcase(os.path.realpath(self.work))
        self.n = 0

    def git(self, *args, cwd=None, check=True, env=None):
        res = subprocess.run(["git", *args], cwd=str(cwd or self.work), env=env or os.environ.copy(),
                             capture_output=True, text=True, timeout=120)
        if check:
            assert res.returncode == 0, f"git {args}: {res.stdout}\n{res.stderr}"
        return res

    def commit(self, where=None, name=None):
        where = where or self.work
        self.n += 1
        fname = name or f"f{self.n}.txt"
        (where / fname).write_text(f"{self.n}\n")
        self.git("add", "--", fname, cwd=where)
        self.git("commit", "-q", "-m", f"c{self.n}", cwd=where)

    def upstream_commit(self):
        self.commit(self.other)
        self.git("push", "-q", "origin", "main", cwd=self.other)

    def head(self, where=None):
        return self.git("rev-parse", "HEAD", cwd=where or self.work).stdout.strip()

    def remote_head(self):
        return self.git("--git-dir", str(self.bare), "rev-parse", "main").stdout.strip()

    def global_cfg(self, *args):
        return self.git("config", "--global", *args)

    @property
    def hooks(self) -> Path:
        return self.work / ".git" / "hooks"

    def pin(self):
        gp = c.resolve_pinned_binary("git")
        return gp, c.pinned_path_dirs(extra=[os.path.dirname(gp.path)])

    def raw(self, command, hooks_dir=None, helpers=(), pairs=None):
        """argv + env of a pinned run built straight from the pins (no snapshot)."""
        gp, dirs = self.pin()
        parsed = git._parse(command)
        pairs = pairs if pairs is not None else git.pin_pairs(
            hooks_dir or (self.hooks.as_posix()), list(helpers))
        return git.build_argv(gp.path, parsed), git.command_env(dirs, pairs)

    def run(self, argv, env):
        return subprocess.run(argv, cwd=str(self.work), env=env, capture_output=True, text=True,
                              timeout=120)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in list(os.environ):
        if name.upper().startswith(("GIT_", "GCM_")):
            monkeypatch.delenv(name)
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(name, str(home / ("xdg" if name == "XDG_CONFIG_HOME" else "")).rstrip("\\/"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(git, "_TEST_EXTRA_ENV", {"GIT_CONFIG_NOSYSTEM": "1"})
    monkeypatch.setattr(c.RELAXATIONS, "git_allowed_protocols", "file:https")
    monkeypatch.setattr(c.RELAXATIONS, "skip_https_only_check", True)
    monkeypatch.setattr(c.RELAXATIONS, "skip_exe_dir_writable_check", True)
    monkeypatch.setattr(c.RELAXATIONS, "version_floors", {"git": c.Floor((2, 0, 0))})
    r = Repo((tmp_path / "ctx").resolve())
    r.root.mkdir()
    r.git("init", "-q", "--bare", "-b", "main", str(r.bare), cwd=r.root)
    r.git("init", "-q", "-b", "main", str(r.work), cwd=r.root)
    for where in (r.work,):
        r.git("config", "user.name", "T", cwd=where)
        r.git("config", "user.email", "t@example.org", cwd=where)
    r.git("remote", "add", "origin", r.url)
    r.commit()
    r.git("push", "-q", "-u", "origin", "main")
    r.git("clone", "-q", r.url, str(r.other), cwd=r.root)
    r.git("config", "user.name", "T", cwd=r.other)
    r.git("config", "user.email", "t@example.org", cwd=r.other)
    return r


def approve(repo, *command, only=()):
    req = Request(tuple(command), repo.cwd, tuple(only), None)
    cand = git.match(req)
    assert cand is not None
    snap = git.snapshot(req, cand)
    entry = {"kind": "git", "cwd": req.cwd, "only_vars": list(req.only_vars), "shape": cand,
             "snapshot": snap}
    return req, entry


FETCH = ("git", "fetch", "origin")
PUSH = ("git", "push", "origin", "main")
PULL = ("git", "pull", "origin", "main")


# --- happy path -------------------------------------------------------------------

def test_snapshot_verify_roundtrip_and_final_argv(repo):
    req, entry = approve(repo, *PUSH, only=["API_TOKEN"])
    snap = entry["snapshot"]
    assert snap["url"] == repo.url and snap["url_push"] is True
    assert snap["helpers"] == []
    assert snap["hooks_dir"] == os.path.normcase(repo.hooks.as_posix()) \
        or snap["hooks_dir"].lower() == repo.hooks.as_posix().lower()
    assert git.check_snapshot(entry) == (True, None)
    v = git.verify(entry, req)
    assert v.ok and v.replace_env is True
    assert v.argv == [snap["git"]["path"], "push", "--atomic", "--", "origin",
                      "refs/heads/main:refs/heads/main"]
    assert v.env["GIT_ALLOW_PROTOCOL"] == "file:https"
    assert v.env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "API_TOKEN" not in v.env
    pairs = git.pin_pairs(snap["hooks_dir"], [])
    assert v.env["GIT_CONFIG_COUNT"] == str(len(pairs))


def test_verified_verdict_actually_pushes(repo):
    req, entry = approve(repo, *PUSH)
    repo.commit()
    v = git.verify(entry, req)
    assert v.ok
    res = repo.run(v.argv, v.env)
    assert res.returncode == 0, res.stderr
    assert repo.remote_head() == repo.head()


def test_verified_fetch_and_pull_run(repo):
    req, entry = approve(repo, *PULL)
    repo.upstream_commit()
    v = git.verify(entry, req)
    assert v.ok
    res = repo.run(v.argv, v.env)
    assert res.returncode == 0, res.stderr
    assert repo.head() == repo.head(repo.other)
    req2, entry2 = approve(repo, "git", "ls-remote", "--heads", "origin")
    v2 = git.verify(entry2, req2)
    res2 = repo.run(v2.argv, v2.env)
    assert res2.returncode == 0 and "refs/heads/main" in res2.stdout


def test_describe_after_snapshot_has_url_hooks_and_warning(repo):
    req, entry = approve(repo, *PUSH)
    text = git.describe(req, entry["shape"])
    assert git.HOOK_WARNING in text
    assert f"Push URL pinned: {repo.url}" in text
    assert "Credential helpers (your own, pinned): none" in text
    assert "Hooks run normally from:" in text
    text2 = git.describe(*(lambda r, e: (r, e["shape"]))(*approve(repo, *FETCH)))
    assert f"Remote URL pinned: {repo.url}" in text2


def test_verify_does_not_apply_cases(repo):
    req, entry = approve(repo, *PUSH)

    def not_applicable(command, ent=entry, cwd=None):
        v = git.verify(ent, Request(tuple(command), cwd or repo.cwd, (), None))
        assert v.ok is False and v.reason is None, (command, v)

    not_applicable(("git", "fetch", "origin"))
    not_applicable(("git", "push", "-u", "origin", "main"))
    not_applicable(("git", "push", "--force", "origin", "main"))
    not_applicable(("git", "push", "other", "main"))
    not_applicable(("git", "status"))
    not_applicable(("git", "push", "origin", "main"), cwd=str(repo.other))
    assert git.verify({"shape": None}, Request(PUSH, repo.cwd, (), None)).reason is None


def test_verify_same_shape_other_branch_is_allowed(repo):
    req, entry = approve(repo, *PUSH)
    v = git.verify(entry, Request(("git", "push", "origin", "other-branch"), repo.cwd, (), None))
    assert v.ok and v.argv[-1] == "refs/heads/other-branch:refs/heads/other-branch"


def test_branch_glob_restricts_branches(repo):
    req, entry = approve(repo, "git", "push", "origin", "feature/a")
    entry["shape"] = dict(entry["shape"], branch_glob="feature/*")
    ok = git.verify(entry, Request(("git", "push", "origin", "feature/b", "feature/c"),
                                   repo.cwd, (), None))
    assert ok.ok
    for branches in (("main",), ("feature/a", "main"), ("featurex",)):
        v = git.verify(entry, Request(("git", "push", "origin") + branches, repo.cwd, (), None))
        assert v.ok is False and v.reason is None
    for bad in ("", "a b", "a;b", "*" * 300, "a\n", None):
        ent = dict(entry, shape=dict(entry["shape"], branch_glob=bad))
        assert git.verify(ent, req).ok is False
        assert git.check_snapshot(ent)[0] is False


def test_branchless_pull_is_not_covered_by_a_restricted_branch_glob(repo):
    # B4-05: a branch-less pull merges branch.<cur>.merge from the (unsnapshotted)
    # local config, so a glob other than "*" cannot be enforced for it.
    req, entry = approve(repo, "git", "pull", "origin")
    assert git.verify(entry, req).ok                       # glob "*": fine
    restricted = dict(entry, shape=dict(entry["shape"], branch_glob="feature/*"))
    v = git.verify(restricted, req)
    assert v.ok is False and v.reason is None


def test_tool_control_variable_names_are_refused(repo):
    req = Request(PUSH, repo.cwd, ("GIT_SSH_COMMAND",), None)
    with pytest.raises(c.ProfileRefusal):
        git.snapshot(req, git.match(req))
    req0, entry = approve(repo, *PUSH, only=["API_TOKEN"])
    v = git.verify(entry, Request(PUSH, repo.cwd, ("HTTPS_PROXY", "API_TOKEN"), None))
    assert v.ok is False and v.reason and "tool-control" in v.reason


def test_snapshot_rejects_candidate_mismatch(repo):
    req = Request(PUSH, repo.cwd, (), None)
    with pytest.raises(c.ProfileRefusal):
        git.snapshot(req, dict(git.match(req), remote="other"))


# --- ineligible repositories (snapshot refuses) ----------------------------------

def _refuses(repo, command, text):
    req = Request(tuple(command), repo.cwd, (), None)
    with pytest.raises(c.ProfileRefusal) as exc:
        git.snapshot(req, git.match(req))
    assert text.lower() in exc.value.reason.lower(), exc.value.reason


def test_unconfigured_remote_refused(repo):
    _refuses(repo, ("git", "fetch", "nosuch"), "not a configured remote")
    # a remote spelled like a path is not even a remote slot
    assert git.match(Request(("git", "fetch", repo.url), repo.cwd, (), None)) is None


@pytest.mark.parametrize("key,value", [
    ("alias.x", "status"), ("filter.x.smudge", "cat"), ("core.fsmonitor", "evil"),
    ("core.hooksPath", "/x"), ("core.sshCommand", "evil"), ("url.evil.insteadOf", "x"),
    ("remote.origin.pushurl", "/elsewhere"), ("credential.helper", "evil"),
    ("diff.external", "evil"), ("include.path", "/x"), ("pull.rebase", "true"),
])
def test_hostile_local_config_refused(repo, key, value):
    repo.git("config", key, value)
    _refuses(repo, FETCH, "benign allowlist")
    _refuses(repo, PUSH, key.lower())


def test_core_worktree_refused(repo):
    repo.global_cfg("core.worktree", repo.work.as_posix())
    _refuses(repo, FETCH, "core.worktree")


def test_worktree_scope_config_checked_too(repo):
    repo.git("config", "extensions.worktreeConfig", "true")
    repo.git("config", "--worktree", "alias.y", "status")
    _refuses(repo, FETCH, "alias.y")


def test_gitdir_file_and_reparse_point_refused(repo):
    real = repo.root / "realgit"
    os.rename(repo.work / ".git", real)
    (repo.work / ".git").write_text(f"gitdir: {real.as_posix()}\n")
    _refuses(repo, FETCH, ".git is not a plain directory")


@pytest.mark.skipif(not WIN, reason="junction via mklink /J")
def test_junction_dot_git_refused(repo):
    real = repo.root / "realgit"
    os.rename(repo.work / ".git", real)
    res = subprocess.run(["cmd", "/c", "mklink", "/J", str(repo.work / ".git"), str(real)],
                         capture_output=True, text=True)
    if res.returncode != 0:
        pytest.skip("cannot create a junction here")
    _refuses(repo, FETCH, ".git is not a plain directory")


def test_second_url_refused_and_pushurl_variants(repo):
    # a second url is only reachable through a non-local scope (local is refused earlier)
    repo.global_cfg("--add", "remote.origin.url", "C:/elsewhere/other.git")
    _refuses(repo, FETCH, "2 URLs")
    _refuses(repo, PUSH, "2 push URLs")


def test_global_pushurl_is_what_push_records(repo):
    other = repo.root / "pushtarget.git"
    repo.git("init", "-q", "--bare", "-b", "main", str(other), cwd=repo.root)
    repo.global_cfg("remote.origin.pushurl", other.as_posix())
    _, fetch_entry = approve(repo, *FETCH)
    _, push_entry = approve(repo, *PUSH)
    assert fetch_entry["snapshot"]["url"] == repo.url
    assert push_entry["snapshot"]["url"] == other.as_posix()
    # two push urls: git pushes to both, so exactly-one fails
    repo.global_cfg("--add", "remote.origin.pushurl", repo.url)
    _refuses(repo, PUSH, "2 push URLs")
    approve(repo, *FETCH)        # fetch only looks at remote.origin.url


def test_insteadof_and_pushinsteadof_are_what_get_url_prints(repo):
    gp, dirs = repo.pin()
    ctx = git._Ctx(repo.cwd, gp, dirs, git.pin_pairs("."))
    assert git._remote_url(ctx, "origin", False) == repo.url
    assert git._remote_url(ctx, "origin", True) == repo.url
    repo.global_cfg(f"url.mirror/.insteadOf", repo.url)
    assert git._remote_url(ctx, "origin", False) == "mirror/"
    assert git._remote_url(ctx, "origin", True) == "mirror/"
    repo.global_cfg("--unset", "url.mirror/.insteadOf")
    repo.global_cfg("url.pushmirror/.pushInsteadOf", repo.url)
    assert git._remote_url(ctx, "origin", False) == repo.url
    assert git._remote_url(ctx, "origin", True) == "pushmirror/"


def test_command_scope_url_adds_a_second_line(repo):
    """C3: a command-scope remote.origin.url ADDS a url; only --all shows it."""
    gp, dirs = repo.pin()
    pairs = git.pin_pairs(".") + [("remote.origin.url", "C:/evil/x.git")]
    ctx = git._Ctx(repo.cwd, gp, dirs, pairs)
    with pytest.raises(c.ProfileRefusal) as exc:
        git._remote_url(ctx, "origin", False)
    assert "2 URLs" in exc.value.reason
    pairs = git.pin_pairs(".") + [("remote.origin.pushurl", "C:/evil/x.git"),
                                  ("remote.origin.pushurl", "C:/evil/y.git")]
    with pytest.raises(c.ProfileRefusal):
        git._remote_url(git._Ctx(repo.cwd, gp, dirs, pairs), "origin", True)
    with pytest.raises(c.ProfileRefusal):
        git._remote_url(ctx, "nosuch", False)


def test_url_in_snapshot_follows_insteadof_in_global(repo):
    repo.global_cfg("url.C:/redirected/.insteadOf", "mirror/")
    repo.global_cfg("remote.origin.url", "mirror/x.git")
    # local remote.origin.url is still there, so two urls: refused
    _refuses(repo, FETCH, "2 URLs")


def test_strict_url_rules_apply_when_relaxation_is_off(repo, monkeypatch):
    monkeypatch.setattr(c.RELAXATIONS, "skip_https_only_check", False)
    _refuses(repo, FETCH, "not an acceptable https URL")          # the local bare path
    repo.git("remote", "set-url", "origin", "https://example.org/o/r.git")
    _, entry = approve(repo, *FETCH)
    assert entry["snapshot"]["url"] == "https://example.org/o/r.git"
    # git itself refuses to print a URL with userinfo (transfer.credentialsInURL=die)
    repo.git("remote", "set-url", "origin", "https://user:pw@example.org/o/r.git")
    _refuses(repo, FETCH, "its URL cannot be read")
    for bad in ("https://example.org:8443/r",
                "https://example.org/r?x=1", "http://example.org/r", "git@example.org:o/r.git"):
        repo.git("remote", "set-url", "origin", bad)
        _refuses(repo, FETCH, "not an acceptable https URL")


# --- version floors ------------------------------------------------------------------

@pytest.fixture
def strict_versions(monkeypatch):
    monkeypatch.setattr(c.RELAXATIONS, "version_floors", {})
    state = {"text": "git version 2.45.1.windows.1"}
    monkeypatch.setattr(git, "_git_version_text", lambda pin, dirs: state["text"])
    return state


def test_strict_default_refuses_this_machines_git(repo, strict_versions):
    for text in ("git version 2.45.1.windows.1", "git version 2.45.3", "git version 2.50.0",
                 "git version 2.44.3.windows.1", "git version 1.9.0", "git version 2.49.0"):
        strict_versions["text"] = text
        _refuses(repo, FETCH, "older than the required")


@pytest.mark.parametrize("text", [
    "git version 2.45.4", "git version 2.45.4.windows.1", "git version 2.50.1",
    "git version 2.50.1.windows.2", "git version 2.51.0", "git version 2.44.4", "git version 2.49.1",
    "git version 3.0.0",
])
def test_strict_accepts_patched_lines(repo, strict_versions, text):
    strict_versions["text"] = text
    _, entry = approve(repo, *FETCH)
    assert entry["snapshot"]["git_version"] == text
    assert git.check_snapshot(entry)[0] is True


def test_unparsable_version_refused(repo, strict_versions):
    strict_versions["text"] = "git version unknown"
    _refuses(repo, FETCH, "cannot determine")


def test_version_is_rechecked_from_the_snapshot(repo, strict_versions):
    strict_versions["text"] = "git version 2.50.1"
    req, entry = approve(repo, *FETCH)
    entry["snapshot"]["git_version"] = "git version 2.45.1.windows.1"
    ok, reason = git.check_snapshot(entry)
    assert not ok and "older" in reason


# --- drift -------------------------------------------------------------------------------

def _write(path: Path, text="x\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _rmtree_force(path):
    """rmtree that survives read-only git objects on Windows."""
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=onerror)


def _hook(repo, name="pre-push", text="exit 0\n"):
    _script(repo.hooks / name, text)


DRIFTS = [
    # (id, mutation(repo), expected substring (lower-case))
    ("local-alias", lambda r: r.git("config", "alias.x", "status"), "alias.x"),
    ("local-filter-smudge", lambda r: r.git("config", "filter.x.smudge", "cat"), "filter.x.smudge"),
    ("local-hookspath", lambda r: r.git("config", "core.hooksPath", "/x"), "core.hookspath"),
    ("local-pushurl", lambda r: r.git("config", "remote.origin.pushurl", "/x"), "pushurl"),
    ("local-second-url", lambda r: r.git("config", "--add", "remote.origin.url", "C:/x/y.git"), "urls; exactly one is required"),
    ("local-url-changed", lambda r: r.git("remote", "set-url", "origin", (r.other).as_posix()),
     "remote url changed"),
    ("local-fetch-refspec", lambda r: r.git("config", "remote.origin.fetch", "+refs/heads/*:refs/x/*"),
     "fetch refspecs"),
    ("remote-removed", lambda r: r.git("remote", "remove", "origin"), "not a configured remote"),
    ("hook-added", lambda r: _hook(r), "the hooks changed"),
    ("hooks-dir-removed", lambda r: shutil.rmtree(r.hooks), "the hooks changed"),
    ("hooks-subdir-added", lambda r: (r.hooks / "empty").mkdir(), "the hooks changed"),
    ("gitattributes-top", lambda r: _write(r.work / ".gitattributes", "* text\n"),
     "attributes/modules"),
    ("info-attributes", lambda r: _write(r.work / ".git" / "info" / "attributes", "* -text\n"),
     "attributes/modules"),
    ("gitmodules", lambda r: _write(r.work / ".gitmodules", "[submodule \"x\"]\n"),
     "attributes/modules"),
    ("lfsconfig", lambda r: _write(r.work / ".lfsconfig", "[lfs]\n"), "attributes/modules"),
    ("nested-attributes-untracked", lambda r: _write(r.work / "sub" / "dir" / ".gitattributes",
                                                     "*.txt filter=evil\n"), "nested .gitattributes"),
    ("nested-attributes-ignored", lambda r: (_write(r.work / ".gitignore", "vendor/\n"),
                                             _write(r.work / "vendor" / "x" / ".gitattributes", "* -text\n")),
     "nested .gitattributes"),
    ("nested-attributes-upper-case", lambda r: _write(r.work / "sub" / ".GITATTRIBUTES", "* -text\n"),
     "nested .gitattributes"),
    ("global-config-key", lambda r: r.global_cfg("core.autocrlf", "true"), "git configuration"),
    ("global-url-rewrite", lambda r: r.global_cfg("url.x/.insteadOf", "y/"), "git configuration"),
    ("global-hookspath", lambda r: (_hook_dir_global(r)), "hooks directory setting"),
    ("global-credential-helper", lambda r: r.global_cfg("credential.helper", "!echo hi"),
     "credential helpers changed"),
    ("global-core-worktree", lambda r: r.global_cfg("core.worktree", "/x"), "core.worktree"),
    ("binary-sha", None, "changed since it was approved"),
    ("cwd-gone", None, "working directory is gone"),
    ("gitdir-file", lambda r: (os.rename(r.work / ".git", r.root / "realgit"),
                               (r.work / ".git").write_text("gitdir: " + (r.root / "realgit").as_posix())),
     ".git is not a plain directory"),
]


def _hook_dir_global(r):
    d = r.root / "ghooks"
    _script(d / "pre-push", "exit 0\n")
    r.global_cfg("core.hooksPath", d.as_posix())


@pytest.mark.parametrize("name,mutate,expect", DRIFTS, ids=[d[0] for d in DRIFTS])
@pytest.mark.parametrize("command", [FETCH, PUSH], ids=["fetch", "push"])
def test_drift_is_caught_at_arm_time_and_at_verify(repo, name, mutate, expect, command):
    req, entry = approve(repo, *command)
    assert git.check_snapshot(entry) == (True, None)
    if name == "binary-sha":
        entry["snapshot"]["git"] = dict(entry["snapshot"]["git"], sha256="0" * 64)
    elif name == "cwd-gone":
        _rmtree_force(repo.work)
        assert not os.path.isdir(repo.work)
    else:
        mutate(repo)
    ok, reason = git.check_snapshot(entry)
    assert ok is False and reason, name
    assert expect in reason.lower(), (name, reason)
    v = git.verify(entry, req)
    assert v.ok is False and v.reason and expect in v.reason.lower(), (name, v.reason)


def test_hook_modified_after_approval_is_drift(repo):
    _hook(repo, text="exit 0\n")
    req, entry = approve(repo, *PUSH)
    assert git.check_snapshot(entry)[0]
    _hook(repo, text="echo changed\nexit 0\n")
    ok, reason = git.check_snapshot(entry)
    assert not ok and "the hooks changed" in reason
    _hook(repo, text="exit 0\n")
    assert git.check_snapshot(entry)[0]          # restored bytes: fine again


def test_hook_deleted_and_hooks_dir_absent_at_approval(repo):
    _hook(repo)
    req, entry = approve(repo, *PUSH)
    os.remove(repo.hooks / "pre-push")
    assert "the hooks changed" in git.check_snapshot(entry)[1]
    shutil.rmtree(repo.hooks)
    req2, entry2 = approve(repo, *PUSH)
    assert entry2["snapshot"]["hooks_tree"] is None
    assert git.check_snapshot(entry2)[0]
    repo.hooks.mkdir()
    assert "the hooks changed" in git.check_snapshot(entry2)[1]


def test_global_hooks_dir_is_the_pinned_one(repo):
    ghooks = repo.root / "ghooks"
    _script(ghooks / "pre-push", "exit 0\n")
    repo.global_cfg("core.hooksPath", ghooks.as_posix())
    req, entry = approve(repo, *PUSH)
    assert entry["snapshot"]["hooks_dir"].lower() == os.path.normpath(ghooks).replace("\\", "/").lower()
    pairs = dict(git.pin_pairs(entry["snapshot"]["hooks_dir"]))
    assert pairs["core.hooksPath"] == entry["snapshot"]["hooks_dir"]
    # the global hookspath itself does not count as unpinned config drift; editing a hook does
    assert git.check_snapshot(entry)[0]
    _script(ghooks / "pre-push", "exit 1\n")
    assert "the hooks changed" in git.check_snapshot(entry)[1]


@pytest.mark.parametrize("value", ["relative/hooks", "//server/share/hooks", "~/nonexistent-ok"])
def test_unusable_global_hookspath_values(repo, value):
    repo.global_cfg("core.hooksPath", value)
    if value.startswith("~/"):
        approve(repo, *FETCH)         # expands under the (fake) home, hooks dir simply absent
    else:
        _refuses(repo, FETCH, "core.hooksPath")


def test_nested_attributes_tracked_modified_and_deleted(repo):
    _write(repo.work / "pkg" / ".gitattributes", "*.bin binary\n")
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "nested attrs")
    req, entry = approve(repo, *FETCH)
    assert list(entry["snapshot"]["nested_attributes"]) == ["pkg/.gitattributes"]
    assert entry["snapshot"]["nested_attributes"]["pkg/.gitattributes"]
    assert git.check_snapshot(entry)[0]
    _write(repo.work / "pkg" / ".gitattributes", "*.bin filter=evil\n")
    ok, reason = git.check_snapshot(entry)
    assert not ok and "nested .gitattributes" in reason
    _write(repo.work / "pkg" / ".gitattributes", "*.bin binary\n")
    assert git.check_snapshot(entry)[0]
    os.remove(repo.work / "pkg" / ".gitattributes")            # tracked file deleted on disk
    ok, reason = git.check_snapshot(entry)
    assert not ok and "nested .gitattributes" in reason


def test_nested_attributes_found_in_deep_untracked_and_removed_again(repo):
    req, entry = approve(repo, *FETCH)
    assert entry["snapshot"]["nested_attributes"] == {}
    deep = repo.work / "a" / "b" / "c" / "d" / ".gitattributes"
    _write(deep, "* text\n")
    assert "nested .gitattributes" in git.check_snapshot(entry)[1]
    os.remove(deep)
    assert git.check_snapshot(entry)[0]
    # top-level files are NOT double-counted as nested
    _write(repo.work / ".gitattributes", "* text\n")
    ok, reason = git.check_snapshot(entry)
    assert "attributes/modules" in reason


def test_nested_attributes_cap_makes_repo_ineligible(repo, monkeypatch):
    monkeypatch.setattr(git, "MAX_NESTED_ATTRIBUTES", 2)
    for i in range(3):
        _write(repo.work / f"d{i}" / ".gitattributes", "* text\n")
    _refuses(repo, FETCH, "more than 2 nested .gitattributes")
    os.remove(repo.work / "d2" / ".gitattributes")
    approve(repo, *FETCH)


def test_nested_attributes_probe_failure_refuses(repo, monkeypatch):
    real = git._probe

    def broken(ctx, args):
        if args and args[0] == "ls-files":
            return c.ProbeResult(error="boom")
        return real(ctx, args)

    monkeypatch.setattr(git, "_probe", broken)
    _refuses(repo, FETCH, "nested .gitattributes")


@pytest.mark.skipif(not WIN, reason="Windows DLL side-loading defence")
def test_cwd_dll_drift(repo):
    req, entry = approve(repo, *FETCH)
    (repo.work / "evil.dll").write_bytes(b"MZ")
    ok, reason = git.check_snapshot(entry)
    assert not ok and "dll" in reason.lower()


def test_subcommand_family_mismatch(repo):
    req, entry = approve(repo, *FETCH)
    entry["shape"] = dict(entry["shape"], sub="push")
    ok, reason = git.check_snapshot(entry)
    assert not ok and "different subcommand" in reason


@pytest.mark.parametrize("breaker", [
    lambda e: e.update(snapshot=None), lambda e: e["snapshot"].pop("url"),
    lambda e: e["snapshot"].update(version=2), lambda e: e["snapshot"].pop("nested_attributes"),
    lambda e: e["snapshot"].update(helpers="x"), lambda e: e["snapshot"].pop("dlls"),
    lambda e: e.update(shape={"sub": "clone", "remote": "origin", "branch_glob": "*", "flags": []}),
    lambda e: e["shape"].update(remote="-x"), lambda e: e["shape"].update(branch_glob="a b"),
    lambda e: e.update(cwd=None), lambda e: e.update(shape="x"),
    lambda e: e["snapshot"]["git"].pop("path"), lambda e: e["snapshot"]["git"].update(sha256="zz"),
    lambda e: e["snapshot"].update(helpers=[{"value": 1, "pin": 2}]),
    lambda e: e["snapshot"].update(helpers=[{"value": "x", "pin": "x", "binary": {}}]),
])
def test_malformed_entries_are_refused_not_crashed(repo, breaker):
    req, entry = approve(repo, *FETCH)
    breaker(entry)
    ok, reason = git.check_snapshot(entry)
    assert ok is False and reason
    v = git.verify(entry, req)
    assert v.ok is False


def test_verify_survives_uncanonical_cwd_spelling(repo):
    req, entry = approve(repo, *FETCH)
    other_spelling = str(repo.work) + os.sep + "."
    v = git.verify(entry, Request(FETCH, other_spelling, (), None))
    assert v.ok


# --- config -z parser on real git output ------------------------------------------------

def test_parser_on_real_git_output(repo):
    home = Path(os.environ["HOME"])
    (home / "inc.cfg").write_text("[inc]\n\tfromfile = 1\n")
    (home / ".gitconfig").write_text(
        "[x]\n\tbare\n\temptyv =\n\tmulti = \"line1\\nline2\"\n"
        "[Mixed \"SubSection\"]\n\tVarName = V\n"
        f"[include]\n\tpath = {(home / 'inc.cfg').as_posix()}\n")
    repo.git("config", "branch.main.description", "d")
    gp, dirs = repo.pin()
    res = c.run_probe([gp.path, "-C", repo.cwd, "config", "--list", "--show-origin", "--show-scope", "-z"],
                      git.command_env(dirs, git.pin_pairs(".")), expect_sha256=gp.sha256)
    assert res.ok
    recs = git.parse_git_config_z(res.stdout)
    by_key = {}
    for r in recs:
        by_key.setdefault(r.key, []).append(r)
    assert by_key["x.bare"][0].value is None
    assert by_key["x.emptyv"][0].value == ""
    assert by_key["x.multi"][0].value == "line1\nline2"
    assert by_key["mixed.SubSection.varname"][0].value == "V"
    inc_path = by_key["include.path"][0]
    assert inc_path.scope == "global" and inc_path.origin.startswith("file:")
    assert inc_path.origin.endswith(".gitconfig")
    inc = by_key["inc.fromfile"][0]
    assert inc.scope == "global" and inc.origin.endswith("inc.cfg") and inc.value == "1"
    local = by_key["remote.origin.url"][0]
    assert local.scope == "local" and local.origin == "file:.git/config" and local.value == repo.url
    cmd = by_key["core.fsmonitor"][0]
    assert cmd.scope == "command" and cmd.origin == "command line:" and cmd.value == "false"
    helpers = [r.value for r in by_key["credential.helper"]]
    assert helpers == ["", ]
    scopes = [r.scope for r in recs]
    assert scopes == sorted(scopes, key=["system", "global", "local", "worktree", "command"].index)


# ---------------------------------------------------------------------------
# Behavioural proofs: the pins beat hostile local config
# ---------------------------------------------------------------------------

def test_fsmonitor_pin_beats_hostile_local_config(repo):
    marker = repo.root / "fsmonitor.marker"
    _script(repo.root / "fs.sh", f'echo ran >> "{marker.as_posix()}"\n')
    repo.git("config", "core.fsmonitor", (repo.root / "fs.sh").as_posix())
    # control: the marker CAN fire when nothing is pinned
    repo.git("status")
    assert marker.exists(), "control failed: the fsmonitor marker never fired unpinned"
    marker.unlink()
    # pinned fetch + pull never fire it
    repo.upstream_commit()
    argv, env = repo.raw(FETCH)
    res = repo.run(argv, env)
    assert res.returncode == 0, res.stderr
    assert not marker.exists()
    argv, env = repo.raw(PULL)
    res = repo.run(argv, env)
    assert res.returncode == 0, res.stderr
    assert not marker.exists()
    assert repo.head() == repo.head(repo.other)
    # control for the pull path: unpinned pull runs it
    repo.upstream_commit()
    repo.git("pull", "--ff-only", "--no-rebase", "origin", "main")
    assert marker.exists(), "control failed: unpinned pull never ran fsmonitor"


def test_pinned_hooks_path_pre_push_fires_local_one_does_not(repo):
    pinned = repo.root / "pinned-hooks"
    local = repo.root / "local-hooks"
    pm, lm = repo.root / "pinned.marker", repo.root / "local.marker"
    _script(pinned / "pre-push", f'echo "$1 $2" > "{pm.as_posix()}"\ncat >> "{pm.as_posix()}"\n')
    _script(local / "pre-push", f'echo "$1 $2" > "{lm.as_posix()}"\ncat >> "{lm.as_posix()}"\n')
    repo.global_cfg("core.hooksPath", pinned.as_posix())
    req, entry = approve(repo, *PUSH)                       # approved against the pinned dir
    hooks_dir = entry["snapshot"]["hooks_dir"]
    # hostile local override appears after approval
    repo.git("config", "core.hooksPath", local.as_posix())
    v = git.verify(entry, req)
    assert v.ok is False and "core.hookspath" in v.reason.lower()      # refused by the allowlist
    # control: unpinned push (local config wins over global) fires the LOCAL hook only
    repo.commit()
    repo.git("push", "-q", "origin", "main")
    assert lm.exists() and not pm.exists(), "control failed: local hook should win unpinned"
    lm.unlink()
    # pinned push (the exact argv/env verify() would emit, built straight from the pins)
    repo.commit()
    tip = repo.head()
    argv, env = repo.raw(PUSH, hooks_dir=hooks_dir)
    assert argv[-1] == "refs/heads/main:refs/heads/main"
    res = repo.run(argv, env)
    assert res.returncode == 0, res.stderr
    assert pm.exists() and not lm.exists()
    lines = pm.read_text().splitlines()
    assert lines[0] == f"origin {repo.url}"
    fields = lines[1].split()
    assert fields[0] == "refs/heads/main" and fields[2] == "refs/heads/main" and fields[1] == tip
    assert repo.remote_head() == tip


def test_pinned_hooks_for_fetch_and_pull_ignore_local_hooks_path(repo):
    pinned = repo.root / "pinned-hooks"
    local = repo.root / "local-hooks"
    pm, lm = repo.root / "p.marker", repo.root / "l.marker"
    for d, m in ((pinned, pm), (local, lm)):
        _script(d / "reference-transaction", f'echo "$1" >> "{m.as_posix()}"\n')
        _script(d / "post-merge", f'echo merge >> "{m.as_posix()}"\n')
    repo.git("config", "core.hooksPath", local.as_posix())
    repo.upstream_commit()
    argv, env = repo.raw(PULL, hooks_dir=pinned.as_posix())
    res = repo.run(argv, env)
    assert res.returncode == 0, res.stderr
    assert pm.exists() and not lm.exists()


def _diverge(repo):
    repo.upstream_commit()
    repo.commit()


def test_pull_never_rebases_or_merges(repo):
    marker = repo.root / "rebase.marker"
    _script(repo.hooks / "pre-rebase", f'echo ran >> "{marker.as_posix()}"\nexit 1\n')
    repo.git("config", "pull.rebase", "true")
    _diverge(repo)
    before = repo.head()
    # control: a plain pull with pull.rebase=true tries to rebase
    repo.git("pull", "origin", "main", check=False)
    assert marker.exists(), "control failed: pre-rebase never fired for a plain pull"
    marker.unlink()
    repo.git("rebase", "--abort", check=False)
    assert repo.head() == before
    argv, env = repo.raw(PULL)
    assert "--ff-only" in argv and "--no-rebase" in argv
    res = repo.run(argv, env)
    assert res.returncode != 0
    assert "fast-forward" in (res.stderr + res.stdout).lower()
    assert not marker.exists()
    assert repo.head() == before                       # no merge commit either
    assert not (repo.work / ".git" / "rebase-merge").exists()


def test_pull_fast_forward_works_with_local_rebase_config(repo):
    marker = repo.root / "rebase.marker"
    _script(repo.hooks / "pre-rebase", f'echo ran >> "{marker.as_posix()}"\nexit 1\n')
    repo.git("config", "pull.rebase", "true")
    repo.upstream_commit()
    argv, env = repo.raw(PULL)
    res = repo.run(argv, env)
    assert res.returncode == 0, res.stderr
    assert repo.head() == repo.head(repo.other) and not marker.exists()


def test_argv_dashdash_blocks_option_like_remote_names(repo):
    """C8: a remote literally named like an option is only a name behind '--'."""
    assert git.match(Request(("git", "fetch", "-x"), repo.cwd, (), None)) is None
    argv, _ = repo.raw(FETCH)
    assert argv[-2:] == ["--", "origin"]


class _Deny401(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


def test_credential_helper_reset_hides_lower_helpers_behaviourally(repo, monkeypatch):
    """C2, behavioural: config queries cannot prove the reset, so run git against a
    loopback 401 server with marker-writing helper scripts (no `git credential`)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Deny401)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        base = f"http://127.0.0.1:{port}"
        marker = repo.root / "helpers.marker"

        def helper(name):
            return _script(repo.root / "h" / name,
                           f'echo {name} >> "{marker.as_posix()}"\ncat > /dev/null\n').as_posix()

        repo.global_cfg("credential.helper", helper("global"))
        repo.global_cfg(f"credential.{base}.helper", helper("globalurl"))
        repo.git("config", "credential.helper", helper("local"))
        repo.git("config", f"credential.{base}.helper", helper("localurl"))
        pinned = helper("pinned")
        monkeypatch.setattr(c.RELAXATIONS, "git_allowed_protocols", "file:https:http")
        target = f"{base}/r.git"

        def names():
            if not marker.exists():
                return set()
            out = set(marker.read_text().split())
            marker.unlink()
            return out

        repo.git("ls-remote", "--", target, check=False,
                 env=dict(os.environ, GIT_ALLOW_PROTOCOL="file:https:http", GIT_TERMINAL_PROMPT="0"))
        assert names() == {"global", "globalurl", "local", "localurl"}, "control failed"

        gp, dirs = repo.pin()
        for helpers, expected in (([git._escape_helper_path(pinned)], {"pinned"}), ([], set())):
            pairs = git.pin_pairs(repo.hooks.as_posix(), helpers)
            res = repo.run([gp.path, "ls-remote", "--", target], git.command_env(dirs, pairs))
            assert res.returncode != 0                      # 401, prompts disabled
            assert names() == expected
    finally:
        server.shutdown()
        server.server_close()
