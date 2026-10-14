"""Tests for vault_lib/profiles/kubectl.py (plan 2.4.0 section 5.3).

Headless.  Nothing here touches a cluster or the user's real kube config: every
run uses a scratch HOME, a scratch KUBECONFIG naming a fake server
(https://127.0.0.1:1) and a private STATE_DIR.  Tests that need the real kubectl
binary (the offline normaliser, ``config view``, the kuberc strict-decoding
signal) skip when it is not installed.
"""
import copy
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vault_lib.profiles import Request, Verdict  # noqa: E402
from vault_lib.profiles import _common as c  # noqa: E402
from vault_lib.profiles import kubectl as k  # noqa: E402
from vault_lib.profiles._common import ArgvRejected, ProfileRefusal  # noqa: E402

WIN = os.name == "nt"
HAVE_KUBECTL = shutil.which("kubectl") is not None
needs_kubectl = pytest.mark.skipif(not HAVE_KUBECTL, reason="kubectl is not installed")

EXEC_ABS = r"C:\tools\plug.exe" if WIN else "/usr/local/bin/plug"


def cmd(text):
    return ("kubectl",) + tuple(shlex.split(text))


# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

def parse(text):
    return k.parse_command(cmd(text))


def rejected(text):
    with pytest.raises(ArgvRejected):
        k.parse_command(cmd(text))


def test_kind_is_kubectl():
    assert k.kind == "kubectl"


@pytest.mark.parametrize("command", [
    (), ("kubectl",), ("git", "status"), ("kubectl", "config", "view"),
    ("kubectl", "exec", "-it", "x"), ("kubectl", "delete", "pod", "x"),
    ("kubectl", "evil", "x"), ("kubectl", "version"), ("kubectl", "rollout"),
    (r"C:\bin\kubectl.exe", "get", "pods"), ("./kubectl", "get", "pods"), ("kubectl2", "get", "pods"),
])
def test_not_mine_returns_none(command):
    if command[:1] in (("kubectl",),) and len(command) >= 2 and command[1] == "rollout":
        pytest.skip("rollout is claimed (then rejected) by the grammar")
    assert k.parse_command(command) is None


def test_exe_suffix_and_case_accepted():
    assert k.parse_command(("kubectl.exe", "get", "pods")) is not None
    assert k.parse_command(("KUBECTL.EXE", "get", "pods")) is not None


@pytest.mark.parametrize("text,args,ns,all_ns,cluster", [
    ("get pods", ("get", "pods"), None, False, False),
    ("get po -n team", ("get", "pods"), "team", False, False),
    ("get deploy nginx -n a", ("get", "deployments", "nginx"), "a", False, False),
    ("get pods -l app=web", ("get", "pods", "--selector=app=web"), None, False, False),
    ("get pods --selector=app==web,tier=db", ("get", "pods", "--selector=app==web,tier=db"),
     None, False, False),
    ("get pods -l example.com/app=x_1.y", ("get", "pods", "--selector=example.com/app=x_1.y"),
     None, False, False),
    ("get pods -l app=", ("get", "pods", "--selector=app="), None, False, False),
    ("get po --show-labels --no-headers -o name -l a=b",
     ("get", "pods", "--selector=a=b", "--output=name", "--no-headers", "--show-labels"),
     None, False, False),
    ("get svc -A", ("get", "services"), None, True, False),
    ("get nodes", ("get", "nodes"), None, False, True),
    ("get ns", ("get", "namespaces"), None, False, True),
    ("get namespaces kube-system", ("get", "namespaces", "kube-system"), None, False, True),
    ("get cm my.config", ("get", "configmaps", "my.config"), None, False, False),
    ("get netpol -o yaml", ("get", "networkpolicies", "--output=yaml"), None, False, False),
    ("get hpa -o json", ("get", "horizontalpodautoscalers", "--output=json"), None, False, False),
    ("get ing -o wide", ("get", "ingresses", "--output=wide"), None, False, False),
    ("get endpointslices", ("get", "endpointslices"), None, False, False),
    ("get pvc", ("get", "persistentvolumeclaims"), None, False, False),
    ("describe svc web -n a", ("describe", "services", "web"), "a", False, False),
    ("describe pods -l app=x", ("describe", "pods", "--selector=app=x"), None, False, False),
])
def test_get_describe_accept(text, args, ns, all_ns, cluster):
    p = parse(text)
    assert p.args == args and p.namespace == ns
    assert p.all_namespaces is all_ns and p.cluster_scoped is cluster
    assert p.access == "read" and p.file is None


@pytest.mark.parametrize("kind_word,plural", [
    ("pods", "pods"), ("pod", "pods"), ("po", "pods"), ("deploy", "deployments"),
    ("rs", "replicasets"), ("sts", "statefulsets"), ("ds", "daemonsets"), ("job", "jobs"),
    ("cj", "cronjobs"), ("svc", "services"), ("ep", "endpoints"), ("ev", "events"),
    ("cm", "configmaps"), ("ing", "ingresses"), ("hpa", "horizontalpodautoscalers"),
    ("netpol", "networkpolicies"), ("pvc", "persistentvolumeclaims"), ("no", "nodes"),
])
def test_kind_aliases(kind_word, plural):
    assert parse(f"get {kind_word}").args == ("get", plural)


@pytest.mark.parametrize("text", [
    "get", "get secrets", "get secret", "get secret foo", "get secrets.v1.", "get pods.v1.",
    "get pods.v1.apps", "get pods,secrets", "get pods,svc", "get pod/foo", "get all",
    "get sa", "get serviceaccounts", "get clusterroles", "get roles", "get rolebindings",
    "get clusterrolebindings", "get crd", "get customresourcedefinitions", "get csr",
    "get mutatingwebhookconfigurations", "get validatingwebhookconfigurations",
    "get storageclass", "get pv", "get PODS", "get Pods", "get pods a b", "get pods foo bar",
    "get pods Foo", "get pods foo_bar", "get pods foo.", "get pods .foo", "get pods " + "a" * 254,
    "get pods -n Foo", "get pods -n foo_bar", "get pods -n a.b", "get pods -n " + "a" * 64,
    "get pods -n -foo", "get pods -n", "get pods -n=foo", "get pods -nfoo", "get pods --namespace foo",
    "get pods --namespace=", "get pods --namespace",
    "get pods -o=name", "get pods -oname", "get pods -lapp=x", "get pods -l=app=x",
    "get pods -Afoo", "get pods -A -n foo", "get pods foo -A", "get pods foo -l a=b",
    "get pods -l app!=x", "get pods -l app", "get pods -l !app", "get pods -l 'app in (a,b)'",
    "get pods -l 'a=b,c'", "get pods -l a=b,", "get pods -l a=b b=c", "get pods -l " + "a=b," * 200 + "c=d",
    "get pods -o jsonpath={.items}", "get pods -o custom-columns=A:.x", "get pods -o go-template=x",
    "get pods -o template=x", "get pods -o kyaml", "get pods -o JSON", "get pods -o wide -o name",
    "get pods -A -A", "get pods -n a -n a", "get pods --no-headers --no-headers",
    "get pods --raw=/api", "get --raw=/api", "get pods -w", "get pods --watch", "get pods --watch-only",
    "get pods --template=x", "get pods -f x.yaml", "get pods -k dir", "get pods -R",
    "get pods --field-selector=x=y", "get pods --chunk-size=1", "get pods --sort-by=.x",
    "get pods --show-managed-fields", "get pods --subresource=status", "get pods --server-print=false",
    "get pods -L app", "get pods --ignore-not-found", "get pods --show-kind", "get pods --output-watch-events",
    "describe pods -A", "describe pods --show-events", "describe secrets", "describe pods -o yaml",
    "get pods --", "get pods -- --foo", "get pods @file", "get pods -l @file", "get pods ''",
    "get pods --namesp=foo", "get pods --all-names",
])
def test_get_describe_reject(text):
    rejected(text)


@pytest.mark.parametrize("bad", ["a\x00b", "a\nb", "a\rb", "a\u202eb", "a\u200bb"])
def test_unsafe_text_rejected(bad):
    with pytest.raises(ArgvRejected):
        k.parse_command(("kubectl", "get", "pods", bad))
    with pytest.raises(ArgvRejected):
        k.parse_command(("kubectl", "get", "pods", "-n", bad))


def test_non_string_token_rejected():
    with pytest.raises(ArgvRejected):
        k.parse_command(("kubectl", "get", "pods", 5))


REJECTED_GLOBALS = [
    "--kubeconfig=/x", "--kubeconfig /x", "--context=other", "--cluster=c", "--user=u",
    "--server=https://x", "-s https://x", "-s=https://x", "--token=abc", "--username=u",
    "--password=p", "--as=root", "--as-group=g", "--as-uid=1", "--as-user-extra=a=b",
    "--certificate-authority=/x", "--client-certificate=/x", "--client-key=/x",
    "--insecure-skip-tls-verify", "--insecure-skip-tls-verify=true", "--insecure-skip-tls-verify=false",
    "--tls-server-name=x", "--proxy-url=http://x", "--profile=cpu", "--profile-output=/x",
    "--cache-dir=/x", "--kuberc=/x", "--request-timeout=1s", "--disable-compression",
    "--match-server-version", "--warnings-as-errors", "-v=9", "-v 9", "-v9", "--v=9",
    "--vmodule=x=1", "--log-flush-frequency=1s", "--log-dir=/x", "--alsologtostderr",
    "--add-dir-header", "-h", "--help", "--version", "--client-certificate-data=x",
]


@pytest.mark.parametrize("command", [
    ("kubectl", "--server=https://attacker.example", "get", "pods", "-n", "dev"),
    ("kubectl", "--kubeconfig=x", "get", "pods"), ("kubectl", "-s", "https://x", "get", "pods"),
    ("kubectl", "--context=evil", "logs", "web-0"), ("kubectl", "-n", "dev", "get", "pods"),
])
def test_global_flag_before_subcommand_never_parses(command):
    # B7: the leading-flag form is not "ours"; it must never yield a Parsed (and so never an
    # offer or an auto-allow) - the normal dialog applies.
    assert not isinstance(k.parse_command(command), k.Parsed)


@pytest.mark.parametrize("flag", REJECTED_GLOBALS)
@pytest.mark.parametrize("base", ["get pods", "describe pods", "logs web-0",
                                  "rollout status deploy/web", "apply -f m.yaml"])
def test_global_flags_rejected_everywhere(flag, base):
    rejected(f"{base} {flag}")


@pytest.mark.parametrize("text,args,ns", [
    ("logs web-0", ("logs", "web-0", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs web-0 -n team", ("logs", "web-0", "--tail=5000", "--limit-bytes=10485760"), "team"),
    ("logs deploy/web", ("logs", "deployment/web", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs pod/a.b", ("logs", "pod/a.b", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs rs/x", ("logs", "replicaset/x", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs sts/x", ("logs", "statefulset/x", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs ds/x", ("logs", "daemonset/x", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs job/x", ("logs", "job/x", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs web-0 -c app --tail=10",
     ("logs", "web-0", "--container=app", "--tail=10", "--limit-bytes=10485760"), None),
    ("logs web-0 --tail=0", ("logs", "web-0", "--tail=0", "--limit-bytes=10485760"), None),
    ("logs web-0 --tail=5000 --limit-bytes=10485760",
     ("logs", "web-0", "--tail=5000", "--limit-bytes=10485760"), None),
    ("logs web-0 --limit-bytes=1", ("logs", "web-0", "--limit-bytes=1", "--tail=5000"), None),
    ("logs web-0 --since=1h --previous --timestamps --all-containers",
     ("logs", "web-0", "--since=1h", "--previous", "--timestamps", "--all-containers",
      "--tail=5000", "--limit-bytes=10485760"), None),
])
def test_logs_accept_and_caps_injected(text, args, ns):
    p = parse(text)
    assert p.args == args and p.namespace == ns and p.wall_clock == k.WALL_CLOCK["logs"]


@pytest.mark.parametrize("text", [
    "logs", "logs a b", "logs svc/web", "logs secret/x", "logs foo/bar/baz", "logs pod/a/b",
    "logs pod/", "logs pod/Foo", "logs /x", "logs Foo", "logs web-0 -f", "logs web-0 --follow",
    "logs web-0 --prefix", "logs web-0 --all-pods", "logs -l app=x", "logs web-0 -l app=x",
    "logs web-0 --ignore-errors", "logs web-0 --max-log-requests=1",
    "logs web-0 --pod-running-timeout=1s", "logs web-0 --since-time=2024-01-01T00:00:00Z",
    "logs web-0 --tail=5001", "logs web-0 --tail=9999", "logs web-0 --tail=-1", "logs web-0 --tail=abc",
    "logs web-0 --tail=10000", "logs web-0 --tail", "logs web-0 --tail 5",
    "logs web-0 --limit-bytes=0", "logs web-0 --limit-bytes=10485761", "logs web-0 --limit-bytes=-1",
    "logs web-0 --limit-bytes=123456789", "logs web-0 --since=0s", "logs web-0 --since=5",
    "logs web-0 --since=1d", "logs web-0 -c Foo", "logs web-0 -c", "logs web-0 -c=app",
    "logs web-0 -capp", "logs web-0 --container app", "logs web-0 --tail=1 --tail=2",
    "logs web-0 -c a -c b", "logs web-0 -A", "logs web-0 -o json",
])
def test_logs_reject(text):
    rejected(text)


@pytest.mark.parametrize("text,seconds", [
    ("rollout status deployment/web", 300), ("rollout status deploy/web", 300),
    ("rollout status sts/web --timeout=60s", 60), ("rollout status ds/web --timeout=2m", 120),
    ("rollout status deployment/web --timeout=300s", 300),
    ("rollout status deployment/web --timeout=1h", 300),      # capped, not refused
    ("rollout status deployment/web --timeout=0s", 300),      # 0 = wait forever -> capped
    ("rollout status deployment/web --timeout=301s", 300),
])
def test_rollout_status_timeout_always_capped(text, seconds):
    p = parse(text)
    prefix = text.split()[2].split("/")[0]
    full = {"deploy": "deployment", "sts": "statefulset", "ds": "daemonset"}.get(prefix, prefix)
    assert p.args == ("rollout", "status", f"{full}/web", f"--timeout={seconds}s")
    assert p.wall_clock == seconds + k.ROLLOUT_WALL_SLACK
    assert p.sub == "rollout" and p.access == "read"


@pytest.mark.parametrize("text", [
    "rollout", "rollout status", "rollout status web", "rollout status pod/x",
    "rollout status svc/x", "rollout status job/x", "rollout status deployment web",
    "rollout status deployment/Web", "rollout status deployment/", "rollout status /x",
    "rollout restart deployment/x", "rollout undo deployment/x", "rollout history deployment/x",
    "rollout pause deployment/x", "rollout resume deployment/x",
    "rollout status deployment/x --revision=1", "rollout status deployment/x -w",
    "rollout status deployment/x --watch=false", "rollout status deployment/x --timeout=10",
    "rollout status deployment/x --timeout 10s", "rollout status deployment/x --timeout=-5s",
    "rollout status deployment/x --timeout=1d", "rollout status deployment/x --timeout=1s --timeout=2s",
    "rollout status deployment/x -l a=b", "rollout status deployment/x -A",
])
def test_rollout_reject(text):
    rejected(text)


def test_rollout_status_namespace():
    assert parse("rollout status deployment/web -n team").namespace == "team"


def test_apply_accept():
    p = parse("apply -f m.yaml")
    assert (p.access, p.sub, p.args, p.file, p.namespace) == (
        "apply", "apply", ("apply", "-f", "-"), "m.yaml", None)
    assert p.wall_clock == k.WALL_CLOCK["apply"]
    p = parse("apply --filename=sub/m.yaml -n team --dry-run=server --validate=strict")
    assert p.args == ("apply", "-f", "-", "--dry-run=server", "--validate=strict")
    assert p.file == "sub/m.yaml" and p.namespace == "team"
    assert parse("apply -f m.json --dry-run=client").args == ("apply", "-f", "-", "--dry-run=client")


@pytest.mark.parametrize("text", [
    "apply", "apply -n team", "apply -k dir", "apply -f m.yaml -k dir", "apply -f m.yaml --prune",
    "apply -f m.yaml --force", "apply -f m.yaml --server-side", "apply -f m.yaml --force-conflicts",
    "apply -f m.yaml --overwrite", "apply -f m.yaml --applyset=x", "apply -f m.yaml -R",
    "apply -f m.yaml --recursive", "apply -f m.yaml --all", "apply -f m.yaml -l a=b",
    "apply -f m.yaml --selector=a=b", "apply -f m.yaml -o json", "apply -f m.yaml --dry-run=none",
    "apply -f m.yaml --dry-run", "apply -f m.yaml --validate=false", "apply -f m.yaml --validate=ignore",
    "apply -f m.yaml --validate=true", "apply -f m.yaml --cascade=foreground", "apply -f m.yaml --wait",
    "apply -f m.yaml -f n.yaml", "apply -f m.yaml extra", "apply m.yaml",
    "apply -f -", "apply -f http://x/m.yaml", "apply -f https://x/m.yaml", "apply -f file:///x.yaml",
    "apply -f ftp://x/m.yaml", "apply -f \\\\\\\\host\\\\share\\\\m.yaml", "apply -f //host/share/m.yaml",
    "apply -f=m.yaml", "apply -fm.yaml", "apply --filename m.yaml", "apply -f @m.yaml",
    "apply -f m.yaml -A",
])
def test_apply_reject(text):
    rejected(text)


def test_parsed_render_namespace_flags():
    p = parse("get pods -A")
    assert p.render(None) == ["get", "pods", "--all-namespaces"]
    p = parse("get pods -n a -o name")
    assert p.render("pinned") == ["get", "pods", "--output=name", "--namespace=pinned"]
    assert p.render(None) == ["get", "pods", "--output=name"]


# ---------------------------------------------------------------------------
# Sanitised kubeconfig (pure)
# ---------------------------------------------------------------------------

def base_kc(**over):
    data = {
        "apiVersion": "v1", "kind": "Config", "preferences": {},
        "clusters": [{"name": "cl", "cluster": {"server": "https://k8s.example.test:6443",
                                                "certificate-authority-data": "Q0E="}}],
        "users": [{"name": "u", "user": {"token": "tok-abc"}}],
        "contexts": [{"name": "ctx1", "context": {"cluster": "cl", "user": "u",
                                                  "namespace": "team"}}],
        "current-context": "ctx1",
    }
    data.update(over)
    return data


def with_cluster(**kv):
    d = base_kc()
    d["clusters"][0]["cluster"].update(kv)
    return d


def with_user(replace=None, **kv):
    d = base_kc()
    if replace is not None:
        d["users"][0]["user"] = replace
    d["users"][0]["user"].update(kv)
    return d


def with_context(**kv):
    d = base_kc()
    d["contexts"][0]["context"].update(kv)
    return d


def exec_user(**over):
    ex = {"apiVersion": "client.authentication.k8s.io/v1", "command": EXEC_ABS,
          "args": ["get-token", "--cluster", "x"], "env": None, "interactiveMode": "Never",
          "provideClusterInfo": False}
    ex.update(over)
    return {"exec": ex}


def test_sanitize_accepts_token_kubeconfig():
    san = k.sanitize_kubeconfig(base_kc())
    assert (san.context, san.namespace, san.auth, san.exec) == ("ctx1", "team", "token", None)
    assert san.server == "https://k8s.example.test:6443"
    assert json.loads(san.text()) == san.clean
    assert san.clean["current-context"] == "ctx1"
    assert san.text().endswith("\n")


def test_sanitize_is_rebuilt_from_a_whitelist_and_idempotent():
    d = base_kc()
    d["users"][0]["user"]["client-certificate-data"] = "Y2VydA=="
    d["users"][0]["user"].pop("token")
    d["users"][0]["user"]["client-key-data"] = "a2V5"
    d["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = False
    san = k.sanitize_kubeconfig(d)
    assert san.auth == "client-certificate"
    assert "insecure-skip-tls-verify" not in san.clean["clusters"][0]["cluster"]
    again = k.sanitize_kubeconfig(json.loads(san.text()))
    assert again.text() == san.text()


def test_sanitize_no_auth_and_no_namespace():
    d = with_user(replace={})
    del d["contexts"][0]["context"]["namespace"]
    san = k.sanitize_kubeconfig(d)
    assert san.auth == "none" and san.namespace is None
    assert "namespace" not in san.clean["contexts"][0]["context"]


@pytest.mark.parametrize("make,why", [
    (lambda: [], "not a mapping"),
    (lambda: base_kc(clusters=[]), "zero clusters"),
    (lambda: base_kc(clusters=base_kc()["clusters"] * 2), "two clusters"),
    (lambda: base_kc(users=base_kc()["users"] * 2), "two users"),
    (lambda: base_kc(contexts=base_kc()["contexts"] * 2), "two contexts"),
    (lambda: base_kc(contexts=None), "no contexts"),
    (lambda: {**base_kc(), "extra-top": 1}, "unknown top-level key"),
    (lambda: {**base_kc(), "extensions": [{"name": "x"}]}, "extensions"),
    (lambda: base_kc(preferences={"colors": True}), "non-empty preferences"),
    (lambda: base_kc(**{"current-context": "other"}), "current-context differs"),
    (lambda: with_cluster(**{"insecure-skip-tls-verify": True}), "insecure-skip-tls-verify"),
    (lambda: with_cluster(**{"proxy-url": "http://proxy:3128"}), "proxy-url"),
    (lambda: with_cluster(**{"tls-server-name": "evil.test"}), "tls-server-name"),
    (lambda: with_cluster(**{"certificate-authority": "/etc/ca.crt"}), "CA file path"),
    (lambda: with_cluster(**{"disable-compression": True}), "disable-compression"),
    (lambda: with_cluster(extensions=[]), "cluster extensions"),
    (lambda: with_cluster(server="http://k8s.example.test"), "http server"),
    (lambda: with_cluster(server="http://127.0.0.1:8001"), "http loopback without relaxation"),
    (lambda: with_cluster(server="ftp://k8s.example.test"), "ftp server"),
    (lambda: with_cluster(server="k8s.example.test"), "no scheme"),
    (lambda: with_cluster(server="https://user:pw@k8s.example.test"), "userinfo"),
    (lambda: with_cluster(server="https://k8s.example.test/?x=1"), "query"),
    (lambda: with_cluster(server="https://k8s.example.test/#frag"), "fragment"),
    (lambda: with_cluster(server="https://k8s example.test"), "space"),
    (lambda: with_cluster(server="https://"), "no host"),
    (lambda: with_cluster(server="https://k8s.example.test:99999"), "bad port"),
    (lambda: with_cluster(server=5), "non-str server"),
    (lambda: with_cluster(**{"certificate-authority-data": 5}), "bad CA data"),
    (lambda: with_user(**{"auth-provider": {"name": "gcp"}}), "auth-provider"),
    (lambda: with_user(tokenFile="/var/run/token"), "tokenFile"),
    (lambda: with_user(username="admin", password="pw"), "basic auth"),
    (lambda: with_user(**{"client-certificate": "/x", "client-key": "/y"}), "cert files"),
    (lambda: with_user(**{"as": "root"}), "impersonation"),
    (lambda: with_user(**{"as-groups": ["g"]}), "impersonation groups"),
    (lambda: with_user(**{"as-user-extra": {"a": ["b"]}}), "impersonation extra"),
    (lambda: with_user(**{"client-certificate-data": "Y2VydA=="}), "cert without key"),
    (lambda: with_user(token=""), "empty token"),
    (lambda: with_user(token=7), "non-str token"),
    (lambda: with_user(token="a\nb"), "token with newline"),
    (lambda: with_context(namespace="Bad_NS"), "bad namespace"),
    (lambda: with_context(namespace="a" * 64), "long namespace"),
    (lambda: with_context(extensions=[]), "context extensions"),
    (lambda: with_context(cluster="other"), "context points at another cluster"),
    (lambda: with_context(user="other"), "context points at another user"),
    (lambda: {**base_kc(), "contexts": [{"name": "-ctx", "context": {"cluster": "cl", "user": "u"}}],
              "current-context": "-ctx"}, "context name starts with -"),
    (lambda: {**base_kc(), "users": [{"name": "u", "user": {"token": "t"}, "extra": 1}]},
     "extra item field"),
    (lambda: {**base_kc(), "users": [{"name": "u", "user": None}]}, "empty user"),
])
def test_sanitize_refuses(make, why):
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(make())


def test_sanitize_http_loopback_needs_relaxation(monkeypatch):
    d = with_cluster(server="http://127.0.0.1:18765")
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(d)
    monkeypatch.setattr(c.RELAXATIONS, "kubectl_allow_http_loopback", True)
    assert k.sanitize_kubeconfig(d).server == "http://127.0.0.1:18765"
    assert k.sanitize_kubeconfig(with_cluster(server="http://localhost:1")).server
    assert k.sanitize_kubeconfig(with_cluster(server="http://[::1]:1")).server
    with pytest.raises(k.KubeconfigRefused):                     # not loopback: still refused
        k.sanitize_kubeconfig(with_cluster(server="http://10.0.0.1:8001"))
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(with_cluster(server="http://example.test"))


def test_sanitize_exec_accepted_absolute_and_normalised():
    san = k.sanitize_kubeconfig(with_user(replace=exec_user()))
    assert san.auth == "exec"
    assert san.exec["command"] == os.path.normpath(EXEC_ABS)
    assert san.exec["args"] == ["get-token", "--cluster", "x"]
    assert san.exec["interactiveMode"] == "Never"
    assert san.clean["users"][0]["user"]["exec"]["command"] == san.exec["command"]
    # unknown optional fields are dropped, env: null / args: null tolerated
    san = k.sanitize_kubeconfig(with_user(replace=exec_user(args=None, installHint="get it")))
    assert san.exec["args"] == []
    assert "installHint" not in san.clean["users"][0]["user"]["exec"]
    san = k.sanitize_kubeconfig(with_user(replace=exec_user(provideClusterInfo=True)))
    assert san.exec["provideClusterInfo"] is True


@pytest.mark.parametrize("over", [
    {"command": "plug"}, {"command": "plug.exe"}, {"command": "./plug"}, {"command": "bin/plug"},
    {"command": ""}, {"command": None}, {"command": 5}, {"command": "/x/y\nz"},
    {"env": [{"name": "A", "value": "B"}]}, {"apiVersion": "v1"}, {"apiVersion": None},
    {"args": "get-token"}, {"args": ["ok", 5]}, {"args": ["bad\narg"]},
    {"interactiveMode": "Always"}, {"unknownField": 1},
])
def test_sanitize_exec_refused(over):
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(with_user(replace=exec_user(**over)))


def test_sanitize_exec_other_forms_refused():
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(with_user(replace=exec_user(), token="t"))     # exec + token
    with pytest.raises(k.KubeconfigRefused):
        k.sanitize_kubeconfig(with_user(replace={"exec": "plug"}))
    with pytest.raises(k.KubeconfigRefused):                                  # below kubectl 1.35
        k.sanitize_kubeconfig(with_user(replace=exec_user()), allow_exec=False)
    # allow_exec=False does not hurt non-exec users
    assert k.sanitize_kubeconfig(base_kc(), allow_exec=False).auth == "token"


@pytest.mark.skipif(not WIN, reason="Windows path forms")
@pytest.mark.parametrize("command,ok", [
    (r"C:\tools\plug.exe", True), ("C:/tools/plug.exe", True), (r"c:\Tools\..\tools\plug.EXE", True),
    (r"\\host\share\plug.exe", False), ("//host/share/plug.exe", False), (r"C:\tools\plug.cmd", False),
    (r"C:\tools\plug.bat", False), (r"C:\tools\plug", False), (r"\tools\plug.exe", False),
    (r"C:plug.exe", False), (r"C:\tools\pl\u00fcg.exe", True), ("C:\\tools\\plug\U0001F600.exe", False),
])
def test_normalise_exec_command_windows(command, ok):
    if ok:
        out = k.normalise_exec_command(command)
        assert "/" not in out and out.lower().endswith(".exe")
        assert out == os.path.normpath(command)
    else:
        with pytest.raises(k.KubeconfigRefused):
            k.normalise_exec_command(command)


@pytest.mark.skipif(WIN, reason="POSIX path forms")
@pytest.mark.parametrize("command,ok", [("/usr/bin/plug", True), ("/usr/bin/../bin/plug", True),
                                        ("plug", False), ("./plug", False), ("", False)])
def test_normalise_exec_command_posix(command, ok):
    if ok:
        assert k.normalise_exec_command(command) == os.path.normpath(command)
    else:
        with pytest.raises(k.KubeconfigRefused):
            k.normalise_exec_command(command)


# ---------------------------------------------------------------------------
# kuberc template
# ---------------------------------------------------------------------------

HEAD = "apiVersion: kubectl.config.k8s.io/v1beta1\nkind: Preference\n"


def test_kuberc_denyall_byte_exact():
    assert k.build_kuberc(None) == HEAD + "credentialPluginPolicy: DenyAll\n"


def test_kuberc_allowlist_byte_exact():
    text = k.build_kuberc(r"C:\tools\plug.exe")
    assert text == (HEAD + "credentialPluginPolicy: Allowlist\n"
                    "credentialPluginAllowlist:\n"
                    "- command: \"C:\\\\tools\\\\plug.exe\"\n")
    assert text.encode("ascii")                     # pure ASCII, no BOM
    assert k.build_kuberc("/usr/bin/plug") == (HEAD + "credentialPluginPolicy: Allowlist\n"
                                               "credentialPluginAllowlist:\n"
                                               "- command: \"/usr/bin/plug\"\n")


def test_kuberc_escapes_quotes_and_non_ascii():
    text = k.build_kuberc('/a"b/\u00fc')
    assert text.endswith('- command: "/a\\"b/\\u00fc"\n')


@pytest.mark.parametrize("bad", ["/a\nb", "/a\u202eb", "/a\U0001F600"])
def test_kuberc_refuses_odd_paths(bad):
    with pytest.raises(ProfileRefusal):
        k.build_kuberc(bad)


def test_stderr_problem():
    assert k.stderr_problem("E1 kuberc: ignoring strict decoding error: unknown field") is not None
    assert k.stderr_problem("KUBERC: IGNORING STRICT DECODING ERROR") is not None
    assert k.stderr_problem("Error from server (NotFound): pods \"x\" not found") is None
    assert k.stderr_problem("") is None and k.stderr_problem(None) is None
    assert k.stderr_problem(b"ignoring strict decoding") is None     # only text is judged
    assert "ignoring strict decoding" in k.STDERR_FATAL_MARKERS


# ---------------------------------------------------------------------------
# Object policy (pure, on normalised JSON)
# ---------------------------------------------------------------------------

def deployment(**spec_pod):
    pod = {"containers": [{"name": "c", "image": "nginx"}]}
    pod.update(spec_pod)
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
            "spec": {"replicas": 1, "template": {"spec": pod}}}


def pod_doc(containers=None, **pod_spec):
    spec = {"containers": containers or [{"name": "c", "image": "x"}]}
    spec.update(pod_spec)
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": spec}


def problems(*docs, namespace="team"):
    return k.check_manifest(list(docs), namespace)


def test_policy_allows_plain_workloads():
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cfg"}, "data": {"a": "b"}}
    svc = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "s", "namespace": "team"},
           "spec": {"ports": [{"port": 80}]}}
    cron = {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"generateName": "x-"},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [
                {"name": "c", "image": "x", "securityContext": {"privileged": False,
                                                                   "allowPrivilegeEscalation": False}}],
                "serviceAccountName": "default", "hostNetwork": False,
                "volumes": [{"name": "v", "emptyDir": {}}, {"name": "w", "configMap": {"name": "cfg"}}]}}}}}}
    assert problems(cm, svc, cron, deployment(), pod_doc()) == []


@pytest.mark.parametrize("doc,needle", [
    ({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}}, "Secret"),
    ({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "s"}}, "ServiceAccount"),
    ({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "r"}}, "Role"),
    ({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "r"}}, "RoleBinding"),
    ({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "r"}}, "ClusterRole"),
    ({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "r"}},
     "ClusterRoleBinding"),
    ({"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": "a.b"}},
     "CustomResourceDefinition"),
    ({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration",
      "metadata": {"name": "w"}}, "Webhook"),
    ({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
      "metadata": {"name": "w"}}, "Webhook"),
    ({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}, "Namespace"),
    ({"apiVersion": "v1", "kind": "Node", "metadata": {"name": "n"}}, "Node"),
    ({"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "n"}}, "PersistentVolume"),
    ({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "n"}}, "StorageClass"),
    ({"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest", "metadata": {"name": "n"}},
     "CertificateSigningRequest"),
    ({"apiVersion": "example.com/v1", "kind": "Widget", "metadata": {"name": "w"}}, "not in the allowed kinds"),
    ({"apiVersion": "v1", "kind": "Deployment", "metadata": {"name": "w"}}, "not in the allowed kinds"),
    ({"apiVersion": "apps/v1beta1", "kind": "Deployment", "metadata": {"name": "w"}}, "not in the allowed kinds"),
    ({"kind": "ConfigMap", "metadata": {"name": "w"}}, "missing apiVersion"),
    ({"apiVersion": "v1", "metadata": {"name": "w"}}, "missing apiVersion"),
    ({"apiVersion": "v1", "kind": "ConfigMap"}, "missing metadata"),
    ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {}}, "missing metadata.name"),
    ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "Bad_Name"}}, "valid Kubernetes name"),
    ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a" * 254}}, "valid Kubernetes name"),
    ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "w", "namespace": "kube-system"}},
     "approved namespace"),
    ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "w", "namespace": ""}},
     "approved namespace"),
])
def test_policy_denies_objects(doc, needle):
    found = problems(doc)
    assert found and needle in " ".join(found)


@pytest.mark.parametrize("pod,needle", [
    (dict(containers=[{"name": "c", "image": "x", "securityContext": {"privileged": True}}]), "privileged"),
    (dict(containers=[{"name": "c", "image": "x", "securityContext": {"privileged": "yes"}}]), "privileged"),
    (dict(containers=[{"name": "c", "image": "x", "securityContext": {"allowPrivilegeEscalation": True}}]),
     "allowPrivilegeEscalation"),
    (dict(initContainers=[{"name": "i", "image": "x", "securityContext": {"privileged": True}}]), "privileged"),
    (dict(hostNetwork=True), "hostNetwork"), (dict(hostPID=True), "hostPID"), (dict(hostIPC=True), "hostIPC"),
    (dict(containers=[{"name": "c", "image": "x", "ports": [{"containerPort": 80, "hostPort": 80}]}]),
     "hostPort"),
    (dict(volumes=[{"name": "v", "hostPath": {"path": "/"}}]), "hostPath"),
    (dict(volumes=[{"name": "v", "secret": {"secretName": "s"}}]), "secret"),
    (dict(volumes=[{"name": "v", "projected": {"sources": []}}]), "projected"),
    (dict(volumes=[{"name": "v", "nfs": {"server": "x", "path": "/"}}]), "nfs"),
    (dict(volumes=[{"name": "v", "csi": {"driver": "x"}}]), "csi"),
    (dict(volumes=[{"name": "v", "ephemeral": {}}]), "ephemeral"),
    (dict(volumes=["oops"]), "malformed"),
    (dict(containers=[{"name": "c", "image": "x",
                       "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]), "capabilities"),
    (dict(containers=[{"name": "c", "image": "x", "envFrom": [{"secretRef": {"name": "s"}}]}]), "secretRef"),
    (dict(containers=[{"name": "c", "image": "x", "env": [{"name": "A", "valueFrom": {
        "secretKeyRef": {"name": "s", "key": "k"}}}]}]), "secretKeyRef"),
    (dict(serviceAccountName="admin"), "service account"),
    (dict(serviceAccount="admin"), "service account"),
    (dict(automountServiceAccountToken=True), "automountServiceAccountToken"),
    (dict(automountServiceAccountToken="true"), "automountServiceAccountToken"),
    (dict(imagePullSecrets=[{"name": "registry-creds"}]), "imagePullSecrets"),
])
def test_policy_denies_pod_spec_features(pod, needle):
    containers = pod.pop("containers", None)
    for wrapper in (pod_doc(containers, **pod), deployment(**({"containers": containers} if containers else {}),
                                                           **pod)):
        found = problems(wrapper)
        assert found and needle.lower() in " ".join(found).lower(), found


def test_policy_automount_token_may_be_off_but_never_forced_on():
    # B8: a pod-level true overrides a hardened ServiceAccount's automount=false; off/absent is fine.
    assert problems(pod_doc(automountServiceAccountToken=False)) == []
    assert problems(pod_doc(automountServiceAccountToken=None)) == []
    assert problems(pod_doc()) == []


def test_policy_empty_image_pull_secrets_references_nothing():
    assert problems(pod_doc(imagePullSecrets=[])) == []
    assert problems(pod_doc(imagePullSecrets=None)) == []
    cron = {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "x"},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "c", "image": "x"}],
                "imagePullSecrets": [{"name": "registry-creds"}]}}}}}}
    assert "imagePullSecrets" in " ".join(problems(cron))


def test_policy_capabilities_drop_is_fine_and_ports_without_hostport():
    ok = pod_doc([{"name": "c", "image": "x",
                   "securityContext": {"capabilities": {"drop": ["ALL"]}, "privileged": None},
                   "ports": [{"containerPort": 80, "hostPort": 0}]}])
    assert problems(ok) == []


def test_policy_lists_and_counts():
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "ok"}}
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}}
    assert problems({"apiVersion": "v1", "kind": "List", "items": [cm, secret]})
    assert problems({"apiVersion": "v1", "kind": "List", "items": [cm, cm]}) == []
    nested = {"apiVersion": "v1", "kind": "List", "items": [{"apiVersion": "v1", "kind": "List",
                                                              "items": [secret]}]}
    assert problems(nested)
    with pytest.raises(k.ManifestRefused):
        problems({"apiVersion": "v1", "kind": "List", "items": [cm, "x"]})
    assert problems() == ["the manifest contains no objects"]
    many = [dict(cm, metadata={"name": f"c{i}"}) for i in range(k.MANIFEST_MAX_OBJECTS + 1)]
    assert "more than" in problems(*many)[0]
    assert problems(*many[:k.MANIFEST_MAX_OBJECTS]) == []


def test_summarize_objects():
    docs = [{"kind": "ConfigMap", "metadata": {"name": "a"}},
            {"kind": "List", "items": [{"kind": "Pod", "metadata": {"generateName": "g-"}}]}]
    assert k.summarize_objects(docs) == ["ConfigMap/a", "Pod/g-"]


def test_parse_json_stream():
    text = json.dumps({"a": 1}, indent=2) + "\n" + json.dumps({"b": [1, 2]}, indent=2) + "\n"
    assert k.parse_json_stream(text) == [{"a": 1}, {"b": [1, 2]}]
    assert k.parse_json_stream("") == [] and k.parse_json_stream(" \n") == []
    for bad in ("{", "[1]", "{} x", '"str"', "{}{"):
        with pytest.raises(k.ManifestRefused):
            k.parse_json_stream(bad)
    with pytest.raises(k.ManifestRefused):
        k.parse_json_stream("{}" * (k.MANIFEST_MAX_OBJECTS * 2 + 1))


def test_resolve_manifest(tmp_path):
    (tmp_path / "ok.yaml").write_text("a: b\n")
    (tmp_path / "ok.JSON").write_text("{}")
    (tmp_path / "x.txt").write_text("a: b\n")
    (tmp_path / "noext").write_text("a: b\n")
    (tmp_path / "d.yaml").mkdir()
    real, err = k.resolve_manifest("ok.yaml", str(tmp_path))
    assert err is None and real == os.path.normcase(os.path.realpath(tmp_path / "ok.yaml"))
    assert k.resolve_manifest(str(tmp_path / "ok.yaml"), "elsewhere")[0] == real
    assert k.resolve_manifest("ok.JSON", str(tmp_path))[1] is None
    for bad in ("x.txt", "noext", "d.yaml", "missing.yaml", "-", "https://x/ok.yaml", "//h/s/ok.yaml",
                "\\\\h\\s\\ok.yaml", "ok\n.yaml"):
        assert k.resolve_manifest(bad, str(tmp_path))[0] is None, bad
    assert k.resolve_manifest("../" + tmp_path.name + "/ok.yaml", str(tmp_path))[0] == real  # normalised


def test_resolve_manifest_refuses_links(tmp_path):
    target = tmp_path / "t.yaml"
    target.write_text("a: b\n")
    link = tmp_path / "l.yaml"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    assert k.resolve_manifest("l.yaml", str(tmp_path))[0] is None


def test_read_manifest_limits(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_bytes(b"a: b\r\n")
    assert k._read_manifest(str(p)) == b"a: b\r\n"             # bytes untouched
    p.write_bytes(b"  \n")
    with pytest.raises(k.ManifestRefused):
        k._read_manifest(str(p))
    p.write_bytes(b"x" * (k.MANIFEST_MAX_BYTES + 1))
    with pytest.raises(k.ManifestRefused):
        k._read_manifest(str(p))
    p.write_bytes(b"x" * k.MANIFEST_MAX_BYTES)
    assert len(k._read_manifest(str(p))) == k.MANIFEST_MAX_BYTES
    with pytest.raises(k.ManifestRefused):
        k._read_manifest(str(tmp_path / "missing.yaml"))


# ---------------------------------------------------------------------------
# Private state files (pure)
# ---------------------------------------------------------------------------

@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(k, "STATE_DIR", str(tmp_path / "state"))
    return tmp_path / "state"


def test_ensure_file_writes_and_repairs(state_dir):
    d = k._private_dir("files")
    p = k._ensure_file(d, "a.json", b"one")
    assert Path(p).read_bytes() == b"one" and Path(p).parent == state_dir / "files"
    Path(p).write_bytes(b"tampered")
    assert k._ensure_file(d, "a.json", b"one") == p and Path(p).read_bytes() == b"one"
    os.unlink(p)
    assert Path(k._ensure_file(d, "a.json", b"one")).read_bytes() == b"one"
    assert [x.name for x in d.iterdir()] == ["a.json"]             # no temp leftovers


def test_ensure_file_blocked_by_directory_refuses(state_dir):
    d = k._private_dir("files")
    (d / "a.json").mkdir()
    with pytest.raises(ProfileRefusal):
        k._ensure_file(d, "a.json", b"one")


@pytest.mark.skipif(WIN, reason="POSIX modes")
def test_state_files_are_private(state_dir):
    d = k._private_dir("files")
    p = k._ensure_file(d, "a.json", b"x")
    assert (os.stat(p).st_mode & 0o777) == 0o600 and (os.stat(d).st_mode & 0o777) == 0o700


def test_cache_dirs_are_fresh_and_stale_ones_purged(state_dir):
    root = k._private_dir("cache")
    old = root / "c-old"
    old.mkdir()
    (old / "f").write_text("x")
    stale = time.time() - k.CACHE_MAX_AGE_SECONDS - 600
    os.utime(old, (stale, stale))
    young = root / "c-young"
    young.mkdir()
    a, b = k._new_cache_dir(), k._new_cache_dir()
    assert a != b and Path(a).is_dir() and Path(a).parent == root
    assert not old.exists() and young.exists()
    assert os.listdir(a) == []


# ---------------------------------------------------------------------------
# Real kubectl: world fixture
# ---------------------------------------------------------------------------

def native_exe():
    if WIN:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "hostname.exe")
    return shutil.which("true") or "/bin/true"


def write_json(path, data):
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    return str(path)


TOKEN = "tok-very-secret-1"


def make_kubeconfig(path, *, server="https://127.0.0.1:1", user=None, namespace="team",
                    cluster_extra=None, ctx_name="ctx1", current=True, extra_contexts=True):
    cluster = {"server": server}
    cluster.update(cluster_extra or {})
    data = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "cl", "cluster": cluster}],
        "users": [{"name": "u", "user": user if user is not None else {"token": TOKEN}}],
        "contexts": [{"name": ctx_name, "context": {"cluster": "cl", "user": "u",
                                                    **({"namespace": namespace} if namespace else {})}}],
    }
    if current:
        data["current-context"] = ctx_name
    if extra_contexts:
        data["clusters"].append({"name": "other-cl", "cluster": {"server": "https://other.invalid:1",
                                                                "insecure-skip-tls-verify": True}})
        data["users"].append({"name": "other-u", "user": {"token": "OTHER-TOKEN-NOT-APPROVED"}})
        data["contexts"].append({"name": "other-ctx", "context": {"cluster": "other-cl",
                                                                  "user": "other-u"}})
    return write_json(path, data)


class World:
    def __init__(self, root: Path, monkeypatch):
        self.root = root
        self.mp = monkeypatch
        self.cwd = root / "work"
        self.cwd.mkdir(exist_ok=True)
        self.kubeconfig = make_kubeconfig(root / "kubeconfig.json")
        self.mp.setenv("KUBECONFIG", self.kubeconfig)

    def use_kubeconfig(self, path):
        self.kubeconfig = str(path)
        self.mp.setenv("KUBECONFIG", self.kubeconfig)

    def req(self, text, cwd=None):
        return Request(cmd(text), str(cwd or self.cwd))

    def entry(self, text, cwd=None):
        """match + snapshot, shaped like an allowlist entry."""
        req = self.req(text, cwd)
        cand = k.match(req)
        assert cand is not None, f"no candidate for {text!r}"
        snap = k.snapshot(req, cand)
        return {"kind": "kubectl", "shape": cand, "snapshot": snap, "cwd": req.cwd}, req

    def write(self, name, text):
        p = self.cwd / name
        p.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return p


@pytest.fixture
def world(tmp_path, monkeypatch):
    if not HAVE_KUBECTL:
        pytest.skip("kubectl is not installed")
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_STATE_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, str(home))
    for var in list(os.environ):
        if var.upper().startswith(("KUBE", "HTTP_PROXY", "HTTPS_PROXY", "SSL_CERT")) or var.upper() == "POD_NAMESPACE":
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(k, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(c.RELAXATIONS, "skip_exe_dir_writable_check", True)
    return World(tmp_path, monkeypatch)


def run_ok(verdict):
    assert isinstance(verdict, Verdict) and verdict.ok, getattr(verdict, "reason", verdict)
    return verdict


def flag_values(argv, name):
    return [a.split("=", 1)[1] for a in argv if a.startswith(name + "=")]


# ---- match / label / candidates -------------------------------------------

@needs_kubectl
def test_match_candidates(world):
    cand = k.match(world.req("get pods"))
    assert cand == {"access": "read", "context": "ctx1", "scope": "namespace", "namespace": "team"}
    assert k.match(world.req("get pods -n other"))["namespace"] == "other"
    assert k.match(world.req("get pods -A")) == {"access": "read", "context": "ctx1",
                                                 "namespace": None, "scope": "all"}
    assert k.match(world.req("get nodes"))["scope"] == "all"
    assert k.match(world.req("describe ns team"))["scope"] == "all"
    assert k.match(world.req("logs web-0"))["namespace"] == "team"
    assert k.match(world.req("rollout status deploy/web -n x"))["namespace"] == "x"


@needs_kubectl
def test_match_default_namespace_when_context_has_none(world):
    world.use_kubeconfig(make_kubeconfig(world.root / "nons.json", namespace=None))
    assert k.match(world.req("get pods"))["namespace"] == "default"


@needs_kubectl
@pytest.mark.parametrize("text", [
    "get secrets", "get pods --token=x", "config view", "exec -it x", "get pods -o jsonpath=x",
    "rollout restart deploy/x", "apply -k dir", "apply -f -", "apply -f missing.yaml", "apply -f dir.yaml",
])
def test_match_none_outside_grammar(world, text):
    (world.cwd / "dir.yaml").mkdir()
    assert k.match(world.req(text)) is None
    assert k.match(Request(("git", "status"), str(world.cwd))) is None


@needs_kubectl
def test_match_none_without_usable_context(world):
    world.use_kubeconfig(make_kubeconfig(world.root / "nocur.json", current=False))
    assert k.match(world.req("get pods")) is None
    world.use_kubeconfig(world.root / "does-not-exist.json")
    assert k.match(world.req("get pods")) is None


@needs_kubectl
def test_match_apply_candidate_pins_namespace_and_file(world):
    p = world.write("m.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n")
    cand = k.match(world.req("apply -f m.yaml"))
    assert cand == {"access": "apply", "context": "ctx1", "namespace": "team",
                    "file": os.path.normcase(os.path.realpath(p))}
    assert k.match(world.req("apply -f m.yaml -n other"))["namespace"] == "other"


@needs_kubectl
def test_label_is_server_generated_and_short(world):
    req = world.req("get pods")
    label = k.label(req, k.match(req))
    assert label == "kubectl read ns=team ctx=ctx1"
    assert k.label(req, k.match(world.req("get pods -A"))) == "kubectl read ns=* ctx=ctx1"
    world.write("m.yaml", "x: y\n")
    cand = k.match(world.req("apply -f m.yaml"))
    assert k.label(req, cand) == "kubectl apply m.yaml ns=team ctx=ctx1"
    long_cand = dict(cand, file=str(world.cwd / ("a" * 200 + ".yaml")))
    assert len(k.label(req, long_cand)) == 100


# ---- snapshot --------------------------------------------------------------

@needs_kubectl
def test_snapshot_read_contents(world):
    entry, req = world.entry("get pods")
    snap = entry["snapshot"]
    json.dumps(snap)                                            # JSON-serialisable
    assert snap["kubectl_version"][:2] >= [1, 36] or snap["kubectl_version"][0] >= 1
    assert snap["kubectl"]["path"].lower().endswith(("kubectl.exe", "kubectl"))
    assert snap["kubeconfig"]["sha256"] == hashlib.sha256(snap["kubeconfig"]["text"].encode()).hexdigest()
    assert snap["kubeconfig"]["server"] == "https://127.0.0.1:1"
    assert snap["kubeconfig"]["auth"] == "token" and snap["kubeconfig"]["namespace"] == "team"
    assert snap["exec"] is None and snap["manifest"] is None
    assert snap["kuberc"] == {"mode": "file", "text": k.build_kuberc(None)}
    # only the approved context travels: never the other cluster's credentials
    assert "OTHER-TOKEN-NOT-APPROVED" not in snap["kubeconfig"]["text"]
    assert "other-ctx" not in snap["kubeconfig"]["text"]
    assert os.path.normcase(os.path.dirname(snap["kubectl"]["path"])) in \
        [os.path.normcase(p) for p in snap["path_dirs"]]
    assert snap["dlls"] == c.snapshot_cwd_dlls(str(world.cwd))


@needs_kubectl
def test_snapshot_does_not_read_the_users_real_kube_dir(world, monkeypatch):
    # a kubeconfig at the scratch HOME's default location must be ignored when KUBECONFIG is set
    kube = Path(os.environ["HOME"]) / ".kube"
    kube.mkdir()
    make_kubeconfig(kube / "config", namespace="homens", ctx_name="homectx")
    entry, _ = world.entry("get pods")
    assert entry["shape"]["context"] == "ctx1"


@needs_kubectl
@pytest.mark.parametrize("kwargs,why", [
    ({"server": "http://127.0.0.1:1"}, "http server"),
    ({"cluster_extra": {"insecure-skip-tls-verify": True}}, "insecure-skip-tls-verify"),
    ({"cluster_extra": {"proxy-url": "http://127.0.0.1:3128"}}, "proxy-url"),
    ({"cluster_extra": {"tls-server-name": "x.test"}}, "tls-server-name"),
    ({"user": {"tokenFile": "/nonexistent/token"}}, "tokenFile"),
    ({"user": {"username": "a", "password": "b"}}, "basic auth"),
    ({"user": {"auth-provider": {"name": "oidc"}}}, "auth-provider"),
    ({"user": {"as": "root", "token": "t"}}, "impersonation"),
    ({"user": {"exec": {"apiVersion": "client.authentication.k8s.io/v1", "command": "plug",
                        "interactiveMode": "Never"}}}, "relative exec"),
    ({"user": {"exec": {"apiVersion": "client.authentication.k8s.io/v1", "command": EXEC_ABS,
                        "interactiveMode": "Never", "env": [{"name": "A", "value": "B"}]}}}, "exec.env"),
])
def test_snapshot_refuses_unsafe_kubeconfigs(world, kwargs, why):
    world.use_kubeconfig(make_kubeconfig(world.root / "bad.json", **kwargs))
    req = world.req("get pods")
    cand = k.match(req)
    assert cand is not None
    with pytest.raises(k.KubeconfigRefused):
        k.snapshot(req, cand)


@needs_kubectl
def test_snapshot_refuses_when_nothing_to_read(world):
    req = world.req("get pods")
    cand = k.match(req)
    world.use_kubeconfig(world.root / "gone.json")
    with pytest.raises(ProfileRefusal):
        k.snapshot(req, cand)


@needs_kubectl
def test_snapshot_http_loopback_with_relaxation(world, monkeypatch):
    world.use_kubeconfig(make_kubeconfig(world.root / "http.json", server="http://127.0.0.1:1"))
    monkeypatch.setattr(c.RELAXATIONS, "kubectl_allow_http_loopback", True)
    entry, _ = world.entry("get pods")
    assert entry["snapshot"]["kubeconfig"]["server"] == "http://127.0.0.1:1"
    assert k.check_snapshot(entry)[0] is True
    monkeypatch.setattr(c.RELAXATIONS, "kubectl_allow_http_loopback", False)
    assert k.check_snapshot(entry)[0] is False                 # re-sanitised on every load


# ---- verify: injected argv -------------------------------------------------

@needs_kubectl
def test_verify_injects_pinned_argv_and_env(world, monkeypatch):
    entry, req = world.entry("get pods")            # snapshot first: the hostile env arrives after approval
    for name, value in {"KUBECONFIG": "/evil", "KUBERC": "/evil", "KUBECTL_KUBERC": "/evil",
                        "KUBECACHEDIR": "/evil", "KUBE_EDITOR": "evil", "KUBERNETES_SERVICE_HOST": "evil",
                        "POD_NAMESPACE": "evil", "HTTP_PROXY": "http://evil", "HTTPS_PROXY": "http://evil",
                        "SSL_CERT_FILE": "/evil", "SOME_SECRET": "leak"}.items():
        monkeypatch.setenv(name, value)
    v = run_ok(k.verify(entry, world.req("get pods -o name")))
    argv, snap = v.argv, entry["snapshot"]
    assert argv[0] == snap["kubectl"]["path"]
    kc = flag_values(argv, "--kubeconfig")[0]
    assert Path(kc).read_text(encoding="utf-8") == snap["kubeconfig"]["text"]
    assert Path(kc).parent == Path(k.STATE_DIR) / "files"
    assert flag_values(argv, "--context") == ["ctx1"]
    cache = flag_values(argv, "--cache-dir")[0]
    assert Path(cache).is_dir() and os.listdir(cache) == []
    assert Path(cache).parent == Path(k.STATE_DIR) / "cache"
    assert flag_values(argv, "--request-timeout") == ["30s"]
    rc = flag_values(argv, "--kuberc")[0]
    assert Path(rc).read_text(encoding="utf-8") == k.build_kuberc(None)
    assert argv[-3:] == ["get", "pods", "--output=name"] or argv[-4:] == [
        "get", "pods", "--output=name", "--namespace=team"]
    assert argv[argv.index("get"):] == ["get", "pods", "--output=name", "--namespace=team"]
    for flag in ("--kubeconfig", "--context", "--cache-dir", "--request-timeout", "--kuberc"):
        assert sum(1 for a in argv if a.startswith(flag + "=")) == 1
    # env: complete, from scratch, no kubectl control variables, no KUBERC next to --kuberc
    assert v.replace_env is True
    names = {n.upper() for n in v.env}
    assert not [n for n in names if n.startswith(("KUBE", "SSL_CERT", "HTTP_PROXY", "HTTPS_PROXY"))]
    assert "POD_NAMESPACE" not in names and "SOME_SECRET" not in names
    assert v.env["PATH"].split(os.pathsep) == snap["path_dirs"]
    assert v.wall_clock == k.WALL_CLOCK["get"] and v.cleanup_paths == (cache,)
    assert v.stdin is None
    assert v.stderr_fatal_markers == k.STDERR_FATAL_MARKERS


@needs_kubectl
def test_verify_cache_dir_is_fresh_each_time(world):
    entry, _ = world.entry("get pods")
    a = run_ok(k.verify(entry, world.req("get pods")))
    b = run_ok(k.verify(entry, world.req("get pods")))
    assert flag_values(a.argv, "--cache-dir") != flag_values(b.argv, "--cache-dir")
    assert a.cleanup_paths != b.cleanup_paths


@needs_kubectl
@pytest.mark.parametrize("text,tail", [
    ("logs web-0", ["logs", "web-0", "--tail=5000", "--limit-bytes=10485760", "--namespace=team"]),
    ("logs deploy/web --tail=7 -n team",
     ["logs", "deployment/web", "--tail=7", "--limit-bytes=10485760", "--namespace=team"]),
    ("rollout status sts/db", ["rollout", "status", "statefulset/db", "--timeout=300s", "--namespace=team"]),
    ("describe pods -l app=x", ["describe", "pods", "--selector=app=x", "--namespace=team"]),
])
def test_verify_rendered_commands(world, text, tail):
    entry, _ = world.entry("get pods")
    v = run_ok(k.verify(entry, world.req(text)))
    assert v.argv[v.argv.index(tail[0]):] == tail


@needs_kubectl
def test_verify_wall_clocks(world):
    entry, _ = world.entry("get pods")
    assert k.verify(entry, world.req("logs web-0")).wall_clock == k.WALL_CLOCK["logs"]
    assert k.verify(entry, world.req("rollout status deploy/w --timeout=45s")).wall_clock == \
        45 + k.ROLLOUT_WALL_SLACK
    assert k.verify(entry, world.req("rollout status deploy/w")).wall_clock == 300 + k.ROLLOUT_WALL_SLACK
    assert k.verify(entry, world.req("describe pods")).wall_clock == k.WALL_CLOCK["describe"]


@needs_kubectl
def test_verify_namespace_scope_rules(world):
    entry, _ = world.entry("get pods")                        # namespace entry for team
    assert run_ok(k.verify(entry, world.req("get pods -n team"))).argv[-1] == "--namespace=team"
    for text in ("get pods -n other", "get pods -A", "get nodes", "get ns", "describe ns team",
                 "apply -f m.yaml"):
        v = k.verify(entry, world.req(text))
        assert (v.ok, v.reason) == (False, None), text        # "not mine", not an error
    for text in ("get secrets", "get pods --kubeconfig=/x", "config view", "exec x"):
        v = k.verify(entry, world.req(text))
        assert (v.ok, v.reason) == (False, None), text
    assert k.verify(entry, Request(("git", "status"), str(world.cwd))).reason is None


@needs_kubectl
def test_verify_all_scope(world):
    entry, _ = world.entry("get pods -A")
    assert entry["shape"]["scope"] == "all"
    v = run_ok(k.verify(entry, world.req("get pods -A")))
    assert v.argv[-1] == "--all-namespaces" and not [a for a in v.argv if a.startswith("--namespace")]
    v = run_ok(k.verify(entry, world.req("get pods -n anything")))
    assert v.argv[-1] == "--namespace=anything"
    v = run_ok(k.verify(entry, world.req("get nodes")))
    assert v.argv[-2:] == ["get", "nodes"]
    v = run_ok(k.verify(entry, world.req("get pods")))         # no namespace: kubectl's default
    assert v.argv[-2:] == ["get", "pods"]


@needs_kubectl
def test_verify_malformed_entries_are_refused(world):
    entry, _ = world.entry("get pods")
    assert k.verify({}, world.req("get pods")).ok is False
    bad = copy.deepcopy(entry)
    bad["shape"]["scope"] = "weird"
    assert k.verify(bad, world.req("get pods")).reason is None
    for key in ("kubeconfig", "kubectl", "kuberc", "path_dirs", "dlls"):
        bad = copy.deepcopy(entry)
        del bad["snapshot"][key]
        v = k.verify(bad, world.req("get pods"))
        assert v.ok is False and v.reason, key
    ok, why = k.check_snapshot({"snapshot": None, "shape": None})
    assert ok is False and why


# ---- drift -----------------------------------------------------------------

@needs_kubectl
def test_drift_kubeconfig_copy_removed_or_changed_is_restored(world):
    entry, req = world.entry("get pods")
    v = run_ok(k.verify(entry, req))
    kc = Path(flag_values(v.argv, "--kubeconfig")[0])
    sealed = entry["snapshot"]["kubeconfig"]["text"]
    kc.unlink()                                                # missing -> kubectl would fall back to localhost:8080
    v = run_ok(k.verify(entry, req))
    assert kc.read_text(encoding="utf-8") == sealed
    kc.write_text(json.dumps({"clusters": [{"name": "x", "cluster": {"server": "https://evil:1"}}]}))
    v = run_ok(k.verify(entry, req))
    assert Path(flag_values(v.argv, "--kubeconfig")[0]).read_text(encoding="utf-8") == sealed
    ok, why = k.check_snapshot(entry)
    assert ok, why


@needs_kubectl
def test_drift_kubeconfig_copy_cannot_be_restored_refuses(world):
    entry, req = world.entry("get pods")
    kc = Path(flag_values(run_ok(k.verify(entry, req)).argv, "--kubeconfig")[0])
    kc.unlink()
    kc.mkdir()                                                 # something unremovable sits in its place
    v = k.verify(entry, req)
    assert v.ok is False and v.reason
    assert k.check_snapshot(entry)[0] is False


@needs_kubectl
def test_drift_sealed_kubeconfig_record_damaged(world):
    entry, req = world.entry("get pods")
    bad = copy.deepcopy(entry)
    bad["snapshot"]["kubeconfig"]["text"] = bad["snapshot"]["kubeconfig"]["text"].replace("127.0.0.1", "10.0.0.9")
    v = k.verify(bad, req)
    assert v.ok is False and "damaged" in v.reason
    # text and hash both edited, but the text is no longer in sanitised form
    bad = copy.deepcopy(entry)
    forged = json.dumps(json.loads(bad["snapshot"]["kubeconfig"]["text"]))
    bad["snapshot"]["kubeconfig"].update(text=forged, sha256=hashlib.sha256(forged.encode()).hexdigest())
    assert "sanitised form" in k.verify(bad, req).reason
    # insecure flag smuggled in with a consistent hash
    d = json.loads(entry["snapshot"]["kubeconfig"]["text"])
    d["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
    forged = json.dumps(d)
    bad = copy.deepcopy(entry)
    bad["snapshot"]["kubeconfig"].update(text=forged, sha256=hashlib.sha256(forged.encode()).hexdigest())
    assert k.verify(bad, req).ok is False


@needs_kubectl
def test_drift_context_mismatch(world):
    entry, req = world.entry("get pods")
    bad = copy.deepcopy(entry)
    bad["shape"]["context"] = "other-ctx"
    v = k.verify(bad, req)
    assert v.ok is False and "different context" in v.reason


@needs_kubectl
def test_drift_kuberc_text_must_match_template(world):
    entry, req = world.entry("get pods")
    bad = copy.deepcopy(entry)
    bad["snapshot"]["kuberc"]["text"] = "apiVersion: kubectl.config.k8s.io/v1beta1\nkind: Preference\n"
    v = k.verify(bad, req)
    assert v.ok is False and "template" in v.reason


@needs_kubectl
def test_drift_kubectl_binary(world):
    entry, req = world.entry("get pods")
    bad = copy.deepcopy(entry)
    bad["snapshot"]["kubectl"]["sha256"] = "0" * 64            # the file on disk no longer hashes to the pin
    v = k.verify(bad, req)
    assert v.ok is False and "changed since" in v.reason
    assert k.check_snapshot(bad)[0] is False
    bad = copy.deepcopy(entry)
    bad["snapshot"]["kubectl"]["path"] = str(world.root / "no-such-kubectl.exe")
    assert k.verify(bad, req).ok is False


@needs_kubectl
def test_drift_real_binary_changed_on_disk(world, monkeypatch):
    fake = world.root / "bin" / ("kubectl.exe" if WIN else "kubectl")
    fake.parent.mkdir()
    shutil.copy2(shutil.which("kubectl"), fake)
    monkeypatch.setattr(k, "KUBECTL_PROGRAM", str(fake))
    entry, req = world.entry("get pods")
    assert entry["snapshot"]["kubectl"]["path"].lower() == str(fake).lower() or \
        os.path.normcase(entry["snapshot"]["kubectl"]["path"]) == os.path.normcase(os.path.realpath(fake))
    run_ok(k.verify(entry, req))
    with open(fake, "ab") as handle:
        handle.write(b"\0")
    v = k.verify(entry, req)
    assert v.ok is False and "changed since" in v.reason


@needs_kubectl
def test_drift_cwd(world):
    entry, req = world.entry("get pods")
    ok, why = k.check_snapshot(entry)
    assert ok, why
    gone = copy.deepcopy(entry)
    gone["cwd"] = str(world.root / "nope")
    ok, why = k.check_snapshot(gone)
    assert ok is False and "working directory" in why


@needs_kubectl
@pytest.mark.skipif(not WIN, reason="DLL side-loading is a Windows concern")
def test_drift_cwd_dll(world):
    entry, req = world.entry("get pods")
    (world.cwd / "evil.dll").write_bytes(b"MZ")
    v = k.verify(entry, req)
    assert v.ok is False and v.reason
    ok, why = k.check_snapshot(entry)
    assert ok is False and why


# ---- check_snapshot / describe ----------------------------------------------

@needs_kubectl
def test_check_snapshot_passes_and_runs_kuberc_selftest(world, monkeypatch):
    entry, _ = world.entry("get pods")
    assert k.check_snapshot(entry) == (True, None)
    calls = []
    real = k.kuberc_selftest
    monkeypatch.setattr(k, "kuberc_selftest", lambda *a: calls.append(a) or "kubectl did not apply")
    ok, why = k.check_snapshot(entry)
    assert (ok, why) == (False, "kubectl did not apply") and len(calls) == 1
    monkeypatch.setattr(k, "kuberc_selftest", real)


@needs_kubectl
def test_describe_read_texts(world):
    entry, req = world.entry("get pods")
    text = k.describe(req, entry["shape"])
    first = text.splitlines()[0]
    assert "namespace team" in first and "context ctx1" in first and "get|describe|logs|rollout status" in first
    assert "Cluster: https://127.0.0.1:1  authentication: token" in text
    assert "Credential plugin" not in text
    assert "vault-owned sanitised kubeconfig copy" in text and "credentials" in text
    assert "--request-timeout=30s" in text and "fresh --cache-dir" in text
    assert "capped at 5000 lines / 10 MiB" in text and "300s" in text
    assert "Never allowed: secrets, RBAC" in text
    assert "The agent can obtain these values" in text and "Use test-grade credentials." in text
    assert "Manifest sha256" not in text


@needs_kubectl
def test_describe_all_scope_and_without_snapshot(world):
    entry, req = world.entry("get pods -A")
    assert "ALL namespaces and cluster-scoped kinds" in k.describe(req, entry["shape"])
    other = Request(cmd("get pods -A --no-headers"), str(world.cwd))
    text = k.describe(other, entry["shape"])                   # no snapshot cached for this request
    assert "Cluster:" not in text and "The agent can obtain these values" in text


# ---- exec plugin ---------------------------------------------------------------

def make_plugin(world):
    d = world.root / "plugins"
    d.mkdir(exist_ok=True)
    plug = d / ("kplug.exe" if WIN else "kplug")
    shutil.copy2(native_exe(), plug)
    return plug


@pytest.fixture
def exec_world(world):
    plug = make_plugin(world)
    command = os.path.realpath(plug)
    user = {"exec": {"apiVersion": "client.authentication.k8s.io/v1", "command": command,
                     "args": ["get-token", "--audience", "x"], "interactiveMode": "Never",
                     "provideClusterInfo": False}}
    world.use_kubeconfig(make_kubeconfig(world.root / "exec.json", user=user))
    world.plug, world.plug_command = plug, command
    return world


@needs_kubectl
def test_exec_plugin_snapshot_kuberc_and_argv(exec_world):
    world = exec_world
    entry, req = world.entry("get pods")
    snap = entry["snapshot"]
    assert snap["kubeconfig"]["auth"] == "exec"
    assert snap["exec"]["command"] == os.path.normpath(world.plug_command)
    assert snap["exec"]["args"] == ["get-token", "--audience", "x"]
    assert snap["exec"]["binary"]["sha256"] == hashlib.sha256(Path(world.plug).read_bytes()).hexdigest()
    assert snap["kuberc"] == {"mode": "file", "text": k.build_kuberc(snap["exec"]["command"])}
    assert "credentialPluginPolicy: Allowlist" in snap["kuberc"]["text"]
    assert os.path.normcase(os.path.dirname(snap["exec"]["command"])) in \
        [os.path.normcase(p) for p in snap["path_dirs"]]
    v = run_ok(k.verify(entry, req))
    rc = flag_values(v.argv, "--kuberc")
    assert len(rc) == 1 and Path(rc[0]).read_text(encoding="utf-8") == snap["kuberc"]["text"]
    assert "KUBERC" not in {n.upper() for n in v.env}          # --kuberc and KUBERC=off are exclusive
    assert k.check_snapshot(entry) == (True, None)
    text = k.describe(req, entry["shape"])
    assert "Credential plugin (hash pinned" in text and snap["exec"]["command"] in text
    assert "get-token --audience x" in text
    assert "The plugin inherits the whole child environment" in text


@needs_kubectl
def test_exec_plugin_drift(exec_world):
    world = exec_world
    entry, req = world.entry("get pods")
    run_ok(k.verify(entry, req))
    with open(world.plug, "ab") as handle:
        handle.write(b"\0")                                    # hash changes
    v = k.verify(entry, req)
    assert v.ok is False and "exec credential plugin" in v.reason and "changed" in v.reason
    ok, why = k.check_snapshot(entry)
    assert ok is False and "exec credential plugin" in why
    world.plug.unlink()
    v = k.verify(entry, req)
    assert v.ok is False and "exec credential plugin" in v.reason


@needs_kubectl
def test_exec_plugin_record_must_match_kubeconfig(exec_world):
    entry, req = exec_world.entry("get pods")
    bad = copy.deepcopy(entry)
    bad["snapshot"]["exec"]["command"] = "C:\\other.exe" if WIN else "/other"
    assert k.verify(bad, req).ok is False
    bad = copy.deepcopy(entry)
    bad["snapshot"]["exec"] = None
    assert k.verify(bad, req).ok is False
    bad = copy.deepcopy(entry)
    bad["snapshot"]["exec"]["binary"]["path"] = str(exec_world.root / "elsewhere.exe")
    assert k.verify(bad, req).ok is False


@needs_kubectl
def test_exec_plugin_refused_below_kubectl_1_35_uses_env_off_otherwise(exec_world, monkeypatch):
    monkeypatch.setattr(k, "KUBERC_MIN_VERSION", (99, 0))      # pretend kubectl is too old
    req = exec_world.req("get pods")
    cand = k.match(req)
    with pytest.raises(k.KubeconfigRefused):
        k.snapshot(req, cand)
    exec_world.use_kubeconfig(exec_world.root / "kubeconfig.json")
    entry, req = exec_world.entry("get pods")                  # token user on an "old" kubectl
    assert entry["snapshot"]["kuberc"] == {"mode": "env_off", "text": None}
    v = run_ok(k.verify(entry, req))
    assert v.env["KUBERC"] == "off"                            # exact lowercase
    assert not [a for a in v.argv if a.startswith("--kuberc")]
    assert k.check_snapshot(entry) == (True, None)


# ---- kuberc self-test with the real kubectl ----------------------------------------

def _pin_and_dirs():
    pin = c.resolve_pinned_binary("kubectl")
    return pin, c.pinned_path_dirs(extra=[os.path.dirname(pin.path)])


@needs_kubectl
def test_kuberc_selftest_accepts_templates(world, tmp_path):
    pin, dirs = _pin_and_dirs()
    for text in (k.build_kuberc(None), k.build_kuberc(k.normalise_exec_command(EXEC_ABS))):
        rc = tmp_path / "good.rc"
        rc.write_text(text, encoding="utf-8", newline="")
        assert k.kuberc_selftest(pin, dirs, str(rc)) is None, text


@needs_kubectl
@pytest.mark.parametrize("text", [
    HEAD + "credentialPluginPolicyy: DenyAll\n",                              # typo'd key: fail-open
    "apiVersion: kubectl.config.k8s.io/v1alpha1\nkind: Preference\ncredentialPluginPolicy: DenyAll\n",
    HEAD + "credentialPluginPolicy: DenyAll\nbogus: 1\n",
    HEAD + "credentialPluginPolicy: Nope\n",
    "apiVersion: kubectl.config.k8s.io/v1beta1\nkind: Wrong\ncredentialPluginPolicy: DenyAll\n",
    HEAD + "credentialPluginPolicy: Allowlist\ncredentialPluginAllowlist:\n- commandd: \"/x\"\n",
])
def test_kuberc_selftest_flags_broken_kuberc_as_fatal(world, tmp_path, text):
    pin, dirs = _pin_and_dirs()
    rc = tmp_path / "bad.rc"
    rc.write_text(text, encoding="utf-8", newline="")
    assert k.kuberc_selftest(pin, dirs, str(rc))


@needs_kubectl
def test_typo_kuberc_really_prints_the_strict_decoding_marker(tmp_path):
    """The premise of the fail-open guard: kubectl exits 0 and only warns on stderr."""
    pin, dirs = _pin_and_dirs()
    rc = tmp_path / "typo.rc"
    rc.write_text(HEAD + "credentialPluginPolicyy: DenyAll\n", encoding="utf-8", newline="")
    res = k._probe(pin, dirs, ["version", "--client", f"--kuberc={rc}"])
    assert res.ok, res.failure_reason()
    assert k.stderr_problem(res.stderr_text()) is not None
    good = tmp_path / "good.rc"
    good.write_text(k.build_kuberc(None), encoding="utf-8", newline="")
    res = k._probe(pin, dirs, ["version", "--client", f"--kuberc={good}"])
    assert res.ok and k.stderr_problem(res.stderr_text()) is None


@needs_kubectl
def test_kuberc_selftest_missing_file(world, tmp_path):
    pin, dirs = _pin_and_dirs()
    assert k.kuberc_selftest(pin, dirs, str(tmp_path / "nope.rc"))


@needs_kubectl
def test_snapshot_fails_when_selftest_fails(world, monkeypatch):
    monkeypatch.setattr(k, "kuberc_selftest", lambda *a: "kubectl did not apply the generated kuberc strictly")
    req = world.req("get pods")
    with pytest.raises(ProfileRefusal, match="kuberc"):
        k.snapshot(req, k.match(req))


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------

GOOD = """apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  a: b
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: nginx:1.27
        ports: [{containerPort: 80}]
"""

DUPLICATE_KIND = """apiVersion: v1
kind: ConfigMap
kind: Secret
metadata: {name: s}
stringData: {a: b}
"""

YAML11_ON = """apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
  - name: c
    image: x
    securityContext: {privileged: on}
"""

MERGE_KEY = """apiVersion: v1
kind: Pod
metadata: {name: p}
x-base: &base {privileged: true}
spec:
  containers:
  - name: c
    image: x
    securityContext:
      <<: *base
"""

ANCHOR_NS = """apiVersion: v1
kind: ConfigMap
metadata:
  name: a
  namespace: &ns kube-system
data: {x: *ns}
"""

LIST_WITH_SECRET = """apiVersion: v1
kind: List
items:
- {apiVersion: v1, kind: ConfigMap, metadata: {name: ok}}
- {apiVersion: v1, kind: Secret, metadata: {name: s}}
"""

HOSTPATH = """apiVersion: apps/v1
kind: Deployment
metadata: {name: d}
spec:
  selector: {matchLabels: {a: b}}
  template:
    metadata: {labels: {a: b}}
    spec:
      containers: [{name: c, image: x}]
      volumes: [{name: v, hostPath: {path: /}}]
"""

WRONG_NS = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: kube-system}\n"
SECRET = "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\nstringData: {a: b}\n"
RBAC = ("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata: {name: x}\nroleRef: {kind: ClusterRole, name: cluster-admin}\n")
CRD_KIND = "apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: w}\n"


@needs_kubectl
def test_normaliser_sees_what_kubectl_sees(world, tmp_path):
    """Differential cases (validate-kubectl.md K6): the policy must run on kubectl's decoding."""
    entry, _ = world.entry("get pods")
    pin = c.PinnedBinary.from_dict(entry["snapshot"]["kubectl"])
    kc = Path(k.STATE_DIR) / "x.json"
    kc.parent.mkdir(parents=True, exist_ok=True)
    kc.write_text(entry["snapshot"]["kubeconfig"]["text"])

    def norm(text):
        return k.normalise_manifest(text.encode(), pin, entry["snapshot"]["path_dirs"],
                                    [f"--kubeconfig={kc}", "--context=ctx1"], {"KUBERC": "off"})

    docs = norm(DUPLICATE_KIND)
    assert docs[0]["kind"] == "Secret"                          # last key wins, silently
    docs = norm("apiVersion: v1\nkind: Secret\nkind: ConfigMap\nmetadata: {name: s}\n")
    assert docs[0]["kind"] == "ConfigMap"
    docs = norm(YAML11_ON)
    assert docs[0]["spec"]["containers"][0]["securityContext"]["privileged"] is True
    docs = norm(MERGE_KEY)
    assert docs[0]["spec"]["containers"][0]["securityContext"] == {"privileged": True}
    # numbers: kubectl reads 010 / 0o10 as octal and 0x10 as hex (YAML 1.1 style), 1_0 as 10
    docs = norm("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: nn}\ndata: {oct: 010, hex: 0x10}\n")
    assert docs[0]["data"] == {"oct": 8, "hex": 16}
    docs = norm("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n"
                "  - {name: c, image: x, ports: [{containerPort: 010}, {containerPort: 0x10}, "
                "{containerPort: 0o10}, {containerPort: 1_0}]}\n")
    assert [p["containerPort"] for p in docs[0]["spec"]["containers"][0]["ports"]] == [8, 16, 8, 10]
    # the YAML 1.1 bool trap: an unquoted `n` is false, and typed metadata.name then fails to decode
    with pytest.raises(k.ManifestRefused) as info:
        norm("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: n}\n")
    assert "cannot unmarshal bool" in info.value.reason
    docs = norm(ANCHOR_NS)
    assert docs[0]["metadata"]["namespace"] == "kube-system" and docs[0]["data"]["x"] == "kube-system"
    assert [d["kind"] for d in norm(GOOD)] == ["ConfigMap", "Deployment"]   # concatenated, not a List
    assert norm("") == [] and k.check_manifest(norm(""), "team") == ["the manifest contains no objects"]
    for broken in ("a: [", "- 1\n- 2\n", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: nn}\n\t bad"):
        with pytest.raises(k.ManifestRefused):
            norm(broken)


def test_manifest_refusal_hint_is_one_sanitised_line():
    hint = k._stderr_hint
    assert hint(b'error: unable to decode "STDIN": json: cannot unmarshal bool into Go struct field '
                b'ObjectMeta.metadata.name of type string\n') == \
        "unable to decode ...: json: cannot unmarshal bool into Go struct field ObjectMeta.metadata.name of type string"
    # manifest fragments echoed by kubectl never reach the text
    leak = hint(b"error: Object 'Kind' is missing in '{\"password\": \"hunter2\"}'\nsecond line\n")
    assert "hunter2" not in leak and "password" not in leak and "second" not in leak
    assert "hunter2" not in hint(b"error: bad value {password: hunter2} here\n")
    assert "hunter2" not in hint(b"error: bad list [hunter2]\n")
    assert hint(b"") == "" and hint(None) == ""
    assert len(hint(b"error: " + b"x" * 1000)) == k.MANIFEST_HINT_MAX
    assert hint("café \x1b[31mred\x00\n".encode()) == "caf"


@needs_kubectl
def test_apply_snapshot_pins_hash_and_summarises(world):
    p = world.write("m.yaml", GOOD)
    entry, req = world.entry("apply -f m.yaml")
    m = entry["snapshot"]["manifest"]
    assert m["sha256"] == hashlib.sha256(GOOD.encode()).hexdigest() and m["size"] == len(GOOD.encode())
    assert m["objects"] == ["ConfigMap/cfg", "Deployment/web"]
    assert m["path"] == entry["shape"]["file"] == os.path.normcase(os.path.realpath(p))
    assert entry["shape"]["access"] == "apply" and entry["shape"]["namespace"] == "team"
    text = k.describe(req, entry["shape"])
    assert "this exact manifest, namespace team, context ctx1" in text
    assert f"Manifest sha256 {m['sha256'][:16]}..." in text and "ConfigMap/cfg, Deployment/web" in text
    assert "no Secret/RBAC/CRD/webhook/Namespace" in text
    assert k.check_snapshot(entry) == (True, None)


@needs_kubectl
def test_apply_verify_delivers_original_bytes_on_stdin(world):
    raw = GOOD.replace("\n", "\r\n").encode("utf-8")           # CRLF: bytes must reach kubectl untouched
    world.write("m.yaml", raw)
    entry, req = world.entry("apply -f m.yaml")
    v = run_ok(k.verify(entry, req))
    assert isinstance(v, k.KubectlVerdict) and v.stdin == raw
    assert v.argv[v.argv.index("apply"):] == ["apply", "-f", "-", "--namespace=team"]
    assert v.wall_clock == k.WALL_CLOCK["apply"] and len(v.cleanup_paths) == 1
    assert "-f" in v.argv and not [a for a in v.argv if a.endswith("m.yaml")]   # the path never reaches kubectl
    v2 = run_ok(k.verify(entry, world.req("apply -f m.yaml -n team --dry-run=server --validate=strict")))
    assert v2.argv[v2.argv.index("apply"):] == ["apply", "-f", "-", "--dry-run=server",
                                                 "--validate=strict", "--namespace=team"]
    assert v2.stdin == raw
    assert flag_values(v2.argv, "--kuberc")


@needs_kubectl
def test_apply_verify_rules(world):
    world.write("m.yaml", GOOD)
    world.write("other.yaml", GOOD)
    entry, _ = world.entry("apply -f m.yaml")
    for text in ("apply -f other.yaml", "apply -f m.yaml -n other", "get pods", "apply -f missing.yaml",
                 "apply -f m.yaml --prune", "apply -f -"):
        v = k.verify(entry, world.req(text))
        assert (v.ok, v.reason) == (False, None), text
    assert run_ok(k.verify(entry, world.req("apply --filename=m.yaml")))
    assert run_ok(k.verify(entry, world.req("apply -f ./sub/../m.yaml"))) if (world.cwd / "sub").exists() \
        else True
    abs_req = Request(cmd(f'apply -f "{world.cwd / "m.yaml"}"'), str(world.cwd))
    assert run_ok(k.verify(entry, abs_req)).stdin == GOOD.encode()
    # a read entry never serves apply, and an apply entry never serves reads
    read_entry, _ = world.entry("get pods")
    assert k.verify(read_entry, world.req("apply -f m.yaml")).reason is None


@needs_kubectl
def test_apply_hash_pin_manifest_changed(world):
    p = world.write("m.yaml", GOOD)
    entry, req = world.entry("apply -f m.yaml")
    p.write_bytes(GOOD.encode() + b"# one more byte\n")
    v = k.verify(entry, req)
    assert v.ok is False and "changed since it was approved" in v.reason
    ok, why = k.check_snapshot(entry)
    assert ok is False and "changed since" in why
    p.write_bytes(GOOD.encode())                                # restored: fine again
    assert run_ok(k.verify(entry, req)).stdin == GOOD.encode()
    p.unlink()
    assert k.verify(entry, req).reason is None                  # no such file: "not mine", dialog applies
    assert k.check_snapshot(entry)[0] is False


@needs_kubectl
def test_apply_swapped_for_evil_manifest_with_forged_hash_is_stopped_by_policy(world):
    p = world.write("m.yaml", GOOD)
    entry, req = world.entry("apply -f m.yaml")
    p.write_bytes(SECRET.encode())
    forged = copy.deepcopy(entry)
    forged["snapshot"]["manifest"]["sha256"] = hashlib.sha256(SECRET.encode()).hexdigest()
    v = k.verify(forged, req)
    assert v.ok is False and "object policy" in v.reason and "Secret" in v.reason


@needs_kubectl
@pytest.mark.parametrize("manifest,needle", [
    (SECRET, "Secret"), (RBAC, "ClusterRoleBinding"), (CRD_KIND, "not in the allowed kinds"),
    (WRONG_NS, "approved namespace"), (HOSTPATH, "hostPath"), (DUPLICATE_KIND, "Secret"),
    (YAML11_ON, "privileged"), (MERGE_KEY, "privileged"), (ANCHOR_NS, "approved namespace"),
    (LIST_WITH_SECRET, "Secret"),
    ("apiVersion: v1\nkind: Namespace\nmetadata: {name: nn}\n", "Namespace"),
    ("apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: nn}\n", "ServiceAccount"),
    ("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostNetwork: true\n  containers: [{name: c, image: x}]\n",
     "hostNetwork"),
    ("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostNetwork: yes\n  containers: [{name: c, image: x}]\n",
     "hostNetwork"),
    ("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  serviceAccountName: admin\n"
     "  containers: [{name: c, image: x}]\n", "service account"),
    ("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: c\n    image: x\n"
     "    envFrom: [{secretRef: {name: s}}]\n", "secretRef"),
    ("", "empty"), ("a: [", "decode"), ("- 1\n- 2\n", "decode"),
])
def test_apply_snapshot_refuses_policy_violations(world, manifest, needle):
    world.write("m.yaml", manifest or "  \n")
    req = world.req("apply -f m.yaml")
    cand = k.match(req)
    assert cand is not None
    with pytest.raises(ProfileRefusal) as info:
        k.snapshot(req, cand)
    assert needle.lower() in info.value.reason.lower(), info.value.reason


@needs_kubectl
def test_apply_namespace_pin_follows_dash_n(world):
    world.write("m.yaml", WRONG_NS)
    req = world.req("apply -f m.yaml -n kube-system")
    entry_ns = k.match(req)["namespace"]
    assert entry_ns == "kube-system"
    snap = k.snapshot(req, k.match(req))                         # explicit approval of that namespace
    assert snap["manifest"]["objects"] == ["ConfigMap/a"]


@needs_kubectl
def test_apply_manifest_too_large_or_too_many_objects(world):
    world.write("big.yaml", "# " + "x" * (k.MANIFEST_MAX_BYTES + 10))
    req = world.req("apply -f big.yaml")
    with pytest.raises(k.ManifestRefused):
        k.snapshot(req, k.match(req))
    many = "".join(f"---\napiVersion: v1\nkind: ConfigMap\nmetadata: {{name: c{i}}}\n"
                   for i in range(k.MANIFEST_MAX_OBJECTS + 1))
    world.write("many.yaml", many)
    req = world.req("apply -f many.yaml")
    with pytest.raises(ProfileRefusal, match="more than"):
        k.snapshot(req, k.match(req))


@needs_kubectl
def test_apply_dry_run_flags_do_not_change_the_entry(world):
    world.write("m.yaml", GOOD)
    a = k.match(world.req("apply -f m.yaml"))
    b = k.match(world.req("apply -f m.yaml --dry-run=client --validate=strict"))
    assert a == b


# ---------------------------------------------------------------------------
# End to end against a loopback fake API (relaxation: kubectl_allow_http_loopback)
# ---------------------------------------------------------------------------

class _FakeApi:
    def __init__(self):
        import http.server

        outer = self
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("Authorization")))
                path = self.path.split("?")[0]
                if path == "/api":
                    return self._send(200, {"kind": "APIVersions", "versions": ["v1"]})
                if path == "/apis":
                    return self._send(200, {"kind": "APIGroupList", "apiVersion": "v1", "groups": []})
                if path == "/api/v1":
                    return self._send(200, {"kind": "APIResourceList", "groupVersion": "v1", "resources": [
                        {"name": "configmaps", "singularName": "configmap", "namespaced": True,
                         "kind": "ConfigMap", "verbs": ["get", "list"], "shortNames": ["cm"]}]})
                if path == "/api/v1/namespaces/team/configmaps":
                    return self._send(200, {"kind": "ConfigMapList", "apiVersion": "v1", "metadata": {},
                                            "items": [{"kind": "ConfigMap", "apiVersion": "v1",
                                                       "metadata": {"name": "fake-cm", "namespace": "team"}}]})
                return self._send(404, {"kind": "Status", "apiVersion": "v1", "status": "Failure",
                                        "reason": "NotFound", "code": 404})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@needs_kubectl
def test_end_to_end_get_against_fake_api(world, monkeypatch):
    api = _FakeApi()
    try:
        monkeypatch.setattr(c.RELAXATIONS, "kubectl_allow_http_loopback", True)
        world.use_kubeconfig(make_kubeconfig(world.root / "fake.json", server=f"http://127.0.0.1:{api.port}"))
        entry, req = world.entry("get configmaps")
        v = run_ok(k.verify(entry, world.req("get configmaps -o name")))
        proc = subprocess.run(v.argv, env=v.env, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=v.wall_clock, cwd=str(world.cwd))
        out, err = proc.stdout.decode(), proc.stderr.decode()
        assert proc.returncode == 0, err
        assert "configmap/fake-cm" in out
        assert k.stderr_problem(err) is None
        # client-go only attaches credentials on TLS (checked with kubectl's own --token too): over the
        # relaxed plain-http loopback no Authorization header leaves, so the path is what proves the pins
        assert api.requests and all(a is None for _p, a in api.requests)
        assert any("/namespaces/team/configmaps" in p for p, _a in api.requests)
        assert not any("other" in p for p, _a in api.requests)
        # the fresh cache dir was used (kubectl wrote its discovery cache there, not under HOME)
        assert os.listdir(v.cleanup_paths[0])
        assert not (Path(os.environ["HOME"]) / ".kube").exists()
    finally:
        api.close()


@needs_kubectl
def test_end_to_end_missing_kubeconfig_never_falls_back_to_localhost(world):
    entry, req = world.entry("get pods")
    v = run_ok(k.verify(entry, req))
    kc = Path(flag_values(v.argv, "--kubeconfig")[0])
    assert kc.exists()                                          # restored/verified before spawn
    kc.unlink()
    v = run_ok(k.verify(entry, req))
    assert Path(flag_values(v.argv, "--kubeconfig")[0]).exists()
