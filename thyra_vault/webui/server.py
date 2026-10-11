"""A one-dialog loopback web server.

``run_flow`` starts a server bound to 127.0.0.1 on a random port, opens the
default browser at it, drives one flow (flows.py) to completion, and shuts the
server down. It blocks the calling MCP tool while the human answers, and returns
when they finish, cancel, or go away.

Threat model, stated plainly because a page on a local port is a weaker place for
a master password than a window no other process can see:

  * A page on a local port CAN be reached by anything on this machine that can
    open a socket -- including an agent with a browser or shell tool. The defences
    below make that hard and detectable; they do not make it impossible. The
    launch code is not on the browser's command line (a private start page
    forwards to it), but a process of the SAME user that can read that page in the
    instant before it connects can still race the human for the session. A process
    that gets a session still needs the master password to unlock anything.
  * Nothing here is reachable from another machine (loopback only) or from a
    web page the human happens to have open (Host / Origin / Fetch-Metadata
    checks, JSON-only bodies, no CORS headers, a token held outside cookies).
  * The launch URL carries a single-use code in its #fragment (never sent to
    any server or logged by the browser's Referer). The page swaps it for a
    session token once; a second use of the code fails loudly, so a raced or
    replayed link is visible to the human as an error page.
  * Passwords and decrypted values never appear in a URL, a log line, or a
    response -- only in the request bodies of the action that needs them.
"""
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import unquote, urlsplit

from .. import envvars
from .flows import Act

# Built by `pnpm build:embed` in web/ and committed, so a plain clone of this
# plugin needs no Node toolchain.
ASSET_DIR = Path(__file__).resolve().parent.parent / "web_dist"

# An unauthenticated exchange body is a few dozen bytes; an authenticated action can
# carry a whole item (an SSH key and notes are up to 50k characters each, and JSON
# escapes can multiply that), so the two limits differ.
MAX_BODY_UNAUTH = 4 * 1024
MAX_BODY = 1024 * 1024
SOCKET_TIMEOUT = 15.0  # seconds a connection may sit silent: no thread is held forever
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/javascript", ".mjs")
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("image/svg+xml", ".svg")


class WebUiUnavailable(RuntimeError):
    """The browser UI cannot be shown (assets missing)."""


class Limits:
    """Timeouts, in seconds. Overridable per call (tests shrink them)."""

    def __init__(self, launch_timeout=180.0, heartbeat_timeout=90.0, closing_grace=4.0,
                 max_lifetime=1800.0, max_bad_codes=5):
        self.launch_timeout = launch_timeout        # browser never connected
        self.heartbeat_timeout = heartbeat_timeout  # tab silently gone
        self.closing_grace = closing_grace          # wait this long after pagehide
        self.max_lifetime = max_lifetime            # absolute ceiling for one dialog
        self.max_bad_codes = max_bad_codes


class StaleScreen(Exception):
    pass


class Session:
    """One dialog: the flow generator plus the connection state around it."""

    def __init__(self, flow, status_of: Optional[Callable[[], Optional[str]]] = None):
        self.flow = flow
        self.status_of = status_of
        self.lock = threading.RLock()
        self.screen: Optional[dict] = None
        self.screen_id: Optional[str] = None
        self.finished = threading.Event()
        self.reason: Optional[str] = None
        self.error: Optional[BaseException] = None
        self.code = secrets.token_urlsafe(24)
        self.code_used = False
        self.token = secrets.token_urlsafe(32)
        self.connected = False
        self.last_seen = 0.0
        self.closing_at: Optional[float] = None
        self.bad_codes = 0

    # -- flow driving ------------------------------------------------------
    def start(self) -> None:
        with self.lock:
            self._advance(lambda: next(self.flow))

    def _advance(self, step) -> None:
        try:
            scr = step()
        except StopIteration:
            self._finish("completed")
        except Exception as exc:  # noqa: BLE001 -- surfaced to the caller after teardown
            self.error = exc
            self._finish("error")
        else:
            self.screen_id = uuid.uuid4().hex
            self.screen = dict(scr, id=self.screen_id)

    def act(self, screen_id: str, action_id: str, values: dict) -> dict:
        with self.lock:
            if self.finished.is_set():
                return self.view()
            if screen_id != self.screen_id:
                raise StaleScreen()
            self._advance(lambda: self.flow.send(Act(action_id, values)))
            return self.view()

    def cancel(self, reason: str) -> None:
        with self.lock:
            if self.finished.is_set():
                return
            try:
                self.flow.close()
            except Exception:  # noqa: BLE001 -- the flow is being abandoned anyway
                pass
            self._finish(reason)

    def _finish(self, reason: str) -> None:
        self.screen = None
        self.reason = reason
        self.finished.set()

    def view(self) -> dict:
        with self.lock:
            if self.finished.is_set():
                status = None
                if self.reason == "completed" and self.status_of is not None:
                    try:
                        status = self.status_of()
                    except Exception:  # noqa: BLE001
                        status = None
                return {"done": True, "reason": self.reason, "status": status}
            return {"screen": self.screen}

    # -- connection bookkeeping -------------------------------------------
    def touch(self) -> None:
        self.last_seen = time.monotonic()
        self.closing_at = None


def _assets_dir() -> Path:
    root = Path(envvars.get("WEB_ASSETS") or ASSET_DIR)
    if not (root / "index.html").is_file():
        raise WebUiUnavailable(
            f"The browser UI is not built ({root / 'index.html'} is missing). "
            f"Run `pnpm install && pnpm build:embed` in web/, and run it again.")
    return root


def _make_handler(session: Session, port: int, assets: Path, limits: Limits):
    host_ok = f"127.0.0.1:{port}"
    origin_ok = f"http://127.0.0.1:{port}"
    asset_root = assets.resolve()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "thyra-vault"
        sys_version = ""

        # Never log: request lines can carry a launch code, and a body log
        # would be a password log.
        def log_message(self, *args, **kwargs):  # noqa: D401
            return

        # -- response helpers ---------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, *, extra=None, head=False):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Content-Security-Policy", CSP)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _json(self, status: int, payload: dict):
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def _deny(self, status=403, code="forbidden"):
            self._json(status, {"error": code})

        # -- request guards -----------------------------------------------
        def _guard_origin(self) -> bool:
            """Reject DNS-rebinding and cross-site requests."""
            if self.headers.get("Host", "") != host_ok:
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != origin_ok:
                return False
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None and site not in ("same-origin", "none"):
                # One exception: the browser is sent here by a local start page
                # (file://, see _write_start_page), so the very first request is a
                # top-level navigation that the browser labels cross-site. Allow
                # exactly that -- loading the static page -- and nothing else. The
                # page holds no secret, framing is refused, and every API call is
                # still same-origin only.
                is_page_navigation = (
                    self.command in ("GET", "HEAD")
                    and not urlsplit(self.path).path.startswith("/api/")
                    and self.headers.get("Sec-Fetch-Mode") == "navigate"
                    and self.headers.get("Sec-Fetch-Dest") == "document")
                if not is_page_navigation:
                    return False
            return True

        def _authed(self) -> bool:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(header[7:].encode("utf-8"), session.token.encode("utf-8"))

        timeout = SOCKET_TIMEOUT

        def _read_json(self, limit: int = MAX_BODY) -> Optional[dict]:
            if not (self.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    == "application/json"):
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return None
            if length < 0 or length > limit:
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, UnicodeDecodeError):
                return None
            return data if isinstance(data, dict) else None

        # -- routing -------------------------------------------------------
        def do_GET(self):
            self._get(head=False)

        def do_HEAD(self):
            self._get(head=True)

        def _get(self, head: bool):
            if not self._guard_origin():
                return self._deny()
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                if not self._authed():
                    return self._deny(401, "unauthorized")
                if path == "/api/screen":
                    session.touch()
                    return self._json(200, session.view())
                return self._deny(404, "not_found")
            self._static(path, head)

        def do_POST(self):
            if not self._guard_origin():
                return self._deny()
            path = urlsplit(self.path).path
            if path == "/api/exchange":
                body = self._read_json(MAX_BODY_UNAUTH)
                if body is None:
                    self.close_connection = True
                    return self._deny(400, "bad_request")
                return self._exchange(body)
            # Everything else needs the token FIRST: an unauthenticated caller does
            # not get its body read or parsed. The unread body would desync a
            # keep-alive connection, so that connection is closed.
            if not self._authed():
                self.close_connection = True
                return self._deny(401, "unauthorized")
            body = self._read_json()
            if body is None:
                self.close_connection = True
                return self._deny(400, "bad_request")
            session.touch()
            if path == "/api/ping":
                return self._json(200, {"ok": True})
            if path == "/api/closing":
                session.closing_at = time.monotonic()
                return self._json(200, {"ok": True})
            if path == "/api/action":
                screen_id, action_id = body.get("screen"), body.get("action")
                values = body.get("values", {})
                if not isinstance(screen_id, str) or not isinstance(action_id, str) \
                        or not isinstance(values, dict):
                    return self._deny(400, "bad_request")
                try:
                    return self._json(200, session.act(screen_id, action_id, values))
                except StaleScreen:
                    # The page raced itself (double click, old tab): re-sync it.
                    return self._json(409, dict(session.view(), error="stale"))
            return self._deny(404, "not_found")

        def _exchange(self, body: dict):
            code = body.get("code")
            if session.code_used:
                # Once the page has connected the code is spent. Further attempts
                # are refused WITHOUT counting: a stranger's failed guesses must not
                # be able to end the human's session.
                return self._deny(403, "invalid_code")
            ok = (isinstance(code, str) and not session.code_used
                  and hmac.compare_digest(code.encode("utf-8"), session.code.encode("utf-8")))
            if not ok:
                session.bad_codes += 1
                if session.bad_codes >= limits.max_bad_codes:
                    session.cancel("error")
                return self._deny(403, "invalid_code")
            session.code_used = True
            session.connected = True
            session.touch()
            self._json(200, {"token": session.token})

        # Anything else is not part of this server.
        def _not_allowed(self):
            self._deny(405, "method_not_allowed")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

        # -- static files --------------------------------------------------
        def _static(self, path: str, head: bool):
            rel = unquote(path).lstrip("/")
            if "\x00" in rel or "\\" in rel:
                return self._deny(400, "bad_request")
            target = (asset_root / (rel or "index.html")).resolve()
            try:
                target.relative_to(asset_root)
            except ValueError:
                return self._deny(403)
            if not target.is_file():
                if "." in Path(rel).name:
                    return self._deny(404, "not_found")
                target = asset_root / "index.html"  # single-page-app fallback
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/json", "image/svg+xml"):
                ctype += "; charset=utf-8" if "charset" not in ctype else ""
            self._send(200, target.read_bytes(), ctype, head=head)

    return Handler


# --- opening the page -------------------------------------------------------
#
# By default the dialog opens as a small APPLICATION WINDOW (no tabs, no address
# bar) in a Chromium-based browser (Edge, Chrome, Brave, Chromium) -- it looks and
# behaves like a small desktop dialog. The window gets its own throwaway profile, which
# is deliberate and is a security property, not a convenience:
#
#   * no browser extensions run in it, so none can read the page or the password;
#   * no history, autofill, password-manager prompt or sync of the launch link;
#   * the window is OUR process: when it is closed we know at once (no waiting for
#     a heartbeat), and when the dialog ends we close it and delete the profile.
#
# Anything else (Firefox, Safari, no Chromium installed, THYRA_VAULT_WINDOW=tab)
# falls back to a normal tab in the default browser.

WINDOW_SIZE = (560, 780)
_APP_FLAGS = ("--no-first-run", "--no-default-browser-check", "--disable-extensions",
              "--disable-save-password-bubble", "--disable-features=PasswordManagerOnboarding",
              "--disable-sync", "--disable-background-networking", "--disable-component-update")
_LINUX_NAMES = ("brave-browser", "brave", "google-chrome", "google-chrome-stable", "chromium",
                "chromium-browser", "microsoft-edge", "microsoft-edge-stable")


def _windows_candidates() -> list:
    roots = [os.environ.get(k) for k in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
    rel = ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe",
           "BraveSoftware/Brave-Browser/Application/brave.exe")
    return [str(Path(r) / x) for r in roots if r for x in rel]


def _mac_candidates() -> list:
    return [f"/Applications/{app}.app/Contents/MacOS/{app}" for app in
            ("Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium")]


def _default_browser_hint() -> Optional[str]:
    """The desktop's default browser, so a user's own choice wins when it is Chromium-based."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        out = subprocess.run(["xdg-settings", "get", "default-web-browser"], capture_output=True,
                             text=True, timeout=2).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out[:-len(".desktop")] if out.endswith(".desktop") else (out or None)


def find_app_browser() -> Optional[str]:
    """Path of a Chromium-based browser that can show an app window, or None."""
    if sys.platform.startswith("win"):
        return next((c for c in _windows_candidates() if Path(c).is_file()), None)
    if sys.platform == "darwin":
        return next((c for c in _mac_candidates() if Path(c).is_file()), None)
    hint = _default_browser_hint()
    names = ([hint] if hint else []) + [n for n in _LINUX_NAMES if n != hint]
    for name in names:
        found = shutil.which(name)
        if found and name in _LINUX_NAMES:
            return found
    return None


def app_command(browser: str, url: str, profile: str, size: Optional[tuple] = None) -> list:
    """The argv for an app window. A list, never a shell string."""
    w, h = size or WINDOW_SIZE
    return [browser, f"--app={url}", f"--user-data-dir={profile}", f"--window-size={w},{h}",
            *_APP_FLAGS]


# Preferences written into the throwaway profile before the browser starts, so a fresh profile does not
# nag: no "save this password?" bubble for the master password, no autofill, and no analytics notice
# (Brave shows one on the first run of every new profile). The first group lives in the profile
# (Default/Preferences); Brave's analytics settings live in the browser-wide "Local State" file.
_PROFILE_PREFS = {
    "credentials_enable_service": False,
    "profile": {"password_manager_enabled": False},
    "autofill": {"profile_enabled": False, "credit_card_enabled": False},
}
_LOCAL_STATE = {
    "brave": {"p3a": {"enabled": False, "notice_acknowledged": True},
              "stats": {"reporting_enabled": False}},
}


def _seed_profile(profile: str) -> None:
    try:
        root = Path(profile)
        default = root / "Default"
        default.mkdir(mode=0o700, exist_ok=True)
        (default / "Preferences").write_text(json.dumps(_PROFILE_PREFS), encoding="utf-8")
        (root / "Local State").write_text(json.dumps(_LOCAL_STATE), encoding="utf-8")
    except OSError:
        pass  # only cosmetic: the window still works, it just may show the browser's own prompts


class AppWindow:
    """A browser window this server launched, and therefore can watch and close."""

    def __init__(self, proc: "subprocess.Popen", profile: str, tracked: bool):
        self.proc, self.profile, self.tracked = proc, profile, tracked

    def alive(self) -> bool:
        return self.proc.poll() is None

    def _signal_tree(self, hard: bool) -> None:
        """Signal the browser AND its children: a browser started through a
        launcher script has the script as its direct child, and ending only that
        would leave the real window (and its helper processes) running."""
        if os.name == "nt":
            subprocess.run(["taskkill", "/T"] + (["/F"] if hard else []) + ["/PID", str(self.proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            return
        try:
            os.killpg(self.proc.pid, signal.SIGKILL if hard else signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    def close(self) -> None:
        for hard in (False, True):
            self._signal_tree(hard)
            deadline = time.monotonic() + 3
            while self.alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not self.alive():
                break
        # The launcher can be gone while helpers linger for a moment; give the
        # profile's files time to be released before deleting it.
        for _ in range(20):
            shutil.rmtree(self.profile, ignore_errors=True)
            if not os.path.exists(self.profile):
                break
            time.sleep(0.15)


def _launch_app_window(url: str, size_key: Optional[str] = None) -> Optional[AppWindow]:
    browser = find_app_browser()
    if not browser:
        return None
    profile = tempfile.mkdtemp(prefix="thyra-vault-window-")  # 0700, ours alone
    _seed_profile(profile)
    try:
        # Its own process group / session, so the whole browser can be ended as one.
        group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
                 else {"start_new_session": True})
        proc = subprocess.Popen(app_command(browser, url, profile, _sizes.get(size_key or url)), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **group)
    except OSError:
        shutil.rmtree(profile, ignore_errors=True)
        return None
    try:
        # A browser that dies at once did not start (or handed the URL to an
        # already-running instance and left). Exit 0 means the latter: the window
        # exists but cannot be watched. Anything else: use a plain tab instead.
        code = proc.wait(timeout=1.5)
    except subprocess.TimeoutExpired:
        return AppWindow(proc, profile, tracked=True)
    if code == 0:
        return AppWindow(proc, profile, tracked=False)
    shutil.rmtree(profile, ignore_errors=True)
    return None


_windows: dict = {}
_sizes: dict = {}  # url -> (width, height), for the app window that url opens


_START_PAGE = ("<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer>"
               "<title>Thyra Vault</title><script>location.replace(%s)</script>"
               "<noscript>Thyra Vault needs JavaScript.</noscript>")
_bootstraps: dict = {}  # url -> the temp folder holding its start page


def _write_start_page(url: str) -> Optional[tuple]:
    """A tiny local page that forwards the browser to ``url``.

    Without it the single-use launch code sits in the browser's command line
    (``--app=http://127.0.0.1:PORT/#c=CODE``), readable in the process list by
    anything on the machine -- including other users -- and in any log that records
    process starts. In a 0700 folder, in a 0600 file, deleted as soon as the page
    has connected, the code is not there. (Another process of the SAME user could
    still read the file in the instant before that: this narrows the window, it
    does not close it. See the README.)
    """
    try:
        folder = tempfile.mkdtemp(prefix="thyra-vault-start-")  # 0700
        page = Path(folder) / "start.html"
        fd = os.open(page, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_START_PAGE % json.dumps(url))
        return page.as_uri(), folder
    except OSError:
        return None


def _forget_start_page(url: str) -> None:
    folder = _bootstraps.pop(url, None)
    if folder:
        shutil.rmtree(folder, ignore_errors=True)


def _default_open(url: str) -> bool:
    if envvars.get("NO_BROWSER"):
        return False
    start = _write_start_page(url)
    if start:
        _bootstraps[url] = start[1]
    target = start[0] if start else url
    if envvars.get("WINDOW", "app").strip().lower() != "tab":
        window = _launch_app_window(target, size_key=url)
        if window is not None:
            _windows[url] = window
            return True
    try:
        return bool(webbrowser.open(target, new=1))
    except Exception:  # noqa: BLE001
        return False


def _window_closed(url: str) -> bool:
    """True when we launched a trackable app window and the human has closed it."""
    window = _windows.get(url)
    return bool(window and window.tracked and not window.alive())


def _close_window(url: str) -> None:
    window = _windows.pop(url, None)
    if window is not None:
        window.close()


# Overridable seams (tests replace these; nothing else should).
_open_url: Callable[[str], bool] = _default_open
_on_ready: Optional[Callable[[str, "Session"], None]] = None


def run_flow(flow, *, status_of: Optional[Callable[[], Optional[str]]] = None,
             limits: Optional[Limits] = None, window_size: Optional[tuple] = None) -> None:
    """Show one dialog in the browser and block until it is over.

    Returns when the flow completes or the human leaves (tab closed, timeout).
    If the flow itself raised, the exception is re-raised here after the server
    is torn down. ``flow``'s caller owns the ``outcome`` dict; leaving early
    leaves it at its denied defaults.
    """
    limits = limits or Limits()
    assets = _assets_dir()
    session = Session(flow, status_of=status_of)
    session.start()
    if session.finished.is_set():
        if session.error:
            raise session.error
        return

    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.RequestHandlerClass = _make_handler(session, port, assets, limits)
    server.daemon_threads = True
    # A peer that drops mid-response would print a traceback to stderr, which an MCP
    # host may capture. Nothing useful is in it.
    server.handle_error = lambda request, client_address: None
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2},
                              name="thyra-vault-webui", daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/#c={session.code}"
    started = time.monotonic()
    if window_size:
        _sizes[url] = window_size
    try:
        if _on_ready is not None:
            _on_ready(url, session)
        if not _open_url(url):
            # Never print the launch code unless there is no other way in: the
            # MCP host may capture stderr.
            print(f"Thyra Vault: open this link in your browser to continue: {url}",
                  file=sys.stderr, flush=True)
        while not session.finished.wait(0.25):
            now = time.monotonic()
            if session.connected and url in _bootstraps:
                _forget_start_page(url)  # the code has been used: the start page is no longer needed
            if _window_closed(url):
                session.cancel("closed")  # the human closed the window: same as cancelling
            elif now - started > limits.max_lifetime:
                session.cancel("timeout")
            elif not session.connected:
                if now - started > limits.launch_timeout:
                    session.cancel("timeout")
            elif now - session.last_seen > limits.heartbeat_timeout:
                session.cancel("closed")
            elif session.closing_at is not None and now - session.closing_at > limits.closing_grace:
                session.cancel("closed")
        time.sleep(0.25)  # let the final response reach the page
    finally:
        session.cancel("error")  # no-op if already finished
        server.shutdown()
        server.server_close()
        _close_window(url)
        _forget_start_page(url)
        _sizes.pop(url, None)
    if session.error:
        raise session.error
