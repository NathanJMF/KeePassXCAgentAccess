"""Fixed HTML form delivery with an offline browser and trusted TLS transport."""

from contextlib import contextmanager
from http.client import HTTPException
from http.cookiejar import CookieJar
import os
from pathlib import Path
from select import select
import subprocess
from types import SimpleNamespace
from urllib.parse import urlencode, urljoin
from urllib.request import Request
from uuid import uuid4
import zlib

from .access_settings import Destination
from .command_action import stop_scope, syscall_filter, verify_scope_limits
from .https_action import failure, prepare_https
from .protocol import decode, encode


_HTML_LIMIT = 128 * 1024
_BROWSER_MEMORY = 768 * 1024**2
_BROWSER_TASKS = 96
_FORM_ENCODING = "application/x-www-form-urlencoded"
_UNCERTAIN = {"outcome": "uncertain"}


def inspect_html(document, url, config):
    scope = f"keeper-browser-{uuid4().hex}.scope"
    environment = {name: os.environ[name] for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
                   if name in os.environ}
    helper = Path(__file__).resolve().with_name("browser_document.py")
    with syscall_filter(unix_sockets=True, unix_socket_pairs=True) as seccomp:
        arguments = [
            "/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet", "--expand-environment=no",
            f"--unit={scope}", "--property=RuntimeMaxSec=12s", "--property=TimeoutStopSec=1s",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
            f"--property=MemoryMax={_BROWSER_MEMORY}", "--property=MemorySwapMax=0",
            f"--property=TasksMax={_BROWSER_TASKS}", "--property=CPUQuota=100%",
            "--", "/usr/bin/prlimit", "--core=0:0", "--fsize=8388608:8388608", "--",
            "/usr/bin/setpriv", "--no-new-privs", "--",
            "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
            "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--size", "16777216", "--tmpfs", "/tmp",
            "--dir", "/tmp/.X11-unix", "--chdir", "/tmp", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin",
            "--setenv", "GDK_BACKEND", "x11", "--setenv", "WEBKIT_DISABLE_COMPOSITING_MODE", "1",
            "--setenv", "GTK_IM_MODULE", "simple", "--seccomp", str(seccomp),
            "--ro-bind", str(helper), "/inspect.py", "--", "/usr/bin/python3", "-I", "/inspect.py",
        ]
        process = subprocess.Popen(
            arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd="/", env=environment, start_new_session=True, pass_fds=(seccomp,),
        )
        try:
            if not select([process.stdout], [], [], 3)[0] or os.read(process.stdout.fileno(), 1) != b"1":
                raise OSError("The private browser did not start.")
            verify_scope_limits(process.pid, scope, memory_limit=_BROWSER_MEMORY, task_limit=_BROWSER_TASKS)
            data, _ = process.communicate(encode({"document": document, "url": url, "config": config}), timeout=8)
            if process.returncode != 0 or not 0 < len(data) <= 8192:
                raise OSError("The private browser did not return a result.")
            return decode(data)
        finally:
            if process.poll() is None:
                stop_scope(scope, environment)
                if process.poll() is None:
                    process.kill()
            process.wait()
            process.stdin.close()
            process.stdout.close()


def _html(response):
    encoding = (response.headers.get("Content-Encoding") or "identity").strip().lower()
    if (response.headers.get_content_type() != "text/html"
            or response.headers.get_content_charset() not in (None, "utf-8")
            or encoding not in ("identity", "gzip")):
        return None
    data = response.read(_HTML_LIMIT + 1)
    if len(data) > _HTML_LIMIT:
        return None
    if encoding == "gzip":
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = decompressor.decompress(data, _HTML_LIMIT + 1)
            if len(data) > _HTML_LIMIT or decompressor.unconsumed_tail:
                return None
            data += decompressor.flush(_HTML_LIMIT + 1 - len(data))
        except zlib.error:
            return None
        if len(data) > _HTML_LIMIT or not decompressor.eof:
            return None
    return data.decode("utf-8")


def _headers(cookies, url, method):
    request = Request(url, method=method)
    cookies.add_cookie_header(request)
    return request, dict(request.header_items())


def _cookies(cookies, response, request):
    cookies.extract_cookies(SimpleNamespace(info=lambda: response.headers), request)


def _hidden(form, profile):
    if not isinstance(form, dict) or set(form) != {"action", "hidden"}:
        raise ValueError("No matching sign-in form.")
    if Destination.parse(form["action"]).url != profile.submit_url:
        raise ValueError("The form targets an unapproved endpoint.")
    controls = form["hidden"]
    if not isinstance(controls, list) or len(controls) > 16:
        raise ValueError("Unsupported sign-in form controls.")
    names = {profile.username_field, profile.password_field}
    fields = []
    for control in controls:
        if (not isinstance(control, list) or len(control) != 2
                or any(not isinstance(value, str) for value in control)):
            raise ValueError("Unsupported sign-in form controls.")
        name, value = control
        if (not name or not name.isascii() or not name.isprintable() or len(name) > 80 or name in names
                or len(value.encode("utf-8")) > 1024 or "\0" in value):
            raise ValueError("Unsupported sign-in form controls.")
        names.add(name)
        fields.append((name, value))
    if len(urlencode(fields)) > 4096:
        raise ValueError("Unsupported sign-in form controls.")
    return fields


def _get(url, cookies):
    with prepare_https(url) as (connection, path):
        request, headers = _headers(cookies, url, "GET")
        connection.request("GET", path, headers=headers)
        with connection.getresponse() as response:
            if response.status == 200:
                _cookies(cookies, response, request)
                return _html(response)
    return None


@contextmanager
def prepare_browser(url, profile, entry):
    credentials = (entry.username, entry.password)
    if any(not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096 for value in credentials):
        raise ValueError("The entry requires a username and password.")
    cookies = CookieJar()
    document = _get(url, cookies)
    if document is None:
        raise ValueError("The configured sign-in page is unavailable.")
    form = inspect_html(document, url, {
        "form_id": profile.form_id, "username_field": profile.username_field, "password_field": profile.password_field,
    })
    controls = _hidden(form, profile)
    encoded = urlencode([*controls, (profile.username_field, credentials[0]),
                         (profile.password_field, credentials[1])]).encode("ascii")
    with prepare_https(profile.submit_url) as (connection, path):
        yield lambda: submit_form(connection, path, profile, cookies, encoded)


def submit_form(connection, path, profile, cookies, encoded):
    request, headers = _headers(cookies, profile.submit_url, "POST")
    headers["Content-Type"] = _FORM_ENCODING
    try:
        connection.request("POST", path, body=encoded, headers=headers)
        with connection.getresponse() as response:
            status = response.status
            if not 200 <= status < 500:
                return _UNCERTAIN
            _cookies(cookies, response, request)
            if status in (302, 303) and profile.success_url:
                location = response.getheader("Location")
                redirect = Destination.parse(urljoin(profile.submit_url, location)).url if location else None
                if redirect != profile.success_url:
                    return _UNCERTAIN
                document = None
            elif 200 <= status < 300:
                document = _html(response)
            elif 400 <= status < 500:
                return {"outcome": "failed", "http_status": status}
            else:
                return _UNCERTAIN
        url = profile.submit_url
        if status in (302, 303):
            url = profile.success_url
            document = _get(url, cookies)
        matched = document is not None and inspect_html(document, url, {"success_id": profile.success_id}) is True
        if not matched:
            return _UNCERTAIN
        # The confirmation GET must itself return HTTP 200.
        return {"outcome": "succeeded", "http_status": 200 if status in (302, 303) else status}
    except (HTTPException, OSError, ValueError, subprocess.SubprocessError):
        return _UNCERTAIN
