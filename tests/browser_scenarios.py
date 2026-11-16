"""Exercise fixed browser sign-ins through the isolated production runner."""

from dataclasses import replace
from http.server import BaseHTTPRequestHandler
import json
import os
import ssl
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs

from pykeepass import PyKeePass

from broker_scenarios import NAMESPACE, PASSWORD, REPO, prepare
from keepassxc_agent_access.access_settings import Action, ActionType, BrowserForm
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from test_agent_runner import call_tool
from tls_fixture import tls_service


USER = "synthetic-browser-user"
SECRET = "synthetic-browser-pass"
SESSION = "synthetic-browser-session"
CSRF = "synthetic-csrf"
FORM = """
<form id="sign-in" method="post" action="/submit">
  <input name="account" type="text">
  <input name="code" type="password">
  <input name="csrf" type="hidden" value="synthetic-csrf">
  <button type="submit">Continue</button>
</form>
"""


def fixture(calls):
    class LoginSite(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, ssl.SSLEOFError):
                # A dispatch denial can close the prepared TLS connection.
                pass

        def html(self, document, *, cookie=None, status=200):
            self.send_response(status)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(document.encode())

        def do_GET(self):
            calls.append(("GET", self.path))
            if self.path == "/login":
                # If website scripts ran they would change the credential destination.
                self.html("<script>document.write('<base href=\"https://bad.invalid/\">')</script>" + FORM,
                          cookie="initial=fixture; Secure; HttpOnly; Path=/")
            elif self.path == "/wrong-form":
                self.html('<base href="https://other.invalid/">' + FORM.replace('action="/submit"', 'action="submit"'))
            elif self.path == "/duplicate-form":
                self.html(FORM.replace('</form>', '<input name="code" type="hidden" value="override"></form>'))
            elif self.path == "/override-form":
                self.html(FORM.replace('<button type="submit">', '<button type="submit" formaction="/other">'))
            elif self.path == "/account" and self.headers.get("Cookie", "").find("session=" + SESSION) >= 0:
                self.html(f'<main id="account-home">{SECRET} {SESSION}</main>')
            else:
                self.html("Unknown page", status=404)

        def do_POST(self):
            calls.append(("POST", self.path))
            data = self.rfile.read(int(self.headers["Content-Length"]))
            form = parse_qs(data.decode("ascii"), strict_parsing=True)
            accepted = (self.headers.get("Cookie") == "initial=fixture"
                        and self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                        and form == {"account": [USER], "code": [SECRET], "csrf": [CSRF]})
            if not accepted or self.path != "/submit":
                self.html("Sign-in rejected", status=401)
                return
            self.send_response(303)
            self.send_header("Set-Cookie", f"session={SESSION}; Secure; HttpOnly; Path=/")
            self.send_header("Location", "/account")
            self.send_header("X-Echo", SECRET)
            self.end_headers()

    return LoginSite


def check(root):
    target, _, private, _ = prepare(root)
    database = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
    entry = database.add_entry(database.root_group, "Synthetic Browser Login", USER, SECRET)
    database.save()
    entry_id = str(entry.uuid)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    anchor = root / "state" / "keeper-scoped-runner" / "fixture"
    runner = REPO / "keeper-run-agent"
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_STATE_HOME=str(root / "state"))
    subprocess.run([runner, "--prepare-socket"], env=env, check=True)
    endpoint = runtime / "keeper-scoped-runner" / "broker.sock"
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    engine = ScopedBroker(workspace, grants, activity)
    uid, gid = subordinate_ids()
    broker = ListingBroker(BrokerConfig(endpoint, uid), lambda: engine, engine)
    calls = []

    def invoke(tool, arguments=None, *, error=False):
        executed = subprocess.run(
            [runner, "--profile", "fixture"], env=env, cwd="/tmp",
            input=json.dumps(call_tool(tool, arguments)) + "\n", text=True,
            capture_output=True, check=True, timeout=41,
        )
        assert all(value not in executed.stdout + executed.stderr for value in (USER, SECRET, SESSION, CSRF))
        reply = json.loads(executed.stdout)["result"]
        assert reply["isError"] == error, reply
        result = reply["content"][0]["text"]
        return json.loads(result) if result.startswith("{") else result

    try:
        subprocess.run([*NAMESPACE, "/usr/bin/test", "!", "-r", str(target.database)], check=True)
        with tls_service(private, handler=fixture(calls)) as (certificate, url, _):
            with patch.dict(os.environ, SSL_CERT_FILE=str(certificate)):
                vault = workspace.add(target, PASSWORD, False, name="Browser fixture")
            profile = BrowserForm(url + "/submit", "sign-in", "account", "code", "account-home", url + "/account")
            action = Action("sign-in", "Synthetic Browser Sign-in", entry_id, url + "/login",
                            kind=ActionType.BROWSER, browser=profile)
            wrong_form = replace(action, id="wrong-form", name="Wrong form fixture", url=url + "/wrong-form")
            duplicate = replace(action, id="duplicate-form", name="Duplicate form fixture", url=url + "/duplicate-form")
            override = replace(action, id="override-form", name="Submitter override fixture", url=url + "/override-form")
            wrong_redirect = replace(action, id="wrong-redirect", name="Wrong redirect fixture",
                                     browser=replace(profile, success_url=url + "/unexpected"))
            missing_marker = replace(action, id="missing-marker", name="Missing confirmation fixture",
                                     browser=replace(profile, success_id="no-such-marker"))
            bindings = (action, wrong_form, duplicate, override, wrong_redirect, missing_marker)
            for binding in bindings:
                workspace.save_binding(vault, binding)
            broker.start()
            request = {
                "identity": "Synthetic Browser Agent", "project": "Browser Fixture",
                "items": [{"vault": vault, "entry": entry_id, "action": binding.id}
                          for binding in bindings],
            }
            assert invoke("request_access", {"request": request}) == {"status": "pending"}
            record, = grants.rows()
            grants.decide(record.id, [grants.choices(item)[0] for item in record.items])
            workspace.pause(False)
            reference = {"vault": vault, "entry": entry_id, "action": action.id}
            invoke("use_password", {**reference, "url": url + "/other"}, error=True)
            assert not calls
            result = invoke("use_password", {**reference, "note": "Verify the scoped browser sign-in"})
            assert result == {"outcome": "succeeded", "http_status": 200}, result
            assert calls == [("GET", "/login"), ("POST", "/submit"), ("GET", "/account")], calls
            event, = activity.rows(action="Synthetic Browser Sign-in", outcome="Succeeded")
            assert event["destination"] == action.destination
            assert event["scope"] == profile.description
            assert event["note"] == "Verify the scoped browser sign-in"
            assert all(value.encode() not in activity.path.read_bytes() for value in (USER, SECRET, SESSION, CSRF))

            calls.clear()
            for malformed in (wrong_form, duplicate, override):
                assert invoke("use_password", {**reference, "action": malformed.id}, error=True) == {"outcome": "failed"}
            assert calls == [("GET", "/wrong-form"), ("GET", "/duplicate-form"), ("GET", "/override-form")], calls

            calls.clear()
            try:
                workspace.session(vault).worker.use(action, lambda _: False)
            except ListingError as error:
                assert error.code == "revoked"
            else:
                raise AssertionError("A revoked gate allowed the sign-in.")
            assert calls == [("GET", "/login")], calls

            calls.clear()
            assert invoke("use_password", {**reference, "action": wrong_redirect.id}, error=True) == {"outcome": "uncertain"}
            assert calls == [("GET", "/login"), ("POST", "/submit")], calls
            assert activity.rows(action="Wrong redirect fixture")[0]["outcome"] == "Interrupted · outcome unknown"
            calls.clear()
            assert invoke("use_password", {**reference, "action": missing_marker.id}, error=True) == {"outcome": "uncertain"}
            assert calls == [("GET", "/login"), ("POST", "/submit"), ("GET", "/account")], calls
            workspace.save_binding(vault, replace(action, browser=replace(profile, success_id="other")), action.id)
            invoke("use_password", reference, error=True)
            assert len(calls) == 3
    finally:
        broker.stop()
        workspace.lock_all()
        if anchor.is_dir():
            fd = os.open(anchor, os.O_PATH | os.O_DIRECTORY)
            try:
                alter_acl(anchor, "-m", f"u:{uid}:rwx")
                subprocess.run([*namespace(uid, gid), "/usr/bin/rm", "-rf",
                                f"/proc/self/fd/{fd}/profile"], cwd="/", pass_fds=(fd,), check=True)
            finally:
                os.close(fd)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="keeper-browser-") as directory:
        check(Path(directory))
    print("Browser scenario passed: real isolated runner and WebKit, private sign-in and cookies, pinned form, Activity.")
