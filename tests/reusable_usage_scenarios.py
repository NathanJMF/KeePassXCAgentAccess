"""Installed-skill credential delivery, without any configured action bindings."""

from base64 import b64encode
from dataclasses import replace
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic, sleep
from unittest.mock import patch
from uuid import uuid4

from pykeepass import PyKeePass

from broker_scenarios import PASSWORD, REPO, prepare
from browser_scenarios import SECRET, SESSION, USER, fixture
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.installation import Installation
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from tls_fixture import tls_service


def site(calls, accepted):
    base = fixture(calls)

    class Service(base):
        def api(self, body=b""):
            basic = "Basic " + b64encode(f"{USER}:{SECRET}".encode()).decode()
            valid = self.headers.get("Authorization") in (basic, "Bearer " + SECRET) or self.headers.get("X-API-Key") == SECRET
            if body:
                try:
                    value = json.loads(body)
                    valid = valid or value.get("credential") == SECRET
                except ValueError:
                    valid = False
            accepted.append((self.command, self.path, bool(valid)))
            # Deliberately reflect the credential. Keeper must never return this.
            self.html(SECRET, status=200 if valid else 401)

        def do_GET(self):
            if self.path.split("?", 1)[0] in ("/api", "/command"):
                self.api()
            else:
                super().do_GET()

        def do_POST(self):
            if self.path == "/api":
                self.api(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            else:
                super().do_POST()
    return Service


def wait_for(check, timeout=40):
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if value := check():
            return value
        sleep(.05)
    raise AssertionError("The synthetic credential operation did not complete.")


def check(root, hold=False):
    target, _, private, _ = prepare(root)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    state = root / "state"
    uid, gid = subordinate_ids()
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    engine = ScopedBroker(workspace, grants, activity)
    skill = root / "Documents/Skills/Keeper/SKILL.md"
    with patch("keepassxc_agent_access.installation.GLib.get_user_data_dir", return_value=str(root / "data")), \
            patch("keepassxc_agent_access.installation.GLib.get_user_config_dir", return_value=str(root / "config")), \
            patch("keepassxc_agent_access.installation.skill_destination", return_value=skill), \
            patch("keepassxc_agent_access.installation.stop_application"), \
            patch("keepassxc_agent_access.installation.external_broker_active", return_value=True):
        installation = Installation()
        installation.install(False)
    driver = installation.app / "fixture_entrypoint.py"
    driver.write_text(
        "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).parent / 'src'))\n"
        "from keepassxc_agent_access.agent_entrypoint import main\n"
        f"raise SystemExit(main(_runtime=Path({str(runtime)!r}), _state=Path({str(state)!r}), _checkout=Path({str(installation.app)!r})))\n")
    frontend = installation.app / "keeper-agent"
    frontend.write_text("#!/bin/sh\nexec /usr/bin/python3 -I " + shlex.quote(str(driver)) + ' "$@"\n')
    frontend.chmod(0o755)
    launcher = skill.with_name("keeper-agent")
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime)):
        subprocess.run([installation.app / "keeper-run-agent", "--prepare-socket"], check=True)
    calls, accepted = [], []
    broker = None
    stopped = Event()
    owner = None

    def invoke(profile, *args, data=None, error=False):
        prefix = [launcher, "--profile", profile, "--note", "Synthetic reusable credential trial"] if profile else [launcher]
        process = subprocess.run([*prefix, *args], cwd="/tmp", capture_output=True, text=True,
                                 input=json.dumps(data) if data is not None else None, timeout=45)
        assert all(secret not in process.stdout + process.stderr for secret in (PASSWORD, SECRET, SESSION))
        if error:
            assert process.returncode and not process.stdout
            return process.stderr
        assert process.returncode == 0 and not process.stderr, (process.returncode, process.stdout, process.stderr)
        return json.loads(process.stdout)

    try:
        with tls_service(private, handler=site(calls, accepted)) as (certificate, url, _):
            database = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
            entries = {}
            for name, path in (("Reusable API", "/api"), ("Reusable Browser", "/login"), ("Reusable Command", "/command")):
                entry = database.add_entry(database.root_group, name, USER, SECRET, url=url + path)
                entries[name] = str(entry.uuid)
            database.save()
            with patch.dict(os.environ, SSL_CERT_FILE=str(certificate)):
                first = workspace.add(target, PASSWORD, False, name="Harbor Credential Trial")
                copied = private / "second.kdbx"
                shutil.copyfile(target.database, copied)
                second = workspace.add(replace(target, database=copied), PASSWORD, False, name="Meadow Isolated Copy")
            workspace.lock(second)
            workspace.pause(False)
            assert all(not record.bindings for record in workspace.registrations.values())
            origin = url + "/"
            broker = ListingBroker(BrokerConfig(runtime / "keeper-scoped-runner/broker.sock", uid), lambda: engine, engine)
            broker.start()

            def eligible(items):
                return bool(items) and all(item.vault == first and item.entry in entries.values()
                                          and not item.action and not item.edits
                                          and set(item.origins) <= {origin} for item in items)

            def owner_review():
                while not stopped.wait(.02):
                    with workspace.mutex:
                        for grant in grants.rows():
                            if grant.status == "pending" and eligible(grant.items):
                                choices = [grants.choices(item) for item in grant.items]
                                if all(len(matches) == 1 for matches in choices):
                                    grants.decide(grant.id, [matches[0] for matches in choices])
                            pending = grant.pending_change
                            if pending and eligible(pending.items):
                                choices = [grants.choices(item) for item in pending.items]
                                if all(len(matches) == 1 for matches in choices):
                                    grants.decide(grant.id, [matches[0] for matches in choices], change_id=pending.id)
                    for ticket in engine.approvals.pending():
                        engine.approvals.resolve(ticket.id, True)

            owner = Thread(target=owner_review, daemon=True)
            owner.start()
            if hold:
                print(f"Installed synthetic skill: {skill}", flush=True)
                try:
                    while True:
                        sleep(.2)
                except KeyboardInterrupt:
                    print(json.dumps({"grants": len(grants.rows()), "authenticated_api_requests": sum(row[2] for row in accepted),
                                      "browser_submissions": sum(row == ("POST", "/submit") for row in calls),
                                      "authenticated_command_requests": sum(path == "/command" and valid for _, path, valid in accepted),
                                      "configured_actions": sum(len(record.bindings) for record in workspace.registrations.values())}), flush=True)
                    return

            profile = invoke(None, "begin", "--identity", "Reusable Delivery Verifier", "--project", "Synthetic Trial")["profile"]
            discovered = invoke(profile, "discover", "--json")
            assert len(discovered["vaults"]) == 2
            def permissions(body=False):
                return [
                    {"vault": first, "entry": entries["Reusable API"], "metadata": True, "url": True,
                     "uses": ["https", *(["https_body"] if body else [])], "origins": [origin]},
                    {"vault": first, "entry": entries["Reusable Browser"], "uses": ["browser"], "origins": [origin]},
                    {"vault": first, "entry": entries["Reusable Command"], "uses": ["local_command", "networked_command"], "origins": [origin]},
                ]
            invoke(profile, "access", "request", "--json", data={"items": permissions()})
            wait_for(lambda: invoke(profile, "access", "status", "--details", "--json")["status"] == "active")
            def use(name, descriptor, error=False):
                return invoke(profile, "use", "--vault", first, "--entry", entries[name], "--json", data=descriptor, error=error)
            for auth in ("basic", "bearer", "template"):
                request = {"type": "https", "url": url + "/api", "auth": auth}
                if auth == "template":
                    request["headers"] = {"X-API-Key": "{{password}}"}
                assert use("Reusable API", request) == {"outcome": "succeeded", "http_status": 200}
            assert all(row[2] for row in accepted) and len(accepted) == 3
            request = {"type": "https", "url": url + "/api", "auth": "template", "method": "POST", "json": {"credential": "{{password}}"}}
            use("Reusable API", request, error=True)
            assert len(accepted) == 3
            invoke(profile, "access", "request", "--json", data={"items": permissions(True), "change_id": str(uuid4())})
            wait_for(lambda: "https_body" in invoke(profile, "access", "status", "--details", "--json")["scope"][0]["uses"])
            assert use("Reusable API", request) == {"outcome": "succeeded", "http_status": 200}
            browser = {"type": "browser", "url": url + "/login", "submit_url": url + "/submit", "form_id": "sign-in",
                       "username_field": "account", "password_field": "code", "success_id": "account-home", "success_url": url + "/account"}
            assert use("Reusable Browser", browser) == {"outcome": "succeeded", "http_status": 200}
            assert ("POST", "/submit") in calls
            if os.environ.get("KEEPER_TEST_LOCAL_SANDBOX") == "1":
                local = {"type": "local_command", "command": ["/usr/bin/cat"]}
                assert use("Reusable Command", local) == {"outcome": "dispatched"}
                script = ('test "$TRIAL_ENVIRONMENT" = present && '
                          'test -z "${DBUS_SESSION_BUS_ADDRESS-}${XDG_RUNTIME_DIR-}" || exit 2; '
                          'p=$("$GIT_ASKPASS" "Credential token"); '
                          "printf 'header = \"Authorization: Bearer %s\"\\n' \"$p\" | "
                          '/usr/bin/curl --config - --silent --cacert /keeper/trust.pem "$1"')
                network = {"type": "networked_command", "command": ["/usr/bin/sh", "-c", script, "keeper", url + "/command"],
                           "origin": origin, "prompt_variable": "GIT_ASKPASS", "prompt_contains": "Credential token",
                           "environment": {"TRIAL_ENVIRONMENT": "present"}}
                assert use("Reusable Command", network) == {"outcome": "dispatched"}
                wait_for(lambda: any(path == "/command" and valid for _, path, valid in accepted))
            invoke(profile, "entries", "list", "--vault", second, "--json", error=True)
            invoke(profile, "use", "--vault", second, "--entry", entries["Reusable API"], "--json", data=request, error=True)
            use("Reusable API", {"type": "https", "url": "https://unapproved.invalid/", "auth": "bearer"}, error=True)
            use("Reusable API", browser, error=True)
            # A real saved password replacement must not inherit reusable scope.
            current = workspace.session(first)
            api_row = next(row for row in current.entries if row["id"] == entries["Reusable API"])
            workspace.put_entry(first, api_row["group"], entry=entries["Reusable API"], title=api_row["title"],
                                username=USER, url=url + "/api", password=SECRET + "-replacement")
            assert "credential changed" in use("Reusable API", request, error=True).lower()
            workspace.pause()
            use("Reusable API", request, error=True)
            assert all(not record.bindings for record in workspace.registrations.values())
            rows = activity.rows()
            assert any(row["outcome"] == "Succeeded" and row["note"] == "Synthetic reusable credential trial" for row in rows)
            assert all(SECRET not in repr(row) and SESSION not in repr(row) for row in rows)
    finally:
        stopped.set()
        if owner:
            owner.join(2)
        if broker:
            broker.stop()
        workspace.lock_all()
        anchors = state / "keeper-agent-sessions"
        if anchors.exists():
            for anchor in anchors.iterdir():
                if not anchor.is_dir():
                    continue
                descriptor = os.open(anchor, os.O_PATH | os.O_DIRECTORY)
                try:
                    alter_acl(anchor, "-m", f"u:{uid}:rwx")
                    subprocess.run([*namespace(uid, gid), "/usr/bin/rm", "-rf", f"/proc/self/fd/{descriptor}/profile"],
                                   pass_fds=(descriptor,), check=True, cwd="/")
                finally:
                    os.close(descriptor)


if __name__ == "__main__":
    import sys
    with TemporaryDirectory(prefix="keeper-reusable-trial-") as temporary:
        check(Path(temporary), hold="--hold" in sys.argv)
    print("Reusable usage scenario passed: zero configured actions, installed skill, scoped API/browser/command delivery and Activity.")
