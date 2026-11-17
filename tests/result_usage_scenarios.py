"""Installed protected-result workflow with a live randomized inventory service."""

from dataclasses import replace
from hashlib import sha256
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import random
import secrets
import shlex
import shutil
import ssl
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic, sleep
from unittest.mock import patch
from urllib.parse import parse_qs
from uuid import uuid4

from pykeepass import PyKeePass

from broker_scenarios import PASSWORD, prepare
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.installation import Installation
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from tls_fixture import tls_service


def wait_for(check, timeout=12):
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if value := check():
            return value
        sleep(.04)
    raise AssertionError("The synthetic result operation did not complete.")


def inventory_site(state):
    class Site(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle(self):
            try:
                super().handle()
            except (OSError, ssl.SSLError):
                pass

        def respond(self, value, status=200, *, public=False):
            body = json.dumps(value).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                # Deliberately unsafe headers must never leave Keeper's worker.
                if not public:
                    self.send_header("X-Reflected-Credential", state["password"])
                    self.send_header("Set-Cookie", "session=" + state["ticket"])
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ssl.SSLError):
                pass

        def do_GET(self):
            if self.path == "/docs":
                # Public documentation contains no credential, ticket or answer.
                self.respond({"origin": state["origin"], "certificate_sha256": state["fingerprint"],
                    "login": {"path": "/auth/session", "form": {"username": "{{username}}", "password": "{{password}}"},
                              "capture": {"ticket": "/data/ticket"}},
                    "request": {"path": "/inventory", "auth": "session",
                                "headers": {"Authorization": "Bearer {{session.ticket}}"}},
                    "result": {"path": "/data", "columns": ["vmid", "name", "node", "status", "free_mib"]}}, public=True)
                return
            authorized = self.headers.get("Authorization") == "Bearer " + state["ticket"]
            state["requests"].append((self.path, authorized))
            if not authorized:
                self.respond({"error": "unauthorized"}, 401)
                return
            if self.path == "/inventory":
                rows = [{**row, "password": state["password"], "ticket": state["ticket"], "username": state["username"]}
                        for row in state["rows"]]
                self.respond({"data": rows})
            elif self.path == "/echo":
                self.respond({"data": [{**state["rows"][0], "name": state["password"]}]})
            else:
                self.respond({"error": "unknown"}, 404)

        def do_POST(self):
            size = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(min(size, 4096))
            form = parse_qs(body.decode(), strict_parsing=True)
            authorized = (self.path == "/auth/session" and form == {
                "username": [state["username"]], "password": [state["password"]]})
            state["logins"].append(authorized)
            if authorized:
                self.respond({"data": {"ticket": state["ticket"], "password": state["password"]}})
            else:
                self.respond({"error": "login denied"}, 401)
    return Site


def check(root, hold=False):
    target, _, private, _ = prepare(root)
    runtime, state_home = root / "runtime", root / "state"
    runtime.mkdir(mode=0o700)
    uid, gid = subordinate_ids()
    state = {"username": "user-" + secrets.token_hex(16), "password": "password-" + secrets.token_hex(24),
             "ticket": "ticket-" + secrets.token_hex(24), "logins": [], "requests": [], "reviews": []}
    vmids = random.sample(range(1000, 60000), 3)
    state["rows"] = [
        {"vmid": vmids[0], "name": "guest-" + secrets.token_hex(4), "node": "node-" + secrets.token_hex(3), "status": "stopped", "free_mib": random.randint(4096, 12000)},
        {"vmid": vmids[1], "name": "guest-" + secrets.token_hex(4), "node": "node-" + secrets.token_hex(3), "status": "running", "free_mib": 16000},
        {"vmid": vmids[2], "name": "guest-" + secrets.token_hex(4), "node": "node-" + secrets.token_hex(3), "status": "stopped", "free_mib": 1024},
    ]
    expected = {key: state["rows"][0][key] for key in ("vmid", "node", "name")}
    random.shuffle(state["rows"])
    decision = root / "decision.json"
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
    driver.write_text("import sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).parent/'src'))\n"
                      "from keepassxc_agent_access.agent_entrypoint import main\n"
                      f"raise SystemExit(main(_runtime=Path({str(runtime)!r}),_state=Path({str(state_home)!r}),_checkout=Path({str(installation.app)!r})))\n")
    executable = installation.app / "keeper-agent"
    executable.write_text("#!/bin/sh\nexec /usr/bin/python3 -I " + shlex.quote(str(driver)) + ' "$@"\n')
    executable.chmod(0o755)
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime)):
        subprocess.run([installation.app / "keeper-run-agent", "--prepare-socket"], check=True)
    launcher = skill.with_name("keeper-agent")
    stopped, owner, broker = Event(), None, None

    def invoke(profile, *args, request=None, rejected=False, failed=False):
        prefix = [launcher, "--profile", profile, "--note", "Read synthetic inventory to choose an eligible deployment guest"] if profile else [launcher]
        process = subprocess.run([*prefix, *args], cwd="/tmp", capture_output=True, text=True,
                                 input=json.dumps(request) if request is not None else None, timeout=30)
        assert all(value not in process.stdout + process.stderr for value in (PASSWORD, state["password"], state["username"], state["ticket"]))
        if rejected:
            assert process.returncode and not process.stdout, (process.returncode, process.stdout)
            return process.stderr
        assert process.returncode == (1 if failed else 0) and not process.stderr, (process.returncode, process.stdout, process.stderr)
        return json.loads(process.stdout)

    try:
        with tls_service(private, handler=inventory_site(state)) as (certificate, url, _):
            state["origin"] = url + "/"
            state["fingerprint"] = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
            database = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
            entry = database.add_entry(database.root_group, "Protected Inventory", state["username"], state["password"], url=url + "/inventory")
            database.save()
            entry_id = str(entry.uuid)
            with patch.dict(os.environ, SSL_CERT_FILE=str(certificate)):
                first = workspace.add(target, PASSWORD, False, name="Harbor Inventory Trial")
                duplicate = private / "copy.kdbx"
                shutil.copyfile(target.database, duplicate)
                second = workspace.add(replace(target, database=duplicate), PASSWORD, False, name="Meadow Inventory Copy")
            workspace.lock(second)
            workspace.pause(False)
            workspace.set_review_action("read_results", False)
            assert not workspace.requires_review("read_results") and not workspace.requires_review("use_https")
            assert all(not record.bindings for record in workspace.registrations.values())
            broker = ListingBroker(BrokerConfig(runtime / "keeper-scoped-runner/broker.sock", uid), lambda: engine, engine)
            broker.start()

            def eligible(items):
                return bool(items) and all(item.vault == first and item.entry == entry_id and not item.username
                    and not item.action and not item.edits and set(item.uses) <= {"https", "https_results", "https_body"}
                    and set(item.origins) <= {state["origin"]} for item in items)

            def owner_review():
                while not stopped.wait(.02):
                    with workspace.mutex:
                        for grant in grants.rows():
                            if grant.status == "pending" and eligible(grant.items):
                                grants.decide(grant.id, [grants.choices(item)[0] for item in grant.items])
                            pending = grant.pending_change
                            if pending and eligible(pending.items):
                                grants.decide(grant.id, [grants.choices(item)[0] for item in pending.items], change_id=pending.id)
                    for ticket in engine.approvals.pending():
                        # Independently approve only this fixture's actual certificate.
                        declared = " ".join(ticket.scope)
                        approved = state["fingerprint"] in declared
                        if engine.approvals.resolve(ticket.id, approved):
                            state["reviews"].append(approved)
            owner = Thread(target=owner_review, daemon=True)
            owner.start()
            if hold:
                print(f"Installed synthetic skill: {skill}", flush=True)
                print(f"Decision output: {decision}", flush=True)
                try:
                    while True:
                        sleep(.2)
                except KeyboardInterrupt:
                    selected = json.loads(decision.read_text()) if decision.exists() else None
                    print(json.dumps({"decision_matches_live_inventory": selected == expected,
                                      "authenticated_inventory_reads": sum(path == "/inventory" and ok for path, ok in state["requests"]),
                                      "successful_private_logins": sum(state["logins"]),
                                      "certificate_approval_prompts": len(state["reviews"]),
                                      "configured_actions": sum(len(row.bindings) for row in workspace.registrations.values())}), flush=True)
                    assert selected == expected, "Fresh agent did not choose the eligible live inventory row"
                    return

            profile = invoke(None, "begin", "--identity", "Inventory Result Consumer", "--project", "Synthetic Result Trial")["profile"]
            catalog = invoke(profile, "discover", "--json")
            assert len(catalog["vaults"]) == 2
            item = {"vault": first, "entry": entry_id, "metadata": True, "url": True}
            invoke(profile, "access", "request", "--json", request={"items": [item]})
            wait_for(lambda: invoke(profile, "access", "status", "--details", "--json")["status"] == "active")
            rows = invoke(profile, "entries", "list", "--vault", first, "--field", "url", "--json")["entries"]
            assert len(rows) == 1 and rows[0]["url"] == url + "/inventory"
            workflow = {"type": "https_results", "origin": state["origin"], "certificate_sha256": state["fingerprint"],
                        "login": {"path": "/auth/session", "form": {"username": "{{username}}", "password": "{{password}}"},
                                  "capture": {"ticket": "/data/ticket"}},
                        "request": {"path": "/inventory", "auth": "session", "headers": {"Authorization": "Bearer {{session.ticket}}"}},
                        "result": {"path": "/data", "columns": ["vmid", "name", "node", "status", "free_mib"]}}
            def use(value, **kwargs):
                return invoke(profile, "use", "--entry", entry_id, "--vault", first, "--json", request=value, **kwargs)
            use(workflow, rejected=True)
            item.update(uses=["https"], origins=[state["origin"]])
            change = {"items": [item], "change_id": str(uuid4())}
            invoke(profile, "access", "request", "--json", request=change)
            wait_for(lambda: invoke(profile, "access", "request", "--json", request=change)["status"] == "active")
            use(workflow, rejected=True)  # Old credential-use permission does not release results.
            item["uses"] = ["https_results", "https_body"]
            change = {"items": [item], "change_id": str(uuid4())}
            invoke(profile, "access", "request", "--json", request=change)
            wait_for(lambda: invoke(profile, "access", "request", "--json", request=change)["status"] == "active")
            result = use(workflow)
            eligible = [row for row in result["data"] if row["status"] == "stopped" and row["free_mib"] >= 4096]
            assert len(eligible) == 1
            selected = {key: eligible[0][key] for key in ("vmid", "node", "name")}
            assert selected == expected
            decision.write_text(json.dumps(selected))
            assert state["logins"] == [True] and state["requests"] == [("/inventory", True)]
            assert all(set(row) == set(workflow["result"]["columns"]) for row in result["data"])
            # The first verified owner approval remembers this token/resource's
            # certificate. Repeat reads (including a token-store reload) follow
            # Auto Approve without spawning more approval dialogs.
            assert state["reviews"] == [True]
            assert use(workflow)["data"] == result["data"]
            with workspace.mutex:
                grants = engine.grants = Grants(workspace, activity)
            assert use(workflow)["data"] == result["data"]
            assert state["reviews"] == [True] and len(state["logins"]) == 3
            invoke(profile, "use", "--entry", entry_id, "--vault", second, "--json", request=workflow, rejected=True)
            use({**workflow, "origin": "https://unapproved.invalid/"}, rejected=True)
            assert len(state["logins"]) == 3
            # Owner review independently rejects a substituted certificate pin.
            use({**workflow, "certificate_sha256": "0" * 64}, rejected=True)
            assert state["reviews"] == [True, False]
            assert len(state["logins"]) == 3
            echo = {**workflow, "request": {**workflow["request"], "path": "/echo"}}
            assert use(echo, failed=True)["outcome"] == "failed"
            workspace.pause()
            use(workflow, rejected=True)
            audit = repr(activity.rows())
            for value in (state["password"], state["ticket"], state["username"], *[row["name"] for row in state["rows"]]):
                assert value not in audit
            assert all(not row.bindings for row in workspace.registrations.values())
    finally:
        stopped.set()
        if owner:
            owner.join(2)
        if broker:
            broker.stop()
        workspace.lock_all()
        anchors = state_home / "keeper-agent-sessions"
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
    with TemporaryDirectory(prefix="keeper-result-trial-") as temporary:
        check(Path(temporary), hold="--hold" in sys.argv)
    print("Result usage scenario passed: private login, useful randomized inventory, consumer decision, scope and audit secrecy.")
