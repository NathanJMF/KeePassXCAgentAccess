"""Exercise the production runner against a synthetic vault under a separate OS UID."""

from base64 import b64encode
from contextlib import nullcontext
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch
from uuid import UUID, uuid4

from pykeepass import PyKeePass

from broker_scenarios import NAMESPACE, PASSWORD, REPO, prepare
from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.command_action import executable_digest
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from test_agent_runner import call_tool
from tls_fixture import tls_service


def check(root):
    target, _, private, expected = prepare(root)
    owner_runtime = os.environ.get("XDG_RUNTIME_DIR")
    api_token = "synthetic_runner_api_token"
    database = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
    api_entry = database.add_entry(database.root_group, "Synthetic Runner API", "", api_token)
    database.save()
    api_header = f"Bearer {api_token}"
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_STATE_HOME=str(root / "state")):
        runner = REPO / "keeper-run-agent"
        subprocess.run([runner, "--prepare-socket"], check=True)
        endpoint = runtime / "keeper-scoped-runner" / "broker.sock"
        anchor = root / "state/keeper-scoped-runner/fixture"
        header = "Basic " + b64encode(b"synthetic user:synthetic credential").decode("ascii")
        with tls_service(private, authorization=header, extra_authorization=(api_header,)) as (certificate, url, calls):
            with patch.dict(os.environ, SSL_CERT_FILE=str(certificate)):
                check_tools(runner, anchor, target, endpoint, private, expected, url, calls, header, owner_runtime,
                            str(api_entry.uuid), api_token)


def check_tools(runner, anchor, target, endpoint, private, expected, url, calls, header, owner_runtime,
                api_entry, api_token):
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    edits = EditRequests(workspace, grants, activity)
    engine = ScopedBroker(workspace, grants, activity, edits=edits)
    uid, gid = subordinate_ids()
    broker = ListingBroker(BrokerConfig(endpoint, uid), lambda: engine, engine)

    def invoke(tool, arguments=None, *, error=False):
        process = subprocess.run(
            [runner, "--profile", "fixture"],
            cwd="/tmp", input=json.dumps(call_tool(tool, arguments)) + "\n", text=True,
            capture_output=True, check=True, timeout=12,
        )
        assert not any(secret in process.stdout for secret in (PASSWORD, header, "synthetic credential", api_token))
        reply = json.loads(process.stdout)["result"]
        assert process.stderr == ""
        assert reply["isError"] == error, reply
        content = reply["content"][0]["text"]
        return content if error else json.loads(content)

    try:
        api_body = '{"operation":"fixture-check"}'
        test_command = os.environ.get("KEEPER_TEST_LOCAL_SANDBOX") == "1"
        # The runner uses a disposable socket directory. The owner worker
        # connects to the desktop's systemd user manager for command scopes.
        environment = patch.dict(os.environ, XDG_RUNTIME_DIR=owner_runtime) if test_command else nullcontext()
        with environment:
            vault = workspace.add(target, PASSWORD, False, name="Runner fixture")
        row, unapproved = expected[:2]
        workspace.save_binding(vault, Action("health", "Runner Status Check", row["id"], url + "/health"))
        api = Action("api", "Runner API Check", api_entry, url + "/api", kind=ActionType.BEARER,
                     method="POST", request_json=api_body)
        workspace.save_binding(vault, api)
        command = None
        if test_command:
            check = "import hashlib,sys;sys.exit(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()!=sys.argv[1])"
            command = ("/usr/bin/python3", "-I", "-c", check, sha256(b"synthetic credential").hexdigest())
            workspace.save_binding(vault, Action("local", "Runner Local Check", row["id"], "", kind=ActionType.STDIN,
                                                 command=command, executable_sha256=executable_digest(command)))
        broker.start()
        subprocess.run([*NAMESPACE, "test", "!", "-r", str(target.database)], check=True)
        assert invoke("access_status") == {"status": "uninitialized"}
        request = {"identity": "Runner fixture", "project": "Synthetic",
                   "items": [{"metadata": True, "vault": vault, "entry": row["id"], "action": "health"}]}
        request["items"].append({"vault": vault, "entry": api_entry, "action": "api"})
        if command is not None:
            request["items"].append({"vault": vault, "entry": row["id"], "action": "local"})
        assert invoke("request_access", {"request": request}) == {"status": "pending"}
        record, = grants.rows()
        assert record.uid == uid
        choices = [grants.choices(item) for item in record.items]
        assert all(len(matches) == 1 for matches in choices)
        grants.decide(record.id, [matches[0] for matches in choices])
        assert invoke("access_status") == {"status": "active"}
        assert "paused" in invoke("list_entries", {"vault": vault}, error=True)
        workspace.pause(False)
        assert invoke("list_vaults") == {"vaults": [{"id": vault, "name": "Runner fixture"}]}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [row]}
        deadline = monotonic() + 2
        while monotonic() < deadline:
            grant, = grants.rows()
            if grant.last_used is not None:
                break
            sleep(.02)
        assert grant.id == record.id and grant.last_used is not None

        action = {"vault": vault, "entry": row["id"], "action": "health"}
        invoke("use_password", {**action, "entry": unapproved["id"]}, error=True)
        assert not calls
        assert invoke("use_password", action) == {"outcome": "succeeded", "http_status": 200}
        assert calls == [("/health", header)]
        api_use = {**action, "entry": api_entry, "action": "api"}
        for override in ({"method": "GET"}, {"request_json": "{}"}, {"url": url + "/other"}):
            invoke("use_password", {**api_use, **override}, error=True)
        assert calls == [("/health", header)]
        assert invoke("use_password", {**api_use, "note": "Verify fixed HTTPS API delivery"}) == {
            "outcome": "succeeded", "http_status": 200,
        }
        expected_calls = [("/health", header), ("POST", "/api", f"Bearer {api_token}", "application/json", api_body.encode())]
        assert calls == expected_calls
        event, = activity.rows(action="Runner API Check", outcome="Succeeded")
        assert event["destination"] == "POST " + url + "/api"
        assert event["note"] == "Verify fixed HTTPS API delivery"
        assert sha256(api_body.encode()).hexdigest() in event["scope"]
        assert all(value not in repr(event) for value in (api_body, api_token))
        workspace.save_binding(vault, replace(api, request_json='{"operation":"changed"}'), original="api")
        invoke("use_password", api_use, error=True)
        assert calls == expected_calls
        if command is not None:
            local = {**action, "action": "local", "command": command}
            invoke("use_password", {**local, "command": (*command, "--different")}, error=True)
            assert invoke("use_password", local) == {"outcome": "succeeded"}
            event, = activity.rows(action="Runner Local Check", outcome="Succeeded")
            assert event["destination"].startswith("Local stdin · /usr/bin/python3")
            assert "synthetic credential" not in repr(event)

        edit = {"id": str(uuid4()), "operation": "update_entry", "vault": vault,
                "entry": row["id"], "fields": {"title": "Reviewed Runner Entry"}}
        assert invoke("request_edit", {"request": edit, "note": "Verify the runner edit flow"}) == {
            "id": edit["id"], "status": "pending",
        }
        assert invoke("edit_status", {"id": edit["id"]}) == {"id": edit["id"], "status": "pending"}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [row]}
        edits.approve(edits.preview(record.id, edit["id"]))
        assert invoke("edit_status", {"id": edit["id"]}) == {"id": edit["id"], "status": "applied"}
        assert invoke("request_edit", {"request": edit}) == {"id": edit["id"], "status": "applied"}
        saved = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
        assert saved.find_entries(uuid=UUID(row["id"]), first=True).title == edit["fields"]["title"]
        updated = {**row, "title": edit["fields"]["title"]}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [updated]}
        event = next(event for event in activity.rows() if event["edit_request_id"] == edit["id"])
        assert event["note"] == "Verify the runner edit flow"

        change = {**request, "change_id": str(uuid4()),
                  "items": [{"metadata": True, "vault": vault, "entry": unapproved["id"]}]}
        workspace.acknowledge_token_auto_approval(True)
        workspace.set_token_auto_approval("auto_approve_token_changes", True)
        assert invoke("request_access", {"request": change}) == {"status": "active"}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [unapproved]}
        invoke("use_password", action, error=True)
        assert calls == expected_calls
        grants.transition(record.id, "disabled")
        assert invoke("access_status") == {"status": "disabled"}
        invoke("list_vaults", error=True)
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
    with TemporaryDirectory(prefix="keeper-runner-") as root:
        check(Path(root))
    print("Runner scenario passed: bundled runner, all seven stdio tools, separate peer UID, scoped TLS and fixed API delivery, persisted edits, and revocation")
