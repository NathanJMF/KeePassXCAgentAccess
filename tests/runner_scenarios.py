"""Exercise the production runner against a synthetic vault under a separate OS UID."""

from base64 import b64encode
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
from keepassxc_agent_access.access_settings import Action
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from test_agent_runner import call_tool
from tls_fixture import tls_service


def check(root):
    target, _, private, expected = prepare(root)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_STATE_HOME=str(root / "state")):
        runner = REPO / "keeper-run-agent"
        subprocess.run([runner, "--prepare-socket"], check=True)
        endpoint = runtime / "keeper-scoped-runner" / "broker.sock"
        anchor = root / "state/keeper-scoped-runner/fixture"
        header = "Basic " + b64encode(b"synthetic user:synthetic credential").decode("ascii")
        with tls_service(private, authorization=header) as (certificate, url, calls):
            with patch.dict(os.environ, SSL_CERT_FILE=str(certificate)):
                check_tools(runner, anchor, target, endpoint, private, expected, url, calls, header)


def check_tools(runner, anchor, target, endpoint, private, expected, url, calls, header):
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
        assert not any(secret in process.stdout for secret in (PASSWORD, header, "synthetic credential"))
        reply = json.loads(process.stdout)["result"]
        assert process.stderr == ""
        assert reply["isError"] == error, reply
        content = reply["content"][0]["text"]
        return content if error else json.loads(content)

    try:
        vault = workspace.add(target, PASSWORD, False, name="Runner fixture")
        row, unapproved = expected[:2]
        workspace.save_binding(vault, Action("health", "Runner Status Check", row["id"], url + "/health"))
        broker.start()
        subprocess.run([*NAMESPACE, "test", "!", "-r", str(target.database)], check=True)
        assert invoke("access_status") == {"status": "uninitialized"}
        request = {"identity": "Runner fixture", "project": "Synthetic",
                   "items": [{"metadata": True, "vault": vault, "entry": row["id"], "action": "health"}]}
        assert invoke("request_access", {"request": request}) == {"status": "pending"}
        record, = grants.rows()
        assert record.uid == uid
        match, = grants.choices(record.items[0])
        grants.decide(record.id, [match])
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
        workspace.set_token_auto_approval("auto_approve_token_changes", True)
        assert invoke("request_access", {"request": change}) == {"status": "active"}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [unapproved]}
        invoke("use_password", action, error=True)
        assert calls == [("/health", header)]
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
    print("Runner scenario passed: bundled runner, all seven stdio tools, separate peer UID, scoped TLS, persisted edits, and revocation")
