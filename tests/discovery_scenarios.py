"""Discover two synthetic vaults through a fresh isolated runner before enrollment."""

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import sleep
from unittest.mock import patch
from uuid import uuid4

from broker_scenarios import PASSWORD, REPO, prepare
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from test_agent_runner import call_tool


def check(root, hold=False):
    target, _, private, expected = prepare(root)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    uid, gid = subordinate_ids()
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    engine = ScopedBroker(workspace, grants, activity)
    broker = None
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_STATE_HOME=str(root / "state")):
        runner = REPO / "keeper-run-agent"
        subprocess.run([runner, "--prepare-socket"], check=True)
        endpoint = runtime / "keeper-scoped-runner/broker.sock"
        first = workspace.add(target, PASSWORD, False, name="Harbor Engineering")
        copy = private / "second.kdbx"
        shutil.copyfile(target.database, copy)
        second = workspace.add(replace(target, database=copy), PASSWORD, False, name="Meadow Operations")
        workspace.lock(second)
        workspace.pause(False)
        broker = ListingBroker(BrokerConfig(endpoint, uid), lambda: engine, engine)
        broker.start()

        def invoke(name, args=None, error=False):
            process = subprocess.run([runner, "--profile", "discovery-fixture"], cwd="/tmp",
                                     input=json.dumps(call_tool(name, args)) + "\n", text=True,
                                     capture_output=True, check=True, timeout=12)
            assert not process.stderr
            reply = json.loads(process.stdout)["result"]
            assert reply["isError"] == error, reply
            raw = reply["content"][0]["text"]
            assert PASSWORD not in raw
            return raw if error else json.loads(raw)

        try:
            if hold:
                wrapper = root / "runner"
                wrapper.write_text(
                    "#!/bin/sh\nexec /usr/bin/env "
                    + "XDG_RUNTIME_DIR=" + str(runtime) + " XDG_STATE_HOME=" + str(root / "state")
                    + " KEEPASSXC_AGENT_MODEL=FreshDiscoveryAgent KEEPASSXC_AGENT_CHAT=DiscoveryTrial "
                    + str(runner) + " --profile fresh-discovery\n"
                )
                wrapper.chmod(0o700)
                print(f"Fresh discovery runner: {wrapper}", flush=True)
                try:
                    while True:
                        sleep(.25)
                except KeyboardInterrupt:
                    return
            assert invoke("access_status") == {"status": "uninitialized"}
            catalog = invoke("discover")
            assert {row["name"] for row in catalog["vaults"]} == {"Harbor Engineering", "Meadow Operations"}
            summary = invoke("discover", {"summary": True})
            assert len(summary["vaults"]) == 2
            assert all(not row["groups"] and not row["entries"] for row in summary["vaults"])
            assert invoke("discover", {"vault": second}) == {"vaults": [catalog["vaults"][1]]}
            live, cached = catalog["vaults"]
            assert live["id"] == first and not live["cached"] and not live["locked"]
            assert cached["id"] == second and cached["cached"] and cached["locked"]
            assert live["entries"] == cached["entries"]
            assert live["groups"] and len(live["entries"]) == len(expected)
            assert invoke("access_status") == {"status": "uninitialized"}
            assert grants.rows() == []
            invoke("list_entries", {"vault": first, "fields": ["username", "url"]}, error=True)
            selected = live["entries"][0]
            request = {"identity": "Discovery Trial", "project": "Synthetic",
                       "items": [{"vault": first, "entry": selected["id"], "metadata": True}]}
            assert invoke("request_access", {"request": request}) == {"status": "pending"}
            grant, = grants.rows()
            grants.decide(grant.id, [grants.choices(item)[0] for item in grant.items])
            rows = invoke("list_entries", {"vault": first, "fields": ["username", "url"]})["entries"]
            assert len(rows) == 1 and rows[0]["id"] == selected["id"]
            assert "username" not in rows[0] and "url" not in rows[0]
            assert invoke("discover") == catalog
            grants.transition(grant.id, "disabled")
            assert invoke("discover") == catalog
            invoke("list_entries", {"vault": first}, error=True)
            workspace.pause()
            invoke("discover", error=True)
            assert activity.rows(action="Discover resources", outcome="Succeeded")
        finally:
            broker.stop()
            workspace.lock_all()
            anchors = root / "state/keeper-scoped-runner"
            if anchors.exists():
                for anchor in anchors.iterdir():
                    fd = os.open(anchor, os.O_PATH | os.O_DIRECTORY)
                    try:
                        alter_acl(anchor, "-m", f"u:{uid}:rwx")
                        subprocess.run([*namespace(uid, gid), "/usr/bin/rm", "-rf",
                                        f"/proc/self/fd/{fd}/profile"], pass_fds=(fd,), check=True, cwd="/")
                    finally:
                        os.close(fd)


if __name__ == "__main__":
    import sys
    with TemporaryDirectory(prefix="keeper-discovery-") as temporary:
        check(Path(temporary), hold="--hold" in sys.argv)
    print("Discovery scenario passed: fresh runner, two vaults, cached names, grant isolation, pause and Activity.")
