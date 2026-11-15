"""Exercise the production runner against a synthetic vault under a separate OS UID."""

import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic, sleep

from broker_scenarios import NAMESPACE, PASSWORD, REPO, isolated_uid, prepare
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from test_agent_runner import call_tool


def check(root):
    target, endpoint, private, expected = prepare(root)
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    engine = ScopedBroker(workspace, grants, activity)
    uid = isolated_uid()
    broker = ListingBroker(BrokerConfig(endpoint, uid), lambda: engine, engine)

    runtime = root / "cli"
    shutil.copy2(REPO / "keeper-agent-runner", runtime / "keeper-agent-runner")
    shutil.copyfile(REPO / "src/keepassxc_agent_access/agent_runner.py",
                    runtime / "src/keepassxc_agent_access/agent_runner.py")
    profiles = root / "profiles"
    profiles.mkdir()
    profiles.chmod(0o1777)
    runner_home = profiles / "trial-home"
    subprocess.run([*NAMESPACE, "mkdir", "-m", "700", str(runner_home)], check=True)
    profile = runner_home / "profile"

    def invoke(tool, arguments=None):
        process = subprocess.run(
            [*NAMESPACE, "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
             str(runtime / "keeper-agent-runner"), "--socket", str(endpoint), "--profile-dir", str(profile)],
            cwd="/tmp", input=json.dumps(call_tool(tool, arguments)) + "\n", text=True,
            capture_output=True, check=True, timeout=12,
        )
        reply = json.loads(process.stdout)["result"]
        assert process.stderr == ""
        assert not reply["isError"], reply
        return json.loads(reply["content"][0]["text"])

    try:
        vault = workspace.add(target, PASSWORD, False, name="Runner fixture")
        row = expected[0]
        broker.start()
        subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)
        subprocess.run([*NAMESPACE, "test", "!", "-r", str(target.database)], check=True)
        assert invoke("access_status") == {"status": "uninitialized"}
        request = {"identity": "Runner fixture", "project": "Synthetic",
                   "items": [{"metadata": True, "vault": vault, "entry": row["id"]}]}
        assert invoke("request_access", {"request": request}) == {"status": "pending"}
        record, = grants.rows()
        assert record.uid == uid
        match, = grants.choices(record.items[0])
        grants.decide(record.id, [match])
        workspace.pause(False)
        assert invoke("access_status") == {"status": "active"}
        assert invoke("list_entries", {"vault": vault}) == {"entries": [row]}
        deadline = monotonic() + 2
        while monotonic() < deadline:
            grant, = grants.rows()
            if grant.last_used is not None:
                break
            sleep(.02)
        assert grant.id == record.id and grant.last_used is not None
    finally:
        broker.stop()
        workspace.lock_all()
        subprocess.run([*NAMESPACE, "rm", "-rf", "--", str(runner_home)], check=True)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="keeper-runner-") as root:
        check(Path(root))
    print("Runner scenario passed: private profile, separate peer UID, and scoped enrollment and listing")
