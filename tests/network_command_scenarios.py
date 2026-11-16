"""Exercise the real runner, broker, vault, prompt, and TLS Git fixture."""

from base64 import b64encode
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pykeepass import create_database

from broker_scenarios import REPO
from git_https_fixture import TOKEN, create_bundle, git, git_https_service, push_command
from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.command_action import executable_digest
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from keepassxc_agent_access.vault import VaultTarget
from test_agent_runner import call_tool


def scenario(root):
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    profile = "network-fixture"
    endpoint = runtime / "keeper-scoped-runner/broker.sock"
    anchor = root / "state/keeper-scoped-runner" / profile
    runner = REPO / "keeper-run-agent"
    environment = {**os.environ, "XDG_RUNTIME_DIR": str(runtime), "XDG_STATE_HOME": str(root / "state")}
    subprocess.run([runner, "--prepare-socket"], env=environment, check=True)
    uid, gid = subordinate_ids()
    path = private / "synthetic.kdbx"
    unlock = "synthetic Git fixture unlock"
    database = create_database(path, unlock)
    entry_id = str(database.add_entry(database.root_group, "Synthetic push", "", TOKEN).uuid)
    database.save()
    bundle, commit = create_bundle(private)
    input_base64 = b64encode(bundle.read_bytes()).decode("ascii")
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    engine = ScopedBroker(workspace, grants, activity)
    broker = ListingBroker(BrokerConfig(endpoint, uid), lambda: engine, engine)

    def invoke(tool, arguments=None, *, error=False):
        result = subprocess.run([runner, "--profile", profile], env=environment, cwd="/",
                                input=json.dumps(call_tool(tool, arguments)) + "\n", text=True,
                                capture_output=True, check=True, timeout=35)
        assert TOKEN not in result.stdout + result.stderr
        response = json.loads(result.stdout)["result"]
        assert response["isError"] == error, response
        return response["content"][0]["text"]

    try:
        with git_https_service(private) as (cert, origin, remote, calls):
            with patch.dict(os.environ, SSL_CERT_FILE=str(cert)):
                vault = workspace.add(VaultTarget(path), unlock, False, name="Synthetic Git")
            command = push_command(origin + "/fixture.git")
            policy = Action("push", "Synthetic HTTPS push", entry_id, origin, kind=ActionType.NETWORK_PROMPT,
                            command=command, executable_sha256=executable_digest(command),
                            prompt_variable="GIT_ASKPASS", accepts_input=True)
            workspace.save_binding(vault, policy)
            wrong_command = push_command("https://localhost:" + origin.rpartition(":")[2] + "/fixture.git")
            rejected = Action("different-origin", "Fixture denied origin", entry_id, origin,
                              kind=ActionType.NETWORK_PROMPT, command=wrong_command,
                              executable_sha256=executable_digest(wrong_command),
                              prompt_variable="GIT_ASKPASS", accepts_input=True)
            workspace.save_binding(vault, rejected)
            broker.start()
            items = [{"vault": vault, "entry": entry_id, "action": action.id} for action in (policy, rejected)]
            request = {"identity": "Synthetic agent", "project": "Network transport", "items": items}
            assert json.loads(invoke("request_access", {"request": request})) == {"status": "pending"}
            grant, = grants.rows()
            grants.decide(grant.id, [grants.choices(item)[0] for item in grant.items])
            workspace.pause(False)
            args = {"vault": vault, "entry": entry_id, "action": policy.id, "command": command}
            invoke("use_password", args, error=True)
            invoke("use_password", {**args, "command": (*command, "--different"), "input_base64": input_base64},
                   error=True)
            bad_result = invoke("use_password", {**args, "action": rejected.id, "command": wrong_command,
                                                "input_base64": input_base64}, error=True)
            assert json.loads(bad_result) == {"outcome": "failed"}
            assert not calls
            result = invoke("use_password", {**args, "input_base64": input_base64,
                                            "note": "Publish the synthetic fixture commit"})
            assert json.loads(result) == {"outcome": "succeeded"}
            assert git(remote, "rev-parse", "refs/heads/main") == commit
            assert any(method == "POST" and signed for method, _, signed in calls)
            success, = activity.rows(action="Synthetic HTTPS push", outcome="Succeeded")
            assert success["agent"] == "Synthetic agent"
            assert origin in success["destination"] and "refs/heads/main" in success["destination"]
            assert "SHA-256" in success["scope"] and success["note"] == "Publish the synthetic fixture commit"
            assert TOKEN not in repr(activity.rows())
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
    with TemporaryDirectory(prefix="keeper-network-qa-") as folder:
        scenario(Path(folder))
    print("Network command scenario passed: synthetic Git push, private askpass, exact origin and Activity")
