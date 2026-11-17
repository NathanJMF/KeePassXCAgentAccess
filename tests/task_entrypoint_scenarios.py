"""Installed-skill workflow using a private broker and synthetic vaults only."""

from dataclasses import replace
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import sleep
from unittest.mock import patch

from broker_scenarios import PASSWORD, REPO, prepare
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.installation import Installation
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace


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
    # Bind this trusted fixture installation to a private runtime in-process.
    # The production entrypoint has no CLI or environment routing override.
    driver = installation.app / "fixture_entrypoint.py"
    driver.write_text(
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent / 'src'))\n"
        "from keepassxc_agent_access.agent_entrypoint import main\n"
        f"raise SystemExit(main(_runtime=Path({str(runtime)!r}), _state=Path({str(state)!r}), "
        f"_checkout=Path({str(installation.app)!r})))\n"
    )
    frontend = installation.app / "keeper-agent"
    frontend.write_text("#!/bin/sh\nexec /usr/bin/python3 -I " + shlex.quote(str(driver)) + ' "$@"\n')
    frontend.chmod(0o755)
    launcher = skill.with_name("keeper-agent")
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime)):
        subprocess.run([installation.app / "keeper-run-agent", "--prepare-socket"], check=True)
    first = workspace.add(target, PASSWORD, False, name="Harbor Engineering")
    copied = private / "second.kdbx"
    shutil.copyfile(target.database, copied)
    second = workspace.add(replace(target, database=copied), PASSWORD, False, name="Meadow Operations")
    workspace.lock(second)
    workspace.pause(False)
    broker = ListingBroker(BrokerConfig(runtime / "keeper-scoped-runner/broker.sock", uid), lambda: engine, engine)
    broker.start()

    def invoke(*args, payload=None, error=False):
        process = subprocess.run([launcher, *args], cwd="/tmp", capture_output=True, text=True,
                                 input=json.dumps(payload) if payload is not None else None, timeout=15)
        assert PASSWORD not in process.stdout + process.stderr
        assert "synthetic credential" not in process.stdout + process.stderr
        if error:
            assert process.returncode and not process.stdout, process.stdout
            return process.stderr
        assert process.returncode == 0 and not process.stderr, process.stderr
        return json.loads(process.stdout)

    def enroll(profile, vault, entry, **extra):
        return invoke("--profile", profile, "--note", "Synthetic identity workflow test", "access", "request", "--json",
                      payload={"items": [{"vault": vault, "entry": entry, "metadata": True}], **extra})

    try:
        if hold:
            print(f"Installed synthetic skill: {skill}", flush=True)
            try:
                while True:
                    with workspace.mutex:
                        for grant in grants.rows():
                            # Fixture owner approves only a single metadata target.
                            if (grant.status == "pending" and len(grant.items) == 1 and grant.items[0].metadata
                                    and not grant.items[0].username and not grant.items[0].url
                                    and not grant.items[0].action and not grant.items[0].edits):
                                choices = grants.choices(grant.items[0])
                                if len(choices) == 1:
                                    grants.decide(grant.id, choices)
                    sleep(.1)
            except KeyboardInterrupt:
                print(json.dumps({"identities": [g.identity for g in grants.rows()],
                                  "scopes": [len(g.scope) for g in grants.rows()],
                                  "discovery_events": len(activity.rows(action="Discover resources"))}), flush=True)
                return
        task = invoke("begin", "--identity", "Forgejo Installer", "--project", "Forgejo Setup", "--model", "Synthetic Model")
        profile = task["profile"]
        status = invoke("--profile", profile, "access", "status", "--details", "--json")
        assert status["status"] == "uninitialized" and status["identity"] == task["identity"]
        catalog = invoke("--profile", profile, "--note", "Find an exact entry reference", "discover", "--json")
        assert len(catalog["vaults"]) == 2 and catalog["vaults"][1]["locked"]
        entry = catalog["vaults"][0]["entries"][0]["id"]
        assert enroll(profile, first, entry) == {"status": "pending"}
        grant, = grants.rows()
        assert grant.identity == task["identity"] and grant.project == task["project"]
        assert grant.context.model == "Synthetic Model"
        grants.decide(grant.id, [grants.choices(item)[0] for item in grant.items])
        status = invoke("--profile", profile, "access", "status", "--details", "--json")
        assert status["status"] == "active" and len(status["scope"]) == 1
        assert status["scope"][0]["vault"] == first and status["scope"][0]["entry"] == entry
        rows = invoke("--profile", profile, "entries", "list", "--vault", first,
                      "--field", "username", "--field", "url", "--json")["entries"]
        assert len(rows) == 1 and rows[0]["id"] == entry
        assert "username" not in rows[0] and "url" not in rows[0]
        invoke("--profile", profile, "entries", "list", "--vault", second, "--json", error=True)
        # Profile routing and attribution come from registration, not ambient env.
        invoke("--profile", profile, "access", "request", "--json",
               payload={"identity": "Somebody Else", "items": [{"vault": first, "entry": entry, "metadata": True}]}, error=True)
        duplicate = invoke("begin", "--identity", "forgejo installer", "--project", "Another Task")
        duplicate_error = invoke("--profile", duplicate["profile"], "access", "request", "--json",
                                 payload={"items": [{"vault": first, "entry": entry, "metadata": True}]}, error=True)
        assert "identity" in duplicate_error.lower()
        fresh = invoke("begin", "--identity", "Forgejo Verifier", "--project", "Forgejo Setup")
        assert fresh["profile"] != profile
        assert enroll(fresh["profile"], first, entry) == {"status": "pending"}
        assert {g.identity for g in grants.rows()} == {"Forgejo Installer", "Forgejo Verifier"}
        # Unknown runner options never reach an alternate socket or credential.
        invoke("--profile", profile, "discover", "--json", "--socket", "/tmp/alternate.sock", error=True)
        workspace.pause()
        assert "paused" in invoke("--profile", profile, "discover", "--json", error=True).lower()
        assert activity.rows(action="Discover resources", outcome="Succeeded")
    finally:
        broker.stop()
        workspace.lock_all()
        anchors = state / "keeper-agent-sessions"
        if anchors.exists():
            for anchor in anchors.iterdir():
                if not anchor.is_dir():
                    continue
                fd = os.open(anchor, os.O_PATH | os.O_DIRECTORY)
                try:
                    alter_acl(anchor, "-m", f"u:{uid}:rwx")
                    subprocess.run([*namespace(uid, gid), "/usr/bin/rm", "-rf", f"/proc/self/fd/{fd}/profile"],
                                   pass_fds=(fd,), check=True, cwd="/")
                finally:
                    os.close(fd)


if __name__ == "__main__":
    import sys
    with TemporaryDirectory(prefix="keeper-task-trial-") as temporary:
        check(Path(temporary), hold="--hold" in sys.argv)
    print("Task entrypoint scenario passed: installed skill, separate identities, discovery, scoped grant, redaction and pause.")
