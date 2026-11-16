"""Verify a whole process tree against a disposable owner desktop boundary."""

import os
from pathlib import Path
from select import select
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory

from pykeepass import create_database

from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.isolated_host import prepare
from keepassxc_agent_access.isolated_runner import subordinate_ids
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Workspace


REPO = Path(__file__).resolve().parents[1]
PROBE = """
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

# Mount and privilege boundaries apply to this tool host and to every descendant.
assert os.getgroups() == []
for name, expected in (("NoNewPrivs", "1"), ("CapEff", "0000000000000000"),
                       ("CapBnd", "0000000000000000"), ("Seccomp", "2")):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    assert status[name].strip() == expected
for fd in range(3, 64):
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("An extra descriptor was inherited")
assert not ({"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
             "SSH_AUTH_SOCK", "KEEPER_OWNER_FIXTURE"} & os.environ.keys())
assert os.environ["HOME"] == "/home/agent"
assert not Path(owner_file).exists()
assert not Path("/run/user").exists()
assert not Path("/sys/fs/cgroup").exists()
assert not Path("/etc/sudoers").exists()
assert not Path(owner_process).exists()
assert subprocess.run(["/usr/bin/sh", "-c", 'test ! -e "$1" && test ! -e /run/user', "sh", owner_file]).returncode == 0
node = Path("/usr/bin/node")
if node.exists():
    assert subprocess.run([str(node), "-e", "process.exit(require('node:fs').existsSync(process.argv[1])?1:0)",
                           owner_file]).returncode == 0
assert subprocess.run(["/usr/bin/unshare", "--user", "/usr/bin/true"], capture_output=True).returncode != 0
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK):
    try:
        socket.socket(family)
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError("A network socket was permitted")
with socket.socket(socket.AF_UNIX) as stream:
    for address in (owner_bus, owner_abstract):
        try:
            stream.connect(address)
        except OSError as error:
            assert error.errno in (errno.ENOENT, errno.ECONNREFUSED)
        else:
            raise AssertionError("An owner socket was accessible")
assert Path("/work").is_dir()
Path("/work/tool-data").write_text("fixture")
try:
    Path("/unexpected-file").touch()
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise AssertionError("The sandbox root is writable")


def invoke(*arguments, body=None):
    return subprocess.run(["keepassxc-agent", *arguments, "--json"], capture_output=True,
                          input=json.dumps(body).encode() if body else None, timeout=6)


request = {"identity": "Synthetic isolated host", "project": "Offline host fixture",
           "items": [{"vault": vault, "entry": entry, "metadata": True}]}
result = invoke("access", "request", body=request)
assert result.returncode == 0 and json.loads(result.stdout) == {"status": "pending"}, result.stderr
print("pending", flush=True)
assert sys.stdin.readline().strip() == "approved"
assert json.loads(invoke("access", "status").stdout) == {"status": "active"}
blocked = invoke("entries", "list", "--vault", vault)
assert blocked.returncode != 0 and b"paused" in blocked.stderr
print("paused", flush=True)
assert sys.stdin.readline().strip() == "resumed"
allowed = invoke("entries", "list", "--vault", vault)
assert allowed.returncode == 0, allowed.stderr
assert [row["id"] for row in json.loads(allowed.stdout)["entries"]] == [entry]
print("scoped", flush=True)
"""


def check(root):
    uid, _ = subordinate_ids()
    host = prepare(uid)
    private = root / "owner"
    private.mkdir(mode=0o700)
    owner_file = private / "owner-policy.json"
    owner_file.write_text("synthetic owner settings")
    database = private / "synthetic.kdbx"
    db = create_database(database, "Synthetic vault unlock")
    entry = db.add_entry(db.root_group, "Allowed fixture", "fixture", "Synthetic secret")
    db.add_entry(db.root_group, "Outside token scope", "fixture", "Other synthetic secret")
    db.save()
    workspace = Workspace(private, None)
    activity = ActivityStore(private / "activity.sqlite")
    activity.recover(30)
    grants = Grants(workspace, activity)
    vault = workspace.add(VaultTarget(database), "Synthetic vault unlock", False, name="Synthetic offline host")
    engine = ScopedBroker(workspace, grants, activity)
    broker = ListingBroker(BrokerConfig(host / "broker/broker.sock", uid), lambda: engine, engine)
    owner_bus = str(private / "owner-bus.sock")
    owner_abstract = "\0keeper-fixture-" + host.name
    specification = {"owner_bus": owner_bus, "owner_abstract": owner_abstract, "owner_file": str(owner_file),
                     "owner_process": f"/proc/{os.getpid()}/status",
                     "vault": vault, "entry": str(entry.uuid)}
    script = "\n".join(f"{key} = {value!r}" for key, value in specification.items()) + "\n" + PROBE
    command = [str(REPO / "keeper-run-isolated"), "--directory", str(host), "--",
               "/usr/bin/python3", "-I", "-c", "import sys; exec(sys.stdin.readline())"]

    try:
        with socket.socket(socket.AF_UNIX) as desktop, socket.socket(socket.AF_UNIX) as abstract:
            desktop.bind(owner_bus)
            desktop.listen()
            abstract.bind(owner_abstract)
            abstract.listen()
            broker.start()
            with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, cwd=REPO) as process:
                def read(expected):
                    if not select([process.stdout], [], [], 18)[0]:
                        raise AssertionError("The isolated tool host did not respond.")
                    line = process.stdout.readline().strip()
                    if line != expected:
                        raise AssertionError(process.communicate(timeout=3)[1] or line)

                try:
                    process.stdin.write(f"exec({script!r})\n")
                    process.stdin.flush()
                    read("pending")
                    record, = grants.rows()
                    assert record.status == "pending" and record.uid == uid
                    grants.decide(record.id, [grants.choices(record.items[0])[0]])
                    process.stdin.write("approved\n")
                    process.stdin.flush()
                    read("paused")
                    workspace.pause(False)
                    process.stdin.write("resumed\n")
                    process.stdin.flush()
                    read("scoped")
                    assert process.wait(timeout=5) == 0
                finally:
                    if process.poll() is None:
                        process.terminate()

            waiting = [*command[:-1], "import time; print('ready', flush=True); time.sleep(60)"]
            with subprocess.Popen(waiting, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, cwd=REPO) as process:
                try:
                    assert select([process.stdout], [], [], 12)[0]
                    assert process.stdout.readline().strip() == "ready"
                    process.terminate()
                    assert process.wait(timeout=5) == 143
                    assert select([process.stdout], [], [], 2)[0] and not process.stdout.read(1)
                finally:
                    if process.poll() is None:
                        process.terminate()

            with (private / "protected-output").open("wb") as output:
                result = subprocess.run(waiting, input=b"", stdout=output, stderr=subprocess.PIPE, cwd=REPO, timeout=5)
                assert result.returncode != 0 and b"stdio pipes" in result.stderr
    finally:
        broker.stop()
        workspace.lock_all()
        shutil.rmtree(host)
    assert owner_file.read_text() == "synthetic owner settings"
    print("Offline agent host scenario passed: owner session, files and network denied; scoped broker permitted.")


if __name__ == "__main__":
    with TemporaryDirectory(prefix="keeper-host-probe-") as folder:
        check(Path(folder))
