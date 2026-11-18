"""Install the owner-authorized, local Keeper MCP service."""

import argparse
from base64 import b64decode
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
from tempfile import NamedTemporaryFile

RUNTIME = {"keeper-agent-runner", "keepassxc-agent", "src/keeper_bootstrap.py", "agent-setup",
           *("src/keepassxc_agent_access/" + name + ".py" for name in
             ("__init__", "agent_cli", "agent_runner", "protocol", "runner_token"))}
PAYLOAD_LIMIT = 2 * 1024 * 1024


def connection_record(owner):
    return Path(f"/etc/keeper/connection-{owner}.json")


def call(executable, *args):
    subprocess.run([f"/usr/bin/{executable}", *args], check=True)


def check_directories(parent):
    for directory in reversed((parent, *parent.parents)):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"Unsafe administrator configuration directory: {directory}.")


def trusted_file(path):
    check_directories(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f"Unexpected ownership or file type at {path}.")
    return path.read_bytes()


def publish(path, contents, mode):
    check_directories(path.parent)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        staging = Path(stream.name)
        try:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            staging.replace(path)
        finally:
            staging.unlink(missing_ok=True)


def unit_contents(owner, account, broker, runtime):
    name = f"keeper-connect-{owner}"
    command = str(broker).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    listener = f"""[Unit]
Description=Keeper Agent Connection for UID {owner}

[Socket]
ListenStream=/run/{name}.sock
SocketUser={owner}
SocketMode=0600
Accept=yes
MaxConnections=16
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
"""
    runner = f"""[Unit]
Description=Keeper Agent Runner for UID {owner}

[Service]
User={account}
ExecStart={runtime}/keeper-agent-runner --socket "{command}" --project-profiles /var/lib/{name} --connection-profiles
StandardInput=socket
StandardOutput=socket
StandardError=journal
StateDirectory={name}
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ProtectProc=invisible
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
RestrictSUIDSGID=yes
LockPersonality=yes
"""
    return listener.encode(), runner.encode()


def owner_broker(owner, endpoint, peer_uid):
    path = Path(endpoint)
    if (not path.is_absolute() or path.parent.resolve(strict=True) != path.parent or not endpoint.isprintable()
            or len(os.fsencode(endpoint)) >= 108
            or any(path.is_relative_to(tree) for tree in ("/home", "/root", "/run/user"))):
        raise ValueError("Use a dedicated broker socket outside protected home and desktop runtime directories.")
    for directory in (path.parent, *path.parent.parents):
        info = directory.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                or info.st_mode & 0o022 and (directory == path.parent or not info.st_mode & stat.S_ISVTX)):
            raise ValueError("Keeper requires an owner-controlled broker directory.")
    if path.parent.stat().st_uid != owner:
        raise ValueError("The broker directory must belong to the desktop account.")
    account = pwd.getpwuid(peer_uid)
    if (peer_uid in (0, owner) or not re.fullmatch(r"[a-z_][a-z0-9_-]*", account.pw_name)
            or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")):
        raise ValueError("Use a separate, non-login Linux account for the Keeper runner.")
    return path, account


def setup(owner, endpoint, peer_uid, payload=None, *, remove=False):
    name = f"keeper-connect-{owner}"
    runtime = Path("/usr/local/lib") / name
    units = Path("/etc/systemd/system")
    listener = units / (name + ".socket")
    runner = units / (name + "@.service")
    tmpfiles = Path("/etc/tmpfiles.d") / (name + ".conf")
    manifest_path = connection_record(owner)
    original = trusted_file(manifest_path)
    previous = json.loads(original) if original is not None else None
    files = {runtime / path for path in RUNTIME} | {listener, runner, tmpfiles}
    if previous is not None:
        hashes = previous.get("files")
        if (previous.get("owner") != owner or previous.get("version") != 1 or not isinstance(hashes, dict)
                or hashes.keys() - {str(path) for path in files}):
            raise ValueError("Keeper’s administrator installation record is invalid.")
        for path in files:
            data = trusted_file(path)
            if (sha256(data).hexdigest() if data is not None else None) != hashes.get(str(path)):
                raise ValueError(f"Keeper will preserve the changed administrator file at {path}.")
    elif any(trusted_file(path) is not None for path in files):
        raise ValueError("An unmanaged Keeper connection already occupies the installer destination.")

    if remove:
        if previous is None:
            return
        call("systemctl", "disable", "--now", listener.name)
        call("systemctl", "stop", name + "@*.service")
        for path in previous["files"]:
            Path(path).unlink()
        manifest_path.unlink()
        call("systemctl", "daemon-reload")
        return

    additions = {}
    if previous and not endpoint and str(tmpfiles) not in previous["files"]:
        endpoint, peer_uid = previous["endpoint"], previous["uid"]
    if previous and str(tmpfiles) in previous["files"] and (endpoint, peer_uid) == (previous["endpoint"], previous["uid"]):
        endpoint = None
    if endpoint:
        broker, account = owner_broker(owner, endpoint, peer_uid)
    else:
        account_name = f"keeper-agent-{owner}"
        try:
            account = pwd.getpwnam(account_name)
        except KeyError:
            subprocess.run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                            "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", account_name], check=True)
            account = pwd.getpwnam(account_name)
        if account.pw_uid in (0, owner) or account.pw_shell != "/usr/sbin/nologin" or account.pw_dir != "/nonexistent":
            raise ValueError("The bundled account name is already used by another Linux user.")
        broker_dir = Path(f"/run/keeper-broker-{owner}")
        broker = broker_dir / "broker.sock"
        additions[tmpfiles] = (
            f"d {broker_dir} 0700 {owner} - -\n"
            f"a+ {broker_dir} - - - - u:{account.pw_uid}:--x,d:u:{account.pw_uid}:rw-\n"
        ).encode()

    if previous and (str(broker), account.pw_uid) != (previous["endpoint"], previous["uid"]):
        raise ValueError("Remove the bundled connection before switching its broker account or socket.")
    additions.update({runtime / path: data for path, data in payload.items()})
    additions[listener], additions[runner] = unit_contents(owner, account.pw_name, broker, runtime)
    old = {path: trusted_file(path) for path in additions}
    try:
        if previous:
            call("systemctl", "stop", listener.name)
            call("systemctl", "stop", name + "@*.service")
        for path, data in additions.items():
            publish(path, data, 0o755 if path.name in ("keeper-agent-runner", "keepassxc-agent") else 0o644)
        if tmpfiles in additions:
            call("systemd-tmpfiles", "--create", str(tmpfiles))
        call("systemd-analyze", "verify", str(listener), str(runner))
        call("systemctl", "daemon-reload")
        call("systemctl", "enable", "--now", listener.name)
        record = {"version": 1, "owner": owner, "endpoint": str(broker), "uid": account.pw_uid,
                  "files": {str(path): sha256(data).hexdigest() for path, data in additions.items()}}
        publish(manifest_path, json.dumps(record).encode(), 0o644)
    except (OSError, ValueError, subprocess.CalledProcessError):
        subprocess.run(["/usr/bin/systemctl", "disable", "--now", listener.name], check=False)
        for path, data in old.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                publish(path, data, 0o755 if path.name in ("keeper-agent-runner", "keepassxc-agent") else 0o644)
        call("systemctl", "daemon-reload")
        if previous:
            call("systemctl", "enable", "--now", listener.name)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove"))
    parser.add_argument("owner", type=int)
    parser.add_argument("--broker")
    parser.add_argument("--runner-uid", type=int)
    parser.add_argument("--payload-sha256")
    options = parser.parse_args()
    if os.geteuid() != 0 or options.owner <= 0:
        parser.error("Keeper's administrator setup requires a non-root desktop account.")
    if os.environ.get("PKEXEC_UID", str(options.owner)) != str(options.owner):
        parser.error("Authenticate as the desktop account that will use Keeper.")
    if bool(options.broker) != (options.runner_uid is not None):
        parser.error("Provide both the current broker socket and runner UID.")
    os.umask(0o022)
    try:
        pwd.getpwuid(options.owner)
        payload = None
        if options.action == "install":
            data = sys.stdin.buffer.read(PAYLOAD_LIMIT + 1)
            if len(data) > PAYLOAD_LIMIT or sha256(data).hexdigest() != options.payload_sha256:
                raise ValueError("Keeper's approved runtime payload changed.")
            encoded = json.loads(data)
            if not isinstance(encoded, dict) or encoded.keys() != RUNTIME:
                raise ValueError("Keeper's runner payload is incomplete.")
            payload = {name: b64decode(content, validate=True) for name, content in encoded.items()}
        setup(options.owner, options.broker, options.runner_uid, payload, remove=options.action == "remove")
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Keeper agent setup failed. {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
