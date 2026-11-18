"""Exercise a private console from an installed runner to a synthetic TLS peer."""
from base64 import b64encode
from contextlib import closing
from hashlib import sha1, sha256
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
import shlex
import ssl
from struct import pack, unpack
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from Cryptodome.Cipher import DES
from pykeepass import PyKeePass

from broker_scenarios import PASSWORD, prepare
from keepassxc_agent_access.activity import ActivityError, ActivityStore
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.installation import Installation
from keepassxc_agent_access.isolated_runner import alter_acl, namespace, subordinate_ids
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.workspace import Workspace
from tls_fixture import tls_service


def console_site(state):
    class Server(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def handle(self):
            try:
                super().handle()
            except (OSError, EOFError):
                pass

        def respond(self, data):
            body = json.dumps({"data": data}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if self.path == "/auth":
                if form != {"user": [state["user"]], "password": [state["password"]]}:
                    return self.send_error(403)
                state["logins"] += 1
                return self.respond({"cookie": state["cookie"], "csrf": state["csrf"]})
            if (self.path != "/vm/103/console" or form != {"websocket": ["1"]}
                    or self.headers.get("Cookie") != "session=" + state["cookie"]
                    or self.headers.get("X-CSRF-Token") != state["csrf"]):
                return self.send_error(403)
            state["created"] += 1
            self.respond({"ticket": state["ticket"], "port": 5903, "password": state["vnc_password"]})

        def do_GET(self):
            target = urlsplit(self.path)
            if (target.path != "/vm/103/stream" or parse_qs(target.query) != {"ticket": [state["ticket"]], "port": ["5903"]}
                    or self.headers.get("Cookie") != "session=" + state["cookie"]
                    or self.headers.get("Upgrade") != "websocket"):
                return self.send_error(403)
            self.close_connection = True
            key = self.headers["Sec-WebSocket-Key"].encode("ascii")
            digest = sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "upgrade")
            self.send_header("Sec-WebSocket-Accept", b64encode(digest).decode("ascii"))
            self.send_header("Sec-WebSocket-Protocol", "binary")
            self.end_headers()

            def send(data, opcode=0x82):
                length = pack("!B", len(data)) if len(data) < 126 else pack("!BH", 126, len(data))
                self.wfile.write(bytes([opcode]) + length + data)

            def read():
                header = self.rfile.read(2)
                if len(header) != 2:
                    raise EOFError
                flags, size = header
                assert flags == 0x82 and size & 128
                size &= 127
                if size == 126:
                    size, = unpack("!H", self.rfile.read(2))
                mask = self.rfile.read(4)
                return bytes(byte ^ mask[i % 4] for i, byte in enumerate(self.rfile.read(size)))

            try:
                send(b"RFB 003.008\n")
                assert read() == b"RFB 003.008\n"
                send(b"\x01\x02")
                assert read() == b"\x02"
                challenge = secrets.token_bytes(16)
                send(challenge)
                key = bytes(int(f"{b:08b}"[::-1], 2) for b in state["vnc_password"].encode("ascii"))
                assert read() == DES.new(key, DES.MODE_ECB).encrypt(challenge)
                send(bytes(4))
                assert read() == b"\x01"
                state["opened"] += 1
                title = state["cookie"].encode("ascii")
                send(pack("!HH16sI", 8, 4, bytes(16), len(title)) + title)
                assert read()[0] == 0  # SetPixelFormat
                assert read()[0] == 2  # SetEncodings
                while True:
                    message = read()
                    if message[0] == 3:  # FramebufferUpdateRequest
                        clipboard = state["ticket"].encode("ascii")
                        send(pack("!B3xI", 3, len(clipboard)) + clipboard)
                        color = bytes((40, 60, 90, 0)) if state["input"] else bytes((0, 0, 0, 0))
                        update = pack("!BBHHHHHi", 0, 0, 1, 0, 0, 8, 4, 0) + color * 32
                        # Split a binary message over two frames, including a
                        # split RFB header. Nothing private may reach the CLI.
                        send(update[:5], opcode=0x02)
                        send(update[5:], opcode=0x80)
                    else:
                        state["input"].append(message)
            finally:
                state["closed"].set()
    return Server


def descriptor(origin, pin):
    return {
        "origin": origin, "certificate_sha256": pin,
        "login": {"path": "/auth", "form": {"user": "{{username}}", "password": "{{password}}"},
                  "capture": {"cookie": "/data/cookie", "csrf": "/data/csrf"}},
        "connect": {"path": "/vm/103/console", "method": "POST", "auth": "session",
                    "headers": {"Cookie": "session={{session.cookie}}", "X-CSRF-Token": "{{session.csrf}}"},
                    "form": {"websocket": "1"}, "capture": {"console_ticket": "/data/ticket", "port": "/data/port",
                                                            "vnc_password": "/data/password"}},
        "socket": {"path": "/vm/103/stream", "headers": {"Cookie": "session={{session.cookie}}"},
                   "query": {"ticket": "{{session.console_ticket}}", "port": "{{session.port}}"},
                   "password": "{{session.vnc_password}}"},
    }


def fixture_state():
    state = {key: key + "-" + secrets.token_hex(16) for key in ("user", "password", "cookie", "csrf", "ticket")}
    state["ticket"] += ":/+%?=&"
    state["vnc_password"] = secrets.token_hex(4)
    state.update(logins=0, created=0, opened=0, input=[], closed=Event())
    return state


def exercise_console(root):
    target, _, private, _ = prepare(root)
    runtime, state_path = root / "runtime", root / "state"
    runtime.mkdir(mode=0o700)
    uid, gid = subordinate_ids()
    state = fixture_state()
    secrets_to_check = [value.encode("ascii") for value in
                        [state[key] for key in ("password", "cookie", "csrf", "ticket", "vnc_password")]]
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
                      f"raise SystemExit(main(_runtime=Path({str(runtime)!r}),_state=Path({str(state_path)!r}),_checkout=Path({str(installation.app)!r})))\n")
    executable = installation.app / "keeper-agent"
    executable.write_text("#!/bin/sh\nexec /usr/bin/python3 -I " + shlex.quote(str(driver)) + ' "$@"\n')
    executable.chmod(0o755)
    with patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime)):
        subprocess.run([installation.app / "keeper-run-agent", "--prepare-socket"], check=True)
    launcher = skill.with_name("keeper-agent")

    def call(profile, *args, data=None, png=False, error=None):
        prefix = [launcher, "--profile", profile, "--note", "Operate only the synthetic guest"] if profile else [launcher]
        child = subprocess.run([*prefix, *args], cwd="/tmp", capture_output=True,
                               input=json.dumps(data).encode() if data is not None else b"", timeout=30)
        assert all(value not in child.stdout + child.stderr for value in secrets_to_check)
        if error:
            assert child.returncode and not child.stdout and error in child.stderr.decode(), child.stderr.decode()
            return
        assert child.returncode == 0 and not child.stderr, child.stderr.decode()
        return child.stdout if png else json.loads(child.stdout)

    stopped = Event()
    broker, owner = None, None
    try:
        with tls_service(private, handler=console_site(state)) as (certificate, url, _):
            origin = url + "/"
            pin = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
            db = PyKeePass(target.database, password=PASSWORD, keyfile=target.key_file)
            entry = str(db.add_entry(db.root_group, "Synthetic console", state["user"], state["password"]).uuid)
            db.save()
            vault = workspace.add(target, PASSWORD, False, name="Console Trial")
            workspace.pause(False)
            broker = ListingBroker(BrokerConfig(runtime / "keeper-scoped-runner/broker.sock", uid), lambda: engine, engine)
            broker.start()

            decisions = []
            def review():
                while not stopped.wait(.015):
                    for ticket in engine.approvals.pending():
                        assert ticket.opens_console and not ticket.trusts_certificate
                        assert "/vm/103/stream" in " ".join(ticket.scope)
                        assert all(secret not in repr(ticket).encode() for secret in secrets_to_check)
                        # Approve an intentionally incorrect pin too, to exercise
                        # the worker's TLS check independently of owner judgment.
                        approve = any(value in " ".join(ticket.scope) for value in (pin, "f" * 64))
                        if engine.approvals.resolve(ticket.id, approve):
                            decisions.append(approve)
            owner = Thread(target=review, daemon=True)
            owner.start()

            def enroll(identity, capabilities):
                profile = call(None, "begin", "--identity", identity, "--project", "Console Trial")["profile"]
                assert call(profile, "access", "request", "--json", data={"items": [{
                    "vault": vault, "entry": entry, "uses": capabilities, "origins": [origin]
                }]})["status"] == "pending"
                record = next(row for row in grants.rows() if row.identity == identity)
                grants.decide(record.id, [grants.choices(record.items[0])[0]])
                return profile, record.id

            profile, identifier = enroll("Console Operator", ["https_results", "https_body"])
            foreign, _ = enroll("Another Console Operator", ["https_results", "https_body"])
            limited, _ = enroll("Read Only Fixture", ["https_results"])
            workflow = descriptor(origin, pin)
            open_args = ("console", "open", "--vault", vault, "--entry", entry, "--json")
            call(limited, *open_args, data=workflow, error="unavailable for this token")
            call(profile, *open_args, data={**workflow, "origin": "https://unapproved.invalid/"}, error="unavailable for this token")
            call(profile, *open_args, data={**workflow, "certificate_sha256": "0" * 64}, error="owner declined")
            call(profile, *open_args, data={**workflow, "certificate_sha256": "f" * 64}, error="could not complete")
            with patch.object(activity, "authorize", side_effect=ActivityError):
                call(profile, *open_args, data=workflow, error="could not verify settings")
            assert not engine.console_access.sessions
            assert (state["logins"], state["created"], state["opened"]) == (0, 0, 0)
            result = call(profile, *open_args, data=workflow)
            console = result["console"]
            assert result["expires_in"] == 900 and decisions == [False, True, True, True]
            assert (state["logins"], state["created"], state["opened"]) == (1, 1, 1)
            view_args = ("console", "view", "--console", console, "--png")
            status_args = ("console", "view", "--console", console, "--status")
            input_args = ("console", "input", "--console", console, "--json")
            call(foreign, *view_args, error="unavailable to this token")
            call(foreign, *status_args, error="unavailable to this token")
            call(foreign, *input_args, data=[{"key": "Enter"}], error="unavailable to this token")
            before = call(profile, *view_args, png=True)
            assert before.startswith(b"\x89PNG\r\n\x1a\n")
            assert call(profile, *status_args) == {"changed": False, "width": 8, "height": 4}
            assert call(profile, *input_args, data=[{"key": "Enter"}, {"text": "Aa!"}, {"x": 3, "y": 1}]) == {"outcome": "succeeded"}
            assert call(profile, *status_args) == {"changed": True, "width": 8, "height": 4}
            assert call(profile, *status_args) == {"changed": False, "width": 8, "height": 4}
            after = call(profile, *view_args, png=True)
            assert before != after
            received = [
                (1, 0xff0d), (0, 0xff0d),
                (1, 0xffe1), (1, ord("A")), (0, ord("A")), (0, 0xffe1),
                (1, ord("a")), (0, ord("a")),
                (1, 0xffe1), (1, ord("!")), (0, ord("!")), (0, 0xffe1),
            ]
            expected_keys = b"".join(pack("!BBHI", 4, down, 0, code) for down, code in received)
            assert state["input"] == [expected_keys + pack("!BBHHBBHH", 5, 1, 3, 1, 5, 0, 3, 1)]
            assert len(decisions) == 4
            worker = workspace.session(vault).worker
            worker_console = worker.console
            close_attempts = []

            def transient_busy(request, gate):
                if request["operation"] == "console_close":
                    close_attempts.append(True)
                    if len(close_attempts) == 1:
                        raise ListingError("busy")
                return worker_console(request, gate)

            with patch.object(worker, "console", side_effect=transient_busy):
                grants.transition(identifier, "disabled")
                assert state["closed"].wait(5), "Revoking the token must close the private socket"
                assert close_attempts == [True, True]
            call(profile, *view_args, error="unavailable for this token")
            state["closed"].clear()
            second = call(foreign, *open_args, data=workflow)["console"]
            assert call(foreign, "console", "close", "--console", second, "--json") == {"outcome": "succeeded"}
            assert state["closed"].wait(5), "Explicit close must close the private socket"
            call(foreign, "console", "view", "--console", second, "--png", error="unavailable to this token")
            rows = activity.rows(agent="Console Operator")
            assert all(secret not in repr(rows).encode() for secret in secrets_to_check)
            assert any(row["action"] == "Send Guest Console Input" and row["outcome"] == "Succeeded"
                       and "3 input events" in row["scope"] and "Enter" not in row["scope"] for row in rows)
            assert "https" not in grants.records[identifier].scope[0].uses
    finally:
        stopped.set()
        if owner:
            owner.join(2)
        if broker:
            broker.stop()
        workspace.lock_all()
        anchors = state_path / "keeper-agent-sessions"
        for anchor in anchors.iterdir() if anchors.exists() else ():
            if not anchor.is_dir():
                continue
            fd = os.open(anchor, os.O_PATH | os.O_DIRECTORY)
            try:
                alter_acl(anchor, "-m", f"u:{uid}:rwx")
                subprocess.run([*namespace(uid, gid), "/usr/bin/rm", "-rf", f"/proc/self/fd/{fd}/profile"],
                               pass_fds=(fd,), check=True, cwd="/")
            finally:
                os.close(fd)


class ConsoleValidationTests(TestCase):
    def test_status_checks_report_changes_without_encoding_images(self):
        from keepassxc_agent_access.agent_cli import _validate
        from keepassxc_agent_access.console_request import open_console

        state = fixture_state()
        with TemporaryDirectory(prefix="keeper-console-status-") as base, \
                tls_service(Path(base), handler=console_site(state)) as (certificate, url, _):
            pin = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
            entry = SimpleNamespace(username=state["user"], password=state["password"])
            config = descriptor(url + "/", pin)
            with closing(open_console(config, entry, lambda: True)) as console:
                payload = {"operation": "console_view", "status_only": True}
                with patch("keepassxc_agent_access.console_transport._png",
                           side_effect=AssertionError("Status checks must not encode screenshots.")):
                    self.assertEqual(_validate(console.view(status_only=True), payload),
                                     {"changed": True, "width": 8, "height": 4})
                    self.assertFalse(_validate(console.view(status_only=True), payload)["changed"])
                    console.input([{"key": "Enter"}])
                    self.assertTrue(_validate(console.view(status_only=True), payload)["changed"])
                image = console.view()
                self.assertIn("png_base64", _validate(image, {"operation": "console_view"}))
                with self.assertRaises(ListingError):
                    _validate(image, payload)

    def test_console_query_cannot_include_password_or_change_origin(self):
        from keepassxc_agent_access.console_request import parse_console
        request = descriptor("https://console.test:443/", "a" * 64)
        self.assertEqual(parse_console(request)["origin"], request["origin"])
        for modified in ({"path": "//outside.test/stream"},
                         {"query": {"leak": "{{password}}", "port": "{{session.port}}"}},
                         {"headers": {"Origin": "https://outside.test/", "Cookie": "{{session.cookie}}"}}):
            with self.subTest(modified=modified):
                altered = {**request, "socket": {**request["socket"], **modified}}
                with self.assertRaises(ValueError):
                    parse_console(altered)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="keeper-console-trial-") as temporary:
        exercise_console(Path(temporary))
    print("Console scenario passed: owner approval, private sign-in and console ticket, screenshot/input, token isolation and revocation.")
