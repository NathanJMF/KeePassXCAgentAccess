"""Dynamic secret-use descriptors and private worker delivery."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4
from time import monotonic

from http.server import BaseHTTPRequestHandler
from pykeepass import create_database

from keepassxc_agent_access.access_settings import ActionType
from keepassxc_agent_access.command_action import prepare_command, sandbox_arguments
from keepassxc_agent_access.command_prompt import askpass
from keepassxc_agent_access.agent_runner import invocation
from keepassxc_agent_access.https_action import authenticate
from keepassxc_agent_access.protocol import ListingError, encode
from keepassxc_agent_access.usage import requires_body_permission, usage_action, usage_origin
from keepassxc_agent_access.vault import DYNAMIC_LOCAL_WINDOW, VaultSession, VaultTarget, open_vault
from tls_fixture import tls_service


class DynamicUsageTests(TestCase):
    def setUp(self):
        self.entry = str(uuid4())

    def test_command_digest_is_computed_by_owner_and_outputs_are_opaque(self):
        argv = ["/usr/bin/cat"]
        with patch("keepassxc_agent_access.usage.executable_digest", return_value="a" * 64) as pin:
            action = usage_action(self.entry, {"type": "local_command", "command": argv})
        pin.assert_called_once_with(argv)
        self.assertTrue(action.opaque)
        with patch("keepassxc_agent_access.usage.executable_digest") as untrusted_pin:
            preview = usage_action(self.entry, {"type": "local_command", "command": argv}, pin_executable=False)
        untrusted_pin.assert_not_called()
        self.assertEqual(preview.executable_sha256, "0" * 64)
        self.assertEqual((action.command, action.executable_sha256), (tuple(argv), "a" * 64))
        for extra in ({"executable_sha256": "b" * 64}, {"action": "binding"}, {"output": "/host/path"}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                usage_action(self.entry, {"type": "local_command", "command": argv, **extra})
        with self.assertRaises(ValueError):
            usage_action(self.entry, {"type": "local_command", "command": argv}, accepts_input=True)

    def test_networked_commands_pin_raw_peer_and_require_explicit_prompt(self):
        request = {"type": "networked_command", "command": ["/usr/bin/true"],
                   "origin": "https://example.invalid:8443/", "prompt_variable": "TOOL_ASKPASS"}
        request["environment"] = {"TOOL_MODE": "fixture"}
        action = usage_action(self.entry, request, accepts_input=True)
        self.assertEqual(action.environment, (("TOOL_MODE", "fixture"),))
        self.assertTrue(action.opaque and action.accepts_input)
        self.assertEqual(usage_origin(action.url), request["origin"])
        for environment in ({"PATH": "/tmp"}, {"https_proxy": "other"}, {"KEEPER_GENERIC_PROMPT": "1"},
                            {"LD_PRELOAD": "/usr/lib/library"}, {"TOOL_ASKPASS": "/tool"}, {"X": "{{password}}"}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                usage_action(self.entry, {**request, "environment": environment})
        for extra in ({"origin": "https://example.invalid/resource"}, {"prompt_variable": "PATH"},
                      {"origin": "http://example.invalid/"}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                usage_action(self.entry, {**request, **extra})

    def test_generic_prompt_is_explicit_and_declared_environment_reaches_only_sandbox(self):
        with patch.dict(os.environ, KEEPER_GENERIC_PROMPT="1"), \
                patch("keepassxc_agent_access.command_prompt.socket.socket", side_effect=OSError) as connect:
            with self.assertRaises(OSError):
                askpass("user@host pAsSwOrD:")
            connect.assert_called_once()
        with patch.dict(os.environ, KEEPER_GENERIC_PROMPT="1"), \
                patch("keepassxc_agent_access.command_prompt.socket.socket") as connect:
            self.assertEqual(askpass("Username for host:"), 1)
            self.assertEqual(askpass("not printable\n"), 1)
            connect.assert_not_called()
        args = sandbox_arguments(("/usr/bin/true",), 17, "fixture.scope", relay_path=Path("/private/relay"),
                                 prompt_variable="TOOL_ASKPASS", generic_prompt=True, environment=(("TOOL_MODE", "fixture"),))
        self.assertIn("--launch-generic", args)
        self.assertIn('{"TOOL_MODE":"fixture"}', args)
        self.assertNotIn(os.environ.get("DBUS_SESSION_BUS_ADDRESS", "owner-session-sentinel"), args)
        command, payload = invocation("use_password", {"entry": self.entry,
                                      "usage": {"type": "networked_command", "origin": "https://example.invalid/",
                                                "command": ["/usr/bin/true"], "prompt_variable": "TOOL_ASKPASS",
                                                "environment": {"TOOL_MODE": "fixture"}}, "input_base64": "eA=="})
        self.assertIn('--environment-json={"TOOL_MODE":"fixture"}', command)
        self.assertEqual(payload, b"x")

    def test_prepare_command_keeps_owner_launcher_environment_out_of_job_arguments(self):
        process = MagicMock()
        process.pid = 123
        process.poll.return_value = 0
        owner_bus = "unix:path=/synthetic-owner-bus"
        owner_runtime = "/synthetic-owner-runtime"
        with patch.dict(os.environ, DBUS_SESSION_BUS_ADDRESS=owner_bus, XDG_RUNTIME_DIR=owner_runtime), \
                patch("keepassxc_agent_access.command_action.executable_digest", return_value="a" * 64), \
                patch("keepassxc_agent_access.command_action.syscall_filter", return_value=nullcontext(17)), \
                patch("keepassxc_agent_access.command_action.network_relay", return_value=nullcontext((Path("/fixture-relay"), Mock()))), \
                patch("keepassxc_agent_access.command_action.read_frame", return_value=b"keeper-ready\n"), \
                patch("keepassxc_agent_access.command_action.verify_scope_limits"), \
                patch("keepassxc_agent_access.command_action.stop_scope") as stop, \
                patch("keepassxc_agent_access.command_action.subprocess.Popen", return_value=process) as launch:
            with prepare_command(("/usr/bin/true",), "a" * 64, destination=Mock(), prompt_variable="TOOL_ASKPASS",
                                 generic_prompt=True, environment=(("TOOL_MODE", "fixture"),), prompt_contains="credential"):
                pass
        args = launch.call_args.args[0]
        self.assertNotIn(owner_bus, json.dumps(args))
        self.assertNotIn(owner_runtime, json.dumps(args))
        index = args.index("--launch-generic")
        self.assertEqual(args[index + 2], "credential")
        self.assertEqual(json.loads(args[index + 3]), {"TOOL_MODE": "fixture"})
        self.assertEqual(launch.call_args.kwargs["env"], {"DBUS_SESSION_BUS_ADDRESS": owner_bus, "XDG_RUNTIME_DIR": owner_runtime})
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[1], launch.call_args.kwargs["env"])

    def test_https_headers_body_and_query_are_typed_without_secret_urls(self):
        request = {"type": "https", "url": "https://api.example.invalid/v2/check", "auth": "template",
                   "method": "POST", "headers": {"X-API-Key": "{{password}}"},
                   "json": {"user": "{{username}}", "credential": "{{password}}"},
                   "query": {"resource": "a/b + c"}}
        action = usage_action(self.entry, request)
        self.assertEqual(action.kind, ActionType.TEMPLATE)
        self.assertEqual(action.query, (("resource", "a/b + c"),))
        self.assertEqual(json.loads(action.request_json), request["json"])
        self.assertIn("?resource=a%2Fb+%2B+c", action.destination)
        self.assertTrue(requires_body_permission(action))
        self.assertFalse(requires_body_permission(usage_action(self.entry, {**request, "json": {"fixed": "value"}})))
        for headers in ({"Host": "other.invalid"}, {"Transfer-Encoding": "chunked"}, {"X-Key": "a\r\nb"}):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                usage_action(self.entry, {**request, "headers": headers})
        for extra in ({"headers": {}, "json": {"{{password}}": "fixed"}},
                      {"headers": {"Content-Type": "{{password}}"}, "json": {"fixed": "value"}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                usage_action(self.entry, {**request, **extra})
        with self.assertRaises(ValueError):
            usage_action(self.entry, {**request, "query": {"key": "{{password}}"}})
        with self.assertRaises(ValueError):
            usage_action(self.entry, {**request, "url": request["url"] + "?key=value"})

    def test_browser_forms_are_dynamic_and_confined_to_same_verified_origin(self):
        request = {"type": "browser", "url": "https://example.invalid/login", "submit_url": "https://example.invalid/session",
                   "form_id": "signin", "username_field": "user", "password_field": "pass", "success_id": "signed-in"}
        action = usage_action(self.entry, request)
        self.assertEqual(action.browser.form_id, "signin")
        self.assertEqual(action.kind, ActionType.BROWSER)
        with self.assertRaises(ValueError):
            usage_action(self.entry, {**request, "submit_url": "https://other.invalid/session"})

    def test_template_body_is_encoded_after_substitution_and_header_injection_is_blocked(self):
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 200
        secret = '\"},"injected":true,"x":"'
        result = authenticate(connection, "/check", SimpleNamespace(password=secret, username="user"), ActionType.TEMPLATE,
                              method="POST", request_json='{"credential":"{{password}}"}')
        self.assertEqual(result, {"outcome": "succeeded", "http_status": 200})
        sent = json.loads(connection.request.call_args.kwargs["body"])
        self.assertEqual(sent, {"credential": secret})
        connection.reset_mock()
        result = authenticate(connection, "/check", SimpleNamespace(password="secret\r\nX: injected", username="user"),
                              ActionType.TEMPLATE, headers=(("X-Token", "{{password}}"),))
        self.assertEqual(result, {"outcome": "failed"})
        connection.request.assert_not_called()

    def test_opaque_commands_hold_exchange_for_fixed_window_and_hide_exit_result(self):
        action = usage_action(self.entry, {"type": "local_command", "command": ["/usr/bin/true"]})
        for runtime, reply in ((.1, {"outcome": "succeeded"}), (4.5, {"outcome": "failed"}), (2, OSError("child stopped"))):
            clock = [0.0]
            session = VaultSession(Mock())
            session.close = Mock()
            session._send = Mock()
            calls = [encode({"ready": True}), reply]

            @contextmanager
            def exchange(request, timeout):
                session._requests.acquire()
                def read():
                    value = calls.pop(0)
                    if not calls:
                        clock[0] += runtime
                    if isinstance(value, Exception):
                        raise value
                    return encode(value) if isinstance(value, dict) else value
                try:
                    yield read
                finally:
                    session._requests.release()

            def advance(delay):
                self.assertTrue(session._requests.locked(), "Padding must keep the vault request occupied")
                clock[0] += delay

            def permit(send):
                send()
                return True

            with self.subTest(runtime=runtime, reply=repr(reply)), \
                    patch.object(session, "_exchange", side_effect=exchange), \
                    patch("keepassxc_agent_access.vault.monotonic", side_effect=lambda: clock[0]), \
                    patch("keepassxc_agent_access.vault.sleep", side_effect=advance):
                result = session.use(action, permit)
                self.assertEqual(result["outcome"], "dispatched")
                self.assertLessEqual(set(result), {"outcome", "_execution_outcome"})
                self.assertEqual(clock[0], DYNAMIC_LOCAL_WINDOW)
                self.assertFalse(session._requests.locked())

    @skipUnless(os.environ.get("KEEPER_TEST_LOCAL_SANDBOX") == "1", "Needs the desktop systemd sandbox")
    def test_live_dynamic_commands_hide_runtime_from_simultaneous_metadata(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.kdbx"
            database = create_database(path, "opaque unlock")
            entry = database.add_entry(database.root_group, "Opaque command", "", "opaque-secret-bit-1")
            database.save()
            # Both commands read the credential; one deliberately encodes a bit
            # in its delay and exit status. The public result and serialized
            # metadata release must be independent of those choices.
            timings = []
            with open_vault(VaultTarget(path), "opaque unlock", Event()) as worker, \
                    ThreadPoolExecutor(max_workers=2) as pool, \
                    patch("keepassxc_agent_access.vault.DYNAMIC_LOCAL_WINDOW", 1.8):
                for invert in (True, False):
                    program = ("import sys,time;d=sys.stdin.buffer.read();"
                               + f"b=d.endswith(b'1') != {invert!r};"
                               + "time.sleep(.4 if b else 0);print(d);sys.exit(int(b))")
                    action = usage_action(str(entry.uuid), {"type": "local_command",
                                          "command": ["/usr/bin/python3", "-I", "-c", program]})
                    dispatched = Event()
                    def permit(send):
                        send()
                        dispatched.set()
                        return True
                    start = monotonic()
                    result = pool.submit(worker.use, action, permit)
                    self.assertTrue(dispatched.wait(5))
                    def metadata():
                        value = worker.scoped_entries([str(entry.uuid)])
                        return value, monotonic() - start
                    metadata_result = pool.submit(metadata)
                    receipt = result.result(timeout=6)
                    rows, released = metadata_result.result(timeout=6)
                    self.assertEqual(receipt["outcome"], "dispatched")
                    self.assertEqual(rows["entries"][0]["id"], str(entry.uuid))
                    self.assertGreaterEqual(released, 1.7)
                    timings.append(released)
                self.assertLess(abs(timings[0] - timings[1]), .5)
                self.assertTrue(worker.available)

    def test_private_template_worker_does_not_return_echoed_credentials(self):
        seen = []
        secret = 'synthetic-template-password-"-sentinel'
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                seen.append((self.path, self.headers.get("X-API-Key"), json.loads(raw)))
                body = secret.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        with TemporaryDirectory() as directory, tls_service(directory, handler=Handler) as (cert, url, _):
            path = Path(directory) / "synthetic.kdbx"
            database = create_database(path, "synthetic unlock")
            entry = database.add_entry(database.root_group, "Template API", "synthetic-user", secret)
            database.save()
            action = usage_action(str(entry.uuid), {"type": "https", "url": url + "/submit", "auth": "template",
                                  "headers": {"X-API-Key": "{{password}}"}, "method": "POST",
                                  "json": {"credential": "{{password}}", "user": "{{username}}"}, "query": {"q": "a b"}})
            def permit(send):
                send()
                return True
            with patch.dict(os.environ, SSL_CERT_FILE=str(cert)), open_vault(VaultTarget(path), "synthetic unlock", Event()) as worker:
                result = worker.use(action, permit)
                self.assertEqual(result, {"outcome": "succeeded", "http_status": 200})
                self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(seen, [("/submit?q=a+b", secret, {"credential": secret, "user": "synthetic-user"})])
