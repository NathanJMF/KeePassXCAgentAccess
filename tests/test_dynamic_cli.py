"""Agent-facing reusable delivery has typed descriptors and opaque command receipts."""

from base64 import b64encode
import json
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import TestCase
from uuid import uuid4

from keepassxc_agent_access.agent_cli import _validate, usage_request
from keepassxc_agent_access.agent_runner import OPERATIONS, invocation
from keepassxc_agent_access.protocol import ListingError, decode, encode
from keepassxc_agent_access.runner_token import credential


CLI = Path(__file__).resolve().parents[1] / "keepassxc-agent"


class DynamicCliTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.endpoint = self.root / "broker.sock"
        self.profile = self.root / "profile"
        self.profile.mkdir(mode=0o700)
        self.secret = credential(self.profile / "token", create=True)
        self.entry = str(uuid4())
        self.vault = str(uuid4())

    def exchange(self, args, data, reply, *, upload=None):
        observed = []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(self.endpoint))
            listener.listen()
            listener.settimeout(5)

            def serve():
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    observed.append(decode(stream.readline()))
                    if upload is not None:
                        connection.sendall(encode({"upload": True}))
                        observed.append(stream.read(len(upload)))
                    connection.sendall(encode(reply))

            thread = Thread(target=serve, daemon=True)
            thread.start()
            result = subprocess.run([CLI, *args], input=data, capture_output=True, check=False, timeout=7,
                                    env={**os.environ, "KEEPASSXC_AGENT_SOCKET": str(self.endpoint),
                                         "KEEPASSXC_AGENT_TOKEN_FILE": str(self.profile / "token")})
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertNotIn(self.secret.encode(), result.stdout + result.stderr)
        return result, observed

    def test_https_request_descriptor_reaches_broker_without_an_action_id(self):
        usage = {"type": "https", "url": "https://api.example.test/status", "auth": "bearer"}
        result, observed = self.exchange(["use", "--entry", self.entry, "--vault", self.vault, "--json"],
                                         encode(usage), {"outcome": "succeeded", "http_status": 200})
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(decode(result.stdout), {"outcome": "succeeded", "http_status": 200})
        self.assertEqual(observed[0]["usage"], usage)
        self.assertNotIn("action", observed[0])
        self.assertEqual(observed[0]["credential"], self.secret)

    def test_dynamic_run_returns_only_dispatch_receipt(self):
        result, observed = self.exchange(["run", "--entry", self.entry, "--json", "--", "/usr/bin/cat"],
                                         b"", {"outcome": "dispatched"})
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(decode(result.stdout), {"outcome": "dispatched"})
        self.assertEqual(observed[0]["usage"], {"type": "local_command", "command": ["/usr/bin/cat"]})
        self.assertNotIn("action", observed[0])

    def test_network_command_upload_keeps_descriptor_and_artifact_separate(self):
        artifact = b"synthetic artifact\x00with binary bytes"
        result, observed = self.exchange([
            "run", "--entry", self.entry, "--origin", "https://git.example.test/", "--prompt-variable", "GIT_ASKPASS",
            "--input", "--json", "--", "/usr/bin/cat", "/input",
        ], artifact, {"outcome": "dispatched"}, upload=artifact)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(observed[1], artifact)
        self.assertEqual(observed[0]["usage"], {"type": "networked_command", "command": ["/usr/bin/cat", "/input"],
                                               "origin": "https://git.example.test/", "prompt_variable": "GIT_ASKPASS"})
        self.assertEqual(observed[0]["upload"]["size"], len(artifact))

    def test_descriptor_unknown_fields_and_mixed_selectors_are_rejected(self):
        invalid = [
            {"type": "local_command", "command": ["/usr/bin/cat"], "token_file": "/tmp/token"},
            {"type": "networked_command", "command": ["/usr/bin/cat"], "origin": "http://example.test/", "prompt_variable": "GIT_ASKPASS"},
            {"type": "networked_command", "command": ["/usr/bin/cat"], "origin": "https://example.test:0/", "prompt_variable": "GIT_ASKPASS"},
            {"type": "https", "url": "https://example.test/", "auth": "raw_password", "password": "sentinel"},
            {"type": "https", "url": "https://example.test/", "auth": "bearer", "query": {"bad": []}},
            {"type": "https_body"},
        ]
        for usage in invalid:
            with self.subTest(usage=usage), self.assertRaises((TypeError, ValueError)):
                usage_request(usage)
        for arguments in (
            {"entry": self.entry},
            {"entry": self.entry, "action": "legacy", "usage": {"type": "local_command", "command": ["/usr/bin/cat"]}},
            {"entry": self.entry, "command": ["/usr/bin/cat"], "usage": {"type": "local_command", "command": ["/usr/bin/cat"]}},
            {"entry": self.entry, "usage": {"type": "local_command", "command": ["/usr/bin/cat"]}, "input_base64": "YQ=="},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                invocation("use_password", arguments)

    def test_command_result_or_extra_fields_cannot_leak_through_a_receipt(self):
        payload = {"operation": "use_password", "usage": {"type": "local_command", "command": ["/usr/bin/cat"]}}
        for reply in ({"outcome": "succeeded"}, {"outcome": "failed"}, {"outcome": "dispatched", "output": "secret"},
                      {"outcome": "dispatched", "http_status": 200}):
            with self.subTest(reply=reply), self.assertRaises(ListingError):
                _validate(reply, payload)
        self.assertEqual(_validate({"outcome": "dispatched"}, payload), {"outcome": "dispatched"})

    def test_mcp_descriptor_and_network_input_use_the_same_cli_contract(self):
        usage = {"type": "https", "url": "https://api.example.test/v1", "auth": "template", "method": "POST",
                 "headers": {"X-API-Key": "{{password}}"}, "json": {"task": "trial"}, "query": {"page": "1"}}
        args, data = invocation("use_password", {"entry": self.entry, "usage": usage})
        self.assertEqual(args[1:], ["use", "--json", f"--entry={self.entry}"])
        self.assertEqual(decode(data), usage)
        many_queries = {**usage, "query": {f"key-{index}": str(index) for index in range(17)}}
        self.assertEqual(usage_request(many_queries), many_queries)
        network = {"type": "networked_command", "command": ["/usr/bin/cat", "/input"],
                   "origin": "https://example.test/", "prompt_variable": "GIT_ASKPASS"}
        args, data = invocation("use_password", {"entry": self.entry, "usage": network,
                                                 "input_base64": b64encode(b"synthetic").decode()})
        self.assertEqual(args[1:], ["run", "--json", f"--entry={self.entry}",
                                    "--origin=https://example.test/", "--prompt-variable=GIT_ASKPASS", "--input",
                                    "--", "/usr/bin/cat", "/input"])
        self.assertEqual(data, b"synthetic")
        self.assertNotIn("action", OPERATIONS["use_password"][1]["inputSchema"]["required"])

    def test_detailed_status_validates_new_permissions_and_pinned_destinations(self):
        permission = {"vault": self.vault, "entry": self.entry, "group": None, "metadata": False,
                      "username": False, "url": False, "action": None, "edits": [], "uses": ["https", "https_body"],
                      "origins": ["https://api.example.test:443/"]}
        reply = {"status": "active", "identity": "Test Agent", "project": "Synthetic", "model": None, "chat": None,
                 "chat_id": None, "scope": [permission], "requested_items": [], "pending_change": None}
        request = {"operation": "access_status", "details": True}
        self.assertEqual(_validate(reply, request), reply)
        for uses, origins in ((["https_body"], permission["origins"]), (["https"], ["https://api.example.test/"]),
                              (["local_command"], permission["origins"]), (["secret"], [])):
            malformed = {**reply, "scope": [{**permission, "uses": uses, "origins": origins}]}
            with self.subTest(uses=uses, origins=origins), self.assertRaises(ListingError):
                _validate(malformed, request)
