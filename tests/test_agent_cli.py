from copy import deepcopy
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import TestCase

from keepassxc_agent_access.agent_cli import _validate, result_usage_request
from keepassxc_agent_access.protocol import ERRORS, LIST_REQUEST, ListingError, decode, encode
from keepassxc_agent_access.runner_token import credential


CLI = Path(__file__).resolve().parents[1] / "keepassxc-agent"


class AgentCliTests(TestCase):
    def test_registration_requires_complete_identity_and_rejects_identity_changes(self):
        base = {key: value for key, value in os.environ.items() if not key.startswith("KEEPASSXC_AGENT_")}
        request = {"items": [{"label": "Synthetic Entry", "metadata": True}]}
        cases = [
            ({"KEEPASSXC_AGENT_IDENTITY": "Task Agent"}, request),
            ({"KEEPASSXC_AGENT_PROJECT": "Task Project"}, request),
            ({"KEEPASSXC_AGENT_IDENTITY": "Task Agent", "KEEPASSXC_AGENT_PROJECT": "Task Project"},
             {**request, "identity": "Other Agent"}),
            ({"KEEPASSXC_AGENT_IDENTITY": "Task Agent", "KEEPASSXC_AGENT_PROJECT": "Task Project"},
             {**request, "project": "Other Project"}),
        ]
        for registered, submitted in cases:
            with self.subTest(registered=registered, submitted=submitted):
                process = subprocess.run([CLI, "access", "request", "--json"], input=encode(submitted),
                                         env={**base, **registered}, capture_output=True, check=False, timeout=7)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(process.stdout, b"")
                self.assertTrue(process.stderr.decode().strip().startswith(ERRORS["invalid_request"]))
                self.assertNotIn(b"Traceback", process.stderr)

    def test_access_details_reject_extra_fields_and_malformed_permissions(self):
        item = {"vault": "00000000-0000-0000-0000-000000000001", "entry": "00000000-0000-0000-0000-000000000002",
                "group": None, "metadata": True, "username": False, "url": False, "action": None, "edits": []}
        reply = {"status": "active", "identity": "Deployment Assistant", "project": "Deploy", "model": None,
                 "chat": None, "chat_id": None, "scope": [item], "requested_items": [{**item, "label": None}],
                 "pending_change": None}
        request = {"operation": "access_status", "details": True}
        self.assertEqual(_validate(reply, request), reply)
        malformed = []
        value = deepcopy(reply)
        value["verifier"] = "secret sentinel"
        malformed.append(value)
        value = deepcopy(reply)
        value["scope"][0]["revision"] = "secret sentinel"
        malformed.append(value)
        value = deepcopy(reply)
        value["scope"][0]["username"] = "secret sentinel"
        malformed.append(value)
        value = deepcopy(reply)
        value["scope"][0]["edits"] = ["unsupported"]
        malformed.append(value)
        value = deepcopy(reply)
        value["pending_change"] = {"id": "secret sentinel", "items": []}
        malformed.append(value)
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(ListingError):
                _validate(value, request)
        with self.assertRaises(ListingError):
            _validate(reply, {"operation": "access_status"})

        extended = {
            **reply,
            "paused": False,
            "last_change": {"id": "00000000-0000-0000-0000-000000000003", "status": "denied"},
            "scope": [{**item, "vault_locked": False, "stale": False,
                       "pinned_origins": ["https://api.example.test:443/"]}],
        }
        self.assertEqual(_validate(extended, request), extended)
        for bad in (
            {**reply, "paused": "no"},
            {**reply, "last_change": {"id": "00000000-0000-0000-0000-000000000003", "status": "pending"}},
            {**reply, "scope": [{**item, "vault_locked": "yes"}]},
            {**reply, "scope": [{**item, "pinned_origins": ["http://api.example.test/"]}]},
            {**reply, "requested_items": [{**item, "label": None, "stale": False}]},
        ):
            with self.subTest(bad=bad), self.assertRaises(ListingError):
                _validate(bad, request)

    def test_result_usage_allows_headers_on_basic_bearer_and_scalar_on_get(self):
        base = {
            "type": "https_results",
            "origin": "https://api.example.test/",
            "request": {"path": "/items", "method": "GET", "auth": "bearer", "headers": {"Accept": "application/json"}},
            "result": {"path": "/data/id", "scalar": "item_id"},
        }
        self.assertEqual(result_usage_request(base), base)
        basic = {**base, "request": {"path": "/items", "auth": "basic", "headers": {"X-Custom": "1"}}}
        self.assertEqual(result_usage_request(basic), basic)
        for auth in ("basic", "bearer"):
            with self.subTest(auth=auth), self.assertRaises(ValueError):
                result_usage_request({**base, "request": {
                    "path": "/items", "auth": auth, "headers": {"authorization": "Bearer leaked"},
                }})
        with self.assertRaises(ValueError):
            result_usage_request({**base, "result": {"path": "/data", "scalar": "password"}})

    def test_error_detail_and_acknowledged_write_exit_status(self):
        with self.assertRaises(ListingError) as error:
            _validate({"error": "invalid_request", "detail": "Supply a valid JSON object."}, {"operation": "list_vaults"})
        self.assertEqual(error.exception.code, "invalid_request")
        self.assertEqual(error.exception.detail, "Supply a valid JSON object.")
        with self.assertRaises(ListingError) as invalid_detail:
            _validate({"error": "invalid_request", "detail": "line1\nline2"}, {"operation": "list_vaults"})
        self.assertEqual(invalid_detail.exception.code, "invalid_response")

        with TemporaryDirectory(dir="/tmp") as directory, socket.socket(socket.AF_UNIX) as listener:
            root = Path(directory)
            endpoint = root / "keeper.sock"
            token_file = root / "token"
            credential(token_file, create=True)
            listener.bind(str(endpoint))
            listener.listen()
            listener.settimeout(7)

            def serve():
                conn, _ = listener.accept()
                with conn, conn.makefile("rb") as stream:
                    stream.readline()
                    conn.sendall(encode({"outcome": "acknowledged", "http_status": 204}))

            server = Thread(target=serve, daemon=True)
            server.start()
            usage = {
                "type": "https_results",
                "origin": "https://api.example.test/",
                "request": {"path": "/items", "method": "POST", "auth": "bearer"},
                "result": {"path": "/data", "columns": ["id"]},
            }
            process = subprocess.run(
                [CLI, "use", "--entry", "00000000-0000-0000-0000-000000000002", "--json"],
                input=encode(usage),
                env={"PATH": "/usr/bin:/bin", "KEEPASSXC_AGENT_SOCKET": str(endpoint),
                     "KEEPASSXC_AGENT_TOKEN_FILE": str(token_file)},
                capture_output=True, check=False, timeout=7,
            )
            server.join(7)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(decode(process.stdout), {"outcome": "acknowledged", "http_status": 204})

    def invoke(self, endpoint, fields=()):
        return subprocess.run(
            [CLI, "entries", "list", "--json", *[f"--field={field}" for field in fields]],
            env={**os.environ, "KEEPASSXC_AGENT_SOCKET": str(endpoint)},
            capture_output=True, check=False, timeout=7,
        )

    def reply(self, contents, fields=()):
        with TemporaryDirectory(dir="/tmp") as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = Path(directory) / "list.sock"
            listener.bind(str(endpoint))
            listener.listen()
            listener.settimeout(7)
            requests = []

            def serve():
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    requests.append(decode(stream.readline()))
                    connection.sendall(contents)

            server = Thread(target=serve, daemon=True)
            server.start()
            result = self.invoke(endpoint, fields)
            server.join(7)
            expected = {**LIST_REQUEST, **({"fields": list(fields)} if fields else {})}
            self.assertEqual(requests, [expected])
            return result

    def test_success_has_exact_json_and_no_diagnostics(self):
        payload = b'{"entries":[{"id":"00000000-0000-0000-0000-000000000001","title":"Sample","group_path":[]}]}\n'
        result = self.reply(payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"")

    def test_malformed_truncated_and_unavailable_never_print_data(self):
        for reply in (b'{"entries":[{"password":"secret sentinel"}]}\n',
                      b'{"entries":[]}', b'not-json\n'):
            with self.subTest(reply=reply):
                result = self.reply(reply)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"secret sentinel", result.stderr)
        with TemporaryDirectory(dir="/tmp") as directory:
            result = self.invoke(Path(directory) / "missing.sock")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Ask the vault owner", result.stderr)

    def test_size_limit_reports_a_safe_diagnostic(self):
        result = self.reply(b'{"error":"too_large"}\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"size limit", result.stderr)

    def test_metadata_fields_are_opt_in_and_must_be_strings(self):
        row = b'{"id":"00000000-0000-0000-0000-000000000001","title":"Sample","group_path":[]'
        payload = b'{"entries":[' + row + b',"username":"sample"}]}\n'
        for fields, status in (((), 1), (("url",), 1), (("username",), 0)):
            with self.subTest(fields=fields):
                result = self.reply(payload, fields)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, b"" if status else payload)
        bad = self.reply(b'{"entries":[' + row + b',"username":7}]}\n', ("username",))
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(bad.stdout, b"")

    def test_listing_can_omit_unapproved_optional_fields(self):
        payload = b'{"entries":[{"id":"00000000-0000-0000-0000-000000000001","title":"Sample","group_path":[]}]}\n'
        result = self.reply(payload, ("username", "url"))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, payload)


class EditCliTests(TestCase):
    identifier = "16a1c7bd-72e4-45a7-bdb0-6fef1918e21a"
    vault = "115e5c59-fa17-4176-a0da-21467b723cbb"
    entry = "349de400-f0c7-4cf7-829b-e6b17b753fb8"

    def setUp(self):
        temp = TemporaryDirectory(dir="/tmp")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.endpoint = self.root / "keeper.sock"
        self.token_file = self.root / "token"
        self.token = credential(self.token_file, create=True)

    def invoke(self, *args, stdin=b""):
        return subprocess.run(
            [CLI, "edits", *args, "--json"], input=stdin, capture_output=True, check=False, timeout=8,
            env={"PATH": "/usr/bin:/bin", "KEEPASSXC_AGENT_SOCKET": str(self.endpoint),
                 "KEEPASSXC_AGENT_TOKEN_FILE": str(self.token_file)},
        )

    def serve(self, *replies):
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(self.endpoint))
        listener.listen()
        listener.settimeout(8)
        observed = []

        def dispatch():
            for reply in replies:
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    observed.append(decode(stream.readline()))
                    connection.sendall(encode(reply))

        server = Thread(target=dispatch, daemon=True)
        server.start()
        return observed, server

    def test_requests_can_be_replayed_and_checked_by_id(self):
        created = {"id": self.identifier, "status": "applied", "result": self.entry}
        pending = {"id": self.identifier, "status": "pending"}
        observed, server = self.serve(pending, created, created)
        edit = {"id": self.identifier, "operation": "create_entry", "vault": self.vault,
                "parent": self.entry, "fields": {"title": "Sample"}}
        responses = [self.invoke("request", stdin=encode(edit)),
                     self.invoke("request", stdin=encode(edit)),
                     self.invoke("status", "--request", self.identifier)]
        server.join(8)
        self.assertEqual([process.returncode for process in responses], [0, 0, 0])
        self.assertEqual([decode(process.stdout) for process in responses], [pending, created, created])
        self.assertEqual(observed, [
            {"version": 1, "operation": "request_edit", "request": edit, "credential": self.token},
            {"version": 1, "operation": "request_edit", "request": edit, "credential": self.token},
            {"version": 1, "operation": "edit_status", "id": self.identifier, "credential": self.token},
        ])
        for process in responses:
            self.assertNotIn(self.token.encode(), process.stdout + process.stderr)

    def test_malformed_edits_fail_before_the_broker_and_never_echo_content(self):
        known = {"id": self.identifier, "operation": "replace_password", "vault": self.vault, "entry": self.entry,
                 "password_source": "owner"}
        references = {"id": self.identifier, "vault": self.vault, "entry": self.entry}
        malformed = (
            encode({**known, "password": "synthetic-password"}),
            encode({**known, "fields": {"password": "synthetic-password"}}),
            encode({**references, "operation": "update_entry", "fields": {"username": ["sample"]}}),
            encode({**references, "operation": "move_entry"}),
            encode({**known, "entry": "broken-id"}),
            encode(known)[:-2] + b',"operation":"replace_password"}\n',
            b'[]\n',
        )
        for request in malformed:
            with self.subTest(request=request):
                process = self.invoke("request", stdin=request)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(process.stdout, b"")
                self.assertNotIn(b"synthetic-password", process.stderr)
                self.assertIn(b"The broker rejected", process.stderr)

    def test_edit_status_rejects_response_secrets_and_wrong_references(self):
        secret = {"id": self.identifier, "status": "applied", "password": "synthetic-response-secret"}
        wrong = {"id": self.entry, "status": "pending"}
        wrong_result_status = {"id": self.identifier, "status": "denied", "result": self.entry}
        bad_create_id = {"id": self.identifier, "status": "applied", "result": "synthetic-response-secret"}
        observed, server = self.serve(secret, wrong, wrong_result_status, bad_create_id)
        for _ in range(4):
            process = self.invoke("status", "--request", self.identifier)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(process.stdout, b"")
            self.assertNotIn(b"synthetic-response-secret", process.stderr)
        server.join(8)
        self.assertEqual(len(observed), 4)

    def test_replayed_non_create_cannot_return_a_result_id(self):
        _, server = self.serve({"id": self.identifier, "status": "applied", "result": self.entry})
        edit = {"id": self.identifier, "operation": "replace_password", "vault": self.vault, "entry": self.entry,
                "password_source": "generate"}
        process = self.invoke("request", stdin=encode(edit))
        server.join(8)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stdout, b"")
