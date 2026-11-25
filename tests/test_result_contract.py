"""New result authority is explicit and result frames expose only selected data."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from uuid import uuid4

from keepassxc_agent_access.access_settings import AccessStore, ActionType
from keepassxc_agent_access.agent_cli import _validate, usage_request
from keepassxc_agent_access.agent_runner import OPERATIONS, invocation
from keepassxc_agent_access.grants import Item
from keepassxc_agent_access.protocol import ListingError, decode, encode
from keepassxc_agent_access.usage import requires_body_permission, requires_write_permission, usage_action
from keepassxc_agent_access.workspace import Workspace


def workflow():
    return {"type": "https_results", "origin": "https://inventory.example.test/",
            "login": {"path": "/api/login", "form": {"user": "{{username}}", "password": "{{password}}"},
                      "capture": {"ticket": "/data/ticket"}},
            "request": {"path": "/api/inventory", "auth": "session", "headers": {"Cookie": "Session={{session.ticket}}"}},
            "result": {"path": "/data", "columns": ["node", "status", "capacity"]}}


class ResultContractTests(TestCase):
    def test_new_grant_is_separate_and_compiles_to_the_reviewed_workflow(self):
        vault, entry = str(uuid4()), str(uuid4())
        permission = Item.parse({"vault": vault, "entry": entry, "uses": ["https_results"],
                                 "origins": ["https://inventory.example.test/"]})
        self.assertEqual(permission.uses, ("https_results",))
        self.assertFalse(permission.metadata)
        action = usage_action(entry, workflow())
        self.assertEqual(action.kind, ActionType.RESULTS)
        self.assertEqual(action.kind.review_operation, "read_results")
        self.assertEqual(action.url, permission.origins[0])
        self.assertEqual(decode(action.result_request.encode())["request"]["path"], "/api/inventory")
        self.assertIn("SHA-256", action.request_summary)
        self.assertFalse(action.opaque)
        self.assertTrue(requires_body_permission(action))
        self.assertFalse(requires_write_permission(action))
        mutation = workflow()
        mutation["request"].update(method="POST", json={"requested": True})
        self.assertTrue(requires_write_permission(usage_action(entry, mutation)))
        login_permission = Item.parse({"vault": vault, "entry": entry, "uses": ["https_results", "https_body"],
                                       "origins": ["https://inventory.example.test/"]})
        self.assertIn("https_body", login_permission.uses)
        for key in ("token", "password", "result_request"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                Item.parse({"vault": vault, "entry": entry, "uses": ["https_results"],
                            "origins": ["https://inventory.example.test/"], key: "cannot-choose-private-data"})

    def test_old_auto_approve_settings_do_not_enable_result_release(self):
        with TemporaryDirectory() as root:
            store = AccessStore(Path(root) / "access.json")
            initial = replace(store.read(), review_usage=False, review_actions=frozenset({"use_browser"}),
                              auto_approve_tokens=True, token_auto_approval_acknowledged=True)
            store.write(initial)
            saved = json.loads(store.path.read_text())
            saved.pop("review_results")
            store.path.write_text(json.dumps(saved))
            before = store.path.read_bytes()
            workspace = Workspace(root, None)
            self.assertTrue(workspace.requires_review("read_results"))
            self.assertFalse(workspace.requires_review("use_https"))
            self.assertTrue(workspace.requires_review("use_browser"))
            self.assertEqual(store.path.read_bytes(), before)
            workspace.set_review_action("read_results", False)
            restarted = Workspace(root, None)
            self.assertFalse(restarted.requires_review("read_results"))
            self.assertTrue(restarted.requires_review("use_browser"))
            self.assertTrue(store.read().auto_approve_tokens)
            self.assertNotIn("read_results", store.read().review_actions)
            workspace.set_review_action("read_results", True)
            self.assertTrue(Workspace(root, None).requires_review("read_results"))

    def test_cli_and_mcp_deliver_the_typed_descriptor_without_an_action(self):
        request = workflow()
        self.assertEqual(usage_request(request), request)
        command, data = invocation("use_password", {"entry": str(uuid4()), "usage": request})
        self.assertEqual(decode(data), request)
        self.assertNotIn("--action", " ".join(map(str, command)))
        self.assertIn("https_results", OPERATIONS["use_password"][1]["inputSchema"]["properties"]["usage"]["properties"]["type"]["enum"])
        for change in ({"origin": "http://inventory.example.test/"}, {"certificate_sha256": "--insecure"},
                       {"result": {"path": "/data", "columns": ["ticket"]}},
                       {"request": {"path": "https://elsewhere.example/", "auth": "bearer"}},
                       {"request": {"path": "/api/inventory", "auth": "session", "method": "POST", "json": {"leak": "{{session.ticket}}"}}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                usage_request({**request, **change})

    def test_reply_validation_allows_useful_rows_and_rejects_private_or_derived_frames(self):
        request = {"operation": "use_password", "usage": workflow()}
        response = {"outcome": "succeeded", "http_status": 200,
                    "data": [{"node": "worker-a", "status": "running", "capacity": 8}]}
        self.assertEqual(_validate(response, request), response)
        with self.assertRaises(ListingError):
            _validate(response, {"operation": "use_password", "usage": {"type": "https"}})
        malformed = [
            {**response, "ticket": "private"},
            {**response, "headers": {"Set-Cookie": "private"}},
            {**response, "data": [{"node": "worker-a", "status": "running", "capacity": {"token": "private"}}]},
            {**response, "data": [{"node": "worker-a", "status": "running", "capacity": 8, "ticket": "private"}]},
            {**response, "data": [{"node": "x" * 4097, "status": "running", "capacity": 8}]},
            {**response, "outcome": "failed"},
        ]
        for reply in malformed:
            with self.subTest(reply=reply), self.assertRaises(ListingError):
                _validate(reply, request)
        for reply in ({"outcome": "failed"}, {"outcome": "failed", "http_status": 401}, {"outcome": "uncertain"}):
            self.assertEqual(_validate(reply, request), reply)

    def test_write_receipt_status_is_bound_to_requested_id_and_contains_no_output(self):
        receipt = str(uuid4())
        request = {"operation": "write_status", "receipt": receipt}
        reply = {"id": receipt, "status": "acknowledged", "http_status": 204}
        self.assertEqual(_validate(reply, request), reply)
        for changes in ({"id": str(uuid4())}, {"status": "uncertain"}, {"data": []}, {"http_status": 404}):
            with self.assertRaises(ListingError):
                _validate({**reply, **changes}, request)
        command, _ = invocation("write_status", {"receipt": receipt})
        self.assertIn("--receipt=" + receipt, command)

import test_dynamic_cli as dynamic_cli


class ResultCliRoundTripTests(TestCase):
    setUp = dynamic_cli.DynamicCliTests.setUp
    exchange = dynamic_cli.DynamicCliTests.exchange

    def test_real_cli_returns_selected_inventory_and_private_profile_stays_hidden(self):
        response = {"outcome": "succeeded", "http_status": 200,
                    "data": [{"node": "node-random-fixture", "status": "running", "capacity": 12}]}
        process, observed = self.exchange(["use", "--entry", self.entry, "--vault", self.vault, "--json"],
                                          encode(workflow()), response)
        self.assertEqual((process.returncode, process.stderr), (0, b""))
        self.assertEqual(decode(process.stdout), response)
        self.assertEqual(observed[0]["usage"], workflow())
        self.assertNotIn("action", observed[0])

    def test_real_cli_rejects_server_session_fields_without_echoing_them(self):
        response = {"outcome": "succeeded", "http_status": 200,
                    "data": [{"node": "node-a", "status": "running", "capacity": 12}],
                    "ticket": "private-session-sentinel"}
        process, _ = self.exchange(["use", "--entry", self.entry, "--vault", self.vault, "--json"],
                                   encode(workflow()), response)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stdout, b"")
        self.assertNotIn(b"private-session-sentinel", process.stderr)
