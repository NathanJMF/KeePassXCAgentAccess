"""Generate a vault login, provision it through a synthetic API and verify it."""

from hashlib import sha256
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from unittest import TestCase
from uuid import UUID, uuid4

from pykeepass import PyKeePass, create_database

from keepassxc_agent_access.account_provision import parse_provision
from keepassxc_agent_access.agent_runner import invocation
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.protocol import ListingError, decode
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Workspace
import test_result_broker as broker_tests
from tls_fixture import tls_service


class ProvisionTests(TestCase):
    reviewed = broker_tests.ResultBrokerTests.reviewed

    def invoke(self, operation, **fields):
        output = []

        def live(effect=lambda: None):
            effect()
            return True

        payload = {"version": 1, "operation": operation, "credential": self.credential, **fields}
        reply = self.engine(payload, 123, None, live, live, lambda frame, guard: guard(lambda: output.append(decode(frame)) or True))
        return decode(reply) if reply else output[0]

    def test_generated_password_reaches_only_the_reviewed_site(self):
        admin_secret = "synthetic-administrative-token"
        remote = {}
        posts = []

        class Service(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_data(self, status, data):
                body = json.dumps({"data": data}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.path not in ("/accounts", "/echo") or self.headers.get("Authorization") != "Bearer " + admin_secret:
                    return self.send_error(403)
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/echo":
                    return self.send_data(200, {"id": 103, "created": data["initial_password"]})
                posts.append(tuple(sorted(data)))
                if data["login"] in remote:
                    return self.send_error(409)
                remote[data["login"]] = data["initial_password"]
                self.send_data(201, {"id": 103, "created": True, "unselected": data["initial_password"]})

            def do_GET(self):
                if self.path != "/accounts/103" or self.headers.get("Authorization") != "Bearer " + admin_secret:
                    return self.send_error(403)
                self.send_data(200, {"id": 103, "created": "example-agent" in remote})

        with TemporaryDirectory() as root, tls_service(Path(root), handler=Service) as (cert, url, _):
            base = Path(root)
            database = base / "synthetic.kdbx"
            unlock = "Synthetic vault password"
            initial = create_database(database, unlock)
            group = initial.add_group(initial.root_group, "Service Accounts")
            admin = str(initial.add_entry(group, "Service Admin", "synthetic-admin", admin_secret).uuid)
            initial.save()
            pin = sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            origin = url + "/"
            workspace = Workspace(base, None)
            self.addCleanup(workspace.lock_all)
            vault = workspace.add(VaultTarget(database), unlock, False)
            activity = ActivityStore(base / "activity.sqlite")
            activity.recover(30)
            grants = Grants(workspace, activity)
            edits = EditRequests(workspace, grants, activity)
            self.engine = ScopedBroker(workspace, grants, activity, edits=edits)
            self.credential = "7b" * 32
            workspace.pause(False)
            grants.enroll(self.credential, 123, {"identity": "Synthetic provisioner", "project": "Fixture",
                                                  "items": [
                                                      {"vault": vault, "group": str(group.uuid), "edits": ["create_entry"]},
                                                      {"vault": vault, "entry": admin, "uses": ["https_results"], "origins": [origin]},
                                                  ]}, Attribution())
            pending = grants.authenticate(self.credential, 123)
            grants.decide(pending.id, [grants.choices(item)[0] for item in pending.items])
            token = grants.authenticate(self.credential, 123)
            edit_id = str(uuid4())
            applied = edits.submit(token, {"id": edit_id, "vault": vault, "parent": str(group.uuid), "operation": "create_entry",
                                           "fields": {"title": "Generated Service Account", "username": "example-agent"},
                                           "password_source": "generate"})
            account = applied["result"]
            created = PyKeePass(database, password=unlock).find_entries(uuid=UUID(account), first=True)
            generated = created.password
            self.assertTrue(generated)
            self.assertFalse(any(scope.entry == account for scope in token.scope))

            usage = {"type": "https_results", "origin": origin, "certificate_sha256": pin, "approve_write_once": True,
                     "request": {"path": "/accounts", "method": "POST", "auth": "bearer", "json": {"enabled": True}},
                     "result": {"path": "/data", "columns": ["id", "created"]}}
            binding = {"entry": account, "body_type": "json", "fields": {"username": "login", "password": "initial_password"}}
            receipt = str(uuid4())

            def provision(receipt_id=receipt):
                return self.invoke("use_password", vault=vault, entry=admin, usage=usage, provision=binding, receipt=receipt_id)

            def inspect(ticket):
                self.assertTrue(ticket.provision_account)
                text = " ".join(ticket.scope)
                for visible in ("Generated Service Account", "Service Admin", "initial_password", pin, admin, account):
                    self.assertIn(visible, text)
                self.assertNotIn(generated, text)
                self.assertNotIn(admin_secret, text)

            response = self.reviewed(provision, inspect=inspect)
            self.assertEqual(response, {"outcome": "succeeded", "http_status": 201, "data": [{"id": 103, "created": True}]})
            self.assertTrue(remote["example-agent"] == generated)
            with self.assertRaises(ListingError) as duplicate:
                provision()
            self.assertEqual(duplicate.exception.code, "receipt_exists")
            self.assertEqual(len(posts), 1)
            self.assertEqual(self.invoke("write_status", receipt=receipt)["status"], "succeeded")
            read = {key: value for key, value in usage.items() if key != "approve_write_once"}
            read["request"] = {"path": "/accounts/103", "auth": "bearer"}
            verified = self.reviewed(lambda: self.invoke("use_password", vault=vault, entry=admin, usage=read))
            self.assertEqual(verified["data"], [{"id": 103, "created": True}])
            self.assertNotIn(generated, repr(activity.rows()))
            self.assertNotIn(admin_secret, repr(activity.rows()))
            self.assertFalse(any(scope.entry == account for scope in grants.records[token.id].scope))
            with self.assertRaises(ListingError) as declined:
                self.reviewed(lambda: provision(str(uuid4())), approve=False)
            self.assertEqual(declined.exception.code, "declined")
            self.assertEqual(len(posts), 1)
            echo = {**usage, "request": {**usage["request"], "path": "/echo"}}
            filtered = self.reviewed(lambda: self.invoke("use_password", vault=vault, entry=admin, usage=echo,
                                                         provision=binding, receipt=str(uuid4())))
            self.assertEqual(filtered, {"outcome": "acknowledged", "http_status": 200})

            def rotate(_ticket):
                workspace.put_entry(vault, str(group.uuid), entry=account, title="Generated Service Account",
                                    username="example-agent", password="Synthetic replacement")

            with self.assertRaises(ListingError) as stale:
                self.reviewed(lambda: provision(str(uuid4())), inspect=rotate)
            self.assertEqual(stale.exception.code, "revoked")
            self.assertEqual(len(posts), 1)

            def release(_ticket):
                outcome = self.invoke("release_entry", vault=vault, entry=account)
                self.assertEqual(outcome["status"], "released")

            with self.assertRaises(ListingError) as pending_release:
                self.reviewed(lambda: provision(str(uuid4())), inspect=release)
            self.assertEqual(pending_release.exception.code, "revoked")
            with self.assertRaises(ListingError) as already_released:
                provision(str(uuid4()))
            self.assertEqual(already_released.exception.code, "ineligible")
            self.assertEqual(len(posts), 1)

    def test_field_collision_and_unpinned_writes_are_rejected(self):
        proposed = {"entry": str(uuid4()), "body_type": "json", "fields": {"password": "password"}}
        workflow = {"type": "https_results", "origin": "https://fixture.test/", "certificate_sha256": "a" * 64,
                    "approve_write_once": True, "result": {"columns": ["status"]},
                    "request": {"method": "POST", "path": "/accounts", "auth": "bearer", "json": {"Password": "fixed"}}}
        with self.assertRaises(ValueError):
            parse_provision(proposed, workflow)
        workflow["request"].pop("json")
        self.assertEqual(parse_provision(proposed, workflow), proposed)
        args, body = invocation("provision_account", {"vault": str(uuid4()), "entry": str(uuid4()),
                                                      "receipt": str(uuid4()), "account": proposed["entry"],
                                                      "workflow": workflow, "body_type": "json",
                                                      "fields": proposed["fields"]})
        self.assertIn("--account=" + proposed["entry"], args)
        self.assertEqual(decode(body)["fields"], proposed["fields"])
        workflow.pop("certificate_sha256")
        with self.assertRaises(ValueError):
            parse_provision(proposed, workflow)
