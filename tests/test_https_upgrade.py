"""Tests for upgraded HTTPS delivery, certificate pinning, body limits, and error diagnostics."""

from base64 import b64encode
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import gzip
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import ipaddress
import json
import os
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from threading import Event, Thread
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch
from uuid import uuid4
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action, ActionType, HTTPS_BODY_LIMIT
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.agent_cli import _validate, main as cli_main, usage_request
from keepassxc_agent_access.agent_runner import OPERATIONS, invocation
from keepassxc_agent_access.grants import Grants, verifier
from keepassxc_agent_access.https_action import BEARER_TOKEN, SOCKET_TIMEOUT, authenticate, prepare_https
from keepassxc_agent_access.protocol import ListingError, REQUEST_LIMIT, decode, encode
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.usage import usage_action
from keepassxc_agent_access.vault import VaultTarget, open_vault
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace


def _write_self_signed_cert(directory: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    fingerprint = sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, fingerprint


@contextmanager
def _ephemeral_tls_server(directory: Path, handler_cls):
    cert_path, key_path, fingerprint = _write_self_signed_cert(directory)
    with ThreadingHTTPServer(("127.0.0.1", 0), handler_cls) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield cert_path, fingerprint, f"https://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()


class HttpsUpgradeActionTests(TestCase):
    def test_limits_and_timeout_raised(self):
        self.assertEqual(REQUEST_LIMIT, 131072)
        self.assertEqual(HTTPS_BODY_LIMIT, 65536)
        self.assertEqual(SOCKET_TIMEOUT, 15)

    def test_relaxed_bearer_token_allows_printable_ascii_and_blocks_whitespace_controls(self):
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 200
        for token in ("user:secret@host!~", "PVEAPIToken=root@pam!agent=uuid-1234", "a,b=c/d+e"):
            with self.subTest(token=token):
                self.assertTrue(BEARER_TOKEN.fullmatch(token))
                self.assertEqual(
                    authenticate(connection, "/check", SimpleNamespace(password=token), ActionType.BEARER),
                    {"outcome": "succeeded", "http_status": 200},
                )
        connection.reset_mock()
        for bad in (None, "", "has space", "lead ", "tab\there", "nl\ninject", "del\x7f", "nonascii\u00e9"):
            with self.subTest(bad=bad):
                self.assertEqual(
                    authenticate(connection, "/check", SimpleNamespace(password=bad), ActionType.BEARER),
                    {"outcome": "failed"},
                )
        connection.request.assert_not_called()

    def test_prepare_https_certificate_pin_match_and_mismatch(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass

            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

        with TemporaryDirectory() as tmp, _ephemeral_tls_server(Path(tmp), Handler) as (_, fingerprint, url):
            entry = SimpleNamespace(password="tok:abc@123", username="u")

            with prepare_https(url + "/ok", certificate_sha256=fingerprint) as (conn, path):
                self.assertEqual(
                    authenticate(conn, path, entry, ActionType.BEARER),
                    {"outcome": "succeeded", "http_status": 200},
                )
            self.assertEqual(seen, ["Bearer tok:abc@123"])

            wrong_pin = "0" * 64 if fingerprint != "0" * 64 else "1" * 64
            with self.assertRaisesRegex(ValueError, "The approved certificate changed"):
                with prepare_https(url + "/ok", certificate_sha256=wrong_pin):
                    pass

            for invalid_pin in ("", "a" * 63, "A" * 64, "g" * 64, 123):
                with self.subTest(invalid_pin=invalid_pin), self.assertRaises(ValueError):
                    with prepare_https(url + "/ok", certificate_sha256=invalid_pin):
                        pass

    def test_32kib_request_json_body_delivery_over_pinned_tls(self):
        received = []
        payload = {"blob": "x" * 32768}
        secret = "tok:32k@host"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                received.append((self.headers.get("Authorization"), json.loads(self.rfile.read(length))))
                self.send_response(200)
                self.end_headers()

        with TemporaryDirectory() as tmp, _ephemeral_tls_server(Path(tmp), Handler) as (_, fingerprint, url):
            root = Path(tmp)
            db_path = root / "vault.kdbx"
            kp = create_database(db_path, "unlock-pass")
            entry = kp.add_entry(kp.root_group, "API", "user", secret)
            kp.save()

            action = usage_action(
                str(entry.uuid),
                {
                    "type": "https",
                    "url": url + "/items",
                    "auth": "bearer",
                    "method": "POST",
                    "json": payload,
                    "certificate_sha256": fingerprint,
                },
            )
            self.assertGreater(len(action.request_json.encode("utf-8")), 32768)

            def allow(send):
                send()
                return True

            with open_vault(VaultTarget(db_path), "unlock-pass", Event()) as worker:
                self.assertEqual(worker.use(action, allow), {"outcome": "succeeded", "http_status": 200})
                bad_action = Action(
                    "bad", "Bad Pin", str(entry.uuid), url + "/items",
                    kind=ActionType.BEARER, method="POST",
                    certificate_sha256=("0" * 64 if fingerprint != "0" * 64 else "1" * 64),
                )
                failed = worker.use(bad_action, allow)
                self.assertEqual(failed["outcome"], "failed")
                self.assertIn("approved certificate changed", failed["error_detail"])
                self.assertLessEqual(len(failed["error_detail"]), 240)
        self.assertEqual(received, [(f"Bearer {secret}", payload)])

    def test_error_detail_scrubs_secrets_strips_ansi_and_decodes_gzip_and_deflate(self):
        secret = "s3cr3t:tok@val"
        username = "alice"
        basic_b64 = b64encode(f"{username}:{secret}".encode()).decode("ascii")
        cases = [
            (401, None, f"\x1b[31mDenied\x1b[0m\nauth=Basic {basic_b64} user={username}:{secret} pass={secret}"),
            (500, "gzip", gzip.compress(f"Server error: Bearer {secret} failed validation".encode("utf-8"))),
            (502, "deflate", zlib.compress(f"Gateway timeout for {secret}: trailing " + ("z" * 700)).encode("utf-8") if False
             else zlib.compress(("Gateway error for " + secret + " " + ("z" * 700)).encode("utf-8"))),
        ]

        for status, encoding, raw_body in cases:
            with self.subTest(status=status, encoding=encoding):
                headers = EmailMessage()
                if encoding:
                    headers["Content-Encoding"] = encoding
                stream = BytesIO(raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body)
                resp = MagicMock()
                resp.status = status
                resp.headers = headers
                resp.read.side_effect = stream.read
                conn = MagicMock()
                conn.getresponse.return_value.__enter__.return_value = resp

                kind = ActionType.BASIC if status == 401 else ActionType.BEARER
                result = authenticate(conn, "/err", SimpleNamespace(username=username, password=secret), kind)
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["http_status"], status)
                detail = result["error_detail"]
                self.assertLessEqual(len(detail), 512)
                self.assertNotIn(secret, detail)
                self.assertNotIn(basic_b64, detail)
                self.assertNotIn("\x1b", detail)
                self.assertIn("[REDACTED]", detail)
                if status == 401:
                    self.assertTrue(detail.startswith("Denied auth="))
                elif status == 500:
                    self.assertEqual(detail, "Server error: [REDACTED] failed validation")
                else:
                    self.assertTrue(detail.startswith("Gateway error for [REDACTED] z"))

    def test_template_error_detail_scrubs_rendered_headers_and_handles_exception(self):
        secret = "tmpl-secret-99"
        username = "bob"
        raw = json.dumps({"error": f"bad key key-{secret} and {username}:{secret}"}).encode("utf-8")
        headers = EmailMessage()
        headers["Content-Encoding"] = "gzip"
        stream = BytesIO(gzip.compress(raw))
        resp = MagicMock()
        resp.status = 403
        resp.headers = headers
        resp.read.side_effect = stream.read
        conn = MagicMock()
        conn.getresponse.return_value.__enter__.return_value = resp

        result = authenticate(
            conn, "/tmpl", SimpleNamespace(username=username, password=secret),
            ActionType.TEMPLATE, method="POST",
            headers=(("X-Api-Key", "key-{{password}}"), ("Accept", "application/json")),
            request_json='{"token":"{{password}}"}',
        )
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["http_status"], 403)
        self.assertNotIn(secret, result["error_detail"])
        self.assertNotIn(f"key-{secret}", result["error_detail"])
        self.assertIn("[REDACTED]", result["error_detail"])

        # Transport exception yields secret-free bounded error_detail.
        failing_conn = MagicMock()
        failing_conn.request.side_effect = TimeoutError(f"timed out sending {secret}")
        err_result = authenticate(
            failing_conn, "/tmpl", SimpleNamespace(username=username, password=secret),
            ActionType.TEMPLATE, method="POST",
            headers=(("X-Api-Key", "key-{{password}}"),),
        )
        self.assertEqual(err_result["outcome"], "uncertain")
        self.assertNotIn(secret, err_result["error_detail"])
        self.assertIn("[REDACTED]", err_result["error_detail"])
        self.assertLessEqual(len(err_result["error_detail"]), 240)


class ValidationAndBrokerUpgradeTests(TestCase):
    def test_usage_and_runner_support_certificate_sha256_and_64kib_body(self):
        entry = str(uuid4())
        pin = "a" * 64
        large_json = {"data": "k" * 65000}
        descriptor = {
            "type": "https",
            "url": "https://api.example.invalid/v1/items",
            "auth": "bearer",
            "method": "POST",
            "json": large_json,
            "certificate_sha256": pin,
        }
        action = usage_action(entry, descriptor)
        self.assertEqual(action.certificate_sha256, pin)
        self.assertLessEqual(len(action.request_json.encode("utf-8")), HTTPS_BODY_LIMIT)
        self.assertEqual(usage_request(descriptor)["certificate_sha256"], pin)

        cmd, stdin_bytes = invocation("use_password", {"entry": entry, "usage": descriptor})
        self.assertIn("use", cmd)
        self.assertEqual(decode(stdin_bytes)["certificate_sha256"], pin)
        self.assertLess(len(stdin_bytes), REQUEST_LIMIT)

        # Schema exposes certificate_sha256 on https usage variant.
        https_variant = OPERATIONS["use_password"][1]["inputSchema"]["properties"]["usage"]["oneOf"][2]
        self.assertEqual(https_variant["properties"]["type"]["enum"], ["https"])
        self.assertIn("certificate_sha256", https_variant["properties"])

        # Over 64 KiB body is rejected.
        with self.assertRaises(ValueError):
            usage_action(entry, {**descriptor, "json": {"data": "k" * 66000}})
        # Bad certificate_sha256 is rejected.
        for bad_pin in ("", "z" * 64, "A" * 64, 123):
            with self.subTest(bad_pin=bad_pin):
                with self.assertRaises(ValueError):
                    usage_action(entry, {**descriptor, "certificate_sha256": bad_pin})
                with self.assertRaises(ValueError):
                    usage_request({**descriptor, "certificate_sha256": bad_pin})

    def test_cli_certificate_sha256_flag_and_validate_extras(self):
        entry = str(uuid4())
        pin = "b" * 64
        https_payload = {"operation": "use_password", "usage": {"type": "https", "url": "https://api.example.invalid/x", "auth": "bearer"}}
        results_payload = {
            "operation": "use_password",
            "usage": {
                "type": "https_results",
                "origin": "https://api.example.invalid/",
                "request": {"path": "/x", "auth": "bearer", "method": "GET"},
                "result": {"path": "/id", "scalar": "id", "headers": ["ETag"]},
            },
        }

        # Valid responses with optional error_detail and safe requested headers.
        self.assertEqual(
            _validate({"outcome": "failed", "http_status": 401, "error_detail": "Denied\nLine 2"}, https_payload),
            {"outcome": "failed", "http_status": 401, "error_detail": "Denied\nLine 2"},
        )
        self.assertEqual(
            _validate({"outcome": "uncertain", "error_detail": "Timed out"}, https_payload),
            {"outcome": "uncertain", "error_detail": "Timed out"},
        )
        self.assertEqual(
            _validate(
                {"outcome": "succeeded", "http_status": 200, "data": [{"id": 7}], "headers": {"ETag": '"v1"'}},
                results_payload,
            ),
            {"outcome": "succeeded", "http_status": 200, "data": [{"id": 7}], "headers": {"ETag": '"v1"'}},
        )
        self.assertEqual(
            _validate({"outcome": "failed", "http_status": 500, "error_detail": "Boom"}, results_payload),
            {"outcome": "failed", "http_status": 500, "error_detail": "Boom"},
        )

        # Strict type and safety checks reject malformed error_detail or unsafe/unexpected headers.
        for bad_reply in (
            {"outcome": "succeeded", "http_status": 200, "error_detail": "No"},
            {"outcome": "failed", "http_status": 500, "error_detail": 123},
            {"outcome": "failed", "http_status": 500, "error_detail": "bad\x00byte"},
            {"outcome": "failed", "http_status": 500, "headers": {"X-Bad": "42"}},
            {"outcome": "succeeded", "http_status": 200, "headers": {"X-Rate": "9"}},
            {"outcome": "succeeded", "http_status": 200, "headers": ["not-a-dict"]},
            {"outcome": "succeeded", "http_status": 200, "headers": {"": "v"}},
        ):
            with self.subTest(bad_reply=bad_reply), self.assertRaises(ListingError):
                _validate(bad_reply, https_payload)
        for bad_results_reply in (
            {"outcome": "succeeded", "http_status": 200, "data": [{"id": 7}], "headers": {"Set-Cookie": "private"}},
            {"outcome": "succeeded", "http_status": 200, "data": [{"id": 7}], "headers": {"X-Other": "1"}},
            {"outcome": "failed", "http_status": 500, "headers": {"ETag": '"v1"'}},
        ):
            with self.subTest(bad_results_reply=bad_results_reply), self.assertRaises(ListingError):
                _validate(bad_results_reply, results_payload)

        # CLI --certificate-sha256 injects certificate_sha256 into stdin descriptor.
        captured = {}

        def fake_request(endpoint, payload, **_kwargs):
            captured["payload"] = payload
            return {"outcome": "succeeded", "http_status": 200}

        stdin_bytes = encode({"type": "https", "url": "https://api.example.invalid/x", "auth": "bearer"})
        with patch("keepassxc_agent_access.agent_cli.request", side_effect=fake_request), \
                patch.dict(os.environ, {"KEEPASSXC_AGENT_SOCKET": "/tmp/fake.sock"}), \
                patch("sys.stdin", SimpleNamespace(buffer=BytesIO(stdin_bytes))), \
                patch("sys.stdout", SimpleNamespace(buffer=BytesIO())):
            rc = cli_main(["use", "--entry", entry, "--certificate-sha256", pin, "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(captured["payload"]["usage"]["certificate_sha256"], pin)

    def test_scoped_broker_supports_certificate_sha256_on_https_and_preserves_error_detail(self):
        with TemporaryDirectory() as tmp:
            workspace = Workspace(tmp, None)
            activity = ActivityStore(workspace.directory / "activity.sqlite")
            activity.recover(30)
            grants = Grants(workspace, activity)
            engine = ScopedBroker(workspace, grants, activity)
            vault = str(uuid4())
            entry = str(uuid4())
            secret = "0a" * 32
            pin = "c" * 64
            seen_actions = []

            entry_row = {"id": entry, "title": "Self-Signed API", "group_path": ["Infra"]}

            class FakeWorker:
                available = True
                row = entry_row

                def scoped_entries(self, identifiers):
                    return {"entries": [self.row] if entry in identifiers else []}

                def entry(self, _):
                    return self.row

                def use(self, action, gate):
                    seen_actions.append(action)
                    if not gate(lambda: None):
                        raise ListingError("revoked")
                    return {
                        "outcome": "failed",
                        "http_status": 401,
                        "error_detail": "Denied by upstream [REDACTED]",
                        "headers": {"X-Request-Id": "req-1"},
                    }

            workspace.registrations[vault] = Registration(vault, "0", VaultTarget(Path("fixture.kdbx")), None, None)
            row = {**entry_row, "username": "u", "url": "https://self.example.test/", "password": "p", "group": str(uuid4())}
            workspace.sessions[vault] = Unlocked(FakeWorker(), (), (row,))
            workspace.pause(False)
            workspace.set_review_action("use_https", False)

            item = {"vault": vault, "entry": entry, "uses": ["https"], "origins": ["https://self.example.test/"]}
            grants.enroll(secret, 1500, {"identity": "Agent", "project": "Proj", "items": [item]}, Attribution())
            grant_id = grants.credentials[verifier(secret)]
            grants.decide(grant_id, [grants.choices(grants.records[grant_id].items[0])[0]])

            def invoke(usage_desc):
                out = []
                data = {"version": 1, "operation": "use_password", "credential": secret, "vault": vault, "entry": entry, "usage": usage_desc}
                engine(data, 1500, Attribution(), lambda e=lambda: None: e() or True, lambda e=lambda: None: e() or True,
                       lambda frame, guard: guard(lambda: out.append(decode(frame)) or True))
                return out[0]

            with patch.object(engine.approvals, "wait", return_value="approved") as wait_mock:
                result = invoke({
                    "type": "https",
                    "url": "https://self.example.test/v1/ping",
                    "auth": "bearer",
                    "certificate_sha256": pin,
                })
            wait_mock.assert_called_once()
            ticket = wait_mock.call_args.args[0]
            self.assertIn(pin, ticket.scope[1])
            self.assertTrue(any("Verify this certificate fingerprint" in line for line in ticket.scope))
            self.assertFalse(ticket.trusts_certificate)
            self.assertIn(f"Certificate SHA-256: {pin}", activity.rows(action="Use password")[0]["scope"])
            self.assertEqual(seen_actions[0].certificate_sha256, pin)
            self.assertEqual(result, {
                "outcome": "failed",
                "http_status": 401,
                "error_detail": "Denied by upstream [REDACTED]",
                "headers": {"X-Request-Id": "req-1"},
            })

            # When the grant also includes https_results, certificate pin trust is persisted and reused.
            secret2 = "0b" * 32
            item2 = {"vault": vault, "entry": entry, "uses": ["https", "https_results"], "origins": ["https://self.example.test/"]}
            grants.enroll(secret2, 1500, {"identity": "Agent2", "project": "Proj", "items": [item2]}, Attribution())
            grant2_id = grants.credentials[verifier(secret2)]
            grants.decide(grant2_id, [grants.choices(grants.records[grant2_id].items[0])[0]])

            def invoke2(usage_desc):
                out = []
                data = {"version": 1, "operation": "use_password", "credential": secret2, "vault": vault, "entry": entry, "usage": usage_desc}
                engine(data, 1500, Attribution(), lambda e=lambda: None: e() or True, lambda e=lambda: None: e() or True,
                       lambda frame, guard: guard(lambda: out.append(decode(frame)) or True))
                return out[0]

            with patch.object(engine.approvals, "wait", return_value="approved") as wait_first:
                invoke2({"type": "https", "url": "https://self.example.test/v1/ping", "auth": "bearer", "certificate_sha256": pin})
            self.assertTrue(wait_first.call_args.args[0].trusts_certificate)
            with patch.object(engine.approvals, "wait", side_effect=AssertionError("Should reuse trusted pin")):
                invoke2({"type": "https", "url": "https://self.example.test/v1/ping", "auth": "bearer", "certificate_sha256": pin})
