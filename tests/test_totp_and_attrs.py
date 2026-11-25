"""Unit tests for TOTP calculation, KeePass custom attributes, and template/result delivery."""

from base64 import b32encode, b64encode
from email.message import EmailMessage
import gzip
from hashlib import sha256
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

from pykeepass import PyKeePass, create_database

from keepassxc_agent_access.access_settings import ActionType
from keepassxc_agent_access.https_action import authenticate, authenticate_template
from keepassxc_agent_access.result_delivery import deliver_results, parse_result_usage
from keepassxc_agent_access.totp import compute_totp, entry_custom_attr, entry_totp
from tls_fixture import tls_service


# RFC 6238 Appendix B test secrets and expected 8-digit TOTP values.
_RFC6238_SECRETS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
_RFC6238_VECTORS = [
    (59, "SHA1", "94287082"),
    (59, "SHA256", "46119246"),
    (59, "SHA512", "90693936"),
    (1111111109, "SHA1", "07081804"),
    (1111111109, "SHA256", "68084774"),
    (1111111109, "SHA512", "25091201"),
    (1111111111, "SHA1", "14050471"),
    (1111111111, "SHA256", "67062674"),
    (1111111111, "SHA512", "99943326"),
    (1234567890, "SHA1", "89005924"),
    (1234567890, "SHA256", "91819424"),
    (1234567890, "SHA512", "93441116"),
    (2000000000, "SHA1", "69279037"),
    (2000000000, "SHA256", "90698825"),
    (2000000000, "SHA512", "38618901"),
    (20000000000, "SHA1", "65353130"),
    (20000000000, "SHA256", "77737706"),
    (20000000000, "SHA512", "47863826"),
]


class TotpModuleTests(TestCase):
    def test_rfc6238_appendix_b_vectors(self):
        for timestamp, algorithm, expected in _RFC6238_VECTORS:
            secret_b32 = b32encode(_RFC6238_SECRETS[algorithm]).decode("ascii")
            uri = f"otpauth://totp/Test:user?secret={secret_b32}&algorithm={algorithm.lower()}&digits=8&period=30"
            with self.subTest(timestamp=timestamp, algorithm=algorithm):
                self.assertEqual(compute_totp(uri, now=timestamp), expected)

    def test_raw_base32_formatting_padding_and_uri_defaults(self):
        raw_b32 = b32encode(b"12345678901234567890").decode("ascii").rstrip("=")
        spaced = " ".join(raw_b32[i:i + 4].lower() for i in range(0, len(raw_b32), 4))
        hyphenated = "-".join(raw_b32[i:i + 4] for i in range(0, len(raw_b32), 4))
        expected_6 = compute_totp(f"otpauth://totp/Example?secret={raw_b32}", now=59)
        self.assertEqual(len(expected_6), 6)
        self.assertEqual(compute_totp(spaced, now=59), expected_6)
        self.assertEqual(compute_totp(hyphenated, now=59), expected_6)
        # Unpadded base32 whose length is not a multiple of 8 (e.g., "MY" -> b"f")
        unpadded = b32encode(b"f").decode("ascii").rstrip("=")
        self.assertEqual(compute_totp(unpadded, now=59), compute_totp("MY======", now=59))
        # Custom period & digits
        self.assertEqual(len(compute_totp(f"otpauth://totp/Ex?secret={raw_b32}&digits=10&period=60", now=120)), 10)

    def test_compute_totp_rejects_invalid_inputs(self):
        valid_b32 = b32encode(b"12345678901234567890").decode("ascii")
        bad_inputs = [
            "",
            "   ",
            None,
            123,
            "not-valid-base32!@#",
            "====",
            "A",
            "JBSWY3DP====",
            f"otpauth://hotp/Test?secret={valid_b32}&counter=1",
            f"http://totp/Test?secret={valid_b32}",
            "otpauth://totp/Test?digits=6",
            "otpauth://totp/Test?secret=",
            f"otpauth://totp/Test?secret={valid_b32}&digits=5",
            f"otpauth://totp/Test?secret={valid_b32}&digits=11",
            f"otpauth://totp/Test?secret={valid_b32}&digits=abc",
            f"otpauth://totp/Test?secret={valid_b32}&period=0",
            f"otpauth://totp/Test?secret={valid_b32}&period=301",
            f"otpauth://totp/Test?secret={valid_b32}&algorithm=MD5",
        ]
        for bad in bad_inputs:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                compute_totp(bad, now=59)

        for bad_now in (-1, -0.1, True, float("nan"), float("inf")):
            with self.subTest(bad_now=bad_now), self.assertRaises(ValueError):
                compute_totp(valid_b32, now=bad_now)

    def test_entry_totp_and_custom_attr_including_pykeepass(self):
        secret_b32 = b32encode(_RFC6238_SECRETS["SHA1"]).decode("ascii")
        uri = f"otpauth://totp/Svc:u?secret={secret_b32}&digits=8&period=30"

        # 1. entry.otp
        e1 = SimpleNamespace(otp=uri, custom_properties={})
        self.assertEqual(entry_totp(e1, now=59), ("94287082", uri))

        # 2. custom_properties["otp"]
        e2 = SimpleNamespace(otp=None, custom_properties={"otp": uri})
        self.assertEqual(entry_totp(e2, now=59), ("94287082", uri))

        # 3. KeePassXC TOTP Seed + TOTP Settings
        e3 = SimpleNamespace(otp=None, custom_properties={"TOTP Seed": secret_b32, "TOTP Settings": "30;8"})
        self.assertEqual(entry_totp(e3, now=59), ("94287082", secret_b32))

        e3_default = SimpleNamespace(otp=None, custom_properties={"TOTP Seed": secret_b32})
        self.assertEqual(entry_totp(e3_default, now=59), (compute_totp(secret_b32, now=59), secret_b32))

        # 4. Real PyKeePass entry round-trip
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vault.kdbx"
            kp = create_database(db_path, "unlock")
            item = kp.add_entry(kp.root_group, "Svc", "alice", "pw")
            item.otp = uri
            item.set_custom_property("api_key", "k-real-123")
            kp.save()
            loaded = PyKeePass(db_path, password="unlock").entries[0]
            self.assertEqual(entry_totp(loaded, now=59), ("94287082", uri))
            self.assertEqual(entry_custom_attr(loaded, "api_key"), "k-real-123")

        # 5. Missing/invalid OTP and custom attributes
        with self.assertRaisesRegex(ValueError, "Entry has no TOTP secret"):
            entry_totp(SimpleNamespace(otp=None, custom_properties={}))
        with self.assertRaises(ValueError):
            entry_totp(SimpleNamespace(otp=None, custom_properties={"TOTP Seed": secret_b32, "TOTP Settings": "bad"}))

        e_attrs = SimpleNamespace(custom_properties={
            "api_key": "attr-secret",
            "empty": "",
            "otp": uri,
            "TOTP Seed": secret_b32,
            "TOTP Settings": "30;6",
        })
        self.assertEqual(entry_custom_attr(e_attrs, "api_key"), "attr-secret")
        for bad_name in ("", "bad name", "a" * 65, "otp", "TOTP Seed", "TOTP Settings", "missing", "empty"):
            with self.subTest(bad_name=bad_name), self.assertRaises(ValueError):
                entry_custom_attr(e_attrs, bad_name)


class HttpsActionTemplateTotpTests(TestCase):
    def test_template_substitutes_totp_and_custom_attr_and_scrubs_errors(self):
        secret_b32 = b32encode(_RFC6238_SECRETS["SHA1"]).decode("ascii")
        otp_uri = f"otpauth://totp/Svc:u?secret={secret_b32}&digits=8&period=30"
        api_key = "ak_live_99887766"
        entry = SimpleNamespace(
            username="svc-user",
            password="",
            otp=otp_uri,
            custom_properties={"api_key": api_key},
        )

        # Success path without needing entry.password when {{password}} is not referenced
        conn = MagicMock()
        ok_resp = conn.getresponse.return_value.__enter__.return_value
        ok_resp.status = 200
        with patch("keepassxc_agent_access.totp.time.time", return_value=59):
            res = authenticate_template(
                conn, "/auth", entry, method="POST",
                headers=(("X-API-Key", "Key {{attr.api_key}}"), ("X-OTP", "{{totp}}")),
                request_json='{"user":"{{username}}","otp":"{{totp}}","key":"{{attr.api_key}}"}',
            )
        self.assertEqual(res, {"outcome": "succeeded", "http_status": 200})
        sent = conn.request.call_args
        self.assertEqual(sent.kwargs["headers"]["X-API-Key"], f"Key {api_key}")
        self.assertEqual(sent.kwargs["headers"]["X-OTP"], "94287082")
        self.assertEqual(json.loads(sent.kwargs["body"]), {"user": "svc-user", "otp": "94287082", "key": api_key})

        # 4xx/5xx error bodies (plain & gzip) scrub TOTP code, OTP URI, raw secret, and custom attr
        for status, encoding in ((401, None), (502, "gzip")):
            with self.subTest(status=status, encoding=encoding):
                raw_msg = f"Rejected code=94287082 key={api_key} uri={otp_uri} raw={secret_b32}".encode("utf-8")
                payload = gzip.compress(raw_msg) if encoding == "gzip" else raw_msg
                hdrs = EmailMessage()
                if encoding:
                    hdrs["Content-Encoding"] = encoding
                stream = BytesIO(payload)
                resp = MagicMock()
                resp.status = status
                resp.headers = hdrs
                resp.read.side_effect = stream.read
                err_conn = MagicMock()
                err_conn.getresponse.return_value.__enter__.return_value = resp
                with patch("keepassxc_agent_access.totp.time.time", return_value=59):
                    err = authenticate(
                        err_conn, "/auth", entry, ActionType.TEMPLATE, method="POST",
                        headers=(("X-API-Key", "{{attr.api_key}}"),),
                        request_json='{"otp":"{{totp}}"}',
                    )
                self.assertEqual(err["outcome"], "failed")
                self.assertEqual(err["http_status"], status)
                detail = err["error_detail"]
                for leaked in ("94287082", api_key, otp_uri, secret_b32):
                    self.assertNotIn(leaked, detail)
                self.assertIn("[REDACTED]", detail)

    def test_template_rejects_unknown_placeholders_and_missing_totp_or_attr(self):
        conn = MagicMock()
        entry = SimpleNamespace(username="u", password="pw", otp=None, custom_properties={})
        bad_cases = [
            {"headers": (("X-Bad", "{{unknown}}"),)},
            {"headers": (("X-Bad", "{{session.tok}}"),)},
            {"headers": (("X-Bad", "{{attr.otp}}"),)},
            {"headers": (("X-Bad", "{{attr.}}"),)},
            {"headers": (("X-Bad", "{{unclosed"),)},
            {"request_json": '{"{{password}}":"x"}'},
            {"request_json": '{"otp":"{{totp}}"}'},  # entry has no TOTP
            {"headers": (("X-Key", "{{attr.missing_key}}"),)},  # entry has no attr
        ]
        for case in bad_cases:
            with self.subTest(case=case):
                res = authenticate_template(conn, "/auth", entry, method="POST", **case)
                self.assertEqual(res, {"outcome": "failed"})
        conn.request.assert_not_called()


class ResultDeliveryTotpAndAttrsTests(TestCase):
    def test_result_delivery_with_totp_and_custom_attr_and_leak_protection(self):
        secret_b32 = b32encode(_RFC6238_SECRETS["SHA1"]).decode("ascii")
        otp_uri = f"otpauth://totp/Svc:u?secret={secret_b32}&digits=8&period=30"
        tenant_token = "tenant-tok-secret-xyz"
        session_ticket = "sess-ticket-abc123456"
        seen = []

        class Service(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass

            def respond(self, payload, status=200):
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8")).items()}
                seen.append(("POST", self.path, body, self.headers.get("X-Tenant-Auth")))
                if self.path == "/login" and body == {"otp": "94287082"} and self.headers.get("X-Tenant-Auth") == tenant_token:
                    self.respond({"data": {"ticket": session_ticket}})
                else:
                    self.respond({"error": f"bad otp=94287082 token={tenant_token} uri={otp_uri}"}, status=401)

            def do_GET(self):
                seen.append(("GET", self.path, self.headers.get("X-OTP"), self.headers.get("X-Tenant-Auth"), self.headers.get("Cookie")))
                if self.path == "/items":
                    self.respond({"data": [{"name": "ok-node", "status": "ready"}]})
                elif self.path == "/echo-totp":
                    self.respond({"data": [{"name": "94287082"}]})
                elif self.path == "/echo-attr":
                    self.respond({"data": [{"name": tenant_token}]})
                elif self.path == "/echo-attr-b64":
                    self.respond({"data": [{"name": b64encode(tenant_token.encode()).decode()}]})
                elif self.path == "/fail":
                    self.respond({"error": f"failed 94287082 {tenant_token} {secret_b32}"}, status=500)

        with TemporaryDirectory() as tmp, tls_service(tmp, handler=Service) as (cert, origin, _):
            pin = sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest()
            entry = SimpleNamespace(
                username="svc-user",
                password="",
                otp=otp_uri,
                custom_properties={"tenant_token": tenant_token},
            )

            with patch("keepassxc_agent_access.totp.time.time", return_value=59):
                # 1. Login using {{totp}} + {{attr.tenant_token}} without password
                login_cfg = {
                    "type": "https_results",
                    "origin": origin,
                    "certificate_sha256": pin,
                    "login": {
                        "path": "/login",
                        "headers": {"X-Tenant-Auth": "{{attr.tenant_token}}"},
                        "form": {"otp": "{{totp}}"},
                        "capture": {"ticket": "/data/ticket"},
                    },
                    "request": {
                        "path": "/items",
                        "auth": "session",
                        "headers": {"Cookie": "Auth={{session.ticket}}"},
                    },
                    "result": {"path": "/data", "columns": ["name", "status"]},
                }
                res = deliver_results(login_cfg, entry, lambda: True)
                self.assertEqual(res, {"outcome": "succeeded", "http_status": 200, "data": [{"name": "ok-node", "status": "ready"}]})

                # 2. request.headers with auth="template" using {{totp}} + {{attr.tenant_token}}
                tmpl_cfg = {
                    "type": "https_results",
                    "origin": origin,
                    "certificate_sha256": pin,
                    "request": {
                        "path": "/items",
                        "auth": "template",
                        "headers": {"X-OTP": "{{totp}}", "X-Tenant-Auth": "{{attr.tenant_token}}"},
                    },
                    "result": {"path": "/data", "columns": ["name", "status"]},
                }
                res2 = deliver_results(tmpl_cfg, entry, lambda: True)
                self.assertEqual(res2, {"outcome": "succeeded", "http_status": 200, "data": [{"name": "ok-node", "status": "ready"}]})

                # 3. TOTP code and custom attr (raw & encoded) cannot be projected out
                for path in ("/echo-totp", "/echo-attr", "/echo-attr-b64"):
                    with self.subTest(path=path):
                        echo_res = deliver_results({**tmpl_cfg, "request": {**tmpl_cfg["request"], "path": path}}, entry, lambda: True)
                        self.assertEqual(echo_res["outcome"], "failed")
                        self.assertNotIn("data", echo_res)
                        for secret in ("94287082", tenant_token, otp_uri, secret_b32):
                            self.assertNotIn(secret, json.dumps(echo_res))

                # 4. 4xx/5xx error_detail scrubs TOTP code, OTP secret/URI, and custom attr
                fail_res = deliver_results({**tmpl_cfg, "request": {**tmpl_cfg["request"], "path": "/fail"}}, entry, lambda: True)
                self.assertEqual(fail_res["outcome"], "failed")
                self.assertEqual(fail_res["http_status"], 500)
                for secret in ("94287082", tenant_token, secret_b32):
                    self.assertNotIn(secret, fail_res["error_detail"])
                self.assertIn("[REDACTED]", fail_res["error_detail"])

                login_fail = deliver_results(
                    {**login_cfg, "login": {**login_cfg["login"], "path": "/login-bad"}},
                    entry,
                    lambda: True,
                )
                self.assertEqual(login_fail["outcome"], "failed")
                self.assertEqual(login_fail["http_status"], 401)
                for secret in ("94287082", tenant_token, otp_uri):
                    self.assertNotIn(secret, login_fail["error_detail"])
                self.assertIn("[REDACTED]", login_fail["error_detail"])

            # 5. Missing TOTP or custom attr fails cleanly before dispatching any HTTP call
            calls = []
            seen.clear()
            missing_entry = SimpleNamespace(username="u", password="", otp=None, custom_properties={})
            missing_totp = deliver_results(tmpl_cfg, missing_entry, lambda: calls.append(True) or True)
            self.assertEqual(missing_totp["outcome"], "failed")
            self.assertIn("TOTP", missing_totp.get("error_detail", ""))
            self.assertEqual(calls, [])
            self.assertEqual(seen, [])

            missing_attr_cfg = {
                "type": "https_results",
                "origin": origin,
                "certificate_sha256": pin,
                "request": {"path": "/items", "auth": "template", "headers": {"X-Key": "{{attr.missing}}"}},
                "result": {"path": "/data", "columns": ["name"]},
            }
            missing_attr = deliver_results(missing_attr_cfg, missing_entry, lambda: calls.append(True) or True)
            self.assertEqual(missing_attr["outcome"], "failed")
            self.assertIn("missing", missing_attr.get("error_detail", ""))
            self.assertEqual(calls, [])
            self.assertEqual(seen, [])

    def test_parse_result_usage_rejects_disallowed_totp_and_attr_placements(self):
        base = {
            "type": "https_results",
            "origin": "https://example.invalid/",
            "request": {"path": "/items", "auth": "template", "headers": {"X-OTP": "{{totp}}"}},
            "result": {"path": "/data", "columns": ["name"]},
        }
        self.assertIsNotNone(parse_result_usage(base))
        invalid_cases = [
            {**base, "request": {"path": "/items", "auth": "template", "headers": {"X-Bad": "{{attr.otp}}"}}},
            {**base, "request": {"path": "/items", "auth": "template", "headers": {"X-Bad": "{{unknown}}"}}},
            {**base, "request": {"path": "/items", "auth": "basic", "headers": {"X-OTP": "{{totp}}"}}},
            {**base, "request": {"path": "/items", "auth": "bearer", "headers": {"X-Key": "{{attr.k}}"}}},
            {**base, "request": {"path": "/items", "auth": "template", "headers": {"X-OTP": "{{totp}}"}, "query": {"q": "{{totp}}"}}},
            {**base, "request": {"path": "/items", "method": "POST", "auth": "template", "headers": {"X-OTP": "{{totp}}"}, "json": {"a": "{{attr.k}}"}}},
            {**base, "login": {"path": "/login", "form": {"user": "{{username}}"}, "capture": {"t": "/t"}}},
            {**base, "request": {"path": "/items", "auth": "template", "headers": {"X-User": "{{username}}"}}},
        ]
        for bad in invalid_cases:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_result_usage(bad)
