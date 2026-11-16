"""Disposable local HTTPS service with synthetic authorization data."""

from base64 import b64encode
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
from threading import Thread
from time import sleep


USERNAME = "synthetic-account"
PASSWORD = "synthetic-action-password-sentinel"
AUTHORIZATION = "Basic " + b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode("ascii")


@contextmanager
def tls_service(root, *, authorization=AUTHORIZATION, extra_authorization=()):
    root = Path(root)
    cert, key = root / "certificate.pem", root / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        "-out", str(cert), "-keyout", str(key),
    ], check=True, capture_output=True)
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle(self):
            try:
                super().handle()
            except (OSError, ssl.SSLError):
                # An authorized TLS setup can be revoked before sending the request.
                pass

        def do_GET(self):
            header = self.headers.get("Authorization", "")
            calls.append((self.path, header))
            self.respond(header)

        def do_POST(self):
            header = self.headers.get("Authorization", "")
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path, header, self.headers.get("Content-Type"), body))
            if self.path != "/disconnect":
                self.respond(header)

        def respond(self, header):
            if self.path == "/slow":
                sleep(5)
            accepted = header in (authorization, *extra_authorization)
            status = 302 if self.path == "/redirect" else 200 if accepted else 401
            try:
                self.send_response(status)
                if self.path == "/redirect":
                    self.send_header("Location", f"https://127.0.0.1:{self.server.server_port}/other")
                self.send_header("X-Echo", header)
                self.end_headers()
                self.wfile.write(header.encode())
            except (OSError, ssl.SSLError):
                pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield cert, f"https://127.0.0.1:{server.server_port}", calls
        finally:
            server.shutdown()
            thread.join()
