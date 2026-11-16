"""An authenticated Git smart-HTTP server bound to loopback for synthetic tests."""

import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
from threading import Thread
from urllib.parse import urlsplit


USERNAME = "fixture-user"
TOKEN = "synthetic-git-network-credential"
AUTHORIZATION = b"Basic " + base64.b64encode(f"{USERNAME}:{TOKEN}".encode("ascii"))
BACKEND = Path("/usr/lib/git-core/git-http-backend")


def git(path, *arguments):
    return subprocess.run(["/usr/bin/git", "-C", str(path), *arguments], check=True,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout.strip()


def create_bundle(root):
    source = root / "source"
    source.mkdir()
    git(source, "init", "-b", "main")
    (source / "example.txt").write_text("Synthetic Git content\n")
    git(source, "add", "example.txt")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Fixture commit")
    path = root / "fixture.bundle"
    git(source, "bundle", "create", str(path), "refs/heads/main")
    return path, git(source, "rev-parse", "HEAD")


def push_command(url):
    # This is fixture configuration of one trusted argv. Keeper has no Git handler.
    script = (
        '/usr/bin/git clone --bare /input /tmp/repository && '
        '/usr/bin/git -C /tmp/repository -c credential.helper= -c credential.username=' + USERNAME
        + ' -c core.hooksPath=/dev/null -c http.followRedirects=false -c push.recurseSubmodules=no'
        ' -c http.sslCAInfo=/keeper/trust.pem push "$1" refs/heads/main:refs/heads/main'
    )
    return ("/usr/bin/sh", "-c", script, "keeper-fixture", url)


@contextmanager
def git_https_service(root):
    certificate = root / "certificate.pem"
    key = root / "key.pem"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                    "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-out", str(certificate), "-keyout", str(key)], check=True, capture_output=True)
    repository = root / "fixture.git"
    git(root, "init", "--bare", "-b", "main", str(repository))
    calls = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def receive(self):
            signed = self.headers.get("Authorization", "").encode("ascii") == AUTHORIZATION
            route = urlsplit(self.path)
            if route.path not in ("/fixture.git/info/refs", "/fixture.git/git-receive-pack"):
                self.send_error(404)
                return
            calls.append((self.command, route.path, signed))
            if not signed:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 2 * 1024**2:
                self.send_error(413)
                return
            environment = {
                "PATH": "/usr/bin:/bin", "GIT_PROJECT_ROOT": str(root), "GIT_HTTP_EXPORT_ALL": "1",
                "PATH_INFO": route.path, "QUERY_STRING": route.query, "REQUEST_METHOD": self.command,
                "CONTENT_TYPE": self.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(length),
                "REMOTE_USER": USERNAME, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
            }
            result = subprocess.run([str(BACKEND)], input=self.rfile.read(length), env=environment,
                                    cwd=root, capture_output=True, timeout=6, check=True)
            headers, body = result.stdout.split(b"\r\n\r\n", 1)
            status = 200
            outgoing = []
            for line in headers.split(b"\r\n"):
                name, value = line.decode("ascii").split(":", 1)
                if name.lower() == "status":
                    status = int(value.split()[0])
                else:
                    outgoing.append((name, value.strip()))
            self.send_response(status)
            for name, value in outgoing:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = receive
        do_POST = receive

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield certificate, f"https://127.0.0.1:{server.server_port}", repository, calls
        finally:
            server.shutdown()
            thread.join()
