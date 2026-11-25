import base64
import hashlib
from pathlib import Path
import subprocess
import tempfile
from threading import Event, Timer
import time
import unittest
from uuid import uuid4

from pykeepass import create_database

from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.ssh_transport import (
    SshTransportError,
    format_ssh_fingerprint,
    parse_ssh_fingerprint,
    probe_host_key,
    run_ssh_command,
    scrub_output,
    ssh_download_bytes,
    ssh_upload_bytes,
)
from keepassxc_agent_access.vault import VaultTarget, open_vault
from tests.ssh_fixture import SshTestServer


def _generate_ed25519_keypair(tmpdir: Path, name: str, passphrase: str = "") -> tuple[str, str]:
    key_path = tmpdir / name
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(key_path)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    priv = key_path.read_text(encoding="utf-8")
    pub = (tmpdir / f"{name}.pub").read_text(encoding="utf-8").strip()
    return priv, pub


class SshTransportUnitTests(unittest.TestCase):
    def test_fingerprint_parse_and_format_roundtrip(self):
        digest = hashlib.sha256(b"synthetic-ssh-host-key").digest()
        hex_fp = digest.hex()
        b64_unpadded = base64.b64encode(digest).decode("ascii").rstrip("=")
        b64_padded = base64.b64encode(digest).decode("ascii")

        self.assertEqual(parse_ssh_fingerprint(hex_fp), hex_fp)
        self.assertEqual(parse_ssh_fingerprint(f"SHA256:{b64_unpadded}"), hex_fp)
        self.assertEqual(parse_ssh_fingerprint(f"SHA256:{b64_padded}"), hex_fp)
        self.assertEqual(format_ssh_fingerprint(hex_fp), f"SHA256:{b64_unpadded}")

        for bad in (
            "",
            "abc",
            hex_fp.upper(),
            hex_fp[:-1] + "g",
            "SHA256:",
            "SHA256:not!valid",
            "SHA256:" + base64.b64encode(b"short").decode("ascii").rstrip("="),
            "MD5:00:11:22",
            None,
        ):
            with self.assertRaises(ValueError):
                parse_ssh_fingerprint(bad)  # type: ignore[arg-type]

        for bad_hex in ("", "zz" * 32, "00" * 31, None):
            with self.assertRaises(ValueError):
                format_ssh_fingerprint(bad_hex)  # type: ignore[arg-type]

    def test_scrub_output_strips_ansi_keys_secrets_and_control_chars(self):
        secret = "Super$ecretPass!99"
        b64_secret = base64.b64encode(secret.encode()).decode("ascii")
        hex_secret = secret.encode().hex()
        url_secret = "Super%24ecretPass%2199"
        raw = (
            "\x1b[31mError\x1b[0m \x1b]0;title\x07line1\n"
            f"raw={secret} b64={b64_secret} hex={hex_secret} url={url_secret}\t123\x00\x01\r\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "public-ok\n"
        )
        cleaned = scrub_output(raw, forbidden=(secret, "1"))
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x01", cleaned)
        self.assertNotIn(secret, cleaned)
        self.assertNotIn(b64_secret, cleaned)
        self.assertNotIn(hex_secret, cleaned)
        self.assertNotIn(url_secret, cleaned)
        self.assertNotIn("OPENSSH PRIVATE KEY", cleaned)
        self.assertIn("Error line1\n", cleaned)
        self.assertIn("\t123\r\n", cleaned)
        self.assertIn("public-ok\n", cleaned)
        self.assertIn("[REDACTED]", cleaned)

        # Truncated PEM block without END marker is also redacted
        truncated = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"
        self.assertEqual(scrub_output(truncated), "before\n[REDACTED]")


class SshTransportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = Path(self._tmpdir.name)

    def test_probe_host_key_with_real_ssh_keyscan(self):
        with SshTestServer() as server:
            kh_line, fp_hex, fp_b64 = probe_host_key(server.host, server.port, timeout=5)
            self.assertEqual(kh_line, server.known_hosts_line)
            self.assertEqual(fp_hex, server.fingerprint_hex)
            self.assertEqual(fp_b64, server.fingerprint_sha256)
            self.assertEqual(parse_ssh_fingerprint(fp_b64), fp_hex)

        # Closed port fails cleanly
        with self.assertRaises(SshTransportError) as ctx:
            probe_host_key("127.0.0.1", server.port, timeout=1)
        self.assertEqual(ctx.exception.code, "ssh_failed")

    def test_password_auth_and_nonzero_exit(self):
        with SshTestServer(username="alice", password="pw-alpha-1234") as server:
            res = run_ssh_command(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "echo hello world",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(res["outcome"], "succeeded")
            self.assertEqual(res["exit_code"], 0)
            self.assertEqual(res["stdout"], "hello world\n")
            self.assertNotIn("Permission denied", res["stderr"])
            self.assertFalse(res["timed_out"])
            self.assertIn(("alice", "password", True), server.auth_attempts)

            fail_res = run_ssh_command(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "fail",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(fail_res["outcome"], "failed")
            self.assertEqual(fail_res["exit_code"], 42)
            self.assertIn("command failed\n", fail_res["stderr"])
            self.assertIn("command failed", fail_res["error_detail"])

            bad_pw = run_ssh_command(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "echo nope",
                password="wrong-password",
                timeout=10,
            )
            self.assertEqual(bad_pw["outcome"], "failed")
            self.assertEqual(bad_pw["exit_code"], 255)
            self.assertIn(("alice", "password", False), server.auth_attempts)

    def test_ed25519_key_auth_unencrypted_and_passphrase_encrypted(self):
        unenc_priv, unenc_pub = _generate_ed25519_keypair(self.tmpdir, "id_unenc")
        enc_priv, enc_pub = _generate_ed25519_keypair(self.tmpdir, "id_enc", passphrase="key-passphrase-99")

        with SshTestServer(username="deploy", password=None) as server:
            server.add_authorized_pubkey_line(unenc_pub)
            server.add_authorized_pubkey_line(enc_pub)

            res1 = run_ssh_command(
                server.host,
                server.port,
                "deploy",
                server.known_hosts_line,
                "echo unencrypted-ok",
                password="",
                private_key=unenc_priv,
                timeout=10,
            )
            self.assertEqual(res1["outcome"], "succeeded")
            self.assertEqual(res1["stdout"], "unencrypted-ok\n")

            res2 = run_ssh_command(
                server.host,
                server.port,
                "deploy",
                server.known_hosts_line,
                "echo encrypted-ok",
                password="key-passphrase-99",
                private_key=enc_priv,
                timeout=10,
            )
            self.assertEqual(res2["outcome"], "succeeded")
            self.assertEqual(res2["stdout"], "encrypted-ok\n")

            # Encrypted key with empty passphrase fails fast without hanging
            res3 = run_ssh_command(
                server.host,
                server.port,
                "deploy",
                server.known_hosts_line,
                "echo should-fail",
                password="",
                private_key=enc_priv,
                timeout=10,
            )
            self.assertEqual(res3["outcome"], "failed")
            self.assertEqual(res3["exit_code"], 255)

    def test_sudo_mode_and_secret_scrubbing(self):
        with SshTestServer(username="ops", password="ssh-login-secret", sudo_password="sudo-root-secret") as server:
            res = run_ssh_command(
                server.host,
                server.port,
                "ops",
                server.known_hosts_line,
                "echo privileged-ok",
                password="ssh-login-secret",
                sudo_password="sudo-root-secret",
                timeout=10,
            )
            self.assertEqual(res["outcome"], "succeeded")
            self.assertEqual(res["stdout"], "privileged-ok\n")
            self.assertNotIn("Sorry, try again.", res["stderr"])
            self.assertNotIn("sudo-root-secret", res["stderr"])
            sudo_cmd = server.executed_commands[-1]
            self.assertIn("/usr/bin/sudo -S -p ", sudo_cmd)
            nonce_prompt = sudo_cmd.split("/usr/bin/sudo -S -p ", 1)[1].split(" -- ", 1)[0]
            self.assertNotIn(nonce_prompt, res["stderr"])

            # Wrong sudo password fails cleanly
            bad_sudo = run_ssh_command(
                server.host,
                server.port,
                "ops",
                server.known_hosts_line,
                "echo privileged-nope",
                password="ssh-login-secret",
                sudo_password="wrong-sudo-password",
                timeout=10,
            )
            self.assertEqual(bad_sudo["outcome"], "failed")
            self.assertEqual(bad_sudo["exit_code"], 1)
            self.assertIn("Sorry, try again.", bad_sudo["stderr"])

            # Output containing secrets (raw, b64, hex) is scrubbed
            b64_pw = base64.b64encode(b"ssh-login-secret").decode("ascii")
            leak = run_ssh_command(
                server.host,
                server.port,
                "ops",
                server.known_hosts_line,
                f"echo leak:ssh-login-secret:{b64_pw}:sudo-root-secret",
                password="ssh-login-secret",
                sudo_password="sudo-root-secret",
                timeout=10,
            )
            self.assertEqual(leak["outcome"], "succeeded")
            self.assertNotIn("ssh-login-secret", leak["stdout"])
            self.assertNotIn(b64_pw, leak["stdout"])
            self.assertNotIn("sudo-root-secret", leak["stdout"])
            self.assertIn("[REDACTED]", leak["stdout"])

    def test_mitm_wrong_host_key_rejected_before_auth(self):
        with SshTestServer(username="alice", password="pw-alpha-1234") as real_server:
            with SshTestServer(username="alice", password="pw-alpha-1234") as mitm_server:
                res = run_ssh_command(
                    mitm_server.host,
                    mitm_server.port,
                    "alice",
                    real_server.known_hosts_line,
                    "echo should-never-run",
                    password="pw-alpha-1234",
                    timeout=10,
                )
                self.assertEqual(res["outcome"], "failed")
                self.assertEqual(res["exit_code"], 255)
                self.assertIn("Host key verification failed", res["stderr"])
                self.assertEqual(mitm_server.auth_attempts, [])
                self.assertEqual(mitm_server.executed_commands, [])

    def test_upload_and_download_bytes(self):
        payload = b"\x00\x01hello-binary-\xff\nline2"
        with SshTestServer(username="alice", password="pw-alpha-1234") as server:
            up = ssh_upload_bytes(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "/tmp/data.bin",
                payload,
                mode="0640",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(up["outcome"], "succeeded")
            self.assertEqual(up["bytes_written"], len(payload))
            self.assertEqual(up["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(server.files["/tmp/data.bin"], (payload, "0640"))

            dl_b64 = ssh_download_bytes(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "/tmp/data.bin",
                encoding="base64",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(dl_b64["outcome"], "succeeded")
            self.assertEqual(base64.b64decode(dl_b64["content"]), payload)
            self.assertEqual(dl_b64["bytes_read"], len(payload))
            self.assertFalse(dl_b64["truncated"])

            # Text mode truncation and scrubbing
            server.files["/tmp/secret.txt"] = (b"prefix pw-alpha-1234 suffix", "0600")
            dl_text = ssh_download_bytes(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "/tmp/secret.txt",
                max_bytes=20,
                encoding="text",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(dl_text["outcome"], "succeeded")
            self.assertTrue(dl_text["truncated"])
            self.assertNotIn("pw-alpha-1234", dl_text["content"])

            # Base64 mode refuses to leak protected credential
            with self.assertRaises(SshTransportError) as ctx:
                ssh_download_bytes(
                    server.host,
                    server.port,
                    "alice",
                    server.known_hosts_line,
                    "/tmp/secret.txt",
                    encoding="base64",
                    password="pw-alpha-1234",
                    timeout=10,
                )
            self.assertEqual(ctx.exception.code, "ssh_failed")

            missing = ssh_download_bytes(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "/tmp/missing.txt",
                password="pw-alpha-1234",
                timeout=10,
            )
            self.assertEqual(missing["outcome"], "failed")
            self.assertEqual(missing["exit_code"], 1)

    def test_timeout_and_live_guard_cancellation(self):
        with SshTestServer(username="alice", password="pw-alpha-1234") as server:
            timed_out = run_ssh_command(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "sleep 5",
                password="pw-alpha-1234",
                timeout=1,
            )
            self.assertEqual(timed_out["outcome"], "failed")
            self.assertTrue(timed_out["timed_out"])
            self.assertIsNone(timed_out["exit_code"])
            self.assertIn("timed out", timed_out["error_detail"])

            # Pre-revoked guard fails immediately
            with self.assertRaises(ListingError) as ctx:
                run_ssh_command(
                    server.host,
                    server.port,
                    "alice",
                    server.known_hosts_line,
                    "echo nope",
                    password="pw-alpha-1234",
                    guard=lambda: False,
                )
            self.assertEqual(ctx.exception.code, "revoked")

            # Guard flipping False mid-execution kills SSH cleanly
            active = Event()
            active.set()
            timer = Timer(0.3, active.clear)
            timer.start()
            started = time.monotonic()
            try:
                with self.assertRaises(ListingError) as ctx2:
                    run_ssh_command(
                        server.host,
                        server.port,
                        "alice",
                        server.known_hosts_line,
                        "sleep 5",
                        password="pw-alpha-1234",
                        timeout=10,
                        guard=active.is_set,
                    )
                self.assertEqual(ctx2.exception.code, "revoked")
                self.assertLess(time.monotonic() - started, 2.0)
            finally:
                timer.cancel()

    def test_vault_ssh_credentials_extraction_and_end_to_end_ssh(self):
        enc_priv, enc_pub = _generate_ed25519_keypair(self.tmpdir, "vault_ed25519", passphrase="vault-key-pass")
        alt_priv, _ = _generate_ed25519_keypair(self.tmpdir, "alt_ed25519")
        db_path = self.tmpdir / "ssh-vault.kdbx"
        master_pw = "vault-master-password"

        kp = create_database(db_path, master_pw)
        # 1) Attachment-based entry with binary non-key attachment first, then key attachments
        att_entry = kp.add_entry(kp.root_group, "SSH Attachment", "vault-user", "vault-key-pass")
        bin_png = kp.add_binary(b"\x89PNG\r\n\x1a\n\xff\xfe\xfd")
        bin_key = kp.add_binary(enc_priv.encode("utf-8"))
        bin_alt = kp.add_binary(alt_priv.encode("utf-8"))
        att_entry.add_attachment(bin_png, "avatar.png")
        att_entry.add_attachment(bin_key, "id_ed25519")
        att_entry.add_attachment(bin_alt, "backup_ed25519")

        # 2) Custom property entry
        prop_entry = kp.add_entry(kp.root_group, "SSH Custom Prop", "prop-user", "")
        prop_entry.set_custom_property("ssh_private_key", alt_priv)

        # 3) Private key stored directly in password + ssh_passphrase custom property
        pwkey_entry = kp.add_entry(kp.root_group, "SSH Pw Key", "pw-user", enc_priv)
        pwkey_entry.set_custom_property("ssh_passphrase", "vault-key-pass")

        # 4) Sudo entry and trashed entry
        sudo_entry = kp.add_entry(kp.root_group, "Sudo Entry", "root", "vault-sudo-secret")
        trashed_entry = kp.add_entry(kp.root_group, "Trashed", "gone", "secret")
        kp.trash_entry(trashed_entry)
        kp.save()

        with open_vault(VaultTarget(db_path), master_pw, Event()) as session:
            creds = session.ssh_credentials(str(att_entry.uuid), sudo_entry_id=str(sudo_entry.uuid))
            # Vault lock is released immediately
            self.assertFalse(session._requests.locked())
            self.assertEqual(creds["username"], "vault-user")
            self.assertEqual(creds["password"], "vault-key-pass")
            self.assertEqual(creds["private_key"], enc_priv)
            self.assertEqual(creds["sudo_password"], "vault-sudo-secret")

            # Named attachment selection
            creds_alt = session.ssh_credentials(str(att_entry.uuid), attachment_name="backup_ed25519")
            self.assertEqual(creds_alt["private_key"], alt_priv)

            # Binary or missing named attachment fails as ineligible
            for bad_att in ("avatar.png", "nonexistent.pem"):
                with self.assertRaises(ListingError) as ctx:
                    session.ssh_credentials(str(att_entry.uuid), attachment_name=bad_att)
                self.assertEqual(ctx.exception.code, "ineligible")

            # Custom property key
            creds_prop = session.ssh_credentials(str(prop_entry.uuid))
            self.assertEqual(creds_prop["private_key"], alt_priv)
            self.assertEqual(creds_prop["password"], "")

            # Password-as-key + ssh_passphrase
            creds_pwkey = session.ssh_credentials(str(pwkey_entry.uuid))
            self.assertEqual(creds_pwkey["private_key"], enc_priv)
            self.assertEqual(creds_pwkey["password"], "vault-key-pass")

            # Trashed or invalid entry / sudo_entry rejected
            for bad_id in (str(trashed_entry.uuid), str(uuid4()), "not-a-uuid"):
                with self.assertRaises(ListingError) as ctx:
                    session.ssh_credentials(bad_id)
                self.assertEqual(ctx.exception.code, "ineligible")
            with self.assertRaises(ListingError):
                session.ssh_credentials(str(att_entry.uuid), sudo_entry_id=str(trashed_entry.uuid))

            # End-to-end SSH + sudo using extracted vault credentials
            with SshTestServer(
                username="vault-user",
                password=None,
                sudo_password="vault-sudo-secret",
            ) as server:
                server.add_authorized_pubkey_line(enc_pub)
                res = run_ssh_command(
                    server.host,
                    server.port,
                    creds["username"],
                    server.known_hosts_line,
                    "echo vault-e2e-ok",
                    password=creds["password"],
                    private_key=creds["private_key"],
                    sudo_password=creds["sudo_password"],
                    timeout=10,
                )
                self.assertEqual(res["outcome"], "succeeded")
                self.assertEqual(res["stdout"], "vault-e2e-ok\n")

    def test_validation_truncation_and_multichunk_upload(self):
        with self.assertRaises(ValueError):
            run_ssh_command("127.0.0.1", 22, "bad\nuser", "127.0.0.1 ssh-ed25519 AAAA", "echo hi", password="pw")
        with self.assertRaises(ValueError):
            run_ssh_command("127.0.0.1", 22, "", "127.0.0.1 ssh-ed25519 AAAA", "echo hi", password="pw")
        with self.assertRaises(ValueError):
            run_ssh_command("127.0.0.1", 22, "alice", "127.0.0.1 ssh-ed25519 AAAA", "echo hi", password="pw", timeout=121)
        with self.assertRaises(ValueError):
            run_ssh_command("-oProxyCommand=id", 22, "alice", "127.0.0.1 ssh-ed25519 AAAA", "echo hi", password="pw")
        with self.assertRaises(SshTransportError):
            run_ssh_command("127.0.0.1", 22, "alice", "127.0.0.1 ssh-ed25519 AAAA", "echo hi", password="", private_key=None)
        with self.assertRaises(ValueError):
            ssh_upload_bytes("127.0.0.1", 22, "alice", "127.0.0.1 ssh-ed25519 AAAA", "/tmp/x", b"hi", mode="999", password="pw")
        with self.assertRaises(ValueError):
            ssh_download_bytes("127.0.0.1", 22, "alice", "127.0.0.1 ssh-ed25519 AAAA", "/tmp/x", encoding="hex", password="pw")

        large_payload = b"X" * (128 * 1024 + 17)
        with SshTestServer(username="alice", password="pw-alpha-1234") as server:
            up = ssh_upload_bytes(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                "/tmp/large.bin",
                large_payload,
                password="pw-alpha-1234",
                timeout=15,
            )
            self.assertEqual(up["outcome"], "succeeded")
            self.assertEqual(up["bytes_written"], len(large_payload))
            self.assertEqual(server.files["/tmp/large.bin"][0], large_payload)

            trunc = run_ssh_command(
                server.host,
                server.port,
                "alice",
                server.known_hosts_line,
                f"echo {'A' * 200}",
                password="pw-alpha-1234",
                max_stdout=32,
                timeout=10,
            )
            self.assertEqual(trunc["outcome"], "succeeded")
            self.assertTrue(trunc["truncated"])
            self.assertEqual(len(trunc["stdout"]), 32)


if __name__ == "__main__":
    unittest.main()
