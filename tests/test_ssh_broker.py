"""Tests for typed origins, SSH grants, SshAccess broker, MCP/CLI, keeper-connect, and UI metadata."""

from base64 import b64decode, b64encode
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from types import ModuleType, SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access_settings import Action, ActionType, Destination
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.agent_cli import _validate, endpoint_target
from keepassxc_agent_access.agent_runner import invocation
from keepassxc_agent_access.grants import (
    CREDENTIAL_USES, Grants, Item, MAX_ITEMS, MAX_ORIGINS, Scope,
)
from keepassxc_agent_access.protocol import ListingError, decode, encode
from keepassxc_agent_access.scoped_broker import ScopedBroker, access_details
from keepassxc_agent_access.ssh_access import format_ssh_fingerprint, parse_ssh_fingerprint
from keepassxc_agent_access.usage import usage_action, usage_origin
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace
from tests.ssh_fixture import SshTestServer
import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from keepassxc_agent_access.workspace_views import (
    ACTIVITY_ACTION_ICONS, credential_use_labels, usage_approval_caption,
)
from keepassxc_agent_access.approvals import Approval, ApprovalQueue


HOST_KEY_A = "a" * 64
HOST_KEY_B = "b" * 64
HOST_KEY_A_B64 = format_ssh_fingerprint(HOST_KEY_A)
SECRET_SENTINEL = "ssh-super-secret-password-sentinel"
KEY_SENTINEL = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-sentinel\n-----END OPENSSH PRIVATE KEY-----"
SUDO_SENTINEL = "sudo-secret-sentinel"


class FakeSshTransport(ModuleType):
    def __init__(self):
        super().__init__("keepassxc_agent_access.ssh_transport")
        self.probed_hex = HOST_KEY_A
        self.calls = []
        self.exec_reply = {"outcome": "succeeded", "exit_code": 0, "stdout": "ok\n", "stderr": ""}
        self.upload_reply = None
        self.download_reply = {"outcome": "succeeded", "content": "hello", "bytes_read": 5, "truncated": False, "exit_code": 0}

    def probe_host_key(self, host, port=22, *, timeout=5):
        canonical_host = f"[{host}]:{port}" if port != 22 else host
        return f"{canonical_host} ssh-ed25519 AAAA", self.probed_hex, format_ssh_fingerprint(self.probed_hex)

    @staticmethod
    def parse_ssh_fingerprint(value):
        if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value):
            return value
        if isinstance(value, str) and value.startswith("SHA256:"):
            encoded = value[7:]
            padded = encoded + "=" * (-len(encoded) % 4)
            digest = b64decode(padded, validate=True)
            if len(digest) == 32:
                return digest.hex()
        raise ValueError("Invalid SSH host key fingerprint.")

    def run_ssh_command(self, host, port, username, known_hosts_line, command, *,
                        password="", private_key=None, sudo_password=None, timeout=30, guard=None, **_kwargs):
        self.calls.append(("run_ssh_command", host, port, username, known_hosts_line, command, sudo_password is not None, timeout))
        if guard and not guard():
            raise ListingError("revoked")
        return dict(self.exec_reply)

    def ssh_upload_bytes(self, host, port, username, known_hosts_line, remote_path, data, *,
                         mode="0600", password="", private_key=None, timeout=60, guard=None, **_kwargs):
        self.calls.append(("ssh_upload_bytes", host, port, username, known_hosts_line, remote_path, data, mode, timeout))
        if guard and not guard():
            raise ListingError("revoked")
        if self.upload_reply is not None:
            return dict(self.upload_reply)
        return {"outcome": "succeeded", "bytes_written": len(data), "exit_code": 0}

    def ssh_download_bytes(self, host, port, username, known_hosts_line, remote_path, *,
                           max_bytes=262144, encoding="text", password="", private_key=None, timeout=60, guard=None, **_kwargs):
        self.calls.append(("ssh_download_bytes", host, port, username, known_hosts_line, remote_path, encoding, max_bytes, timeout))
        if guard and not guard():
            raise ListingError("revoked")
        return dict(self.download_reply)


class TypedDestinationAndGrantsTests(TestCase):
    def test_destination_supports_https_ssh_and_tcp_schemes(self):
        legacy = Destination("api.example.test", 443, "/")
        self.assertEqual(legacy.scheme, "https")
        self.assertEqual(legacy.url, "https://api.example.test:443/")

        self.assertEqual(Destination.parse("ssh://bastion.example.test", allowed_schemes=("ssh",)).url,
                         "ssh://bastion.example.test:22")
        self.assertEqual(Destination.parse("ssh://bastion.example.test/", allowed_schemes=("ssh",)).url,
                         "ssh://bastion.example.test:22")
        self.assertEqual(Destination.parse("ssh://[::1]:2222", allowed_schemes=("ssh",)).url, "ssh://[::1]:2222")
        self.assertEqual(Destination.parse("tcp://db.example.test:5432", allowed_schemes=("tcp",)).url,
                         "tcp://db.example.test:5432")

        with self.assertRaisesRegex(ValueError, "HTTPS endpoint"):
            Destination.parse("ssh://bastion.example.test:22")
        with self.assertRaisesRegex(ValueError, "explicit port"):
            Destination.parse("tcp://db.example.test", allowed_schemes=("tcp",))
        for bad in ("ssh://user@bastion.example.test:22", "ssh://bastion.example.test/shell",
                    "tcp://db.example.test:5432/dbname", "ssh://bastion.example.test:22?x=1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Destination.parse(bad, allowed_schemes=("https", "ssh", "tcp"))

        self.assertEqual(usage_origin("tcp://db.example.test:5432"), "tcp://db.example.test:5432")
        action = usage_action(str(uuid4()), {
            "type": "networked_command",
            "command": ["/usr/bin/psql", "-h", "db.example.test"],
            "origin": "tcp://db.example.test:5432",
            "prompt_variable": "PG_ASKPASS",
        }, pin_executable=False)
        self.assertEqual(action.kind, ActionType.NETWORK_PROMPT)
        self.assertEqual(action.url, "tcp://db.example.test:5432")
        self.assertEqual(ScopedBroker._usage_destination(action), "TCP peer db.example.test:5432")

    def test_ssh_credential_uses_and_origin_scheme_validation(self):
        vault, entry = str(uuid4()), str(uuid4())
        self.assertEqual(MAX_ITEMS, 32)
        self.assertEqual(MAX_ORIGINS, 16)

        item = Item.parse({
            "vault": vault, "entry": entry,
            "uses": ["ssh_exec", "ssh_sftp", "ssh_sudo"],
            "origins": ["ssh://bastion.example.test"],
        })
        self.assertEqual(item.uses, ("ssh_exec", "ssh_sftp", "ssh_sudo"))
        self.assertEqual(item.origins, ("ssh://bastion.example.test:22",))

        mixed = Item.parse({
            "vault": vault, "entry": entry,
            "uses": ["https", "ssh_exec"],
            "origins": ["https://api.example.test", "ssh://bastion.example.test:2222"],
        })
        self.assertEqual(mixed.origins, ("https://api.example.test:443/", "ssh://bastion.example.test:2222"))

        for bad in (
            {"vault": vault, "entry": entry, "uses": ["ssh_sudo"], "origins": ["ssh://bastion.example.test"]},
            {"vault": vault, "entry": entry, "uses": ["ssh_exec"], "origins": ["https://api.example.test/"]},
            {"vault": vault, "entry": entry, "uses": ["https"], "origins": ["ssh://bastion.example.test"]},
            {"vault": vault, "entry": entry, "uses": ["ssh_exec"], "origins": ["tcp://bastion.example.test:22"]},
            {"vault": vault, "entry": entry, "uses": ["https", "ssh_exec"], "origins": ["https://api.example.test/"]},
            {"vault": vault, "entry": entry, "uses": ["https", "ssh_exec"], "origins": ["ssh://bastion.example.test"]},
            {"vault": vault, "entry": entry, "uses": ["https", "ssh_exec"],
             "origins": ["https://api.example.test/", "ssh://bastion.example.test", "tcp://db.example.test:5432"]},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Item.parse(bad)

        # Scope ssh_host_keys validation
        rev = "1" * 64
        scope = Scope(vault, entry, False, None, None, uses=["ssh_exec"],
                      origins=["ssh://bastion.example.test:22"], use_revision=rev,
                      ssh_host_keys=[("ssh://bastion.example.test:22", HOST_KEY_A)])
        self.assertEqual(scope.ssh_host_keys, (("ssh://bastion.example.test:22", HOST_KEY_A),))
        with self.assertRaises(ValueError):
            Scope(vault, entry, False, None, None, uses=["https"],
                  origins=["https://api.example.test:443/"], use_revision=rev,
                  ssh_host_keys=[("https://api.example.test:443/", HOST_KEY_A)])

    def test_ssh_host_keys_preserved_across_permission_change(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            workspace = Workspace(directory, None)
            activity = ActivityStore(workspace.directory / "activity.sqlite")
            activity.recover(30)
            grants = Grants(workspace, activity)
            vault, entry, second = str(uuid4()), str(uuid4()), str(uuid4())
            cred = "c1" * 32
            workspace.registrations[vault] = Registration(vault, "Infra", VaultTarget(Path("infra.kdbx")), None, None)
            workspace.sessions[vault] = Unlocked(
                SimpleNamespace(available=True), (),
                ({"id": entry, "title": "SSH Host", "group_path": ["Servers"]},
                 {"id": second, "title": "Second", "group_path": ["Servers"]}),
            )
            self.assertEqual(grants.enroll(cred, 1500, {
                "identity": "Deployer", "project": "Ops",
                "items": [{"vault": vault, "entry": entry, "uses": ["ssh_exec"], "origins": ["ssh://box.example.test"]}],
            }, Attribution()), "pending")
            record = grants.authenticate(cred, 1500)
            grants.decide(record.id, [grants.choices(item)[0] for item in record.items])
            active = grants.authenticate(cred, 1500)
            rev = workspace.registrations[vault].credential_revision(entry)
            grants.trust_ssh_host_key(
                active.id, active.generation, vault, entry, rev,
                "ssh://box.example.test:22", HOST_KEY_A, (None,),
            )
            change_id = str(uuid4())
            grants.enroll(cred, 1500, {
                "change_id": change_id,
                "items": [
                    {"vault": vault, "entry": entry, "uses": ["ssh_exec", "ssh_sftp"],
                     "origins": ["ssh://box.example.test:22"]},
                    {"vault": vault, "entry": second, "metadata": True},
                ],
            }, Attribution())
            pending = grants.authenticate(cred, 1500).pending_change
            grants.decide(active.id, [grants.choices(item)[0] for item in pending.items], change_id=change_id)
            updated = grants.authenticate(cred, 1500)
            self.assertEqual(updated.scope[0].ssh_host_keys, (("ssh://box.example.test:22", HOST_KEY_A),))


class SshBrokerTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory(dir="/tmp")
        self.addCleanup(temp.cleanup)
        self.workspace = Workspace(temp.name, None)
        self.workspace.paused = False
        self.activity = ActivityStore(self.workspace.directory / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.broker = ScopedBroker(self.workspace, self.grants, self.activity, approvals=ApprovalQueue(timeout=2))
        self.vault = str(uuid4())
        self.entry = str(uuid4())
        self.sudo_entry = str(uuid4())
        self.credential = "d1" * 32
        self.transport = FakeSshTransport()
        self.worker = SimpleNamespace(
            available=True,
            ssh_credentials=lambda entry_id, sudo_id, attachment: {
                "username": "ops",
                "password": SECRET_SENTINEL,
                "private_key": KEY_SENTINEL if attachment else None,
                "sudo_password": SUDO_SENTINEL if sudo_id else SECRET_SENTINEL,
            },
        )
        self.workspace.registrations[self.vault] = Registration(
            self.vault, "Infra", VaultTarget(Path("infra.kdbx")), None, None,
        )
        self.workspace.sessions[self.vault] = Unlocked(
            self.worker, (),
            ({"id": self.entry, "title": "Bastion SSH", "group_path": ["Servers"]},
             {"id": self.sudo_entry, "title": "Bastion Sudo", "group_path": ["Servers"]}),
        )

    def _enroll_and_approve(self, items):
        self.assertEqual(self.grants.enroll(self.credential, 1500, {
            "identity": "SSH Agent", "project": "Automation", "items": items,
        }, Attribution()), "pending")
        record = self.grants.authenticate(self.credential, 1500)
        self.grants.decide(record.id, [self.grants.choices(item)[0] for item in record.items])
        return self.grants.authenticate(self.credential, 1500)

    def _call(self, operation, *, approve=True, upload=None, **params):
        delivered = []
        payload = {"version": 1, "operation": operation, "credential": self.credential, **params}

        def deliver(frame, guard):
            if guard(lambda: True):
                delivered.append(decode(frame))
                return True
            return False

        def dispatch(effect):
            return effect()

        def live(effect=lambda: True):
            return effect()

        def resolve_approvals():
            for _ in range(100):
                pending = self.broker.approvals.pending()
                if pending:
                    self.broker.approvals.resolve(pending[0].id, approve)
                    return
                import time
                time.sleep(0.01)

        with patch("keepassxc_agent_access.ssh_access._ssh_transport", return_value=self.transport):
            if approve is not None:
                t = Thread(target=resolve_approvals, daemon=True)
                t.start()
            self.broker(payload, 1500, None, live, dispatch, deliver, upload=upload)
            if approve is not None:
                t.join(2)
        return delivered[0] if delivered else None

    def test_ssh_exec_tofu_pinning_change_detection_and_audit_privacy(self):
        self._enroll_and_approve([{
            "vault": self.vault, "entry": self.entry,
            "uses": ["ssh_exec"], "origins": ["ssh://bastion.example.test"],
        }])
        # First use requires owner review and trusts the host key.
        reply = self._call(
            "ssh_exec", approve=True,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test",
            command="uname -a",
            host_key_sha256=HOST_KEY_A_B64,
        )
        self.assertEqual(reply, {"outcome": "succeeded", "exit_code": 0, "stdout": "ok\n", "stderr": ""})
        token = self.grants.authenticate(self.credential, 1500)
        self.assertEqual(token.scope[0].ssh_host_keys, (("ssh://bastion.example.test:22", HOST_KEY_A),))
        details = access_details(token, workspace=self.workspace)
        self.assertEqual(details["scope"][0]["pinned_ssh_hosts"], ["ssh://bastion.example.test:22"])

        # Subsequent call with trusted key and use_ssh auto-approved runs without prompt.
        reply2 = self._call(
            "ssh_exec", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="id",
        )
        self.assertEqual(reply2["outcome"], "succeeded")

        # Mismatched expected fingerprint fails before dispatch.
        with self.assertRaises(ListingError) as err:
            self._call(
                "ssh_exec", approve=None,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                command="id",
                host_key_sha256=HOST_KEY_B,
            )
        self.assertEqual(err.exception.code, "host_key_mismatch")

        # Changed server host key forces review even when use_ssh is auto-approved!
        self.transport.probed_hex = HOST_KEY_B
        with self.assertRaises(ListingError) as declined:
            self._call(
                "ssh_exec", approve=False,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                command="id",
            )
        self.assertEqual(declined.exception.code, "declined")
        self.assertEqual(self.grants.authenticate(self.credential, 1500).scope[0].ssh_host_keys,
                         (("ssh://bastion.example.test:22", HOST_KEY_A),))

        # Approving the changed key repins it.
        self._call(
            "ssh_exec", approve=True,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="id",
        )
        self.assertEqual(self.grants.authenticate(self.credential, 1500).scope[0].ssh_host_keys,
                         (("ssh://bastion.example.test:22", HOST_KEY_B),))

        # Verify no secrets appear in Activity or tokens file.
        dumped = json.dumps(self.activity.rows()) + self.grants.path.read_text()
        for secret in (SECRET_SENTINEL, KEY_SENTINEL, SUDO_SENTINEL):
            self.assertNotIn(secret, dumped)

    def test_ssh_first_pin_key_repin_and_reuse_window(self):
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("ssh_first_pin", True)
        self.workspace.set_scoped_auto_approval("ssh_reuse", True)
        self._enroll_and_approve([{
            "vault": self.vault, "entry": self.entry,
            "uses": ["ssh_exec"], "origins": ["ssh://bastion.example.test"],
        }])
        # Auto first pin + auto reuse window when use_ssh is not reviewed.
        reply = self._call(
            "ssh_exec", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="hostname", reuse_minutes=5,
        )
        self.assertGreater(reply["reuse_expires_in"], 0)
        self.assertEqual(self.grants.authenticate(self.credential, 1500).scope[0].ssh_host_keys,
                         (("ssh://bastion.example.test:22", HOST_KEY_A),))

        # Turn ON use_ssh review: existing reuse permit still bypasses review while key matches!
        self.workspace.set_review_action("use_ssh", True)
        # Re-seed permit since set_review_action(..., True) bumped workspace.generation as expected!
        reply_approved = self._call(
            "ssh_exec", approve=True,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="date", reuse_minutes=10,
        )
        self.assertGreater(reply_approved["reuse_expires_in"], 0)
        reply_reused = self._call(
            "ssh_exec", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="uptime",
        )
        self.assertEqual(reply_reused["outcome"], "succeeded")

        # If host key changes, reuse permit MUST NOT bypass review unless ssh_key_repin is enabled.
        self.transport.probed_hex = HOST_KEY_B
        with self.assertRaises(ListingError) as declined:
            self._call(
                "ssh_exec", approve=False,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                command="uptime",
            )
        self.assertEqual(declined.exception.code, "declined")

        self.workspace.set_review_action("use_ssh", False)
        self.workspace.set_scoped_auto_approval("ssh_key_repin", True)
        self._call(
            "ssh_exec", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="uptime",
        )
        self.assertEqual(self.grants.authenticate(self.credential, 1500).scope[0].ssh_host_keys,
                         (("ssh://bastion.example.test:22", HOST_KEY_B),))

    def test_ssh_sudo_and_separate_sudo_entry_enforcement(self):
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("ssh_first_pin", True)
        self._enroll_and_approve([
            {"vault": self.vault, "entry": self.entry,
             "uses": ["ssh_exec"], "origins": ["ssh://bastion.example.test"]},
            {"vault": self.vault, "entry": self.sudo_entry,
             "uses": ["ssh_exec", "ssh_sudo"], "origins": ["ssh://bastion.example.test"]},
        ])
        with self.assertRaises(ListingError) as err:
            self._call(
                "ssh_exec", approve=None,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                command="systemctl status nginx", sudo=True,
            )
        self.assertEqual(err.exception.code, "ineligible")

        reply = self._call(
            "ssh_exec", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            command="systemctl status nginx", sudo=True, sudo_entry=self.sudo_entry,
        )
        self.assertEqual(reply["outcome"], "succeeded")
        self.assertEqual(self.transport.calls[-1][6], True)

        # Releasing sudo_entry immediately revokes sudo_entry usage.
        token = self.grants.authenticate(self.credential, 1500)
        self.grants.release_entry(token, self.vault, self.sudo_entry, Attribution())
        with self.assertRaises(ListingError) as err2:
            self._call(
                "ssh_exec", approve=None,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                command="systemctl status nginx", sudo=True, sudo_entry=self.sudo_entry,
            )
        self.assertEqual(err2.exception.code, "ineligible")

    def test_ssh_upload_binary_pipe_and_content_base64_and_download(self):
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("ssh_first_pin", True)
        self._enroll_and_approve([{
            "vault": self.vault, "entry": self.entry,
            "uses": ["ssh_sftp"], "origins": ["ssh://bastion.example.test"],
        }])
        # Inline content_base64
        up1 = self._call(
            "ssh_upload", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            remote_path="/tmp/conf.json", mode="0640",
            content_base64=b64encode(b'{"ok":true}').decode("ascii"),
        )
        self.assertEqual(up1, {"outcome": "succeeded", "remote_path": "/tmp/conf.json", "bytes_written": 11})
        self.assertEqual(self.transport.calls[-1][6], b'{"ok":true}')
        self.assertEqual(self.transport.calls[-1][7], "0640")

        # Binary broker upload frame (8 MiB capable pipe)
        blob = b"binary-blob-\x00-\xff"
        with TemporaryDirectory(dir="/tmp") as upload_dir:
            blob_path = Path(upload_dir) / "data"
            blob_path.write_bytes(blob)

            @contextmanager
            def fake_upload(info, guard):
                self.assertEqual(info["size"], len(blob))
                yield blob_path

            up2 = self._call(
                "ssh_upload", approve=None, upload=fake_upload,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                remote_path="/tmp/blob.bin",
                upload_info={"size": len(blob), "sha256": sha256(blob).hexdigest()},
            ) if False else None
            # Pass exact payload key "upload"
            delivered = []
            payload = {
                "version": 1, "operation": "ssh_upload", "credential": self.credential,
                "vault": self.vault, "entry": self.entry,
                "origin": "ssh://bastion.example.test:22",
                "remote_path": "/tmp/blob.bin",
                "upload": {"size": len(blob), "sha256": sha256(blob).hexdigest()},
            }
            with patch("keepassxc_agent_access.ssh_access._ssh_transport", return_value=self.transport):
                self.broker(payload, 1500, None, lambda effect=lambda: True: effect(),
                            lambda effect: effect(),
                            lambda frame, guard: delivered.append(decode(frame)) or True,
                            upload=fake_upload)
            self.assertEqual(delivered[0], {"outcome": "succeeded", "remote_path": "/tmp/blob.bin", "bytes_written": len(blob)})
            self.assertEqual(self.transport.calls[-1][6], blob)

        # Download
        down = self._call(
            "ssh_download", approve=None,
            vault=self.vault, entry=self.entry,
            origin="ssh://bastion.example.test:22",
            remote_path="/etc/motd", encoding="text", max_bytes=4096,
        )
        self.assertEqual(down["content"], "hello")
        # Base64 max_bytes > 524288 rejected
        with self.assertRaises(ListingError) as bad_size:
            self._call(
                "ssh_download", approve=None,
                vault=self.vault, entry=self.entry,
                origin="ssh://bastion.example.test:22",
                remote_path="/etc/motd", encoding="base64", max_bytes=524289,
            )
        self.assertEqual(bad_size.exception.code, "invalid_request")

    def test_mcp_cli_keeper_connect_and_ui_metadata_for_ssh(self):
        vault, entry, sudo_entry = str(uuid4()), str(uuid4()), str(uuid4())
        # MCP invocations
        args, data = invocation("ssh_exec", {
            "vault": vault, "entry": entry, "origin": "ssh://host.test",
            "command": "whoami", "sudo": True, "sudo_entry": sudo_entry,
            "host_key_sha256": HOST_KEY_A_B64, "timeout": 90, "reuse_minutes": 15,
        })
        self.assertEqual(args[1:3], ["ssh", "exec"])
        self.assertIn("--sudo", args)
        self.assertIn(f"--sudo-entry={sudo_entry}", args)
        self.assertIn("--timeout=90", args)
        self.assertIn("--reuse-for=15", args)
        self.assertEqual(decode(data), {"command": "whoami"})

        args, data = invocation("ssh_upload", {
            "vault": vault, "entry": entry, "origin": "ssh://host.test:2222",
            "remote_path": "/tmp/a.txt", "mode": "0755",
            "input_base64": b64encode(b"payload").decode("ascii"),
        })
        self.assertEqual(args[1:3], ["ssh", "upload"])
        self.assertIn("--input", args)
        self.assertEqual(data, b"payload")

        with self.assertRaisesRegex(ValueError, "keeper-connect"):
            invocation("ssh_upload", {
                "vault": vault, "entry": entry, "origin": "ssh://host.test",
                "remote_path": "/tmp/a.txt", "input_path": "/tmp/local",
            })

        args, data = invocation("ssh_download", {
            "vault": vault, "entry": entry, "origin": "ssh://host.test",
            "remote_path": "/etc/hosts", "encoding": "base64", "max_bytes": 1024,
        })
        self.assertEqual(args[1:3], ["ssh", "download"])
        self.assertIn("--encoding=base64", args)
        self.assertIn("--max-bytes=1024", args)

        # CLI _validate for SSH operations
        self.assertEqual(
            _validate({"outcome": "succeeded", "exit_code": 0, "stdout": "hi", "stderr": ""},
                      {"operation": "ssh_exec"}),
            {"outcome": "succeeded", "exit_code": 0, "stdout": "hi", "stderr": ""},
        )
        with self.assertRaises(ListingError):
            _validate({"outcome": "succeeded", "exit_code": 0, "stdout": "hi", "stderr": "", "password": "leak"},
                      {"operation": "ssh_exec"})
        self.assertEqual(
            _validate({"outcome": "succeeded", "remote_path": "/tmp/a", "bytes_written": 7, "reuse_expires_in": 300},
                      {"operation": "ssh_upload", "reuse_minutes": 5}),
            {"outcome": "succeeded", "remote_path": "/tmp/a", "bytes_written": 7, "reuse_expires_in": 300},
        )
        self.assertEqual(
            _validate({"outcome": "succeeded", "remote_path": "/etc/hosts", "encoding": "text", "size": 5, "content": "abc"},
                      {"operation": "ssh_download"}),
            {"outcome": "succeeded", "remote_path": "/etc/hosts", "encoding": "text", "size": 5, "content": "abc"},
        )
        self.assertEqual(endpoint_target("ssh://host.test", allowed_schemes=("ssh",), origin=True), "ssh://host.test:22")
        self.assertEqual(endpoint_target("tcp://db.test:5432", allowed_schemes=("tcp",), origin=True), "tcp://db.test:5432")

        # keeper-connect ssh_upload input_path rewriting & schema injection
        connect_path = Path(__file__).resolve().parents[1] / "keeper-connect"
        loader = SourceFileLoader("keeper_connect", str(connect_path))
        spec = spec_from_loader("keeper_connect", loader)
        mod = module_from_spec(spec)
        loader.exec_module(mod)

        tools_reply = encode({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "ssh_upload", "inputSchema": {"type": "object", "properties": {"entry": {"type": "string"}}}}]},
        })
        injected = decode(mod.process_incoming_line(tools_reply))
        self.assertIn("input_path", injected["result"]["tools"][0]["inputSchema"]["properties"])

        with TemporaryDirectory(dir="/tmp") as d:
            local_file = Path(d) / "upload.bin"
            local_file.write_bytes(b"ssh-upload-bytes")
            req = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "ssh_upload",
                "arguments": {"vault": vault, "entry": entry, "origin": "ssh://host.test",
                              "remote_path": "/tmp/up", "input_path": str(local_file)},
            }}
            fwd, local = mod.process_outgoing_line(encode(req))
            self.assertIsNone(local)
            args_out = decode(fwd)["params"]["arguments"]
            self.assertNotIn("input_path", args_out)
            self.assertEqual(b64decode(args_out["input_base64"]), b"ssh-upload-bytes")

        # UI metadata
        for action_name in ("Run SSH Command", "Upload SSH File", "Download SSH File"):
            self.assertIn(action_name, ACTIVITY_ACTION_ICONS)
        item = Item.parse({"vault": vault, "entry": entry,
                           "uses": ["ssh_exec", "ssh_sftp", "ssh_sudo"],
                           "origins": ["ssh://host.test"]})
        labels = dict(credential_use_labels(item))
        self.assertEqual(set(labels), {CREDENTIAL_USES["ssh_exec"], CREDENTIAL_USES["ssh_sftp"], CREDENTIAL_USES["ssh_sudo"]})
        ticket = Approval(1, 1000, Attribution(), "Run SSH Command", (), "ssh://host.test:22", 100,
                          trusts_certificate=True, ssh_operation=True)
        self.assertIn("SSH host key", usage_approval_caption(ticket))

    def test_real_ssh_fixture_broker_end_to_end(self):
        with SshTestServer(username="ops", password=SECRET_SENTINEL, sudo_password=SECRET_SENTINEL) as server:
            origin = f"ssh://{server.host}:{server.port}"
            self._enroll_and_approve([
                {"vault": self.vault, "entry": self.entry,
                 "uses": ["ssh_exec", "ssh_sftp", "ssh_sudo"], "origins": [origin]},
            ])

            def call_real(operation, *, approve=False, **params):
                delivered = []
                payload = {"version": 1, "operation": operation, "credential": self.credential,
                           "vault": self.vault, "entry": self.entry, "origin": origin, **params}

                def resolve():
                    for _ in range(100):
                        pending = self.broker.approvals.pending()
                        if pending:
                            self.broker.approvals.resolve(pending[0].id, True)
                            return
                        import time
                        time.sleep(0.01)

                if approve:
                    t = Thread(target=resolve, daemon=True)
                    t.start()
                self.broker(payload, 1500, None, lambda effect=lambda: True: effect(),
                            lambda effect: effect(),
                            lambda frame, guard: delivered.append(decode(frame)) or True)
                if approve:
                    t.join(2)
                return delivered[0]

            exec_res = call_real("ssh_exec", approve=True, command="echo e2e-ok")
            self.assertEqual(exec_res["outcome"], "succeeded")
            self.assertEqual(exec_res["stdout"], "e2e-ok\n")

            token = self.grants.authenticate(self.credential, 1500)
            self.assertEqual(token.scope[0].ssh_host_keys, ((origin, server.fingerprint_hex),))

            sudo_res = call_real("ssh_exec", approve=False, command="echo sudo-ok", sudo=True)
            self.assertEqual(sudo_res["outcome"], "succeeded")
            self.assertEqual(sudo_res["stdout"], "sudo-ok\n")

            up_res = call_real("ssh_upload", approve=False, remote_path="/tmp/real-up.txt",
                               mode="0640", content_base64=b64encode(b"real-file-data").decode("ascii"))
            self.assertEqual(up_res, {"outcome": "succeeded", "remote_path": "/tmp/real-up.txt", "bytes_written": 14})

            down_res = call_real("ssh_download", approve=False, remote_path="/tmp/real-up.txt")
            self.assertEqual(down_res["outcome"], "succeeded")
            self.assertEqual(down_res["content"], "real-file-data")
            self.assertEqual(down_res["size"], 14)

            dumped = json.dumps(self.activity.rows()) + self.grants.path.read_text()
            self.assertNotIn(SECRET_SENTINEL, dumped)
            self.assertNotIn(SUDO_SENTINEL, dumped)

    def test_ssh_scoped_options_decoupled_from_https_and_ssh_reuse_switch_governs_permits(self):
        # SSH host-key pinning & reuse must not require use_https or read_results auto-approval.
        self.workspace.set_review_action("use_https", True)
        self.workspace.set_review_action("read_results", True)
        self.assertTrue(self.workspace.requires_review("use_https"))
        self.assertTrue(self.workspace.requires_review("read_results"))
        self.workspace.set_scoped_auto_approval("ssh_first_pin", True)
        self.workspace.set_scoped_auto_approval("ssh_key_repin", True)
        self._enroll_and_approve([{
            "vault": self.vault, "entry": self.entry,
            "uses": ["ssh_exec"], "origins": ["ssh://bastion.example.test"],
        }])

        # First pin and changed pin both auto-approve with only SSH enabled.
        self._call("ssh_exec", approve=None, vault=self.vault, entry=self.entry,
                   origin="ssh://bastion.example.test:22", command="hostname")
        self.transport.probed_hex = HOST_KEY_B
        self._call("ssh_exec", approve=None, vault=self.vault, entry=self.entry,
                   origin="ssh://bastion.example.test:22", command="hostname")

        # Require manual SSH command review: when ssh_reuse is OFF, reuse_minutes=5 is not offered or stored.
        self.workspace.set_review_action("use_ssh", True)
        with patch.object(self.broker.approvals, "wait",
                          side_effect=lambda ticket, _live: (self.assertEqual(ticket.reuse_minutes, 0), "approved")[1]):
            res_no_reuse = self._call("ssh_exec", approve=None, vault=self.vault, entry=self.entry,
                                      origin="ssh://bastion.example.test:22", command="date", reuse_minutes=5)
        self.assertEqual(res_no_reuse["reuse_expires_in"], 0)
        with self.assertRaises(ListingError) as declined:
            self._call("ssh_exec", approve=False, vault=self.vault, entry=self.entry,
                       origin="ssh://bastion.example.test:22", command="uptime")
        self.assertEqual(declined.exception.code, "declined")

        # Turn ssh_reuse ON while use_https + read_results + use_ssh still require review.
        self.workspace.set_scoped_auto_approval("ssh_reuse", True)
        with patch.object(self.broker.approvals, "wait",
                          side_effect=lambda ticket, _live: (self.assertEqual(ticket.reuse_minutes, 5), "approved")[1]):
            res_reuse = self._call("ssh_exec", approve=None, vault=self.vault, entry=self.entry,
                                   origin="ssh://bastion.example.test:22", command="date", reuse_minutes=5)
        self.assertGreater(res_reuse["reuse_expires_in"], 0)
        self.assertEqual(
            self._call("ssh_exec", approve=None, vault=self.vault, entry=self.entry,
                       origin="ssh://bastion.example.test:22", command="uptime")["outcome"],
            "succeeded",
        )
