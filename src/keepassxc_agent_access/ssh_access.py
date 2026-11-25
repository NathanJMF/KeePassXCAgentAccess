"""Authorize and broker SSH command execution and SFTP transfers."""

from base64 import b64decode, b64encode
from dataclasses import dataclass
from math import ceil
import re
from time import monotonic, time

from .access_settings import Destination, label, uuid_text
from .activity import entry_target_labels
from .approvals import Approval
from .protocol import (
    ERRORS, ListingError, MAX_SSH_REUSE_MINUTES, MAX_SSH_TIMEOUT,
    RESPONSE_LIMIT, UPLOAD_LIMIT, encode, sanitize_error_detail,
)


MAX_SSH_PERMITS = 64
DEFAULT_SSH_TIMEOUT = 30
DEFAULT_DOWNLOAD_BYTES = 262144
MAX_TEXT_DOWNLOAD_BYTES = 1048576
MAX_BASE64_DOWNLOAD_BYTES = 524288


def _ssh_transport():
    from . import ssh_transport
    return ssh_transport


def format_ssh_fingerprint(sha256_hex):
    return "SHA256:" + b64encode(bytes.fromhex(sha256_hex)).decode("ascii").rstrip("=")


def parse_ssh_fingerprint(value):
    if not isinstance(value, str):
        raise ValueError("Invalid SSH host key fingerprint.")
    try:
        return _ssh_transport().parse_ssh_fingerprint(value)
    except ImportError:
        pass
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    if value.startswith("SHA256:"):
        encoded = value[7:]
        if encoded and re.fullmatch(r"[A-Za-z0-9+/=]+", encoded):
            padded = encoded + "=" * (-len(encoded) % 4)
            digest = b64decode(padded, validate=True)
            if len(digest) == 32:
                return digest.hex()
    raise ValueError("Invalid SSH host key fingerprint.")


def _validate_remote_path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 1024
            or "\0" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("Invalid remote path.")
    return value


def _validate_attachment(value):
    cleaned = label(value, limit=160)
    if cleaned in (".", "..") or "/" in cleaned or "\\" in cleaned:
        raise ValueError("Invalid attachment filename.")
    return cleaned


@dataclass(frozen=True)
class SshPermit:
    token_id: str
    token_generation: int
    generation: int
    vault: str
    entry: str
    revision: str
    sudo_revision: str | None
    sudo_entry: str | None
    session: object
    host_key_sha256: str
    expires: float


class SshAccess:
    def __init__(self, broker):
        self.broker = broker
        self.workspace = broker.workspace
        self.activity = broker.activity
        self.permits = {}
        self.pin_reviews = set()

    def _permit_current(self, permit):
        token = self.broker.grants.records.get(permit.token_id)
        registration = self.workspace.registrations.get(permit.vault)
        return (
            not self.workspace.paused
            and monotonic() < permit.expires
            and self.workspace.generation == permit.generation
            and self.broker.grants.is_active(token)
            and token.generation == permit.token_generation
            and self.workspace.session(permit.vault) is permit.session
            and registration is not None
            and registration.credential_revision(permit.entry) == permit.revision
            and (permit.sudo_entry is None or (
                (permit.vault, permit.sudo_entry) not in token.released_entries
                and registration.credential_revision(permit.sudo_entry) == permit.sudo_revision
            ))
        )

    def handle(self, operation, keys, payload, uid, context, live, dispatch, deliver, *,
               upload=None, input_info=None):
        credential = payload.get("credential")
        vault = uuid_text(payload["vault"])
        entry = uuid_text(payload["entry"])
        target = Destination.parse(payload["origin"], allowed_schemes=("ssh",))
        origin = target.url
        attachment = _validate_attachment(payload["attachment"]) if "attachment" in keys else None
        requested_fp = parse_ssh_fingerprint(payload["host_key_sha256"]) if "host_key_sha256" in keys else None
        timeout = payload.get("timeout", DEFAULT_SSH_TIMEOUT)
        if type(timeout) is not int or not 1 <= timeout <= MAX_SSH_TIMEOUT:
            raise ValueError
        requested_minutes = payload.get("reuse_minutes", 0)
        if type(requested_minutes) is not int or not 0 <= requested_minutes <= MAX_SSH_REUSE_MINUTES:
            raise ValueError

        common_optional = {"attachment", "host_key_sha256", "timeout", "reuse_minutes"}
        sudo = False
        sudo_entry = None
        command = None
        remote_path = None
        mode = "0600"
        content_bytes = None
        encoding = "text"
        max_bytes = DEFAULT_DOWNLOAD_BYTES

        if operation == "ssh_exec":
            required = {"vault", "entry", "origin", "command"}
            if not required <= keys <= required | common_optional | {"sudo", "sudo_entry"}:
                raise ValueError
            command = payload["command"]
            if not isinstance(command, str) or not 1 <= len(command) <= 8192 or "\0" in command:
                raise ValueError
            sudo = payload.get("sudo", False)
            if type(sudo) is not bool:
                raise ValueError
            if "sudo_entry" in keys:
                if not sudo:
                    raise ValueError
                candidate = uuid_text(payload["sudo_entry"])
                if candidate != entry:
                    sudo_entry = candidate
        elif operation == "ssh_upload":
            required = {"vault", "entry", "origin", "remote_path"}
            if not required <= keys <= required | common_optional | {"mode", "upload", "content_base64"}:
                raise ValueError
            if ("upload" in keys) == ("content_base64" in keys):
                raise ValueError
            if ("upload" in keys) != (upload is not None and input_info is not None):
                raise ValueError
            remote_path = _validate_remote_path(payload["remote_path"])
            mode = payload.get("mode", "0600")
            if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{3,4}", mode):
                raise ValueError
            if "content_base64" in keys:
                raw_b64 = payload["content_base64"]
                if not isinstance(raw_b64, str):
                    raise ValueError
                content_bytes = b64decode(raw_b64, validate=True)
                if len(content_bytes) > UPLOAD_LIMIT:
                    raise ValueError
        else:
            required = {"vault", "entry", "origin", "remote_path"}
            if not required <= keys <= required | common_optional | {"encoding", "max_bytes"}:
                raise ValueError
            remote_path = _validate_remote_path(payload["remote_path"])
            encoding = payload.get("encoding", "text")
            if encoding not in ("text", "base64"):
                raise ValueError
            max_limit = MAX_BASE64_DOWNLOAD_BYTES if encoding == "base64" else MAX_TEXT_DOWNLOAD_BYTES
            max_bytes = payload.get("max_bytes", DEFAULT_DOWNLOAD_BYTES)
            if type(max_bytes) is not int or not 1 <= max_bytes <= max_limit:
                raise ValueError

        action_title = {
            "ssh_exec": "Run SSH Command",
            "ssh_upload": "Upload SSH File",
            "ssh_download": "Download SSH File",
        }[operation]
        review_action = "use_ssh" if operation == "ssh_exec" else "use_ssh_sftp"
        op_kind = "ssh_exec" if operation == "ssh_exec" else "ssh_sftp"

        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            token = self.broker.grants.authenticate(credential, uid)
            self.broker._charge_request(token.verifier, uid, active=self.broker.grants.is_active(token))
            if not self.broker.grants.is_active(token):
                raise ListingError("ineligible", detail=f"Token status is {token.status}; an active token is required.")
            if self.workspace.paused:
                raise ListingError("paused")

            registration = self.workspace.registrations.get(vault)
            session = self.workspace.session(vault) if registration else None
            if session is None:
                raise ListingError("ineligible", detail="The target vault is locked or not in this token's scope.")

            credential_revision = registration.credential_revision(entry)
            sudo_revision = registration.credential_revision(sudo_entry) if sudo_entry else None
            if sudo_entry and (
                (vault, sudo_entry) in token.released_entries
                or not any(row["id"] == sudo_entry for row in session.entries)
            ):
                raise ListingError("ineligible", detail="The target sudo entry is unavailable or released.")

            if operation == "ssh_exec":
                needed_primary = {"ssh_exec"} if (not sudo or sudo_entry is not None) else {"ssh_exec", "ssh_sudo"}
            else:
                needed_primary = {"ssh_sftp"}

            def primary_matches(active_token, rev):
                return any(
                    (s.vault, s.entry, s.use_revision) == (vault, entry, rev)
                    and needed_primary <= set(s.uses) and origin in s.origins
                    for s in active_token.scope
                )

            def sudo_matches(active_token, rev):
                if sudo_entry is None:
                    return True
                return any(
                    (s.vault, s.entry, s.use_revision) == (vault, sudo_entry, rev)
                    and "ssh_sudo" in s.uses and origin in s.origins
                    for s in active_token.scope
                )

            permitted = primary_matches(token, credential_revision)
            if not permitted:
                refreshed = self.broker.grants.refresh_rotated_credential(token.id, vault, entry, credential_revision)
                if refreshed is not None:
                    token = refreshed
                    permitted = primary_matches(token, credential_revision)
            sudo_permitted = sudo_matches(token, sudo_revision)
            if not sudo_permitted and sudo_entry is not None:
                refreshed = self.broker.grants.refresh_rotated_credential(token.id, vault, sudo_entry, sudo_revision)
                if refreshed is not None:
                    token = refreshed
                    sudo_permitted = sudo_matches(token, sudo_revision)

            primary_stale = not permitted and any(
                (s.vault, s.entry) == (vault, entry) and s.use_revision != credential_revision
                and needed_primary <= set(s.uses) and origin in s.origins
                for s in token.scope
            )
            sudo_stale = sudo_entry is not None and not sudo_permitted and any(
                (s.vault, s.entry) == (vault, sudo_entry) and s.use_revision != sudo_revision
                and "ssh_sudo" in s.uses and origin in s.origins
                for s in token.scope
            )
            if primary_stale or sudo_stale:
                raise ListingError("credential_changed")
            if not permitted or not sudo_permitted or not any(row["id"] == entry for row in session.entries):
                raise ListingError(
                    "ineligible",
                    detail="This token does not permit the requested SSH operation, entry, or origin.",
                )

            generation = self.workspace.generation
            token_generation = token.generation
            folder, title = entry_target_labels(session.entries, entry)
            if operation == "ssh_exec":
                scope_summary = f"Command ({len(command)} chars)" + (" · sudo" if sudo else "")
                if sudo_entry:
                    scope_summary += f" · sudo entry {sudo_entry}"
            elif operation == "ssh_upload":
                size_bytes = input_info["size"] if input_info is not None else len(content_bytes)
                scope_summary = f"Upload {remote_path} (mode {mode}) · {size_bytes} bytes"
            else:
                scope_summary = f"Download {remote_path} ({encoding}, max {max_bytes} bytes)"
            if attachment:
                scope_summary += f" · Key {attachment}"
            event = self.activity.begin(
                uid, context, action_title, origin, entry,
                vault=registration.name, vault_id=vault, token=token.id,
                agent=token.identity, project=token.project, folder=folder, entry_title=title,
                scope=scope_summary,
            )

        committed_pin = None

        def guard(effect):
            with self.workspace.mutex:
                current = self.broker.grants.records.get(token.id)
                if (self.workspace.paused or self.workspace.generation != generation
                        or current is None or current.generation != token_generation
                        or not self.broker.grants.is_active(current)):
                    return False
                if self.workspace.session(vault) is not session:
                    return False
                reg = self.workspace.registrations.get(vault)
                if reg is None or reg.credential_revision(entry) != credential_revision:
                    return False
                if sudo_entry and (reg.credential_revision(sudo_entry) != sudo_revision
                                   or (vault, sudo_entry) in current.released_entries):
                    return False
                if committed_pin is not None:
                    pins = self.broker.grants.ssh_host_key_pins(
                        current, vault, entry, credential_revision, origin)
                    if not pins or any(pin != committed_pin for pin in pins):
                        return False
                return effect()

        dispatch_started = False
        pin_reservation = None
        try:
            transport = _ssh_transport()
            try:
                probed = transport.probe_host_key(target.host, target.port)
                if isinstance(probed, tuple):
                    known_hosts_line, probed_hex, _ = probed
                    probed_hex = parse_ssh_fingerprint(probed_hex)
                elif isinstance(probed, str):
                    probed_hex = parse_ssh_fingerprint(probed)
                    known_hosts_line = ""
                elif isinstance(probed, dict):
                    probed_hex = parse_ssh_fingerprint(probed["sha256_hex"])
                    known_hosts_line = probed.get("known_hosts_line", "")
                else:
                    probed_hex = parse_ssh_fingerprint(probed.sha256_hex)
                    known_hosts_line = getattr(probed, "known_hosts_line", "")
            except ListingError:
                raise
            except Exception as error:
                code = getattr(error, "code", None)
                if code in ERRORS:
                    raise ListingError(code, detail=getattr(error, "detail", None) or str(error)) from None
                if isinstance(error, (OSError, TimeoutError, ValueError, AttributeError, KeyError)):
                    raise ListingError("ssh_failed", detail=str(error)) from None
                raise

            probed_fp = format_ssh_fingerprint(probed_hex)
            if requested_fp is not None and probed_hex != requested_fp:
                raise ListingError(
                    "host_key_mismatch",
                    detail=f"Expected {format_ssh_fingerprint(requested_fp)}, got {probed_fp}.",
                )
            if not guard(live):
                raise ListingError("revoked")

            permit_key = (token.id, vault, entry, origin, op_kind, bool(sudo))
            with self.workspace.mutex:
                self.permits = {k: p for k, p in self.permits.items() if self._permit_current(p)}
                current = self.broker.grants.records[token.id]
                expected_pins, pin_trusted, first_pin, changed_pin = self.broker.grants.ssh_host_key_status(
                    current, vault, entry, credential_revision, origin, probed_hex)
                _, _, auto_pin = self.broker.grants.ssh_host_key_auto_pin(
                    current, vault, entry, credential_revision, origin, probed_hex)
                needs_pin = not pin_trusted
                if pin_trusted:
                    committed_pin = probed_hex
                permit = self.permits.get(permit_key)
                permit_valid = (
                    permit is not None
                    and permit.sudo_entry == sudo_entry
                    and permit.host_key_sha256 == probed_hex
                    and pin_trusted
                )
                review_policy = self.workspace.requires_review(review_action)
                reused = permit_valid
                review_needed = False if reused else (review_policy or (needs_pin and not auto_pin))
                if needs_pin:
                    key = (token.id, token_generation, vault, entry, credential_revision, origin, probed_hex)
                    if key in self.pin_reviews:
                        raise ListingError("busy")
                    self.pin_reviews.add(key)
                    pin_reservation = key

            if review_needed:
                details = [
                    " › ".join(part for part in (registration.name, folder, title) if part),
                    f"Target: {origin}",
                ]
                if operation == "ssh_exec":
                    details.append(f"Command: {command}")
                    if sudo:
                        details.append("Elevated privileges: sudo" + (f" (entry {sudo_entry})" if sudo_entry else ""))
                elif operation == "ssh_upload":
                    size_bytes = input_info["size"] if input_info is not None else len(content_bytes)
                    details.append(f"Upload to: {remote_path} (mode {mode}, {size_bytes} bytes)")
                else:
                    details.append(f"Download from: {remote_path} ({encoding}, max {max_bytes} bytes)")
                if attachment:
                    details.append(f"SSH key attachment: {attachment}")
                details.append(f"Host key fingerprint: {probed_fp}")
                if changed_pin:
                    previous = ", ".join(format_ssh_fingerprint(pin) for pin in expected_pins if pin)
                    details.append(f"HOST KEY CHANGED (previously trusted: {previous}). Verify before trusting.")
                elif needs_pin:
                    details.append("First-use host key verification. Approving trusts this host key for this token, entry, and destination.")
                else:
                    details.append("Host key status: Trusted")
                if requested_minutes:
                    details.append(f"Reuse window: Allow {op_kind} to {origin} for {requested_minutes} minutes.")
                ticket = Approval(
                    event, uid, context, action_title, tuple(details), origin,
                    monotonic() + self.broker.approvals.timeout,
                    identity=token.identity, project=token.project, requested=time(),
                    trusts_certificate=needs_pin, reuse_minutes=requested_minutes, ssh_operation=True,
                )
                answer = self.broker.approvals.wait(ticket, lambda: guard(live))
                if answer != "approved":
                    raise ListingError(answer)

            if reused:
                decision = "Used approved SSH reuse window"
            elif review_needed:
                if requested_minutes:
                    decision = f"Owner approved SSH for {requested_minutes} min"
                elif needs_pin:
                    decision = "Owner approved SSH once and trusted host key"
                else:
                    decision = "Owner approved SSH once"
            elif needs_pin and auto_pin:
                decision = "Auto approved first SSH host key" if first_pin else "Auto approved changed SSH host key"
            else:
                decision = "Auto approved SSH operation"
            self.activity.authorize(event, decision)
            if not guard(live):
                raise ListingError("revoked")

            if operation == "ssh_upload" and input_info is not None:
                with upload(input_info, guard) as input_path:
                    content_bytes = input_path.read_bytes()

            worker = getattr(session, "worker", session)
            creds = worker.ssh_credentials(entry, sudo_entry, attachment)
            if not guard(live):
                raise ListingError("revoked")

            def ssh_guard():
                def on_dispatch():
                    nonlocal dispatch_started
                    if not dispatch_started:
                        self.activity.dispatched(event)
                        dispatch_started = True
                    return True
                return guard(lambda: dispatch(on_dispatch))

            transport = _ssh_transport()
            username = creds.get("username", "")
            password = creds.get("password") or ""
            private_key = creds.get("private_key")
            sudo_password = (
                (creds.get("sudo_password") if creds.get("sudo_password") is not None else password)
                if sudo else None
            )
            with self.broker._command_slot():
                try:
                    if operation == "ssh_exec":
                        raw = transport.run_ssh_command(
                            target.host, target.port, username, known_hosts_line, command,
                            password=password, private_key=private_key, sudo_password=sudo_password,
                            timeout=timeout, guard=ssh_guard,
                        )
                    elif operation == "ssh_upload":
                        raw = transport.ssh_upload_bytes(
                            target.host, target.port, username, known_hosts_line, remote_path, content_bytes,
                            mode=mode, password=password, private_key=private_key,
                            timeout=timeout, guard=ssh_guard,
                        )
                    else:
                        raw = transport.ssh_download_bytes(
                            target.host, target.port, username, known_hosts_line, remote_path,
                            max_bytes=max_bytes, encoding=encoding,
                            password=password, private_key=private_key,
                            timeout=timeout, guard=ssh_guard,
                        )
                except ListingError:
                    raise
                except Exception as error:
                    code = getattr(error, "code", None)
                    if code in ERRORS:
                        raise ListingError(code, detail=getattr(error, "detail", None) or str(error)) from None
                    if isinstance(error, (OSError, TimeoutError, ValueError)):
                        raise ListingError("ssh_failed", detail=str(error)) from None
                    raise

            if not dispatch_started and guard(live):
                self.activity.dispatched(event)
                dispatch_started = True

            verified_connect = raw.get("outcome") == "succeeded" or raw.get("exit_code") is not None
            if needs_pin and verified_connect:
                def pin_key():
                    nonlocal committed_pin
                    self.broker.grants.trust_ssh_host_key(
                        token.id, token_generation, vault, entry, credential_revision,
                        origin, probed_hex, expected_pins,
                    )
                    committed_pin = probed_hex
                    return True

                if not guard(pin_key):
                    raise ListingError("revoked")

            if raw.get("exit_code") is None and raw.get("outcome") != "succeeded":
                raise ListingError("ssh_failed", detail=raw.get("error_detail") or "The SSH operation did not complete.")

            if operation == "ssh_exec":
                result = {
                    "outcome": raw["outcome"],
                    "exit_code": raw["exit_code"],
                    "stdout": raw.get("stdout", ""),
                    "stderr": raw.get("stderr", ""),
                }
                if "truncated" in raw:
                    result["truncated"] = bool(raw["truncated"])
            elif operation == "ssh_upload":
                result = {
                    "outcome": raw.get("outcome", "succeeded"),
                    "remote_path": raw.get("remote_path", remote_path),
                    "bytes_written": raw.get("bytes_written", len(content_bytes)),
                }
            else:
                result = {
                    "outcome": raw.get("outcome", "succeeded"),
                    "remote_path": raw.get("remote_path", remote_path),
                    "encoding": raw.get("encoding", encoding),
                    "size": raw.get("size", raw.get("bytes_read", 0)),
                    "content": raw.get("content", ""),
                }
                if "truncated" in raw:
                    result["truncated"] = bool(raw["truncated"])

            grant_reuse = (
                requested_minutes > 0
                and not reused
                and (review_needed or self.workspace.scoped_auto_approval_enabled("ssh_reuse"))
                and (pin_trusted or committed_pin == probed_hex)
                and verified_connect
            )
            if grant_reuse:
                def store_permit():
                    self.permits = {k: p for k, p in self.permits.items() if self._permit_current(p)}
                    if len(self.permits) < MAX_SSH_PERMITS:
                        self.permits[permit_key] = SshPermit(
                            token.id, token_generation, generation, vault, entry,
                            credential_revision, sudo_revision, sudo_entry, session,
                            probed_hex, monotonic() + requested_minutes * 60,
                        )
                    return True
                guard(store_permit)

            if requested_minutes:
                with self.workspace.mutex:
                    permit = self.permits.get(permit_key)
                    result["reuse_expires_in"] = (
                        max(0, ceil(permit.expires - monotonic()))
                        if permit is not None and self._permit_current(permit) else 0
                    )

            frame = encode(result)
            if len(frame) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            delivered = deliver(frame, guard)
            outcome_label = "Succeeded" if result["outcome"] == "succeeded" else "Failed"
            self.activity.finish(event, outcome_label if delivered else "Results Not Delivered")
            if delivered and dispatch_started:
                with self.workspace.mutex:
                    self.broker.grants.used(token)
            return None
        except ListingError as error:
            outcome = "Denied"
            if dispatch_started:
                outcome = "Interrupted · outcome unknown"
            elif error.code in ("busy", "too_large", "host_key_mismatch", "ssh_failed"):
                outcome = "Failed"
            elif error.code == "revoked":
                outcome = "Revoked"
            elif error.code == "paused":
                outcome = "Paused"
            elif error.code == "expired":
                outcome = "Expired"
            elif error.code == "credential_changed":
                outcome = "Stale"
            self.activity.finish(event, outcome, detail=(error.detail or ERRORS.get(error.code)))
            raise
        finally:
            if pin_reservation is not None:
                with self.workspace.mutex:
                    self.pin_reviews.discard(pin_reservation)
