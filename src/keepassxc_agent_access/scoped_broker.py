"""Authorize scoped requests and recheck their state before releasing data."""

from .access_settings import action_id, uuid_text
from .activity import ActivityError, Attribution
from .protocol import ListingError, encode
from .settings import SettingsError


class ScopedBroker:
    def __init__(self, workspace, grants, activity):
        self.workspace = workspace
        self.grants = grants
        self.activity = activity

    def __call__(self, payload, uid, _engine, live, dispatch, deliver):
        try:
            return self.handle(payload, uid, live, dispatch, deliver)
        except (ActivityError, SettingsError):
            raise ListingError("audit_unavailable") from None

    def handle(self, payload, uid, live, dispatch, deliver):
        try:
            if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
                raise ValueError
            operation = payload["operation"]
            fields = set(payload) - {"version", "operation", "credential", "context"}
            context = Attribution.parse(payload.get("context", {}))
            entry, binding_id, vault = None, None, None
            if operation == "request_access" and fields == {"request"}:
                pass
            elif operation in ("access_status", "list_vaults") and not fields:
                pass
            elif operation == "list_entries" and fields <= {"vault"}:
                vault = uuid_text(payload["vault"]) if "vault" in fields else None
            elif operation == "use_password" and fields in ({"entry", "action"}, {"entry", "action", "vault"}):
                entry = uuid_text(payload["entry"])
                binding_id = action_id(payload["action"])
                vault = uuid_text(payload["vault"]) if "vault" in fields else None
            else:
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ListingError("invalid_request") from None
        credential = payload.get("credential")
        if credential is None:
            raise ListingError("token_required")

        if isinstance(credential, str) and credential and credential in encode(
            {"context": payload.get("context"), "request": payload.get("request")}
        ).decode("ascii"):
            raise ListingError("invalid_request")

        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            if operation == "request_access":
                status = self.grants.enroll(credential, uid, payload["request"], context)
                return encode({"status": status})
            token = self.grants.authenticate(credential, uid)
            if operation == "access_status":
                return encode({"status": token.status})
            generation = self.workspace.generation
            name = {"list_vaults": "List vaults", "list_entries": "List entries",
                    "use_password": "Use password"}[operation]
            registered = self._catalog(token)
            chosen = vault
            if vault is None and len(registered) == 1 and operation != "list_vaults":
                chosen = next(iter(registered))
            registration = self.workspace.registrations.get(chosen) if chosen in registered else None
            session = self.workspace.session(chosen) if registration else None
            binding = registration.binding(entry, binding_id) if registration and entry else None
            permitted = (
                binding is not None and binding.action.enabled and
                any((s.vault, s.entry, s.action, s.revision) == (chosen, entry, binding_id, binding.revision)
                    for s in token.scope)
            )
            event = self.activity.begin(
                uid, context, name + (f" · {binding.action.name}" if permitted else ""),
                binding.action.url if permitted else None, entry if permitted else None,
                vault=registration.name if registration else None, vault_id=chosen if registration else None,
                token=token.id, agent=token.identity, project=token.project,
            )

        def guard(effect):
            with self.workspace.mutex:
                current = self.grants.records[token.id]
                if (self.workspace.paused or self.workspace.generation != generation
                        or current.generation != token.generation or current.status != "active"):
                    return False
                if operation == "list_vaults":
                    if self._catalog(current) != registered:
                        return False
                else:
                    if self.workspace.session(chosen) is not session:
                        return False
                    record = self.workspace.registrations.get(chosen)
                    if record is None:
                        return False
                    if binding is not None:
                        saved = record.binding(entry, binding_id)
                        if saved is not binding or not saved.action.enabled:
                            return False
                return effect()

        dispatch_started = False
        try:
            if token.status != "active":
                raise ListingError("ineligible")
            with self.workspace.mutex:
                if self.workspace.paused:
                    raise ListingError("paused")
            if operation != "list_vaults":
                if vault is None and len(registered) > 1:
                    raise ListingError("select_vault")
                if session is None or (operation == "use_password" and not permitted):
                    raise ListingError("ineligible")
            if operation == "use_password" and session.worker.entry(entry) is None:
                raise ListingError("ineligible")
            if not guard(live):
                raise ListingError("revoked")
            self.activity.authorize(event, "Approved token")
            if operation == "list_vaults":
                result = {"vaults": [{"id": key, "name": name} for key, name in registered.items()]}
            elif operation == "list_entries":
                entries = {scope.entry for scope in token.scope if scope.vault == chosen and scope.metadata}
                result = session.worker.scoped_entries(entries)
                if "error" in result:
                    raise ListingError(result["error"])
            else:
                def gate(send):
                    def audit_and_send():
                        nonlocal dispatch_started
                        self.activity.dispatched(event)
                        dispatch_started = True
                        send()
                    return guard(lambda: dispatch(audit_and_send))

                result = session.worker.use(binding.action, gate)
            succeeded = result.get("outcome") != "failed"
            delivered = deliver(encode(result), guard)
            if operation == "use_password":
                # An HTTP request dispatched before revocation may still complete on its fixed endpoint.
                self.activity.finish(event, "Succeeded" if succeeded else "Failed", result.get("http_status"))
            elif not delivered:
                raise ListingError("revoked")
            else:
                self.activity.finish(event, "Succeeded")
            if succeeded and delivered:
                with self.workspace.mutex:
                    self.grants.used(token)
            return None
        except ListingError as error:
            outcome = "Denied"
            if dispatch_started:
                outcome = "Interrupted · outcome unknown"
            elif error.code in ("busy", "too_large"):
                outcome = "Failed"
            elif error.code == "revoked" or not guard(live) and error.code == "unavailable":
                outcome = "Revoked"
            elif error.code == "paused":
                outcome = "Paused"
            self.activity.finish(event, outcome)
            raise

    def _catalog(self, token):
        identifiers = {scope.vault for scope in token.scope}
        return {r.id: r.name for r in self.workspace.registrations.values() if r.id in identifiers}
