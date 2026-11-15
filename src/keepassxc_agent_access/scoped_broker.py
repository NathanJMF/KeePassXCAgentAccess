"""Authorize scoped requests and recheck their state before releasing data."""

from .access_settings import action_id, uuid_text
from .activity import ActivityError, Attribution
from .grants import OPTIONAL_METADATA_FIELDS
from .protocol import RESPONSE_LIMIT, ListingError, encode
from .settings import SettingsError


class ScopedBroker:
    def __init__(self, workspace, grants, activity, edits=None):
        self.workspace = workspace
        self.grants = grants
        self.activity = activity
        self.edits = edits

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
            keys = set(payload) - {"version", "operation", "credential", "context"}
            context = Attribution.parse(payload.get("context", {}))
            entry, binding_id, vault = None, None, None
            fields = ()
            if operation in ("request_access", "request_edit") and keys == {"request"}:
                pass
            elif operation == "edit_status" and keys == {"id"}:
                pass
            elif operation in ("access_status", "list_vaults") and not keys:
                pass
            elif operation == "list_entries" and keys <= {"vault", "fields"}:
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                fields = payload.get("fields", [])
                if (not isinstance(fields, list) or len(fields) > len(OPTIONAL_METADATA_FIELDS)
                        or any(field not in OPTIONAL_METADATA_FIELDS for field in fields)
                        or len(set(fields)) != len(fields)):
                    raise ValueError
            elif operation == "use_password" and keys in ({"entry", "action"}, {"entry", "action", "vault"}):
                entry = uuid_text(payload["entry"])
                binding_id = action_id(payload["action"])
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
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
            if operation in ("request_edit", "edit_status"):
                if self.edits is None:
                    raise ListingError("ineligible")
                reply = (self.edits.submit(token, payload["request"], context) if operation == "request_edit"
                         else self.edits.status(token, payload["id"]))
                return encode(reply)
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
                scope=f"Requested entry fields · {', '.join(fields)}" if fields else None,
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
                result = self._entries(token, session, chosen, fields)
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
            frame = encode(result)
            if len(frame) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            delivered = deliver(frame, guard)
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

    @staticmethod
    def _entries(token, session, vault, fields):
        permissions = {}
        for scope in token.scope:
            if scope.vault == vault and scope.metadata:
                allowed = permissions.setdefault(scope.entry, set())
                allowed.update(field for field in fields if getattr(scope, field))
        result = session.worker.scoped_entries(permissions.keys())
        if "error" in result:
            raise ListingError(result["error"])
        # The worker provides only the scoped identities and basic metadata. Read
        # separately approved values from this same session's owner projection.
        owner_rows = {}
        if any(permissions.values()):
            for row in session.entries:
                identifier = row["id"]
                if permissions.get(identifier):
                    owner_rows[identifier] = row if identifier not in owner_rows else {}
        rows = []
        for row in result["entries"]:
            identifier = row["id"]
            if identifier not in permissions:
                continue
            projected = {"id": identifier, "title": row["title"], "group_path": row["group_path"]}
            values = owner_rows.get(identifier, {})
            projected.update({field: values[field] for field in fields
                              if field in permissions[identifier] and isinstance(values.get(field), str)})
            rows.append(projected)
        return {"entries": rows}
