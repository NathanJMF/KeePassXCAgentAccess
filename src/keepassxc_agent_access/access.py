"""Validate, authorize, record, and dispatch broker requests."""

from dataclasses import dataclass
from time import monotonic

from .access_settings import AccessMode, action_id, uuid_text
from .activity import ActivityError, Attribution
from .approvals import Approval
from .protocol import ListingError, decode, encode
from .settings import SettingsError


@dataclass(frozen=True)
class Request:
    operation: str
    attribution: Attribution
    include_reviewed: bool = False
    entry: str | None = None
    action: str | None = None

    @classmethod
    def parse(cls, payload):
        try:
            if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
                raise ValueError
            operation = payload["operation"]
            context = Attribution.parse(payload.get("context", {}))
            remaining = set(payload) - {"version", "operation", "context"}
            if operation == "list_entries" and remaining <= {"include_reviewed"}:
                include = payload.get("include_reviewed", False)
                if type(include) is bool:
                    return cls(operation, context, include_reviewed=include)
            if operation == "use_password" and remaining == {"entry", "action"}:
                return cls(operation, context, entry=uuid_text(payload["entry"]), action=action_id(payload["action"]))
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
        raise ListingError("invalid_request")


def entry_scope(row):
    return " / ".join([*row["group_path"], row["title"]]) or "(Untitled entry)"


class AccessEngine:
    def __init__(self, settings, activity, approvals, available=lambda: True):
        self.settings = settings
        self.activity = activity
        self.approvals = approvals
        self.available = available

    def __call__(self, payload, uid, session, live, dispatch, deliver):
        request = Request.parse(payload)
        still_live = lambda: live() and self.available()
        event = None
        try:
            settings = self.settings.read()
            policy = settings.for_vault(session.identity)
            action = next((item for item in policy.actions if item.id == request.action), None)
            if request.entry is None:
                name = "List entries"
                destination = None
            elif (not action or not action.enabled or action.entry != request.entry or action.is_command
                  or action.method != "GET"):
                event = self.activity.begin(uid, request.attribution, "Use password · unavailable action", None)
                raise ListingError("ineligible")
            else:
                name = f"Use password · {action.name}"
                destination = action.url
            event = self.activity.begin(uid, request.attribution, name, destination, request.entry)

            review = settings.mode is AccessMode.REVIEW
            if request.entry is None:
                listing = decode(session.list_entries())
                if "error" in listing:
                    raise ListingError(listing["error"])
                rows = listing["entries"]
                if settings.mode is AccessMode.SMART:
                    review = request.include_reviewed and any(row["id"] not in policy.automatic for row in rows)
                    if not request.include_reviewed:
                        rows = [row for row in rows if row["id"] in policy.automatic]
                scope = tuple(entry_scope(row) for row in rows)
            else:
                entry = session.entry(request.entry)
                if entry is None:
                    raise ListingError("ineligible")
                scope = (entry_scope(entry),)
                if settings.mode is AccessMode.SMART:
                    review = request.entry not in policy.automatic

            if not still_live():
                raise ListingError("revoked")
            if review:
                ticket = Approval(event, uid, request.attribution, name, scope, destination,
                                  monotonic() + self.approvals.timeout)
                answer = self.approvals.wait(ticket, still_live)
                if answer != "approved":
                    raise ListingError(answer)

            self.activity.authorize(event, "Approved once" if review else "Allowed by policy")
            if not still_live():
                raise ListingError("revoked")

            if request.entry is None:
                if not deliver(encode({"entries": rows})):
                    raise ListingError("revoked")
                self.activity.finish(event, "Succeeded")
                return None

            def gate(send):
                if not still_live():
                    return False
                self.activity.dispatched(event)
                return dispatch(send)

            result = session.use(action, gate)
            self.activity.finish(event, "Succeeded" if result["outcome"] == "succeeded" else "Failed",
                                 result.get("http_status"))
            return encode(result)
        except (ActivityError, SettingsError):
            raise ListingError("audit_unavailable") from None
        except ListingError as error:
            if event is not None:
                outcome = {
                    "declined": "Declined", "expired": "Timed out", "revoked": "Revoked",
                    "ineligible": "Denied", "busy": "Busy",
                }.get(error.code, "Failed")
                try:
                    self.activity.finish(event, outcome)
                except ActivityError:
                    raise ListingError("audit_unavailable") from None
            raise
