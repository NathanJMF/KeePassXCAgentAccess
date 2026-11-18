"""Fixed request templates for approved guest command endpoints."""

from dataclasses import dataclass
import re

from .protocol import MAX_GUEST_TEXT, encode
from .result_delivery import ResultRequest, parse_result_usage


_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")


@dataclass(frozen=True)
class GuestRequest:
    submit: ResultRequest
    poll: ResultRequest
    body_type: str
    command_field: str
    job_query: str
    argument_prefix: tuple[str, ...] | None

    def start(self, command):
        if (not isinstance(command, str) or not 1 <= len(command) <= MAX_GUEST_TEXT
                or not command.isascii()
                or any(not char.isprintable() and (self.body_type != "json" or char not in "\n\t")
                       for char in command)):
            raise ValueError("Use a bounded guest command. JSON commands may contain line breaks and tabs.")
        data = self.submit.data
        value = command if self.argument_prefix is None else [*self.argument_prefix, command]
        data["request"].setdefault(self.body_type, {})[self.command_field] = value
        return parse_result_usage(data)

    def status(self, job):
        if not (type(job) is int and 1 <= job < 2**53 or isinstance(job, str) and _JOB_ID.fullmatch(job)):
            raise ValueError("The guest service did not return a supported job identifier.")
        data = self.poll.data
        data["request"].setdefault("query", {})[self.job_query] = str(job)
        return parse_result_usage(data)


def parse_guest_request(data):
    required = {"origin", "certificate_sha256", "submit", "poll", "body_type", "command_field", "job_query"}
    if not isinstance(data, dict) or not required <= data.keys() <= required | {"login", "argument_prefix"}:
        raise ValueError("Provide pinned submit and polling requests for the guest.")
    body_type, command_field, job_query = data["body_type"], data["command_field"], data["job_query"]
    if (body_type not in ("form", "json") or not isinstance(command_field, str) or not _FIELD.fullmatch(command_field)
            or not isinstance(job_query, str) or not _FIELD.fullmatch(job_query)):
        raise ValueError("Choose one command field and one job query parameter.")
    prefix = data.get("argument_prefix")
    if "argument_prefix" in data and (body_type != "json" or not isinstance(prefix, list)
            or not 1 <= len(prefix) <= 8 or any(not isinstance(arg, str) or not 1 <= len(arg) <= 128
                                                or not arg.isascii() or not arg.isprintable() for arg in prefix)):
        raise ValueError("Supply a short, fixed JSON argument prefix.")
    common = {key: data[key] for key in ("origin", "certificate_sha256", "login") if key in data}
    submit = data["submit"]
    poll = data["poll"]
    if not isinstance(submit, dict) or set(submit) != {"request", "job_path"}:
        raise ValueError("Provide a command request and the path to its job ID.")
    if not isinstance(poll, dict) or set(poll) != {"request", "result"}:
        raise ValueError("Provide a job status request and its result fields.")
    start = parse_result_usage({"type": "https_results", **common, "request": submit["request"],
                                "result": {"path": submit["job_path"], "scalar": "job_id"}})
    status = parse_result_usage({"type": "https_results", **common, **poll})
    request, query = start.data["request"], status.data["request"]
    if (request["method"] != "POST" or query["method"] != "GET"
            or ("json" if body_type == "form" else "form") in request
            or command_field.casefold() in {field.casefold() for field in request.get(body_type, {})}
            or job_query.casefold() in {field.casefold() for field in query.get("query", {})}):
        raise ValueError("Use a POST command, a GET status request, and unassigned value fields.")
    if len(encode(data)) > 3000:
        raise ValueError("The guest command template exceeds the size limit.")
    return GuestRequest(start, status, body_type, command_field, job_query, tuple(prefix) if prefix else None)
