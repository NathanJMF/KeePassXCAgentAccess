"""Status waits use the existing guarded operations and one absolute deadline."""

from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.agent_cli import wait_status
from keepassxc_agent_access.agent_runner import invocation
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.result_delivery import _project


class StatusWaitTests(TestCase):
    def wait(self, responses, seconds=10, **predicate):
        tick = 100
        calls = []

        def advance(delay):
            nonlocal tick
            calls.append(delay)
            tick += delay

        with patch("keepassxc_agent_access.agent_cli.request", side_effect=responses) as request, \
                patch("keepassxc_agent_access.agent_cli.monotonic", side_effect=lambda: tick), \
                patch("keepassxc_agent_access.agent_cli.sleep", side_effect=advance):
            answer = wait_status("/tmp/test.sock", {"operation": "fixture"}, seconds, **predicate)
        self.assertTrue(request.call_args_list)
        self.assertEqual(set(item.kwargs["deadline"] for item in request.call_args_list), {100 + seconds})
        return answer, calls

    def test_guest_wait_distinguishes_absent_values_and_json_types(self):
        projection = {"path": "", "columns": ["ready"]}
        responses = [{"outcome": "succeeded", "data": _project(row, projection, (), guest_output=True)}
                     for row in ({"ready": 1}, {}, {"ready": True})]
        answer, delays = self.wait(responses, field="ready", expected=True)
        self.assertEqual(answer["wait"], "matched")
        self.assertEqual(delays, [1, 2])
        missing = _project({}, projection, (), guest_output=True)
        answer, delays = self.wait([{"outcome": "succeeded", "data": missing}] * 4, seconds=4,
                                   field="ready", expected=None)
        self.assertEqual(answer["wait"], "timed_out")
        self.assertNotIn("data", answer)
        self.assertEqual(sum(delays), 4)
        explicit = _project({"ready": None}, projection, (), guest_output=True)
        answer, _ = self.wait([{"outcome": "succeeded", "data": explicit}], field="ready", expected=None)
        self.assertEqual(answer["wait"], "matched")

    def test_console_wait_stops_on_change_and_revocation(self):
        answer, delays = self.wait([{"changed": False}, {"changed": True}])
        self.assertEqual(answer["wait"], "changed")
        self.assertEqual(delays, [1])
        with self.assertRaises(ListingError) as error:
            self.wait([ListingError("revoked")])
        self.assertEqual(error.exception.code, "revoked")
        with self.assertRaises(ListingError) as error:
            self.wait([ListingError("wait_elapsed")])
        self.assertEqual(error.exception.code, "wait_elapsed")

    def test_stdio_console_images_are_opt_in(self):
        handle = str(uuid4())
        arguments, _ = invocation("console_view", {"console": handle})
        self.assertIn("--status", arguments)
        self.assertNotIn("--json", arguments)
        arguments, _ = invocation("console_view", {"console": handle, "image": True})
        self.assertIn("--json", arguments)
        arguments, _ = invocation("guest_wait", {"receipt": handle, "until": "ready", "equals": True})
        self.assertIn("--equals-json=true", arguments)
