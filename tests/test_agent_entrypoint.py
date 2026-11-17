"""The installed task frontend must not inherit another task or caller routing."""

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from keepassxc_agent_access import agent_entrypoint as entrypoint


class TaskEntrypointTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"

    def test_fresh_tasks_get_separate_profiles_even_with_the_same_readable_name(self):
        first = entrypoint.create_session("Build Assistant", "Forgejo Setup", state=self.state)
        second = entrypoint.create_session("Build Assistant", "Forgejo Setup", state=self.state)
        self.assertNotEqual(first["profile"], second["profile"])
        for item in (first, second):
            anchor, metadata = entrypoint.session(item["profile"], state=self.state)
            self.assertEqual(metadata, {"identity": "Build Assistant", "project": "Forgejo Setup"})
            self.assertEqual(anchor.parent, self.state / "keeper-agent-sessions")
            self.assertEqual(list(anchor.iterdir()), [])
            self.assertEqual((anchor.parent / (item["profile"] + ".json")).stat().st_mode & 0o777, 0o600)

    def test_all_valid_unicode_metadata_round_trips_within_size_cap(self):
        values = ["🦉" * 160] * 4
        registration = entrypoint.create_session(*values, state=self.state)
        _, metadata = entrypoint.session(registration["profile"], state=self.state)
        self.assertEqual(list(metadata.values()), values)

    def test_registration_metadata_cannot_be_replaced_with_symlink_or_shared_file(self):
        registration = entrypoint.create_session("Trial", "Tests", state=self.state)
        path = self.state / "keeper-agent-sessions" / (registration["profile"] + ".json")
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            entrypoint.session(registration["profile"], state=self.state)
        path.unlink()
        path.symlink_to(self.root / "unrelated")
        with self.assertRaises(OSError):
            entrypoint.session(registration["profile"], state=self.state)
        with self.assertRaises(ValueError):
            entrypoint.session("default", state=self.state)
        with self.assertRaises(ValueError):
            entrypoint.session("../other", state=self.state)

    def test_live_paths_ignore_caller_environment_and_do_not_reuse_legacy_profiles(self):
        home = self.root / "owner"
        home.mkdir(mode=0o700)
        with patch.dict(os.environ, HOME=str(self.root / "wrong-home"),
                        XDG_STATE_HOME=str(self.root / "wrong-state"),
                        XDG_RUNTIME_DIR=str(self.root / "wrong-runtime")), \
                patch.object(entrypoint, "installed_home", return_value=home):
            registration = entrypoint.create_session("Fresh Agent", "Tests")
            with patch.object(entrypoint, "launch", return_value=0) as launch, \
                    patch.object(entrypoint, "owned"), \
                    patch.object(entrypoint, "subordinate_ids", return_value=(100000, 100000)):
                self.assertEqual(entrypoint.main(["--profile", registration["profile"], "discover", "--json"]), 0)
            args, kwargs = launch.call_args
            self.assertEqual(args[0], Path(f"/run/user/{os.getuid()}/keeper-scoped-runner"))
            self.assertEqual(kwargs["anchor"].parent, home / ".local/state/keeper-agent-sessions")
            self.assertFalse((self.root / "wrong-state").exists())
            self.assertEqual(kwargs["attribution"], {"KEEPASSXC_AGENT_IDENTITY": "Fresh Agent",
                                                    "KEEPASSXC_AGENT_PROJECT": "Tests"})

    def test_begin_and_task_commands_have_no_socket_or_token_override(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(entrypoint.main(["begin", "--identity", "Fresh Agent", "--project", "Tests"],
                                             _state=self.state), 0)
        registration = json.loads(output.getvalue())
        with patch.object(entrypoint, "launch", return_value=0) as launch, \
                patch.object(entrypoint, "owned"), \
                patch.object(entrypoint, "subordinate_ids", return_value=(100000, 100000)), \
                patch.dict(os.environ, KEEPASSXC_AGENT_SOCKET="/tmp/evil", KEEPASSXC_AGENT_TOKEN_FILE="/tmp/token",
                           KEEPASSXC_AGENT_IDENTITY="Inherited Agent", KEEPASSXC_AGENT_NOTE="Inherited note"):
            self.assertEqual(entrypoint.main(["--profile", registration["profile"], "--note", "List names",
                                             "discover", "--json"], _state=self.state), 0)
        _, kwargs = launch.call_args
        self.assertEqual(kwargs["cli"], ["discover", "--json"])
        self.assertEqual(kwargs["attribution"], {"KEEPASSXC_AGENT_IDENTITY": "Fresh Agent",
                                                "KEEPASSXC_AGENT_PROJECT": "Tests",
                                                "KEEPASSXC_AGENT_NOTE": "List names"})
        with self.assertRaises(SystemExit):
            entrypoint.main(["--socket", "/tmp/evil", "discover"], _state=self.state)
