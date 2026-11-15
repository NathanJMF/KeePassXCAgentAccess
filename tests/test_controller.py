import unittest
from threading import Event, Thread
from unittest.mock import Mock

from keepassxc_agent_access.controller import VaultController, VaultState
from keepassxc_agent_access.vault import UnlockCancelled, VaultError


class ControllerTests(unittest.TestCase):
    def test_states_and_release(self):
        session = Mock()
        controller = VaultController(Mock(return_value=session))
        self.assertIs(controller.state(False), VaultState.SETUP)
        self.assertIs(controller.state(True), VaultState.LOCKED)
        controller.unlock(controller.begin(), None, "synthetic", "manual")
        self.assertIs(controller.state(True), VaultState.UNLOCKED)
        controller.lock()
        self.assertIs(controller.state(True), VaultState.LOCKED)
        self.assertIsNone(controller.source)
        session.close.assert_called_once()

    def test_failed_unlock_stays_locked(self):
        controller = VaultController(Mock(side_effect=VaultError("Wrong password.")))
        with self.assertRaises(VaultError):
            controller.unlock(controller.begin(), None, "synthetic", "manual")
        self.assertIs(controller.state(True), VaultState.LOCKED)

    def test_late_unlock_is_discarded(self):
        started, finish, cancelled = Event(), Event(), Event()
        session = Mock()

        def delayed_open(*_):
            started.set()
            finish.wait(2)
            return session

        controller = VaultController(delayed_open)
        attempt = controller.begin()

        def unlock():
            try:
                controller.unlock(attempt, None, "synthetic", "manual")
            except UnlockCancelled:
                cancelled.set()

        thread = Thread(target=unlock)
        thread.start()
        self.assertTrue(started.wait(2))
        controller.lock()
        finish.set()
        thread.join(2)
        self.assertTrue(cancelled.is_set())
        self.assertIs(controller.state(True), VaultState.LOCKED)
        session.close.assert_called_once()
