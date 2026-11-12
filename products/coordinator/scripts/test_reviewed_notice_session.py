# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the reviewed-notice tutorial session owner."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest.mock


REPO = Path(__file__).resolve().parents[3]
SESSION_SOURCE = REPO / "products/coordinator/examples/reviewed-notice/session.py"


def load_session():
    spec = importlib.util.spec_from_file_location("reviewed_notice_session", SESSION_SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReviewedNoticeSessionStartupTests(unittest.TestCase):
    def test_startup_passes_the_breg_owner_project_to_coordinator(self):
        session = load_session()
        fixture = unittest.mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / "breg"
            fixture.write_breg.return_value = owner
            fixture.free_ports.return_value = (18102, 18103)
            journey = fixture.Journey.return_value
            journey.root = root
            journey.bin = root / "bin"
            journey.containers = []
            journey.sessions = []
            journey.env = {}
            journey.ports = {"breg": 18100, "issuer": 18101, "bregdb": 15432}
            journey.urls = {"breg": "http://127.0.0.1:18100"}
            journey.tls_database.side_effect = [("coordinator-test-db", None), ("messaging-test-db", None)]
            journey.ctl.return_value = {"resource": "urn:test:breg"}
            journey.messaging_service.return_value = ("http://127.0.0.1:18104", root / "messaging.yaml")
            journey.export.return_value = {"resource": "urn:test:messaging"}
            journey.coordinator_service.side_effect = RuntimeError("stopped before starting Coordinator")
            args = SimpleNamespace(
                session_dir=root, bin_dir=journey.bin, released_clients=False, messaging_image=None,
            )

            with unittest.mock.patch.object(session, "load_fixture", return_value=fixture), \
                    unittest.mock.patch.object(session.os, "umask"), \
                    unittest.mock.patch.dict(session.os.environ):
                session.serve(args)

            journey.coordinator_service.assert_called_once()
            self.assertEqual(journey.coordinator_service.call_args.args[:2], (owner, "reviewed-notice"))
            state = session.read_state(root)
            self.assertEqual(state["error"], "RuntimeError: stopped before starting Coordinator")
            self.assertEqual(state["cleanupStatus"], "complete")


class ReviewedNoticeSessionCleanupTests(unittest.TestCase):
    def test_dead_failed_session_retries_and_records_completed_cleanup(self):
        session = load_session()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session.write_private(root / session.STATE, {
                "status": "failed", "supervisorPid": 99, "cleanupStatus": "failed",
                "ownedBinDir": str(root / "bin"), "ownedContainers": [], "ownedSessions": [],
            })
            args = SimpleNamespace(session_dir=root, command_timeout=1)
            with unittest.mock.patch.object(session, "alive", return_value=False):
                session.signal_command(args, "stop")
            state = json.loads((root / session.STATE).read_text(encoding="utf-8"))
            self.assertEqual(state["cleanupStatus"], "complete")
            self.assertTrue((root / "control/stop.done").is_file())

    def test_stop_retries_cleanup_when_the_supervisor_dies_while_waiting(self):
        session = load_session()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {
                "status": "failed", "supervisorPid": 99, "cleanupStatus": "failed",
                "ownedBinDir": str(root / "bin"), "ownedContainers": [], "ownedSessions": [],
            }
            session.write_private(root / session.STATE, state)
            args = SimpleNamespace(session_dir=root, command_timeout=1)
            with unittest.mock.patch.object(session, "alive", side_effect=[True, False]), \
                    unittest.mock.patch.object(session, "retry_cleanup") as retry:
                session.signal_command(args, "stop")
            retry.assert_called_once()
            self.assertEqual(retry.call_args.args[1]["cleanupStatus"], "failed")

    def test_retry_refuses_a_container_without_the_journey_ownership_label(self):
        session = load_session()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {
                "status": "failed", "supervisorPid": 99, "cleanupStatus": "failed",
                "ownedBinDir": str(root / "bin"), "ownedContainers": ["owned-example"],
                "ownedSessions": [],
            }
            session.write_private(root / session.STATE, state)
            inspected = subprocess.CompletedProcess([], 0, "another-owner\n", "")
            with unittest.mock.patch.object(session.subprocess, "run", return_value=inspected) as run:
                with self.assertRaises(SystemExit):
                    session.retry_cleanup(root, state)
            self.assertEqual(run.call_count, 1, "an unowned container must never reach docker rm")
            retained = json.loads((root / session.STATE).read_text(encoding="utf-8"))
            self.assertEqual(retained["cleanupStatus"], "failed")
            self.assertIn("unowned docker container", retained["cleanupError"])
            self.assertFalse((root / "control/stop.done").exists())


if __name__ == "__main__":
    unittest.main()
