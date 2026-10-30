# SPDX-License-Identifier: Apache-2.0
"""Focused contract boundaries for the maintained native service journey."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coordinator_native_journey", SCRIPTS / "test-real-services.py")
native = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(SCRIPTS))
try:
    spec.loader.exec_module(native)
finally:
    sys.path.pop(0)


class NativeFixtureContracts(unittest.TestCase):
    def test_cli_consumer_keeps_flat_casework_and_nested_coordinator_reports(self):
        journey = native.Journey.__new__(native.Journey)
        journey.bin = Path("/synthetic/bin")
        journey.env = {}
        journey.log_index = 0
        with tempfile.TemporaryDirectory() as directory:
            journey.root = Path(directory)
            casework = {
                "ok": True,
                "command": "dev-token",
                "status": "complete",
                "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
                "kind": "CaseworkReport",
                "version": "1.0.0",
                "headerFile": "casework.header",
                "diagnostics": [],
            }
            coordinator = {
                "ok": True,
                "command": "check",
                "status": "complete",
                "kind": "CoordinatorReport",
                "data": {"state": "ready"},
            }
            with patch.object(native.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=0, stdout=json.dumps(casework).encode(), stderr=b""),
                SimpleNamespace(returncode=0, stdout=json.dumps(coordinator).encode(), stderr=b""),
            ]):
                self.assertEqual(journey.ctl("caseworkctl", "dev", "token"), casework)
                self.assertEqual(journey.ctl("coordinatorctl", "check"), coordinator)

    def test_start_discovers_exact_revision_and_replays_same_command(self):
        journey = native.Journey.__new__(native.Journey)
        requests = []
        revision = "sha256:" + "a" * 64
        def request(owner, method, url, body=None, headers=None):
            requests.append((method, url, body, headers))
            if method == "GET":
                return {"workflow": "deferred-appointment", "workflowRevision": revision}
            return {"runId": "synthetic-run"}
        journey.producer_request = request
        self.assertEqual(journey.start(None, "http://127.0.0.1:1", "original-key", {"correction": {}}, "deferred-appointment"), "synthetic-run")
        self.assertEqual([method for method, *_ in requests], ["GET", "POST", "POST"])
        self.assertEqual(requests[1], requests[2])
        self.assertEqual(requests[1][2], {"workflow": "deferred-appointment", "workflowRevision": revision, "input": {"correction": {}}})

    def test_another_workflow_contract_never_starts_a_run(self):
        journey = native.Journey.__new__(native.Journey)
        requests = []
        def request(owner, method, url, body=None, headers=None):
            requests.append(method)
            return {"workflow": "another", "workflowRevision": "sha256:" + "a" * 64}
        journey.producer_request = request
        with self.assertRaises(AssertionError):
            journey.start(None, "http://127.0.0.1:1", "original-key", {}, "deferred-appointment")
        self.assertEqual(requests, ["GET"])

    def test_real_policy_binding_changes_only_the_owned_request_binding(self):
        source = (native.REPO / "products/coordinator/examples/reviewed-notice/functions.rhai").read_text()
        binding = {"id": "application-review", "version": "1", "digest": "sha256:" + "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "functions.rhai").write_text(source)
            native.bind_review_policy(project, binding)
            bound = (project / "functions.rhai").read_text()
        self.assertIn(binding["digest"], bound)
        self.assertEqual(source, bound.replace(binding["digest"], "sha256:" + "b" * 64))
        self.assertEqual((native.REPO / "products/coordinator/examples/reviewed-notice/functions.rhai").read_text(), source)

    def test_breg_source_uses_standalone_proposals_without_service_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = native.write_breg(Path(directory), {"jwks": "http://127.0.0.1:1", "casework": "http://127.0.0.1:2"})
            project = json.loads((root / "registry.yaml").read_text())
        self.assertNotIn("entities", project)
        self.assertEqual(len(project["recordTypes"]), 1)
        self.assertEqual(project["recordTypes"][0]["mutationPolicy"], {"patch": "proposal-required"})
        for action in project["actions"]:
            self.assertEqual(action["execution"]["mode"], "proposal")
            self.assertNotIn("application", action["execution"]["proposal"])
        for profile in project["accessProfiles"]:
            if profile.get("actorKind") == "service":
                for grant in profile["permissions"].get("proposals", []):
                    self.assertFalse({"apply", "retry"}.intersection(grant["operations"]))


if __name__ == "__main__":
    unittest.main()


class OwnedCleanupTests(unittest.TestCase):
    def test_an_auto_removed_owned_image_container_is_already_clean(self):
        journey = native.Journey.__new__(native.Journey)
        journey.proxies, journey.children, journey.sessions = [], [], []
        journey.containers = ["coordinator-tutorial-messagingctl-owned"]
        journey.env, journey.root = {}, Path("/synthetic/owned")
        with patch.object(native.subprocess, "run", side_effect=[
            SimpleNamespace(returncode=1), SimpleNamespace(returncode=0, stdout=b"unrelated-container\n"),
        ]):
            journey.cleanup(True)

    def test_an_unavailable_container_listing_does_not_hide_cleanup_failure(self):
        journey = native.Journey.__new__(native.Journey)
        journey.proxies, journey.children, journey.sessions = [], [], []
        journey.containers = ["coordinator-tutorial-messagingctl-owned"]
        journey.env, journey.root = {}, Path("/synthetic/owned")
        with patch.object(native.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"")):
            with self.assertRaisesRegex(AssertionError, "owned cleanup failed"):
                journey.cleanup(True)
