# SPDX-License-Identifier: Apache-2.0
"""Focused contract boundaries for the maintained native service journey."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coordinator_native_journey", SCRIPTS / "test-real-services.py")
native = importlib.util.module_from_spec(spec)
review_spec = importlib.util.spec_from_file_location("coordinator_review_journey", SCRIPTS / "test-review-provider.py")
review_native = importlib.util.module_from_spec(review_spec)
sys.path.insert(0, str(SCRIPTS))
try:
    spec.loader.exec_module(native)
    review_spec.loader.exec_module(review_native)
finally:
    sys.path.pop(0)


class NativeFixtureContracts(unittest.TestCase):
    def test_start_discovers_exact_revision_and_replays_same_command(self):
        journey = native.Journey.__new__(native.Journey)
        requests = []
        revision = "sha256:" + "a" * 64
        def request(owner, method, url, body=None, headers=None):
            requests.append((method, url, body, headers))
            if method == "GET":
                return {"workflow": "proposal-follow-up", "workflowRevision": revision}
            return {"runId": "synthetic-run"}
        journey.producer_request = request
        self.assertEqual(journey.start(None, "http://127.0.0.1:1", "original-key", {"correction": {}}, "proposal-follow-up"), "synthetic-run")
        self.assertEqual([method for method, *_ in requests], ["GET", "POST", "POST"])
        self.assertEqual(requests[1], requests[2])
        self.assertEqual(requests[1][2], {"workflow": "proposal-follow-up", "workflowRevision": revision, "input": {"correction": {}}})

    def test_another_workflow_contract_never_starts_a_run(self):
        journey = native.Journey.__new__(native.Journey)
        requests = []
        def request(owner, method, url, body=None, headers=None):
            requests.append(method)
            return {"workflow": "another", "workflowRevision": "sha256:" + "a" * 64}
        journey.producer_request = request
        with self.assertRaises(AssertionError):
            journey.start(None, "http://127.0.0.1:1", "original-key", {}, "proposal-follow-up")
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

    def test_native_review_contexts_use_tagged_owner_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = review_native.write_source(native, Path(directory), {
                "jwks": "http://127.0.0.1:1", "casework": "http://127.0.0.1:2",
            })
            project = json.loads((root / "registry.yaml").read_text())
        contexts = {action["id"]: action["execution"]["proposal"].get("reviewContext")
            for action in project["actions"]}
        self.assertEqual(set(contexts["correct-email"]["fields"]),
            {"tenant", "applicationId", "currentEmail", "proposedEmail", "reason"})
        for action in review_native.VARIANTS:
            self.assertEqual(set(contexts[action]["fields"]),
                {"applicationId", "recordActive", "currentAmount", "proposedAmount"})
        for context in filter(None, contexts.values()):
            for source in context["fields"].values():
                self.assertIn(source["type"], {"input", "record"})
                self.assertIn("input", source)
                self.assertNotIn("fromInput", source)
                self.assertNotIn("fromRecord", source)

    def test_native_review_automatic_selects_id_and_other_routes_pin_exact_policy(self):
        bindings = {action: {"id": flow, "version": "1", "digest": "sha256:" + "a" * 64}
            for action, (flow, _, _) in review_native.VARIANTS.items()}
        with tempfile.TemporaryDirectory() as directory:
            root = review_native.write_source(native, Path(directory), {
                "jwks": "http://127.0.0.1:1", "casework": "http://127.0.0.1:2",
                "coordinator": "http://127.0.0.1:3",
            }, bindings)
            project = json.loads((root / "registry.yaml").read_text())
        policies = {action["id"]: action["execution"]["proposal"]["review"].get("policy")
            for action in project["actions"]}
        self.assertEqual(policies["correct-amount"], {"id": "review-provider"})
        for action in list(review_native.VARIANTS)[1:]:
            self.assertEqual(policies[action], bindings[action])


if __name__ == "__main__":
    unittest.main()
