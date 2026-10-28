"""Regression assertions for the live journey's acceptance oracle."""

import copy
import unittest

from proof import check_correlation, check_minimized, check_cleanup, check_observations


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.proposal = {"id": "p1", "submissionVersion": 1, "effectDigest": "sha256:effects"}
        self.accepted = {
            "requestId": "r1",
            "policy": {"id": "status-review", "version": "1", "digest": "sha256:policy"},
            "subject": {
                "source": "registry",
                "type": "proposal",
                "id": "p1",
                "version": "1",
                "digest": "sha256:effects",
            },
            "submissionDigest": "sha256:submission",
        }
        self.result = dict(self.accepted, status="approved", outcome="approved")

    def test_exact_accepted_result(self):
        check_correlation(self.proposal, self.accepted, self.result)

    def test_each_correlation_field_must_match(self):
        mutations = [
            ("requestId", "other"),
            ("policy", {"id": "other"}),
            ("subject", dict(self.result["subject"], id="other")),
            ("submissionDigest", "sha256:other"),
            ("status", "rejected"),
            ("outcome", "rejected"),
        ]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_correlation(self.proposal, self.accepted, dict(self.result, **{key: value}))

    def test_subject_must_name_exact_frozen_submission(self):
        for key, value in [
            ("id", "other"),
            ("version", "2"),
            ("digest", "sha256:other"),
            ("source", "other"),
        ]:
            accepted = copy.deepcopy(self.accepted)
            accepted["subject"][key] = value
            result = dict(accepted, status="approved", outcome="approved")
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_correlation(self.proposal, accepted, result)


class DisclosureTests(unittest.TestCase):
    def test_exact_boolean_output(self):
        check_minimized(
            {
                "supportedValues": [
                    {"providesValueFor": "urn:example:concept:record-active:active", "value": True}
                ]
            },
            True,
        )

    def test_private_facts_or_additional_outputs_fail(self):
        for payload in [
            {
                "supportedValues": [
                    {"providesValueFor": "urn:example:concept:record-active:active", "value": "true"}
                ]
            },
            {
                "supportedValues": [
                    {"providesValueFor": "urn:example:concept:record-active:active", "value": True},
                    {"providesValueFor": "label", "value": "PRIVATE-CANARY"},
                ]
            },
            {
                "supportedValues": [
                    {"providesValueFor": "urn:example:concept:record-active:active", "value": True}
                ],
                "label": "PRIVATE-CANARY",
            },
        ]:
            with self.subTest(payload=payload), self.assertRaises(AssertionError):
                check_minimized(payload, True)

    def test_cleanup_requires_all_owned_resources_gone(self):
        check_cleanup({"processesStopped": True, "databasesRemaining": 0, "rolesRemaining": 0})
        for key, value in [("processesStopped", False), ("databasesRemaining", 1), ("rolesRemaining", 1)]:
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_cleanup(
                    {**dict(processesStopped=True, databasesRemaining=0, rolesRemaining=0), key: value}
                )


class CleanupFailureTests(unittest.TestCase):
    def test_database_inventory_failure_still_removes_owned_container(self):
        from pathlib import Path
        from unittest.mock import Mock, patch
        from support import Harness

        harness = object.__new__(Harness)
        harness.output = Path("/unused-test-output")
        harness.processes = []
        harness.issuer = None
        harness.pg_env = {}
        harness.resources = {"databases": [], "roles": []}
        harness.container = "owned-test-container"
        harness.sql = Mock(side_effect=RuntimeError("inventory unavailable"))
        harness.run = Mock(return_value="")
        with patch("support.write"), patch("support.subprocess.run", return_value=Mock(stdout="")):
            with self.assertRaises((AssertionError, RuntimeError)):
                harness.cleanup()
        harness.run.assert_any_call("container-remove", ["docker", "rm", "-f", "owned-test-container"])


class ObservationTests(unittest.TestCase):
    def pair(self):
        identity = {
            key: "fixed"
            for key in (
                "configurationRevision",
                "subjects",
                "issuedBy",
                "providedBy",
                "supportsRequirement",
                "isConformantTo",
                "purpose",
                "audience",
            )
        }
        before = dict(
            identity,
            requestNonce="first",
            supportedValues=[
                {"providesValueFor": "urn:example:concept:record-active:active", "value": False}
            ],
        )
        after = dict(
            identity,
            requestNonce="second",
            supportedValues=[{"providesValueFor": "urn:example:concept:record-active:active", "value": True}],
        )
        return before, after

    def test_same_subject_contract_changes_only_the_observed_answer(self):
        check_observations(*self.pair())

    def test_identity_drift_is_not_a_source_correction(self):
        before, after = self.pair()
        for key in (
            "configurationRevision",
            "subjects",
            "issuedBy",
            "providedBy",
            "supportsRequirement",
            "isConformantTo",
            "purpose",
            "audience",
        ):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                check_observations(before, dict(after, **{key: "other"}))

    def test_both_observations_need_distinct_requests(self):
        before, after = self.pair()
        with self.assertRaises(AssertionError):
            check_observations(before, dict(after, requestNonce="first"))


if __name__ == "__main__":
    unittest.main()
