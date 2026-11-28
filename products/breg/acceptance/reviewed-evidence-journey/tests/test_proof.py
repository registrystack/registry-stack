"""Regression assertions for the live journey's acceptance oracle."""

import copy
import unittest

from proof import check_correlation, check_minimized, check_cleanup, check_observations, check_ask_loop


class AskLoopTests(unittest.TestCase):
    def test_static_source_fixture_omits_only_oauth_replay(self):
        from run_live import bind_static_fixture

        fixture = {
            "cases": [
                {
                    "id": "positive",
                    "acquisition": {
                        "intercepts": [
                            {"type": "endpoint", "endpoint": "registry"},
                            {"type": "token-endpoint", "endpoint": "registry"},
                        ],
                        "exchanges": [
                            {"request": {"tokenRequest": True}},
                            {"request": {"path": "/lookup"}, "response": {"status": 200}},
                        ],
                    },
                },
                {"id": "timeout", "sourceFailure": "timeout"},
            ]
        }
        bind_static_fixture(fixture)
        self.assertEqual(
            fixture["cases"][0]["acquisition"],
            {
                "intercepts": [{"type": "endpoint", "endpoint": "registry"}],
                "exchanges": [{"request": {"path": "/lookup"}, "response": {"status": 200}}],
            },
        )
        self.assertEqual(fixture["cases"][1], {"id": "timeout", "sourceFailure": "timeout"})

    def test_evidence_connection_uses_the_current_endpoint_binding(self):
        from run_live import registry_connection

        self.assertEqual(
            registry_connection("http://127.0.0.1:1234"),
            {
                "endpoints": {
                    "registry": {
                        "origin": "http://127.0.0.1:1234",
                        "authentication": {
                            "type": "static-authorization",
                            "tokenRef": "secret:file/source-token",
                        },
                    }
                }
            },
        )

    def test_literal_loopback_hook_uses_the_default_dns_policy(self):
        from pathlib import Path
        from types import SimpleNamespace
        from run_live import breg_runtime

        harness = SimpleNamespace(
            output=Path("/unused"),
            secret_root=Path("/unused/secrets"),
            hook_origin="http://127.0.0.1:1234",
            db_configs={"source": {}},
            issuer_url="http://127.0.0.1:1235",
            tokens={},
        )
        runtime = breg_runtime(
            harness, "source", Path("/unused/package"), "http://127.0.0.1:1236", "http://127.0.0.1:1237"
        )
        self.assertEqual(runtime["destinations"]["hooks"]["ask-observer"]["dnsFamily"], "dual-stack-strict")

    def observations(self):
        submitted = {"id": "p1", "submissionVersion": 1, "effectDigest": "sha256:effects"}
        ask = {
            "askId": "q1",
            "state": "open",
            "wants": [{"kind": "document"}],
            "askedAt": "2026-11-28T00:00:00Z",
            "dueAt": "2026-11-28T01:00:00Z",
        }
        task = {"taskId": "t1", "requestId": "r1", "marker": "waiting"}
        party = dict(
            submitted,
            state="submitted",
            status="awaiting-party",
            turn="party",
            asks=[{"id": "q1", "state": "open", "dueAt": ask["dueAt"]}],
        )
        answered = dict(
            submitted,
            state="submitted",
            status="in-review",
            turn="official",
            asks=[
                {"id": "q1", "state": "answered", "answer": {"text": "PRIVATE-ANSWER", "additions": ["f1"]}}
            ],
        )
        document = {
            "id": "f1",
            "verificationStatus": "notRequired",
            "download": {
                "method": "GET",
                "operation": "get-review-context",
                "accessProfile": "reviewer",
                "path": "/v1/proposals/p1/additions/f1?reviewAskId=q1&submissionVersion=1",
            },
        }
        return {
            "submitted": submitted,
            "accepted": {"requestId": "r1"},
            "asked": {"task": task, "ask": ask},
            "party": party,
            "partyPage": {"items": [party]},
            "hook": {
                "id": "e1",
                "type": "proposal.asked",
                "data": {"proposalId": "p1", "submissionVersion": 1, "transition": "asked"},
            },
            "answered": answered,
            "additionId": "f1",
            "task": dict(task, marker="answered"),
            "context": {
                "taskId": "t1",
                "requestId": "r1",
                "asks": [
                    {
                        "askId": "q1",
                        "taskId": "t1",
                        "state": "answered",
                        "answer": {"text": "PRIVATE-ANSWER", "documents": [document]},
                    }
                ],
            },
            "download": b"PRIVATE-FILE",
            "createdRequestIds": ["r1"],
            "correlations": [{"requestId": "r1"}] * 3,
            "decidedTask": dict(
                task,
                state="decided",
                decidedByCaller=True,
                decisionReceipt={"decision": "approve", "outcome": "approved"},
            ),
            "requests": [{"actor": "producer", "method": "POST", "status": 201}],
        }

    def test_served_loop_returns_only_identifiers_and_states(self):
        summary = check_ask_loop(self.observations(), "PRIVATE-ANSWER", b"PRIVATE-FILE")
        self.assertEqual(summary["requestId"], "r1")
        self.assertEqual(summary["taskId"], "t1")
        self.assertNotIn("PRIVATE", str(summary))
        self.assertEqual(summary["marker"], "answered")

    def test_mirror_compares_absolute_deadlines_across_utc_spellings(self):
        observations = self.observations()
        observations["party"]["asks"][0]["dueAt"] = "2026-11-28T01:00:00+00:00"
        check_ask_loop(observations, "PRIVATE-ANSWER", b"PRIVATE-FILE")

    def test_each_loop_boundary_rejects_a_mismatched_observation(self):
        mutations = [
            ("party", "status", "in-review"),
            ("party", "turn", "official"),
            ("answered", "submissionVersion", 2),
            ("answered", "effectDigest", "other"),
            ("answered", "status", "awaiting-party"),
            ("task", "marker", "waiting"),
            ("task", "taskId", "another-task"),
            ("context", "requestId", "another-request"),
            ("decidedTask", "taskId", "another-task"),
            ("decidedTask", "decidedByCaller", False),
        ]
        for member, key, value in mutations:
            observations = self.observations()
            observations[member][key] = value
            with self.subTest(member=member, key=key), self.assertRaises(AssertionError):
                check_ask_loop(observations, "PRIVATE-ANSWER", b"PRIVATE-FILE")
        for member, value in [
            ("partyPage", {"items": []}),
            ("createdRequestIds", ["r1", "r2"]),
            ("download", b"other"),
            ("requests", [{"actor": "applicant"}]),
        ]:
            observations = self.observations()
            observations[member] = value
            with self.subTest(member=member), self.assertRaises(AssertionError):
                check_ask_loop(observations, "PRIVATE-ANSWER", b"PRIVATE-FILE")

    def test_answer_and_citation_are_read_from_the_right_ask(self):
        for change in ("text", "file", "ask", "link", "deadline", "event"):
            observations = self.observations()
            answer = observations["context"]["asks"][0]["answer"]
            if change == "text":
                answer["text"] = "another answer"
            elif change == "file":
                answer["documents"][0]["id"] = "another-file"
            elif change == "ask":
                observations["context"]["asks"][0]["askId"] = "another-ask"
            elif change == "link":
                answer["documents"][0]["download"]["path"] = "/v1/proposals/p1/additions/f1?reviewAskId=q2"
            elif change == "deadline":
                del observations["asked"]["ask"]["dueAt"]
            else:
                observations["hook"]["type"] = "proposal.submitted"
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check_ask_loop(observations, "PRIVATE-ANSWER", b"PRIVATE-FILE")


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
            {
                "supportedValues": [
                    {"providesValueFor": "urn:example:concept:record-active:active", "value": True}
                ],
                "sourceState": "retired",
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
        with (
            patch("support.write") as write,
            patch("support.subprocess.run", return_value=Mock(stdout="")),
        ):
            with self.assertRaises((AssertionError, RuntimeError)):
                harness.cleanup()
        harness.run.assert_any_call("container-remove", ["docker", "rm", "-f", "owned-test-container"])
        receipt = write.call_args.args[1]
        self.assertEqual(["database inventory unavailable"], receipt["errors"])
        self.assertTrue(receipt["containerRemoved"])

    def test_failed_container_removal_is_reported(self):
        from pathlib import Path
        from unittest.mock import Mock, patch
        from support import Harness

        def run(label, _command):
            if label == "container-remove":
                raise RuntimeError("container removal refused")
            return ""

        harness = object.__new__(Harness)
        harness.output = Path("/unused-test-output")
        harness.processes = []
        harness.issuer = None
        harness.pg_env = {}
        harness.resources = {"databases": [], "roles": []}
        harness.container = "owned-test-container"
        harness.sql = Mock(return_value="0")
        harness.run = Mock(side_effect=run)
        with patch("support.write") as write, patch("support.subprocess.run"):
            with self.assertRaises(AssertionError):
                harness.cleanup()
        receipt = write.call_args.args[1]
        self.assertEqual(["container cleanup failed"], receipt["errors"])
        self.assertFalse(receipt["containerRemoved"])


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
