"""The bounded same-key resend of an admission, against a scripted service."""

from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_coordinator_client import CoordinatorClient, CoordinatorClientError  # noqa: E402
from scripted import INSPECTION, KEY, RUN, START_REQUEST, STATUS, Scripted, ok, problem  # noqa: E402

LIST_PATH = "/deployment/v1/runs?limit=20"

UNAVAILABLE = problem(503, "service.unavailable")
KEY_REUSED = problem(409, "idempotency.key-reused")


class MutationRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = Scripted()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.service.close()

    def test_a_503_is_resent_once_under_the_same_key_and_succeeds(self) -> None:
        self.service.script(UNAVAILABLE, ok(STATUS))

        outcome = CoordinatorClient(self.service.base_url).start("one-call-token", KEY, START_REQUEST)

        self.assertEqual(outcome, {"kind": "complete", "value": STATUS})
        observations = self.service.observations()
        self.assertEqual(len(observations), 2)
        first, resend = observations
        self.assertEqual(first["path"], "/deployment/v1/runs")
        self.assertEqual(first["idempotency_key"], KEY)
        self.assertEqual(resend, first)

    def test_the_default_ceiling_is_two_resends(self) -> None:
        self.service.script(UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, ok(STATUS))
        with self.assertRaises(CoordinatorClientError) as raised:
            CoordinatorClient(self.service.base_url).start("one-call-token", KEY, START_REQUEST)
        self.assertEqual(raised.exception.status, 503)
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(self.service.observations()), 3)

    def test_a_ceiling_of_zero_sends_once_and_reports_the_outcome_unknown(self) -> None:
        self.service.script(UNAVAILABLE, ok(STATUS))
        client = CoordinatorClient(self.service.base_url, max_mutation_retries=0)

        with self.assertRaises(CoordinatorClientError) as raised:
            client.start("one-call-token", KEY, START_REQUEST)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "service.unavailable")
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(self.service.observations()), 1)

    def test_a_4xx_refusal_is_never_resent_and_reports_the_outcome_known(self) -> None:
        self.service.script(KEY_REUSED, ok(STATUS))
        client = CoordinatorClient(self.service.base_url, max_mutation_retries=2)

        with self.assertRaises(CoordinatorClientError) as raised:
            client.start("one-call-token", KEY, START_REQUEST)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 409)
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(len(self.service.observations()), 1)

    def test_a_flow_the_deployment_does_not_serve_is_never_resent_and_reports_the_outcome_known(
        self,
    ) -> None:
        self.service.script(problem(404, "flow.not-served"), ok(STATUS))
        client = CoordinatorClient(self.service.base_url, max_mutation_retries=2)

        with self.assertRaises(CoordinatorClientError) as raised:
            client.start("one-call-token", KEY, START_REQUEST)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "flow.not-served")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertNotIn("canary", f"{raised.exception!r} {raised.exception}")
        self.assertEqual(len(self.service.observations()), 1)

    def test_a_run_of_a_flow_outside_the_caller_policy_reads_as_absent_on_every_run_action(
        self,
    ) -> None:
        for call, path in (
            (lambda c: c.status("token", RUN), f"/deployment/v1/runs/{RUN}"),
            (lambda c: c.inspect("token", RUN), f"/deployment/v1/runs/{RUN}/inspect"),
            (lambda c: c.reconcile("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/reconcile"),
            (lambda c: c.retry_same("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/retry-same"),
            (lambda c: c.cancel("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/cancel"),
        ):
            with self.subTest(path=path):
                self.service.script(problem(404, "run.not-visible"), ok(INSPECTION))
                with self.assertRaises(CoordinatorClientError) as raised:
                    call(CoordinatorClient(self.service.base_url, max_mutation_retries=2))
                self.assertEqual(raised.exception.kind, "problem")
                self.assertEqual(raised.exception.status, 404)
                self.assertEqual(raised.exception.code, "run.not-visible")
                self.assertIs(raised.exception.outcome_unknown, False)
                self.assertEqual([o["path"] for o in self.service.observations()], [path])

    def test_every_call_but_start_is_never_resent(self) -> None:
        for call, path in (
            (lambda c: c.status("token", RUN), f"/deployment/v1/runs/{RUN}"),
            (lambda c: c.inspect("token", RUN), f"/deployment/v1/runs/{RUN}/inspect"),
            (lambda c: c.reconcile("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/reconcile"),
            (lambda c: c.list("token", 20), LIST_PATH),
            (lambda c: c.retry_same("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/retry-same"),
            (lambda c: c.cancel("token", RUN, "reason"), f"/deployment/v1/runs/{RUN}/cancel"),
        ):
            with self.subTest(path=path):
                self.service.script(UNAVAILABLE, ok(INSPECTION))
                with self.assertRaises(CoordinatorClientError) as raised:
                    call(CoordinatorClient(self.service.base_url, max_mutation_retries=2))
                self.assertEqual(raised.exception.status, 503)
                self.assertIs(raised.exception.outcome_unknown, True)
                self.assertEqual([o["path"] for o in self.service.observations()], [path])

    def test_a_request_refused_before_any_exchange_reports_the_outcome_known(self) -> None:
        self.service.script()
        with self.assertRaises(CoordinatorClientError) as raised:
            CoordinatorClient(self.service.base_url).start("one-call-token", "two\nlines", START_REQUEST)
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(self.service.observations(), [])


if __name__ == "__main__":
    unittest.main()
