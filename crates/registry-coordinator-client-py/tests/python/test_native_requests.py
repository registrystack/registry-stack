from __future__ import annotations

import json
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_coordinator_client import CoordinatorClient, CoordinatorClientError  # noqa: E402
from scripted import (  # noqa: E402
    INSPECTION,
    KEY,
    OTHER_RUN,
    RETRY_SCHEDULED,
    RUN,
    START_REQUEST,
    STATUS,
    Scripted,
    ok,
    problem,
    problem_document,
)


def rendered(error: Exception) -> str:
    return "\n".join((str(error), repr(error), repr(vars(error))))


class NativeRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = Scripted()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.service.close()

    def setUp(self) -> None:
        self.client = CoordinatorClient(self.service.base_url)
        self.service.script()

    def observed(self) -> list[dict[str, str]]:
        return self.service.observations()

    def test_start_posts_the_flow_and_input_under_the_key(self) -> None:
        self.service.script(ok(STATUS))

        outcome = self.client.start("one-call-token", KEY, START_REQUEST)

        self.assertEqual(outcome, {"kind": "complete", "value": STATUS})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], "/deployment/v1/runs")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")
        self.assertEqual(observed["idempotency_key"], KEY)
        self.assertEqual(observed["content_type"], "application/json")
        self.assertEqual(json.loads(observed["body"]), START_REQUEST)

    def test_workflow_discovers_one_bound_revision_without_starting(self) -> None:
        contract = {"workflow": "nursing-notice", "workflowRevision": START_REQUEST["workflowRevision"], "input": {"type": "object"}, "outcomes": {"sent": {"type": "object"}}, "reviewPolicy": None}
        self.service.script(ok(contract))
        self.assertEqual(self.client.workflow("contract-token", "nursing-notice"), {"kind": "complete", "value": contract})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], "/deployment/v1/workflows/nursing-notice")
        self.assertEqual(observed["idempotency_key"], "")

    def test_workflow_carries_the_exact_review_policy_and_refuses_a_different_revision(self) -> None:
        contract = {"workflow": "nursing-notice", "workflowRevision": START_REQUEST["workflowRevision"], "input": {"type": "object"}, "outcomes": {"sent": {"type": "object"}}, "reviewPolicy": {"id": "nursing-notice", "version": "pilot-1", "digest": START_REQUEST["workflowRevision"]}}
        self.service.script(ok(contract))
        self.assertEqual(self.client.workflow("contract-token", "nursing-notice"), {"kind": "complete", "value": contract})
        contract["reviewPolicy"]["digest"] = "sha256:" + "1" * 64
        self.service.script(ok(contract))
        with self.assertRaises(CoordinatorClientError) as refused:
            self.client.workflow("contract-token", "nursing-notice")
        self.assertEqual(refused.exception.kind, "protocol")

    def test_status_reads_the_run_without_a_key_or_body(self) -> None:
        self.service.script(ok(STATUS))

        outcome = self.client.status("status-token", RUN)

        self.assertEqual(outcome, {"kind": "complete", "value": STATUS})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}")
        self.assertEqual(observed["authorization"], "Bearer status-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(observed["body"], "")

    def test_every_run_response_rejects_an_unknown_effective_state_without_disclosing_it(self) -> None:
        run = {**STATUS, "state": "protected-state-canary"}
        calls = (
            (lambda: self.client.start("token", KEY, START_REQUEST), run),
            (lambda: self.client.status("token", RUN), run),
            (lambda: self.client.cancel("token", RUN, "caller-withdrew"), run),
            (lambda: self.client.inspect("token", RUN), {**INSPECTION, "run": run}),
            (lambda: self.client.reconcile("token", RUN, "response-lost"), {**INSPECTION, "run": run}),
            (lambda: self.client.list("token", 1), {"runs": [run]}),
        )
        for call, document in calls:
            self.service.script(ok(document))
            with self.assertRaises(CoordinatorClientError) as refused:
                call()
            error = refused.exception
            self.assertEqual(error.kind, "protocol")
            self.assertEqual(error.protocol_failure, "body")
            self.assertNotIn("protected-state-canary", rendered(error))
            self.assertEqual(len(self.observed()), 1)

    def test_a_run_and_step_status_carry_the_failure_path_a_refused_call_input_names(self) -> None:
        absent = object()
        for member, expected in (("/recordId", "/recordId"), (None, None), (absent, None)):
            with self.subTest(member="absent" if member is absent else member):
                run = {name: value for name, value in STATUS.items() if name != "failurePath"}
                step = {
                    name: value for name, value in INSPECTION["steps"][0].items()
                    if name != "failurePath"
                }
                if member is not absent:
                    run["failurePath"] = member
                    step["failurePath"] = member
                self.service.script(ok(run), ok({**INSPECTION, "run": run, "steps": [step]}))

                status = self.client.status("status-token", RUN)
                inspection = self.client.inspect("inspect-token", RUN)

                self.assertEqual(status["kind"], "complete")
                self.assertEqual(inspection["kind"], "complete")
                self.assertEqual(status["value"]["failurePath"], expected)
                self.assertEqual(inspection["value"]["run"]["failurePath"], expected)
                self.assertEqual(inspection["value"]["steps"][0]["failurePath"], expected)

    def test_inspect_reads_the_inspection(self) -> None:
        self.service.script(ok(INSPECTION))

        outcome = self.client.inspect("inspect-token", RUN)

        self.assertEqual(outcome, {"kind": "complete", "value": INSPECTION})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}/inspect")
        self.assertEqual(observed["authorization"], "Bearer inspect-token")
        self.assertEqual(observed["idempotency_key"], "")

    def test_an_inspection_without_an_operation_completes(self) -> None:
        bare = {**INSPECTION, "recovery": {"retryAllowed": False, "reason": "receipt-expired"}}
        self.service.script(ok(bare))
        outcome = self.client.inspect("token", RUN)
        self.assertEqual(outcome["value"]["recovery"]["reason"], "receipt-expired")
        self.assertNotIn("operation", outcome["value"]["recovery"])

    def test_reconcile_posts_the_reason_only(self) -> None:
        self.service.script(ok(INSPECTION))

        outcome = self.client.reconcile("reconcile-token", RUN, "operator-ticket-4821")

        self.assertEqual(outcome, {"kind": "complete", "value": INSPECTION})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}/reconcile")
        self.assertEqual(observed["authorization"], "Bearer reconcile-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(json.loads(observed["body"]), {"reason": "operator-ticket-4821"})

    def test_list_reads_the_latest_runs_under_the_limit(self) -> None:
        self.service.script(ok({"runs": [STATUS]}))

        outcome = self.client.list("list-token", 5)

        self.assertEqual(outcome, {"kind": "complete", "value": {"runs": [STATUS]}})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], "/deployment/v1/runs?limit=5")
        self.assertEqual(observed["authorization"], "Bearer list-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(observed["body"], "")

    def test_list_preserves_the_opaque_cursor_and_filters(self) -> None:
        attention_status = {**STATUS, "state": "attention"}
        self.service.script(ok({"runs": [attention_status], "nextCursor": "cursor-next"}))

        outcome = self.client.list("list-token", 1, "cursor-before", "attention", True)

        self.assertEqual(
            outcome,
            {"kind": "complete", "value": {"runs": [attention_status], "nextCursor": "cursor-next"}},
        )
        (observed,) = self.observed()
        self.assertEqual(
            observed["path"],
            "/deployment/v1/runs?limit=1&cursor=cursor-before&state=attention&attention=true",
        )
        for arguments in (
            ("token", 20, None, "waiting", None),
            ("token", 20, "line\nbreak", None, None),
            ("token", 20, None, None, 1),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.list(*arguments)
                self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertEqual(len(self.observed()), 1)


    def test_list_refuses_received_runs_outside_intersected_state_and_attention_filters(self) -> None:
        for state_filter, attention, returned in (
            (None, True, 'attention'), (None, True, 'failed'), (None, False, 'running'),
            ('failed', True, 'failed'), ('attention', True, 'attention'), ('running', False, 'running'),
        ):
            run = {**STATUS, 'state': returned}
            self.service.script(ok({'runs': [run]}))
            self.assertEqual(self.client.list('filter-token-canary', 1, None, state_filter, attention),
                             {'kind': 'complete', 'value': {'runs': [run]}})
        for state_filter, attention, returned in (
            ('failed', None, 'finished'), (None, True, 'running'), (None, False, 'attention'),
            (None, False, 'failed'), ('attention', True, 'failed'), ('attention', False, 'attention'),
        ):
            self.service.script(ok({'runs': [{**STATUS, 'state': returned}]}))
            with self.subTest(state_filter=state_filter, attention=attention, returned=returned):
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.list('filter-token-canary', 1, None, state_filter, attention)
                self.assertEqual(raised.exception.kind, 'protocol')
                self.assertEqual(raised.exception.protocol_failure, 'body')
                self.assertNotIn('filter-token-canary', rendered(raised.exception))
                self.assertEqual(len(self.observed()), 1)
        self.service.script(ok({'runs': []}))
        self.assertEqual(self.client.list('token', 1, None, 'attention', False), {'kind': 'complete', 'value': {'runs': []}})

    def test_retry_same_posts_the_reason_only_and_no_key(self) -> None:
        self.service.script(ok(RETRY_SCHEDULED))

        outcome = self.client.retry_same("retry-token", RUN, "operator-ticket-4821")

        self.assertEqual(outcome, {"kind": "complete", "value": RETRY_SCHEDULED})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}/retry-same")
        self.assertEqual(observed["authorization"], "Bearer retry-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(json.loads(observed["body"]), {"reason": "operator-ticket-4821"})

    def test_cancel_posts_the_reason_only_and_no_key(self) -> None:
        cancelled = {**STATUS, "cancelRequested": True}
        self.service.script(ok(cancelled))

        outcome = self.client.cancel("cancel-token", RUN, "caller withdrew the request")

        self.assertEqual(outcome, {"kind": "complete", "value": cancelled})
        (observed,) = self.observed()
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}/cancel")
        self.assertEqual(observed["authorization"], "Bearer cancel-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(json.loads(observed["body"]), {"reason": "caller withdrew the request"})

    def test_a_list_limit_outside_one_to_one_hundred_is_refused_before_io(self) -> None:
        for limit in (0, 101, -1, 2**32, True, 1.0, "5", None):
            with self.subTest(limit=limit):
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.list("token", limit)
                self.assertEqual(raised.exception.kind, "invalid-request")
                self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(self.observed(), [])
        self.service.script(ok({"runs": []}), ok({"runs": []}))
        self.assertEqual(self.client.list("token", 1), {"kind": "complete", "value": {"runs": []}})
        self.assertEqual(self.client.list("token", 100), {"kind": "complete", "value": {"runs": []}})

    def test_a_list_longer_than_the_limit_is_a_protocol_failure(self) -> None:
        self.service.script(ok({"runs": [STATUS, STATUS]}))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.list("token", 1)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.protocol_failure, "body")

    def test_a_refused_list_retry_or_cancellation_keeps_the_status_and_code(self) -> None:
        for call, answer in (
            (lambda: self.client.list("answered-token-canary", 20), problem(400, "request.invalid")),
            (lambda: self.client.retry_same("answered-token-canary", RUN, "reason"), problem(409, "retry.refused")),
            (lambda: self.client.cancel("answered-token-canary", RUN, "reason"), problem(409, "execution.held")),
        ):
            status, _, document = answer
            self.service.script(answer)
            with self.assertRaises(CoordinatorClientError) as raised:
                call()
            error = raised.exception
            self.assertEqual(error.kind, "problem")
            self.assertEqual(error.status, status)
            self.assertEqual(error.code, document["code"])
            self.assertIs(error.outcome_unknown, False)
            text = rendered(error)
            for canary in ("server-prose-canary", "server-title-canary", "answered-token-canary"):
                self.assertNotIn(canary, text)

    def test_a_retry_answer_outside_the_request_is_a_protocol_failure(self) -> None:
        for answer in (
            {"runId": OTHER_RUN, "status": "retry-scheduled"},
            {"runId": RUN, "status": "scheduled"},
            {"runId": RUN, "status": "retry-scheduled", "extra": 1},
        ):
            with self.subTest(answer=answer):
                self.service.script(ok(answer))
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.retry_same("token", RUN, "reason")
                self.assertEqual(raised.exception.kind, "protocol")
                self.assertEqual(raised.exception.protocol_failure, "body")
                self.assertIs(raised.exception.outcome_unknown, True)

    def test_a_problem_preserves_status_and_code_and_never_the_prose(self) -> None:
        self.service.script(problem(409, "idempotency.key-reused"))

        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.start("answered-token-canary", KEY, START_REQUEST)

        error = raised.exception
        self.assertEqual(error.kind, "problem")
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "idempotency.key-reused")
        self.assertIs(error.outcome_unknown, False)
        self.assertIsNone(error.protocol_failure)
        self.assertIsNone(error.transport_kind)
        text = rendered(error)
        for canary in ("server-prose-canary", "server-title-canary", "answered-token-canary", KEY):
            self.assertNotIn(canary, text)
        self.assertFalse(hasattr(error, "trace_id"))

    def test_a_problem_answered_as_plain_json_is_a_protocol_failure(self) -> None:
        self.service.script((404, "application/json", problem_document(404, "run.not-visible")))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.status("token", RUN)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.protocol_failure, "media-type")
        self.assertIsNone(raised.exception.code)

    def test_a_problem_outside_the_shape_is_a_protocol_failure(self) -> None:
        valid = problem_document(400, "request.invalid")
        without_code = {name: value for name, value in valid.items() if name != "code"}
        for answer in (
            {**valid, "code": "UPPER.invalid"},
            {**valid, "code": ""},
            {**valid, "code": "request-invalid"},
            {**valid, "suggestedAction": None},
            without_code,
            {"code": "request.invalid", "message": "m", "suggestedAction": None},
            {**valid, "status": 409},
            {**valid, "type": "https://id.registrystack.org/problems/registry-casework/request/invalid"},
            {**valid, "traceId": "0af7651916cd43dd8448eb211c80319c"},
        ):
            with self.subTest(answer=answer):
                self.service.script((400, "application/problem+json", answer))
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.status("token", RUN)
                self.assertEqual(raised.exception.kind, "protocol")
                self.assertEqual(raised.exception.protocol_failure, "problem")
                self.assertEqual(raised.exception.status, 400)

    def test_a_wrong_media_type_is_a_protocol_failure(self) -> None:
        self.service.script((200, "text/plain", STATUS))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.status("token", RUN)
        error = raised.exception
        self.assertEqual(error.kind, "protocol")
        self.assertEqual(error.protocol_failure, "media-type")
        self.assertEqual(error.status, 200)
        self.assertIs(error.outcome_unknown, True)

    def test_a_duplicate_json_member_is_a_protocol_failure(self) -> None:
        raw = json.dumps(STATUS)[:-1] + ', "step": "other"}'
        self.service.script((200, "application/json", raw))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.status("token", RUN)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.protocol_failure, "body")

    def test_an_answer_for_another_run_is_a_protocol_failure(self) -> None:
        for call, answer in (
            (lambda: self.client.status("token", OTHER_RUN), ok(STATUS)),
            (lambda: self.client.inspect("token", OTHER_RUN), ok(INSPECTION)),
            (lambda: self.client.reconcile("token", OTHER_RUN, "reason"), ok(INSPECTION)),
            (lambda: self.client.cancel("token", OTHER_RUN, "reason"), ok(STATUS)),
        ):
            self.service.script(answer)
            with self.assertRaises(CoordinatorClientError) as raised:
                call()
            self.assertEqual(raised.exception.kind, "protocol")
            self.assertEqual(raised.exception.protocol_failure, "body")

    def test_a_start_answer_for_another_flow_is_a_protocol_failure(self) -> None:
        self.service.script(ok({**STATUS, "workflow": "other-workflow"}))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.start("token", KEY, START_REQUEST)
        self.assertEqual(raised.exception.protocol_failure, "body")

    def test_a_redirect_is_not_followed(self) -> None:
        self.service.script((302, "application/json", {}), ok(STATUS))
        with self.assertRaises(CoordinatorClientError) as raised:
            self.client.status("token", RUN)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.protocol_failure, "status")
        self.assertEqual(raised.exception.status, 302)
        self.assertEqual(len(self.observed()), 1)

    def test_an_oversized_answer_is_a_transport_failure(self) -> None:
        self.service.script(ok(STATUS))
        with self.assertRaises(CoordinatorClientError) as raised:
            CoordinatorClient(self.service.base_url, max_response_bytes=16).status("token", RUN)
        self.assertEqual(raised.exception.kind, "transport")
        self.assertIsInstance(raised.exception.transport_kind, str)

    def test_uuid_spellings_share_the_canonical_run_routes(self) -> None:
        for run in (RUN.upper(), RUN.replace("-", ""), f"{{{RUN}}}", f"urn:uuid:{RUN}"):
            for method, suffix, response in (
                ("status", "", STATUS),
                ("inspect", "/inspect", INSPECTION),
                ("reconcile", "/reconcile", INSPECTION),
                ("retry_same", "/retry-same", RETRY_SCHEDULED),
                ("cancel", "/cancel", STATUS),
            ):
                with self.subTest(run=run, method=method):
                    self.service.script(ok(response))
                    args = ("reason",) if method in ("reconcile", "retry_same", "cancel") else ()
                    outcome = getattr(self.client, method)("token", run, *args)
                    self.assertEqual(outcome, {"kind": "complete", "value": response})
                    (observed,) = self.observed()
                    self.assertEqual(observed["path"], f"/deployment/v1/runs/{RUN}{suffix}")

    def test_invalid_run_ids_are_refused_before_io(self) -> None:
        for run in ("", "../ready", "not-a-uuid", RUN + "/inspect", f"urn:uuid:{RUN}/inspect"):
            with self.subTest(run=run):
                for call in (
                    lambda: self.client.status("token", run),
                    lambda: self.client.inspect("token", run),
                    lambda: self.client.reconcile("token", run, "reason"),
                    lambda: self.client.retry_same("token", run, "reason"),
                    lambda: self.client.cancel("token", run, "reason"),
                ):
                    with self.assertRaises(CoordinatorClientError) as raised:
                        call()
                    self.assertEqual(raised.exception.kind, "invalid-request")
                    self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(self.observed(), [])

    def test_invalid_key_flow_and_reason_are_refused_before_io(self) -> None:
        for key in ("", "café", "line\nbreak", "k" * 257):
            with self.subTest(key=key[:12]):
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.start("token", key, START_REQUEST)
                self.assertEqual(raised.exception.kind, "invalid-request")
        for workflow in ("", "has space", "a/b", "f" * 65):
            with self.subTest(workflow=workflow[:12]):
                with self.assertRaises(CoordinatorClientError) as raised:
                    self.client.start("token", KEY, {"workflow": workflow, "input": {}})
                self.assertEqual(raised.exception.kind, "invalid-request")
        for reason in ("", "line\nbreak", "r" * 257, "\u00e9" * 129):
            for call in (self.client.reconcile, self.client.retry_same, self.client.cancel):
                with self.subTest(reason=reason[:12], call=call.__name__):
                    with self.assertRaises(CoordinatorClientError) as raised:
                        call("token", RUN, reason)
                    self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertEqual(self.observed(), [])

    def test_unreachable_service_is_a_transport_failure(self) -> None:
        probe = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        host, port = probe.server_address
        probe.server_close()
        client = CoordinatorClient(f"http://{host}:{port}/", connect_timeout_seconds=1.0)
        with self.assertRaises(CoordinatorClientError) as raised:
            client.status("token", RUN)
        self.assertEqual(raised.exception.kind, "transport")
        self.assertIsInstance(raised.exception.transport_kind, str)
        self.assertIs(raised.exception.outcome_unknown, False)


if __name__ == "__main__":
    unittest.main()
