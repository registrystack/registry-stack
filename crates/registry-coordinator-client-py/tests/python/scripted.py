"""A loopback Coordinator that answers each request with the next scripted answer."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

RUN = "7e367d42-b001-4d44-b94c-9447bfa182aa"
OTHER_RUN = "00000000-0000-4000-8000-000000000001"
KEY = "nursing-notice-2026-10-10-0001"
START_REQUEST = {"workflow": "nursing-notice", "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "input": {"requestId": "one", "values": [None, True, 23]}}

STATUS = {
    "runId": RUN,
    "workflow": "nursing-notice",
    "workflowRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000",

    "bindingDigest": "sha256:binding",
    "step": "notify",
    "state": "pending",
    "outcome": None,
    "output": None,
    "failureCode": None,
    "failurePath": None,
    "admittedAt": "2026-10-10T12:00:00Z",
    "deadlineAt": "2026-10-10T12:05:00Z",
    "nextDueAt": None,
    "uncertain": False,
    "restoreReviewRequired": False,
    "cancelRequested": False,
    "authoredCancelRequested": False,
}
INSPECTION = {
    "run": STATUS,
    "effects": [],
    "waits": [],
    "steps": [
        {
            "step": "notify",
            "state": "unknown",
            "generation": 1,
            "attempt": 1,
            "nextDueAt": None,
            "leaseExpiresAt": None,
            "commandPrepared": True,
            "uncertain": True,
            "receiptExpired": False,
            "failureCode": "response-lost",
            "failurePath": None,
        }
    ],
    "recovery": {
        "retryAllowed": True,
        "reason": None,
        "operation": {
            "id": "submit-message",
            "version": 1,
            "product": "messaging",
            "effect": "mutation",
            "keyRequirement": "required",
            "requiresPreparation": False,
            "recovery": "same-command-and-receipt",
            "readReceipt": True,
        },
    },
}

RETRY_SCHEDULED = {"runId": RUN, "status": "retry-scheduled"}
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
PROBLEM_TYPE_BASE = "https://id.registrystack.org/problems/registry-coordinator/"

Answer = tuple[int, str, "object"]


def ok(document: object) -> Answer:
    return (200, "application/json", document)


def problem_document(status: int, code: str) -> dict[str, object]:
    """A refusal as the runtime answers it, whose trace matches the answer's traceparent."""
    return {
        "type": PROBLEM_TYPE_BASE + code.replace(".", "/"),
        "title": "server-title-canary",
        "status": status,
        "detail": "server-prose-canary",
        "code": code,
        "traceId": TRACE_ID,
    }


def problem(status: int, code: str) -> Answer:
    return (status, "application/problem+json", problem_document(status, code))


class _Handler(BaseHTTPRequestHandler):
    answers: list[Answer] = []
    observations: list[dict[str, str]] = []

    def _serve(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        self.observations.append({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "content_type": self.headers.get("content-type", ""),
            "body": self.rfile.read(length).decode("utf-8"),
        })
        status, content_type, document = (
            self.answers.pop(0) if self.answers else (418, "application/json", {})
        )
        payload = (
            document.encode("utf-8")
            if isinstance(document, str)
            else json.dumps(document).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("location", "/must-not-follow")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _serve  # noqa: N815
    do_POST = _serve  # noqa: N815

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class Scripted:
    """One loopback server under a `/deployment/` prefix, scripted per test."""

    def __init__(self) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}/deployment/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    @staticmethod
    def script(*answers: Answer) -> None:
        _Handler.answers[:] = list(answers)
        _Handler.observations.clear()

    @staticmethod
    def observations() -> list[dict[str, str]]:
        return _Handler.observations
