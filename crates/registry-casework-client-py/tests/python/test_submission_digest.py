from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import (  # noqa: E402
    CaseworkClient,
    CaseworkClientError,
    submission_digest,
)

FIXTURE = json.loads(
    (Path(__file__).parents[3]
     / "registry-casework-client/tests/fixtures/submission-digest.json").read_text()
)


def reordered(value):
    if isinstance(value, dict):
        return {key: reordered(member) for key, member in reversed(list(value.items()))}
    if isinstance(value, list):
        return [reordered(member) for member in value]
    return value


class SubmissionDigestTests(unittest.TestCase):
    def test_matches_rust_for_unicode_and_reordered_keys(self):
        producer = FIXTURE["producer"]
        namespace = FIXTURE["sourceNamespace"]
        request = FIXTURE["request"]
        expected = FIXTURE["expectedSubmissionDigest"]
        self.assertEqual(submission_digest(producer, namespace, request), expected)
        self.assertEqual(submission_digest(producer, namespace, reordered(request)), expected)
        self.assertNotEqual(submission_digest("another-producer", namespace, request), expected)
        self.assertNotEqual(submission_digest(producer, "another-namespace", request), expected)

    def test_composes_with_current_policy_admission_and_response_loss_recovery(self):
        self.assert_admission_recovery(False)

    def test_composes_with_pinned_policy_admission_and_response_loss_recovery(self):
        self.assert_admission_recovery(True)

    def assert_admission_recovery(self, pinned):
        request = {**FIXTURE["request"], "policy": FIXTURE["request"]["policy"] if pinned else {"id": FIXTURE["request"]["policy"]["id"]}}
        digest = submission_digest(FIXTURE["producer"], FIXTURE["sourceNamespace"], request)
        accepted = {
            "requestId": "00000000-0000-4000-8000-000000000001",
            "subject": request["subject"],
            "policy": FIXTURE["request"]["policy"],
            "submissionDigest": digest,
        }
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                seen.append((self.path, self.headers["idempotency-key"], body))
                self.send_response(201 if len(seen) == 1 else 200)
                self.send_header("content-type", "application/json")
                self.send_header(
                    "traceparent",
                    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                )
                self.end_headers()
                self.wfile.write(json.dumps(accepted).encode())

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        client = CaseworkClient(f"http://127.0.0.1:{server.server_port}/tenant/")

        def submit(expected):
            return client.create_or_recover_review_request(
                "synthetic-token", "requester", "retained-submission-key", request, expected,
            )

        self.assertEqual(submit(digest)["value"], accepted)
        self.assertEqual(submit(digest)["value"], accepted)
        with self.assertRaises(CaseworkClientError) as raised:
            submit("sha256:" + "c" * 64)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(len(seen), 3, "admission never silently retries")
        self.assertEqual(
            seen[0][:2], ("/tenant/v1/review-requests", "retained-submission-key"),
        )
        self.assertEqual(json.loads(seen[0][2]), request)
        self.assertEqual(seen[1], seen[0])

    def test_invalid_inputs_are_local_value_free_refusals(self):
        producer = FIXTURE["producer"]
        namespace = FIXTURE["sourceNamespace"]
        request = FIXTURE["request"]
        cyclic = {}
        cyclic["self"] = cyclic
        invalid_policy = {**request, "policy": {**request["policy"], "digest": "private-bad-digest"}}
        unsafe_context = {
            **request,
            "context": {"mode": "submitted", "snapshot": {"count": 9007199254740992}},
        }
        for caller, source, body in [
            ("", namespace, request),
            (producer, "", request),
            (producer, namespace, invalid_policy),
            (producer, namespace, {**request, "policy": {"id": request["policy"]["id"], "version": request["policy"]["version"]}}),
            (producer, namespace, {**request, "policy": {"id": request["policy"]["id"], "digest": request["policy"]["digest"]}}),
            (producer, namespace, {**request, "unknown": "private-value"}),
            (producer, namespace, unsafe_context),
            (producer, namespace, cyclic),
        ]:
            with self.subTest(caller=caller, source=source):
                with self.assertRaises(CaseworkClientError) as raised:
                    submission_digest(caller, source, body)
                error = raised.exception
                self.assertEqual(error.kind, "invalid-request")
                self.assertFalse(error.outcome_unknown)
                self.assertNotRegex(str(error), r"private|9007199254740992")


if __name__ == "__main__":
    unittest.main()
