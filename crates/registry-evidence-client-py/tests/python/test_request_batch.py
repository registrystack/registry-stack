"""Ordered multi-subject request batches through the compiled Python surface.

These tests keep signing out of Python. The live mixed available/unavailable
case needs a response signed for nonces generated only during `prepare_batch`,
so the Rust integration suite drives that case with a fresh in-memory key.
Here the stdlib stub proves the exact request, one-send guard, opaque response,
ordered unavailable statuses, and fail-closed malformed-member handling.
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "helpers"))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import fixtures  # noqa: E402
import registry_evidence_client as revc  # noqa: E402
from stub_server import StubRoute, StubServer  # noqa: E402

REQUEST_BATCH_MEDIA_TYPE = (
    "application/vnd.registrystack.evidence.request-batch+json"
)
REQUEST_BATCH_SCHEMA = "registry.evidence-request-batch/v1"
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def envelope(items: list[dict]) -> bytes:
    return json.dumps(
        {
            "schema": REQUEST_BATCH_SCHEMA,
            "type": "EvidenceRequestBatchResponse",
            "items": items,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class RequestBatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer({})
        self.addCleanup(self.server.close)
        self.client = revc.EvidenceClient(
            self.server.base_url, fixtures.VALID_JWKS, [], "test-token"
        )

    def test_prepare_refuses_unknown_top_level_and_item_fields(self):
        spec = fixtures.request_batch_spec()
        spec["unknown"] = True
        with self.assertRaises(revc.ConfigurationError) as raised:
            self.client.prepare_batch(spec)
        self.assertEqual(raised.exception.kind, "configuration")

        item_fields = {
            "audience": "urn:other:audience",
            "holderKeys": [],
            "holder_keys": [],
            "responseFormat": "signed-jws",
            "response_format": "signed-jws",
            "evidence_type": "urn:example:evidence-type:v2",
            "issued_by": "urn:example:other-issuer",
            "provided_by": "urn:example:other-provider",
            "configuration_revision": "sha256:" + "1" * 64,
            "expected_assurance_profile": "substantial",
            "expected_outputs": [],
            "maximum_assertion_lifetime_seconds": 1,
            "clock_skew_seconds": 0,
            "arbitrary_unknown": True,
        }
        for field, value in item_fields.items():
            with self.subTest(field=field):
                spec = fixtures.request_batch_spec()
                spec["items"][0][field] = value
                with self.assertRaises(revc.ConfigurationError) as raised:
                    self.client.prepare_batch(spec)
                self.assertEqual(raised.exception.kind, "configuration")

        self.assertEqual(self.server.requests, [])

    def test_exact_wire_ordered_statuses_and_one_send_guard(self):
        self.server.routes["POST /v1/evidence/batch"] = StubRoute(
            status=200,
            headers={
                "Content-Type": REQUEST_BATCH_MEDIA_TYPE,
                "traceparent": TRACEPARENT,
            },
            body=envelope(
                [
                    {"result": "evidence_not_available"},
                    {"result": "evidence_not_available"},
                ]
            ),
        )
        prepared = self.client.prepare_batch(fixtures.request_batch_spec())
        self.assertIsInstance(prepared, revc.PreparedEvidenceRequestBatch)
        self.assertEqual(prepared.count, 2)
        self.assertEqual(len(prepared.request_nonces), 2)
        self.assertEqual(len(set(prepared.request_nonces)), 2)
        self.assertEqual(len(prepared.policy_documents), 2)
        self.assertEqual(
            prepared.subject_expectations,
            ["accept_first_use", "accept_first_use"],
        )

        raw = self.client.send_batch(prepared)
        self.assertIsInstance(raw, revc.RawEvidenceRequestBatchResponse)
        self.assertEqual(raw.trace_id, TRACE_ID)
        self.assertEqual(
            json.loads(raw.body),
            json.loads(self.server.routes["POST /v1/evidence/batch"].body),
        )

        self.assertEqual(len(self.server.requests), 1)
        request = self.server.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/v1/evidence/batch")
        self.assertEqual(request.headers["accept"], REQUEST_BATCH_MEDIA_TYPE)
        self.assertEqual(request.headers["content-type"], "application/json")
        self.assertEqual(
            json.loads(request.body),
            {
                "requirement": "urn:example:requirement:v1",
                "purpose": "example-purpose",
                "items": [
                    {
                        "requestNonce": prepared.request_nonces[0],
                        "subjects": [
                            {
                                "role": "subject",
                                "selector": {
                                    "profile": "national-id",
                                    "values": {
                                        "record_reference": "synthetic-001"
                                    },
                                },
                            }
                        ],
                    },
                    {
                        "requestNonce": prepared.request_nonces[1],
                        "subjects": [
                            {
                                "role": "subject",
                                "selector": {
                                    "profile": "national-id",
                                    "values": {
                                        "record_reference": "synthetic-002"
                                    },
                                },
                            }
                        ],
                    },
                ],
            },
        )

        verified = self.client.verify_batch(prepared, raw)
        self.assertIsInstance(verified, revc.VerifiedEvidenceRequestBatch)
        self.assertEqual(verified.trace_id, TRACE_ID)
        self.assertEqual(
            verified.items,
            [
                {"status": "not_available"},
                {"status": "not_available"},
            ],
        )
        retained = self.client.verify_batch_as_of(prepared, raw, 0.0)
        self.assertEqual(retained.items, verified.items)
        self.assertEqual(retained.trace_id, TRACE_ID)

        with self.assertRaises(revc.ConfigurationError) as raised:
            self.client.send_batch(prepared)
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertEqual(len(self.server.requests), 1)

    def test_an_invalid_member_refuses_the_whole_batch(self):
        self.server.routes["POST /v1/evidence/batch"] = StubRoute(
            status=200,
            headers={"Content-Type": REQUEST_BATCH_MEDIA_TYPE},
            body=envelope(
                [
                    {"result": "evidence_not_available"},
                    {"result": "not-a-batch-result"},
                ]
            ),
        )
        prepared = self.client.prepare_batch(fixtures.request_batch_spec())
        raw = self.client.send_batch(prepared)

        with self.assertRaises(revc.ProtocolError) as raised:
            self.client.verify_batch(prepared, raw)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.status, 200)


if __name__ == "__main__":
    unittest.main()
