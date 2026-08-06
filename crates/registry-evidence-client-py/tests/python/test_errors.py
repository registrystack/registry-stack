"""Error mapping from the deployment's answer onto the client's own stable
exception kinds.

None of these responses are signed, and none need to be: `send()` only
validates status, content type, and reads bounded bytes (see
`expect_success` in `crates/registry-evidence-client/src/client.rs`); only
`verify()`/`verify_as_of()` ever parse or verify the JWS, and nothing in this
file calls either. Every status/code combination below mirrors
`crates/registry-evidence-client/src/problem.rs`'s own mapping table exactly.
"""

from __future__ import annotations

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

PROBLEM_MEDIA_TYPE = "application/problem+json"
EVIDENCE_JWS_MEDIA_TYPE = "application/jose+json"
OPERATION = "01JQ0QZ8YHZ0000000000000AB"


class ErrorMappingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer({})
        self.addCleanup(self.server.close)

    def _client(self, **kwargs):
        return revc.EvidenceClient(
            self.server.base_url, fixtures.VALID_JWKS, [], "test-token", **kwargs
        )

    def _send(self, client):
        prepared = client.prepare(fixtures.request_spec())
        return client.send(prepared)

    def test_401_maps_to_denied(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=401,
            headers={"Content-Type": PROBLEM_MEDIA_TYPE},
            body=fixtures.problem_body(401, "authentication_failed"),
        )
        with self.assertRaises(revc.DeniedError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.kind, "denied")
        self.assertEqual(error.status, 401)
        self.assertEqual(error.code, "authentication_failed")
        self.assertIsNone(error.retry_after_seconds)
        self.assertEqual(error.operation, OPERATION)

    def test_403_maps_to_denied(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=403,
            headers={"Content-Type": PROBLEM_MEDIA_TYPE},
            body=fixtures.problem_body(403, "not_authorized"),
        )
        with self.assertRaises(revc.DeniedError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.status, 403)
        self.assertEqual(error.code, "not_authorized")

    def test_429_maps_to_denied_with_retry_after(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=429,
            headers={"Content-Type": PROBLEM_MEDIA_TYPE, "Retry-After": "30"},
            body=fixtures.problem_body(429, "rate_limited"),
        )
        with self.assertRaises(revc.DeniedError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.status, 429)
        self.assertEqual(error.retry_after_seconds, 30)

    def test_422_with_the_not_available_code_maps_to_not_available(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=422,
            headers={"Content-Type": PROBLEM_MEDIA_TYPE},
            body=fixtures.problem_body(422, "evidence_not_available"),
        )
        with self.assertRaises(revc.NotAvailableError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.kind, "not_available")
        self.assertEqual(error.operation, OPERATION)

    def test_400_with_an_ordinary_code_maps_to_protocol(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=400,
            headers={"Content-Type": PROBLEM_MEDIA_TYPE},
            body=fixtures.problem_body(400, "malformed_request"),
        )
        with self.assertRaises(revc.ProtocolError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.kind, "protocol")
        self.assertEqual(error.status, 400)
        self.assertEqual(error.code, "malformed_request")

    def test_a_success_with_the_wrong_media_type_maps_to_protocol(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"not a JWS",
        )
        with self.assertRaises(revc.ProtocolError) as raised:
            self._send(self._client())
        error = raised.exception
        self.assertEqual(error.status, 200)
        self.assertIsNone(error.code)

    def test_an_oversized_response_maps_to_transport(self):
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=200,
            headers={"Content-Type": EVIDENCE_JWS_MEDIA_TYPE},
            body=b"x" * 64,
        )
        with self.assertRaises(revc.TransportError) as raised:
            self._send(self._client(max_response_bytes=16))
        error = raised.exception
        self.assertEqual(error.kind, "transport")
        self.assertEqual(error.transport_kind, "response_too_large")


if __name__ == "__main__":
    unittest.main()
