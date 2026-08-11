"""`RawEvidenceResponse` exposes the same two readings as the Rust SDK.

`registry_evidence_client` is a thin binding over
`registry-evidence-client`, so its surface follows the core's: the core's
`RawEvidenceResponse` offers `body()` and `trace_id()` so a relying party can
retain the exact bytes it verified and correlate a request with the
deployment's audit trail. `registry-evidence-client-node` exposes both as
getters; Python exposes both as read-only attributes, the same shape
`VerifiedEvidence` already uses here.

Reading either one still judges nothing: `verify()` is the only thing that
decides whether those bytes are trustworthy.
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

EVIDENCE_JWS_MEDIA_TYPE = "application/jose+json"
# The correlation header carries one exact lower-case W3C v0 trace context.
CORRELATION_HEADER = "traceparent"
TRACE_ID = fixtures.TRACE_ID
TRACEPARENT = fixtures.TRACEPARENT
# `send()` parses nothing, so the shape of these bytes does not matter here;
# what matters is that exactly they come back out.
SIGNED_BODY = b'{"payload": "not-a-real-jws", "signature": "not-a-real-signature"}'


class RawResponseTest(unittest.TestCase):
    def _response(self, headers: dict[str, str]) -> revc.RawEvidenceResponse:
        server = StubServer({})
        self.addCleanup(server.close)
        server.routes["POST /v1/evidence"] = StubRoute(
            status=200,
            headers={"Content-Type": EVIDENCE_JWS_MEDIA_TYPE, **headers},
            body=SIGNED_BODY,
        )
        client = revc.EvidenceClient(server.base_url, fixtures.VALID_JWKS, [], "test-token")
        return client.send(client.prepare(fixtures.request_spec()))

    def test_the_body_is_exactly_the_bytes_the_deployment_served(self):
        response = self._response({})
        self.assertIsInstance(response.body, bytes)
        self.assertEqual(response.body, SIGNED_BODY)

    def test_the_trace_id_is_extracted_from_the_response_traceparent(self):
        response = self._response({CORRELATION_HEADER: TRACEPARENT})
        self.assertEqual(response.trace_id, TRACE_ID)

    def test_a_response_without_a_traceparent_is_protocol(self):
        server = StubServer({})
        self.addCleanup(server.close)
        server.routes["POST /v1/evidence"] = StubRoute(
            status=200,
            headers={"Content-Type": EVIDENCE_JWS_MEDIA_TYPE},
            body=SIGNED_BODY,
            include_traceparent=False,
        )
        client = revc.EvidenceClient(server.base_url, fixtures.VALID_JWKS, [], "test-token")
        with self.assertRaises(revc.ProtocolError):
            client.send(client.prepare(fixtures.request_spec()))

    def test_neither_reading_can_be_reassigned(self):
        # Both are readings of what arrived over the wire. Letting Python
        # overwrite either one would let a later `verify()` failure be
        # reported against bytes or an trace_id the deployment never sent.
        response = self._response({CORRELATION_HEADER: TRACEPARENT})
        for attribute, value in (("body", b"tampered"), ("trace_id", "tampered")):
            with self.subTest(attribute=attribute):
                with self.assertRaises(AttributeError):
                    setattr(response, attribute, value)


if __name__ == "__main__":
    unittest.main()
