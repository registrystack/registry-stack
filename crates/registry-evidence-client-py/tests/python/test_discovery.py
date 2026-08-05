"""`discover()` and `fetch_jwks()` against a stub server.

`discover()` requires a credential (`Authorization: Bearer <token>`);
`fetch_jwks()` never sends one, since a key set fetched from the same origin
as the response it would verify establishes nothing (see `client.rs`'s own
`Credential::None` for that endpoint). Both endpoints return a plain Python
dict built from the deployment's JSON, not a dataclass: this file checks the
camelCase shape survives untouched.
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

JSON_MEDIA_TYPE = "application/json"
JWKS_MEDIA_TYPE = "application/jwk-set+json"

DEFINITIONS_DOCUMENT = {
    "schema": "registry.evidence-definitions/v1",
    "assuranceProfile": "local",
    "configurationRevision": "test-revision-1",
    "issuedBy": "https://issuer.example.test",
    "providedBy": "https://provider.example.test",
    "definitions": [],
}


class DiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer({})
        self.addCleanup(self.server.close)

    def _client(self):
        return revc.EvidenceClient(
            self.server.base_url, fixtures.VALID_JWKS, "test-token"
        )

    def test_discover_returns_the_definitions_document_as_a_dict(self):
        self.server.routes["GET /v1/evidence-definitions"] = StubRoute(
            status=200,
            headers={"Content-Type": JSON_MEDIA_TYPE},
            body=json.dumps(DEFINITIONS_DOCUMENT).encode("utf-8"),
        )
        document = self._client().discover()
        self.assertEqual(document, DEFINITIONS_DOCUMENT)

    def test_discover_sends_a_bearer_credential(self):
        self.server.routes["GET /v1/evidence-definitions"] = StubRoute(
            status=200,
            headers={"Content-Type": JSON_MEDIA_TYPE},
            body=json.dumps(DEFINITIONS_DOCUMENT).encode("utf-8"),
        )
        self._client().discover()
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(
            self.server.requests[0].headers.get("authorization"),
            "Bearer test-token",
        )

    def test_fetch_jwks_returns_the_committed_fixture_as_a_dict(self):
        fixture_path = (
            pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "jwks.json"
        )
        jwks_bytes = fixture_path.read_bytes()
        self.server.routes["GET /.well-known/evidence/jwks.json"] = StubRoute(
            status=200,
            headers={"Content-Type": JWKS_MEDIA_TYPE},
            body=jwks_bytes,
        )
        document = self._client().fetch_jwks()
        self.assertEqual(document, json.loads(jwks_bytes))

    def test_fetch_jwks_sends_no_credential(self):
        self.server.routes["GET /.well-known/evidence/jwks.json"] = StubRoute(
            status=200,
            headers={"Content-Type": JWKS_MEDIA_TYPE},
            body=b'{"keys": []}',
        )
        self._client().fetch_jwks()
        self.assertEqual(len(self.server.requests), 1)
        self.assertNotIn("authorization", self.server.requests[0].headers)


if __name__ == "__main__":
    unittest.main()
