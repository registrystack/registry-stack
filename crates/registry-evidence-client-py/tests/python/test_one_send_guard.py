"""A prepared request allows exactly one `send()`.

`PreparedEvidenceRequest.claim_single_send()` (see
`crates/registry-evidence-client/src/prepare.rs`) spends its claim before any
I/O, so a second `send()` on the same prepared object must raise
`ConfigurationError` without a second request ever reaching the deployment:
resending the same nonce would earn a second source access and a second audit
entry there.
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


class OneSendGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer({})
        self.addCleanup(self.server.close)
        self.server.routes["POST /v1/evidence"] = StubRoute(
            status=200,
            headers={"Content-Type": EVIDENCE_JWS_MEDIA_TYPE},
            # `send()` never parses or verifies this body (only `verify()` and
            # `verify_as_of()` do), so an obviously-fake JWS is enough here.
            body=b'{"payload": "not-a-real-jws"}',
        )

    def test_a_second_send_is_refused_without_reaching_the_network(self):
        client = revc.EvidenceClient(
            self.server.base_url, fixtures.VALID_JWKS, [], "test-token"
        )
        prepared = client.prepare(fixtures.request_spec())

        client.send(prepared)
        self.assertEqual(len(self.server.requests), 1)

        with self.assertRaises(revc.ConfigurationError) as raised:
            client.send(prepared)
        self.assertEqual(raised.exception.kind, "configuration")

        # The guard is claimed before any I/O, so the refused second attempt
        # never reaches the stub at all.
        self.assertEqual(len(self.server.requests), 1)


if __name__ == "__main__":
    unittest.main()
