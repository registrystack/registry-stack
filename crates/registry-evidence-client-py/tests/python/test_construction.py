"""Construction-time refusals.

Every case here is caught inside `EvidenceClientConfig::validate` (see
`crates/registry-evidence-client/src/config.rs`), before any HTTP client is
even built, let alone any request sent.
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


class ConstructionTest(unittest.TestCase):
    def test_a_non_https_non_loopback_base_url_is_refused(self):
        with self.assertRaises(revc.ConfigurationError) as raised:
            revc.EvidenceClient("http://example.org", fixtures.VALID_JWKS, [], "test-token")
        error = raised.exception
        self.assertEqual(error.kind, "configuration")
        # A caller branches on `kind`, never by parsing `str(error)`: the
        # message is never JSON-shaped.
        self.assertFalse(str(error).strip().startswith("{"))

    def test_an_empty_key_set_is_refused(self):
        with self.assertRaises(revc.ConfigurationError) as raised:
            revc.EvidenceClient("https://example.org", {"keys": []}, [], "test-token")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_a_malformed_revoked_key_identifier_is_refused(self):
        with self.assertRaises(revc.ConfigurationError) as raised:
            revc.EvidenceClient(
                "https://example.org",
                fixtures.VALID_JWKS,
                ["not-a-thumbprint"],
                "test-token",
            )
        self.assertEqual(raised.exception.kind, "configuration")

    def test_a_base_url_with_an_empty_path_segment_is_refused(self):
        with self.assertRaises(revc.ConfigurationError) as raised:
            revc.EvidenceClient(
                "https://example.org/a//b", fixtures.VALID_JWKS, [], "test-token"
            )
        self.assertEqual(raised.exception.kind, "configuration")

    def test_a_cyclic_mapping_is_refused_as_a_configuration_error(self):
        # Refused earlier than the cases above, in the Python-to-JSON bridge
        # (`src/convert.rs`) rather than in `validate`: a mapping that holds
        # itself has no depth to convert, so the bridge's depth bound ends the
        # descent and the interpreter stays alive to raise.
        cyclic = {}
        cyclic["self"] = cyclic
        with self.assertRaises(revc.ConfigurationError) as raised:
            revc.EvidenceClient("https://example.org", cyclic, [], "test-token")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_a_loopback_http_base_url_is_accepted(self):
        # Not a refusal case: confirms the three refusals above are testing
        # the specific rules, not "any base URL fails". Port 1 is never
        # connected to here; construction never performs I/O.
        client = revc.EvidenceClient(
            "http://127.0.0.1:1", fixtures.VALID_JWKS, [], "test-token"
        )
        self.assertIsInstance(client, revc.EvidenceClient)

    def test_every_exception_carries_every_stable_attribute(self):
        with self.assertRaises(revc.EvidenceClientError) as raised:
            revc.EvidenceClient("http://example.org", fixtures.VALID_JWKS, [], "test-token")
        for attribute in (
            "kind",
            "status",
            "code",
            "trace_id",
            "retry_after_seconds",
            "transport_kind",
            "token_kind",
        ):
            self.assertTrue(hasattr(raised.exception, attribute), attribute)


if __name__ == "__main__":
    unittest.main()
