"""Offline retained-byte verification through the public Python extension."""

from __future__ import annotations

import datetime
import json
import pathlib
import sys
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "helpers"))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import registry_evidence_client as revc  # noqa: E402

_FIXTURES = _TESTS_DIR.parent / "fixtures"
_AS_OF = datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc).timestamp()


def _context() -> bytes:
    return json.dumps(
        {
            "schema": "registry.evidence-client.retained-verification/v1",
            "responseFormat": "signed-jws",
            "trustedJwks": json.loads((_FIXTURES / "jwks.json").read_bytes()),
            "verificationPolicy": json.loads((_FIXTURES / "policy.json").read_bytes()),
            "subjectExpectation": {"mode": "pinned"},
        }
    ).encode()


class RetainedTest(unittest.TestCase):
    def test_recorded_decision_verifies_and_current_decision_expires(self):
        response = (_FIXTURES / "response.jws.json").read_bytes()
        verified = revc.verify_retained_as_of(_context(), response, _AS_OF)
        self.assertEqual(verified.evidence["requestNonce"], "A" * 43)
        with self.assertRaises(revc.VerificationError):
            revc.verify_retained(_context(), response)

    def test_context_and_exact_response_are_required(self):
        response = (_FIXTURES / "response.jws.json").read_bytes()
        changed = json.loads(_context())
        changed["schema"] = "registry.example/unknown"
        with self.assertRaises(revc.ConfigurationError):
            revc.verify_retained_as_of(json.dumps(changed).encode(), response, _AS_OF)
        with self.assertRaises(revc.VerificationError):
            revc.verify_retained_as_of(_context(), b"changed", _AS_OF)


if __name__ == "__main__":
    unittest.main()
