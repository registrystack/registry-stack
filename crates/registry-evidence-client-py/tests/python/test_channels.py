"""The assertion channel through the public Python extension.

A Python test cannot sign an Evidence response, so these cases verify the
committed golden responses (see `tests/golden_fixture.rs`) through the retained
verification entry point, which judges them against the same policy members a
`prepare` specification states: `acceptedChannels` and
`maximumCredentialAgeSeconds`. The `prepare` surface itself is covered by
`tests/happy_path.rs`.
"""

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

import fixtures  # noqa: E402
import registry_evidence_client as revc  # noqa: E402

_FIXTURES = _TESTS_DIR.parent / "fixtures"
_AS_OF = datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc).timestamp()
_DAY = 24 * 60 * 60


def _context(**policy_members) -> bytes:
    policy = json.loads((_FIXTURES / "policy.json").read_bytes())
    policy.update(policy_members)
    return json.dumps(
        {
            "schema": "registry.evidence-client.retained-verification/v1",
            "responseFormat": "signed-jws",
            "trustedJwks": json.loads((_FIXTURES / "jwks.json").read_bytes()),
            "verificationPolicy": policy,
            "subjectExpectation": {"mode": "pinned"},
        }
    ).encode()


class ChannelTest(unittest.TestCase):
    def test_a_source_assertion_states_its_channel_and_no_presented_credential(self):
        response = (_FIXTURES / "response.jws.json").read_bytes()
        verified = revc.verify_retained_as_of(_context(), response, _AS_OF)
        self.assertEqual(verified.evidence["channel"], "source")
        self.assertNotIn("presentedCredential", verified.evidence)

    def test_the_default_policy_refuses_a_holder_presented_assertion(self):
        response = (_FIXTURES / "response.holder-presented.jws.json").read_bytes()
        with self.assertRaises(revc.VerificationError):
            revc.verify_retained_as_of(_context(), response, _AS_OF)

    def test_a_policy_accepting_holder_presented_exposes_the_presented_credential(self):
        response = (_FIXTURES / "response.holder-presented.jws.json").read_bytes()
        verified = revc.verify_retained_as_of(
            _context(acceptedChannels=["source", "holder-presented"]),
            response,
            _AS_OF,
        )
        self.assertEqual(verified.evidence["channel"], "holder-presented")
        self.assertEqual(
            verified.evidence["presentedCredential"],
            {
                "trustEntry": "national-id",
                "issuer": "https://issuer.example",
                "type": "https://credentials.example/identity",
                "issuedAt": "2026-07-31T00:00:00Z",
                "subjectLink": "attribute-match",
            },
        )

    def test_the_maximum_credential_age_refuses_an_older_credential(self):
        response = (_FIXTURES / "response.holder-presented.jws.json").read_bytes()
        # The credential was issued one day before the observation.
        with self.assertRaises(revc.VerificationError):
            revc.verify_retained_as_of(
                _context(
                    acceptedChannels=["holder-presented"],
                    maximumCredentialAgeSeconds=_DAY - 1,
                ),
                response,
                _AS_OF,
            )
        verified = revc.verify_retained_as_of(
            _context(
                acceptedChannels=["holder-presented"],
                maximumCredentialAgeSeconds=_DAY,
            ),
            response,
            _AS_OF,
        )
        self.assertEqual(verified.evidence["channel"], "holder-presented")

    def test_prepare_refuses_a_channel_policy_outside_the_contract(self):
        client = revc.EvidenceClient(
            "https://evidence.example.org", fixtures.VALID_JWKS, [], "test-token"
        )
        for members in (
            {"accepted_channels": []},
            {"accepted_channels": ["source", "source"]},
            {"accepted_channels": ["wallet"]},
            {"maximum_credential_age_seconds": 0},
        ):
            with self.subTest(members=members):
                spec = {**fixtures.request_spec(), **members}
                with self.assertRaises(revc.EvidenceClientError):
                    client.prepare(spec)

    def test_prepare_accepts_the_channel_policy_members(self):
        client = revc.EvidenceClient(
            "https://evidence.example.org", fixtures.VALID_JWKS, [], "test-token"
        )
        spec = {
            **fixtures.request_spec(),
            "accepted_channels": ["source", "holder-presented"],
            "maximum_credential_age_seconds": 30 * _DAY,
        }
        policy = client.prepare(spec).policy_document
        self.assertEqual(policy["acceptedChannels"], ["source", "holder-presented"])
        self.assertEqual(policy["maximumCredentialAgeSeconds"], 30 * _DAY)
        default = client.prepare(fixtures.request_spec()).policy_document
        self.assertNotIn("acceptedChannels", default)


if __name__ == "__main__":
    unittest.main()
