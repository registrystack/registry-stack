"""Holder keys as a Python caller supplies them, and the batch envelope a
request presenting several of them can be answered with.

Neither needs a server: `prepare` performs no I/O, and
`SdJwtVcBatchResponse.parse` reads bytes a caller already holds. This is the
Python analog of `registry-evidence-client-node`'s
`__test__/holder-keys.test.js`.
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

# Two genuine, on-curve P-256 public points, so an accepted key here is one the
# wrapped client's own acceptability check also accepts.
HOLDER_KEYS = [
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        "alg": "ES256",
        "kid": "holder-key-0",
    },
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
        "y": "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
        "alg": "ES256",
        "kid": "holder-key-1",
    },
]

# Every private JWK member, across key types: a caller that pasted a whole key
# pair rather than its public half is refused on any of them, not just on `d`.
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k", "oth")

# The envelope wire shape, stated here rather than reached for: the wrapped
# crate declares `schema` and `type` privately.
SD_JWT_VC_BATCH_SCHEMA_V1 = "registry.sd-jwt-vc-batch-envelope/v1"
SD_JWT_VC_BATCH_ENVELOPE_TYPE = "SdJwtVcBatchEnvelope"


def client() -> revc.EvidenceClient:
    return revc.EvidenceClient(
        "https://evidence.example.org", fixtures.VALID_JWKS, [], "holder-keys-token"
    )


def envelope(credentials: list) -> bytes:
    return json.dumps(
        {
            "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
            "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
            "credentials": credentials,
        }
    ).encode("utf-8")


class HolderKeysTest(unittest.TestCase):
    def test_holder_keys_never_reach_the_closed_verification_policy(self):
        spec = fixtures.request_spec()
        spec["holder_keys"] = HOLDER_KEYS
        prepared = client().prepare(spec)
        policy = json.dumps(prepared.policy_document)
        for key in HOLDER_KEYS:
            self.assertNotIn(key["x"], policy)
            self.assertNotIn(key["kid"], policy)

    def test_presenting_no_holder_key_is_the_request_this_package_always_sent(self):
        spec = fixtures.request_spec()
        self.assertNotIn("holder_keys", spec)
        self.assertIsNotNone(client().prepare(spec))
        self.assertIsNotNone(client().prepare({**spec, "holder_keys": []}))
        self.assertIsNotNone(client().prepare({**spec, "holder_keys": None}))

    def test_a_holder_key_carrying_a_private_member_is_refused_without_echo(self):
        # The refusal has to say "private key material" specifically: an
        # "unknown member" refusal reads as a typo, and the caller would not
        # learn it had just handed its private key to an outbound request.
        private_canary = "secret-private-scalar-value"
        for member in PRIVATE_JWK_MEMBERS:
            with self.subTest(member=member):
                key = {**HOLDER_KEYS[0], member: private_canary}
                spec = {**fixtures.request_spec(), "holder_keys": [key]}
                with self.assertRaises(revc.ConfigurationError) as raised:
                    client().prepare(spec)
                message = str(raised.exception)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIn("private key material", message)
                self.assertIn(f"`{member}`", message)
                self.assertNotIn(private_canary, message)
                self.assertNotIn(private_canary, repr(raised.exception))

    def test_a_holder_key_outside_the_public_jwk_shape_is_refused_without_echo(self):
        canary = "secret-canary-value"
        for key in (
            {**HOLDER_KEYS[0], "use": canary},
            {"kty": canary},
            canary,
            None,
        ):
            with self.subTest(key=key):
                spec = {**fixtures.request_spec(), "holder_keys": [key]}
                with self.assertRaises(revc.ConfigurationError) as raised:
                    client().prepare(spec)
                self.assertNotIn(canary, str(raised.exception))
                self.assertNotIn(canary, repr(raised.exception))

    def test_a_holder_key_collection_that_is_not_a_sequence_is_refused(self):
        spec = {**fixtures.request_spec(), "holder_keys": HOLDER_KEYS[0]}
        with self.assertRaises(revc.ConfigurationError) as raised:
            client().prepare(spec)
        self.assertEqual(raised.exception.kind, "configuration")

    def test_a_batch_envelope_answers_holder_key_i_with_credential_i(self):
        parsed = revc.SdJwtVcBatchResponse.parse(
            envelope(["credential-for-key-0", "credential-for-key-1"])
        )
        self.assertEqual(parsed.count, 2)
        self.assertEqual(
            list(parsed.credentials), ["credential-for-key-0", "credential-for-key-1"]
        )
        self.assertEqual(parsed.credential_for_holder_key(0), "credential-for-key-0")
        self.assertEqual(parsed.credential_for_holder_key(1), "credential-for-key-1")
        self.assertIsNone(parsed.credential_for_holder_key(2))

    def test_a_body_that_is_not_this_envelope_is_refused_as_a_protocol_failure(self):
        bodies = [
            b"not json",
            json.dumps(
                {
                    "schema": "something-else",
                    "type": SD_JWT_VC_BATCH_ENVELOPE_TYPE,
                    "credentials": ["a"],
                }
            ).encode("utf-8"),
            envelope([]),
            envelope([""]),
        ]
        for body in bodies:
            with self.subTest(body=body[:32]):
                with self.assertRaises(revc.ProtocolError) as raised:
                    revc.SdJwtVcBatchResponse.parse(body)
                self.assertEqual(raised.exception.kind, "protocol")
                self.assertEqual(raised.exception.status, 200)


if __name__ == "__main__":
    unittest.main()
