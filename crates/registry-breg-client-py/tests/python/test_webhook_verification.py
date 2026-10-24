"""Verify Base Registry Engine hook deliveries through the shared Rust verifier.

The fixed vector is the one `registry-breg-client/tests/webhook.rs` and the
Node binding's `hook-verification.test.js` use, which in turn belongs to
`registry-platform-crypto` delivery signatures.
"""

from __future__ import annotations

import unittest
import json
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

import registry_breg_client as breg_client  # noqa: E402

BaseRegistryClientError = breg_client.BaseRegistryClientError
verify_hook_delivery = breg_client.verify_hook_delivery

KEY = b"webhook-delivery-signing-key-0123456789abcdef"
BODY = b'{"entity":"case","values":{"label":"value"}}'
SIGNATURE = "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM"
IDEMPOTENCY_KEY = "sha256:" + "a" * 64


def headers() -> dict[str, str]:
    return {
        "Ce-Specversion": "1.0",
        "CE-ID": "00000000-0000-4000-8000-000000000001",
        "ce-source": "urn:registrystack:registry:example:instance:primary",
        "ce-type": "case-created-v1",
        "ce-time": "2026-08-30T00:00:00Z",
        "ce-dataschema": "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
        "x-registry-event-generation": "1",
        "x-registry-delivery-attempt": "1",
        "x-registry-delivery-time": "2026-08-30T00:00:01Z",
        "idempotency-key": IDEMPOTENCY_KEY,
        "content-type": "application/json",
        "x-registry-signature": SIGNATURE,
    }


def verify(**overrides):
    arguments = {
        "method": "POST",
        "path": "/hooks/registry",
        "headers": headers(),
        "body": BODY,
        "key": KEY,
    }
    arguments.update(overrides)
    return verify_hook_delivery(**arguments)


class HookVerificationTests(unittest.TestCase):
    def test_shared_language_vectors_preserve_exact_rfc3339_fractions(self):
        fixture = Path(__file__).resolve().parents[3] / "registry-platform-crypto/tests/fixtures/delivery-signatures.json"
        for vector in json.loads(fixture.read_text()):
            exact = {**headers(), "x-registry-delivery-time": vector["deliveryTime"], "x-registry-signature": vector["signature"]}
            with self.subTest(timestamp=vector["deliveryTime"]):
                if vector["valid"]:
                    self.assertEqual(verify(headers=exact)["delivery_time"], vector["deliveryTime"])
                    self.assert_refused("signature-mismatch", headers={**exact, "x-registry-delivery-time": "2026-08-30T00:00:01.0000Z"})
                else:
                    self.assert_refused("invalid-delivery-time", headers=exact)

    def assert_refused(self, code: str, message: str | None = None, **overrides) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            verify(**overrides)
        error = raised.exception
        self.assertEqual(error.kind, "hook-verification")
        self.assertEqual(error.code, code)
        self.assertFalse(error.outcome_unknown)
        rendered = str(error)
        if message is not None:
            self.assertEqual(rendered, message)
        for secret in (SIGNATURE, KEY.decode(), BODY.decode(), "case-patched-v1"):
            self.assertNotIn(secret, rendered)

    def test_fixed_vector_verifies_and_returns_exact_delivery(self) -> None:
        verified = verify()
        self.assertEqual(
            verified,
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "source": "urn:registrystack:registry:example:instance:primary",
                "type": "case-created-v1",
                "time": "2026-08-30T00:00:00Z",
                "dataschema": "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
                "generation": "1",
                "attempt": "1",
                "delivery_time": "2026-08-30T00:00:01Z",
                "idempotency_key": IDEMPOTENCY_KEY,
                "body": BODY,
            },
        )
        self.assertIsInstance(verified["body"], bytes)

    def test_arguments_are_keyword_only(self) -> None:
        with self.assertRaises(TypeError):
            verify_hook_delivery("POST", "/hooks/registry", headers(), BODY, KEY)

    def test_refuses_a_tampered_signed_header(self) -> None:
        self.assert_refused(
            "signature-mismatch", headers={**headers(), "ce-type": "case-patched-v1"}
        )

    def test_refuses_a_tampered_body(self) -> None:
        self.assert_refused("signature-mismatch", body=b'{"tampered":true}')

    def test_refuses_the_wrong_key(self) -> None:
        self.assert_refused("signature-mismatch", key=b"k" * 32)

    def test_refuses_another_request_target(self) -> None:
        self.assert_refused("signature-mismatch", path="/hooks/other")

    def test_refuses_a_truncated_signature(self) -> None:
        self.assert_refused(
            "malformed-signature",
            headers={**headers(), "x-registry-signature": "v1=truncated"},
        )

    def test_refuses_a_header_repeated_under_another_case(self) -> None:
        self.assert_refused(
            "duplicate-header",
            "a Base Registry Engine hook header is repeated; remove duplicate signed headers",
            headers={**headers(), "CE-TYPE": "case-created-v1"},
        )

    def test_reports_an_invalid_delivery_time_with_its_fix(self) -> None:
        fixture = Path(__file__).resolve().parents[3] / "registry-platform-crypto/tests/fixtures/delivery-signatures.json"
        vector = next(value for value in json.loads(fixture.read_text()) if not value["valid"])
        self.assert_refused(
            "invalid-delivery-time",
            "the Base Registry Engine hook delivery time is invalid; check the signed delivery time and sender clock",
            headers={**headers(), "x-registry-delivery-time": vector["deliveryTime"], "x-registry-signature": vector["signature"]},
        )

    def test_reports_an_oversized_body_with_its_fix(self) -> None:
        self.assert_refused(
            "body-too-large",
            "the Base Registry Engine hook body exceeds the Version 1 limit; reduce the body size",
            body=b"x" * 1_048_577,
        )

    def test_reports_an_invalid_key_with_its_fix(self) -> None:
        self.assert_refused(
            "invalid-key",
            "the Base Registry Engine hook verification key is too short; configure a key of at least 32 bytes",
            key=b"short-key",
        )

    def test_refuses_an_unknown_signature_version(self) -> None:
        self.assert_refused(
            "unsupported-version",
            headers={**headers(), "x-registry-signature": SIGNATURE.replace("v1=", "v2=", 1)},
        )

    def test_refuses_each_missing_signed_header(self) -> None:
        for name in headers():
            with self.subTest(header=name):
                missing = headers()
                del missing[name]
                self.assert_refused("missing-header", headers=missing)

    def test_refuses_input_of_the_wrong_shape_before_verification(self) -> None:
        for overrides in (
            {"method": b"POST"},
            {"path": None},
            {"headers": [("ce-id", "x")]},
            {"headers": {**headers(), "ce-id": b"x"}},
            {"headers": {**headers(), 1: "x"}},
            {"body": BODY.decode()},
            {"body": bytearray(BODY)},
            {"key": KEY.decode()},
            {"key": memoryview(KEY)},
        ):
            with self.subTest(field=next(iter(overrides))):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    verify(**overrides)
                self.assertEqual(raised.exception.kind, "invalid-request")
                self.assertNotIn(KEY.decode(), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
