"""Verify Base Registry Engine hook deliveries through the shared Rust verifier.

The fixed vector is the one `registry-breg-client/tests/webhook.rs` and the
Node binding's `hook-verification.test.js` use, which in turn belongs to
`registry-platform-crypto` delivery signatures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timedelta, timezone
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


def headers() -> list[tuple[str, str]]:
    return [
        ("Ce-Specversion", "1.0"),
        ("CE-ID", "00000000-0000-4000-8000-000000000001"),
        ("ce-source", "urn:registrystack:registry:example:instance:primary"),
        ("ce-type", "case-created-v1"),
        ("ce-time", "2026-08-30T00:00:00Z"),
        ("ce-dataschema", "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa"),
        ("x-registry-event-generation", "1"),
        ("x-registry-delivery-attempt", "1"),
        ("x-registry-delivery-time", "2026-08-30T00:00:01Z"),
        ("idempotency-key", IDEMPOTENCY_KEY),
        ("content-type", "application/json"),
        ("x-registry-signature", SIGNATURE),
    ]


def replace_header(values: list[tuple[str, str]], name: str, value: str) -> list[tuple[str, str]]:
    return [
        (candidate, value if candidate.lower() == name.lower() else current)
        for candidate, current in values
    ]


def verify(**overrides):
    arguments = {
        "method": "POST",
        "path": "/hooks/registry",
        "headers": headers(),
        "body": BODY,
        "key": KEY,
        # The fixed vector is dated 2026-08-30, outside any default window.
        "caller_enforced_freshness": True,
    }
    arguments.update(overrides)
    return verify_hook_delivery(**arguments)


def signed_headers(delivery_time: datetime) -> list[tuple[str, str]]:
    """The fixed headers re-signed for `delivery_time` with the vector's key."""
    stamp = delivery_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    values = replace_header(headers(), "x-registry-delivery-time", stamp)
    by_name = {name.lower(): value for name, value in values}
    signed = bytearray(b"breg-webhook-signature-v1")
    for value in (
        by_name["ce-specversion"].encode(),
        by_name["ce-id"].encode(),
        by_name["ce-source"].encode(),
        by_name["ce-type"].encode(),
        by_name["ce-time"].encode(),
        by_name["ce-dataschema"].encode(),
        by_name["x-registry-event-generation"].encode(),
        by_name["x-registry-delivery-attempt"].encode(),
        by_name["x-registry-delivery-time"].encode(),
        b"POST",
        b"/hooks/registry",
        b"application/json",
        by_name["idempotency-key"].encode(),
        BODY,
    ):
        signed.extend(len(value).to_bytes(8, "big") + value)
    digest = hmac.new(KEY, signed, hashlib.sha256).digest()
    signature = "v1=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return replace_header(values, "x-registry-signature", signature)


def verify_default(delivery_time: datetime, **overrides):
    return verify(
        headers=signed_headers(delivery_time), caller_enforced_freshness=False, **overrides
    )


class HookVerificationTests(unittest.TestCase):
    def test_shared_language_vectors_preserve_exact_rfc3339_fractions(self):
        fixture = Path(__file__).resolve().parents[3] / "registry-platform-crypto/tests/fixtures/delivery-signatures.json"
        for vector in json.loads(fixture.read_text()):
            exact = replace_header(
                replace_header(headers(), "x-registry-delivery-time", vector["deliveryTime"]),
                "x-registry-signature",
                vector["signature"],
            )
            with self.subTest(timestamp=vector["deliveryTime"]):
                if vector["valid"]:
                    self.assertEqual(verify(headers=exact)["delivery_time"], vector["deliveryTime"])
                    self.assert_refused(
                        "signature-mismatch",
                        headers=replace_header(exact, "x-registry-delivery-time", "2026-08-30T00:00:01.0000Z"),
                    )
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

    def test_default_window_is_300_seconds_in_both_directions(self) -> None:
        now = datetime.now(timezone.utc)
        for offset in (0, -290, 290):
            with self.subTest(offset=offset):
                self.assertEqual(
                    verify_default(now + timedelta(seconds=offset))["id"],
                    "00000000-0000-4000-8000-000000000001",
                )
        for offset in (-310, 310):
            with self.subTest(offset=offset):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    verify_default(now + timedelta(seconds=offset))
                self.assertEqual(raised.exception.kind, "hook-verification")
                self.assertEqual(raised.exception.code, "stale-delivery")

    def test_default_window_refuses_the_old_fixed_vector(self) -> None:
        self.assert_refused("stale-delivery", caller_enforced_freshness=False)

    def test_max_skew_seconds_replaces_the_default_window(self) -> None:
        stamp = datetime.now(timezone.utc) - timedelta(seconds=600)
        self.assertEqual(verify_default(stamp, max_skew_seconds=900)["attempt"], "1")
        with self.assertRaises(BaseRegistryClientError) as raised:
            verify_default(datetime.now(timezone.utc) - timedelta(seconds=60), max_skew_seconds=10)
        self.assertEqual(raised.exception.code, "stale-delivery")

    def test_caller_enforced_freshness_accepts_an_old_delivery(self) -> None:
        self.assertEqual(verify(caller_enforced_freshness=True)["attempt"], "1")

    def test_refuses_a_freshness_option_out_of_range_or_combined(self) -> None:
        for overrides in (
            {"max_skew_seconds": 0},
            {"max_skew_seconds": 3601},
            {"max_skew_seconds": -1},
            {"max_skew_seconds": 1.5},
            {"max_skew_seconds": True},
            {"max_skew_seconds": "10"},
            {"max_skew_seconds": 10, "caller_enforced_freshness": True},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    verify(**{"caller_enforced_freshness": False, **overrides})
                self.assertEqual(raised.exception.kind, "invalid-request")
        for edge in (1, 3600):
            self.assertEqual(
                verify_default(datetime.now(timezone.utc), max_skew_seconds=edge)["attempt"], "1"
            )

    def test_arguments_are_keyword_only(self) -> None:
        with self.assertRaises(TypeError):
            verify_hook_delivery("POST", "/hooks/registry", headers(), BODY, KEY)

    def test_refuses_a_tampered_signed_header(self) -> None:
        self.assert_refused(
            "signature-mismatch", headers=replace_header(headers(), "ce-type", "case-patched-v1")
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
            headers=replace_header(headers(), "x-registry-signature", "v1=truncated"),
        )

    def test_refuses_a_header_repeated_under_another_case(self) -> None:
        self.assert_refused(
            "duplicate-header",
            "a Base Registry Engine hook header is repeated; remove duplicate signed headers",
            headers=[*headers(), ("CE-TYPE", "case-created-v1")],
        )

    def test_ordered_header_pairs_preserve_verification_and_duplicate_refusals(self) -> None:
        pairs = headers()
        self.assertEqual(verify(headers=pairs)["id"], "00000000-0000-4000-8000-000000000001")

        tampered = [
            (name, "case-patched-v1" if name.lower() == "ce-type" else value)
            for name, value in pairs
        ]
        self.assert_refused("signature-mismatch", headers=tampered)
        self.assert_refused("duplicate-header", headers=[*pairs, ("ce-type", "withheld")])

        with self.assertRaises(BaseRegistryClientError) as raised:
            verify(headers=dict(headers()))
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertNotIn("withheld", str(raised.exception))

    def test_reports_an_invalid_delivery_time_with_its_fix(self) -> None:
        fixture = Path(__file__).resolve().parents[3] / "registry-platform-crypto/tests/fixtures/delivery-signatures.json"
        vector = next(value for value in json.loads(fixture.read_text()) if not value["valid"])
        self.assert_refused(
            "invalid-delivery-time",
            "the Base Registry Engine hook delivery time is invalid; check the signed delivery time and sender clock",
            headers=replace_header(
                replace_header(headers(), "x-registry-delivery-time", vector["deliveryTime"]),
                "x-registry-signature",
                vector["signature"],
            ),
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
            headers=replace_header(headers(), "x-registry-signature", SIGNATURE.replace("v1=", "v2=", 1)),
        )

    def test_refuses_each_missing_signed_header(self) -> None:
        for name, _ in headers():
            with self.subTest(header=name):
                missing = [(candidate, value) for candidate, value in headers() if candidate != name]
                self.assert_refused("missing-header", headers=missing)

    def test_refuses_input_of_the_wrong_shape_before_verification(self) -> None:
        for overrides in (
            {"method": b"POST"},
            {"path": None},
            {"headers": [("ce-id",)]},
            {"headers": [*headers(), ("ce-id", b"x")]},
            {"headers": [*headers(), (1, "x")]},
            {"headers": dict(headers())},
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
