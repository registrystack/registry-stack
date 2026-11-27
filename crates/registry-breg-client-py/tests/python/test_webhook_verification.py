"""Verify Base Registry Engine Standard Webhooks through the Rust client."""
from __future__ import annotations

import base64
import hmac
import json
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

import registry_breg_client as breg_client  # noqa: E402

BaseRegistryClientError = breg_client.BaseRegistryClientError
verify_hook_delivery = breg_client.verify_hook_delivery

KEY = b"0123456789abcdef0123456789abcdef"
PREVIOUS_KEY = b"abcdef0123456789abcdef0123456789"
BODY = b'{"causation":{"hop":0,"root":"00000000-0000-4000-8000-000000000001"},"data":{},"dataschema":"https://example.test/schema","id":"00000000-0000-4000-8000-000000000001","source":"/products/breg/deployments/example","subject":{"recordReference":"breg/case/42","recordRevision":7},"time":"2026-08-30T00:00:00.123Z","type":"case-created-v1"}'
SIGNATURE = "v1,NELq97rzqnAqQUxh1eiskBB3oOl+4FsqaI1ZV/lAqQY="
EVENT = json.loads(BODY)
TIMESTAMP = 1788048001
CRATES = Path(__file__).resolve().parents[3]


def headers(event_id=EVENT["id"], timestamp=TIMESTAMP, signature=SIGNATURE):
    return [
        ("Content-Type", "application/json"),
        ("Webhook-ID", event_id),
        ("webhook-timestamp", str(timestamp)),
        ("webhook-signature", signature),
    ]


def verify(**overrides):
    return verify_hook_delivery(**{
        "headers": headers(), "body": BODY, "key": KEY,
        "caller_enforced_freshness": True, **overrides,
    })


def signed_headers(delivery_time, key=KEY, event_id=EVENT["id"]):
    stamp = int(delivery_time.timestamp())
    digest = hmac.digest(key, f"{event_id}.{stamp}.".encode("ascii") + BODY, "sha256")
    return headers(event_id, stamp, "v1," + base64.b64encode(digest).decode("ascii"))


def verify_default(delivery_time, **overrides):
    return verify(headers=signed_headers(delivery_time), caller_enforced_freshness=False, **overrides)


class HookVerificationTests(unittest.TestCase):
    def test_shared_language_vectors(self):
        fixture = CRATES / "registry-platform-crypto/tests/fixtures/standard-webhooks.json"
        for vector in json.loads(fixture.read_text()):
            with self.subTest(vector=vector["name"]):
                code = vector["expected"]
                if code in {"accepted", "stale-delivery"}:
                    code = "invalid-envelope"
                if vector["keyPolicy"] == "below-minimum":
                    code = "invalid-key"
                previous = vector["previousKeyHex"]
                self.assert_refused(
                    code, headers=headers(vector["id"], vector["timestamp"], vector["signature"]),
                    body=vector["body"].encode(), key=bytes.fromhex(vector["keyHex"]),
                    previous_key=bytes.fromhex(previous) if previous else None,
                )

    def test_stub_refusal_codes_match_rust(self):
        rust = (CRATES / "registry-breg-client/src/hook.rs").read_text()
        stub = (CRATES / "registry-breg-client-py/python/registry_breg_client/__init__.pyi").read_text()
        codes = re.findall(r'=> "([a-z-]+)"', rust)
        self.assertEqual(codes, re.findall(r'"([a-z-]+)"', stub.split("HookVerificationRefusalCode = Literal[", 1)[1].split("]", 1)[0]))

    def test_previous_key_and_envelope_identity(self):
        stamp = datetime.fromtimestamp(TIMESTAMP, timezone.utc)
        rotated = signed_headers(stamp, PREVIOUS_KEY)
        self.assert_refused("signature-mismatch", headers=rotated)
        self.assertEqual(verify(headers=rotated, previous_key=PREVIOUS_KEY)["id"], EVENT["id"])
        self.assert_refused("id-mismatch", headers=signed_headers(stamp, event_id="00000000-0000-4000-8000-000000000002"))

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
        stamp = datetime.fromtimestamp(TIMESTAMP, timezone.utc)
        self.assertEqual(signed_headers(stamp), headers())
        self.assertEqual(verify(), {
            **{field: EVENT[field] for field in ("id", "source", "type", "time", "dataschema")},
            "timestamp": TIMESTAMP, "body": BODY,
        })

    def test_default_window_is_300_seconds_in_both_directions(self) -> None:
        now = datetime.now(timezone.utc)
        for offset in (0, -295, 295):
            with self.subTest(offset=offset):
                self.assertEqual(
                    verify_default(now + timedelta(seconds=offset))["id"],
                    "00000000-0000-4000-8000-000000000001",
                )
        for offset in (-305, 305):
            with self.subTest(offset=offset):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    verify_default(now + timedelta(seconds=offset))
                self.assertEqual(raised.exception.kind, "hook-verification")
                self.assertEqual(raised.exception.code, "stale-delivery")

    def test_default_window_refuses_the_old_fixed_vector(self) -> None:
        self.assert_refused("stale-delivery", caller_enforced_freshness=False)

    def test_an_explicit_none_freshness_option_keeps_the_default_window(self) -> None:
        self.assert_refused("stale-delivery", caller_enforced_freshness=None)
        self.assertEqual(
            verify(
                headers=signed_headers(datetime.now(timezone.utc)),
                max_skew_seconds=None,
                caller_enforced_freshness=None,
            )["id"],
            EVENT["id"],
        )

    def test_max_skew_seconds_replaces_the_default_window(self) -> None:
        stamp = datetime.now(timezone.utc) - timedelta(seconds=600)
        self.assertEqual(verify_default(stamp, max_skew_seconds=900)["id"], EVENT["id"])
        with self.assertRaises(BaseRegistryClientError) as raised:
            verify_default(datetime.now(timezone.utc) - timedelta(seconds=60), max_skew_seconds=10)
        self.assertEqual(raised.exception.code, "stale-delivery")

    def test_caller_enforced_freshness_accepts_an_old_delivery(self) -> None:
        self.assertEqual(verify(caller_enforced_freshness=True)["id"], EVENT["id"])

    def test_refuses_a_freshness_option_out_of_range_or_combined(self) -> None:
        for overrides in (
            {"max_skew_seconds": 0},
            {"max_skew_seconds": 3601},
            {"max_skew_seconds": -1},
            {"max_skew_seconds": 1.5},
            {"max_skew_seconds": True},
            {"max_skew_seconds": "10"},
            {"max_skew_seconds": 10, "caller_enforced_freshness": True},
            {"caller_enforced_freshness": "yes"},
            {"caller_enforced_freshness": 1},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    verify(**{"caller_enforced_freshness": False, **overrides})
                self.assertEqual(raised.exception.kind, "invalid-request")
        for edge in (1, 3600):
            self.assertEqual(
                verify_default(datetime.now(timezone.utc), max_skew_seconds=edge)["id"], EVENT["id"]
            )

    def test_arguments_are_keyword_only(self) -> None:
        with self.assertRaises(TypeError):
            verify_hook_delivery("POST", "/hooks/registry", headers(), BODY, KEY)

    def test_refuses_invalid_headers_and_bytes(self):
        self.assert_refused("signature-mismatch", body=b"{}")
        self.assert_refused("signature-mismatch", key=b"k" * 32)
        self.assert_refused("body-too-large", body=b"x" * 1_048_577)
        self.assert_refused("duplicate-header", headers=[*headers(), ("webhook-id", EVENT["id"])])
        self.assert_refused("invalid-content-type", headers=[("Content-Type", "text/plain"), *headers()[1:]])

    def test_reports_invalid_keys_without_their_bytes(self):
        for overrides, expected in (
            ({"key": b"x" * 31}, 'The current hook key is 31 bytes and must contain 32 to 64 exact bytes.'),
            ({"key": b"x" * 64 + b"\n"}, 'The current hook key is 65 bytes including a trailing newline and must contain 32 to 64 exact bytes.'),
            ({"key": b"whsec_synthetic_key_text_for_test"}, 'The current hook key starts with whsec_ and must be supplied as exact key bytes.'),
            ({"previous_key": KEY}, 'The previous hook key equals the current key. Pass the key the sender used before rotation, or omit the previous key.'),
        ):
            with self.assertRaises(BaseRegistryClientError) as raised:
                verify(**overrides)
            self.assertEqual(raised.exception.code, "invalid-key")
            self.assertEqual(str(raised.exception), expected)
            self.assertNotIn(next(iter(overrides.values())).decode(), str(raised.exception))

    def test_refuses_each_missing_signed_header(self) -> None:
        for name, _ in headers():
            with self.subTest(header=name):
                missing = [(candidate, value) for candidate, value in headers() if candidate != name]
                self.assert_refused("missing-header", headers=missing)

    def test_refuses_input_of_the_wrong_shape_before_verification(self) -> None:
        for overrides in (
            {"previous_key": KEY.decode()},
            {"headers": [("webhook-id",)]},
            {"headers": [*headers(), ("webhook-id", b"x")]},
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
