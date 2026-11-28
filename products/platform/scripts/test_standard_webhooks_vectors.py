# SPDX-License-Identifier: Apache-2.0
"""Check the shared delivery vectors against the official Standard Webhooks library."""

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from standardwebhooks.webhooks import Webhook, WebhookVerificationError

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "crates/registry-platform-crypto/tests/fixtures/standard-webhooks.json"
)


def webhooks(vector):
    for field in ("keyHex", "previousKeyHex"):
        if vector[field] is not None:
            yield Webhook(bytes.fromhex(vector[field]))


class StandardWebhooksVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.by_name = {vector["name"]: vector for vector in cls.vectors}

    def test_library_reproduces_every_committed_signature(self):
        for vector in self.vectors:
            if vector["expected"] != "accepted":
                continue
            with self.subTest(vector=vector["name"]):
                instant = datetime.fromtimestamp(int(vector["timestamp"]), UTC)
                entries = [
                    webhook.sign(vector["id"], instant, vector["body"])
                    for webhook in webhooks(vector)
                ]
                self.assertEqual(" ".join(entries), vector["signature"])

    def test_published_vector_matches_the_library_test(self):
        # libraries/v1.3.0, libraries/python/tests/test_webhooks.py, test_sign_function
        vector = self.by_name["standard-webhooks-published"]
        instant = datetime.fromtimestamp(1614265330, UTC)
        webhook = Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
        expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        self.assertEqual(vector["id"], "msg_p5jXN8AQM9LWM0D4loKWxJek")
        self.assertEqual(vector["timestamp"], "1614265330")
        self.assertEqual(vector["body"], '{"test": 2432232314}')
        self.assertEqual(vector["keyPolicy"], "below-minimum")
        self.assertEqual(vector["signature"], expected)
        self.assertEqual(webhook.sign(vector["id"], instant, vector["body"]), expected)

    def fresh_rotation(self):
        vector = self.by_name["rotation-two-signatures"]
        current, previous = webhooks(vector)
        instant = datetime.now(UTC)
        headers = {
            "webhook-id": vector["id"],
            "webhook-timestamp": str(int(instant.timestamp())),
            "webhook-signature": " ".join(
                webhook.sign(vector["id"], instant, vector["body"])
                for webhook in (current, previous)
            ),
        }
        return current, previous, vector["body"], headers

    def test_library_signs_vectors_outside_the_registry_wire_profile(self):
        for name in ("id-with-period", "timestamp-leading-zero"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                instant = datetime.fromtimestamp(int(vector["timestamp"]), UTC)
                (webhook,) = webhooks(vector)
                self.assertEqual(
                    webhook.sign(vector["id"], instant, vector["body"]),
                    vector["signature"],
                )

    def test_library_accepts_a_two_key_header_with_either_key_now(self):
        current, previous, body, headers = self.fresh_rotation()
        for webhook in (current, previous):
            self.assertEqual(webhook.verify(body, headers), json.loads(body))

    def test_library_refuses_a_tampered_body_now(self):
        current, previous, body, headers = self.fresh_rotation()
        for webhook in (current, previous):
            with self.assertRaises(WebhookVerificationError):
                webhook.verify(body + " ", headers)
