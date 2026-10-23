import json
from pathlib import Path
import tempfile
import unittest
from service import Inbox, WakeRefused


class WakeReceiverTests(unittest.TestCase):
    def test_acknowledgement_follows_durable_acceptance_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            payload = {
                "type": "review.completed",
                "eventId": "00000000-0000-4000-8000-000000000001",
                "requestId": "00000000-0000-4000-8000-000000000002",
                "resultId": "00000000-0000-4000-8000-000000000003",
                "completedAt": "2026-10-23T00:00:00Z",
            }
            body = json.dumps(payload).encode()
            self.assertTrue(
                inbox.accept(
                    "Bearer canary-receiver-token",
                    "receiver-one",
                    payload["eventId"],
                    body,
                    token="canary-receiver-token",
                    binding="receiver-one",
                )
            )
            self.assertFalse(
                inbox.accept(
                    "Bearer canary-receiver-token",
                    "receiver-one",
                    payload["eventId"],
                    body,
                    token="canary-receiver-token",
                    binding="receiver-one",
                )
            )
            payload["resultId"] = "00000000-0000-4000-8000-000000000004"
            with self.assertRaises(WakeRefused):
                inbox.accept(
                    "Bearer canary-receiver-token",
                    "receiver-one",
                    payload["eventId"],
                    json.dumps(payload).encode(),
                    token="canary-receiver-token",
                    binding="receiver-one",
                )
            self.assertEqual(inbox.pending(), 1)
            self.assertEqual(Inbox(Path(root) / "inbox.sqlite").pending(), 1)

    def test_authentication_binding_and_closed_payload_are_checked_before_acceptance(
        self,
    ):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            for auth, binding, body in [
                ("Bearer other", "receiver-one", b"{}"),
                ("Bearer canary-receiver-token", "other", b"{}"),
                (
                    "Bearer canary-receiver-token",
                    "receiver-one",
                    b'{"decision":"approved"}',
                ),
                (
                    "Bearer canary-receiver-token",
                    "receiver-one",
                    b'{"type":1,"type":2}',
                ),
            ]:
                with self.assertRaises(WakeRefused):
                    inbox.accept(
                        auth,
                        binding,
                        "canary",
                        body,
                        token="canary-receiver-token",
                        binding="receiver-one",
                    )
            self.assertEqual(inbox.pending(), 0)
