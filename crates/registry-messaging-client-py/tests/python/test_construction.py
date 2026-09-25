from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_messaging_client import MessagingClient, MessagingClientError  # noqa: E402

SUBMISSION = {
    "senderProfile": "reminders-sms",
    "to": {"phone": "+15550100"},
    "template": {"id": "appointment-reminder", "version": "1"},
    "locale": "en",
    "data": {"time": "10:00"},
}


class ConstructionTests(unittest.TestCase):
    def test_constructs_without_retaining_credentials(self) -> None:
        client = MessagingClient("https://messaging.example.invalid/tenant")
        self.assertIsInstance(client, MessagingClient)
        self.assertNotIn("token", repr(client).lower())

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            MessagingClient("not a URL")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_negative_timeout_is_a_configuration_error(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            MessagingClient("https://messaging.example.invalid/", request_timeout_seconds=-1.0)
        self.assertEqual(raised.exception.kind, "configuration")

    def test_token_error_does_not_repeat_credential(self) -> None:
        malformed = "bad token with spaces canary"
        client = MessagingClient("https://messaging.example.invalid/")
        for call in (
            lambda: client.message(malformed, "0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d"),
            lambda: client.submit(malformed, "key-1", SUBMISSION),
        ):
            with self.assertRaises(MessagingClientError) as raised:
                call()
            self.assertEqual(raised.exception.kind, "invalid_request")
            self.assertNotIn("canary", str(raised.exception))
            self.assertNotIn("canary", repr(raised.exception))
            self.assertNotIn("canary", repr(vars(raised.exception)))

    def test_cyclic_submission_is_rejected_before_io(self) -> None:
        data: dict[str, object] = {}
        data["cycle"] = data
        client = MessagingClient("https://messaging.example.invalid/")
        with self.assertRaises(MessagingClientError) as raised:
            client.submit("valid-token", "key-1", {**SUBMISSION, "data": data})
        self.assertEqual(raised.exception.kind, "invalid_request")

    def test_unknown_submission_member_is_rejected_before_io(self) -> None:
        client = MessagingClient("https://messaging.example.invalid/")
        with self.assertRaises(MessagingClientError) as raised:
            client.submit("valid-token", "key-1", {**SUBMISSION, "priority": "high"})
        self.assertEqual(raised.exception.kind, "invalid_request")


if __name__ == "__main__":
    unittest.main()
