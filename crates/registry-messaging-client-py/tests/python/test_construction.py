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

    def test_timeouts_and_response_bound_accept_numbers_in_range(self) -> None:
        for keyword, value in (
            ("request_timeout_seconds", 2),
            ("request_timeout_seconds", 1.5),
            ("connect_timeout_seconds", 2),
            ("connect_timeout_seconds", 1.5),
            ("max_response_bytes", 1500),
        ):
            with self.subTest(keyword=keyword, value=value):
                MessagingClient("https://messaging.example.invalid/", **{keyword: value})

    def test_bool_or_out_of_range_bound_is_a_configuration_error(self) -> None:
        for keyword, value in (
            ("request_timeout_seconds", True),
            ("request_timeout_seconds", False),
            ("request_timeout_seconds", -1),
            ("request_timeout_seconds", float("nan")),
            ("request_timeout_seconds", float("inf")),
            ("request_timeout_seconds", "2"),
            ("connect_timeout_seconds", True),
            ("connect_timeout_seconds", -1),
            ("max_response_bytes", True),
            ("max_response_bytes", False),
            ("max_response_bytes", -1),
            ("max_response_bytes", 2**64),
            ("max_response_bytes", 1.5),
            ("max_response_bytes", "1500"),
        ):
            with self.subTest(keyword=keyword, value=value):
                with self.assertRaises(MessagingClientError) as raised:
                    MessagingClient("https://messaging.example.invalid/", **{keyword: value})
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

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
