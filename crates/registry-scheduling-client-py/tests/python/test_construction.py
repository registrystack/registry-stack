from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_scheduling_client import SchedulingClient, SchedulingClientError  # noqa: E402

APPOINTMENT_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0f"
ADMISSION = {
    "offering": "registry-update-30",
    "start": "2026-10-05T09:00:00Z",
    "party": {"recipients": 1, "attendees": 1},
    "policyRevision": 3,
    "capabilities": [],
    "prerequisites": [],
}


class ConstructionTests(unittest.TestCase):
    def test_constructs_without_retaining_credentials(self) -> None:
        client = SchedulingClient("https://scheduling.example.invalid/tenant")
        self.assertIsInstance(client, SchedulingClient)
        self.assertNotIn("token", repr(client).lower())

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        for build in (
            lambda: SchedulingClient("not a URL"),
            lambda: SchedulingClient("https://scheduling.example.invalid/", max_response_bytes=0),
        ):
            with self.assertRaises(SchedulingClientError) as raised:
                build()
            self.assertEqual(raised.exception.kind, "configuration")

    def test_negative_timeout_is_a_configuration_error(self) -> None:
        with self.assertRaises(SchedulingClientError) as raised:
            SchedulingClient("https://scheduling.example.invalid/", request_timeout_seconds=-1.0)
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
                SchedulingClient("https://scheduling.example.invalid/", **{keyword: value})

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
                with self.assertRaises(SchedulingClientError) as raised:
                    SchedulingClient("https://scheduling.example.invalid/", **{keyword: value})
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_token_error_does_not_repeat_credential(self) -> None:
        malformed = "bad token with spaces canary"
        client = SchedulingClient("https://scheduling.example.invalid/")
        for call in (
            lambda: client.get_scheduling(malformed),
            lambda: client.get_appointment(malformed, APPOINTMENT_ID),
            lambda: client.create_hold(malformed, "key-1", ADMISSION),
        ):
            with self.assertRaises(SchedulingClientError) as raised:
                call()
            self.assertEqual(raised.exception.kind, "invalid-request")
            self.assertNotIn("canary", str(raised.exception))
            self.assertNotIn("canary", repr(raised.exception))
            self.assertNotIn("canary", repr(vars(raised.exception)))

    def test_cyclic_admission_is_rejected_before_io(self) -> None:
        party: dict[str, object] = {}
        party["cycle"] = party
        client = SchedulingClient("https://scheduling.example.invalid/")
        with self.assertRaises(SchedulingClientError) as raised:
            client.create_hold("valid-token", "key-1", {**ADMISSION, "party": party})
        self.assertEqual(raised.exception.kind, "invalid-request")

    def test_unknown_admission_member_is_rejected_before_io(self) -> None:
        client = SchedulingClient("https://scheduling.example.invalid/")
        with self.assertRaises(SchedulingClientError) as raised:
            client.create_hold("valid-token", "key-1", {**ADMISSION, "priority": "high"})
        self.assertEqual(raised.exception.kind, "invalid-request")


if __name__ == "__main__":
    unittest.main()
