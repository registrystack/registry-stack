from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_coordinator_client import CoordinatorClient, CoordinatorClientError  # noqa: E402

BASE = "https://coordinator.example.invalid/deployment"
RUN = "7e367d42-b001-4d44-b94c-9447bfa182aa"
REQUEST = {"workflow": "nursing-notice", "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "input": {"requestId": "one"}}


class ConstructionTests(unittest.TestCase):
    def test_constructs_without_retaining_credentials(self) -> None:
        client = CoordinatorClient(BASE)
        self.assertIsInstance(client, CoordinatorClient)
        self.assertNotIn("token", repr(client).lower())

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        with self.assertRaises(CoordinatorClientError) as raised:
            CoordinatorClient("not a URL")
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertIs(raised.exception.outcome_unknown, False)

    def test_an_unusable_base_url_is_a_configuration_error(self) -> None:
        for url in ("http://coordinator.example.invalid/", "https://user:pw@coordinator.example.invalid/"):
            with self.subTest(url=url):
                with self.assertRaises(CoordinatorClientError) as raised:
                    CoordinatorClient(url)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertNotIn("pw", str(raised.exception))

    def test_unknown_or_missing_members_are_refused(self) -> None:
        with self.assertRaises(TypeError):
            CoordinatorClient(BASE, attempt_timeout_milliseconds=1)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            CoordinatorClient()  # type: ignore[call-arg]

    def test_none_is_the_default_for_every_optional_member(self) -> None:
        CoordinatorClient(
            BASE,
            attempt_timeout_seconds=None,
            connect_timeout_seconds=None,
            maximum_response_bytes=None,
            user_agent=None,
            trusted_root_certificates=None,
            maximum_mutation_retries=None,
        )

    def test_members_accept_values_in_range(self) -> None:
        for keyword, value in (
            ("attempt_timeout_seconds", 2),
            ("attempt_timeout_seconds", 1.5),
            ("connect_timeout_seconds", 2),
            ("connect_timeout_seconds", 1.5),
            ("maximum_response_bytes", 1500),
            ("user_agent", "adopter/1"),
        ):
            with self.subTest(keyword=keyword):
                CoordinatorClient(BASE, **{keyword: value})

    def test_bool_or_out_of_range_members_are_configuration_errors(self) -> None:
        for keyword, value in (
            ("attempt_timeout_seconds", True),
            ("attempt_timeout_seconds", False),
            ("attempt_timeout_seconds", 0),
            ("attempt_timeout_seconds", -1),
            ("attempt_timeout_seconds", float("nan")),
            ("attempt_timeout_seconds", float("inf")),
            ("attempt_timeout_seconds", 1e300),
            ("attempt_timeout_seconds", "2"),
            ("connect_timeout_seconds", True),
            ("connect_timeout_seconds", -1),
            ("connect_timeout_seconds", 0),
            ("maximum_response_bytes", True),
            ("maximum_response_bytes", 0),
            ("maximum_response_bytes", -1),
            ("maximum_response_bytes", 2**64),
            ("maximum_response_bytes", 16 * 1024 * 1024 + 1),
            ("maximum_response_bytes", "1500"),
        ):
            with self.subTest(keyword=keyword, value=value):
                with self.assertRaises(CoordinatorClientError) as raised:
                    CoordinatorClient(BASE, **{keyword: value})
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_mutation_retries_accept_zero_to_two_only(self) -> None:
        for retries in (0, 1, 2):
            with self.subTest(retries=retries):
                CoordinatorClient(BASE, maximum_mutation_retries=retries)
        for retries in (3, 255, 256, -1, 1.5, "1", True):
            with self.subTest(retries=retries):
                with self.assertRaises(CoordinatorClientError) as raised:
                    CoordinatorClient(BASE, maximum_mutation_retries=retries)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_token_error_does_not_repeat_credential(self) -> None:
        malformed = "bad token with spaces canary"
        client = CoordinatorClient(BASE)
        for call in (
            lambda: client.start(malformed, "key-1", REQUEST),
            lambda: client.status(malformed, RUN),
            lambda: client.inspect(malformed, RUN),
            lambda: client.reconcile(malformed, RUN, "reason"),
        ):
            with self.assertRaises(CoordinatorClientError) as raised:
                call()
            self.assertEqual(raised.exception.kind, "invalid-request")
            self.assertIs(raised.exception.outcome_unknown, False)
            self.assertNotIn("canary", str(raised.exception))
            self.assertNotIn("canary", repr(raised.exception))
            self.assertNotIn("canary", repr(vars(raised.exception)))

    def test_cyclic_input_is_rejected_before_io(self) -> None:
        data: dict[str, object] = {}
        data["cycle"] = data
        with self.assertRaises(CoordinatorClientError) as raised:
            CoordinatorClient(BASE).start("valid-token", "key-1", {"workflow": "nursing-notice", "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "input": data})
        self.assertEqual(raised.exception.kind, "invalid-request")

    def test_a_malformed_start_request_is_rejected_before_io(self) -> None:
        client = CoordinatorClient(BASE)
        for request in (
            {**REQUEST, "extra": True},
            {"workflow": "nursing-notice"},
            {"input": {}},
            {"workflow": 1, "input": {}},
            "not a mapping",
            None,
        ):
            with self.subTest(request=request):
                with self.assertRaises(CoordinatorClientError) as raised:
                    client.start("valid-token", "key-1", request)  # type: ignore[arg-type]
                self.assertEqual(raised.exception.kind, "invalid-request")


if __name__ == "__main__":
    unittest.main()
