from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient, CaseworkClientError  # noqa: E402


class ConstructionTests(unittest.TestCase):
    def test_constructs_without_retaining_credentials(self) -> None:
        client = CaseworkClient("https://casework.example.invalid/tenant")
        self.assertIsInstance(client, CaseworkClient)
        self.assertNotIn("token", repr(client).lower())

    def test_none_means_omission_for_optional_configuration(self) -> None:
        client = CaseworkClient(
            "https://casework.example.invalid/tenant",
            attempt_timeout_seconds=None,
            connect_timeout_seconds=None,
            maximum_response_bytes=None,
            user_agent=None,
            trusted_root_certificates=None,
            maximum_mutation_retries=None,
        )
        self.assertIsInstance(client, CaseworkClient)

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        with self.assertRaises(CaseworkClientError) as raised:
            CaseworkClient("not a URL")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_numeric_configuration_is_lossless_and_uses_the_public_name(self) -> None:
        invalid_configurations = (
            {"attempt_timeout_seconds": True},
            {"attempt_timeout_seconds": 2**64},
            {"connect_timeout_seconds": False},
            {"maximum_response_bytes": True},
            {"maximum_response_bytes": 2**64},
        )
        for options in invalid_configurations:
            with self.subTest(options=options), self.assertRaises(CaseworkClientError) as raised:
                CaseworkClient("https://casework.example.invalid/", **options)
            self.assertEqual(raised.exception.kind, "configuration")

        with self.assertRaises(TypeError):
            CaseworkClient(
                "https://casework.example.invalid/", request_timeout_seconds=1.0
            )
        with self.assertRaises(TypeError):
            CaseworkClient(
                "https://casework.example.invalid/", max_mutation_retries=0
            )

    def test_token_error_does_not_repeat_credential(self) -> None:
        secret = "bad token with spaces canary"
        client = CaseworkClient("https://casework.example.invalid/")
        with self.assertRaises(CaseworkClientError) as raised:
            client.description(secret, "requester")
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))

    def test_accepted_binding_has_safe_field_guidance_before_token_or_io(self):
        client = CaseworkClient("https://casework.example.invalid/")
        valid = {"requestId":"00000000-0000-4000-8000-000000000001", "policy":{"id":"review","version":"1","digest":"sha256:"+"a"*64}, "subject":{"source":"registry","type":"case","id":"one","version":"1","digest":"sha256:"+"b"*64}, "submissionDigest":"sha256:"+"c"*64}
        for key in valid:
            with self.subTest(key=key), self.assertRaises(CaseworkClientError) as raised:
                client.review_result("bad token canary", "requester", {**valid,key:"canary-private-binding"})
            error = raised.exception
            self.assertEqual(error.kind,"invalid-request")
            self.assertEqual(error.validation,{"path":"$."+key,"reason":"binding-invalid","allowed":[]})
            self.assertNotIn("canary",str(error))
        with self.assertRaises(CaseworkClientError) as raised:
            client.review_result("bad token canary", "requester", {**valid,"requestId":"00000000-0000-0000-0000-000000000000"})
        self.assertEqual(raised.exception.validation,{"path":"$.requestId","reason":"binding-invalid","allowed":[]})

    def test_cyclic_request_is_rejected_before_io(self) -> None:
        display: dict[str, object] = {}
        display["cycle"] = display
        client = CaseworkClient("https://casework.example.invalid/")
        with self.assertRaises(CaseworkClientError) as raised:
            client.create_or_recover_review_request(
                "valid-token", "requester", "create-key", {
                    "policy": {"id":"decision", "version":"1", "digest": f"sha256:{'a' * 64}"},
                    "subject": {
                        "source": "source", "type": "case", "id": "one", "version": "1",
                        "digest": f"sha256:{'a' * 64}",
                    },
                    "requesterReference": "reference",
                    "context": {"mode": "submitted", "snapshot": display},
                },
                f"sha256:{'b' * 64}",
            )
        self.assertEqual(raised.exception.kind, "invalid-request")

    def test_review_task_discovery_keeps_ownership_closed_and_scoped(self) -> None:
        client = CaseworkClient("https://casework.example.invalid/")
        calls = (
            lambda: client.review_tasks(
                "valid-token", "staff", {"ownership": "someone-elses"}
            ),
            lambda: client.review_tasks(
                "valid-token", "staff", {"ownership": "assigned_to_me"}
            ),
            lambda: client.supervisory_review_tasks(
                "valid-token", "supervisor", {"ownership": "unclaimed"}
            ),
            *(lambda query=query: client.own_review_decisions(
                "valid-token", "staff", query
            ) for query in ({"author": "colleague"}, {"ownership": "assigned-to-me"},
                            {"cursor": "not-a-uuid"}, {"limit": 0}, {"limit": 101})),
            *(lambda request_id=request_id: client.supervisory_review_tasks(
                "valid-token", "supervisor", {"requestId": request_id}
            ) for request_id in ("", "not-a-uuid", 42, {}, [])),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(CaseworkClientError) as raised:
                    call()
                self.assertEqual(raised.exception.kind, "invalid-request")


if __name__ == "__main__":
    unittest.main()
