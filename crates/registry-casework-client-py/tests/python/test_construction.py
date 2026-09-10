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

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        with self.assertRaises(CaseworkClientError) as raised:
            CaseworkClient("not a URL")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_token_error_does_not_repeat_credential(self) -> None:
        secret = "bad token with spaces canary"
        client = CaseworkClient("https://casework.example.invalid/")
        with self.assertRaises(CaseworkClientError) as raised:
            client.description(secret, "requester")
        self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))

    def test_cyclic_request_is_rejected_before_io(self) -> None:
        display: dict[str, object] = {}
        display["cycle"] = display
        client = CaseworkClient("https://casework.example.invalid/")
        with self.assertRaises(CaseworkClientError) as raised:
            client.create_hosted_item(
                "valid-token", "requester", "create-key", {
                    "kind": "decision",
                    "requesterReference": "reference",
                    "display": display,
                }
            )
        self.assertEqual(raised.exception.kind, "invalid_request")


if __name__ == "__main__":
    unittest.main()
