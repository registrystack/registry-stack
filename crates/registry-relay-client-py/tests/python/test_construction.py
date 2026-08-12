from __future__ import annotations

import pathlib
import sys
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
TOKEN_CA = (TESTS / "fixtures" / "token-ca.pem").read_bytes()
PRIVATE_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    "alg": "EdDSA",
    "kid": "client-key-1",
}
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class ConstructionTest(unittest.TestCase):
    def test_public_static_and_private_key_jwt_clients_construct_offline(self):
        self.assertIsNotNone(relay.RelayClient("http://127.0.0.1:9/prefix"))
        self.assertIsNotNone(
            relay.RelayClient(
                "http://127.0.0.1:9/prefix",
                authorization={"static": "placeholder-token"},
            )
        )
        self.assertIsNotNone(
            relay.RelayClient(
                "http://127.0.0.1:9/prefix",
                authorization={
                    "private_key_jwt": {
                        "token_endpoint": "http://127.0.0.1:9/token",
                        "client_id": "client",
                        "client_key": PRIVATE_JWK,
                        "trusted_root_certificates": TOKEN_CA,
                    }
                },
                request_timeout_seconds=1.0,
                connect_timeout_seconds=1.0,
                user_agent="relay-python-test",
                max_response_bytes=4096,
            )
        )

    def test_static_authorization_requires_the_closed_discriminated_shape(self):
        for authorization in (
            "placeholder-token",
            {"bearer": "placeholder-token"},
            {"static": "placeholder-token", "private_key_jwt": {}},
        ):
            with self.subTest(authorization=authorization):
                with self.assertRaises(relay.RelayClientError) as raised:
                    relay.RelayClient(
                        "http://127.0.0.1:9/prefix",
                        authorization=authorization,
                    )
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertNotIn("placeholder-token", str(raised.exception))

    def test_configuration_errors_are_structured_and_redacted(self):
        secret = "canary-secret-that-must-not-render"
        with self.assertRaises(relay.RelayClientError) as raised:
            relay.RelayClient(
                "https://relay.example",
                authorization={"private_key_jwt": {}, "static": secret},
            )
        error = raised.exception
        self.assertEqual(error.kind, "configuration")
        self.assertIsNone(error.code)
        self.assertIsNone(error.status)
        self.assertIsNone(error.trace_id)
        self.assertIsNone(error.retry_after_seconds)
        self.assertIsNone(error.transport_kind)
        self.assertIsNone(error.token_kind)
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error))

    def test_private_key_jwt_trusted_roots_reject_bad_material_without_exposure(self):
        canary = b"canary-private-ca-material"
        with self.assertRaises(relay.RelayClientError) as raised:
            relay.RelayClient(
                "https://relay.example",
                authorization={
                    "private_key_jwt": {
                        "token_endpoint": "https://tokens.example/token",
                        "client_id": "client",
                        "client_key": PRIVATE_JWK,
                        "trusted_root_certificates": canary,
                    }
                },
            )
        self.assertEqual(raised.exception.kind, "token")
        self.assertEqual(raised.exception.token_kind, "configuration")
        self.assertNotIn(canary.decode(), str(raised.exception))
        self.assertNotIn(canary.decode(), repr(raised.exception))

    def test_private_key_jwt_shape_rejects_extra_fields_before_conversion(self):
        private_key_jwt: dict[str, object] = {
            "token_endpoint": "https://tokens.example/token",
            "client_id": "client",
            "client_key": PRIVATE_JWK,
            "trusted_root_certificates": TOKEN_CA,
        }
        for index in range(20_000):
            private_key_jwt[f"canary-extra-{index}"] = object()
        with self.assertRaises(relay.RelayClientError) as raised:
            relay.RelayClient(
                "https://relay.example",
                authorization={"private_key_jwt": private_key_jwt},
            )
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertEqual(
            str(raised.exception),
            'authorization["private_key_jwt"] carries an unsupported field',
        )
        self.assertNotIn("canary-extra", str(raised.exception))

    def test_private_key_jwt_fields_share_one_conversion_budget(self):
        with self.assertRaises(relay.RelayClientError) as raised:
            relay.RelayClient(
                "https://relay.example",
                authorization={
                    "private_key_jwt": {
                        "token_endpoint": "https://tokens.example/token",
                        "client_id": "client",
                        "client_key": PRIVATE_JWK,
                        "audience": "a" * (3 * 1024 * 1024),
                        "user_agent": "b" * (3 * 1024 * 1024),
                        "trusted_root_certificates": TOKEN_CA,
                    }
                },
            )
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertEqual(
            str(raised.exception),
            "the Python object graph exceeds the conversion text bound",
        )

    def test_private_key_jwt_trusted_roots_are_bounded_before_copy(self):
        oversized = b"canary-oversized-ca" + b"x" * 1_048_576
        with self.assertRaises(relay.RelayClientError) as raised:
            relay.RelayClient(
                "https://relay.example",
                authorization={
                    "private_key_jwt": {
                        "token_endpoint": "https://tokens.example/token",
                        "client_id": "client",
                        "client_key": PRIVATE_JWK,
                        "trusted_root_certificates": oversized,
                    }
                },
            )
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertEqual(
            str(raised.exception),
            'authorization["private_key_jwt"]["trusted_root_certificates"] '
            "exceeds the accepted byte bound",
        )
        self.assertNotIn("canary-oversized-ca", str(raised.exception))

    def test_cyclic_and_overdeep_authorization_graphs_fail_without_recursing(self):
        cyclic: dict[str, object] = {}
        cyclic["private_key_jwt"] = cyclic
        with self.assertRaises(relay.RelayClientError) as cyclic_error:
            relay.RelayClient("https://relay.example", authorization=cyclic)
        self.assertEqual(cyclic_error.exception.kind, "configuration")

        nested: object = None
        for _ in range(140):
            nested = [nested]
        with self.assertRaises(relay.RelayClientError):
            relay.RelayClient("https://relay.example", authorization=nested)

    def test_unsafe_base_url_and_zero_bounds_are_rejected_by_the_sdk(self):
        for kwargs in (
            {"base_url": "https://secret@relay.example"},
            {"base_url": "https://relay.example", "request_timeout_seconds": 0.0},
            {"base_url": "https://relay.example", "max_response_bytes": 0},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(relay.RelayClientError) as raised:
                    relay.RelayClient(**kwargs)
                self.assertEqual(raised.exception.kind, "configuration")

    def test_max_response_bytes_range_errors_are_stable_configuration_errors(self):
        for value in (-1, 1 << 100):
            with self.subTest(value=value):
                with self.assertRaises(relay.RelayClientError) as raised:
                    relay.RelayClient(
                        "http://127.0.0.1:9", max_response_bytes=value
                    )
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertEqual(
                    str(raised.exception),
                    "max_response_bytes must be an unsigned 64-bit integer",
                )


if __name__ == "__main__":
    unittest.main()
