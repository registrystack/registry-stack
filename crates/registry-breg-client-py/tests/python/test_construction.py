import unittest
from collections import UserDict
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

import registry_breg_client as breg_client  # noqa: E402

BaseRegistryClient = breg_client.BaseRegistryClient
BaseRegistryClientError = breg_client.BaseRegistryClientError


class ConstructionTests(unittest.TestCase):
    def test_constructs_with_a_deployment_base(self) -> None:
        self.assertIsInstance(
            BaseRegistryClient("https://registry.example.invalid/tenant"),
            BaseRegistryClient,
        )

    def test_invalid_configuration_has_a_stable_kind(self) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            BaseRegistryClient("not a URL")
        self.assertEqual(raised.exception.kind, "configuration")

    def test_unknown_authorization_shape_is_rejected(self) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            BaseRegistryClient(
                "https://registry.example.invalid/tenant",
                authorization={"ambient": "not-supported"},
            )
        self.assertEqual(raised.exception.kind, "configuration")

    def test_configuration_errors_do_not_repeat_static_credentials(self) -> None:
        secret = "canary-static-token-that-must-not-render"
        with self.assertRaises(BaseRegistryClientError) as raised:
            BaseRegistryClient(
                "https://registry.example.invalid/tenant",
                authorization={"static": secret, "private_key_jwt": {}},
            )
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))

    def test_cyclic_request_graph_is_rejected_before_io(self) -> None:
        client = BaseRegistryClient("https://registry.example.invalid/tenant")
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(BaseRegistryClientError) as raised:
            client.continue_list(cyclic)
        self.assertEqual(raised.exception.kind, "invalid_request")

    def test_mapping_protocol_is_not_accepted_as_a_plain_json_object(self) -> None:
        client = BaseRegistryClient("https://registry.example.invalid/tenant")
        with self.assertRaises(BaseRegistryClientError) as raised:
            client.continue_list(UserDict())
        self.assertEqual(raised.exception.kind, "invalid_request")

    def test_opaque_authority_types_have_no_public_constructor(self) -> None:
        for name in (
            "BRegCreateBinding",
            "BRegPatchBinding",
            "BRegLifecycleAuthority",
            "BRegLifecycleAction",
            "BRegMetadata",
        ):
            with self.assertRaises(TypeError):
                getattr(breg_client, name)()

    def test_stub_promises_only_supported_plain_json_containers(self) -> None:
        stub = (
            Path(__file__).resolve().parents[2]
            / "python/registry_breg_client/__init__.pyi"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Mapping", stub)
        self.assertIn(
            'JsonValue = JsonScalar | list["JsonValue"] | '
            'tuple["JsonValue", ...] | dict[str, "JsonValue"]',
            stub,
        )
        self.assertIn(
            "operations: list[dict[str, JsonValue]] | tuple[dict[str, JsonValue], ...]",
            stub,
        )

    def test_build_script_separates_extension_and_embedding_linkage(self) -> None:
        build_script = (Path(__file__).resolve().parents[2] / "build.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("CARGO_FEATURE_EXTENSION_MODULE", build_script)
        self.assertIn("add_extension_module_link_args", build_script)
        self.assertIn("add_libpython_rpath_link_args", build_script)


if __name__ == "__main__":
    unittest.main()
