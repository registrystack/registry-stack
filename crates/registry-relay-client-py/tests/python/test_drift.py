from __future__ import annotations

import ast
import pathlib
import sys
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
CRATE = TESTS.parents[1]
PACKAGE = CRATE / "python" / "registry_relay_client"
STUB = PACKAGE / "__init__.pyi"
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402

ERROR_ATTRIBUTES = {
    "kind",
    "code",
    "status",
    "trace_id",
    "retry_after_seconds",
    "transport_kind",
    "token_kind",
}


def class_members(node: ast.ClassDef) -> set[str]:
    result: set[str] = set()
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.add("__new__" if item.name == "__init__" else item.name)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            result.add(item.target.id)
    return result


class DriftTest(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(STUB.read_text(encoding="utf-8"))
        self.stub_classes = {
            node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
        }
        self.classes = {
            name: node
            for name, node in self.stub_classes.items()
            if name in {"RelayClient", "RelayClientError"}
        }

    def test_stub_and_runtime_top_level_classes_match_both_directions(self):
        self.assertEqual(set(self.classes), {"RelayClient", "RelayClientError"})
        self.assertEqual(
            {name for name in dir(relay) if not name.startswith("_")},
            {"RelayClient", "RelayClientError"},
        )

    def test_client_methods_match_both_directions(self):
        stub = class_members(self.classes["RelayClient"])
        live = set(vars(relay.RelayClient)) - {"__doc__", "__module__"}
        self.assertEqual(stub, live)

    def test_error_attributes_and_inheritance_are_pinned(self):
        self.assertEqual(
            class_members(self.classes["RelayClientError"]), ERROR_ATTRIBUTES
        )
        self.assertTrue(issubclass(relay.RelayClientError, Exception))

    def test_required_and_optional_typed_dict_keys_are_pinned(self):
        private_required = self.stub_classes["_PrivateKeyJwtRequired"]
        self.assertEqual(
            class_members(private_required),
            {"token_endpoint", "client_id", "client_key"},
        )
        private_config = self.stub_classes["PrivateKeyJwtConfig"]
        self.assertEqual(
            [base.id for base in private_config.bases if isinstance(base, ast.Name)],
            ["_PrivateKeyJwtRequired"],
        )
        self.assertEqual(
            class_members(private_config),
            {
                "audience",
                "assertion_lifetime_seconds",
                "refresh_margin_seconds",
                "request_timeout_seconds",
                "connect_timeout_seconds",
                "user_agent",
                "trusted_root_certificates",
            },
        )
        self.assertTrue(
            any(
                keyword.arg == "total"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in private_config.keywords
            )
        )

        continuation_required = self.stub_classes[
            "_CollectionContinuationRequired"
        ]
        self.assertEqual(
            class_members(continuation_required), {"route", "cursor", "format"}
        )
        continuation = self.stub_classes["CollectionContinuation"]
        self.assertEqual(
            [base.id for base in continuation.bases if isinstance(base, ast.Name)],
            ["_CollectionContinuationRequired"],
        )
        self.assertEqual(class_members(continuation), {"accessProfile"})
        self.assertTrue(
            any(
                keyword.arg == "total"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in continuation.keywords
            )
        )

    def test_stub_promises_only_plain_mapping_inputs(self):
        tree = ast.parse(STUB.read_text(encoding="utf-8"))
        self.assertFalse(
            any(isinstance(node, ast.Name) and node.id == "Mapping" for node in ast.walk(tree))
        )

    def test_pep_561_and_package_metadata_files_exist(self):
        self.assertTrue((PACKAGE / "py.typed").is_file())
        self.assertTrue((PACKAGE / "__init__.py").is_file())
        self.assertTrue((CRATE / "pyproject.toml").is_file())
        self.assertTrue((CRATE / "README.md").is_file())
        self.assertTrue((CRATE / "LICENSE").is_file())


if __name__ == "__main__":
    unittest.main()
