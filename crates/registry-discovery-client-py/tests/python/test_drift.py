"""Pin the Discovery Python runtime, stub, and package surface together."""

from __future__ import annotations

import ast
import pathlib
import sys
import typing
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
CRATE = TESTS.parents[1]
PACKAGE = CRATE / "python" / "registry_discovery_client"
STUB = PACKAGE / "__init__.pyi"
sys.path.insert(0, str(TESTS))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import registry_discovery_client as discovery  # noqa: E402


RUNTIME_CLASS_NAMES = {
    "AcceptedServiceSelection",
    "DiscoveryClient",
    "DiscoveryClientError",
}
RUNTIME_FUNCTION_NAMES = {
    "accept_selection",
    "renew_unchanged_selection",
    "select_evidence_alternative",
    "select_evidence_service",
    "select_exact",
    "select_relay_service",
    "validate_selection",
    "validate_selection_structure",
}
RUNTIME_NAMES = RUNTIME_CLASS_NAMES | RUNTIME_FUNCTION_NAMES
ERROR_ATTRIBUTES = {"kind", "status", "problem", "transport_kind"}
EXPECTED_PACKAGE_FILES = {"__init__.py", "__init__.pyi", "py.typed"}

DIGEST = "sha256:" + "1" * 64
NEXT_DIGEST = "sha256:" + "2" * 64
RESPONSE = {
    "catalogRevision": DIGEST,
    "items": [
        {
            "recordId": "record-a",
            "bindingId": "urn:registrystack:discovery:binding:sha256:3a316636cd4b722c008a02dcf61633c7be64aa85bc9d3c20d932a0a2e8e06129",
            "serviceId": "urn:example:service:a",
            "serviceKind": "evidence",
            "title": "Evidence service",
            "description": "Issues minimum-disclosure evidence",
            "endpointUrl": "https://provider.example/evidence",
            "legalIssuerId": "urn:example:legal-issuer",
            "technicalProviderId": "urn:example:technical-provider",
            "jurisdictions": ["urn:example:jurisdiction"],
            "conformsTo": ["urn:example:profile"],
            "evidenceTypeIds": ["urn:example:evidence-type"],
            "semanticClassIds": [],
            "operationFamilyIds": [],
            "originId": "origin-a",
            "originUrl": "https://provider.example/catalog.jsonld",
            "originContentDigest": DIGEST,
            "originFetchedAt": "2026-08-15T00:00:00Z",
        }
    ],
}
REQUEST = {
    "recordId": "record-a",
    "matchedCapability": {
        "kind": "evidence-type",
        "id": "urn:example:evidence-type",
    },
}


def class_members(node: ast.ClassDef) -> set[str]:
    result: set[str] = set()
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.add("__new__" if item.name == "__init__" else item.name)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            result.add(item.target.id)
    return result


def live_class_members(cls: type) -> set[str]:
    return set(vars(cls)) - {"__doc__", "__module__"}


class DriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = ast.parse(STUB.read_text(encoding="utf-8"))
        self.stub_classes = {
            node.name: node
            for node in self.tree.body
            if isinstance(node, ast.ClassDef)
        }
        self.stub_functions = {
            node.name: node
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def test_runtime_and_stub_export_the_exact_function_and_class_surface(self) -> None:
        live_names = {name for name in dir(discovery) if not name.startswith("_")}
        self.assertEqual(live_names, RUNTIME_NAMES)
        self.assertEqual(
            set(self.stub_functions) & RUNTIME_NAMES,
            RUNTIME_FUNCTION_NAMES,
        )
        self.assertEqual(
            set(self.stub_classes) & RUNTIME_NAMES,
            RUNTIME_CLASS_NAMES,
        )
        for name in RUNTIME_FUNCTION_NAMES:
            with self.subTest(function=name):
                self.assertTrue(callable(getattr(discovery, name)))
        for name in RUNTIME_CLASS_NAMES:
            with self.subTest(cls=name):
                self.assertIsInstance(getattr(discovery, name), type)

    def test_client_methods_match_the_stub_in_both_directions(self) -> None:
        self.assertEqual(
            class_members(self.stub_classes["DiscoveryClient"]),
            live_class_members(discovery.DiscoveryClient),
        )

    def test_accepted_selection_properties_match_and_are_returned_only_by_acceptance(self) -> None:
        stub = self.stub_classes["AcceptedServiceSelection"]
        self.assertEqual(class_members(stub), {"endpoint_url", "selection"})
        self.assertEqual(
            live_class_members(discovery.AcceptedServiceSelection)
            - {"__class_getitem__"},
            {"endpoint_url", "selection"},
        )
        accepted_type = discovery.AcceptedServiceSelection[dict[str, object]]
        self.assertIs(
            typing.get_origin(accepted_type),
            discovery.AcceptedServiceSelection,
        )
        self.assertEqual(typing.get_args(accepted_type), (dict[str, object],))
        for item in stub.body:
            if isinstance(item, ast.FunctionDef):
                self.assertTrue(
                    any(
                        isinstance(decorator, ast.Name)
                        and decorator.id == "property"
                        for decorator in item.decorator_list
                    ),
                    f"{item.name} must remain a read-only property",
                )

        selection = discovery.select_exact(RESPONSE, REQUEST)
        accepted = discovery.accept_selection(selection, lambda candidate: candidate == selection)
        self.assertIsInstance(accepted, discovery.AcceptedServiceSelection)
        self.assertEqual(accepted.endpoint_url, selection["endpointUrl"])
        self.assertEqual(accepted.selection, selection)

    def test_structural_validation_alias_and_renewal_are_live_and_typed(self) -> None:
        selection = discovery.select_exact(RESPONSE, REQUEST)
        self.assertEqual(
            discovery.validate_selection(selection),
            discovery.validate_selection_structure(selection),
        )
        legacy_docstring = ast.get_docstring(self.stub_functions["validate_selection"])
        self.assertIsNotNone(legacy_docstring)
        self.assertIn("Deprecated", legacy_docstring)
        self.assertIn("Deprecated", discovery.validate_selection.__doc__)

        current = {
            **selection,
            "catalogRevision": NEXT_DIGEST,
            "originContentDigest": NEXT_DIGEST,
            "originFetchedAt": "2026-08-25T00:00:00Z",
        }
        self.assertEqual(
            discovery.renew_unchanged_selection(selection, current),
            current,
        )
        with self.assertRaises(discovery.DiscoveryClientError) as caught:
            discovery.renew_unchanged_selection(
                selection,
                {
                    **current,
                    "legalIssuerId": "urn:example:legal-issuer:other",
                },
            )
        self.assertEqual(caught.exception.kind, "selection_changed")

    def test_error_attributes_and_inheritance_are_pinned(self) -> None:
        self.assertEqual(
            class_members(self.stub_classes["DiscoveryClientError"]),
            ERROR_ATTRIBUTES,
        )
        self.assertTrue(issubclass(discovery.DiscoveryClientError, Exception))

    def test_pep_561_marker_and_package_contents_are_pinned(self) -> None:
        package_files = {
            path.name for path in PACKAGE.iterdir() if path.is_file()
        }
        self.assertEqual(package_files, EXPECTED_PACKAGE_FILES)
        self.assertEqual(
            (PACKAGE / "py.typed").read_text(encoding="utf-8").strip(),
            "",
            "the complete typed package must not be marked partial",
        )
        self.assertTrue((CRATE / "pyproject.toml").is_file())
        self.assertTrue((CRATE / "README.md").is_file())
        self.assertTrue((CRATE / "LICENSE").is_file())
        package_initializer = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("from .registry_discovery_client import *", package_initializer)


if __name__ == "__main__":
    unittest.main()
