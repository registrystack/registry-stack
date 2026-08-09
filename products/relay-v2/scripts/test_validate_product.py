#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("validate_product.py")
SPEC = importlib.util.spec_from_file_location("relay_v2_validate_product", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class RelayV2ProductCatalogTests(unittest.TestCase):
    def test_tracked_product_catalog_is_internally_complete(self) -> None:
        self.assertEqual([], VALIDATOR.validate_all())

    def test_scenario_matrix_must_bind_one_exact_journey_step(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unknown_step(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                value["scenarios"][0]["journeyStep"] = "not-a-step"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_unknown_step):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(any("exact journey step" in error for error in errors), errors)

    def test_journey_authorization_references_must_resolve(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unknown_authorization(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "expected-http.yaml" and path.parent.name == "civil-event":
                value["steps"][0]["authorizationFixture"] = "unknown-fixture"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_unknown_authorization):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(any("unknown authorization fixture" in error for error in errors), errors)

    def test_each_registry_must_keep_an_invalid_source_row_refusal(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_business_invalid_row(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                for scenario in value["scenarios"]:
                    if scenario.get("project") == "business-registry":
                        scenario.pop("invalidSourceRowClass", None)
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_business_invalid_row):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(
            any("business-registry: at least one invalid source-row refusal" in error for error in errors),
            errors,
        )

    def test_acceptance_must_cover_all_four_invalid_source_row_classes(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_excessive_size(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                for scenario in value["scenarios"]:
                    if scenario.get("invalidSourceRowClass") == "excessive-size":
                        scenario["invalidSourceRowClass"] = "missing-required"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_excessive_size):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(any("invalid source-row classes must cover" in error for error in errors), errors)

    def test_security_test_resolution_rejects_a_similar_prefix(self) -> None:
        errors: list[str] = []
        VALIDATOR.executable_test_resolves(
            {
                "path": "crates/registry-relay-v2/src/contract.rs",
                "name": "runtime_rejects_governed_override_extra",
            },
            "test reference",
            errors,
        )
        self.assertEqual(1, len(errors), errors)
        self.assertIn("exact executable test does not resolve", errors[0])

    def test_security_test_resolution_accepts_the_exact_annotated_function(self) -> None:
        errors: list[str] = []
        VALIDATOR.executable_test_resolves(
            {
                "path": "crates/registry-relay-v2/src/contract.rs",
                "name": "runtime_rejects_governed_override",
            },
            "test reference",
            errors,
        )
        self.assertEqual([], errors)

    def test_unannotated_function_is_not_executable_evidence(self) -> None:
        errors: list[str] = []
        VALIDATOR.executable_test_resolves(
            {
                "path": "crates/registry-relay-v2/src/contract.rs",
                "name": "valid_secret_reference",
            },
            "test reference",
            errors,
        )
        self.assertEqual(1, len(errors), errors)
        self.assertIn("exact executable test does not resolve", errors[0])


if __name__ == "__main__":
    unittest.main()
