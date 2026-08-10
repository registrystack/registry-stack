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

    def test_each_operation_requires_a_declared_default_representation(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_social_lookup_default(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "registry.yaml" and path.parent.name == "social-assistance":
                value["resources"][0]["operations"]["lookups"][0].pop(
                    "defaultRepresentation"
                )
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_social_lookup_default):
            VALIDATOR.validate_acceptance_representation_contracts(errors)
        self.assertTrue(
            any("every declared operation needs one declared default representation" in error for error in errors),
            errors,
        )

    def test_social_quota_fixture_is_bound_to_the_pre_quota_journey(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_social_quota_drift(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "runtime.yaml" and path.parent.name == "social-assistance":
                value["quotas"]["burst"] = 11
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_social_quota_drift):
            VALIDATOR.validate_acceptance_representation_contracts(errors)
        self.assertTrue(
            any("quota fixture must admit exactly" in error for error in errors), errors
        )

    def test_civil_lookup_quota_fixture_is_bound_to_the_pre_quota_journey(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_civil_quota_drift(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "runtime.yaml" and path.parent.name == "civil-event":
                value["quotas"]["burst"] = 7
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_civil_quota_drift):
            VALIDATOR.validate_acceptance_representation_contracts(errors)
        self.assertTrue(
            any("lookup quota fixture must admit exactly" in error for error in errors), errors
        )

    def test_invalid_source_row_scenario_must_match_the_executable_failure(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unresolved_source_row(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                scenario = next(
                    item for item in value["scenarios"] if item.get("invalidSourceRowClass")
                )
                scenario["expectedStatus"] = 404
                scenario["expectedCode"] = "consultation.unresolved"
            return value

        errors: list[str] = []
        with mock.patch.object(
            VALIDATOR, "load_yaml", side_effect=load_with_unresolved_source_row
        ):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(
            any("must expect 503 source.unavailable" in error for error in errors), errors
        )
        self.assertTrue(
            any("expectation disagrees with the journey" in error for error in errors), errors
        )

    def test_invalid_transform_scenario_must_remain_a_source_failure(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unresolved_transform(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                scenario = next(
                    item
                    for item in value["scenarios"]
                    if item.get("id") == "social-invalid-transform"
                )
                scenario["expectedStatus"] = 404
                scenario["expectedCode"] = "consultation.unresolved"
            return value

        errors: list[str] = []
        with mock.patch.object(
            VALIDATOR, "load_yaml", side_effect=load_with_unresolved_transform
        ):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(
            any("must expect 503 source.unavailable" in error for error in errors), errors
        )

    def test_both_bounded_transforms_require_a_failure_scenario(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_civil_transform_scenario(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                scenario = next(
                    item
                    for item in value["scenarios"]
                    if item.get("id") == "civil-invalid-transform"
                )
                scenario["id"] = "civil-transform-failure-renamed"
            return value

        errors: list[str] = []
        with mock.patch.object(
            VALIDATOR, "load_yaml", side_effect=load_without_civil_transform_scenario
        ):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(
            any("both bounded transforms require" in error for error in errors), errors
        )

    def test_unknown_and_scope_hidden_representations_share_one_outcome(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_enumerable_unknown_representation(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "expected-http.yaml" and path.parent.name == "social-assistance":
                step = next(
                    item
                    for item in value["steps"]
                    if item.get("id") == "unknown-representation"
                )
                step["expect"]["code"] = "representation.not_found"
            return value

        errors: list[str] = []
        with mock.patch.object(
            VALIDATOR, "load_yaml", side_effect=load_with_enumerable_unknown_representation
        ):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(
            any("must conceal representation existence" in error for error in errors), errors
        )

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

    def test_security_inventory_rejects_a_deleted_invariant(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_one_invariant(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"].pop()
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_one_invariant):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(any("closed invariant inventory" in error for error in errors), errors)

    def test_security_inventory_rejects_empty_required_evidence(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_empty_fields(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"][0]["threat"] = ""
                value["invariants"][0]["enforcementPoint"] = ""
                value["invariants"][0]["expected"] = ""
                value["invariants"][0]["evidence"] = ""
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_empty_fields):
            VALIDATOR.validate_catalogs(errors)
        for field in ("threat", "enforcementPoint", "expected", "evidence"):
            self.assertTrue(any(f".{field}:" in error for error in errors), errors)

    def test_security_inventory_requires_an_exact_negative_test(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unknown_negative(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"][0]["negativeTest"] = "not_a_listed_test"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_unknown_negative):
            VALIDATOR.validate_catalogs(errors)
        self.assertTrue(any("select one exact listed negative test" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
