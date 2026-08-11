from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-stable-surface-compatibility.py"

V2_ERROR_REFERENCE = """\
## Relay

### Response shape

| Member | Value |
| --- | --- |
| `type` | The problem type URI |
| `code` | The stable code string |

### Problem codes

| Code | Status | Title | Detail |
| --- | --- | --- | --- |
| `request.fields_invalid` | 400 | Field selection is invalid | field selection is invalid |
| `aggregate-data.denied` | 403 | Aggregate data access is not permitted | aggregate data access is not permitted |

### Reading the set

Prose that is not a table.

## Evidence Gateway

Evidence Gateway documents its own set elsewhere.
"""

LEGACY_ERROR_REFERENCE = """\
## Registry Notary
| Code | Meaning | Cause |
| --- | --- | --- |
| `notary.retired` | historical Notary error | x |
## Registry Relay
| Code | Meaning | Cause |
| --- | --- | --- |
| `auth.scope_denied` | required scope is missing | x |
"""


def load_module():
    spec = importlib.util.spec_from_file_location("stable_surface", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class StableSurfaceCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_only_the_problem_table_inside_the_relay_section_is_read(self) -> None:
        parsed = self.module.parse_error_registry(V2_ERROR_REFERENCE)

        self.assertEqual(
            {
                "request.fields_invalid": self.module.ErrorContract(
                    400, "Field selection is invalid", "field selection is invalid"
                ),
                "aggregate-data.denied": self.module.ErrorContract(
                    403,
                    "Aggregate data access is not permitted",
                    "aggregate data access is not permitted",
                ),
            },
            parsed,
            "the response-shape table, the prose, and the sections that point "
            "elsewhere carry no released code",
        )

    def test_a_code_may_carry_a_hyphen(self) -> None:
        self.assertIsNotNone(self.module.MACHINE_CODE.fullmatch("aggregate-data.too_large"))
        self.assertIsNone(self.module.MACHINE_CODE.fullmatch("AggregateData.too_large"))

    def test_a_malformed_problem_row_is_an_error_not_a_silent_skip(self) -> None:
        text = """\
## Relay

| Code | Status | Title | Detail |
| --- | --- | --- | --- |
| `request.fields_invalid` | 400 | Field selection is invalid |
"""
        with self.assertRaisesRegex(self.module.ContractError, "malformed problem row"):
            self.module.parse_error_registry(text)

    def test_a_code_documented_twice_is_an_error(self) -> None:
        text = """\
## Relay

| Code | Status | Title | Detail |
| --- | --- | --- | --- |
| `request.fields_invalid` | 400 | Field selection is invalid | one detail |
| `request.fields_invalid` | 400 | Field selection is invalid | another detail |
"""
        with self.assertRaisesRegex(self.module.ContractError, "documented more than once"):
            self.module.parse_error_registry(text)

    def test_an_error_reference_without_relay_codes_is_an_error(self) -> None:
        with self.assertRaisesRegex(self.module.ContractError, "no maintained Relay problem codes"):
            self.module.parse_error_registry("## Evidence Gateway\n\nNothing here.\n")

    def test_the_retired_relay_1_0_reference_is_recognized_not_parsed(self) -> None:
        self.assertTrue(self.module.is_legacy_error_registry(LEGACY_ERROR_REFERENCE))
        self.assertFalse(self.module.is_legacy_error_registry(V2_ERROR_REFERENCE))

    def test_error_additions_are_allowed_but_removal_and_change_are_not(self) -> None:
        old = {
            "request.fields_invalid": self.module.ErrorContract(
                400, "Field selection is invalid", "field selection is invalid"
            )
        }
        additive = {
            **old,
            "request.conflict": self.module.ErrorContract(
                409, "Request conflicts", "the request conflicts"
            ),
        }
        self.assertEqual([], self.module.compare_error_contracts(old, additive))
        self.assertIn(
            "released error code removed: request.fields_invalid",
            self.module.compare_error_contracts(old, {}),
        )
        for field, value in (
            ("status", 422),
            ("title", "A changed title"),
            ("detail", "a changed detail"),
        ):
            changed = {
                "request.fields_invalid": self.module.ErrorContract(
                    value if field == "status" else 400,
                    value if field == "title" else "Field selection is invalid",
                    value if field == "detail" else "field selection is invalid",
                )
            }
            errors = self.module.compare_error_contracts(old, changed)
            self.assertTrue(
                any(f"changed {field}" in error for error in errors),
                f"a changed {field} is a breaking change for a caller",
            )

    def test_metric_contract_is_anchored_in_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "metrics.rs"
            source.write_text(
                '# TYPE product_requests_total counter\\nmetric{{outcome=\\"{}\\"}}',
                encoding="utf-8",
            )
            contract = {
                "schema": "registry-stack.selected-metrics/v1",
                "release_line": 1,
                "metrics": [
                    {
                        "product": "registry-relay",
                        "name": "product_requests_total",
                        "type": "counter",
                        "meaning": "Completed requests.",
                        "labels": {"outcome": "Bounded outcome."},
                        "source": "metrics.rs",
                    }
                ],
            }
            validated = self.module.validate_metrics_contract(contract, root)
            self.assertIn(("registry-relay", "product_requests_total"), validated)
            contract["metrics"][0]["labels"] = {"route": "Raw route."}
            with self.assertRaisesRegex(self.module.ContractError, "selected label"):
                self.module.validate_metrics_contract(contract, root)

    def test_an_empty_metrics_list_is_a_valid_contract(self) -> None:
        contract = {
            "schema": "registry-stack.selected-metrics/v1",
            "release_line": 1,
            "metrics": [],
        }
        self.assertEqual({}, self.module.validate_metrics_contract(contract, ROOT))
        self.assertEqual({}, self.module._validate_metrics_shape_only(contract))

    def test_current_stable_surfaces_accept_only_maintained_products(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "metrics.rs"
            source.write_text("# TYPE retired_total counter\n", encoding="utf-8")
            contract = {
                "schema": "registry-stack.selected-metrics/v1",
                "release_line": 1,
                "metrics": [
                    {
                        "product": "registry-notary",
                        "name": "retired_total",
                        "type": "counter",
                        "meaning": "A retired metric.",
                        "labels": {},
                        "source": "metrics.rs",
                    }
                ],
            }
            with self.assertRaisesRegex(self.module.ContractError, "maintained product"):
                self.module.validate_metrics_contract(contract, root)

    def test_historical_notary_metrics_do_not_block_current_retirement(self) -> None:
        relay = {
            "product": "registry-relay",
            "name": "relay_requests_total",
            "type": "counter",
            "meaning": "Completed Relay requests.",
            "labels": {},
            "source": "relay.rs",
        }
        notary = {
            "product": "registry-notary",
            "name": "notary_requests_total",
            "type": "counter",
            "meaning": "Completed Notary requests.",
            "labels": {},
            "source": "notary.rs",
        }
        base = {
            (relay["product"], relay["name"]): relay,
            (notary["product"], notary["name"]): notary,
        }
        current = {(relay["product"], relay["name"]): relay}
        self.assertEqual([], self.module.compare_metrics_contracts(base, current))

    def test_metric_additions_are_allowed_but_protected_fields_do_not_change(self) -> None:
        metric = {
            "product": "registry-relay",
            "name": "requests_total",
            "type": "counter",
            "meaning": "Completed requests.",
            "labels": {"outcome": "Bounded outcome."},
            "source": "metrics.rs",
        }
        key = (metric["product"], metric["name"])
        self.assertEqual([], self.module.compare_metrics_contracts({key: metric}, {key: metric}))
        changed = {**metric, "type": "gauge"}
        errors = self.module.compare_metrics_contracts({key: metric}, {key: changed})
        self.assertTrue(any("changed type" in error for error in errors))
        self.assertTrue(self.module.compare_metrics_contracts({key: metric}, {}))

    def test_a_retired_metric_is_skipped_and_its_siblings_stay_protected(self) -> None:
        retired = next(iter(self.module.RETIRED_SELECTED_METRICS))
        sibling = (retired[0], "registry_relay_not_a_retired_family")
        metric = {
            "product": retired[0],
            "name": retired[1],
            "type": "counter",
            "meaning": "A Relay 1.0 family.",
            "labels": {},
            "source": "crates/registry-relay/src/observability.rs",
        }
        base = {retired: metric, sibling: {**metric, "name": sibling[1]}}

        errors = self.module.compare_metrics_contracts(base, {})

        self.assertEqual(
            [f"selected metric removed: {sibling[0]} {sibling[1]}"],
            errors,
            "only the recorded family is exempt; every other family under the "
            "same product is still guarded",
        )

    def test_every_retirement_record_states_why_the_family_went_away(self) -> None:
        for key, reason in self.module.RETIRED_SELECTED_METRICS.items():
            with self.subTest(metric=key):
                self.assertEqual(2, len(key), "a record names product and metric")
                self.assertIn(key[0], self.module.KNOWN_RELEASE_PRODUCTS)
                self.assertTrue(
                    reason.strip(), f"{' '.join(key)} was retired without a reason"
                )

    def test_every_retired_family_is_absent_from_the_current_contract(self) -> None:
        current = self.module.validate_metrics_contract(
            self.module.load_json(
                (ROOT / self.module.METRICS_CONTRACT).read_text(encoding="utf-8"),
                str(self.module.METRICS_CONTRACT),
            ),
            ROOT,
        )
        for key in self.module.RETIRED_SELECTED_METRICS:
            with self.subTest(metric=key):
                self.assertNotIn(
                    key,
                    current,
                    "a family recorded as retired must not also be claimed as current",
                )

    def test_real_current_contract_validates_without_a_base(self) -> None:
        self.assertEqual([], self.module.check(None, ROOT))


if __name__ == "__main__":
    unittest.main()
