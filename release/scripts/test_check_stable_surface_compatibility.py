from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-stable-surface-compatibility.py"


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

    def test_error_registry_requires_one_stack_wide_meaning(self) -> None:
        text = """\
## Registry Notary
| Code | Meaning | Cause |
| --- | --- | --- |
| `auth.scope_denied` | required scope is missing | x |
## Registry Relay
| Code | Meaning | Cause |
| --- | --- | --- |
| `auth.scope_denied` | scope denied | x |
"""
        with self.assertRaisesRegex(self.module.ContractError, "stack-wide meaning"):
            self.module.parse_error_registry(text)

    def test_retired_notary_errors_do_not_enter_the_current_contract(self) -> None:
        text = """\
## Registry Notary
| Code | Meaning | Cause |
| --- | --- | --- |
| `notary.retired` | historical Notary error | x |
## Registry Relay
| Code | Meaning | Cause |
| --- | --- | --- |
| `relay.active` | maintained Relay error | x |
"""
        self.assertEqual(
            {
                "relay.active": self.module.ErrorContract(
                    "maintained Relay error", frozenset({"registry-relay"})
                )
            },
            self.module.parse_error_registry(text),
        )

    def test_error_additions_are_allowed_but_removal_and_change_are_not(self) -> None:
        old = {
            "request.invalid": self.module.ErrorContract(
                "request is invalid", frozenset({"registry-notary", "registry-relay"})
            )
        }
        additive = {
            **old,
            "request.conflict": self.module.ErrorContract(
                "request conflicts", frozenset({"registry-notary"})
            ),
        }
        self.assertEqual([], self.module.compare_error_contracts(old, additive))
        self.assertIn(
            "released error code removed: request.invalid",
            self.module.compare_error_contracts(old, {}),
        )
        changed = {
            "request.invalid": self.module.ErrorContract(
                "different meaning", frozenset({"registry-notary"})
            )
        }
        errors = self.module.compare_error_contracts(old, changed)
        self.assertTrue(any("meaning changed" in error for error in errors))
        self.assertTrue(any("removed from: registry-relay" in error for error in errors))

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

    def test_current_stable_surfaces_accept_only_maintained_products(self) -> None:
        self.assertEqual({"registry-relay"}, set(self.module.OPENAPI_SPECS))
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

    def test_openapi_error_mapping_removal_is_breaking(self) -> None:
        document = {
            "paths": {
                "/v1/items": {
                    "get": {
                        "responses": {
                            "404": {
                                "content": {
                                    "application/problem+json": {
                                        "example": {"code": "item.not_found"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        mapping = self.module.openapi_error_mappings(document, "registry-relay")
        self.assertEqual(1, len(mapping))
        errors = self.module.compare_openapi_mappings(mapping, set())
        self.assertEqual(1, len(errors))
        self.assertIn("item.not_found", errors[0])

    def diagnostic_entry(self, code: str = "registryctl.authoring.test") -> dict:
        return {
            "family": "authoring_validation",
            "code": code,
            "owner": "registryctl",
            "product": "registryctl",
            "phase": "static_validation",
            "safe_meaning": "The authored project failed a static rule.",
            "rule": "authored project must satisfy the closed static rule",
            "safe_remediation": "Correct the reviewed authored field and retry.",
            "field_address_pattern": None,
            "evidence_scope": "offline authored project files",
            "secret_sensitive_value_policy": "no_received_value",
            "docs_anchor": f"/reference/diagnostics/authoring/#registryctl--{code}",
            "lifecycle": "unreleased",
            "introduced_in": None,
            "stability": "pre1_stable_code",
            "evidence_limitation": "Static evidence does not prove live compatibility.",
        }

    def diagnostic_catalog(self, *entries: dict) -> dict:
        return {
            "schema_version": "registryctl.authoring_error_reference.v1",
            "entries": list(entries),
        }

    def test_diagnostic_additions_are_allowed_but_removal_and_semantic_drift_are_not(
        self,
    ) -> None:
        key = ("authoring_validation", "registryctl", "registryctl.authoring.test")
        old = {
            key: self.module.DiagnosticContract(
                "registryctl",
                "The authored project failed a static rule.",
                "authored project must satisfy the closed static rule",
                "/reference/diagnostics/authoring/#registryctl--registryctl.authoring.test",
            )
        }
        additive = {
            **old,
            (
                "authoring_validation",
                "registryctl",
                "registryctl.authoring.second",
            ): self.module.DiagnosticContract(
                "registryctl",
                "A second static meaning.",
                "a second static rule",
                "/reference/diagnostics/authoring/#registryctl--registryctl.authoring.second",
            ),
        }
        self.assertEqual([], self.module.compare_diagnostic_contracts(old, additive))
        self.assertTrue(self.module.compare_diagnostic_contracts(old, {}))
        for field, value in (
            ("owner", "registry_relay"),
            ("safe_meaning", "A changed meaning."),
            ("rule", "a changed rule"),
            (
                "docs_anchor",
                "/reference/diagnostics/authoring/#registryctl--registryctl.authoring.changed",
            ),
        ):
            changed = {
                key: self.module.DiagnosticContract(
                    value if field == "owner" else old[key].owner,
                    value if field == "safe_meaning" else old[key].safe_meaning,
                    value if field == "rule" else old[key].rule,
                    value if field == "docs_anchor" else old[key].docs_anchor,
                )
            }
            errors = self.module.compare_diagnostic_contracts(old, changed)
            self.assertTrue(any(f"changed {field}" in error for error in errors))

    def test_historical_notary_diagnostics_do_not_block_current_retirement(self) -> None:
        key = ("notary_activation", "registry_notary", "registry_notary.retired")
        base = {
            key: self.module.DiagnosticContract(
                "registry_notary",
                "The retired Notary activation failed.",
                "the historical activation must satisfy the retired rule",
                "/reference/diagnostics/operator/#registry_notary--retired",
            )
        }
        self.assertEqual([], self.module.compare_diagnostic_contracts(base, {}))

    def test_diagnostic_catalog_rejects_shape_duplicates_reordering_and_lifecycle_drift(
        self,
    ) -> None:
        valid = self.diagnostic_catalog(self.diagnostic_entry())
        result = self.module.validate_diagnostic_catalog(valid, "authoring")
        self.assertEqual(1, len(result))

        malformed = self.diagnostic_catalog(self.diagnostic_entry())
        malformed["entries"][0]["unexpected"] = True
        with self.assertRaisesRegex(self.module.ContractError, "strict entry shape"):
            self.module.validate_diagnostic_catalog(malformed, "authoring")

        duplicate = self.diagnostic_catalog(
            self.diagnostic_entry(),
            self.diagnostic_entry(),
        )
        with self.assertRaisesRegex(self.module.ContractError, "duplicate"):
            self.module.validate_diagnostic_catalog(duplicate, "authoring")

        reordered = self.diagnostic_catalog(
            self.diagnostic_entry("registryctl.authoring.z"),
            self.diagnostic_entry("registryctl.authoring.a"),
        )
        with self.assertRaisesRegex(self.module.ContractError, "not ordered"):
            self.module.validate_diagnostic_catalog(reordered, "authoring")

        stale = self.diagnostic_catalog(self.diagnostic_entry())
        stale["entries"][0]["introduced_in"] = "0.13.0"
        with self.assertRaisesRegex(self.module.ContractError, "introduced_in: null"):
            self.module.validate_diagnostic_catalog(stale, "authoring")

        reassigned = self.diagnostic_catalog(self.diagnostic_entry())
        reassigned["entries"][0]["owner"] = "registry_relay"
        with self.assertRaisesRegex(self.module.ContractError, "product-owner"):
            self.module.validate_diagnostic_catalog(reassigned, "authoring")

    def test_real_current_contract_validates_without_a_base(self) -> None:
        self.assertEqual([], self.module.check(None, ROOT))


if __name__ == "__main__":
    unittest.main()
