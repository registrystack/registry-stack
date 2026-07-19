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
                        "product": "registry-notary",
                        "name": "product_requests_total",
                        "type": "counter",
                        "meaning": "Completed requests.",
                        "labels": {"outcome": "Bounded outcome."},
                        "source": "metrics.rs",
                    }
                ],
            }
            validated = self.module.validate_metrics_contract(contract, root)
            self.assertIn(("registry-notary", "product_requests_total"), validated)
            contract["metrics"][0]["labels"] = {"route": "Raw route."}
            with self.assertRaisesRegex(self.module.ContractError, "selected label"):
                self.module.validate_metrics_contract(contract, root)

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

    def test_real_current_contract_validates_without_a_base(self) -> None:
        self.assertEqual([], self.module.check(None, ROOT))


if __name__ == "__main__":
    unittest.main()
