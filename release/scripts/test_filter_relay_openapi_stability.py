from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "filter-relay-openapi-stability.py"


def load_module():
    spec = importlib.util.spec_from_file_location("filter_relay_openapi_stability", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def roster_entry(
    entry_id: str,
    *,
    stability: str,
    policy: str,
    token: str | None = None,
    media_type: str | None = None,
):
    entry = {
        "id": entry_id,
        "category": "aggregate_output",
        "stability_tier": stability,
        "feature_frozen": stability == "experimental",
        "canonical_release": stability == "stable",
        "openapi_policy": policy,
    }
    if token is not None and media_type is not None:
        entry["openapi_selectors"] = {
            "format_tokens": [token],
            "media_types": [media_type],
        }
    return entry


class RelayOpenapiStabilityFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.roster = [
            roster_entry("json-output", stability="stable", policy="included"),
            roster_entry(
                "csv-output",
                stability="experimental",
                policy="included_unstable",
                token="csv",
                media_type="text/csv",
            ),
            roster_entry(
                "sdmx-output",
                stability="experimental",
                policy="included_unstable",
                token="sdmx-json",
                media_type="application/vnd.sdmx.data+json;version=2.1",
            ),
        ]
        aggregate_operation = {
            "get": {
                "parameters": [
                    {
                        "name": "f",
                        "schema": {"enum": ["json", "csv", "sdmx-json"]},
                    }
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"type": "object"}},
                            "text/csv": {"schema": {"type": "string"}},
                            "application/vnd.sdmx.data+json;version=2.1": {
                                "schema": {"type": "object"}
                            },
                        }
                    }
                },
            }
        }
        self.document = {
            "openapi": "3.1.0",
            "paths": {
                "/v1/datasets/{dataset_id}/aggregates/{aggregate_id}": aggregate_operation,
                "/v1/datasets/{dataset_id}/entities/{entity}/records/{record_id}": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {"schema": {"type": "object"}}
                                }
                            }
                        }
                    }
                },
            },
        }

    def test_roster_selectors_remove_only_unstable_aggregate_representations(self) -> None:
        filtered = self.module.filter_openapi(self.document, self.roster)
        operation = filtered["paths"]["/v1/datasets/{dataset_id}/aggregates/{aggregate_id}"][
            "get"
        ]
        self.assertEqual(["json"], operation["parameters"][0]["schema"]["enum"])
        self.assertEqual(
            {"application/json"}, set(operation["responses"]["200"]["content"])
        )
        self.assertIn(
            "/v1/datasets/{dataset_id}/entities/{entity}/records/{record_id}",
            filtered["paths"],
        )
        self.assertEqual(
            self.document["paths"][
                "/v1/datasets/{dataset_id}/entities/{entity}/records/{record_id}"
            ],
            filtered["paths"][
                "/v1/datasets/{dataset_id}/entities/{entity}/records/{record_id}"
            ],
        )

    def test_filter_has_no_hard_coded_format_list(self) -> None:
        roster = [
            roster_entry(
                "future-output",
                stability="experimental",
                policy="included_unstable",
                token="future-format",
                media_type="application/vnd.example.future",
            )
        ]
        document = {
            "paths": {
                "/v1/aggregates/example": {
                    "get": {
                        "parameters": [{"schema": {"enum": ["json", "future-format"]}}],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {},
                                    "application/vnd.example.future": {},
                                }
                            }
                        },
                    }
                }
            }
        }
        filtered = self.module.filter_openapi(document, roster)
        operation = filtered["paths"]["/v1/aggregates/example"]["get"]
        self.assertEqual(["json"], operation["parameters"][0]["schema"]["enum"])
        self.assertEqual({"application/json"}, set(operation["responses"]["200"]["content"]))

    def test_stable_roster_surface_cannot_be_downgraded(self) -> None:
        base = [roster_entry("json-output", stability="stable", policy="included")]
        current = [
            roster_entry(
                "json-output",
                stability="experimental",
                policy="included_unstable",
                token="json",
                media_type="application/json",
            )
        ]
        errors = self.module.compare_rosters(base, current)
        self.assertTrue(any("downgraded" in error for error in errors))
        self.assertTrue(any("excluded" in error for error in errors))

    def test_included_unstable_entry_requires_authoritative_selectors(self) -> None:
        invalid = [
            roster_entry("csv-output", stability="experimental", policy="included_unstable")
        ]
        with self.assertRaisesRegex(self.module.RosterError, "exact OpenAPI selectors"):
            self.module.filter_openapi(self.document, invalid)


if __name__ == "__main__":
    unittest.main()
