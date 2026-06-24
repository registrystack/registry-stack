#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "PyYAML>=6.0",
# ]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Focused regression checks for Registry Lab built-in sidecar wiring.

The DHIS2 and civil sidecars now use the built-in http_json engine instead of
the OpenFn Node worker pool. Local and hosted demo Notary configs use the
current source_adapter_sidecar connector spelling.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
LOCAL_COMPOSE = ROOT / "compose.yaml"
HOSTED_COMPOSE = ROOT / "compose.coolify.yaml"
LOCAL_CIVIL_NOTARY = ROOT / "config/notary/openfn-civil-notary.yaml"
LOCAL_DHIS2_NOTARY = ROOT / "config/notary/dhis2-health-notary.yaml"
HOSTED_DHIS2_NOTARY = ROOT / "config/coolify/notary/dhis2-health-notary.yaml"
HOSTED_OPENFN_TEMPLATE = ROOT / "config/coolify/openfn/openfn-dhis2-sidecar.yaml.template"
HOSTED_OPENFN_BOOTSTRAP = ROOT / "config/coolify/openfn/openfn-dhis2-sidecar.bootstrap.yaml"
# Primary smoke scripts (shims smoke-openfn.sh / smoke-dhis2-openfn.sh delegate here).
LOCAL_CIVIL_SMOKE = ROOT / "scripts/smoke-civil.sh"
LOCAL_DHIS2_SMOKE = ROOT / "scripts/smoke-dhis2.sh"
README = ROOT / "README.md"
HOSTED_OPENFN_REPORT = ROOT / "config/coolify/openfn/governed/openfn-dhis2-sidecar-runtime.report.json"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def claim_source_bindings(path: Path) -> list[dict[str, object]]:
    config = yaml.safe_load(read(path))
    claims = config["evidence"]["claims"]
    return [
        binding
        for claim in claims
        for binding in claim["source_bindings"].values()
    ]


class BuiltinSidecarLabConfigTest(unittest.TestCase):
    def test_local_sidecars_use_unsigned_dev_escape_hatch(self) -> None:
        body = read(LOCAL_COMPOSE)
        # Both civil and DHIS2 sidecars still use --allow-unsigned-dev-config
        # (built-in engine manifests are unsigned dev configs for local demo use).
        self.assertGreaterEqual(body.count("--allow-unsigned-dev-config"), 2)
        self.assertIn("--config /etc/registry-notary-source-adapter/civil-sidecar.yaml", body)
        self.assertIn("--config /etc/registry-notary-source-adapter/dhis2-health-sidecar.yaml", body)

    def test_local_sidecars_point_to_built_in_manifests(self) -> None:
        body = read(LOCAL_COMPOSE)
        self.assertIn("config/source-adapter/civil-sidecar.yaml", body)
        self.assertIn("config/source-adapter/dhis2-health-sidecar.yaml", body)

    def test_hosted_openfn_sidecar_uses_governed_bootstrap(self) -> None:
        body = read(HOSTED_COMPOSE)
        self.assertIn("/etc/registry-notary-openfn/openfn-dhis2-sidecar.bootstrap.yaml", body)
        self.assertIn("openfn-sidecar-tuf-state:/var/lib/registry-notary-openfn-sidecar/tuf", body)
        self.assertIn("openfn-sidecar-config-state:/var/lib/registry-notary-openfn-sidecar/config-trust", body)
        self.assertIn("openfn-sidecar-audit-state:/var/lib/registry-notary-openfn-sidecar/audit", body)
        self.assertNotIn("cfg-openfn-jobs:/tmp/registry-lab-openfn-jobs:ro", body)
        self.assertNotIn("/tmp/registry-lab-openfn-jobs", body)
        hosted_service = body.split("  openfn-dhis2-sidecar:", 1)[1].split("\n  dhis2-health-notary:", 1)[0]
        self.assertNotIn("--allow-unsigned-dev-config", hosted_service)

        bootstrap = read(HOSTED_OPENFN_BOOTSTRAP)
        self.assertIn("audit:", bootstrap)
        self.assertIn("sink: file", bootstrap)
        self.assertIn(
            "path: /var/lib/registry-notary-openfn-sidecar/audit/dhis2-openfn-sidecar-audit.jsonl",
            bootstrap,
        )
        self.assertIn("hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET", bootstrap)

    def test_smoke_scripts_mirror_just_source_defaults(self) -> None:
        for path in (LOCAL_CIVIL_SMOKE, LOCAL_DHIS2_SMOKE):
            body = read(path)
            self.assertIn('default_source_dir "../registry-notary" "vendor/registry-notary"', body)
            self.assertIn("REGISTRY_OPENFN_NOTARY_SOURCE_DIR", body)
            self.assertIn('default_source_dir "../registry-platform" "vendor/registry-platform"', body)

    def test_openfn_notary_bindings_use_sidecar_connector(self) -> None:
        civil_bindings = claim_source_bindings(LOCAL_CIVIL_NOTARY)
        self.assertEqual(1, len(civil_bindings))
        self.assertEqual("openfn_civil", civil_bindings[0]["connection"])
        self.assertEqual("source_adapter_sidecar", civil_bindings[0]["connector"])

        local_dhis2_bindings = claim_source_bindings(LOCAL_DHIS2_NOTARY)
        self.assertEqual(9, len(local_dhis2_bindings))
        self.assertEqual(
            {"dhis2_openfn"},
            {binding["connection"] for binding in local_dhis2_bindings},
        )
        self.assertEqual(
            {"source_adapter_sidecar"},
            {binding["connector"] for binding in local_dhis2_bindings},
        )

        hosted_dhis2_bindings = claim_source_bindings(HOSTED_DHIS2_NOTARY)
        self.assertEqual(9, len(hosted_dhis2_bindings))
        self.assertEqual(
            {"dhis2_openfn"},
            {binding["connection"] for binding in hosted_dhis2_bindings},
        )
        self.assertEqual(
            {"source_adapter_sidecar"},
            {binding["connector"] for binding in hosted_dhis2_bindings},
        )

    def test_hosted_notary_pins_generated_sidecar_hash(self) -> None:
        report = json.loads(read(HOSTED_OPENFN_REPORT))
        notary = read(HOSTED_DHIS2_NOTARY)
        config_hash = report["config_hash"]
        self.assertIn("expected_sidecar:", notary)
        self.assertIn("instance_id: hosted-dhis2-openfn-sidecar", notary)
        self.assertIn("stream_id: dhis2-openfn-sidecar-runtime", notary)
        self.assertIn("require_expression_hashes_verified: true", notary)
        self.assertIn("require_runtime_verified: true", notary)
        self.assertIn("require_smoke_verified: true", notary)
        self.assertIn(f"config_hash: {config_hash}", notary)

    def test_hosted_dhis2_runtime_keeps_lookup_value_as_match_key(self) -> None:
        body = read(HOSTED_OPENFN_TEMPLATE)
        self.assertIn('"tracked_entity": lookup.value', body)
        self.assertIn('"reconciliation_ref": \'dhis2:tracked-entity:\' + body.trackedEntities[0].trackedEntity', body)

    def test_lab_readme_names_sidecar_connector(self) -> None:
        body = read(README)
        normalized = " ".join(body.split())
        self.assertIn("Registry Notary `source_adapter_sidecar` connector", normalized)
        self.assertNotIn("Registry Notary `registry_data_api` connector", body)


if __name__ == "__main__":
    unittest.main()
