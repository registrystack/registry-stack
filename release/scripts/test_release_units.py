#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
from unittest import TestCase, main


SCRIPT = Path(__file__).with_name("release_units.py")


def load_module():
    spec = importlib.util.spec_from_file_location("release_units", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseUnitsTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_registry_maps_every_approved_release_unit(self) -> None:
        registry = self.module.load_registry()
        self.assertEqual(
            {
                "breg-casework-evidence",
                "breg-mcp",
                "breg-review",
                "clients",
                "coordinator",
                "discovery",
                "evidence-oid4vci",
                "manifest",
                "messaging",
                "render",
                "scheduling",
            },
            set(registry.names),
        )
        self.assertEqual("discovery", registry.require_pilot("discovery").name)
        for held in set(registry.names) - {"discovery"}:
            with self.subTest(unit=held):
                with self.assertRaisesRegex(
                    self.module.UnitRegistryError, "not enabled for the release pilot"
                ):
                    registry.require_pilot(held)

    def test_discovery_identity_and_candidate_roster_are_unit_scoped(self) -> None:
        self.assertEqual("v1.2.3", self.module.asset_tag("1.2.3"))
        self.assertEqual(
            "discovery/v1.2.3", self.module.release_tag("discovery", "1.2.3")
        )
        self.assertEqual(
            "registry-discovery-v1.2.3-candidate.tar.gz",
            self.module.candidate_bundle_name("discovery", "1.2.3"),
        )
        self.assertEqual(
            "registry-discovery-v1.2.3-release-manifest.json",
            self.module.public_manifest_name("discovery", "1.2.3"),
        )
        self.assertEqual(
            "registry-discovery-v1.2.3.sbom.spdx.json",
            self.module.sbom_name("discovery", "1.2.3"),
        )
        self.assertEqual(
            "registry-discovery-v1.2.3-security-evidence.tar.gz",
            self.module.security_evidence_name("discovery", "1.2.3"),
        )
        self.assertEqual(
            {
                "THIRD_PARTY_NOTICES": "notice",
                "discovery-install.sh": "installer",
                "discovery-v1.2.3-install.sh": "installer",
                "discovery-v1.2.3-linux-amd64": "binary",
                "discoveryctl-v1.2.3-linux-amd64": "binary",
                "registry-discovery-v1.2.3-security-evidence.tar.gz": "security-evidence",
                "registry-discovery-v1.2.3.sbom.spdx.json": "sbom",
            },
            self.module.payload_inventory("discovery", "1.2.3"),
        )
        self.assertEqual({"discovery"}, self.module.image_names("discovery"))

    def test_registry_parser_is_closed_and_rejects_duplicate_members(self) -> None:
        registry = json.loads(self.module.REGISTRY_PATH.read_text(encoding="utf-8"))
        discovery = registry["units"]["discovery"]
        discovery["unknown"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "units.yaml"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.UnitRegistryError, "must contain exactly"
            ):
                self.module.load_registry(path)

        del discovery["unknown"]
        discovery["members"].append(discovery["members"][0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "units.yaml"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.UnitRegistryError, "must not contain duplicates"
            ):
                self.module.load_registry(path)

    def test_unknown_unit_and_noncanonical_version_are_refused(self) -> None:
        with self.assertRaisesRegex(self.module.UnitRegistryError, "unknown release unit"):
            self.module.release_tag("unknown", "1.2.3")
        for version in ("v1.2.3", "01.2.3", "1.2", "1.2.3-dev"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(
                    self.module.UnitRegistryError, "canonical semantic version"
                ):
                    self.module.asset_tag(version)

    def test_current_stack_payloads_have_one_declared_owner(self) -> None:
        candidate_script = SCRIPT.with_name("release_candidate.py")
        spec = importlib.util.spec_from_file_location(
            "release_candidate_for_unit_ownership", candidate_script
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load module spec from {candidate_script}")
        candidate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(candidate)
        registry = self.module.load_registry()
        for name in candidate._release_payload_inventory("0.45.0"):
            with self.subTest(name=name):
                self.assertIn(
                    registry.artifact_owner(name),
                    set(registry.names) | {"distribution"},
                )
        self.assertEqual("clients", registry.artifact_owner("registrystack-client-0.45.0.tgz"))
        self.assertEqual("clients", registry.artifact_owner("registry_stack_client-0.45.0-cp311-abi3-manylinux.whl"))
        self.assertEqual("distribution", registry.artifact_owner("registry-docs-v0.45.0.tar.gz"))
        self.assertEqual("distribution", registry.artifact_owner("rstack-v0.45.0-linux-amd64"))
        self.assertEqual("distribution", registry.artifact_owner("rstack-install.sh"))
        self.assertEqual(
            ("docs", "editors/vscode", "editors/zed", "rstack"),
            registry.distribution_members,
        )


if __name__ == "__main__":
    main()
