#!/usr/bin/env python3
"""Focused tests for the adopter-runtime Compose conformance checker."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_adopter_compose_contract.py")
SPEC = importlib.util.spec_from_file_location("adopter_compose_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AdopterComposeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = {
            "services": {
                name: {
                    "labels": {
                        "io.registrystack.probe.owner": "renderer",
                    }
                }
                for name in CHECKER.PRODUCT_SERVICES
            }
        }

    def test_ordinary_model_rejects_initialization_service(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["registry-initialize-notary"] = {}
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exactly the five governed services"
        ):
            CHECKER.assert_ordinary_model(model)

    def test_parent_boundary_rejects_private_network_member(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "networks": {"registry-private": None}
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "private network"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_private_namespace_member(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "network_mode": "service:registry-private-namespace"
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "private namespace"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_any_private_service_namespace(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "network_mode": "service:registry-notary"
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "private namespace"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_container_namespace_mode(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "network_mode": "container:registry-adopter-probe-registry-notary-1"
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "private namespace"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_resolves_private_network_alias(self) -> None:
        baseline = json.loads(json.dumps(self.baseline))
        baseline["networks"] = {
            "registry-private": {"name": "registry-adopter-probe-private"}
        }
        model = json.loads(json.dumps(baseline))
        model["networks"]["parent-alias"] = {
            "name": "registry-adopter-probe-private"
        }
        model["services"]["parent-private-client"] = {
            "networks": {"parent-alias": None}
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "private network"):
            CHECKER.assert_parent_boundary(
                model,
                baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_renderer_owned_resources(self) -> None:
        baseline = json.loads(json.dumps(self.baseline))
        baseline["secrets"] = {
            "registry-notary-signing-key": {
                "name": "registry-adopter-probe_registry-notary-signing-key"
            }
        }
        baseline["volumes"] = {
            "registry-notary-state": {
                "name": "registry-adopter-probe_registry-notary-state"
            }
        }
        model = json.loads(json.dumps(baseline))
        model["services"]["parent-private-client"] = {
            "secrets": [{"source": "registry-notary-signing-key"}],
            "volumes": [
                {
                    "type": "volume",
                    "source": "registry-notary-state",
                    "target": "/state",
                }
            ],
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "renderer-owned secret"):
            CHECKER.assert_parent_boundary(
                model,
                baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_volumes_from_product(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "volumes_from": ["registry-notary:ro"]
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "inherited"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_parent_boundary_rejects_container_volumes_from(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "volumes_from": [
                "container:registry-adopter-probe-registry-notary-1"
            ]
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "inherited"):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent="parent-private-client",
            )

    def test_negative_fixture_rejects_mixed_private_boundaries(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["parent-private-client"] = {
            "networks": {"registry-private": None},
            "network_mode": "service:registry-private-namespace",
        }
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "also joined the private namespace",
        ):
            CHECKER.assert_negative_boundary(
                model,
                self.baseline,
                "private-network",
            )
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "also joined the private network",
        ):
            CHECKER.assert_negative_boundary(
                model,
                self.baseline,
                "private-namespace",
            )

    def test_parent_boundary_rejects_product_mutation(self) -> None:
        model = json.loads(json.dumps(self.baseline))
        model["services"]["registry-notary"]["labels"]["parent"] = "mutation"
        with self.assertRaisesRegex(
            CHECKER.ContractError, "changed renderer-owned service"
        ):
            CHECKER.assert_parent_boundary(
                model,
                self.baseline,
                expected_parent=None,
            )

    def test_initialization_model_rejects_ordinary_service_mutation(self) -> None:
        ordinary = json.loads(json.dumps(self.baseline))
        initialized = json.loads(json.dumps(ordinary))
        for name in CHECKER.INITIALIZATION_SERVICES:
            initialized["services"][name] = {
                "image": "example.invalid/probe@sha256:" + "a" * 64,
            }
        initialized["services"]["registry-notary"]["image"] = (
            "example.invalid/mutated@sha256:" + "b" * 64
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "initialization file changed ordinary service registry-notary",
        ):
            CHECKER.assert_initialization_model(
                initialized,
                ordinary,
                {
                    name: "example.invalid/probe@sha256:" + "a" * 64
                    for name in CHECKER.PRODUCT_SERVICES
                },
            )

    def test_plan_probe_is_complete_and_renderer_independent(self) -> None:
        CHECKER.validate_plan(
            CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json"
        )

    def test_plan_probe_rejects_changed_recovery_action(self) -> None:
        plan = json.loads(
            (
                CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json"
            ).read_text(encoding="utf-8")
        )
        plan["workloads"][0]["reactivation_action"] = "arbitrary"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaisesRegex(CHECKER.ContractError, "reactivation_action"):
                CHECKER.validate_plan(path)

    def test_plan_probe_rejects_compose_volume_syntax(self) -> None:
        plan = json.loads(
            (
                CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json"
            ).read_text(encoding="utf-8")
        )
        plan["workloads"][0]["volumes"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaisesRegex(CHECKER.ContractError, "volumes"):
                CHECKER.validate_plan(path)

    def test_minimum_compose_download_is_checksum_pinned(self) -> None:
        wrapper = SCRIPT.with_suffix(".sh").read_text(encoding="utf-8")
        self.assertIn("COMPOSE_MINIMUM_VERSION=\"2.35.0\"", wrapper)
        self.assertIn(
            "dba1915cf2f282527f5df0cd7a94b9503047ed200317801853abe8f22c8cd493",
            wrapper,
        )
        self.assertIn("actual != expected", wrapper)


if __name__ == "__main__":
    unittest.main()
