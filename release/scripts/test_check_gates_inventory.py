#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-gates-inventory.py"


def load_module():
    spec = importlib.util.spec_from_file_location("check_gates_inventory", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_real_ci_workflow_declares_inventory(self) -> None:
        self.assertEqual([], self.module.missing_gates(self.workflow))

    def test_missing_relay_exposure_gate_is_reported(self) -> None:
        text = self.workflow.replace("name: Relay exposure check", "name: Relay exposure")
        self.assertIn("Relay exposure check", self.module.missing_gates(text))

    def test_missing_registryctl_tutorial_execution_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: npm run check:tutorial:registryctl",
            "run: npm run execute-registryctl-tutorial",
        )
        self.assertIn(
            "Registryctl tutorial source execution", self.module.missing_gates(text)
        )

    def test_missing_release_docset_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "release/scripts/registry-release validate-docsets",
            "release/scripts/registry-release skip-docsets",
        )
        self.assertIn("Release docset validation", self.module.missing_gates(text))

    def test_missing_openid_conformance_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_openid_conformance_runner.py",
            "python3 release/scripts/openid-conformance-runner.py list",
        )
        self.assertIn(
            "OpenID conformance runner tests", self.module.missing_gates(text)
        )

    def test_missing_stable_surface_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/check-stable-surface-compatibility.py",
            "run: python3 release/scripts/skip-stable-surface-compatibility.py",
        )
        self.assertIn("Stable surface compatibility", self.module.missing_gates(text))

    def test_missing_relay_openapi_stability_filter_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_filter_relay_openapi_stability.py",
            "run: python3 -m unittest release/scripts/skip_filter_relay_openapi_stability.py",
        )
        self.assertIn("Relay OpenAPI stability filter tests", self.module.missing_gates(text))

    def test_missing_openapi_base_reference_is_reported(self) -> None:
        text = self.workflow.replace(
            "OPENAPI_CONTRACT_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.before }}",
            "OPENAPI_CONTRACT_BASE_REF: disabled",
        )
        self.assertIn("OpenAPI base-reference input", self.module.missing_gates(text))

    def test_missing_upgrade_exercise_template_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/validate-upgrade-exercise.py --template",
            "python3 release/scripts/validate-upgrade-exercise.py --skip-template",
        )
        self.assertIn(
            "Upgrade exercise template validation", self.module.missing_gates(text)
        )

    def test_missing_stable_error_registry_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "docs/site/src/content/docs/reference/errors.mdx)",
            "docs/site/src/content/docs/reference/removed-errors.mdx)",
        )
        self.assertIn("Stable error registry path filter", self.module.missing_gates(text))

    def test_missing_relay_support_roster_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "docs/site/src/data/relay-support.yaml|docs/site/src/data/generated/relay-support.json)",
            "docs/site/src/data/removed-relay-support.yaml)",
        )
        self.assertIn("Relay support roster path filter", self.module.missing_gates(text))

    def test_missing_registryctl_tutorial_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "registryctl_tutorial: ${{ steps.filter.outputs.registryctl_tutorial }}",
            "registryctl_tutorial_disabled: ${{ steps.filter.outputs.registryctl_tutorial }}",
        )
        self.assertIn("Registryctl tutorial path filter", self.module.missing_gates(text))


if __name__ == "__main__":
    unittest.main()
