#!/usr/bin/env python3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = {
    "products/casework/scripts/check-checkpoint.sh": (
        "CASEWORKCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_prepare_cargo_runtime",
    ),
    "products/casework/scripts/check-review-journeys.sh": (
        "CASEWORK_BIN",
        "CASEWORKCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/breg/scripts/test-adopter-workflow.sh": (
        "BREG_BIN",
        "BREGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/breg/scripts/test-historical-workflow.sh": (
        "BREG_BIN",
        "BREGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "registry_prepare_cargo_runtime",
    ),
    "products/scheduling/scripts/check-checkpoint.sh": (
        "SCHEDULINGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_prepare_cargo_runtime",
    ),
    "products/messaging/scripts/check-checkpoint.sh": (
        "MESSAGINGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/evidence/scripts/check-authoring-no-io.sh": ("CLIPPY_DRIVER_BIN",),
    "products/discovery/scripts/test-adopter-tutorial.sh": (
        "DISCOVERY_BIN",
        "DISCOVERYCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "registry_prepare_cargo_runtime",
    ),
    "products/relay-v2/scripts/check-generated.sh": (
        "RELAYCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
}


class CargoRuntimeScriptContractTests(unittest.TestCase):
    def test_every_reported_gate_keeps_its_runtime_and_override_contract(self):
        self.assertEqual(len(CONTRACTS), 9)
        for relative, markers in CONTRACTS.items():
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
