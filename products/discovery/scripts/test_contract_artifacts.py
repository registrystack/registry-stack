#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_contract_artifacts.py"
SPEC = importlib.util.spec_from_file_location("validate_contract_artifacts", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load contract validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ContractArtifactsTest(unittest.TestCase):
    def test_profile_and_security_contracts_are_valid(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_executable_binding_without_test_attribute_is_refused(self) -> None:
        source = "#[test]\nfn bound_refusal() {}\n"
        VALIDATOR.require_executable_test(source, "bound_refusal", "fixture.rs")
        without_attribute = source.replace("#[test]\n", "")
        with self.assertRaisesRegex(ValueError, "lacks a test attribute"):
            VALIDATOR.require_executable_test(
                without_attribute, "bound_refusal", "fixture.rs"
            )

    def test_python_binding_without_discoverable_test_name_is_refused(self) -> None:
        source = "class BoundTests:\n    def test_bound_refusal(self):\n        pass\n"
        VALIDATOR.require_executable_test(
            source, "test_bound_refusal", "fixture.py"
        )
        without_test_name = source.replace("test_bound_refusal", "bound_refusal")
        with self.assertRaisesRegex(ValueError, "is not discoverable"):
            VALIDATOR.require_executable_test(
                without_test_name, "test_bound_refusal", "fixture.py"
            )

    def test_javascript_binding_without_discoverable_test_name_is_refused(self) -> None:
        source = "test('bound refusal', () => {});\n"
        VALIDATOR.require_executable_test(source, "bound refusal", "fixture.js")
        without_test_name = source.replace("bound refusal", "other refusal")
        with self.assertRaisesRegex(ValueError, "is not discoverable"):
            VALIDATOR.require_executable_test(
                without_test_name, "bound refusal", "fixture.js"
            )


if __name__ == "__main__":
    unittest.main()
