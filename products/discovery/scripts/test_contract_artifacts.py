#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
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

    def test_openapi_problem_variants_pin_runtime_code_and_detail(self) -> None:
        document = json.loads((ROOT.parents[1] / "crates/registry-discovery/openapi.json").read_text())
        expected = {
            "invalid-request": ("request.invalid", "The Discovery request is invalid."),
            "not-found": ("request.not-found", "The requested Discovery resource was not found."),
            "result-bound-exceeded": ("request.result-bound-exceeded", "The complete Discovery result exceeds its configured bound."),
            "unavailable": ("service.unavailable", "Registry Discovery is temporarily unavailable."),
        }
        variants = document["components"]["schemas"]["Problem"]["oneOf"]
        self.assertEqual(len(variants), len(expected))
        for variant in variants:
            properties = variant["properties"]
            suffix = properties["type"]["const"].rsplit("/", 1)[1]
            with self.subTest(problem=suffix):
                code, detail = expected[suffix]
                self.assertEqual(properties["code"].get("const"), code)
                self.assertEqual(properties["detail"].get("const"), detail)

    def test_openapi_problem_responses_declare_bounded_traceparent(self) -> None:
        document = json.loads((ROOT.parents[1] / "crates/registry-discovery/openapi.json").read_text())
        for name, response in document["components"]["responses"].items():
            with self.subTest(response=name):
                header = response.get("headers", {}).get("traceparent", {})
                self.assertTrue(header.get("required"))
                self.assertEqual(header.get("schema", {}).get("maxLength"), 55)
                self.assertIn("pattern", header.get("schema", {}))
                pattern = header["schema"]["pattern"]
                self.assertRegex("00-11111111111111111111111111111111-2222222222222222-01", pattern)
                for invalid in [
                    "00-00000000000000000000000000000000-2222222222222222-01",
                    "00-11111111111111111111111111111111-0000000000000000-01",
                    "01-11111111111111111111111111111111-2222222222222222-01",
                ]:
                    self.assertNotRegex(invalid, pattern)

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
