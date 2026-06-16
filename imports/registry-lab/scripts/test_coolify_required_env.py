#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the Coolify required-env pre-deploy gate."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "check-coolify-required-env.py"


def load_script():
    spec = importlib.util.spec_from_file_location("check_coolify_required_env", SCRIPT_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CoolifyRequiredEnvTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = load_script()

    def test_reads_required_keys_from_compose_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "compose.yaml"
            compose.write_text(
                "x-coolify-required-env:\n  - TOKEN_B\n  - TOKEN_A\n  - TOKEN_A\n",
                encoding="utf-8",
            )
            self.assertEqual(["TOKEN_A", "TOKEN_B"], self.script.required_env_keys(compose))

    def test_registry_lab_gate_includes_social_notary_source_token(self) -> None:
        compose = SCRIPT_DIR.parent / "compose.coolify.yaml"
        keys = self.script.required_env_keys(compose)
        self.assertIn("SOCIAL_EVIDENCE_SOURCE_RAW", keys)

    def test_registry_lab_gate_includes_agri_homepage_token(self) -> None:
        compose = SCRIPT_DIR.parent / "compose.coolify.yaml"
        keys = self.script.required_env_keys(compose)
        self.assertIn("AGRI_EVIDENCE_CLIENT_BEARER", keys)

    def test_collects_values_from_coolify_list_payload(self) -> None:
        values = self.script.collect_env_values(
            [
                {"key": "TOKEN_A", "value": "secret"},
                {"key": "TOKEN_B", "value": ""},
                {"name": "TOKEN_C", "real_value": "masked"},
            ]
        )
        self.assertEqual("secret", values["TOKEN_A"])
        self.assertEqual("", values["TOKEN_B"])
        self.assertEqual("masked", values["TOKEN_C"])

    def test_ignores_preview_values(self) -> None:
        values = self.script.collect_env_values(
            [
                {"key": "TOKEN_A", "value": "preview-secret", "is_preview": True},
                {"key": "TOKEN_B", "value": "prod-secret", "is_preview": False},
            ]
        )
        self.assertEqual({"TOKEN_B": "prod-secret"}, values)

    def test_collects_values_from_wrapped_payload(self) -> None:
        values = self.script.collect_env_values({"data": [{"key": "TOKEN_A", "value": "secret"}]})
        self.assertEqual({"TOKEN_A": "secret"}, values)

    def test_reports_missing_and_empty_required_keys(self) -> None:
        missing = self.script.missing_required_keys(
            ["TOKEN_A", "TOKEN_B", "TOKEN_C"],
            {"TOKEN_A": "secret", "TOKEN_B": ""},
        )
        self.assertEqual(["TOKEN_B", "TOKEN_C"], missing)


if __name__ == "__main__":
    unittest.main()
