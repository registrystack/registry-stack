#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused regression checks for Lab 2 source-dir and profile demos."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JUSTFILE = ROOT / "justfile"
DOCTOR_SCRIPT = ROOT / "scripts/lab2-doctor-profile.sh"
DOCTOR_SUMMARY = ROOT / "scripts/lab2_doctor_summary.py"
LAB2_GENERATE = ROOT / "scripts/lab2-generate-governed-config.sh"
LAB2_GENERATOR = ROOT / "tools/lab2-governed-config/src/main.rs"
DEMO_STORY = ROOT / "scripts/lab2-demo-story.sh"
COMMONS_CHECK = ROOT / "scripts/commons-check.sh"
WORKFLOW = ROOT / ".github/workflows/release-source-model.yml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def just_recipe(name: str) -> str:
    body = read(JUSTFILE)
    marker = f"\n{name}:"
    start = body.index(marker) + 1
    next_recipe = body.find("\n# ", start + len(marker))
    if next_recipe == -1:
        return body[start:]
    return body[start:next_recipe]


class Lab2MainFeatureTest(unittest.TestCase):
    def test_lab2_up_uses_exported_source_dirs_not_forced_vendor_paths(self) -> None:
        recipe = just_recipe("lab2-up")
        self.assertIn("docker compose -f compose.yaml -f compose.lab2.yaml build lab2-civil-registry-relay", recipe)
        self.assertIn("docker compose -f compose.yaml -f compose.lab2.yaml build lab2-civil-notary", recipe)
        self.assertNotIn("REGISTRY_RELAY_SOURCE_DIR=./vendor/registry-relay", recipe)
        self.assertNotIn("REGISTRY_NOTARY_SOURCE_DIR=./vendor/registry-notary", recipe)
        self.assertNotIn("REGISTRY_PLATFORM_SOURCE_DIR=./vendor/registry-platform", recipe)

    def test_lab2_generation_can_select_source_platform_checkout(self) -> None:
        body = read(LAB2_GENERATE)
        self.assertIn("REGISTRY_PLATFORM_SOURCE_DIR:-vendor/registry-platform", body)
        self.assertIn("registry-platform-config", body)
        self.assertIn("registry-platform-ops", body)
        self.assertIn("mktemp -d", body)
        self.assertIn("cargo run --quiet --manifest-path", body)

    def test_commons_check_defaults_to_monorepo_source_dirs(self) -> None:
        body = read(COMMONS_CHECK)
        self.assertIn('stack_root="${REGISTRY_STACK_SOURCE_DIR:-${lab_root}/..}"', body)
        self.assertIn('platform_dir="${REGISTRY_PLATFORM_SOURCE_DIR:-${stack_root}}"', body)
        self.assertIn('manifest_dir="${REGISTRY_MANIFEST_REPO:-${stack_root}}"', body)
        self.assertIn('relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-${stack_root}/crates/registry-relay}"', body)
        self.assertIn('notary_ci_dir="${notary_dir}/products/notary"', body)
        self.assertNotIn('${lab_root}/../registry-platform', body)
        self.assertNotIn('${lab_root}/../registry-relay', body)
        self.assertNotIn('${lab_root}/../registry-notary', body)

    def test_lab2_notary_rotation_uses_signing_key_not_stale_profile_id(self) -> None:
        body = read(LAB2_GENERATOR)
        self.assertIn("rotate_notary_credential_profile_signing_key", body)
        self.assertIn('"civil-evidence-demo"', body)
        self.assertNotIn('["evidence", "credential_profiles", "civil_status_sd_jwt"]', body)

    def test_lab2_doctor_recipe_and_script_capture_product_profile_reports(self) -> None:
        recipe = just_recipe("lab2-doctor")
        self.assertIn("scripts/lab2-doctor-profile.sh", recipe)
        self.assertTrue(os.access(DOCTOR_SCRIPT, os.X_OK), "doctor script must be executable")

        script = read(DOCTOR_SCRIPT)
        self.assertIn("LAB2_DOCTOR_PROFILE:-hosted_lab", script)
        self.assertIn("LAB2_DOCTOR_STRICT:-0", script)
        self.assertIn("registry-relay", script)
        self.assertIn("doctor", script)
        self.assertIn("--profile", script)
        self.assertIn("registry-notary", script)
        self.assertIn("summary-${profile}.json", script)
        self.assertIn("scripts/lab2_doctor_summary.py", script)

    def test_doctor_summary_strict_mode_fails_on_active_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            relay = tmp_path / "relay.json"
            notary = tmp_path / "notary.json"
            summary = tmp_path / "summary.json"

            relay.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "deployment_profile": {"value": "hosted_lab", "source": "override"},
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )
            notary.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "deployment_profile": {"value": "hosted_lab", "source": "override"},
                        "diagnostics": [
                            {"status": "passed", "severity": "info", "code": "ok"},
                            {
                                "status": "active",
                                "severity": "finding_warn",
                                "code": "notary.openapi.public",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(DOCTOR_SUMMARY),
                    "--profile",
                    "hosted_lab",
                    "--strict",
                    "--relay-status",
                    "0",
                    "--relay-report",
                    str(relay),
                    "--notary-status",
                    "0",
                    "--notary-report",
                    str(notary),
                    "--summary",
                    str(summary),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(0, result.returncode)
            report = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(1, report["reports"][1]["finding_count"])

    def test_doctor_summary_strict_mode_allows_passed_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            relay = tmp_path / "relay.json"
            notary = tmp_path / "notary.json"
            summary = tmp_path / "summary.json"

            relay.write_text(json.dumps({"ok": True, "findings": []}), encoding="utf-8")
            notary.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "diagnostics": [
                            {"status": "passed", "severity": "info", "code": "ok"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(DOCTOR_SUMMARY),
                    "--profile",
                    "hosted_lab",
                    "--strict",
                    "--relay-status",
                    "0",
                    "--relay-report",
                    str(relay),
                    "--notary-status",
                    "0",
                    "--notary-report",
                    str(notary),
                    "--summary",
                    str(summary),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(0, report["reports"][0]["finding_count"])
            self.assertEqual(0, report["reports"][1]["finding_count"])

    def test_narrated_demo_includes_profile_doctor_evidence(self) -> None:
        body = read(DEMO_STORY)
        self.assertIn("Deployment-profile doctor reports make lab posture visible", body)
        self.assertIn("LAB2_DOCTOR_PROFILE=hosted_lab", body)
        self.assertIn("doctor/summary-hosted_lab.json", body)

    def test_release_source_model_workflow_runs_when_lab2_wiring_changes(self) -> None:
        body = read(WORKFLOW)
        for path in (
            "justfile",
            "compose.lab2.yaml",
            "scripts/lab2-generate-governed-config.sh",
            "scripts/lab2-doctor-profile.sh",
            "scripts/lab2_doctor_summary.py",
            "scripts/lab2-demo-story.sh",
            "scripts/test_lab2_main_features.py",
        ):
            self.assertIn(path, body)
        self.assertIn("python scripts/test_lab2_main_features.py", body)


if __name__ == "__main__":
    unittest.main()
