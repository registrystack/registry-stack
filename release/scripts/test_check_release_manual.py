#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-release-manual.py"
MANUAL = ROOT / "release" / "MANUAL.md"


def load_module():
    spec = importlib.util.spec_from_file_location("check_release_manual", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseManualCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_repository_manual_examples_match_public_cli(self) -> None:
        result = self.module.check_manual(MANUAL)
        self.assertEqual([], result["errors"])
        self.assertEqual("passed", result["status"])
        self.assertEqual(
            [
                "prepare",
                "validate",
                "validate-docsets",
                "audit",
                "finalize",
                "validate-source",
                "verify-published",
                "collect-evidence-bundle",
                "render-release-closeout",
            ],
            [entry["command"] for entry in result["commands_checked"]],
        )

    def test_multiline_example_and_variables_are_normalized(self) -> None:
        argv = self.module.example_argv(
            "release/scripts/registry-release prepare \\\n"
            '  --version "${version}" \\\n'
            '  --release-id "$release_id"'
        )
        self.assertEqual(
            ["prepare", "--version", "example", "--release-id", "example"],
            argv,
        )

    def test_unknown_option_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manual = Path(temp_dir) / "MANUAL.md"
            manual.write_text(
                "<!-- registry-release-check -->\n"
                "```bash\n"
                "release/scripts/registry-release prepare --version 1.2.3 "
                "--release-id beta-1 --silent-policy-choice\n"
                "```\n",
                encoding="utf-8",
            )
            result = self.module.check_manual(manual)
        self.assertEqual("failed", result["status"])
        self.assertTrue(any("not accepted" in error for error in result["errors"]))

    def test_unmarked_or_missing_command_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manual = Path(temp_dir) / "MANUAL.md"
            manual.write_text("```bash\necho no release command\n```\n", encoding="utf-8")
            result = self.module.check_manual(manual)
        self.assertEqual("failed", result["status"])
        self.assertIn("no marked", result["errors"][0])

    def test_cli_output_is_stable_json(self) -> None:
        first = subprocess.run(
            [str(SCRIPT), "--manual", str(MANUAL)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        second = subprocess.run(
            [str(SCRIPT), "--manual", str(MANUAL)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(first, second)
        self.assertEqual("passed", json.loads(first)["status"])


if __name__ == "__main__":
    unittest.main()
