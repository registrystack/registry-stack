#!/usr/bin/env python3
"""Regression checks for nightly planning and the actual workflow commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from ci_changes import SHARDS
from nightly_rust_coverage import coverage_matrix, main


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/nightly-rust-coverage.yml"


def shell_step(name: str) -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    step = workflow.split(f"      - name: {name}\n", 1)[1]
    body = step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    return textwrap.dedent(body)


class NightlyCoverageTests(unittest.TestCase):
    def test_all_live_shards_have_stable_flags_and_owned_packages(self) -> None:
        entries = coverage_matrix()["include"]
        expected_flags = {
            "discovery": "discovery",
            "platform": "platform",
            "manifest": "manifest-unit",
            "relay-client": "relay-client",
            "relay-v2": "relay-v2",
            "breg": "breg",
            "casework": "casework",
            "stack-client": "stack-client",
            "evidence": "evidence",
            "developer-tools": "developer-tools",
        }
        self.assertEqual({entry["name"]: entry["flag"] for entry in entries}, expected_flags)
        self.assertEqual([entry["name"] for entry in entries], list(SHARDS))
        for entry in entries:
            with self.subTest(shard=entry["name"]):
                self.assertEqual(entry["packages"].split(), list(SHARDS[entry["name"]]))
                self.assertEqual(entry["features"], "")
                self.assertEqual(
                    entry["all_features"],
                    str(entry["name"] in {"platform", "relay-v2"}).lower(),
                )

    def test_plan_validates_locked_metadata_and_appends_github_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            output.write_text("existing=value\n", encoding="utf-8")
            with (
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                patch("nightly_rust_coverage.subprocess.run") as run,
                patch("nightly_rust_coverage.Workspace") as workspace,
            ):
                run.return_value.stdout = '{"metadata": "fixture"}'
                main()
                run.assert_called_once_with(
                    ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
                    check=True, capture_output=True, text=True,
                )
                workspace.assert_called_once_with({"metadata": "fixture"})
            lines = output.read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[0], "existing=value")
            self.assertEqual(json.loads(lines[1].removeprefix("matrix=")), coverage_matrix())
        self.assertIn(
            "run: python3 .github/scripts/nightly_rust_coverage.py",
            WORKFLOW.read_text(encoding="utf-8"),
        )

    def test_invalid_workspace_does_not_publish_a_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with (
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                patch("nightly_rust_coverage.subprocess.run") as run,
                patch("nightly_rust_coverage.Workspace", side_effect=ValueError("stale")),
            ):
                run.return_value.stdout = "{}"
                with self.assertRaisesRegex(ValueError, "stale"):
                    main()
            self.assertFalse(output.exists())

    def test_workflow_cargo_commands_for_every_shard(self) -> None:
        # Execute the owning shell, recording argv instead of compiling Rust.
        # This detects shell argument drift in both test and export steps.
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            cargo = temporary / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['CARGO_COMMAND_LOG'], 'a') as log:\n"
                "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            log = temporary / "commands.jsonl"
            for entry in coverage_matrix()["include"]:
                with self.subTest(shard=entry["name"]):
                    log.write_text("", encoding="utf-8")
                    env = {
                        **os.environ,
                        "PATH": f"{temporary}{os.pathsep}{os.environ['PATH']}",
                        "CARGO_COMMAND_LOG": str(log),
                        "CARGO_TARGET_DIR": str(temporary / "target"),
                        "COVERAGE_PACKAGES": entry["packages"],
                        "COVERAGE_ALL_FEATURES": entry["all_features"],
                        "COVERAGE_FEATURES": entry["features"],
                    }
                    for name in ("Run shard with coverage", "Export shard coverage"):
                        script = shell_step(name).replace("${{ matrix.name }}", entry["name"])
                        self.assertNotRegex(script, re.escape("${{"))
                        subprocess.run(["bash", "-c", script], env=env, check=True)
                    commands = [json.loads(line) for line in log.read_text().splitlines()]
                    packages = [arg for package in SHARDS[entry["name"]] for arg in ("-p", package)]
                    features = ["--all-features"] if entry["name"] in {"platform", "relay-v2"} else []
                    self.assertEqual(commands, [
                        ["llvm-cov", "clean", "--workspace"],
                        ["llvm-cov", "--locked", *packages, *features, "--no-report"],
                        ["llvm-cov", "report", "--locked", *packages],
                        ["llvm-cov", "report", "--locked", *packages, "--lcov", "--output-path",
                         str(temporary / "target/coverage" / f"{entry['name']}.lcov")],
                    ])


if __name__ == "__main__":
    unittest.main()
