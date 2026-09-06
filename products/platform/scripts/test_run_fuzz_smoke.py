#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "products" / "platform" / "scripts" / "run-fuzz-smoke.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
FUZZ_MANIFEST = ROOT / "products" / "platform" / "fuzz" / "Cargo.toml"


class PlatformFuzzRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp_root = Path(self.temporary.name)
        self.product_dir = self.temp_root / "products" / "platform"
        script_dir = self.product_dir / "scripts"
        script_dir.mkdir(parents=True)
        self.runner = script_dir / RUNNER.name
        shutil.copy2(RUNNER, self.runner)

        self.fake_bin = self.temp_root / "bin"
        self.fake_bin.mkdir()
        self.log = self.temp_root / "cargo.jsonl"
        fake_cargo = self.fake_bin / "cargo"
        fake_cargo.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys

with open(os.environ["FAKE_CARGO_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"cwd": os.getcwd(), "argv": sys.argv[1:]}) + "\\n")

target = sys.argv[8]
raise SystemExit(17 if target in os.environ.get("FAKE_CARGO_FAILURES", "").split() else 0)
""",
            encoding="utf-8",
        )
        fake_cargo.chmod(0o755)

    def run_runner(
        self, *targets: str, failures: tuple[str, ...] = ()
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_CARGO_LOG"] = str(self.log)
        env["FAKE_CARGO_FAILURES"] = " ".join(failures)
        return subprocess.run(
            [str(self.runner), *targets],
            cwd=self.temp_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def cargo_calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def expected_args(self, target: str) -> list[str]:
        return [
            "+nightly",
            "fuzz",
            "run",
            "--fuzz-dir",
            "fuzz",
            "--target",
            "x86_64-unknown-linux-gnu",
            target,
            "--",
            "-max_total_time=60",
            "-rss_limit_mb=1024",
            f"-artifact_prefix=fuzz/artifacts/{target}/",
            "-print_final_stats=1",
        ]

    def test_success_runs_each_target_with_exact_context_and_arguments(self) -> None:
        targets = ("authcommon_parsers", "sqlite_statement")
        result = self.run_runner(*targets)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            [
                {
                    "cwd": os.path.realpath(self.product_dir),
                    "argv": self.expected_args(target),
                }
                for target in targets
            ],
            self.cargo_calls(),
        )
        for target in targets:
            self.assertTrue((self.product_dir / "fuzz" / "artifacts" / target).is_dir())

    def test_failure_is_aggregated_after_every_target_is_attempted(self) -> None:
        targets = ("sdjwt_holder_proof", "sdjwt_issuance")
        result = self.run_runner(*targets, failures=(targets[0],))

        self.assertEqual(1, result.returncode)
        self.assertEqual(
            [self.expected_args(target) for target in targets],
            [call["argv"] for call in self.cargo_calls()],
        )
        self.assertIn(f"platform fuzz target failed: {targets[0]} (exit 17)", result.stderr)
        self.assertIn(f"platform fuzz smoke failed for: {targets[0]}", result.stderr)

    def test_invalid_or_duplicate_roster_is_rejected_before_execution(self) -> None:
        cases = (
            (
                ("authcommon_parsers", "unknown_target"),
                "unknown platform fuzz target: unknown_target",
            ),
            (
                ("authcommon_parsers", "authcommon_parsers"),
                "duplicate platform fuzz target: authcommon_parsers",
            ),
        )
        for targets, message in cases:
            with self.subTest(targets=targets):
                self.log.unlink(missing_ok=True)
                result = self.run_runner(*targets)
                self.assertEqual(2, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertEqual([], self.cargo_calls())


class PlatformFuzzWorkflowTest(unittest.TestCase):
    def test_pr_matrix_runs_every_declared_fuzz_target_once_in_two_pairs(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        strategy = workflow["jobs"]["platform-fuzz"]["strategy"]
        matrix = strategy["matrix"]["include"]
        pairs = [(entry["target_a"], entry["target_b"]) for entry in matrix]
        flattened = [target for pair in pairs for target in pair]

        manifest = tomllib.loads(FUZZ_MANIFEST.read_text(encoding="utf-8"))
        declared = [binary["name"] for binary in manifest["bin"]]

        self.assertIs(False, strategy["fail-fast"])
        self.assertEqual(
            {
                ("authcommon_parsers", "sqlite_statement"),
                ("sdjwt_holder_proof", "sdjwt_issuance"),
            },
            set(pairs),
        )
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertCountEqual(declared, flattened)


if __name__ == "__main__":
    unittest.main()
