#!/usr/bin/env python3
"""Prove grouped PostgreSQL lanes preserve the owned test/feature inventory."""

from __future__ import annotations

from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("breg_postgres_inventory", SCRIPT_DIR / "validate_product.py")
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
RUNNER = SCRIPT_DIR / "test-postgres.sh"


class PostgresRunnerTests(unittest.TestCase):
    def run_lane(self, *arguments: str, database: bool = True, fail: bool = False, fail_build: bool = False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "cargo.jsonl"
            cargo = root / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['BREG_RUNNER_TEST_LOG'], 'a') as log:\n"
                "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "sys.exit(17 if os.environ.get('BREG_RUNNER_TEST_FAIL') == '1' else 0)\n",
                encoding="utf-8",
            )
            cargo.write_text(cargo.read_text().replace(
                "sys.exit(17 if", "if sys.argv[1] == 'build':\n"
                "    if os.environ.get('BREG_RUNNER_TEST_FAIL_BUILD') == '1': sys.exit(19)\n"
                "    print(json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'evidence'}, 'executable': os.environ['BREG_RUNNER_TEST_BINARY']}))\n"
                "if '--test' in sys.argv and 'postgres_action_evidence' in sys.argv:\n"
                "    assert os.environ.get('BREG_TEST_EVIDENCE_BINARY') == os.environ['BREG_RUNNER_TEST_BINARY']\n"
                "    assert os.environ.get('BREG_RUNNER_TEST_PYYAML') == '1'\n"
                "sys.exit(17 if"
            ))
            cargo.chmod(0o755)
            evidence = root / "configured target with spaces" / "debug" / "evidence"
            evidence.parent.mkdir(parents=True)
            evidence.write_text("#!/bin/sh\nexit 0\n")
            evidence.chmod(0o755)
            uv = root / "uv"
            uv.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "assert sys.argv[1:5] == ['run', '--no-project', '--with', 'PyYAML==6.0.2']\n"
                "os.environ['BREG_RUNNER_TEST_PYYAML'] = '1'\n"
                "os.execvp(sys.argv[5], sys.argv[5:])\n"
            )
            uv.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                PATH=f"{root}{os.pathsep}{environment['PATH']}",
                BREG_RUNNER_TEST_LOG=str(log),
                BREG_RUNNER_TEST_BINARY=str(evidence),
                BREG_RUNNER_TEST_FAIL="1" if fail else "0",
                BREG_RUNNER_TEST_FAIL_BUILD="1" if fail_build else "0",
            )
            environment.pop("BREG_TEST_DATABASE_URL", None)
            if database:
                environment["BREG_TEST_DATABASE_URL"] = "postgresql://fixture.invalid/test"
            result = subprocess.run(
                [str(RUNNER), *arguments], env=environment,
                capture_output=True, text=True, check=False,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def inventory(self, calls):
        commands = []
        for call in calls:
            if call[0] == "build":
                self.assertEqual(["build", "--locked", "-p", "registry-evidence", "--bin", "evidence", "--message-format=json"], call)
                continue
            self.assertEqual(["test", "--locked", "-p", "registry-breg", "--features"], call[:5])
            targets = call[6:]
            self.assertTrue(targets)
            self.assertEqual(0, len(targets) % 2)
            self.assertTrue(all(flag == "--test" for flag in targets[::2]))
            commands.extend(" ".join(["cargo", *call[:6], "--test", target]) for target in targets[1::2])
        return Counter(commands)

    def test_default_and_partition_preserve_every_owned_target_and_feature_set(self):
        default_result, default = self.run_lane()
        explicit_result, explicit = self.run_lane("--lane", "all")
        ordinary_result, ordinary = self.run_lane("--lane", "postgres")
        action_result, actions = self.run_lane("--lane", "immediate-actions")
        for result in (default_result, explicit_result, ordinary_result, action_result):
            self.assertEqual(0, result.returncode, result.stderr)
        expected = Counter(VALIDATOR.POSTGRES_TEST_COMMANDS)
        self.assertEqual(expected, self.inventory(default))
        self.assertEqual(default, explicit)
        self.assertEqual(expected, self.inventory(ordinary) + self.inventory(actions))
        self.assertFalse(self.inventory(ordinary) & self.inventory(actions))
        self.assertEqual(6, len(ordinary))
        self.assertEqual(7, len(default))
        self.assertEqual([shlex.split(
            "test --locked -p registry-breg --features postgres-test --test postgres_immediate_actions"
        )], actions)

    def test_real_evidence_build_precedes_proof_and_is_absent_from_action_lane(self):
        result, calls = self.run_lane("--lane", "postgres")
        self.assertEqual(0, result.returncode, result.stderr)
        builds = [index for index, call in enumerate(calls) if call[0] == "build"]
        self.assertEqual(1, len(builds))
        proof = next(index for index, call in enumerate(calls) if "postgres_action_evidence" in call)
        self.assertLess(builds[0], proof)
        self.assertIn("postgres_action_evidence_targets", calls[proof])
        result, calls = self.run_lane("--lane", "immediate-actions")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(any(call[0] == "build" for call in calls))

    def test_evidence_build_failure_prevents_proof_instead_of_skipping_real_runtime(self):
        result, calls = self.run_lane("--lane", "postgres", fail_build=True)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("build", calls[-1][0])
        self.assertFalse(any("postgres_action_evidence" in call for call in calls))

    def test_invalid_selection_refuses_before_cargo(self):
        for arguments in (
            ("--lane",), ("--lane", ""), ("--lane", "unknown"), ("postgres",),
            ("--lane", "postgres", "extra"), ("--lane", "postgres", "--lane", "all"),
        ):
            with self.subTest(arguments=arguments):
                result, calls = self.run_lane(*arguments)
                self.assertEqual(2, result.returncode)
                self.assertIn("Usage:", result.stderr)
                self.assertEqual([], calls)

    def test_each_lane_requires_database_and_propagates_cargo_failure(self):
        for lane in ("all", "postgres", "immediate-actions"):
            with self.subTest(lane=lane):
                result, calls = self.run_lane("--lane", lane, database=False)
                self.assertEqual(2, result.returncode)
                self.assertIn("BREG_TEST_DATABASE_URL must be set", result.stderr)
                self.assertEqual([], calls)
                result, calls = self.run_lane("--lane", lane, fail=True)
                self.assertEqual(17, result.returncode)
                self.assertEqual(1, len(calls))

    def test_inventory_validator_rejects_lost_duplicate_filtered_or_wrong_feature_targets(self):
        source = RUNNER.read_text(encoding="utf-8")
        for changed in (
            source.replace("--test http_auth", "--test missing_http_auth"),
            source.replace("--test http_auth", '--test "http_auth'),
            source.replace("--test http_auth", "--test http_auth --test http_auth"),
            source.replace("--test http_auth", "--test http_auth selected_test"),
            source.replace("--features runtime ", "--features runtime,tooling ", 1),
        ):
            with self.subTest(changed=changed[:40]), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory) / "runner.sh"
                candidate.write_text(changed, encoding="utf-8")
                candidate.chmod(0o755)
                with patch.object(VALIDATOR, "POSTGRES_ENTRYPOINT", candidate):
                    errors = []
                    VALIDATOR.validate_postgres_entrypoint(errors)
                self.assertTrue(errors)

    def test_ci_keeps_all_lanes_and_tls_adopter_order(self):
        workflow = yaml.safe_load((SCRIPT_DIR.parents[2] / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["breg-contracts"]
        self.assertEqual(["contracts", "postgres", "immediate-actions"], job["strategy"]["matrix"]["lane"])
        self.assertFalse(job["strategy"]["fail-fast"])
        self.assertIn("postgres", job["services"])
        runs = {step["run"]: step for step in job["steps"] if "run" in step}
        contract_commands = (
            "products/breg/scripts/check-contracts.sh",
            "products/breg/scripts/check-client-contract.sh",
            "products/breg/scripts/test-postgres-tls.sh",
            "products/breg/scripts/test-adopter-workflow.sh",
            "products/breg/quickstart/run.sh --smoke",
            "products/breg/quickstart/run.sh --spatial --smoke",
        )
        for command in contract_commands:
            self.assertEqual("matrix.lane == 'contracts'", runs[command]["if"])
        self.assertLess(list(runs).index(contract_commands[2]), list(runs).index(contract_commands[3]))
        uv = next(step for step in job["steps"] if step.get("name") == "Install uv")
        self.assertEqual("matrix.lane != 'immediate-actions'", uv["if"])
        postgres = runs['products/breg/scripts/test-postgres.sh --lane "$BREG_POSTGRES_LANE"']
        self.assertEqual("matrix.lane != 'contracts'", postgres["if"])
        self.assertEqual("${{ matrix.lane }}", postgres["env"]["BREG_POSTGRES_LANE"])


if __name__ == "__main__":
    unittest.main()
