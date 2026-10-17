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
ACTION_EXAMPLES_RUNNER = SCRIPT_DIR / "test-immediate-action-examples.sh"


class PostgresRunnerTests(unittest.TestCase):
    def run_lane(self, *arguments: str, database: bool = True, fail: bool = False, fail_build: bool = False, runner: Path = RUNNER):
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
                [str(runner), *arguments], env=environment,
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
            self.assertEqual(["test", "--locked", "-p"], call[:3])
            self.assertIn(call[3], VALIDATOR.POSTGRES_TEST_PACKAGES)
            self.assertEqual("--features", call[4])
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
        self.assertEqual(4, len(ordinary))
        self.assertEqual(5, len(default))
        self.assertEqual([shlex.split(
            "test --locked -p registry-breg --features postgres-test,tooling,schema --test postgres_immediate_actions"
        )], actions)

    def test_real_evidence_build_precedes_proof_and_is_absent_from_action_lane(self):
        result, calls = self.run_lane("--lane", "postgres")
        self.assertEqual(0, result.returncode, result.stderr)
        builds = [index for index, call in enumerate(calls) if call[0] == "build"]
        self.assertEqual(1, len(builds))
        proof = next(index for index, call in enumerate(calls) if "postgres_action_evidence" in call)
        self.assertLess(builds[0], proof)
        self.assertIn("postgres_action_evidence_targets", calls[proof])
        self.assertIn("postgres_action_evidence_retention", calls[proof])
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

    def test_immediate_action_examples_run_the_native_atomicity_and_recovery_proof(self):
        result, calls = self.run_lane(runner=ACTION_EXAMPLES_RUNNER)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([shlex.split(
            "test --locked -p registry-breg --features postgres-test,tooling,schema "
            "--test postgres_refactor "
            "facility_action_is_atomic_checks_references_and_recovers_exactly_once "
            "-- --exact --test-threads=1"
        )], calls)

    def test_immediate_action_examples_require_database_and_propagate_failures(self):
        result, calls = self.run_lane(runner=ACTION_EXAMPLES_RUNNER, database=False)
        self.assertEqual(2, result.returncode)
        self.assertIn("BREG_TEST_DATABASE_URL must be set", result.stderr)
        self.assertEqual([], calls)
        result, calls = self.run_lane(runner=ACTION_EXAMPLES_RUNNER, fail=True)
        self.assertEqual(17, result.returncode)
        self.assertEqual(1, len(calls))
        result, calls = self.run_lane("--mode", "immediate-actions", runner=ACTION_EXAMPLES_RUNNER)
        self.assertEqual(2, result.returncode)
        self.assertIn("Usage:", result.stderr)
        self.assertEqual([], calls)

    def test_inventory_validator_rejects_lost_duplicate_filtered_or_wrong_feature_targets(self):
        source = RUNNER.read_text(encoding="utf-8")
        for changed in (
            source.replace("--test http_auth", "--test missing_http_auth"),
            source.replace("--test http_auth", '--test "http_auth'),
            source.replace("--test http_auth", "--test http_auth --test http_auth"),
            source.replace("--test http_auth", "--test http_auth selected_test"),
            source.replace("--features runtime,tooling,schema ", "--features postgres-test,tooling,schema ", 1),
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
        # The change classifier owns the lane list: review runs only the first
        # lane, and the merge queue and nightly sweep run all of them.
        self.assertEqual("${{ fromJSON(needs.changes.outputs.breg_contracts_lanes) }}", job["strategy"]["matrix"]["lane"])
        spec = importlib.util.spec_from_file_location("ci_changes", SCRIPT_DIR.parents[2] / ".github/scripts/ci_changes.py")
        assert spec is not None and spec.loader is not None
        ci_changes = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = ci_changes
        spec.loader.exec_module(ci_changes)
        self.assertEqual(("contracts", "postgres", "immediate-actions"), ci_changes.BREG_CONTRACTS_LANES)
        self.assertFalse(job["strategy"]["fail-fast"])
        steps = job["steps"]
        start_index = next(
            index for index, step in enumerate(steps)
            if step.get("name") == "Start PostgreSQL service"
        )
        configure_index = next(
            index for index, step in enumerate(steps)
            if step.get("name") == "Configure Base Registry Engine test environment"
        )
        stop_index = next(
            index for index, step in enumerate(steps)
            if step.get("name") == "Stop PostgreSQL service"
        )
        self.assertEqual(
            {
                "name": "Start PostgreSQL service",
                "id": "postgres",
                "uses": "./.github/actions/postgres-service",
                "with": {
                    "image": (
                        "postgis/postgis@sha256:"
                        "01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6"
                    ),
                    "container_name": "registry-stack-breg-contracts-postgres",
                    "database": "breg",
                    "database_user": "breg",
                    "database_password": "breg_test",
                },
            },
            steps[start_index],
        )
        self.assertEqual(
            {
                "DATABASE_PORT": "${{ steps.postgres.outputs.port }}",
                "POSTGRES_CONTAINER_ID": "${{ steps.postgres.outputs.container_id }}",
                "TLS_CA_PEM_PATH": "${{ runner.temp }}/breg-postgres-trusted-ca.pem",
            },
            steps[configure_index]["env"],
        )
        self.assertEqual(
            {
                "name": "Stop PostgreSQL service",
                "if": "always()",
                "uses": "./.github/actions/postgres-service",
                "with": {
                    "operation": "stop",
                    "container_id": "${{ steps.postgres.outputs.container_id }}",
                },
            },
            steps[stop_index],
        )
        self.assertLess(start_index, configure_index)
        runs = {step["run"]: step for step in steps if "run" in step}
        contract_commands = (
            "uv run --no-project --with PyYAML==6.0.2 products/breg/scripts/check-contracts.sh",
            "products/breg/scripts/check-client-contract.sh",
            "products/breg/scripts/test-postgres-tls.sh",
            "products/breg/scripts/test-adopter-workflow.sh",
            "products/breg/quickstart/run.sh --smoke",
            "products/breg/quickstart/run.sh --spatial --smoke",
            "products/breg/scripts/check-mcp-gateway-boundary.sh",
            "products/breg/scripts/check-service-dependencies.sh",
            "products/breg/scripts/test-immediate-action-examples.sh",
        )
        for command in contract_commands:
            self.assertEqual("matrix.lane == 'contracts'", runs[command]["if"])
        contract_indices = [steps.index(runs[command]) for command in contract_commands]
        self.assertLess(configure_index, min(contract_indices))
        self.assertGreater(stop_index, max(contract_indices))
        self.assertLess(list(runs).index(contract_commands[2]), list(runs).index(contract_commands[3]))
        # The native Action harness uses a plain administrator connection. The
        # TLS proof changes this shared service to TLS-only for adopter checks.
        self.assertLess(
            list(runs).index("products/breg/scripts/test-immediate-action-examples.sh"),
            list(runs).index("products/breg/scripts/test-postgres-tls.sh"),
        )
        uv = next(step for step in job["steps"] if step.get("name") == "Install uv")
        self.assertEqual("matrix.lane != 'immediate-actions'", uv["if"])
        postgres = runs['products/breg/scripts/test-postgres.sh --lane "$BREG_POSTGRES_LANE"']
        self.assertEqual("matrix.lane != 'contracts'", postgres["if"])
        self.assertEqual("${{ matrix.lane }}", postgres["env"]["BREG_POSTGRES_LANE"])


if __name__ == "__main__":
    unittest.main()
