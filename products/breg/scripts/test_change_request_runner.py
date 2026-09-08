#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parents[2]
RUNNER = SCRIPT_DIR / "test-change-request-examples.sh"
IMMEDIATE_RUNNER = SCRIPT_DIR / "test-immediate-action-examples.sh"

_FAILING_STUB = """#!/usr/bin/env bash
printf '%s\\n' "{tool} must not run in this test" >&2
exit 1
"""


class ChangeRequestRunnerInstalledModeTests(unittest.TestCase):
    # Proves --installed mode fails before it touches PostgreSQL or the
    # temp directory when breg or bregctl are missing from PATH. The stub
    # PATH holds only a real dirname, which the runner uses to locate its
    # own directory before any preflight check runs, plus stub openssl,
    # psql, and python3 commands that fail loudly if ever invoked. A pass
    # here proves the reported failure comes from the missing installed
    # binaries, not from a stub standing in for a tool the runner also
    # needs, and that no PostgreSQL example directory was left behind.
    def test_installed_mode_fails_before_postgres_or_temp_directory_when_binaries_are_missing(self) -> None:
        real_dirname = shutil.which("dirname")
        real_bash = shutil.which("bash")
        self.assertIsNotNone(real_dirname, "dirname must be resolvable to build the stub PATH")
        self.assertIsNotNone(real_bash, "bash must be resolvable to run the script directly")
        assert real_dirname is not None
        assert real_bash is not None

        with tempfile.TemporaryDirectory() as stub_dir, tempfile.TemporaryDirectory() as work_dir:
            stub_bin = Path(stub_dir)
            (stub_bin / "dirname").symlink_to(real_dirname)
            for tool in ("openssl", "psql", "python3"):
                stub_path = stub_bin / tool
                stub_path.write_text(_FAILING_STUB.format(tool=tool), encoding="utf-8")
                stub_path.chmod(0o755)

            work = Path(work_dir)
            tls_ca_path = work / "ca.pem"
            tls_ca_path.write_text("not a real certificate\n", encoding="utf-8")
            env_file = work / "test.env"
            env_file.write_text(
                "export BREG_TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:1/db\n"
                f"export BREG_TEST_TLS_CA_PEM_PATH={tls_ca_path}\n",
                encoding="utf-8",
            )

            environment = dict(os.environ)
            environment["PATH"] = str(stub_bin)

            before_temp_directories = set(REPOSITORY_ROOT.glob(".breg-cr-examples.*"))
            result = subprocess.run(
                [real_bash, str(RUNNER), "--installed", "--env", str(env_file)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            after_temp_directories = set(REPOSITORY_ROOT.glob(".breg-cr-examples.*"))

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("breg-install.sh provides breg and bregctl", result.stderr)
        self.assertTrue(
            "breg is required" in result.stderr or "bregctl is required" in result.stderr,
            result.stderr,
        )
        for tool in ("openssl", "psql", "python3"):
            self.assertNotIn(f"{tool} must not run in this test", result.stderr)
        self.assertEqual(before_temp_directories, after_temp_directories)

    def test_immediate_mode_accepts_rhai_project_before_database_preflight(self) -> None:
        environment = dict(os.environ)
        environment.pop("BREG_TEST_DATABASE_URL", None)
        environment.pop("BREG_TEST_TLS_CA_PEM_PATH", None)
        result = subprocess.run(
            ["bash", str(RUNNER), "--mode", "immediate-actions", "--rhai-project",
             str(REPOSITORY_ROOT / "products/breg/acceptance/person-registration-rhai")],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BREG_TEST_DATABASE_URL is required.", result.stderr)
        self.assertNotIn("usage:", result.stderr)

    def test_rhai_fixture_defaults_and_override_reach_the_selected_runner(self) -> None:
        # The trusted env hook runs after option parsing and fixture selection,
        # before service preflight. Stop there to observe the selected fixture
        # without starting PostgreSQL or creating runner resources.
        cases = (
            (RUNNER, [], "change-request", "acceptance/person-name-change-rhai"),
            (IMMEDIATE_RUNNER, [], "immediate-actions", "acceptance/person-registration-rhai"),
            (IMMEDIATE_RUNNER, ["--rhai-project", "/private/tmp/edited-person-project"],
             "immediate-actions", None),
        )
        with tempfile.TemporaryDirectory() as work_dir:
            env_file = Path(work_dir) / "selected-fixtures.env"
            env_file.write_text(
                'printf "%s\\n" "$mode" "$rhai_project"\nexit 0\n',
                encoding="utf-8",
            )
            for runner, arguments, expected_mode, fixture in cases:
                with self.subTest(runner=runner.name, arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(runner), *arguments, "--env", str(env_file)],
                        cwd=work_dir,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    expected_project = (
                        str(REPOSITORY_ROOT / "products/breg" / fixture)
                        if fixture is not None else "/private/tmp/edited-person-project"
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [expected_mode, expected_project])

    def test_usage_and_help_document_installed_mode(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")
        self.assertIn("--installed", script)
        self.assertIn("breg-install.sh provides breg and bregctl", script)
        self.assertIn("== Using installed breg and bregctl from PATH", script)

    def test_source_binaries_resolve_the_selected_cargo_target_directory(self) -> None:
        cases = (
            (None, REPOSITORY_ROOT / "target"),
            ("/private/tmp/breg-test-target", Path("/private/tmp/breg-test-target")),
            ("build/breg-target", REPOSITORY_ROOT / "build/breg-target"),
        )
        with tempfile.TemporaryDirectory() as work_dir:
            env_file = Path(work_dir) / "binary-selection.env"
            env_file.write_text(
                'trap \'printf "%s\\n" "$breg" "$bregctl"\' EXIT\n',
                encoding="utf-8",
            )
            for configured, expected in cases:
                with self.subTest(target_directory=configured):
                    environment = dict(os.environ)
                    environment.pop("BREG_TEST_DATABASE_URL", None)
                    environment.pop("CARGO_TARGET_DIR", None)
                    if configured is not None:
                        environment["CARGO_TARGET_DIR"] = configured
                    result = subprocess.run(
                        ["bash", str(IMMEDIATE_RUNNER), "--env", str(env_file)],
                        cwd=work_dir,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("BREG_TEST_DATABASE_URL is required.", result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [
                        str(expected / "debug/breg"), str(expected / "debug/bregctl"),
                    ])


if __name__ == "__main__":
    unittest.main()
