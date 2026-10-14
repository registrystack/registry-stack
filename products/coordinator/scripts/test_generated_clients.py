# SPDX-License-Identifier: Apache-2.0
"""Prerequisite and execution boundaries of the opt-in generated-client proof."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "coordinator_generated_clients", Path(__file__).with_name("test-generated-clients.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class GeneratedClientRunnerTests(unittest.TestCase):
    def test_missing_or_remote_database_refused_without_echoing_credentials(self):
        for value in ("", "postgres://user:secret-canary@remote.example/db", "postgres://localhost/",
                      "https://localhost/db", "postgres://[invalid/db"):
            with self.subTest(value=value):
                with self.assertRaises(runner.PrerequisiteError) as error:
                    runner.require_database({"COORDINATOR_TEST_DATABASE_URL": value})
                self.assertIn("COORDINATOR_TEST_DATABASE_URL", str(error.exception))
                self.assertNotIn("secret-canary", str(error.exception))

    def test_only_loopback_disposable_database_names_are_accepted(self):
        for host in ("localhost", "127.0.0.1", "[::1]"):
            runner.require_database({"COORDINATOR_TEST_DATABASE_URL": f"postgres://{host}/owned_test"})

    def test_child_build_settings_preserve_parent_environment_and_remove_stale_addon(self):
        original = {"NAPI_RS_NATIVE_LIBRARY_PATH": "stale.node", "CARGO_TARGET_DIR": "/tmp/owned-target",
                    "CARGO_BUILD_JOBS": "1", "RUSTC_WRAPPER": "ambient-wrapper"}
        environment = runner.proof_environment(original)
        self.assertIn("NAPI_RS_NATIVE_LIBRARY_PATH", original)
        self.assertNotIn("NAPI_RS_NATIVE_LIBRARY_PATH", environment)
        self.assertEqual(environment["CARGO_TARGET_DIR"], "/tmp/owned-target")
        self.assertEqual(environment["CARGO_BUILD_JOBS"], "1")
        self.assertEqual(environment["RUSTC_WRAPPER"], "")
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")

    def test_missing_pyright_requires_explicit_local_setup(self):
        with patch.object(runner.shutil, "which", return_value=None):
            with self.assertRaises(runner.PrerequisiteError) as error:
                runner.executable("pyright", "/definitely-missing/pyright")
        self.assertIn("local virtual environment", str(error.exception))
        self.assertIn("--pyright", str(error.exception))

    def test_relative_cargo_target_is_shared_across_package_working_directories(self):
        environment = runner.proof_environment({"CARGO_TARGET_DIR": "target-proof"})
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(runner.REPO / "target-proof"))

    def test_local_compiler_with_spaces_remains_one_executable_path(self):
        with tempfile.TemporaryDirectory() as root:
            compiler = Path(root) / "tools with spaces/tsc"
            compiler.parent.mkdir()
            compiler.write_text("#!/bin/sh\nexit 0\n")
            compiler.chmod(0o700)
            self.assertEqual(runner.executable("tsc", str(compiler)), compiler)

    def test_wrapper_quotes_tool_path_and_forwards_arguments(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            target = directory / "tool with spaces"
            target.write_text("#!/bin/sh\n[ \"$1\" = 'argument with spaces' ]\n")
            target.chmod(0o700)
            runner.tool_wrapper(directory, "pyright", target)
            result = runner.subprocess.run([str(directory / "pyright"), "argument with spaces"])
            self.assertEqual(result.returncode, 0)

    def test_missing_node_dependencies_use_only_local_pinned_install(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(runner, "NODE", Path(root)), patch.object(runner, "run_command") as command, \
                    patch.object(runner, "executable", return_value=Path(root) / "tsc"):
                runner.prepare_node({}, Path("/tools/npm"), None)
            command.assert_called_once_with(["/tools/npm", "ci"], {}, cwd=Path(root))

    def test_explicit_proof_plan_includes_database_and_strict_compiler_regressions(self):
        commands = runner.proof_commands()
        self.assertEqual(len(commands), 2)
        self.assertIn("sdk_generation", commands[0])
        self.assertIn("deployment_postgres", commands[1])
        self.assertIn("generated_", commands[1])
        for command in commands:
            self.assertIn("--locked", command)
            self.assertIn("--ignored", command)
            self.assertIn("--test-threads=1", command)

    def test_missing_database_stops_before_any_tool_or_build(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(runner, "run_command") as command:
            with self.assertRaises(runner.PrerequisiteError):
                runner.run()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
