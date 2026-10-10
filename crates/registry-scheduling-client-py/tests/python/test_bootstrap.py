"""Cargo target discovery without building the native extension."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch


class BootstrapTargetTests(unittest.TestCase):
    def setUp(self):
        path = pathlib.Path(__file__).with_name("bootstrap.py")
        spec = importlib.util.spec_from_file_location("bootstrap_under_test", path)
        self.bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bootstrap)

    def test_library_uses_the_target_reported_by_locked_cargo_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "relocated-target"
            reply = subprocess.CompletedProcess(
                [], 0, json.dumps({"target_directory": str(target)}), ""
            )
            with patch.object(self.bootstrap.subprocess, "run", return_value=reply) as run:
                with patch.object(self.bootstrap.platform, "system", return_value="Linux"):
                    library = self.bootstrap._library()
            self.assertEqual(library, target / "debug" / "libregistry_scheduling_client.so")
            run.assert_called_once_with(
                ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
                cwd=self.bootstrap._WORKSPACE_ROOT,
                capture_output=True,
                check=False,
                text=True,
            )

    def test_metadata_failure_refuses_to_guess_a_library_path(self):
        reply = subprocess.CompletedProcess([], 1, "", "metadata unavailable")
        with patch.object(self.bootstrap.subprocess, "run", return_value=reply):
            with self.assertRaisesRegex(RuntimeError, "cargo metadata failed"):
                self.bootstrap._library()


if __name__ == "__main__":
    unittest.main()
