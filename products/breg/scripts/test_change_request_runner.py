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

    def test_usage_and_help_document_installed_mode(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")
        self.assertIn("--installed", script)
        self.assertIn("breg-install.sh provides breg and bregctl", script)
        self.assertIn("== Using installed breg and bregctl from PATH", script)


if __name__ == "__main__":
    unittest.main()
