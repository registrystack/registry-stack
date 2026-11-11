import subprocess
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bin/bootstrap-k3s.sh"


class BootstrapTest(unittest.TestCase):
    def test_usage_describes_install_and_private_server_join(self):
        result = subprocess.run(["bash", BOOTSTRAP, "--help"], capture_output=True, text=True, check=True)
        self.assertIn("--install", result.stdout)
        self.assertIn("--join", result.stdout)
        self.assertIn("token-file", result.stdout)

    def test_rejects_incomplete_join_before_host_checks(self):
        result = subprocess.run(
            ["bash", BOOTSTRAP, "--join", "https://k3s.example.test:6443"], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)
