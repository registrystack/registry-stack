import subprocess
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bin/bootstrap-k3s.sh"


class BootstrapTest(unittest.TestCase):
    def assert_host_release(self, distribution, version, *, supported):
        command = 'source "$1"; require_supported_ubuntu "$2" "$3"'
        result = subprocess.run(
            ["bash", "-c", command, "bootstrap-test", BOOTSTRAP, distribution, version],
            capture_output=True,
            text=True,
        )
        if supported:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        else:
            self.assertEqual(result.returncode, 1)
            self.assertIn("Ubuntu 24.04 or 26.04", result.stderr)

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

    def test_accepts_supported_ubuntu_releases(self):
        self.assert_host_release("ubuntu", "24.04", supported=True)
        self.assert_host_release("ubuntu", "26.04", supported=True)

    def test_rejects_other_ubuntu_releases_and_distributions(self):
        self.assert_host_release("ubuntu", "22.04", supported=False)
        self.assert_host_release("debian", "13", supported=False)
