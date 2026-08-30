#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = PRODUCT_ROOT / "quickstart"


class RegistryServerQuickstartTests(unittest.TestCase):
    def test_offline_self_test_passes_without_network(self) -> None:
        result = subprocess.run(
            [str(QUICKSTART / "self-test.sh")],
            cwd=PRODUCT_ROOT.parents[1],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("self-test passed", result.stdout)

    def test_readme_keeps_local_and_production_paths_separate(self) -> None:
        readme = (QUICKSTART / "README.md").read_text(encoding="utf-8")
        self.assertIn("registry-serverctl init", readme)
        self.assertIn("adds only local package identity", readme)
        self.assertIn("quickstart/.run/secrets/operator-token", readme)
        self.assertIn("does not put the token on the command line", readme)
        self.assertIn("unsigned", readme)
        self.assertIn("local package", readme)
        self.assertIn("Production pilots still require", readme)


if __name__ == "__main__":
    unittest.main()
