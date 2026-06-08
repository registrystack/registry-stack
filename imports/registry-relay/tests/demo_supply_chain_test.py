# SPDX-License-Identifier: Apache-2.0
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class DemoSupplyChainTest(unittest.TestCase):
    def test_registry_manifest_helper_uses_immutable_rev(self):
        script = (ROOT / "scripts" / "run_registry_manifest_cli.sh").read_text()

        self.assertNotIn("--tag", script)
        self.assertIn("--rev", script)
        match = re.search(r'REGISTRY_MANIFEST_GIT_REV:-([0-9a-f]{40})', script)
        self.assertIsNotNone(match)
        self.assertTrue(SHA_RE.match(match.group(1)))

    def test_registry_notary_demo_clones_immutable_rev(self):
        script = (ROOT / "demo" / "scripts" / "registry_notary_demo.py").read_text()

        self.assertNotIn("--branch", script)
        self.assertNotIn("REGISTRY_NOTARY_GIT_TAG", script)
        match = re.search(r'REGISTRY_NOTARY_GIT_REV = "([0-9a-f]{40})"', script)
        self.assertIsNotNone(match)
        self.assertIn('"fetch", "--depth", "1", "origin", git_rev', script)
        self.assertIn('"checkout", "--detach", "FETCH_HEAD"', script)


if __name__ == "__main__":
    unittest.main()
