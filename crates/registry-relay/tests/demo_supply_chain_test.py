# SPDX-License-Identifier: Apache-2.0
import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_registry_notary_demo():
    path = ROOT / "demo" / "scripts" / "registry_notary_demo.py"
    spec = importlib.util.spec_from_file_location("registry_notary_demo", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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

    def test_registry_notary_demo_discovers_registry_notary_offering(self):
        demo = load_registry_notary_demo()

        offering, endpoint_url = demo.find_registry_notary_offering(
            {
                "evidence_offerings": [
                    {
                        "access": {
                            "kind": "evidence-server",
                            "endpoint_url": "https://legacy.example.test",
                        }
                    },
                    {
                        "access": {
                            "kind": "registry-notary",
                            "endpoint_url": "https://notary.example.test",
                        }
                    },
                ]
            }
        )

        self.assertEqual(endpoint_url, "https://notary.example.test")
        self.assertEqual(offering["access"]["kind"], "registry-notary")

    def test_zitadel_token_helper_keeps_client_secret_out_of_curl_argv(self):
        script = (ROOT / "scripts" / "mint-zitadel-token.sh").read_text()

        self.assertNotIn('--user "${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}"', script)
        self.assertNotIn("--user ${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}", script)
        self.assertIn('chmod 600 "${curl_config}"', script)
        self.assertIn('curl --config "${curl_config}"', script)
        self.assertIn('user = "%s"', script)


if __name__ == "__main__":
    unittest.main()
