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

    def test_zitadel_token_helper_keeps_client_secret_out_of_curl_argv(self):
        script = (ROOT / "scripts" / "mint-zitadel-token.sh").read_text()

        self.assertNotIn('--user "${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}"', script)
        self.assertNotIn("--user ${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}", script)
        self.assertIn('chmod 600 "${curl_config}"', script)
        self.assertIn('curl --config "${curl_config}"', script)
        self.assertIn('user = "%s"', script)


if __name__ == "__main__":
    unittest.main()
