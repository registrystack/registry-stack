from __future__ import annotations

from pathlib import Path
import unittest


RUNTIME = Path(__file__).resolve().parents[1] / "runtime.yaml"


class RuntimeAuthorizationTests(unittest.TestCase):
    def test_client_signing_key_uses_the_required_file_provider(self) -> None:
        runtime = RUNTIME.read_text(encoding="utf-8")

        self.assertIn(
            "secretProviders:\n"
            "  environment: {}\n"
            "  file:\n"
            "    root: /run/registry-coordinator/secrets\n",
            runtime,
        )
        self.assertIn("signingKeyRef: secret:file/external-job-client-jwk", runtime)
        self.assertNotIn("signingKeyRef: secret:env/", runtime)


if __name__ == "__main__":
    unittest.main()
