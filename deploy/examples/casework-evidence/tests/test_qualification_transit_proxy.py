#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


PROXY_PATH = Path(__file__).parents[1] / "qualification_transit_proxy.py"


def load_proxy_module():
    spec = importlib.util.spec_from_file_location("qualification_transit_proxy", PROXY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QualificationTransitProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_proxy_module()

    def test_allows_only_key_metadata_and_signing_for_exact_key(self):
        self.assertTrue(
            self.module.is_allowed("GET", "/v1/transit/keys/evidence-signing")
        )
        self.assertTrue(
            self.module.is_allowed(
                "POST", "/v1/transit/sign/evidence-signing/sha2-256"
            )
        )

    def test_denies_other_keys_methods_queries_and_paths(self):
        refused = [
            ("GET", "/v1/transit/keys/another-key"),
            ("POST", "/v1/transit/sign/another-key"),
            ("POST", "/v1/transit/sign/evidence-signing"),
            ("POST", "/v1/transit/sign/evidence-signing/sha2-512"),
            ("DELETE", "/v1/transit/keys/evidence-signing"),
            ("POST", "/v1/transit/keys/evidence-signing"),
            ("GET", "/v1/transit/keys/evidence-signing?version=1"),
            ("GET", "/v1/sys/health"),
        ]
        for method, path in refused:
            with self.subTest(method=method, path=path):
                self.assertFalse(self.module.is_allowed(method, path))


if __name__ == "__main__":
    unittest.main()
