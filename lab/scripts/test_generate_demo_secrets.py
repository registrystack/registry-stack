#!/usr/bin/env python3
"""Focused tests for local demo secret generation."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("generate-demo-secrets.py")


def load_generator():
    previous_keys = sys.modules.get("generate_demo_keys")
    fake_keys = types.ModuleType("generate_demo_keys")
    fake_keys.generate_raw_key = lambda: "raw-key-fixture"
    fake_keys.generate_registry_notary_issuer_jwk = (
        lambda: '{"kty":"OKP","crv":"Ed25519","x":"fixture","d":"fixture"}'
    )
    sys.modules["generate_demo_keys"] = fake_keys
    spec = importlib.util.spec_from_file_location("generate_demo_secrets", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load generate-demo-secrets.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        if previous_keys is None:
            sys.modules.pop("generate_demo_keys", None)
        else:
            sys.modules["generate_demo_keys"] = previous_keys
    return module


class GenerateDemoSecretsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = load_generator()

    def test_local_config_shape_does_not_include_commitments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_config = root / "config/relay/civil-registry-relay.yaml"
            local_config.parent.mkdir(parents=True)
            original = self.relay_config()
            local_config.write_text(original, encoding="utf-8")

            self.generator.DEMO_ROOT = root
            values = self.generator.generate_env()

            self.assertIn("CIVIL_METADATA_CLIENT_HASH", values)
            self.assertEqual(local_config.read_text(encoding="utf-8"), original)
            self.assertNotIn("commitment:", original)

    def test_generated_env_contains_fingerprint_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.generator.DEMO_ROOT = root
            values = self.generator.generate_env()

            raw = values["CIVIL_METADATA_CLIENT_RAW"]
            expected = self.generator.fingerprint(raw)
            self.assertEqual(values["CIVIL_METADATA_CLIENT_HASH"], expected)

    def test_generates_esignet_relay_credentials(self) -> None:
        values = self.generator.generate_env()

        for key in [
            "CIVIL_ESIGNET_IDENTITY_RELEASE_RAW",
            "CIVIL_ESIGNET_IDENTITY_RELEASE_HASH",
            "POPULATION_METADATA_CLIENT_RAW",
            "POPULATION_METADATA_CLIENT_HASH",
            "POPULATION_ESIGNET_IDENTITY_RELEASE_RAW",
            "POPULATION_ESIGNET_IDENTITY_RELEASE_HASH",
            "REGISTRY_ESIGNET_KYC_TOKEN_SECRET",
            "REGISTRY_ESIGNET_PSUT_SECRET",
            "REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD",
        ]:
            with self.subTest(key=key):
                self.assertIn(key, values)
                self.assertTrue(values[key])

    @staticmethod
    def relay_config() -> str:
        return """auth:
  mode: api_key
  api_keys:
    - id: metadata_client
      fingerprint:
        provider: env
        name: CIVIL_METADATA_CLIENT_HASH
"""


if __name__ == "__main__":
    unittest.main()
