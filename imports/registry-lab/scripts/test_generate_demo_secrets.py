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

    def test_default_commitment_rewrite_leaves_hosted_configs_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_config = root / "config/relay/civil-registry-relay.yaml"
            hosted_config = root / "config/coolify/relay/civil-registry-relay.yaml"
            local_config.parent.mkdir(parents=True)
            hosted_config.parent.mkdir(parents=True)
            original = self.relay_config("sha256:" + ("0" * 64))
            local_config.write_text(original, encoding="utf-8")
            hosted_config.write_text(original, encoding="utf-8")

            self.generator.DEMO_ROOT = root
            updated = self.generator.write_config_fingerprint_commitments(
                {"CIVIL_METADATA_CLIENT_HASH": "sha256:" + ("1" * 64)}
            )

            self.assertEqual(updated, 1)
            self.assertNotEqual(local_config.read_text(encoding="utf-8"), original)
            self.assertEqual(hosted_config.read_text(encoding="utf-8"), original)

    def test_include_hosted_rewrites_hosted_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosted_config = root / "config/coolify/relay/civil-registry-relay.yaml"
            hosted_config.parent.mkdir(parents=True)
            original = self.relay_config("sha256:" + ("0" * 64))
            hosted_config.write_text(original, encoding="utf-8")

            self.generator.DEMO_ROOT = root
            updated = self.generator.write_config_fingerprint_commitments(
                {"CIVIL_METADATA_CLIENT_HASH": "sha256:" + ("1" * 64)},
                include_hosted=True,
            )

            self.assertEqual(updated, 1)
            self.assertNotEqual(hosted_config.read_text(encoding="utf-8"), original)

    @staticmethod
    def relay_config(commitment: str) -> str:
        return f"""auth:
  mode: api_key
  api_keys:
    - id: metadata_client
      fingerprint:
        provider: env
        name: CIVIL_METADATA_CLIENT_HASH
        commitment: {commitment}
"""


if __name__ == "__main__":
    unittest.main()
