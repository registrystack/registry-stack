#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "sync-registry-client-node.py"
TARGET = ROOT / "crates" / "registry-stack-client-node"
PLATFORM_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}


def load_module():
    spec = importlib.util.spec_from_file_location("sync_registry_client_node", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SyncRegistryClientNodeReadmeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.files = self.module.expected_files()

    def test_generates_a_readme_for_every_platform_package(self) -> None:
        for platform in PLATFORM_TRIPLES:
            with self.subTest(platform=platform):
                self.assertIn(TARGET / "npm" / platform / "README.md", self.files)

    def test_each_readme_names_its_own_package_and_target_triple(self) -> None:
        for platform, triple in PLATFORM_TRIPLES.items():
            with self.subTest(platform=platform):
                text = self.files[TARGET / "npm" / platform / "README.md"].decode()
                self.assertIn(f"# `@registrystack/client-{platform}`", text)
                self.assertIn(f"**{triple}**", text)
                self.assertIn(
                    "[`@registrystack/client`]"
                    "(https://www.npmjs.com/package/@registrystack/client)",
                    text,
                )

    def test_the_root_package_gets_no_generated_readme(self) -> None:
        # The root README is authored by hand, not generated; only the three
        # platform packages get one written for them.
        self.assertNotIn(TARGET / "README.md", self.files)


if __name__ == "__main__":
    unittest.main()
