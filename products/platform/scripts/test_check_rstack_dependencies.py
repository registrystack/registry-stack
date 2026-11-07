#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-rstack-dependencies.py")
SPEC = importlib.util.spec_from_file_location("rstack_dependencies", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CLEAN = """registry-rstack v0.1.0 (/work/crates/registry-rstack)
ring v0.17.0
rustls v0.23.0
registry-thunderid-tooling v0.1.0 (/work/crates/registry-thunderid-tooling)
sha2 v0.10.0
"""


class RstackDependencies(unittest.TestCase):
    def test_a_plain_launcher_tree_passes(self) -> None:
        self.assertEqual([], MODULE.banned(MODULE.package_names(CLEAN)))

    def test_each_banned_family_is_refused(self) -> None:
        for name in (
            "registry-platform-crypto",
            "registry-platform-oidc",
            "registry-platform-httputil",
            "aws-lc-fips-sys",
            "aws-lc-rs",
            "jsonwebtoken",
            "p256",
            "reqwest",
            "tokio",
        ):
            with self.subTest(name=name):
                tree = CLEAN + f"{name} v1.0.0\n"
                self.assertEqual([name], MODULE.banned(MODULE.package_names(tree)))

    def test_similar_names_are_not_refused(self) -> None:
        self.assertEqual([], MODULE.banned(["aws-lcx", "tokio-util-not", "ring", "rustls-webpki"]))

    def test_a_repeated_package_is_reported_once(self) -> None:
        self.assertEqual(["p256"], MODULE.banned(["p256", "p256"]))


if __name__ == "__main__":
    unittest.main()
