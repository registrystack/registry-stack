#!/usr/bin/env python3
"""The rstack installation model must match the exact release payload roster."""

from __future__ import annotations

import unittest

import release_candidate
import rstack_components


def payloads(version: str) -> list[dict[str, object]]:
    return [
        {"name": name, "kind": kind, "size": 17, "sha256": "a" * 64}
        for name, kind in release_candidate._release_payload_inventory(version).items()
    ]


class ComponentManifestTests(unittest.TestCase):
    def test_release_inventory_ships_launcher_on_each_published_platform(self) -> None:
        inventory = release_candidate._release_payload_inventory("0.44.0")
        for platform in rstack_components.PLATFORMS:
            self.assertEqual(inventory[f"rstack-v0.44.0-{platform}" + (".tar.gz" if platform == "macos-arm64" else "")], "binary")
        self.assertEqual(inventory["rstack-v0.44.0-install.sh"], "installer")
        self.assertEqual(inventory["rstack-install.sh"], "installer")
        self.assertNotIn("rstack-v0.43.0-linux-amd64", release_candidate._release_payload_inventory("0.43.0"))

    def test_tooling_only_platform_and_absent_component_are_explicit(self) -> None:
        document = rstack_components.build_component_manifest("0.44.0", payloads("0.44.0"))
        self.assertEqual(document["schema_version"], "registry-stack.components.v1")
        self.assertEqual(document["release"], "v0.44.0")
        self.assertEqual(set(document["launcher"]), set(rstack_components.PLATFORMS))
        scheduling = document["components"]["scheduling"]
        self.assertEqual(scheduling["entrypoint"], "schedulingctl")
        self.assertFalse(scheduling["platforms"]["macos-arm64"]["capabilities"]["runtime"])
        self.assertTrue(scheduling["platforms"]["linux-amd64"]["capabilities"]["runtime"])
        self.assertNotIn("coordinator", document["components"])
        self.assertNotIn("macos-arm64", document["components"]["manifest"]["platforms"])

    def test_asset_references_retain_size_and_digest(self) -> None:
        document = rstack_components.build_component_manifest("0.44.0", payloads("0.44.0"))
        asset = document["components"]["breg"]["platforms"]["linux-amd64"]["assets"][0]
        self.assertEqual(asset["size"], 17)
        self.assertEqual(asset["sha256"], "a" * 64)
        self.assertTrue(asset["name"].endswith("-v0.44.0-linux-amd64"))

    def test_unclassified_or_incomplete_binary_roster_fails_closed(self) -> None:
        actual = payloads("0.44.0")
        with self.assertRaisesRegex(ValueError, "unclassified"):
            rstack_components.build_component_manifest(
                "0.44.0", actual + [{"name": "mystery-v0.44.0-linux-amd64", "kind": "binary", "size": 5, "sha256": "b" * 64}]
            )
        without_ctl = [item for item in actual if item["name"] != "bregctl-v0.44.0-linux-amd64"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            rstack_components.build_component_manifest("0.44.0", without_ctl)


if __name__ == "__main__":
    unittest.main()
