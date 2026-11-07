#!/usr/bin/env python3
"""The rstack installation model must match the exact release payload roster."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from release.scripts import release_candidate, rstack_components


def payloads(version: str) -> list[dict[str, object]]:
    return [
        {"name": name, "kind": kind, "size": 17, "sha256": "a" * 64}
        for name, kind in release_candidate._release_payload_inventory(version).items()
    ]


def component_name_enum(node: object) -> list[str]:
    """Return the enum that closes the candidate's rstack component names."""
    if isinstance(node, dict):
        components = node.get("components")
        if isinstance(components, dict) and "propertyNames" in components:
            return components["propertyNames"]["enum"]
        children = node.values()
    elif isinstance(node, list):
        children = node
    else:
        return []
    for child in children:
        found = component_name_enum(child)
        if found:
            return found
    return []


class ComponentManifestTests(unittest.TestCase):
    def test_release_inventory_ships_launcher_on_each_published_platform(self) -> None:
        inventory = release_candidate._release_payload_inventory("0.44.0")
        for platform in rstack_components.PLATFORMS:
            self.assertEqual(inventory[f"rstack-v0.44.0-{platform}" + (".tar.gz" if platform == "macos-arm64" else "")], "binary")
        self.assertEqual(inventory["rstack-v0.44.0-install.sh"], "installer")
        self.assertEqual(inventory["rstack-install.sh"], "installer")
        self.assertNotIn("rstack-v0.43.0-linux-amd64", release_candidate._release_payload_inventory("0.43.0"))

    def test_all_published_components_are_available_on_every_platform(self) -> None:
        document = rstack_components.build_component_manifest("0.44.0", payloads("0.44.0"))
        self.assertEqual(document["schema_version"], "registry-stack.components.v1")
        self.assertEqual(document["release"], "v0.44.0")
        self.assertEqual(set(document["launcher"]), set(rstack_components.PLATFORMS))
        scheduling = document["components"]["scheduling"]
        self.assertEqual(scheduling["entrypoint"], "schedulingctl")
        self.assertTrue(scheduling["platforms"]["macos-arm64"]["capabilities"]["runtime"])
        self.assertTrue(scheduling["platforms"]["linux-amd64"]["capabilities"]["runtime"])
        self.assertEqual(
            set(document["components"]["coordinator"]["platforms"]),
            set(rstack_components.PLATFORMS),
        )
        self.assertEqual(
            set(document["components"]["manifest"]["platforms"]),
            set(rstack_components.PLATFORMS),
        )

    def test_adapter_installs_from_v0_46_0_with_its_job_host_as_a_capability(self) -> None:
        self.assertNotIn(
            "adapter",
            rstack_components.build_component_manifest("0.45.0", payloads("0.45.0"))["components"],
        )
        adapter = rstack_components.build_component_manifest("0.46.0", payloads("0.46.0"))[
            "components"
        ]["adapter"]
        self.assertEqual("adapterctl", adapter["entrypoint"])
        self.assertEqual(set(rstack_components.PLATFORMS), set(adapter["platforms"]))
        for platform, supported in adapter["platforms"].items():
            with self.subTest(platform=platform):
                self.assertEqual(
                    {"tooling": True, "runtime": True},
                    supported["capabilities"],
                )

    def test_candidate_schemas_admit_every_component_name(self) -> None:
        schemas = Path(__file__).resolve().parent.parent / "schemas"
        for schema_name in ("release-candidate-v2.schema.json", "release-candidate-v3.schema.json"):
            with self.subTest(schema=schema_name):
                schema = json.loads((schemas / schema_name).read_text(encoding="utf-8"))
                self.assertEqual(
                    set(rstack_components.PRODUCTS),
                    set(component_name_enum(schema)),
                )

    def test_plain_macos_binary_is_limited_to_registry_manifest(self) -> None:
        self.assertEqual(
            ("registry-manifest", "macos-arm64"),
            rstack_components._binary_name(
                "registry-manifest-v0.44.0-macos-arm64", "v0.44.0"
            ),
        )
        with self.assertRaisesRegex(ValueError, "unclassified"):
            rstack_components._binary_name("breg-v0.44.0-macos-arm64", "v0.44.0")

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
