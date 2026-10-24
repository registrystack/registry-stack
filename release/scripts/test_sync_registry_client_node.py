#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
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
PRODUCTS = ("discovery", "evidence", "breg", "casework", "messaging", "scheduling")
COMPATIBILITY = ROOT / "crates" / "registry-stack-client" / "compatibility.json"


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

    def test_each_native_platform_package_carries_third_party_notices(self) -> None:
        expected = (ROOT / "THIRD_PARTY_NOTICES").read_bytes()
        for platform in PLATFORM_TRIPLES:
            with self.subTest(platform=platform):
                path = TARGET / "npm" / platform / "THIRD_PARTY_NOTICES"
                self.assertEqual(self.files[path], expected)

    def test_the_root_package_gets_no_generated_readme(self) -> None:
        # The root README is authored by hand, not generated; only the three
        # platform packages get one written for them.
        self.assertNotIn(TARGET / "README.md", self.files)


class SyncRegistryClientNodeDeclarationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.files = self.module.expected_files()

    def test_standalone_clients_keep_the_generated_loader_diagnostic(self) -> None:
        for product in PRODUCTS:
            with self.subTest(product=product):
                declaration = (
                    ROOT / "crates" / f"registry-{product}-client-node" / "index.d.ts"
                ).read_bytes()
                self.assertIn(b"export declare const __napiBindingTarget:", declaration)

    def test_unified_facades_omit_the_loader_only_diagnostic(self) -> None:
        for product in PRODUCTS:
            with self.subTest(product=product):
                declaration = self.files[TARGET / product / "index.d.ts"]
                self.assertNotIn(
                    b"export declare const __napiBindingTarget:", declaration
                )


class SyncRegistryClientNodeCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.files = self.module.expected_files()
        self.path = TARGET / "compatibility.json"

    def test_generates_the_common_compatibility_record_at_the_package_version(self) -> None:
        expected = json.loads(COMPATIBILITY.read_text(encoding="utf-8"))
        package = json.loads((TARGET / "package.json").read_text(encoding="utf-8"))
        expected["sdkPackage"]["version"] = package["version"]

        self.assertEqual(json.loads(self.files[self.path]), expected)

    def test_root_manifest_exports_and_packs_the_compatibility_record(self) -> None:
        package = json.loads((TARGET / "package.json").read_text(encoding="utf-8"))
        self.assertIn("compatibility.json", package["files"])
        self.assertEqual(
            package["exports"]["./compatibility.json"], "./compatibility.json"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            environment = os.environ.copy()
            environment["NPM_CONFIG_CACHE"] = str(
                Path(temporary_directory) / "npm-cache"
            )
            result = subprocess.run(
                [
                    "npm",
                    "pack",
                    "--ignore-scripts",
                    "--json",
                    "--pack-destination",
                    temporary_directory,
                ],
                cwd=TARGET,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            packed = json.loads(result.stdout)
            self.assertEqual(len(packed), 1)
            tarball = Path(temporary_directory) / packed[0]["filename"]
            with tarfile.open(tarball, mode="r:gz") as archive:
                packaged = archive.extractfile("package/compatibility.json")
                self.assertIsNotNone(packaged)
                assert packaged is not None
                self.assertEqual(packaged.read(), self.files[self.path])


CASEWORK_PYTHON_LICENCE = "crates/registry-casework-client-py/LICENSE"
MESSAGING_LICENCES = (
    "crates/registry-messaging-client-node/LICENSE",
    "crates/registry-messaging-client-py/LICENSE",
)
SCHEDULING_LICENCES = (
    "crates/registry-scheduling-client-node/LICENSE",
    "crates/registry-scheduling-client-py/LICENSE",
)
COORDINATOR_LICENCES = (
    "crates/registry-coordinator-client-node/LICENSE",
    "crates/registry-coordinator-client-py/LICENSE",
)


class SyncRegistryClientNodeLicenceTest(unittest.TestCase):
    def test_render_binding_licenses_are_owned_by_the_sync_generator(self) -> None:
        generated = load_module().expected_files()
        for language in ("node", "py"):
            self.assertEqual(generated[ROOT / "crates" / f"registry-render-client-{language}" / "LICENSE"], (ROOT / "LICENSE").read_bytes())

    def setUp(self) -> None:
        self.module = load_module()
        self.files = self.module.expected_files()
        self.licence = (ROOT / "LICENSE").read_bytes()
        self.gated = sorted(
            str(path.relative_to(ROOT))
            for path in self.files
            if path.name == "LICENSE"
        )

    def test_every_gated_licence_carries_the_root_apache_text(self) -> None:
        self.assertTrue(self.gated)
        for name in self.gated:
            with self.subTest(licence=name):
                self.assertEqual(
                    len(self.files[ROOT / name]), len(self.licence), name
                )
                self.assertTrue(self.files[ROOT / name] == self.licence, name)

    def test_the_casework_python_binding_licence_is_gated(self) -> None:
        # The wheel is assembled from this crate, so its licence is held by the
        # same gate as the other assembled bindings.
        self.assertIn(CASEWORK_PYTHON_LICENCE, self.gated)

    def test_the_casework_python_binding_ships_the_root_apache_text(self) -> None:
        shipped = (ROOT / CASEWORK_PYTHON_LICENCE).read_bytes()
        self.assertEqual(
            len(shipped), len(self.licence), CASEWORK_PYTHON_LICENCE
        )
        self.assertTrue(shipped == self.licence, CASEWORK_PYTHON_LICENCE)

    def test_the_messaging_binding_licences_are_gated(self) -> None:
        # Both Messaging bindings compare their licence copies with the root
        # LICENSE in their own checks, so the same gate holds them.
        for licence in MESSAGING_LICENCES:
            with self.subTest(licence=licence):
                self.assertIn(licence, self.gated)

    def test_the_scheduling_binding_licences_are_gated(self) -> None:
        # Both Scheduling bindings compare their licence copies with the root
        # LICENSE in their own checks, so the same gate holds them.
        for licence in SCHEDULING_LICENCES:
            with self.subTest(licence=licence):
                self.assertIn(licence, self.gated)

    def test_the_coordinator_binding_licences_are_gated(self) -> None:
        for licence in COORDINATOR_LICENCES:
            with self.subTest(licence=licence):
                self.assertIn(licence, self.gated)


if __name__ == "__main__":
    unittest.main()
