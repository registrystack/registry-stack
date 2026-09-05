#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "assemble-registry-client-packages.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "assemble_registry_client_packages", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AssembleClientPackagesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.steps = self.module.plan(
            ROOT,
            "9.9.9",
            "darwin-arm64",
            "all",
            "maturin",
            Path("/work"),
            Path("/out"),
        )
        self.rendered = [step.render() for step in self.steps]

    def test_the_checked_in_manifest_is_never_bound_in_place(self) -> None:
        facade_manifest = str(
            ROOT / "crates" / "registry-stack-client-node" / "package.json"
        )
        bind = [line for line in self.rendered if "bind-optional-deps" in line]
        self.assertEqual(1, len(bind))
        self.assertIn("/work/node-root/package.json", bind[0])
        self.assertNotIn(facade_manifest, bind[0])

    def test_the_root_package_is_packed_from_the_staged_copy(self) -> None:
        pack = [line for line in self.rendered if "npm pack" in line]
        self.assertEqual(2, len(pack))
        for line in pack:
            self.assertTrue(line.startswith("(cd /work/node-root && npm pack"), line)
            self.assertIn("--ignore-scripts", line)
            self.assertIn("--pack-destination /out", line)
        self.assertIn("./npm/darwin-arm64", pack[1])

    def test_the_platform_package_receives_every_product_addon(self) -> None:
        for product in self.module.PRODUCTS:
            addon = (
                f"crates/registry-{product}-client-node/"
                f"{product}-client.darwin-arm64.node"
            )
            self.assertTrue(
                any(
                    addon in line and "/work/node-root/npm/darwin-arm64/" in line
                    for line in self.rendered
                ),
                f"{product} addon is not copied into the platform package",
            )

    def test_the_binding_wheels_are_built_before_the_public_wheel(self) -> None:
        builds = [
            index
            for index, line in enumerate(self.rendered)
            if "maturin build --release --locked" in line
        ]
        self.assertEqual(4, len(builds))
        assemble = next(
            index
            for index, line in enumerate(self.rendered)
            if "assemble-registry-client-wheel.py" in line
        )
        self.assertLess(max(builds), assemble)

    def test_the_public_wheel_reads_the_internal_breg_wheel_name(self) -> None:
        assemble = next(
            line
            for line in self.rendered
            if "assemble-registry-client-wheel.py" in line
        )
        self.assertIn(
            "--breg-wheel /work/product-wheels/"
            "registry_breg_client_native-9.9.9-cp310-abi3-macosx_11_0_arm64.whl",
            assemble,
        )
        for product in ("discovery", "evidence", "relay"):
            self.assertIn(
                f"--{product}-wheel /work/product-wheels/"
                f"registry_{product}_client-9.9.9-cp310-abi3-macosx_11_0_arm64.whl",
                assemble,
            )

    def test_each_platform_names_the_wheel_tag_its_release_matrix_builds(self) -> None:
        candidate = (
            ROOT / ".github" / "workflows" / "release-candidate.yml"
        ).read_text(encoding="utf-8")
        for entry in self.module.PLATFORMS.values():
            self.assertIn(f"registry_wheel_tag: {entry['wheel_tag']}", candidate)

    def test_the_artifact_selection_splits_the_two_halves(self) -> None:
        node_only = self.module.plan(
            ROOT, "9.9.9", "darwin-arm64", "node", "maturin", Path("/work"), Path("/out")
        )
        python_only = self.module.plan(
            ROOT,
            "9.9.9",
            "darwin-arm64",
            "python",
            "maturin",
            Path("/work"),
            Path("/out"),
        )
        self.assertFalse(any("maturin" in step.render() for step in node_only))
        self.assertFalse(any("npm pack" in step.render() for step in python_only))
        self.assertEqual(len(self.steps), len(node_only) + len(python_only))

    def test_the_dry_run_prints_the_recipe_and_touches_nothing(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--output-dir",
                "/out",
                "--napi-platform",
                "darwin-arm64",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("npm pack --ignore-scripts", result.stdout)
        self.assertIn("assemble-registry-client-wheel.py", result.stdout)
        self.assertFalse(Path("/out").exists())

    def test_an_unsupported_host_is_refused(self) -> None:
        self.assertNotIn(("Windows", "AMD64"), self.module.HOST_PLATFORMS)
        self.assertEqual(sorted(self.module.PLATFORMS), sorted(
            set(self.module.HOST_PLATFORMS.values())
        ))


if __name__ == "__main__":
    unittest.main()
