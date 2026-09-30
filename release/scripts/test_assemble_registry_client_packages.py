#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
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

    def test_the_staged_copy_is_recreated_on_every_run(self) -> None:
        removals = [
            index
            for index, line in enumerate(self.rendered)
            if "rm -rf /work/node-root)" in line
        ]
        self.assertEqual(1, len(removals), "the staged copy is not discarded")
        copies = [
            index
            for index, line in enumerate(self.rendered)
            if "cp -R" in line and "/work/node-root" in line
        ]
        self.assertTrue(copies, "nothing is copied into the staged copy")
        self.assertLess(removals[0], min(copies))

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

    def test_macos_platform_package_bundles_fips_dylibs_before_packing(self) -> None:
        bundle_index, bundle = next(
            (index, step)
            for index, step in enumerate(self.steps)
            if step.argv[0:2]
            == (
                "python3",
                str(ROOT / "release/scripts/bundle-client-macos-fips.py"),
            )
        )
        platform_directory = Path("/work/node-root/npm/darwin-arm64")
        self.assertIn(
            ("--library-directory", str(platform_directory)),
            tuple(zip(bundle.argv, bundle.argv[1:])),
        )
        self.assertIn(
            ("--library-root", str(ROOT / "target")),
            tuple(zip(bundle.argv, bundle.argv[1:])),
        )
        consumers = [
            Path(bundle.argv[index + 1])
            for index, argument in enumerate(bundle.argv)
            if argument == "--consumer"
        ]
        self.assertEqual(
            consumers,
            [
                platform_directory / f"{product}-client.darwin-arm64.node"
                for product in self.module.PRODUCTS
            ],
        )
        addon_copies = [
            index
            for index, step in enumerate(self.steps)
            if step.description.startswith("add the built ")
        ]
        pack_indices = [
            index
            for index, step in enumerate(self.steps)
            if step.argv[:2] == ("npm", "pack")
        ]
        self.assertLess(max(addon_copies), bundle_index)
        self.assertLess(bundle_index, min(pack_indices))

        manifest = json.loads(
            (
                ROOT
                / "crates/registry-stack-client-node/npm/darwin-arm64/package.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn("*.dylib", manifest["files"])

    def test_linux_packages_do_not_run_the_macos_bundler(self) -> None:
        steps = self.module.plan(
            ROOT,
            "9.9.9",
            "linux-x64-gnu",
            "all",
            "/maturin/maturin",
            Path("/work"),
            Path("/out"),
            "/maturin/python",
        )
        self.assertFalse(
            any(
                any(
                    argument.endswith("bundle-client-macos-fips.py")
                    for argument in step.argv
                )
                for step in steps
            )
        )
        assemble = next(
            step
            for step in steps
            if any(
                argument.endswith("assemble-registry-client-wheel.py")
                for argument in step.argv
            )
        )
        self.assertNotIn("--macos-library-root", assemble.argv)

    def test_the_product_wheels_are_rebuilt_from_an_empty_directory(self) -> None:
        removals = [
            index
            for index, line in enumerate(self.rendered)
            if "rm -rf /work/product-wheels)" in line
        ]
        self.assertEqual(1, len(removals), "the previous product wheels are kept")
        builds = [
            index
            for index, line in enumerate(self.rendered)
            if "maturin build" in line
        ]
        self.assertTrue(builds, "no product wheel is built")
        self.assertLess(removals[0], min(builds))

    def test_the_binding_wheels_are_built_before_the_public_wheel(self) -> None:
        builds = [
            index
            for index, line in enumerate(self.rendered)
            if "maturin build --release --locked" in line
        ]
        self.assertEqual(5, len(builds))
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
        self.assertIn(
            "--casework-wheel /work/product-wheels/"
            "registry_casework_client_native-9.9.9-cp310-abi3-macosx_11_0_arm64.whl",
            assemble,
        )
        self.assertIn(f"--macos-library-root {ROOT / 'target'}", assemble)

    def test_ci_profile_only_changes_all_five_binding_build_profiles(self) -> None:
        for napi_platform in self.module.PLATFORMS:
            with self.subTest(platform=napi_platform):
                args = (
                    ROOT, "9.9.9", napi_platform, "all", "maturin",
                    Path("/work"), Path("/out"), "/maturin/python",
                )
                release = self.module.plan(*args)
                ci = self.module.plan(*args, python_profile="ci")
                self.assertEqual(len(release), len(ci))
                products = []
                for release_step, ci_step in zip(release, ci):
                    if release_step.argv[:2] == ("maturin", "build"):
                        self.assertEqual(
                            ci_step.argv,
                            ("maturin", "build", "--profile", "ci", *release_step.argv[3:]),
                        )
                        self.assertEqual(ci_step.cwd, release_step.cwd)
                        products.append(ci_step.cwd.name)
                    elif release_step.argv[0].endswith("build-linux-python-client"):
                        profile_index = release_step.argv.index("--profile") + 1
                        self.assertEqual(release_step.argv[profile_index], "release")
                        expected = list(release_step.argv)
                        expected[profile_index] = "ci"
                        self.assertEqual(ci_step.argv, tuple(expected))
                        self.assertEqual(ci_step.cwd, release_step.cwd)
                        products.append(
                            release_step.argv[release_step.argv.index("--client") + 1]
                        )
                    else:
                        self.assertEqual(ci_step, release_step)
                expected_products = list(self.module.PRODUCTS)
                if napi_platform == "darwin-arm64":
                    expected_products = [
                        f"registry-{product}-client-py"
                        for product in self.module.PRODUCTS
                    ]
                self.assertEqual(products, expected_products)

    def test_cli_ci_profile_is_explicit_and_rejects_unknown_profiles(self) -> None:
        command = [
            sys.executable, str(SCRIPT), "--output-dir", "/out",
            "--napi-platform", "linux-x64-gnu", "--artifacts", "python", "--dry-run",
            "--include-casework", "--zig-python", "/maturin/python",
            "--maturin", "/maturin/maturin",
        ]
        result = subprocess.run(
            [*command, "--python-profile", "ci"], capture_output=True, text=True, check=True
        )
        self.assertEqual(result.stdout.count("build-linux-python-client"), 5)
        self.assertEqual(result.stdout.count("--profile ci"), 5)
        self.assertNotIn("--profile release", result.stdout)
        invalid = subprocess.run(
            [*command, "--python-profile", "dev"], capture_output=True, text=True
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("invalid choice", invalid.stderr)

    def test_path_maturin_is_resolved_for_the_linux_helper(self) -> None:
        resolved = self.module.resolve_executable("python3")
        self.assertTrue(Path(resolved).is_absolute())
        self.assertEqual(Path(resolved), Path(sys.executable).resolve())
        with self.assertRaisesRegex(ValueError, "executable is not on PATH"):
            self.module.resolve_executable("definitely-not-a-registry-build-tool")

    def test_linux_wheels_use_the_canonical_zig_compiler_helper(self) -> None:
        steps = self.module.plan(
            ROOT,
            "9.9.9",
            "linux-x64-gnu",
            "python",
            "/maturin/maturin",
            Path("/work"),
            Path("/out"),
            "/maturin/python",
        )
        builds = [
            step
            for step in steps
            if step.argv[0].endswith("build-linux-python-client")
        ]
        self.assertEqual(len(builds), 5)
        for product, step in zip(self.module.PRODUCTS, builds):
            self.assertEqual(step.cwd, ROOT)
            self.assertIn(("--client", product), tuple(zip(step.argv, step.argv[1:])))
            self.assertIn("x86_64-unknown-linux-gnu", step.argv)
            self.assertIn("manylinux_2_17", step.argv)
            self.assertIn("/maturin/python", step.argv)
            self.assertNotIn("--zig", step.argv)

        with self.assertRaisesRegex(ValueError, "require --zig-python"):
            self.module.plan(
                ROOT,
                "9.9.9",
                "linux-x64-gnu",
                "python",
                "/maturin/maturin",
                Path("/work"),
                Path("/out"),
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
                "--include-casework",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("npm pack --ignore-scripts", result.stdout)
        self.assertIn("assemble-registry-client-wheel.py", result.stdout)
        self.assertFalse(Path("/out").exists())

    def test_0_29_requires_explicit_casework_candidate_selection(self) -> None:
        args = (
            ROOT,
            "0.29.0",
            "darwin-arm64",
            "all",
            "maturin",
            Path("/work"),
            Path("/out"),
        )
        with self.assertRaisesRegex(ValueError, "explicit --include-casework"):
            self.module.plan(*args)

        candidate = self.module.plan(*args, include_casework=True)
        rendered = [step.render() for step in candidate]
        self.assertTrue(
            any("casework-client.darwin-arm64.node" in line for line in rendered)
        )
        wheel = next(
            line
            for line in rendered
            if "assemble-registry-client-wheel.py" in line
        )
        self.assertIn("--include-casework", wheel)
        self.assertFalse(
            any("bundle-client-macos-fips.py" in line for line in rendered)
        )
        self.assertNotIn("--macos-library-root", wheel)

    def test_0_30_includes_casework_without_the_candidate_override(self) -> None:
        steps = self.module.plan(
            ROOT,
            "0.30.0",
            "darwin-arm64",
            "all",
            "maturin",
            Path("/work"),
            Path("/out"),
        )
        rendered = [step.render() for step in steps]
        self.assertTrue(
            any("casework-client.darwin-arm64.node" in line for line in rendered)
        )
        wheel = next(
            line
            for line in rendered
            if "assemble-registry-client-wheel.py" in line
        )
        self.assertNotIn("--include-casework", wheel)

    def test_an_unsupported_host_is_refused(self) -> None:
        self.assertNotIn(("Windows", "AMD64"), self.module.HOST_PLATFORMS)
        self.assertEqual(sorted(self.module.PLATFORMS), sorted(
            set(self.module.HOST_PLATFORMS.values())
        ))


if __name__ == "__main__":
    unittest.main()
