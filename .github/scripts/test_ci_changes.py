#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import subprocess
import tomllib
import unittest
from pathlib import Path

from ci_changes import SHARDS, Workspace, classify
from run_cargo_packages import command_args, package_args


class CiChangesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        metadata = subprocess.run(
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        cls.workspace = Workspace(json.loads(metadata.stdout))

    def test_shards_cover_every_workspace_package_once(self) -> None:
        assigned = [package for packages in SHARDS.values() for package in packages]
        self.assertCountEqual(assigned, self.workspace.package_names)
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_example_pr_runs_only_affected_rust_shards(self) -> None:
        outputs = classify(
            self.workspace,
            (
                ".github/workflows/release.yml",
                "crates/registry-relay/docs/configuration.md",
                "crates/registry-relay/src/state_plane/runtime.rs",
                "crates/registryctl/src/project_authoring/project.rs",
                "release/scripts/test_registry_release.py",
            ),
        )
        shard_names = {
            entry["name"] for entry in outputs["rust_matrix"]["include"]
        }
        self.assertEqual(shard_names, {"relay", "registryctl"})
        self.assertTrue(outputs["release_tool"])
        self.assertTrue(outputs["release_source_proof"])
        self.assertTrue(outputs["registryctl_tutorial"])
        self.assertFalse(outputs["platform"])

    def test_reverse_dependencies_are_included(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-platform-crypto/src/lib.rs",),
        )
        self.assertIn("registry-platform-crypto", outputs["rust_packages"])
        self.assertIn("registry-relay", outputs["rust_packages"])
        self.assertIn("registry-notary", outputs["rust_packages"])

    def test_ci_workflow_change_runs_the_complete_matrix(self) -> None:
        outputs = classify(self.workspace, (".github/workflows/ci.yml",))
        self.assertCountEqual(outputs["rust_packages"], self.workspace.package_names)
        self.assertTrue(outputs["docs"])
        self.assertTrue(outputs["editors"])

    def test_docs_only_change_skips_rust(self) -> None:
        outputs = classify(
            self.workspace,
            ("docs/site/src/content/docs/reference/glossary.mdx",),
        )
        self.assertFalse(outputs["rust"])
        self.assertEqual(outputs["rust_matrix"], {"include": []})
        self.assertTrue(outputs["docs"])

    def test_other_workflow_changes_do_not_select_the_full_matrix(self) -> None:
        outputs = classify(
            self.workspace,
            (".github/workflows/release.yml",),
        )
        self.assertFalse(outputs["rust"])
        self.assertTrue(outputs["release_tool"])
        self.assertTrue(outputs["release_source_proof"])
        self.assertFalse(outputs["docs"])

    def test_nightly_notary_fuzz_inventory_matches_declared_targets(self) -> None:
        workflow = Path(".github/workflows/nightly-security.yml").read_text(
            encoding="utf-8"
        )
        target_block = re.search(
            r"name: Run notary fuzz smoke.*?for target in \\\n"
            r"(?P<targets>.*?)\n\s*do",
            workflow,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(target_block)
        configured = re.findall(
            r"^\s+([a-z][a-z0-9_]*)",
            target_block["targets"],
            re.MULTILINE,
        )

        manifest = tomllib.loads(
            Path("products/notary/fuzz/Cargo.toml").read_text(encoding="utf-8")
        )
        declared = [target["name"] for target in manifest["bin"]]
        self.assertCountEqual(configured, declared)


class RunCargoPackagesTest(unittest.TestCase):
    def test_builds_a_direct_cargo_argument_vector(self) -> None:
        packages = package_args('["registry-relay","registryctl"]')
        self.assertEqual(
            command_args("test", packages, True),
            [
                "cargo",
                "test",
                "--locked",
                "--profile",
                "ci",
                "-p",
                "registry-relay",
                "-p",
                "registryctl",
                "--all-features",
            ],
        )

    def test_rejects_shell_syntax_in_package_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Cargo package name"):
            package_args('["registry-relay; id"]')


if __name__ == "__main__":
    unittest.main()
