#!/usr/bin/env python3
"""Focused tests for the release source-model shell validator."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIR / "check-release-source-model.sh"

MANIFEST_YAML = """\
stack:
  release: test
  version: 0.0.1

artifacts:
  registry-lab: 0.0.1

external:
  crosswalk:
    repo: PublicSchema/crosswalk
    ref: 1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a
  registry-atlas:
    repo: example/registry-atlas
    ref: 2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b
  esignet-relay-authenticator:
    repo: example/esignet-relay-authenticator
    ref: 3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c
"""

POST_LAB_MANIFEST_YAML = """\
stack:
  release: test
  version: 0.0.1

external:
  crosswalk:
    repo: PublicSchema/crosswalk
    ref: 1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a
"""

NO_EXTERNAL_MANIFEST_YAML = """\
stack:
  release: test
  version: 0.19.1

external: {}
"""


class MonorepoSourceModelTest(unittest.TestCase):
    def test_monorepo_mode_passes_without_lab_directory(self) -> None:
        with MonorepoFixture() as stack_root:
            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release-source registry-stack", result.stdout)
        self.assertNotIn("lab", result.stdout)

    def test_monorepo_mode_passes_without_retired_notary_crates(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "crates" / "registry-notary-server")

            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)

    def test_monorepo_mode_rejects_legacy_vendor_mode(self) -> None:
        with MonorepoFixture() as stack_root:
            result = run_validator(stack_root, "vendor")

        self.assertEqual(2, result.returncode)
        self.assertIn("REGISTRY_RELEASE_SOURCE_MODE=monorepo", result.stderr)

    def test_monorepo_mode_rejects_deprecated_source_mode_env(self) -> None:
        with MonorepoFixture() as stack_root:
            result = run_validator_with_env_default(
                stack_root,
                extra_env={"REGISTRY_RELEASE_SOURCE_MODE": "source"},
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("REGISTRY_RELEASE_SOURCE_MODE=monorepo", result.stderr)

    def test_monorepo_mode_rejects_missing_relay_v2_crate(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "crates" / "registry-relay-v2")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("registry-relay-v2 crate", result.stderr)

    def test_monorepo_mode_rejects_missing_evidence_oid4vci_crate(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "crates" / "registry-evidence-oid4vci")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("registry-evidence-oid4vci crate", result.stderr)

    def test_monorepo_mode_records_all_declared_external_release_refs(self) -> None:
        with MonorepoFixture() as stack_root:
            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "release-source-external registry-stack-test.yaml crosswalk",
            result.stdout,
        )
        self.assertIn(
            "release-source-external registry-stack-test.yaml registry-atlas",
            result.stdout,
        )

    def test_monorepo_mode_rejects_malformed_external_ref(self) -> None:
        with MonorepoFixture() as stack_root:
            manifest = stack_root / "release" / "manifests" / "registry-stack-test.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
                    "not-a-commit",
                ),
                encoding="utf-8",
            )

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("external.registry-atlas", result.stderr)

    def test_monorepo_mode_allows_omitting_historical_lab_externals(self) -> None:
        with MonorepoFixture() as stack_root:
            manifest = stack_root / "release" / "manifests" / "registry-stack-test.yaml"
            manifest.write_text(POST_LAB_MANIFEST_YAML, encoding="utf-8")

            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "release-source-external registry-stack-test.yaml crosswalk",
            result.stdout,
        )
        self.assertNotIn("registry-atlas", result.stdout)
        self.assertNotIn("esignet-relay-authenticator", result.stdout)

    def test_monorepo_mode_allows_no_external_source_dependencies(self) -> None:
        with MonorepoFixture() as stack_root:
            manifest = stack_root / "release" / "manifests" / "registry-stack-test.yaml"
            manifest.write_text(NO_EXTERNAL_MANIFEST_YAML, encoding="utf-8")

            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("release-source-external", result.stdout)

    def test_monorepo_mode_requires_externals_for_historical_lab_artifact(self) -> None:
        with MonorepoFixture() as stack_root:
            manifest = stack_root / "release" / "manifests" / "registry-stack-test.yaml"
            manifest.write_text(
                MANIFEST_YAML.replace(
                    "  registry-atlas:\n"
                    "    repo: example/registry-atlas\n"
                    "    ref: 2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing required external.registry-atlas", result.stderr)

    def test_monorepo_mode_rejects_missing_manifests(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "release" / "manifests")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("no release manifest", result.stderr)


class MonorepoFixture:
    """A minimal registry-stack-shaped checkout with release tooling."""

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        stack_root = Path(self.tmp.name) / "registry-stack"
        stack_root.mkdir()
        git(stack_root, "init")
        configure_identity(stack_root)
        (stack_root / "Cargo.toml").write_text(
            "[workspace]\n"
            "members = []\n\n"
            "[workspace.dependencies]\n",
            encoding="utf-8",
        )
        (stack_root / "Cargo.lock").write_text(
            "version = 4\n",
            encoding="utf-8",
        )
        for crate_dir in (
            "crates/registry-platform-authcommon",
            "crates/registry-manifest-core",
            "crates/registry-notary-server",
            "crates/registry-discovery-profile",
            "crates/registry-discovery",
            "crates/registry-discoveryctl",
            "crates/registry-discovery-client",
            "crates/registry-discovery-client-node",
            "crates/registry-discovery-client-py",
            "crates/registry-relay-v2",
            "crates/registry-relayctl",
            "crates/registry-relay-http-contract",
            "crates/registry-relay-client",
            "crates/registry-relay-client-node",
            "crates/registry-relay-client-py",
            "crates/registry-evidence",
            "crates/registry-evidencectl",
            "crates/registry-mint",
            "crates/registry-evidence-oid4vci",
            "crates/registry-breg",
            "crates/registry-bregctl",
            "crates/registry-breg-client",
            "crates/registry-breg-client-node",
            "crates/registry-breg-client-py",
            "crates/registry-stack-client-node",
            "crates/registry-stack-client-py",
        ):
            (stack_root / crate_dir).mkdir(parents=True)
            (stack_root / crate_dir / ".keep").write_text("", encoding="utf-8")
        release_scripts = stack_root / "release" / "scripts"
        release_scripts.mkdir(parents=True)
        shutil.copy2(VALIDATOR_PATH, release_scripts / VALIDATOR_PATH.name)
        manifests = stack_root / "release" / "manifests"
        manifests.mkdir()
        (manifests / "registry-stack-test.yaml").write_text(
            MANIFEST_YAML,
            encoding="utf-8",
        )
        git(stack_root, "add", "-A")
        git(stack_root, "commit", "-m", "Seed monorepo checkout")
        self.stack_root = stack_root
        return stack_root

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.tmp.cleanup()


def run_monorepo_validator(
    stack_root: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_validator(stack_root, "monorepo", extra_env=extra_env)


def run_validator(
    stack_root: Path,
    mode: str,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", "release/scripts/check-release-source-model.sh", mode],
        cwd=stack_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def run_validator_with_env_default(
    stack_root: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", "release/scripts/check-release-source-model.sh"],
        cwd=stack_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def configure_identity(repo: Path) -> None:
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Registry Stack Test")


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True)


if __name__ == "__main__":
    unittest.main()
