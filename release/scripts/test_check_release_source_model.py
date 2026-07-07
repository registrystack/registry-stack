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


class ReleaseSourceModelTest(unittest.TestCase):
    def test_vendor_mode_accepts_clean_committed_submodules(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            result = run_validator(checkout_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release-source registry-relay", result.stdout)
        self.assertIn("dirty=0", result.stdout)

    def test_vendor_mode_rejects_submodule_head_past_gitlink(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            relay = checkout_root / "vendor" / "registry-relay"
            configure_identity(relay)
            (relay / "src.txt").write_text("advanced\n", encoding="utf-8")
            git(relay, "add", "src.txt")
            git(relay, "commit", "-m", "Advance relay")

            result = run_validator(checkout_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match committed gitlink", result.stderr)

    def test_vendor_mode_rejects_dirty_submodule(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            (checkout_root / "vendor" / "registry-notary" / "dirty.txt").write_text(
                "dirty\n",
                encoding="utf-8",
            )

            result = run_validator(checkout_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("vendor checkout has 1 dirty path(s)", result.stderr)

    def test_vendor_mode_rejects_uninitialized_submodule(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            git(checkout_root, "submodule", "deinit", "-f", "vendor/registry-manifest")

            result = run_validator(checkout_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("submodule is not initialized", result.stderr)

    def test_vendor_mode_ignores_deprecated_in_repo_cel_mapping_default(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            stale = checkout_root / "vendor" / "cel-mapping"
            stale.mkdir()
            (stale / "Cargo.toml").write_text(
                "[package]\nname = \"cel-mapping\"\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )

            result = run_validator(
                checkout_root,
                extra_env={"CEL_MAPPING_SOURCE_DIR": "./vendor/cel-mapping"},
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release-source crosswalk", result.stdout)
        self.assertNotIn("vendor/cel-mapping", result.stdout)

    def test_vendor_mode_prefers_legacy_lab_vendor_gitlinks(self) -> None:
        """The script must default to lab/vendor/ pins while lab/ still exists."""
        with ReleaseSourceFixture(
            script_rel_dir="release/scripts",
            vendor_rel_dir="lab/vendor",
        ) as checkout_root:
            result = _run(
                checkout_root,
                "release/scripts/check-release-source-model.sh",
                "vendor",
                None,
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("lab/vendor/crosswalk", result.stdout)
        self.assertIn("lab/vendor/registry-relay", result.stdout)

    def test_vendor_mode_ignores_stale_lab_cel_mapping_default(self) -> None:
        """The lab-root absolute deprecated default must stay ignored."""
        with ReleaseSourceFixture(
            script_rel_dir="release/scripts",
            vendor_rel_dir="lab/vendor",
        ) as checkout_root:
            stale = checkout_root / "lab" / "vendor" / "cel-mapping"
            stale.mkdir()
            (stale / "Cargo.toml").write_text(
                "[package]\nname = \"cel-mapping\"\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )

            result = _run(
                checkout_root,
                "release/scripts/check-release-source-model.sh",
                "vendor",
                # resolve() matches the script's physical repo-root spelling,
                # the same exact-string form the old lab script ignored.
                {"CEL_MAPPING_SOURCE_DIR": str(stale.resolve())},
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("lab/vendor/crosswalk", result.stdout)
        self.assertNotIn("cel-mapping", result.stdout)

    def test_vendor_mode_resolves_lab_relative_crosswalk_override(self) -> None:
        """lab/justfile exports CROSSWALK_SOURCE_DIR=./vendor/crosswalk relative to lab/."""
        with ReleaseSourceFixture(
            script_rel_dir="release/scripts",
            vendor_rel_dir="lab/vendor",
        ) as checkout_root:
            result = _run(
                checkout_root,
                "release/scripts/check-release-source-model.sh",
                "vendor",
                {"CROSSWALK_SOURCE_DIR": "./vendor/crosswalk"},
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("lab/vendor/crosswalk", result.stdout)

    def test_source_mode_honors_deprecated_cel_mapping_source_dir(self) -> None:
        with ReleaseSourceFixture() as checkout_root:
            sources = checkout_root.parent / "sources"
            crosswalk_source = (sources / "crosswalk").resolve()

            result = _run(
                checkout_root,
                "scripts/check-release-source-model.sh",
                "source",
                {
                    "REGISTRY_PLATFORM_SOURCE_DIR": str(sources / "registry-platform"),
                    "REGISTRY_RELAY_SOURCE_DIR": str(sources / "registry-relay"),
                    "REGISTRY_NOTARY_SOURCE_DIR": str(sources / "registry-notary"),
                    "CEL_MAPPING_SOURCE_DIR": str(sources / "crosswalk"),
                },
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(f"release-source crosswalk {crosswalk_source}", result.stdout)


class MonorepoSourceModelTest(unittest.TestCase):
    """Monorepo mode must pass with no lab/ checkout present.

    lab/ is planned for deletion; the release source proof must not depend on
    it, in-tree or otherwise (registry-stack#224).
    """

    def test_monorepo_mode_passes_without_lab_directory(self) -> None:
        with MonorepoFixture() as stack_root:
            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release-source registry-stack", result.stdout)
        self.assertNotIn("lab", result.stdout)

    def test_monorepo_mode_rejects_missing_relay_crate(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "crates" / "registry-relay")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("registry-relay crate", result.stderr)

    def test_monorepo_mode_records_external_release_refs(self) -> None:
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

    def test_monorepo_mode_rejects_missing_required_external(self) -> None:
        with MonorepoFixture() as stack_root:
            manifest = stack_root / "release" / "manifests" / "registry-stack-test.yaml"
            lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
            kept = [
                line
                for line in lines
                if "registry-atlas" not in line and "2b2b" not in line
            ]
            manifest.write_text("".join(kept), encoding="utf-8")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing required external.registry-atlas", result.stderr)

    def test_monorepo_mode_rejects_gitlink_manifest_ref_drift(self) -> None:
        """While lab/vendor gitlinks are committed, the current manifest must match them."""
        with MonorepoFixture() as stack_root:
            add_gitlink(stack_root, "lab/vendor/registry-atlas", "a" * 40)

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "does not match committed lab/vendor/registry-atlas gitlink",
            result.stderr,
        )

    def test_monorepo_mode_rejects_missing_required_external_gitlink(self) -> None:
        """If legacy lab gitlinks still exist, each current required external must have one."""
        with MonorepoFixture() as stack_root:
            add_gitlink(
                stack_root,
                "lab/vendor/crosswalk",
                "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
            )
            add_gitlink(
                stack_root,
                "lab/vendor/esignet-relay-authenticator",
                "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c",
            )

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "external.registry-atlas has no committed lab/vendor/registry-atlas gitlink",
            result.stderr,
        )

    def test_monorepo_mode_cross_checks_only_the_current_manifest(self) -> None:
        """Historical manifests keep their release-day refs and are not cross-checked."""
        with MonorepoFixture() as stack_root:
            add_gitlink(
                stack_root,
                "lab/vendor/crosswalk",
                "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
            )
            add_gitlink(
                stack_root,
                "lab/vendor/registry-atlas",
                "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
            )
            add_gitlink(
                stack_root,
                "lab/vendor/esignet-relay-authenticator",
                "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c",
            )
            old = stack_root / "release" / "manifests" / "registry-stack-old.yaml"
            old.write_text(
                MANIFEST_YAML.replace("version: 0.0.1", "version: 0.0.0").replace(
                    "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
                    "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
                ),
                encoding="utf-8",
            )

            result = run_monorepo_validator(stack_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "release-source-external-pin registry-stack-test.yaml registry-atlas",
            result.stdout,
        )

    def test_monorepo_mode_rejects_missing_manifests(self) -> None:
        with MonorepoFixture() as stack_root:
            shutil.rmtree(stack_root / "release" / "manifests")

            result = run_monorepo_validator(stack_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("no release manifest", result.stderr)


class ReleaseSourceFixture:
    def __init__(
        self,
        *,
        script_rel_dir: str = "scripts",
        vendor_rel_dir: str = "vendor",
    ) -> None:
        self.script_rel_dir = script_rel_dir
        self.vendor_rel_dir = vendor_rel_dir

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sources = root / "sources"
        self.checkout_root = root / "release-source-checkout"
        self.sources.mkdir()
        self.checkout_root.mkdir()
        git(self.checkout_root, "init")
        configure_identity(self.checkout_root)
        script_dir = self.checkout_root / self.script_rel_dir
        script_dir.mkdir(parents=True)
        shutil.copy2(VALIDATOR_PATH, script_dir / VALIDATOR_PATH.name)

        for name in (
            "registry-platform",
            "registry-relay",
            "registry-notary",
            "registry-manifest",
            "crosswalk",
        ):
            source = self.sources / name
            source.mkdir()
            git(source, "init")
            configure_identity(source)
            (source / "Cargo.toml").write_text(
                f"[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )
            git(source, "add", "Cargo.toml")
            git(source, "commit", "-m", f"Seed {name}")
            git(
                self.checkout_root,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                str(source),
                f"{self.vendor_rel_dir}/{name}",
            )

        git(self.checkout_root, "add", ".gitmodules", self.vendor_rel_dir)
        git(self.checkout_root, "commit", "-m", "Seed vendor submodules")
        return self.checkout_root

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.tmp.cleanup()


class MonorepoFixture:
    """A minimal registry-stack-shaped checkout with release/scripts/ but no lab/."""

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        stack_root = Path(self.tmp.name) / "registry-stack"
        stack_root.mkdir()
        git(stack_root, "init")
        configure_identity(stack_root)
        (stack_root / "Cargo.toml").write_text(
            "[workspace]\nmembers = []\n",
            encoding="utf-8",
        )
        for crate_dir in (
            "crates/registry-platform-authcommon",
            "crates/registry-manifest-core",
            "crates/registry-notary-server",
            "crates/registry-relay",
            "crates/registryctl",
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


def run_validator(
    checkout_root: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(checkout_root, "scripts/check-release-source-model.sh", "vendor", extra_env)


def run_monorepo_validator(
    stack_root: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        stack_root,
        "release/scripts/check-release-source-model.sh",
        "monorepo",
        extra_env,
    )


def _run(
    cwd: Path,
    script_rel_path: str,
    mode: str,
    extra_env: dict[str, str] | None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", script_rel_path, mode],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def add_gitlink(repo: Path, rel_path: str, sha: str) -> None:
    """Record a committed submodule gitlink without materializing a checkout."""
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},{rel_path}")
    git(repo, "commit", "-m", f"Pin {rel_path}")


def configure_identity(repo: Path) -> None:
    git(repo, "config", "user.name", "Registry Stack Test")
    git(repo, "config", "user.email", "registry-stack-test@example.invalid")


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )


if __name__ == "__main__":
    unittest.main()
