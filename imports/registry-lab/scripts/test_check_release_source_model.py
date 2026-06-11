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


class ReleaseSourceModelTest(unittest.TestCase):
    def test_vendor_mode_accepts_clean_committed_submodules(self) -> None:
        with ReleaseSourceFixture() as lab_root:
            result = run_validator(lab_root)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release-source registry-relay", result.stdout)
        self.assertIn("dirty=0", result.stdout)

    def test_vendor_mode_rejects_submodule_head_past_gitlink(self) -> None:
        with ReleaseSourceFixture() as lab_root:
            relay = lab_root / "vendor" / "registry-relay"
            configure_identity(relay)
            (relay / "src.txt").write_text("advanced\n", encoding="utf-8")
            git(relay, "add", "src.txt")
            git(relay, "commit", "-m", "Advance relay")

            result = run_validator(lab_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match committed gitlink", result.stderr)

    def test_vendor_mode_rejects_dirty_submodule(self) -> None:
        with ReleaseSourceFixture() as lab_root:
            (lab_root / "vendor" / "registry-notary" / "dirty.txt").write_text(
                "dirty\n",
                encoding="utf-8",
            )

            result = run_validator(lab_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("vendor checkout has 1 dirty path(s)", result.stderr)

    def test_vendor_mode_rejects_uninitialized_submodule(self) -> None:
        with ReleaseSourceFixture() as lab_root:
            git(lab_root, "submodule", "deinit", "-f", "vendor/registry-manifest")

            result = run_validator(lab_root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("submodule is not initialized", result.stderr)


class ReleaseSourceFixture:
    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sources = root / "sources"
        self.lab_root = root / "registry-lab"
        self.sources.mkdir()
        self.lab_root.mkdir()
        git(self.lab_root, "init")
        configure_identity(self.lab_root)
        (self.lab_root / "scripts").mkdir()
        shutil.copy2(VALIDATOR_PATH, self.lab_root / "scripts" / VALIDATOR_PATH.name)

        for name in (
            "registry-platform",
            "registry-relay",
            "registry-notary",
            "registry-manifest",
            "cel-mapping",
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
                self.lab_root,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                str(source),
                f"vendor/{name}",
            )

        git(self.lab_root, "add", ".gitmodules", "vendor")
        git(self.lab_root, "commit", "-m", "Seed vendor submodules")
        return self.lab_root

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.tmp.cleanup()


def run_validator(lab_root: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["REGISTRY_LAB_CHECK_ATLAS"] = "0"
    return subprocess.run(
        ["bash", "scripts/check-release-source-model.sh", "vendor"],
        cwd=lab_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def configure_identity(repo: Path) -> None:
    git(repo, "config", "user.name", "Registry Lab Test")
    git(repo, "config", "user.email", "registry-lab-test@example.invalid")


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )


if __name__ == "__main__":
    unittest.main()
