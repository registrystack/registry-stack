#!/usr/bin/env python3
"""Hold the build-release-image.sh command line and its platform selection.

The script drives `docker buildx` through a stand-in `docker` on PATH that
records its arguments, so no daemon, registry or base image is needed.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/build-release-image.sh"
BUILDKIT_IMAGE = (
    "ghcr.io/registrystack/buildkit:v0.31.2@sha256:"
    "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
)
BUILDKIT_REPO_DIGEST = (
    "ghcr.io/registrystack/buildkit@sha256:"
    "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
)

FAKE_DOCKER = f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "${{FAKE_DOCKER_LOG}}"
case "$1 ${{2:-}}" in
  "buildx version") echo "github.com/docker/buildx v0.33.0 fixture" ;;
  "buildx inspect") printf 'Driver: docker-container\\nBuildKit version: v0.31.2\\n' ;;
  "ps --all") echo "buildx_buildkit_fixture0" ;;
  "inspect --format") echo "{BUILDKIT_IMAGE}" ;;
  "image inspect") echo "{BUILDKIT_REPO_DIGEST}" ;;
  "buildx build") : ;;
  *) echo "unexpected docker call: $*" >&2; exit 99 ;;
esac
"""


class BuildReleaseImageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text(FAKE_DOCKER, encoding="utf-8")
        docker.chmod(0o755)
        self.fake_bin = fake_bin
        self.log = self.tmp / "docker.log"
        self.log.write_text("", encoding="utf-8")

    def run_script(self, name: str = "breg", **overrides: str) -> subprocess.CompletedProcess:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("RELEASE_IMAGE_")
        }
        environment.update(
            {
                "PATH": f"{self.fake_bin}{os.pathsep}{environment['PATH']}",
                "FAKE_DOCKER_LOG": str(self.log),
                "RELEASE_BUILDX_BUILDER": "fixture",
                "RELEASE_IMAGE_OCI_LAYOUT": str(self.tmp / "layout.oci"),
            }
        )
        environment.update(overrides)
        return subprocess.run(
            [
                str(SCRIPT),
                name,
                "ghcr.io/registrystack/breg-candidate:fixture",
                "https://example.invalid/source",
                "0123456789abcdef0123456789abcdef01234567",
                "1.2.3",
                str(self.tmp / "meta/metadata.json"),
            ],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def build_calls(self) -> list[str]:
        return [
            line
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.startswith("buildx build ")
        ]

    def expected_build_call(self, name: str, platform: str) -> str:
        return " ".join(
            [
                "buildx build --builder fixture",
                f"--platform {platform}",
                f"--file {ROOT}/release/docker/Dockerfile.{name}",
                "--tag ghcr.io/registrystack/breg-candidate:fixture",
                "--provenance=false",
                "--label org.opencontainers.image.source=https://example.invalid/source",
                "--label org.opencontainers.image.revision=0123456789abcdef0123456789abcdef01234567",
                "--label org.opencontainers.image.version=1.2.3",
                "--build-arg SOURCE_DATE_EPOCH=0",
                f"--metadata-file {self.tmp}/meta/metadata.json",
                f"--output type=oci,dest={self.tmp}/layout.oci,tar=false,"
                "rewrite-timestamp=true,compatibility-version=20",
                ".",
            ]
        )

    def test_default_command_line_is_the_amd64_release_command_line(self) -> None:
        result = self.run_script()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            [self.expected_build_call("breg", "linux/amd64")], self.build_calls()
        )

    def test_explicit_amd64_matches_the_default(self) -> None:
        result = self.run_script(RELEASE_IMAGE_PLATFORM="linux/amd64")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            [self.expected_build_call("breg", "linux/amd64")], self.build_calls()
        )

    def test_arm64_changes_only_the_platform(self) -> None:
        result = self.run_script(RELEASE_IMAGE_PLATFORM="linux/arm64")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            [self.expected_build_call("breg", "linux/arm64")], self.build_calls()
        )

    def test_unsupported_platforms_are_refused_before_any_docker_call(self) -> None:
        for platform in ("linux/arm", "linux/amd64,linux/arm64", "darwin/arm64", "arm64", ""):
            with self.subTest(platform=platform):
                self.log.write_text("", encoding="utf-8")
                result = self.run_script(RELEASE_IMAGE_PLATFORM=platform)
                self.assertEqual(2, result.returncode)
                self.assertIn("RELEASE_IMAGE_PLATFORM must be", result.stderr)
                self.assertEqual("", self.log.read_text(encoding="utf-8"))

    def test_adapter_is_a_recognised_image(self) -> None:
        result = self.run_script("adapter")
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.build_calls()
        self.assertEqual(1, len(calls))
        self.assertIn(f"--file {ROOT}/release/docker/Dockerfile.adapter ", calls[0])
        self.assertIn("--platform linux/amd64 ", calls[0])


if __name__ == "__main__":
    unittest.main()
