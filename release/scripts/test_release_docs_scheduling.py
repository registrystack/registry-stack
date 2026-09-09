#!/usr/bin/env python3
"""Keep independently packaged docs bound to the exact candidate inputs."""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ReleaseDocsSchedulingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release-candidate.yml").read_text()
        )
        self.jobs = self.workflow["jobs"]

    def step(self, job: str, name: str) -> dict:
        return next(
            step for step in self.jobs[job]["steps"] if step.get("name") == name
        )

    def test_archive_build_is_independent_and_preserves_source_and_lock(self) -> None:
        docs = self.jobs["build-docs"]
        self.assertEqual(docs["needs"], "validate")
        self.assertNotIn("if", docs)
        self.assertEqual(docs["permissions"], {"contents": "read"})
        checkout = self.step("build-docs", "Checkout exact candidate source")
        self.assertEqual(
            checkout["with"]["ref"], "${{ needs.validate.outputs.source_sha }}"
        )
        self.assertFalse(checkout["with"]["persist-credentials"])
        package = self.step("build-docs", "Package exact release docs archive")
        self.assertEqual(package["working-directory"], "docs/site")
        self.assertEqual(
            package["env"]["DOCS_DOCSET"], "${{ needs.validate.outputs.tag }}"
        )
        self.assertEqual(
            package["env"]["DOCS_ARCHIVE_OUTPUT"],
            "${{ runner.temp }}/registry-docs-${{ needs.validate.outputs.tag }}.tar.gz",
        )
        self.assertEqual(
            package["run"].splitlines(),
            [
                "set -euo pipefail",
                "npm ci",
                "npm run build:archive",
                "npm run archive:snapshot -- \\",
                '  "${DOCS_DOCSET}" \\',
                '  --output "${DOCS_ARCHIVE_OUTPUT}" \\',
                "  --verify-lock",
            ],
        )
        builders = [
            job_id
            for job_id, job in self.jobs.items()
            for step in job["steps"]
            if "npm run build:archive" in step.get("run", "")
        ]
        self.assertEqual(builders, ["build-docs"])

    def test_assembly_requires_current_attempt_docs_artifact(self) -> None:
        assemble = self.jobs["assemble"]
        self.assertIn("build-docs", assemble["needs"])
        self.assertNotIn("if", assemble)
        upload = self.step("build-docs", "Upload exact release docs archive")["with"]
        self.assertEqual(
            upload["name"],
            "candidate-docs-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertEqual(upload["if-no-files-found"], "error")
        self.assertEqual(upload["retention-days"], 2)
        self.assertEqual(
            upload["path"],
            "${{ runner.temp }}/registry-docs-${{ needs.validate.outputs.tag }}.tar.gz",
        )
        download = self.step("assemble", "Download exact build products")["with"]
        self.assertEqual(download["path"], "inputs")
        def expand(value: str) -> str:
            return value.replace("${{ github.run_id }}", "123").replace(
                "${{ github.run_attempt }}", "2"
            )

        self.assertTrue(
            fnmatch.fnmatch(expand(upload["name"]), expand(download["pattern"]))
        )
        self.assertFalse(
            fnmatch.fnmatch("candidate-docs-123-1", expand(download["pattern"]))
        )

    def stage_fixture(
        self, include_docs: bool
    ) -> tuple[subprocess.CompletedProcess, bytes | None]:
        script = self.step(
            "assemble", "Assemble public payload and validate version-appropriate install inputs"
        )["run"]
        # Execute the maintained staging commands before the version-dependent
        # client validation, using opaque archive bytes to detect rewriting.
        script = script.split('version=', 1)[0]
        script = script.replace("${{ needs.validate.outputs.tag }}", "v1.2.3")
        archive = "registry-docs-v1.2.3.tar.gz"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for platform, subdir in (
                ("canonical", "dist/bin"),
                ("macos-arm64", "platform"),
                ("linux-arm64", "platform"),
            ):
                inputs = root / f"inputs/candidate-{platform}-123-2" / subdir
                inputs.mkdir(parents=True)
                (inputs / platform).write_bytes(platform.encode())
            # A stale archive in the old canonical location must not satisfy
            # the independently required docs input.
            (root / "inputs/candidate-canonical-123-2" / archive).write_bytes(b"stale")
            if include_docs:
                docs = root / "inputs/candidate-docs-123-2"
                docs.mkdir()
                (docs / archive).write_bytes(b"exact locked archive\x00\xff")
            result = subprocess.run(
                ["bash", "-c", script],
                cwd=root,
                env={**os.environ, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"},
                capture_output=True,
                text=True,
                check=False,
            )
            staged = root / "candidate/bundle-root" / archive
            return result, staged.read_bytes() if staged.exists() else None

    def test_assembly_copies_exact_docs_bytes(self) -> None:
        result, staged = self.stage_fixture(include_docs=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(staged, b"exact locked archive\x00\xff")

    def test_missing_docs_input_fails_even_with_old_canonical_archive(self) -> None:
        result, staged = self.stage_fixture(include_docs=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate-docs-123-2", result.stderr)
        self.assertIsNone(staged)


if __name__ == "__main__":
    unittest.main()
