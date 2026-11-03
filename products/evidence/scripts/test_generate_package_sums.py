#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit and CLI tests for Evidence package checksum root selection."""

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("generate-package-sums.py")
SPEC = importlib.util.spec_from_file_location("generate_package_sums", SCRIPT)
GENERATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GENERATOR)


class PackageRootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="evidence-package-sums."
        )
        self.root = Path(self.temporary.name)
        self.evidence_root = self.root / "products/evidence"
        self.compiled_extra = self.root / "compiled-extra"
        self.authored_extra = self.root / "authored-extra"

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_evidence(root: Path, kind: str) -> None:
        root.mkdir(parents=True)
        (root / "evidence.yaml").write_text(
            "apiVersion: id.registrystack.org/formats/evidence/v1alpha1\n"
            f"kind: {kind}\n"
        )

    def configured_generator(self):
        return mock.patch.multiple(
            GENERATOR,
            REPOSITORY=self.root,
            EVIDENCE_ROOT=self.evidence_root,
            EXTRA_PACKAGES=(self.authored_extra, self.compiled_extra),
        )

    def test_package_roots_apply_the_bundle_kind_to_normal_and_extra_roots(self):
        normal_bundle = self.evidence_root / "compiled"
        normal_project = self.evidence_root / "authored"
        self.write_evidence(normal_bundle, "EvidenceBundle")
        self.write_evidence(normal_project, "EvidenceProject")
        self.write_evidence(self.compiled_extra, "EvidenceBundle")
        self.write_evidence(self.authored_extra, "EvidenceProject")

        with self.configured_generator():
            roots = GENERATOR.package_roots()

        self.assertEqual(roots, sorted([normal_bundle, self.compiled_extra]))

    def test_write_creates_sums_only_for_compiled_bundles(self):
        normal_bundle = self.evidence_root / "compiled"
        normal_project = self.evidence_root / "authored"
        self.write_evidence(normal_bundle, "EvidenceBundle")
        self.write_evidence(normal_project, "EvidenceProject")
        self.write_evidence(self.compiled_extra, "EvidenceBundle")
        self.write_evidence(self.authored_extra, "EvidenceProject")

        output = io.StringIO()
        with (
            self.configured_generator(),
            mock.patch.object(sys, "argv", [str(SCRIPT), "--write"]),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(GENERATOR.main(), 0)

        self.assertTrue((normal_bundle / "SHA256SUMS").is_file())
        self.assertTrue((self.compiled_extra / "SHA256SUMS").is_file())
        self.assertFalse((normal_project / "SHA256SUMS").exists())
        self.assertFalse((self.authored_extra / "SHA256SUMS").exists())
        self.assertIn("(2 packages)", output.getvalue())


if __name__ == "__main__":
    unittest.main()
