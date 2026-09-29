# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for the Render and Evidence OID4VCI release images."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SupportingReleaseImageTests(unittest.TestCase):
    def dockerfile(self, name: str) -> str:
        return (ROOT / f"release/docker/Dockerfile.{name}").read_text(
            encoding="utf-8"
        )

    def test_registry_render_image_keeps_packages_external_and_audit_writable(self) -> None:
        dockerfile = self.dockerfile("registry-render")
        self.assertIn(
            "install -m 0755 /workspace/image-bin/registry-render "
            "/workspace/runtime-root/usr/local/bin/registry-render",
            dockerfile,
        )
        self.assertIn("WORKDIR /var/lib/registry-render", dockerfile)
        self.assertIn(
            "chmod 0700 /workspace/runtime-root/var/lib/registry-render/audit",
            dockerfile,
        )
        self.assertIn(
            'CMD ["serve", "--runtime-config", '
            '"/etc/registry-render/runtime.yaml"]',
            dockerfile,
        )
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("fontconfig", dockerfile)
        self.assertNotIn("/workspace/runtime-root/srv", dockerfile)

    def test_oid4vci_image_keeps_only_process_local_delivery_state(self) -> None:
        dockerfile = self.dockerfile("evidence-oid4vci")
        self.assertIn(
            "install -m 0755 /workspace/image-bin/evidence-oid4vci "
            "/workspace/runtime-root/usr/local/bin/evidence-oid4vci",
            dockerfile,
        )
        self.assertIn("WORKDIR /var/lib/registry-evidence-oid4vci", dockerfile)
        self.assertIn(
            "chmod 0700 /workspace/runtime-root/var/lib/registry-evidence-oid4vci",
            dockerfile,
        )
        self.assertNotIn("/var/lib/registry-evidence-oid4vci/audit", dockerfile)
        self.assertNotIn("/var/lib/registry-evidence-oid4vci/state", dockerfile)
        self.assertIn(
            'CMD ["serve", "--config", '
            '"/etc/registry-evidence-oid4vci/runtime.yaml"]',
            dockerfile,
        )

    def test_both_images_ship_license_notices_as_nonroot_distroless(self) -> None:
        for name in ("registry-render", "evidence-oid4vci"):
            with self.subTest(name=name):
                dockerfile = self.dockerfile(name)
                self.assertIn(
                    "gcr.io/distroless/cc-debian13:nonroot@sha256:", dockerfile
                )
                self.assertIn('org.registrystack.runtime.uid="65532"', dockerfile)
                self.assertIn('org.registrystack.runtime.gid="65532"', dockerfile)
                self.assertIn(f"/licenses/{name}/LICENSE", dockerfile)
                self.assertIn(f"/licenses/{name}/THIRD_PARTY_NOTICES", dockerfile)

    def test_release_image_builder_admits_both_image_names(self) -> None:
        builder = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        supported = next(
            line.strip()
            for line in builder.splitlines()
            if line.strip().startswith("discovery|evidence|")
        )
        self.assertIn("|evidence-oid4vci|", supported)
        self.assertIn("|registry-render|", supported)


if __name__ == "__main__":
    unittest.main()
