# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for supporting-service release images."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SUPPORTING_IMAGES = {
    "breg-mcp": {
        "workdir": "/var/lib/breg-mcp",
        "command": 'CMD ["--runtime-config", "/etc/breg-mcp/runtime.yaml", "serve"]',
    },
    "breg-review": {
        "workdir": "/var/lib/breg-review",
        "command": 'CMD ["--runtime-config", "/etc/breg-review/runtime.yaml", "serve"]',
    },
    "evidence-oid4vci": {
        "workdir": "/var/lib/registry-evidence-oid4vci",
        "command": 'CMD ["serve", "--runtime-config", "/etc/registry-evidence-oid4vci/runtime.yaml"]',
    },
    "messaging": {
        "workdir": "/var/lib/registry-messaging",
        "command": 'CMD ["--runtime-config", "/etc/registry-messaging/runtime.yaml", "serve"]',
    },
    "registry-render": {
        "workdir": "/var/lib/registry-render",
        "command": 'CMD ["serve", "--runtime-config", "/etc/registry-render/runtime.yaml"]',
    },
}


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
            'CMD ["serve", "--runtime-config", '
            '"/etc/registry-evidence-oid4vci/runtime.yaml"]',
            dockerfile,
        )

    def test_supporting_images_share_the_release_runtime_contract(self) -> None:
        for name, contract in SUPPORTING_IMAGES.items():
            with self.subTest(name=name):
                dockerfile = self.dockerfile(name)
                self.assertIn(
                    "gcr.io/distroless/cc-debian13:nonroot@sha256:", dockerfile
                )
                self.assertIn('org.registrystack.runtime.uid="65532"', dockerfile)
                self.assertIn('org.registrystack.runtime.gid="65532"', dockerfile)
                self.assertIn(f"/licenses/{name}/LICENSE", dockerfile)
                self.assertIn(f"/licenses/{name}/THIRD_PARTY_NOTICES", dockerfile)
                self.assertIn(f"WORKDIR {contract['workdir']}", dockerfile)
                self.assertIn(contract["command"], dockerfile)
                self.assertIn(f'ENTRYPOINT ["/usr/local/bin/{name}"]', dockerfile)

    def test_messaging_image_requires_its_operator_tool(self) -> None:
        dockerfile = self.dockerfile("messaging")
        self.assertIn(
            "install -m 0755 /workspace/image-bin/messagingctl "
            "/workspace/runtime-root/usr/local/bin/messagingctl",
            dockerfile,
        )
        self.assertNotIn("if [ -e /workspace/image-bin/messagingctl ]", dockerfile)

    def test_shared_publication_surfaces_admit_every_supporting_image(self) -> None:
        builder = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        supported = next(
            line.strip()
            for line in builder.splitlines()
            if line.strip().startswith("discovery|evidence|")
        )
        collector = (ROOT / "release/scripts/collect-rehearsal-advisory-evidence.py").read_text(
            encoding="utf-8"
        )
        smoke = (ROOT / "release/scripts/smoke-release-image-oci-labels.sh").read_text(
            encoding="utf-8"
        )
        cleanup = (ROOT / "release/scripts/cleanup-release-candidates.py").read_text(
            encoding="utf-8"
        )
        for name in SUPPORTING_IMAGES:
            with self.subTest(name=name):
                self.assertIn(name, supported)
                self.assertIn(f'"{name}"', collector)
                self.assertIn(name, smoke.split("images=(", 1)[1].split(")", 1)[0])
                self.assertIn(f'"{name}",', cleanup)
                self.assertIn(f'"{name}-candidate",', cleanup)


if __name__ == "__main__":
    unittest.main()
