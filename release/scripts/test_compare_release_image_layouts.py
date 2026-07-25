#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("compare-release-image-layouts.py")


def load_module():
    spec = importlib.util.spec_from_file_location(
        "compare_release_image_layouts", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def write_layout(
    root: Path,
    *,
    layers: list[bytes],
    config_seed: str = "config",
    index_annotation: str | None = None,
    provenance: bool = False,
    provenance_subject: str | None = None,
    extra_descriptor: bool = False,
    omit_application_platform: bool = False,
    duplicate_provenance: bool = False,
) -> Path:
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    layer_descriptors = []
    for payload in layers:
        digest = sha256(payload)
        (blobs / digest.removeprefix("sha256:")).write_bytes(payload)
        layer_descriptors.append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": digest,
                "size": len(payload),
            }
        )
    config_payload = config_seed.encode()
    config_digest = sha256(config_payload)
    (blobs / config_digest.removeprefix("sha256:")).write_bytes(config_payload)
    manifest = {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_payload),
        },
        "layers": layer_descriptors,
    }
    manifest_payload = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode()
    manifest_digest = sha256(manifest_payload)
    (blobs / manifest_digest.removeprefix("sha256:")).write_bytes(manifest_payload)
    descriptor: dict[str, object] = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": len(manifest_payload),
    }
    if not omit_application_platform:
        descriptor["platform"] = {"os": "linux", "architecture": "amd64"}
    if index_annotation is not None:
        descriptor["annotations"] = {"example.test/index": index_annotation}
    descriptors = [descriptor]
    if provenance:
        empty_config = b"{}"
        empty_config_digest = sha256(empty_config)
        (blobs / empty_config_digest.removeprefix("sha256:")).write_bytes(empty_config)
        statement = b'{"_type":"https://in-toto.io/Statement/v0.1"}'
        statement_digest = sha256(statement)
        (blobs / statement_digest.removeprefix("sha256:")).write_bytes(statement)
        attestation_manifest = {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.unknown.config.v1+json",
                "digest": empty_config_digest,
                "size": len(empty_config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": statement_digest,
                    "size": len(statement),
                }
            ],
        }
        attestation_payload = json.dumps(
            attestation_manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        attestation_digest = sha256(attestation_payload)
        (blobs / attestation_digest.removeprefix("sha256:")).write_bytes(
            attestation_payload
        )
        provenance_descriptor = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": attestation_digest,
            "size": len(attestation_payload),
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": (provenance_subject or manifest_digest),
            },
        }
        descriptors.append(provenance_descriptor)
        if duplicate_provenance:
            descriptors.append(dict(provenance_descriptor))
    if extra_descriptor:
        descriptors.append(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": len(manifest_payload),
                "platform": {"os": "linux", "architecture": "arm64"},
            }
        )
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": descriptors}),
        encoding="utf-8",
    )
    return root


class CompareReleaseImageLayoutsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_exact_comparison_accepts_identical_images(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(root / "right", layers=[b"base", b"app"])

            self.module.compare_layouts(left, right, exact_image=True)

    def test_default_comparison_rejects_config_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(
                root / "right", layers=[b"base", b"app"], config_seed="other"
            )

            with self.assertRaisesRegex(
                self.module.LayoutError, "config digests differ"
            ):
                self.module.compare_layouts(left, right, exact_image=False)
            self.module.compare_layouts(
                left, right, exact_image=False, rootfs_only=True
            )

    def test_rootfs_comparison_rejects_changed_ordered_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(root / "right", layers=[b"base", b"changed"])

            with self.assertRaisesRegex(
                self.module.LayoutError, "rootfs layer digests differ"
            ):
                self.module.compare_layouts(left, right, exact_image=False)

    def test_exact_comparison_rejects_index_only_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(
                root / "right",
                layers=[b"base", b"app"],
                index_annotation="changed",
            )

            with self.assertRaisesRegex(self.module.LayoutError, "OCI indexes differ"):
                self.module.compare_layouts(left, right, exact_image=True)
            self.module.compare_layouts(left, right, exact_image=False)

    def test_default_comparison_accepts_provenance_bearing_published_layout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            published = write_layout(
                root / "published",
                layers=[b"base", b"app"],
                provenance=True,
            )
            cold = write_layout(root / "cold", layers=[b"base", b"app"])

            self.module.compare_layouts(published, cold, exact_image=False)
            context = self.module.manifest_context(published, require_provenance=True)
            self.assertEqual("linux/amd64", context["platform"])
            self.assertEqual(
                "buildkit-provenance",
                context["topology"]["provenance_descriptors"][0]["kind"],
            )

    def test_rejects_misbound_provenance_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = write_layout(
                Path(directory) / "layout",
                layers=[b"base", b"app"],
                provenance=True,
                provenance_subject="sha256:" + "9" * 64,
            )
            with self.assertRaisesRegex(self.module.LayoutError, "not bound"):
                self.module.manifest_context(layout, require_provenance=True)

    def test_rejects_unclassified_extra_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = write_layout(
                Path(directory) / "layout",
                layers=[b"base", b"app"],
                provenance=True,
                extra_descriptor=True,
            )
            with self.assertRaisesRegex(
                self.module.LayoutError, "unexpected.*topology"
            ):
                self.module.manifest_context(layout, require_provenance=True)

    def test_require_provenance_rejects_plain_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = write_layout(
                Path(directory) / "layout",
                layers=[b"base", b"app"],
            )
            with self.assertRaisesRegex(
                self.module.LayoutError, "no BuildKit provenance"
            ):
                self.module.manifest_context(layout, require_provenance=True)

    def test_provenance_index_requires_explicit_application_platform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = write_layout(
                Path(directory) / "layout",
                layers=[b"base", b"app"],
                provenance=True,
                omit_application_platform=True,
            )
            with self.assertRaisesRegex(self.module.LayoutError, "explicitly declare"):
                self.module.manifest_context(layout, require_provenance=True)

    def test_provenance_index_rejects_duplicate_attestation_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = write_layout(
                Path(directory) / "layout",
                layers=[b"base", b"app"],
                provenance=True,
                duplicate_provenance=True,
            )
            with self.assertRaisesRegex(self.module.LayoutError, "exactly one"):
                self.module.manifest_context(layout, require_provenance=True)

    def test_rejects_missing_layer_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(root / "right", layers=[b"base", b"app"])
            missing_digest = sha256(b"app").removeprefix("sha256:")
            (right / "blobs" / "sha256" / missing_digest).unlink()

            with self.assertRaisesRegex(self.module.LayoutError, "missing OCI blob"):
                self.module.compare_layouts(left, right, exact_image=True)

    def test_rejects_corrupted_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(root / "right", layers=[b"base", b"app"])
            corrupted_digest = sha256(b"app").removeprefix("sha256:")
            (right / "blobs" / "sha256" / corrupted_digest).write_bytes(b"corrupt")

            with self.assertRaisesRegex(self.module.LayoutError, "digest mismatch"):
                self.module.compare_layouts(left, right, exact_image=True)


if __name__ == "__main__":
    unittest.main()
