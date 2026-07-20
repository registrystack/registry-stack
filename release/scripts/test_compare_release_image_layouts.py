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
    spec = importlib.util.spec_from_file_location("compare_release_image_layouts", SCRIPT)
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
    manifest_payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_digest = sha256(manifest_payload)
    (blobs / manifest_digest.removeprefix("sha256:")).write_bytes(manifest_payload)
    descriptor: dict[str, object] = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": len(manifest_payload),
    }
    if index_annotation is not None:
        descriptor["annotations"] = {"example.test/index": index_annotation}
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": [descriptor]}),
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

    def test_exact_comparison_rejects_metadata_only_manifest_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(
                root / "right", layers=[b"base", b"app"], config_seed="other"
            )

            with self.assertRaisesRegex(self.module.LayoutError, "manifest digests differ"):
                self.module.compare_layouts(left, right, exact_image=True)
            self.module.compare_layouts(left, right, exact_image=False)

    def test_rootfs_comparison_rejects_changed_ordered_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = write_layout(root / "left", layers=[b"base", b"app"])
            right = write_layout(root / "right", layers=[b"base", b"changed"])

            with self.assertRaisesRegex(self.module.LayoutError, "rootfs layer digests differ"):
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
