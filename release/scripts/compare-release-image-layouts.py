#!/usr/bin/env python3
"""Compare release OCI layouts without depending on mutable image tags."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class LayoutError(ValueError):
    pass


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise LayoutError(f"missing OCI layout file: {path}") from error
    except json.JSONDecodeError as error:
        raise LayoutError(f"invalid OCI layout JSON in {path}: {error}") from error


def digest_blob(layout: Path, digest: object) -> Path:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise LayoutError(f"unsupported OCI digest in {layout}: {digest!r}")
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise LayoutError(f"invalid sha256 digest in {layout}: {digest!r}")
    return layout / "blobs" / "sha256" / value


def verified_digest_blob(layout: Path, digest: object) -> Path:
    path = digest_blob(layout, digest)
    try:
        with path.open("rb") as blob:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: blob.read(1024 * 1024), b""):
                hasher.update(chunk)
    except FileNotFoundError as error:
        raise LayoutError(f"missing OCI blob in {layout}: {digest}") from error
    actual = f"sha256:{hasher.hexdigest()}"
    if actual != digest:
        raise LayoutError(
            f"OCI blob digest mismatch in {layout}: expected {digest}, got {actual}"
        )
    return path


def manifest_context(layout: Path) -> tuple[str, str, list[str]]:
    index_path = layout / "index.json"
    index = read_json(index_path)
    index_digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1:
        count = len(manifests) if isinstance(manifests, list) else 0
        raise LayoutError(f"expected exactly one OCI manifest in {layout}, found {count}")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict):
        raise LayoutError(f"invalid OCI manifest descriptor in {layout}")
    manifest_digest = descriptor.get("digest")
    manifest = read_json(verified_digest_blob(layout, manifest_digest))
    config = manifest.get("config") if isinstance(manifest, dict) else None
    if not isinstance(config, dict):
        raise LayoutError(f"OCI manifest in {layout} has no config descriptor")
    verified_digest_blob(layout, config.get("digest"))
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    if not isinstance(layers, list) or not layers:
        raise LayoutError(f"OCI manifest in {layout} has no layers")
    layer_digests: list[str] = []
    for layer in layers:
        if not isinstance(layer, dict):
            raise LayoutError(f"invalid OCI layer descriptor in {layout}")
        digest = layer.get("digest")
        verified_digest_blob(layout, digest)
        layer_digests.append(str(digest))
    return index_digest, str(manifest_digest), layer_digests


def compare_layouts(left: Path, right: Path, *, exact_image: bool) -> None:
    left_index, left_manifest, left_layers = manifest_context(left)
    right_index, right_manifest, right_layers = manifest_context(right)
    if left_layers != right_layers:
        raise LayoutError(
            "ordered rootfs layer digests differ: "
            f"{left}={left_layers!r} {right}={right_layers!r}"
        )
    if exact_image and left_manifest != right_manifest:
        raise LayoutError(
            f"image manifest digests differ: {left_manifest} != {right_manifest}"
        )
    if exact_image and left_index != right_index:
        raise LayoutError(f"OCI indexes differ: {left} != {right}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument(
        "--rootfs-only",
        action="store_true",
        help="require identical ordered rootfs layers but allow image metadata to differ",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        compare_layouts(args.left, args.right, exact_image=not args.rootfs_only)
    except LayoutError as error:
        print(f"release image layout comparison failed: {error}", file=sys.stderr)
        return 1
    scope = "rootfs" if args.rootfs_only else "image and rootfs"
    print(f"verified identical release {scope}: {args.left} == {args.right}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
