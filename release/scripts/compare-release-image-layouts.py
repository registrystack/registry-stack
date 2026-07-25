#!/usr/bin/env python3
"""Compare release OCI image config and rootfs without mutable image tags."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
IMAGE_MANIFEST_TYPES = {OCI_MANIFEST, DOCKER_MANIFEST}
ATTESTATION_REFERENCE_TYPE = "attestation-manifest"
ATTESTATION_ANNOTATION = "vnd.docker.reference.type"
SUBJECT_ANNOTATION = "vnd.docker.reference.digest"


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
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
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


def platform_name(descriptor: dict[str, Any]) -> str | None:
    platform = descriptor.get("platform")
    if platform is None:
        return None
    if not isinstance(platform, dict) or set(platform) - {
        "os",
        "architecture",
        "variant",
    }:
        raise LayoutError(
            "OCI descriptor platform is malformed or has unsupported fields"
        )
    os_name = platform.get("os")
    architecture = platform.get("architecture")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        raise LayoutError("OCI descriptor platform requires string os and architecture")
    return f"{os_name}/{architecture}"


def descriptor_manifest(layout: Path, descriptor: dict[str, Any]) -> dict[str, Any]:
    media_type = descriptor.get("mediaType")
    if media_type not in IMAGE_MANIFEST_TYPES:
        raise LayoutError(
            f"unexpected OCI manifest descriptor media type {media_type!r}"
        )
    value = read_json(verified_digest_blob(layout, descriptor.get("digest")))
    if not isinstance(value, dict):
        raise LayoutError(f"OCI manifest in {layout} must be an object")
    return value


def is_provenance_descriptor(descriptor: dict[str, Any]) -> bool:
    annotations = descriptor.get("annotations")
    return (
        isinstance(annotations, dict)
        and annotations.get(ATTESTATION_ANNOTATION) == ATTESTATION_REFERENCE_TYPE
    )


def validate_provenance_descriptor(
    layout: Path,
    descriptor: dict[str, Any],
    application_digest: str,
) -> dict[str, str]:
    annotations = descriptor.get("annotations")
    if not isinstance(annotations, dict):
        raise LayoutError("BuildKit provenance descriptor has no annotations")
    unknown_annotations = set(annotations) - {
        ATTESTATION_ANNOTATION,
        SUBJECT_ANNOTATION,
    }
    if unknown_annotations:
        raise LayoutError(
            "BuildKit provenance descriptor has unexpected annotations: "
            f"{sorted(unknown_annotations)!r}"
        )
    if annotations.get(SUBJECT_ANNOTATION) != application_digest:
        raise LayoutError(
            "BuildKit provenance descriptor is not bound to the selected application manifest"
        )
    if platform_name(descriptor) != "unknown/unknown":
        raise LayoutError(
            "BuildKit provenance descriptor platform must be unknown/unknown"
        )
    manifest = descriptor_manifest(layout, descriptor)
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise LayoutError("BuildKit provenance manifest has no attestation layers")
    if not any(
        isinstance(layer, dict)
        and layer.get("mediaType") == "application/vnd.in-toto+json"
        for layer in layers
    ):
        raise LayoutError(
            "BuildKit provenance manifest has no in-toto attestation layer"
        )
    for layer in layers:
        if not isinstance(layer, dict):
            raise LayoutError(
                "BuildKit provenance manifest has an invalid layer descriptor"
            )
        verified_digest_blob(layout, layer.get("digest"))
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise LayoutError("BuildKit provenance manifest has no config descriptor")
    verified_digest_blob(layout, config.get("digest"))
    return {
        "digest": str(descriptor["digest"]),
        "media_type": str(descriptor["mediaType"]),
        "platform": "unknown/unknown",
        "subject_digest": application_digest,
        "kind": "buildkit-provenance",
    }


def manifest_context(
    layout: Path,
    *,
    expected_platform: str = "linux/amd64",
    require_provenance: bool = False,
) -> dict[str, Any]:
    index_path = layout / "index.json"
    index = read_json(index_path)
    index_digest = "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or not manifests:
        raise LayoutError(f"OCI index in {layout} has no manifest descriptors")
    if any(not isinstance(item, dict) for item in manifests):
        raise LayoutError(f"OCI index in {layout} has an invalid manifest descriptor")

    applications = [
        item
        for item in manifests
        if not is_provenance_descriptor(item)
        and platform_name(item) in {None, expected_platform}
    ]
    provenance = [item for item in manifests if is_provenance_descriptor(item)]
    classified = len(applications) + len(provenance)
    if classified != len(manifests):
        raise LayoutError(
            f"OCI index in {layout} contains unexpected platform or descriptor topology"
        )
    if len(applications) != 1:
        raise LayoutError(
            f"expected exactly one {expected_platform} application manifest in "
            f"{layout}, found {len(applications)}"
        )
    application_descriptor = applications[0]
    application_platform = platform_name(application_descriptor)
    if require_provenance and application_platform != expected_platform:
        raise LayoutError(
            "provenance-bearing OCI index application descriptor must explicitly "
            f"declare {expected_platform}"
        )
    if require_provenance and not provenance:
        raise LayoutError(
            f"OCI index in {layout} has no BuildKit provenance descriptor"
        )
    if require_provenance and len(provenance) != 1:
        raise LayoutError(
            "provenance-bearing OCI index must contain exactly one BuildKit "
            f"provenance descriptor, found {len(provenance)}"
        )
    application_digest = str(application_descriptor.get("digest"))
    application_manifest = descriptor_manifest(layout, application_descriptor)

    config = application_manifest.get("config")
    if not isinstance(config, dict):
        raise LayoutError(
            f"OCI application manifest in {layout} has no config descriptor"
        )
    config_digest = str(config.get("digest"))
    verified_digest_blob(layout, config_digest)
    layers = application_manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise LayoutError(f"OCI application manifest in {layout} has no layers")
    layer_digests: list[str] = []
    for layer in layers:
        if not isinstance(layer, dict):
            raise LayoutError(f"invalid OCI application layer descriptor in {layout}")
        digest = str(layer.get("digest"))
        verified_digest_blob(layout, digest)
        layer_digests.append(digest)

    provenance_descriptors = [
        validate_provenance_descriptor(layout, item, application_digest)
        for item in provenance
    ]
    descriptor_platform = application_platform or expected_platform
    return {
        "index_digest": index_digest,
        "application_manifest_digest": application_digest,
        "platform": descriptor_platform,
        "config_digest": config_digest,
        "ordered_layer_digests": layer_digests,
        "topology": {
            "application_descriptor": {
                "digest": application_digest,
                "media_type": str(application_descriptor["mediaType"]),
                "platform": descriptor_platform,
            },
            "provenance_descriptors": provenance_descriptors,
        },
    }


def compare_layouts(
    left: Path,
    right: Path,
    *,
    exact_image: bool,
    rootfs_only: bool = False,
) -> None:
    left_context = manifest_context(left)
    right_context = manifest_context(right)
    if (
        not rootfs_only
        and left_context["config_digest"] != right_context["config_digest"]
    ):
        raise LayoutError(
            "image config digests differ: "
            f"{left_context['config_digest']} != {right_context['config_digest']}"
        )
    if left_context["ordered_layer_digests"] != right_context["ordered_layer_digests"]:
        raise LayoutError(
            "ordered rootfs layer digests differ: "
            f"{left}={left_context['ordered_layer_digests']!r} "
            f"{right}={right_context['ordered_layer_digests']!r}"
        )
    if exact_image and (
        left_context["application_manifest_digest"]
        != right_context["application_manifest_digest"]
    ):
        raise LayoutError(
            "image manifest digests differ: "
            f"{left_context['application_manifest_digest']} != "
            f"{right_context['application_manifest_digest']}"
        )
    if exact_image and left_context["index_digest"] != right_context["index_digest"]:
        raise LayoutError(f"OCI indexes differ: {left} != {right}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path, nargs="?")
    parser.add_argument("right", type=Path, nargs="?")
    parser.add_argument(
        "--exact-image",
        action="store_true",
        help="also require identical selected image manifest and top-level index bytes",
    )
    parser.add_argument(
        "--rootfs-only",
        action="store_true",
        help=(
            "legacy label-smoke mode: compare only ordered rootfs layers; candidate "
            "and repeatability proofs must use the safer default"
        ),
    )
    parser.add_argument(
        "--inspect-layout",
        type=Path,
        help="emit normalized config, layer, and provenance-bearing topology JSON",
    )
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="require BuildKit provenance when inspecting one layout",
    )
    args = parser.parse_args(argv)
    if args.inspect_layout is not None:
        if (
            args.left is not None
            or args.right is not None
            or args.exact_image
            or args.rootfs_only
        ):
            parser.error(
                "--inspect-layout cannot be combined with comparison arguments"
            )
    elif args.left is None or args.right is None:
        parser.error("comparison requires LEFT and RIGHT layouts")
    elif args.exact_image and args.rootfs_only:
        parser.error("--exact-image and --rootfs-only are mutually exclusive")
    elif args.require_provenance:
        parser.error("--require-provenance is only valid with --inspect-layout")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.inspect_layout is not None:
            context = manifest_context(
                args.inspect_layout,
                require_provenance=args.require_provenance,
            )
            print(json.dumps(context, indent=2, sort_keys=True))
            return 0
        compare_layouts(
            args.left,
            args.right,
            exact_image=args.exact_image,
            rootfs_only=args.rootfs_only,
        )
    except LayoutError as error:
        print(f"release image layout comparison failed: {error}", file=sys.stderr)
        return 1
    scope = (
        "ordered rootfs"
        if args.rootfs_only
        else "exact image, config, and rootfs"
        if args.exact_image
        else "image config and ordered rootfs"
    )
    print(f"verified identical release {scope}: {args.left} == {args.right}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
