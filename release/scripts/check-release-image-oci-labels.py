#!/usr/bin/env python3
"""Fail closed unless a release image has the expected OCI identity labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


DEFAULT_FORMAT_TEMPLATE = "{{json .Image.Config}}"
OCI_LABELS = {
    "source": "org.opencontainers.image.source",
    "revision": "org.opencontainers.image.revision",
    "version": "org.opencontainers.image.version",
}


class CheckError(RuntimeError):
    """An image could not be proven to have the required OCI labels."""


def read_layout_blob(layout: Path, digest: object) -> dict[str, Any]:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise CheckError(f"unsupported OCI digest in {layout}: {digest!r}")
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CheckError(f"invalid sha256 digest in {layout}: {digest!r}")
    path = layout / "blobs" / "sha256" / value
    try:
        content = path.read_bytes()
    except OSError as error:
        raise CheckError(f"could not read OCI blob {digest} in {layout}: {error}") from error
    actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
    if actual != digest:
        raise CheckError(
            f"OCI blob digest mismatch in {layout}: expected {digest}, got {actual}"
        )
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise CheckError(f"invalid OCI JSON blob {digest} in {layout}: {error}") from error
    if not isinstance(document, dict):
        raise CheckError(f"OCI JSON blob {digest} in {layout} must be an object")
    return document


def inspect_oci_layout(image_ref: str, format_template: str) -> dict[str, Any]:
    if format_template != DEFAULT_FORMAT_TEMPLATE:
        raise CheckError("format-template overrides are not supported for OCI layouts")
    layout = Path(image_ref.removeprefix("oci-layout://"))
    try:
        index = json.loads((layout / "index.json").read_text(encoding="utf-8"))
    except OSError as error:
        raise CheckError(f"could not read OCI layout index in {layout}: {error}") from error
    except json.JSONDecodeError as error:
        raise CheckError(f"invalid OCI layout index in {layout}: {error}") from error
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1:
        count = len(manifests) if isinstance(manifests, list) else 0
        raise CheckError(f"expected exactly one OCI manifest in {layout}, found {count}")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict):
        raise CheckError(f"invalid OCI manifest descriptor in {layout}")
    manifest = read_layout_blob(layout, descriptor.get("digest"))
    config_descriptor = manifest.get("config")
    if not isinstance(config_descriptor, dict):
        raise CheckError(f"OCI manifest in {layout} has no config descriptor")
    config_document = read_layout_blob(layout, config_descriptor.get("digest"))
    config = config_document.get("config")
    if not isinstance(config, dict):
        raise CheckError(f"OCI image config in {layout} has no config object")
    return config


def inspect_image_config(image_ref: str, format_template: str) -> dict[str, Any]:
    if image_ref.startswith("oci-layout://"):
        return inspect_oci_layout(image_ref, format_template)
    command = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        "--format",
        format_template,
        image_ref,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise CheckError(
            f"could not run docker buildx imagetools inspect for {image_ref!r}: "
            f"{error}"
        ) from error

    if (
        result.returncode != 0
        and format_template == DEFAULT_FORMAT_TEMPLATE
        and ".Image.Config" in result.stderr
    ):
        raw_result = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", image_ref],
            check=False,
            capture_output=True,
            text=True,
        )
        if raw_result.returncode == 0:
            try:
                index = json.loads(raw_result.stdout)
                platform = next(
                    descriptor
                    for descriptor in index["manifests"]
                    if descriptor.get("platform", {}).get("os") == "linux"
                    and descriptor.get("platform", {}).get("architecture") == "amd64"
                )
                application_ref = f"{image_ref.split('@', 1)[0]}@{platform['digest']}"
            except (KeyError, StopIteration, TypeError, json.JSONDecodeError):
                application_ref = None
            if application_ref is not None:
                result = subprocess.run(
                    [
                        "docker",
                        "buildx",
                        "imagetools",
                        "inspect",
                        "--format",
                        format_template,
                        application_ref,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

    if result.returncode != 0:
        detail = result.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise CheckError(
            "docker buildx imagetools inspect failed for "
            f"{image_ref!r} with exit code {result.returncode}{suffix}"
        )

    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CheckError(
            f"docker returned invalid image config JSON for {image_ref!r}: {error}"
        ) from error

    if not isinstance(config, dict):
        raise CheckError(
            f"image config for {image_ref!r} must be a JSON object, "
            f"got {type(config).__name__}"
        )
    return config


def require_oci_labels(
    image_ref: str,
    config: dict[str, Any],
    expected: dict[str, str],
) -> None:
    if "Labels" not in config:
        raise CheckError(
            f"image config for {image_ref!r} is missing the Labels object; "
            "required OCI labels cannot be verified"
        )

    labels = config["Labels"]
    if not isinstance(labels, dict):
        raise CheckError(
            f"image config Labels for {image_ref!r} must be a JSON object, "
            f"got {type(labels).__name__}"
        )

    for identity, label in OCI_LABELS.items():
        if label not in labels:
            raise CheckError(
                f"image config Labels for {image_ref!r} is missing required "
                f"OCI label {label!r}"
            )
        actual = labels[label]
        wanted = expected[identity]
        if actual != wanted:
            raise CheckError(
                f"image OCI label {label!r} for {image_ref!r} has value "
                f"{actual!r}; expected exactly {wanted!r}"
            )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify exact OCI source, revision, and version image labels."
    )
    parser.add_argument("image_ref", help="Registry reference or OCI layout to inspect")
    parser.add_argument("--source", required=True, help="Expected OCI source label")
    parser.add_argument("--revision", required=True, help="Expected OCI revision label")
    parser.add_argument("--version", required=True, help="Expected OCI version label")
    parser.add_argument(
        "--format-template",
        default=DEFAULT_FORMAT_TEMPLATE,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = inspect_image_config(args.image_ref, args.format_template)
        require_oci_labels(
            args.image_ref,
            config,
            {
                "source": args.source,
                "revision": args.revision,
                "version": args.version,
            },
        )
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"verified release image OCI labels for {args.image_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
