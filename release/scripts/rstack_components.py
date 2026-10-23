#!/usr/bin/env python3
"""Derive installable rstack components from the exact release payload records."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any


PLATFORMS = ("linux-amd64", "linux-arm64", "macos-arm64")
SCHEMA_VERSION = "registry-stack.components.v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")

# Binary names are the publication roster's exact asset stems. A product only
# becomes installable where all baseline binaries have been published.
PRODUCTS = {
    "breg": {
        "entrypoint": "bregctl",
        "baseline": ("bregctl", "breg"),
        "optional": ("breg-mcp", "breg-review"),
        "runtime": "breg",
    },
    "casework": {
        "entrypoint": "caseworkctl",
        "baseline": ("caseworkctl", "casework"),
        "optional": (),
        "runtime": "casework",
    },
    "discovery": {
        "entrypoint": "discoveryctl",
        "baseline": ("discoveryctl", "discovery"),
        "optional": (),
        "runtime": "discovery",
    },
    "evidence": {
        "entrypoint": "evidencectl",
        "baseline": ("evidencectl", "evidence"),
        "optional": ("evidence-oid4vci",),
        "runtime": "evidence",
    },
    "manifest": {
        "entrypoint": "registry-manifest",
        "baseline": ("registry-manifest",),
        "optional": (),
        "runtime": None,
    },
    "messaging": {
        "entrypoint": "messagingctl",
        "baseline": ("messagingctl", "messaging"),
        "optional": (),
        "runtime": "messaging",
    },
    "render": {
        "entrypoint": "registry-render",
        "baseline": ("registry-render",),
        "optional": (),
        "runtime": "registry-render",
    },
    "scheduling": {
        "entrypoint": "schedulingctl",
        "baseline": ("schedulingctl",),
        "optional": ("scheduling",),
        "runtime": "scheduling",
    },
    "coordinator": {
        "entrypoint": "coordinatorctl",
        "baseline": ("coordinatorctl", "coordinator"),
        "optional": (),
        "runtime": "coordinator",
    },
}


def _binary_name(asset_name: str, tag: str) -> tuple[str, str]:
    for platform in PLATFORMS:
        suffix = f"-{tag}-{platform}"
        if platform == "macos-arm64":
            if asset_name == f"registry-manifest{suffix}":
                return "registry-manifest", platform
            suffix += ".tar.gz"
        if asset_name.endswith(suffix):
            binary = asset_name[: -len(suffix)]
            if binary:
                return binary, platform
    raise ValueError(f"unclassified release binary asset: {asset_name}")


def _asset(record: dict[str, Any]) -> dict[str, Any]:
    name = record.get("name")
    size = record.get("size")
    digest = record.get("sha256")
    if not isinstance(name, str) or not name or name != name.split("/")[-1]:
        raise ValueError("binary asset name must be a public basename")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError(f"binary asset {name} needs a positive size")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise ValueError(f"binary asset {name} needs a SHA-256 digest")
    return {"name": name, "size": size, "sha256": digest}


def build_component_manifest(version: str, payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the versioned component model or refuse roster drift.

    Every binary payload, including the launcher, must be classified exactly
    once. Nonbinary payloads remain covered by the parent release manifest.
    """

    if VERSION.fullmatch(version) is None:
        raise ValueError("release version must be canonical X.Y.Z")
    tag = f"v{version}"
    binaries: dict[str, dict[str, dict[str, Any]]] = {platform: {} for platform in PLATFORMS}
    for record in payloads:
        if record.get("kind") != "binary":
            continue
        asset = _asset(record)
        binary, platform = _binary_name(asset["name"], tag)
        if binary in binaries[platform]:
            raise ValueError(f"duplicate {platform} binary {binary}")
        binaries[platform][binary] = asset

    launcher: dict[str, dict[str, Any]] = {}
    for platform in PLATFORMS:
        if "rstack" not in binaries[platform]:
            raise ValueError(f"incomplete launcher on {platform}: rstack is missing")
        launcher[platform] = binaries[platform]["rstack"]

    classified = {"rstack"}
    components: dict[str, dict[str, Any]] = {}
    for name, spec in PRODUCTS.items():
        baseline = spec["baseline"]
        optional = spec["optional"]
        group = set(baseline) | set(optional)
        classified.update(group)
        supported: dict[str, dict[str, Any]] = {}
        for platform, published in binaries.items():
            present = group & published.keys()
            if not present:
                continue
            missing = set(baseline) - published.keys()
            if missing:
                raise ValueError(f"incomplete {name} baseline on {platform}: {sorted(missing)}")
            selected = [published[binary] for binary in (*baseline, *optional) if binary in published]
            supported[platform] = {
                "assets": selected,
                "capabilities": {
                    "tooling": True,
                    "runtime": spec["runtime"] in published if spec["runtime"] else False,
                    **{binary: binary in published for binary in optional},
                },
            }
        if supported:
            components[name] = {
                "entrypoint": spec["entrypoint"],
                "dependencies": [],
                "platforms": supported,
            }

    unknown = sorted({binary for group in binaries.values() for binary in group} - classified)
    if unknown:
        raise ValueError(f"unclassified release binaries: {unknown}")
    return {
        "schema_version": SCHEMA_VERSION,
        "release": tag,
        "launcher": launcher,
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        payloads = json.load(sys.stdin)
        if not isinstance(payloads, list):
            raise ValueError("payloads must be an array")
        document = build_component_manifest(args.version, payloads)
    except (json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"rstack component manifest: {exc}\n")
    sys.stdout.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
