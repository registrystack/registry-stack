#!/usr/bin/env python3
"""Resolve and verify the latest published release that carries docs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


TAG_PATTERN = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _release_version(tag: str) -> tuple[int, int, int] | None:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def _matching_assets(release: dict[str, Any], name: str) -> list[dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError(
            f"release {release.get('tag_name')!r} assets must be an array"
        )
    return [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == name
    ]


def resolve_latest_published_docs_release(
    metadata: Any,
    *,
    expected_tag: str | None = None,
    expected_sha256: str | None = None,
) -> dict[str, str]:
    if not isinstance(metadata, list):
        raise ValueError("release metadata must be a JSON array")
    if (expected_tag is None) != (expected_sha256 is None):
        raise ValueError("expected tag and docs SHA-256 must be supplied together")
    if expected_tag is not None and TAG_PATTERN.fullmatch(expected_tag) is None:
        raise ValueError("expected tag must be canonical v<major>.<minor>.<patch> text")
    if (
        expected_sha256 is not None
        and SHA256_PATTERN.fullmatch(expected_sha256) is None
    ):
        raise ValueError(
            "expected docs SHA-256 must be 64 lowercase hexadecimal characters"
        )

    candidates: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for value in metadata:
        if not isinstance(value, dict):
            raise ValueError("each release metadata entry must be a JSON object")
        if value.get("draft") is not False or value.get("prerelease") is not False:
            continue
        tag = value.get("tag_name")
        version = _release_version(tag) if isinstance(tag, str) else None
        published_at = value.get("published_at")
        if version is None or not isinstance(published_at, str) or not published_at:
            continue
        archive = f"registry-docs-{tag}.tar.gz"
        if _matching_assets(value, archive):
            candidates.append((version, value))

    if not candidates:
        raise ValueError("no published non-prerelease release carries a docs archive")
    _, release = max(candidates, key=lambda item: item[0])
    tag = release["tag_name"]
    archive = f"registry-docs-{tag}.tar.gz"
    checksum_bundle = f"registry-stack-{tag}-SHA256SUMS.sigstore.json"
    required_assets = {
        archive: _matching_assets(release, archive),
        "SHA256SUMS": _matching_assets(release, "SHA256SUMS"),
        checksum_bundle: _matching_assets(release, checksum_bundle),
    }
    for name, matches in required_assets.items():
        if len(matches) != 1:
            raise ValueError(
                f"latest docs release {tag} must carry exactly one {name} asset"
            )
    digest = required_assets[archive][0].get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError(f"latest docs release {tag} has no authenticated docs digest")
    docs_sha256 = digest.removeprefix("sha256:")
    if SHA256_PATTERN.fullmatch(docs_sha256) is None:
        raise ValueError(f"latest docs release {tag} has an invalid docs digest")
    if expected_tag is not None and tag != expected_tag:
        raise ValueError(
            f"requested docs release {expected_tag} is stale; latest published "
            f"docs release is {tag}"
        )
    if expected_sha256 is not None and docs_sha256 != expected_sha256:
        raise ValueError(
            f"requested docs digest for {tag} does not match its release asset"
        )
    return {
        "tag_name": tag,
        "docs_sha256": docs_sha256,
        "published_at": release["published_at"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--expected-tag")
    parser.add_argument("--expected-sha256")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
        resolved = resolve_latest_published_docs_release(
            metadata,
            expected_tag=args.expected_tag,
            expected_sha256=args.expected_sha256,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(resolved, sort_keys=True))


if __name__ == "__main__":
    main()
