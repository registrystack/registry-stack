#!/usr/bin/env python3
"""Emit a deterministic payload through the real RegistryReleaseLockV1 producer."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Sequence

import registry_release_lock


VERSION = "1.0.0"
MANIFEST_SOURCE_REF = "1" * 40
TAG_TARGET = MANIFEST_SOURCE_REF


def create_payload(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="registry-runtime-parity-") as temporary:
        root = Path(temporary)
        assets = root / "assets"
        assets.mkdir()
        tag = f"v{VERSION}"
        for platform in registry_release_lock.PLATFORMS:
            (assets / f"registryctl-{tag}-{platform}").write_bytes(
                f"registryctl {platform}\n".encode()
            )

        starters = {}
        for starter_id, digest_character in (("http", "3"), ("spreadsheet", "4")):
            starter = root / f"{starter_id}.yaml"
            starter.write_text(
                "starter:\n"
                f"  id: {starter_id}\n"
                f"  release: {VERSION}\n"
                f"  content_digest: sha256:{digest_character * 64}\n",
                encoding="utf-8",
            )
            starters[starter_id] = starter
        image_indexes = {}
        image_identities = {}
        for name, repository, digest_character in [
            ("relay", "example.invalid/registrystack/registry-relay", "d"),
            ("postgresql", "example.invalid/registrystack/postgresql", "f"),
        ]:
            index_path = root / f"{name}.index.json"
            index_path.write_bytes(
                registry_release_lock.canonical_json(
                    {
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [
                            {
                                "mediaType": (
                                    registry_release_lock.OCI_IMAGE_MANIFEST_MEDIA_TYPE
                                ),
                                "digest": f"sha256:{digest_character * 64}",
                                "platform": {
                                    "os": "linux",
                                    "architecture": "amd64",
                                },
                            }
                        ],
                    }
                )
            )
            image_indexes[name] = index_path
            image_identities[name] = (
                f"{repository}@{registry_release_lock.sha256_file(index_path)}"
            )
        image_lock = root / "image-lock.json"
        image_lock.write_text(
            json.dumps(
                {
                    "release_tag": tag,
                    "manifest_source_ref": MANIFEST_SOURCE_REF,
                    "tag_target": TAG_TARGET,
                    "images": {
                        "registry-relay": image_identities["relay"],
                        "postgresql": image_identities["postgresql"],
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        original_starters = registry_release_lock.STARTERS
        registry_release_lock.STARTERS = starters
        try:
            registry_release_lock.create_payload(
                argparse.Namespace(
                    version=VERSION,
                    manifest_source_ref=MANIFEST_SOURCE_REF,
                    tag_target=TAG_TARGET,
                    asset_dir=assets,
                    image_lock=image_lock,
                    relay_image_index=image_indexes["relay"],
                    postgresql_image_index=image_indexes["postgresql"],
                    output=output,
                )
            )
        finally:
            registry_release_lock.STARTERS = original_starters


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    create_payload(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
