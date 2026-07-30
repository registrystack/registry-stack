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

        starter = root / "http.yaml"
        starter.write_text(
            "starter:\n"
            "  id: http\n"
            f"  release: {VERSION}\n"
            f"  content_digest: sha256:{'3' * 64}\n",
            encoding="utf-8",
        )
        image_lock = root / "image-lock.json"
        image_lock.write_text(
            json.dumps(
                {
                    "release_tag": tag,
                    "manifest_source_ref": MANIFEST_SOURCE_REF,
                    "tag_target": TAG_TARGET,
                    "images": {
                        "registry-relay": (
                            "example.invalid/registrystack/registry-relay@sha256:"
                            + "a" * 64
                        ),
                        "registry-notary": (
                            "example.invalid/registrystack/registry-notary@sha256:"
                            + "b" * 64
                        ),
                        "postgresql": (
                            "example.invalid/registrystack/postgresql@sha256:"
                            + "c" * 64
                        ),
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        original_starters = registry_release_lock.STARTERS
        registry_release_lock.STARTERS = {"http": starter}
        try:
            registry_release_lock.create_payload(
                argparse.Namespace(
                    version=VERSION,
                    manifest_source_ref=MANIFEST_SOURCE_REF,
                    tag_target=TAG_TARGET,
                    asset_dir=assets,
                    image_lock=image_lock,
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
