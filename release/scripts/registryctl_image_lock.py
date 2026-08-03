#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared Registryctl release image-lock contracts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POSTGRESQL_IMAGE_REF_PATH = ROOT / "release" / "registryctl-postgresql-image.ref"
SCHEMA_V1 = "registryctl.release_image_lock.v1"
SCHEMA_V2 = "registryctl.release_image_lock.v2"
SCHEMA_V3 = "registryctl.release_image_lock.v3"
PLATFORM = "linux/amd64"
V2_MINIMUM_VERSION = (0, 14, 0)
V3_MINIMUM_VERSION = (0, 17, 0)
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PRODUCT_IMAGE_REPOSITORIES = {
    "registry-relay": "ghcr.io/registrystack/registry-relay",
    "registry-notary": "ghcr.io/registrystack/registry-notary",
}
POSTGRESQL_IMAGE_REPOSITORY = "docker.io/library/postgres"


def schema_for_release_version(version: str) -> str:
    if SEMVER.fullmatch(version) is None:
        raise ValueError(
            "registryctl image lock release version must be semantic version text, "
            f"got {version!r}"
        )
    parsed = tuple(int(part) for part in version.split("."))
    if parsed >= V3_MINIMUM_VERSION:
        return SCHEMA_V3
    return SCHEMA_V2 if parsed >= V2_MINIMUM_VERSION else SCHEMA_V1


def repositories_for_schema(schema_version: str) -> dict[str, str]:
    if schema_version == SCHEMA_V1:
        return dict(PRODUCT_IMAGE_REPOSITORIES)
    if schema_version == SCHEMA_V2:
        return {
            **PRODUCT_IMAGE_REPOSITORIES,
            "postgresql": POSTGRESQL_IMAGE_REPOSITORY,
        }
    if schema_version == SCHEMA_V3:
        return {
            "registry-relay": PRODUCT_IMAGE_REPOSITORIES["registry-relay"],
            "postgresql": POSTGRESQL_IMAGE_REPOSITORY,
        }
    raise ValueError(
        "registryctl release image lock schema_version must be "
        f"{SCHEMA_V1!r}, {SCHEMA_V2!r}, or {SCHEMA_V3!r}"
    )


def read_canonical_image_ref(
    path: Path,
    *,
    image_name: str,
    repository: str,
) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{image_name} image ref must be a regular file: {path}")
    if path.stat().st_size > 1024:
        raise ValueError(f"{image_name} image ref exceeds 1024 bytes: {path}")
    body = path.read_text(encoding="utf-8")
    lines = body.splitlines()
    if len(lines) != 1 or body not in {lines[0], f"{lines[0]}\n"}:
        raise ValueError(
            f"{image_name} image ref must contain exactly one unpadded line"
        )
    image_ref = lines[0]
    if (
        re.fullmatch(
            rf"{re.escape(repository)}@sha256:[0-9a-f]{{64}}",
            image_ref,
        )
        is None
    ):
        raise ValueError(f"{image_name} must be {repository}@sha256:<64 lowercase hex>")
    return image_ref


def reviewed_postgresql_image_ref() -> str:
    # Keep the runtime dependency independent of mutable tags and registry
    # state at release time. The reviewed file is the only digest authority.
    return read_canonical_image_ref(
        POSTGRESQL_IMAGE_REF_PATH,
        image_name="postgresql",
        repository=POSTGRESQL_IMAGE_REPOSITORY,
    )


def read_reviewed_postgresql_image_ref(path: Path) -> str:
    image_ref = read_canonical_image_ref(
        path,
        image_name="postgresql",
        repository=POSTGRESQL_IMAGE_REPOSITORY,
    )
    reviewed = reviewed_postgresql_image_ref()
    # A workflow-supplied file may select the reviewed pin, never substitute it.
    if image_ref != reviewed:
        raise ValueError(
            "postgresql image ref must match the reviewed release-tooling pin "
            f"{reviewed}"
        )
    return image_ref


def validate_images(schema_version: str, images: Any) -> dict[str, str]:
    repositories = repositories_for_schema(schema_version)
    if not isinstance(images, dict) or set(images) != set(repositories):
        expected = ", ".join(sorted(repositories))
        raise ValueError(
            f"registryctl release image lock images must contain exactly {expected}"
        )
    for image_name, repository in repositories.items():
        value = images.get(image_name)
        if (
            not isinstance(value, str)
            or re.fullmatch(
                rf"{re.escape(repository)}@sha256:[0-9a-f]{{64}}",
                value,
            )
            is None
        ):
            raise ValueError(
                f"{image_name} is not pinned to its exact canonical digest "
                f"{repository}@sha256:<64 lowercase hex>"
            )
    if (
        schema_version in {SCHEMA_V2, SCHEMA_V3}
        and images["postgresql"] != reviewed_postgresql_image_ref()
    ):
        raise ValueError(
            "postgresql image ref does not match the reviewed release-tooling pin"
        )
    return images
