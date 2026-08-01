#!/usr/bin/env python3
"""Fail-closed parsers for Registry Stack release workflow boundaries."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence


MAX_INPUT_BYTES = 16 * 1024 * 1024
HTTP_STATUS = re.compile(rb"^HTTP/\S+\s+([1-5][0-9]{2})(?:\s|$)")
IMAGE_COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
VERSION_TAG = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
SHA256_DIGEST = r"sha256:[0-9a-f]{64}"


class GuardError(ValueError):
    """A release destination or response cannot be proven safe."""


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise GuardError(f"duplicate JSON member {name!r}")
        result[name] = value
    return result


def read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise GuardError(f"{path} must be a regular non-symlink file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise GuardError(f"{path} exceeds the release guard size limit")
    return path.read_bytes()


def read_json(path: Path) -> Any:
    try:
        return json.loads(
            read_bytes(path).decode("utf-8"),
            object_pairs_hook=reject_duplicate_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuardError(f"cannot read release guard JSON {path}: {error}") from error


def final_http_status(path: Path) -> str:
    statuses = [
        match.group(1).decode("ascii")
        for line in read_bytes(path).splitlines()
        if (match := HTTP_STATUS.match(line)) is not None
    ]
    if not statuses:
        raise GuardError("GitHub API response has no valid HTTP status line")
    return statuses[-1]


def public_image_destination(final_ref: str, namespace: str) -> tuple[str, str]:
    namespace_pattern = re.escape(namespace)
    match = re.fullmatch(
        rf"ghcr\.io/{namespace_pattern}/(?P<package>{IMAGE_COMPONENT}):"
        rf"(?P<tag>{VERSION_TAG})",
        final_ref,
    )
    if match is None:
        raise GuardError(
            "public image destination must be an exact Registry Stack GHCR version tag"
        )
    return match.group("package"), match.group("tag")


def package_versions(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, list) or any(
        not isinstance(page, list) for page in document
    ):
        raise GuardError("GitHub package versions must be a slurped page array")
    versions: list[dict[str, Any]] = []
    for page in document:
        for value in page:
            if not isinstance(value, dict):
                raise GuardError("GitHub package version entries must be objects")
            versions.append(value)
    return versions


def image_tag_versions(document: Any, *, tag: str) -> list[dict[str, Any]]:
    if not isinstance(tag, str) or re.fullmatch(VERSION_TAG, tag) is None:
        raise GuardError("public image tag must be canonical vMAJOR.MINOR.PATCH")
    matches: list[dict[str, Any]] = []
    for version in package_versions(document):
        metadata = version.get("metadata")
        if not isinstance(metadata, dict):
            raise GuardError("GitHub package version metadata must be an object")
        container = metadata.get("container")
        if not isinstance(container, dict):
            raise GuardError("GitHub package container metadata must be an object")
        tags = container.get("tags")
        if not isinstance(tags, list) or any(not isinstance(value, str) for value in tags):
            raise GuardError("GitHub package version tags must be strings")
        if tag in tags:
            matches.append(version)
    return matches


def require_image_tag_absent(document: Any, *, tag: str) -> None:
    matches = image_tag_versions(document, tag=tag)
    if not matches:
        return
    if len(matches) != 1:
        raise GuardError("public image tag resolves to multiple package versions")
    raise GuardError("public image destination already exists")


def reconcile_image_tag(document: Any, *, tag: str, expected_digest: str) -> str:
    if not isinstance(expected_digest, str) or re.fullmatch(
        SHA256_DIGEST, expected_digest
    ) is None:
        raise GuardError(
            "expected image digest must be canonical sha256:<64 lowercase hex>"
        )
    matches = image_tag_versions(document, tag=tag)
    if not matches:
        return "absent"
    if len(matches) != 1:
        raise GuardError("public image tag resolves to multiple package versions")
    actual_digest = matches[0].get("name")
    if not isinstance(actual_digest, str) or re.fullmatch(
        SHA256_DIGEST, actual_digest
    ) is None:
        raise GuardError("GitHub package version name must be a canonical sha256 digest")
    if actual_digest != expected_digest:
        raise GuardError("public image tag digest does not match expected digest")
    return "present"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="release_workflow_guard.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("http-status")
    status.add_argument("--response", type=Path, required=True)

    destination = subparsers.add_parser("public-image-destination")
    destination.add_argument("--final-ref", required=True)
    destination.add_argument("--namespace", required=True)

    absent = subparsers.add_parser("require-image-tag-absent")
    absent.add_argument("--metadata", type=Path, required=True)
    absent.add_argument("--tag", required=True)

    reconcile = subparsers.add_parser("reconcile-image-tag")
    reconcile.add_argument("--metadata", type=Path, required=True)
    reconcile.add_argument("--tag", required=True)
    reconcile.add_argument("--expected-digest", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "http-status":
            print(final_http_status(args.response))
        elif args.command == "public-image-destination":
            print(
                "\t".join(
                    public_image_destination(args.final_ref, args.namespace)
                )
            )
        elif args.command == "require-image-tag-absent":
            require_image_tag_absent(
                read_json(args.metadata),
                tag=args.tag,
            )
        elif args.command == "reconcile-image-tag":
            print(
                reconcile_image_tag(
                    read_json(args.metadata),
                    tag=args.tag,
                    expected_digest=args.expected_digest,
                )
            )
        else:
            raise AssertionError(f"unsupported command {args.command}")
        return 0
    except (GuardError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
