#!/usr/bin/env python3
"""Download version-keyed release assets for committed upgrade evidence."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable


STACK_REPOSITORY = "registrystack/registry-stack"
SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = (
    rf"(?:{SEMVER_NUMBER}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
VERSION = re.compile(
    rf"^v{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}"
    rf"(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?$"
)


class PreparationError(RuntimeError):
    """Committed upgrade evidence cannot be prepared safely."""


def candidate_versions(records: Path) -> tuple[str, ...]:
    versions: set[str] = set()
    for path in sorted(records.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise PreparationError(
                "upgrade exercise record could not be read"
            ) from None
        if not isinstance(value, dict) or value.get("record_kind") == "template":
            continue
        if value.get("record_kind") != "candidate_evidence":
            raise PreparationError("upgrade exercise record kind is invalid")
        for label in ("source_release", "target_release"):
            release = value.get(label)
            version = release.get("version") if isinstance(release, dict) else None
            if not isinstance(version, str) or VERSION.fullmatch(version) is None:
                raise PreparationError(
                    f"candidate upgrade {label.removesuffix('_release')} version is invalid"
                )
            versions.add(version)
    return tuple(sorted(versions))


def required_asset_names(version: str) -> tuple[str, ...]:
    image_lock = f"registryctl-{version}-image-lock.json"
    capsule = f"registry-stack-{version}-release-capsule.json"
    return (
        image_lock,
        f"{image_lock}.sig",
        f"{image_lock}.pem",
        capsule,
        f"{capsule}.sig",
        f"{capsule}.pem",
        f"registry-stack-{version}-release-provenance.intoto.jsonl",
        "SHA256SUMS",
    )


def run_download(command: list[str]) -> None:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        raise PreparationError(
            "candidate release assets could not be downloaded"
        ) from None
    if result.returncode != 0:
        raise PreparationError(
            "candidate release assets could not be downloaded"
        )


def prepare_assets(
    records: Path,
    asset_root: Path,
    *,
    downloader: Callable[[list[str]], None] = run_download,
) -> tuple[str, ...]:
    versions = candidate_versions(records)
    if not versions:
        return versions
    asset_root.mkdir(parents=True, exist_ok=True)
    for version in versions:
        destination = asset_root / version
        try:
            destination.mkdir(mode=0o700)
        except OSError:
            raise PreparationError(
                "candidate version asset directory must be new"
            ) from None
        names = required_asset_names(version)
        command = [
            "gh",
            "release",
            "download",
            version,
            "--repo",
            STACK_REPOSITORY,
            "--dir",
            str(destination),
        ]
        for name in names:
            command.extend(("--pattern", name))
        downloader(command)
        try:
            actual = {path.name for path in destination.iterdir()}
        except OSError:
            raise PreparationError(
                "candidate release asset set could not be inspected"
            ) from None
        if actual != set(names) or any(
            not path.is_file() or path.is_symlink()
            for path in destination.iterdir()
        ):
            raise PreparationError(
                "candidate release asset set is incomplete or unsafe"
            )
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discover", type=Path, required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        versions = prepare_assets(args.discover, args.asset_root)
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(
                    f"has_candidates={'true' if versions else 'false'}\n"
                )
                output.write(f"versions={','.join(versions)}\n")
    except (PreparationError, OSError) as error:
        print(f"upgrade asset preparation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"prepared upgrade release inputs for {len(versions)} version(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
