#!/usr/bin/env python3
"""Download version-keyed release assets for committed candidate evidence."""

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
PRODUCT_INPUT_SCHEMA_FILENAME = "product-input-lifecycle-v1.schema.json"


class PreparationError(RuntimeError):
    """Committed candidate evidence cannot be prepared safely."""


def load_closed_json_record(path: Path, label: str) -> object:
    def reject_duplicate_fields(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for field, field_value in pairs:
            if field in value:
                raise PreparationError(
                    f"{label} contains a duplicate JSON field"
                )
            value[field] = field_value
        return value

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        raise PreparationError(f"{label} could not be read") from None
    try:
        return json.loads(content, object_pairs_hook=reject_duplicate_fields)
    except json.JSONDecodeError:
        raise PreparationError(f"{label} could not be read") from None


def candidate_versions(records: Path) -> tuple[str, ...]:
    versions: set[str] = set()
    for path in sorted(records.glob("*.json")):
        value = load_closed_json_record(path, "upgrade exercise record")
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


def product_input_candidate_versions(records: Path) -> tuple[str, ...]:
    versions: set[str] = set()
    for path in sorted(records.glob("*.json")):
        if path.name == PRODUCT_INPUT_SCHEMA_FILENAME:
            continue
        value = load_closed_json_record(
            path, "product-input lifecycle record"
        )
        if not isinstance(value, dict) or value.get("record_kind") == "template":
            continue
        if value.get("record_kind") != "candidate_evidence":
            raise PreparationError(
                "product-input lifecycle record kind is invalid"
            )
        candidate = value.get("candidate")
        version = candidate.get("version") if isinstance(candidate, dict) else None
        if not isinstance(version, str) or VERSION.fullmatch(version) is None:
            raise PreparationError(
                "product-input lifecycle candidate version is invalid"
            )
        versions.add(version)
    return tuple(sorted(versions))


def required_asset_names(
    version: str, *, include_candidate_receipt: bool = False
) -> tuple[str, ...]:
    image_lock = f"registryctl-{version}-image-lock.json"
    capsule = f"registry-stack-{version}-release-capsule.json"
    names = (
        image_lock,
        f"{image_lock}.sig",
        f"{image_lock}.pem",
        capsule,
        f"{capsule}.sig",
        f"{capsule}.pem",
        f"registry-stack-{version}-release-provenance.intoto.jsonl",
        "SHA256SUMS",
    )
    if include_candidate_receipt:
        return names + (f"registry-stack-{version}-candidate-receipt.json",)
    return names


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
    product_input_records: Path | None = None,
    downloader: Callable[[list[str]], None] = run_download,
) -> tuple[str, ...]:
    upgrade_versions = set(candidate_versions(records))
    product_input_versions = (
        set()
        if product_input_records is None
        else set(product_input_candidate_versions(product_input_records))
    )
    versions = tuple(sorted(upgrade_versions | product_input_versions))
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
        include_candidate_receipt = version in product_input_versions
        names = required_asset_names(
            version, include_candidate_receipt=include_candidate_receipt
        )
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
        if include_candidate_receipt:
            receipt = (
                destination / f"registry-stack-{version}-candidate-receipt.json"
            )
            receipt.rename(destination / "release-candidate-receipt.json")
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discover", type=Path, required=True)
    parser.add_argument(
        "--product-input-records",
        type=Path,
        help="directory containing product-input lifecycle records",
    )
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        versions = prepare_assets(
            args.discover,
            args.asset_root,
            product_input_records=args.product_input_records,
        )
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(
                    f"has_candidates={'true' if versions else 'false'}\n"
                )
                output.write(f"versions={','.join(versions)}\n")
    except (PreparationError, OSError) as error:
        print(f"candidate asset preparation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"prepared candidate release inputs for {len(versions)} version(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
