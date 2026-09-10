#!/usr/bin/env python3
"""Validate canonical binary shards and reconstruct the release layout."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path


VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ShardError(ValueError):
    """A binary shard cannot be used as canonical release input."""


def rosters(version: str) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    match = VERSION.fullmatch(version)
    if match is None:
        raise ShardError("version must be canonical semantic version text")
    parsed = tuple(int(part) for part in match.groups())
    tag = f"v{version}"
    core: list[str] = []
    image_bins: list[tuple[str, str]] = []
    if parsed >= (0, 24, 0):
        discovery = f"discovery-{tag}-linux-amd64"
        core.append(discovery)
        image_bins.append(("discovery", discovery))
    breg: list[str] = []
    if parsed >= (0, 26, 0):
        breg = [f"breg-{tag}-linux-amd64", f"bregctl-{tag}-linux-amd64"]
        image_bins.append(("breg", breg[0]))
    casework: list[str] = []
    if parsed >= (0, 30, 0):
        casework = [
            f"casework-{tag}-linux-amd64",
            f"caseworkctl-{tag}-linux-amd64",
        ]
        image_bins.append(("casework", casework[0]))
    common = [
        f"evidence-{tag}-linux-amd64",
        f"evidencectl-{tag}-linux-amd64",
        f"mint-{tag}-linux-amd64",
        f"evidence-oid4vci-{tag}-linux-amd64",
        f"registry-manifest-{tag}-linux-amd64",
        f"relay-{tag}-linux-amd64",
        f"relayctl-{tag}-linux-amd64",
    ]
    core.extend(common)
    for image_name in ("evidence", "mint", "relay"):
        image_bins.append((image_name, f"{image_name}-{tag}-linux-amd64"))
    return {"core": core, "breg": breg, "casework": casework}, image_bins


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ShardError(f"missing shard path: {path}") from error
    if not stat.S_ISREG(mode):
        raise ShardError(f"shard path must be a regular file: {path}")


def validate_shard(
    name: str,
    root: Path,
    expected_assets: list[str],
    expected_builder: str,
    version: str,
    source_sha: str,
) -> dict[str, Path]:
    if not root.is_dir() or root.is_symlink():
        raise ShardError(f"{name} shard must be a directory: {root}")
    expected_root = {"bin", "RELEASE_BINARY_SHARD", "RELEASE_BUILDER_IMAGE"}
    actual_root = {entry.name for entry in root.iterdir()}
    if actual_root != expected_root:
        raise ShardError(
            f"{name} shard root inventory mismatch: expected {sorted(expected_root)}, "
            f"found {sorted(actual_root)}"
        )
    bin_dir = root / "bin"
    if not bin_dir.is_dir() or bin_dir.is_symlink():
        raise ShardError(f"{name} shard bin must be a directory")
    expected_bin = {*expected_assets, "SHA256SUMS"}
    actual_bin = {entry.name for entry in bin_dir.iterdir()}
    if actual_bin != expected_bin:
        raise ShardError(
            f"{name} shard binary inventory mismatch: expected {sorted(expected_bin)}, "
            f"found {sorted(actual_bin)}"
        )

    marker = root / "RELEASE_BUILDER_IMAGE"
    require_regular_file(marker)
    marker_value = marker.read_text(encoding="utf-8")
    if marker_value != f"{expected_builder}\n":
        raise ShardError(f"{name} shard builder identity does not match the pinned builder")
    metadata = root / "RELEASE_BINARY_SHARD"
    require_regular_file(metadata)
    expected_metadata = (
        "registry-stack.release-binary-shard.v1\n"
        f"source_sha={source_sha}\n"
        f"version={version}\n"
        f"group={name}\n"
    )
    if metadata.read_text(encoding="utf-8") != expected_metadata:
        raise ShardError(f"{name} shard metadata does not match the requested build")

    sums = bin_dir / "SHA256SUMS"
    require_regular_file(sums)
    checksum_assets: list[str] = []
    checksum_values: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        parts = line.split("  ")
        if len(parts) != 2 or not SHA256.fullmatch(parts[0]) or not parts[1]:
            raise ShardError(f"{name} shard has a malformed checksum line")
        asset = parts[1]
        if asset in checksum_values:
            raise ShardError(f"{name} shard checksum roster duplicates {asset}")
        checksum_assets.append(asset)
        checksum_values[asset] = parts[0]
    if checksum_assets != expected_assets:
        raise ShardError(
            f"{name} shard checksum roster mismatch: expected {expected_assets}, "
            f"found {checksum_assets}"
        )

    validated: dict[str, Path] = {}
    for asset in expected_assets:
        path = bin_dir / asset
        require_regular_file(path)
        if sha256(path) != checksum_values[asset]:
            raise ShardError(f"{name} shard checksum mismatch for {asset}")
        validated[asset] = path
    return validated


def write_sums(directory: Path, names: list[str]) -> None:
    (directory / "SHA256SUMS").write_text(
        "".join(f"{sha256(directory / name)}  {name}\n" for name in names),
        encoding="utf-8",
    )


def merge(
    *,
    version: str,
    source_sha: str,
    core: Path,
    breg: Path,
    casework: Path | None,
    output: Path,
    builder_image: str,
) -> None:
    shard_rosters, image_roster = rosters(version)
    if not builder_image or "\n" in builder_image:
        raise ShardError("pinned builder image must be one nonempty line")
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ShardError("source SHA must be an exact lowercase commit ID")
    if output.exists() or output.is_symlink():
        raise ShardError(f"output already exists: {output}")

    inputs = {
        "core": validate_shard(
            "core", core, shard_rosters["core"], builder_image, version, source_sha
        ),
        "breg": validate_shard(
            "breg", breg, shard_rosters["breg"], builder_image, version, source_sha
        ),
    }
    if casework is None:
        if shard_rosters["casework"]:
            raise ShardError("casework shard is required from version 0.30.0")
        inputs["casework"] = {}
    else:
        inputs["casework"] = validate_shard(
            "casework",
            casework,
            shard_rosters["casework"],
            builder_image,
            version,
            source_sha,
        )
    sources = inputs["core"] | inputs["breg"] | inputs["casework"]
    final_bin_roster: list[str] = []
    if shard_rosters["core"] and shard_rosters["core"][0].startswith("discovery-"):
        final_bin_roster.append(shard_rosters["core"][0])
    final_bin_roster.extend(shard_rosters["breg"])
    final_bin_roster.extend(shard_rosters["casework"])
    final_bin_roster.extend(
        asset for asset in shard_rosters["core"] if not asset.startswith("discovery-")
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        bin_dir = temporary / "bin"
        image_bin_dir = temporary / "image-bin"
        bin_dir.mkdir()
        image_bin_dir.mkdir()
        for asset in final_bin_roster:
            destination = bin_dir / asset
            shutil.copyfile(sources[asset], destination)
            destination.chmod(0o755)
        write_sums(bin_dir, final_bin_roster)

        marker = image_bin_dir / "RELEASE_BUILDER_IMAGE"
        marker.write_text(f"{builder_image}\n", encoding="utf-8")
        image_names: list[str] = []
        for image_name, source_name in image_roster:
            destination = image_bin_dir / image_name
            shutil.copyfile(sources[source_name], destination)
            destination.chmod(0o755)
            image_names.append(image_name)
        write_sums(image_bin_dir, ["RELEASE_BUILDER_IMAGE", *image_names])
        os.replace(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--breg", required=True, type=Path)
    parser.add_argument("--casework", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--builder-image", required=True)
    args = parser.parse_args()
    try:
        merge(
            version=args.version,
            source_sha=args.source_sha,
            core=args.core,
            breg=args.breg,
            casework=args.casework,
            output=args.output,
            builder_image=args.builder_image,
        )
    except (OSError, UnicodeError, ShardError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
