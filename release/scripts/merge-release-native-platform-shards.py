#!/usr/bin/env python3
"""Validate and merge exact-source macOS release binary shards."""

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
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
TARGET = "aarch64-apple-darwin"
ASSET = "macos-arm64"
RUST_TOOLCHAIN = "1.95.0"
PURPOSES = {"candidate_input", "review_only"}


class ShardError(ValueError):
    """A native shard cannot be used as release input."""


def rosters(version: str) -> dict[str, list[str]]:
    match = VERSION.fullmatch(version)
    if match is None:
        raise ShardError("version must be canonical semantic version text")
    parsed = tuple(int(part) for part in match.groups())
    tag = f"v{version}"
    core = [
        f"relayctl-{tag}-{ASSET}",
        f"evidence-{tag}-{ASSET}",
        f"evidencectl-{tag}-{ASSET}",
        f"mint-{tag}-{ASSET}",
        f"evidence-oid4vci-{tag}-{ASSET}",
    ]
    if parsed >= (0, 30, 0):
        core.remove(f"mint-{tag}-{ASSET}")
    breg = []
    bregctl = []
    if parsed >= (0, 26, 0):
        breg = [f"breg-{tag}-{ASSET}"]
        bregctl = [f"bregctl-{tag}-{ASSET}"]
    casework = []
    if parsed >= (0, 30, 0):
        casework = [
            f"casework-{tag}-{ASSET}",
            f"caseworkctl-{tag}-{ASSET}",
        ]
    return {
        "core": core,
        "breg": breg,
        "bregctl": bregctl,
        "casework": casework,
    }


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
    *,
    purpose: str,
    version: str,
    source_sha: str,
) -> dict[str, Path]:
    if not root.is_dir() or root.is_symlink():
        raise ShardError(f"{name} shard must be a directory: {root}")
    expected_root = {"SHA256SUMS", "RELEASE_NATIVE_PLATFORM_SHARD"}
    if expected_assets or (root / "platform").exists():
        expected_root.add("platform")
    actual_root = {entry.name for entry in root.iterdir()}
    if actual_root != expected_root:
        raise ShardError(
            f"{name} shard root inventory mismatch: expected {sorted(expected_root)}, "
            f"found {sorted(actual_root)}"
        )
    platform = root / "platform"
    if expected_assets and (not platform.is_dir() or platform.is_symlink()):
        raise ShardError(f"{name} shard platform must be a directory")
    if platform.exists() and (not platform.is_dir() or platform.is_symlink()):
        raise ShardError(f"{name} shard platform must be a directory")
    actual_assets = {entry.name for entry in platform.iterdir()} if platform.exists() else set()
    if actual_assets != set(expected_assets):
        raise ShardError(
            f"{name} shard binary inventory mismatch: expected {expected_assets}, "
            f"found {sorted(actual_assets)}"
        )

    metadata = root / "RELEASE_NATIVE_PLATFORM_SHARD"
    require_regular_file(metadata)
    expected_metadata = (
        "registry-stack.release-native-platform-shard.v1\n"
        f"purpose={purpose}\n"
        f"source_sha={source_sha}\n"
        f"version={version}\n"
        f"target={TARGET}\n"
        f"asset={ASSET}\n"
        f"group={name}\n"
        f"rust_toolchain={RUST_TOOLCHAIN}\n"
    )
    if metadata.read_text(encoding="utf-8") != expected_metadata:
        raise ShardError(f"{name} shard metadata does not match the requested build")

    sums = root / "SHA256SUMS"
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
        path = platform / asset
        require_regular_file(path)
        if sha256(path) != checksum_values[asset]:
            raise ShardError(f"{name} shard checksum mismatch for {asset}")
        validated[asset] = path
    return validated


def merge(
    *,
    version: str,
    source_sha: str,
    purpose: str,
    core: Path,
    breg: Path,
    bregctl: Path,
    casework: Path | None,
    output: Path,
) -> None:
    shard_rosters = rosters(version)
    if SOURCE_SHA.fullmatch(source_sha) is None:
        raise ShardError("source SHA must be an exact lowercase commit ID")
    if purpose not in PURPOSES:
        raise ShardError("purpose must be candidate_input or review_only")
    if output.exists() or output.is_symlink():
        raise ShardError(f"output already exists: {output}")

    inputs = {
        "core": validate_shard(
            "core",
            core,
            shard_rosters["core"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
        ),
        "breg": validate_shard(
            "breg",
            breg,
            shard_rosters["breg"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
        ),
        "bregctl": validate_shard(
            "bregctl",
            bregctl,
            shard_rosters["bregctl"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
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
            purpose=purpose,
            version=version,
            source_sha=source_sha,
        )
    sources = inputs["core"] | inputs["breg"] | inputs["bregctl"] | inputs["casework"]
    final_roster = [
        *shard_rosters["core"],
        *shard_rosters["breg"],
        *shard_rosters["bregctl"],
        *shard_rosters["casework"],
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        platform = temporary / "platform"
        platform.mkdir()
        for asset in final_roster:
            destination = platform / asset
            shutil.copyfile(sources[asset], destination)
            destination.chmod(0o755)
        os.replace(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--breg", required=True, type=Path)
    parser.add_argument("--bregctl", required=True, type=Path)
    parser.add_argument("--casework", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        merge(
            version=args.version,
            source_sha=args.source_sha,
            purpose=args.purpose,
            core=args.core,
            breg=args.breg,
            bregctl=args.bregctl,
            casework=args.casework,
            output=args.output,
        )
    except (OSError, UnicodeError, ShardError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
