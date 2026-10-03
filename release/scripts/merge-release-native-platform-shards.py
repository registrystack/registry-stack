#!/usr/bin/env python3
"""Validate and merge exact-source macOS release binary shards."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_roster  # noqa: E402


VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
TARGET = "aarch64-apple-darwin"
ASSET = "macos-arm64"
RUST_TOOLCHAIN = "1.95.0"
PURPOSES = {"candidate_input", "review_only"}
MINT_RETIREMENT_VERSION = (0, 31, 0)
MACOS_FIPS_ARCHIVE_MINIMUM_VERSION = (0, 33, 0)
# Scheduling has no macOS runtime asset; its operator tool is a native
# release binary from this version.
SCHEDULINGCTL_MINIMUM_VERSION = (0, 36, 0)


class ShardError(ValueError):
    """A native shard cannot be used as release input."""


def validate_nightly_tag(
    version: str, source_sha: str, nightly_tag: str | None
) -> None:
    if nightly_tag is None:
        return
    match = re.fullmatch(
        rf"v{re.escape(version)}-nightly\.([0-9]{{8}})\.([0-9a-f]{{40}})",
        nightly_tag,
    )
    if match is None:
        raise ShardError(
            "nightly tag must match "
            f"v{version}-nightly.<YYYYMMDD>.<40-character lowercase source SHA>"
        )
    try:
        datetime.datetime.strptime(match.group(1), "%Y%m%d")
    except ValueError as error:
        raise ShardError("nightly tag contains an invalid YYYYMMDD date") from error
    if match.group(2) != source_sha:
        raise ShardError("nightly tag source SHA does not match --source-sha")


def rosters(version: str, nightly_tag: str | None = None) -> dict[str, list[str]]:
    match = VERSION.fullmatch(version)
    if match is None:
        raise ShardError("version must be canonical semantic version text")
    parsed = tuple(int(part) for part in match.groups())
    tag = nightly_tag or f"v{version}"
    core = [
        f"evidence-{tag}-{ASSET}",
        f"evidencectl-{tag}-{ASSET}",
        f"mint-{tag}-{ASSET}",
        f"evidence-oid4vci-{tag}-{ASSET}",
    ]
    if release_roster.relay_in_release(parsed):
        core.insert(0, f"relayctl-{tag}-{ASSET}")
    if parsed >= MINT_RETIREMENT_VERSION:
        core.remove(f"mint-{tag}-{ASSET}")
    breg = []
    bregctl = []
    if parsed >= (0, 26, 0):
        breg = [f"breg-{tag}-{ASSET}"]
        bregctl = [f"bregctl-{tag}-{ASSET}"]
    if release_roster.breg_services_in_release(parsed):
        # The citizen MCP gateway and its review page are clients of BReg, so
        # they build beside bregctl rather than beside the runtime.
        bregctl.extend(
            [f"breg-mcp-{tag}-{ASSET}", f"breg-review-{tag}-{ASSET}"]
        )
    casework = []
    if parsed >= (0, 30, 0):
        casework = [
            f"casework-{tag}-{ASSET}",
            f"caseworkctl-{tag}-{ASSET}",
        ]
    scheduling = []
    if parsed >= SCHEDULINGCTL_MINIMUM_VERSION:
        scheduling = [f"schedulingctl-{tag}-{ASSET}"]
    if parsed >= MACOS_FIPS_ARCHIVE_MINIMUM_VERSION:
        core = [f"{name}.tar.gz" for name in core]
        breg = [f"{name}.tar.gz" for name in breg]
        bregctl = [f"{name}.tar.gz" for name in bregctl]
        casework = [f"{name}.tar.gz" for name in casework]
        scheduling = [f"{name}.tar.gz" for name in scheduling]
    return {
        "core": core,
        "breg": breg,
        "bregctl": bregctl,
        "casework": casework,
        "scheduling": scheduling,
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
    nightly_tag: str | None,
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
            f"{name} shard asset inventory mismatch: expected {expected_assets}, "
            f"found {sorted(actual_assets)}"
        )

    metadata = root / "RELEASE_NATIVE_PLATFORM_SHARD"
    require_regular_file(metadata)
    parsed_version = tuple(int(part) for part in version.split("."))
    format_version = (
        "v2"
        if parsed_version >= MACOS_FIPS_ARCHIVE_MINIMUM_VERSION
        else "v1"
    )
    if nightly_tag is None:
        expected_metadata = (
            f"registry-stack.release-native-platform-shard.{format_version}\n"
            f"purpose={purpose}\n"
            f"source_sha={source_sha}\n"
            f"version={version}\n"
            f"target={TARGET}\n"
            f"asset={ASSET}\n"
            f"group={name}\n"
            f"rust_toolchain={RUST_TOOLCHAIN}\n"
        )
    else:
        expected_metadata = (
            "registry-stack.release-native-platform-shard.v3\n"
            f"purpose={purpose}\n"
            f"source_sha={source_sha}\n"
            f"version={version}\n"
            f"nightly_tag={nightly_tag}\n"
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
    scheduling: Path | None = None,
    nightly_tag: str | None = None,
) -> None:
    validate_nightly_tag(version, source_sha, nightly_tag)
    shard_rosters = rosters(version, nightly_tag)
    if SOURCE_SHA.fullmatch(source_sha) is None:
        raise ShardError("source SHA must be an exact lowercase commit ID")
    if purpose not in PURPOSES:
        raise ShardError("purpose must be candidate_input or review_only")
    if nightly_tag is not None and purpose != "review_only":
        raise ShardError("nightly native shards must use purpose review_only")
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
            nightly_tag=nightly_tag,
        ),
        "breg": validate_shard(
            "breg",
            breg,
            shard_rosters["breg"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
            nightly_tag=nightly_tag,
        ),
        "bregctl": validate_shard(
            "bregctl",
            bregctl,
            shard_rosters["bregctl"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
            nightly_tag=nightly_tag,
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
            nightly_tag=nightly_tag,
        )
    if scheduling is None:
        if shard_rosters["scheduling"]:
            raise ShardError("scheduling shard is required from version 0.36.0")
        inputs["scheduling"] = {}
    else:
        inputs["scheduling"] = validate_shard(
            "scheduling",
            scheduling,
            shard_rosters["scheduling"],
            purpose=purpose,
            version=version,
            source_sha=source_sha,
            nightly_tag=nightly_tag,
        )
    sources = (
        inputs["core"]
        | inputs["breg"]
        | inputs["bregctl"]
        | inputs["casework"]
        | inputs["scheduling"]
    )
    final_roster = [
        *shard_rosters["core"],
        *shard_rosters["breg"],
        *shard_rosters["bregctl"],
        *shard_rosters["casework"],
        *shard_rosters["scheduling"],
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        platform = temporary / "platform"
        platform.mkdir()
        for asset in final_roster:
            destination = platform / asset
            shutil.copyfile(sources[asset], destination)
            destination.chmod(
                0o644
                if tuple(int(part) for part in version.split("."))
                >= MACOS_FIPS_ARCHIVE_MINIMUM_VERSION
                else 0o755
            )
        os.replace(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--nightly-tag")
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--breg", required=True, type=Path)
    parser.add_argument("--bregctl", required=True, type=Path)
    parser.add_argument("--casework", type=Path)
    parser.add_argument("--scheduling", type=Path)
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
            scheduling=args.scheduling,
            output=args.output,
            nightly_tag=args.nightly_tag,
        )
    except (OSError, UnicodeError, ShardError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
