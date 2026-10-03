#!/usr/bin/env python3
"""Validate canonical binary shards and reconstruct the release layout."""

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
MINT_RETIREMENT_VERSION = (0, 31, 0)
# From this version schedulingctl is published and each stateful product image
# carries its operator tool beside the runtime binary.
OPERATOR_TOOL_VERSION = (0, 36, 0)


class ShardError(ValueError):
    """A binary shard cannot be used as canonical release input."""


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


def rosters(
    version: str, nightly_tag: str | None = None
) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    match = VERSION.fullmatch(version)
    if match is None:
        raise ShardError("version must be canonical semantic version text")
    parsed = tuple(int(part) for part in match.groups())
    tag = nightly_tag or f"v{version}"
    core: list[str] = []
    image_bins: list[tuple[str, str]] = []
    if parsed >= (0, 24, 0):
        discovery = f"discovery-{tag}-linux-amd64"
        core.append(discovery)
        image_bins.append(("discovery", discovery))
    if release_roster.discoveryctl_in_release(parsed):
        core.append(f"discoveryctl-{tag}-linux-amd64")
    breg: list[str] = []
    if parsed >= (0, 26, 0):
        breg = [f"breg-{tag}-linux-amd64", f"bregctl-{tag}-linux-amd64"]
        image_bins.append(("breg", breg[0]))
        if parsed >= OPERATOR_TOOL_VERSION:
            image_bins.append(("bregctl", breg[1]))
    if release_roster.breg_services_in_release(parsed):
        # The citizen MCP gateway and its review page ship in the BReg set.
        for service in ("breg-mcp", "breg-review"):
            asset = f"{service}-{tag}-linux-amd64"
            breg.append(asset)
            image_bins.append((service, asset))
    casework: list[str] = []
    if parsed >= (0, 30, 0):
        casework = [
            f"casework-{tag}-linux-amd64",
            f"caseworkctl-{tag}-linux-amd64",
        ]
        image_bins.append(("casework", casework[0]))
        if parsed >= OPERATOR_TOOL_VERSION:
            image_bins.append(("caseworkctl", casework[1]))
    scheduling: list[str] = []
    if parsed >= (0, 33, 0):
        scheduling = [f"scheduling-{tag}-linux-amd64"]
        image_bins.append(("scheduling", scheduling[0]))
        if parsed >= OPERATOR_TOOL_VERSION:
            scheduling.append(f"schedulingctl-{tag}-linux-amd64")
            image_bins.append(("schedulingctl", scheduling[1]))
    messaging: list[str] = []
    if release_roster.messaging_in_release(parsed):
        messaging = [
            f"messaging-{tag}-linux-amd64",
            f"messagingctl-{tag}-linux-amd64",
        ]
        image_bins.append(("messaging", messaging[0]))
        if parsed >= OPERATOR_TOOL_VERSION:
            image_bins.append(("messagingctl", messaging[1]))
    common = [
        f"evidence-{tag}-linux-amd64",
        f"evidencectl-{tag}-linux-amd64",
        f"mint-{tag}-linux-amd64",
        f"evidence-oid4vci-{tag}-linux-amd64",
        f"registry-manifest-{tag}-linux-amd64",
    ]
    if release_roster.relay_in_release(parsed):
        common.extend(
            [
                f"relay-{tag}-linux-amd64",
                f"relayctl-{tag}-linux-amd64",
            ]
        )
    if parsed >= MINT_RETIREMENT_VERSION:
        common.remove(f"mint-{tag}-linux-amd64")
    if release_roster.render_in_release(parsed):
        common.append(f"registry-render-{tag}-linux-amd64")
    core.extend(common)
    historical_images = ["evidence", "mint"]
    if release_roster.relay_in_release(parsed):
        historical_images.append("relay")
    for image_name in historical_images:
        if image_name != "mint" or parsed < MINT_RETIREMENT_VERSION:
            image_bins.append((image_name, f"{image_name}-{tag}-linux-amd64"))
    if release_roster.evidence_oid4vci_image_in_release(parsed):
        image_bins.append(
            ("evidence-oid4vci", f"evidence-oid4vci-{tag}-linux-amd64")
        )
    if release_roster.render_in_release(parsed):
        image_bins.append(
            ("registry-render", f"registry-render-{tag}-linux-amd64")
        )
    return {
        "core": core,
        "breg": breg,
        "casework": casework,
        "scheduling": scheduling,
        "messaging": messaging,
    }, image_bins


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
    nightly_tag: str | None,
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
    if nightly_tag is None:
        expected_metadata = (
            "registry-stack.release-binary-shard.v1\n"
            f"source_sha={source_sha}\n"
            f"version={version}\n"
            f"group={name}\n"
        )
    else:
        expected_metadata = (
            "registry-stack.release-binary-shard.v2\n"
            f"source_sha={source_sha}\n"
            f"version={version}\n"
            f"nightly_tag={nightly_tag}\n"
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
    scheduling: Path | None,
    messaging: Path | None,
    output: Path,
    builder_image: str,
    nightly_tag: str | None = None,
) -> None:
    validate_nightly_tag(version, source_sha, nightly_tag)
    shard_rosters, image_roster = rosters(version, nightly_tag)
    if not builder_image or "\n" in builder_image:
        raise ShardError("pinned builder image must be one nonempty line")
    if SOURCE_SHA.fullmatch(source_sha) is None:
        raise ShardError("source SHA must be an exact lowercase commit ID")
    if output.exists() or output.is_symlink():
        raise ShardError(f"output already exists: {output}")

    inputs = {
        "core": validate_shard(
            "core", core, shard_rosters["core"], builder_image, version, source_sha,
            nightly_tag
        ),
        "breg": validate_shard(
            "breg", breg, shard_rosters["breg"], builder_image, version, source_sha,
            nightly_tag
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
            nightly_tag,
        )
    if scheduling is None:
        if shard_rosters["scheduling"]:
            raise ShardError("scheduling shard is required from version 0.33.0")
        inputs["scheduling"] = {}
    else:
        inputs["scheduling"] = validate_shard(
            "scheduling",
            scheduling,
            shard_rosters["scheduling"],
            builder_image,
            version,
            source_sha,
            nightly_tag,
        )
    if messaging is None:
        if shard_rosters["messaging"]:
            raise ShardError(
                "messaging shard is required for a release that ships Messaging"
            )
        inputs["messaging"] = {}
    else:
        inputs["messaging"] = validate_shard(
            "messaging",
            messaging,
            shard_rosters["messaging"],
            builder_image,
            version,
            source_sha,
            nightly_tag,
        )
    sources = (
        inputs["core"]
        | inputs["breg"]
        | inputs["casework"]
        | inputs["scheduling"]
        | inputs["messaging"]
    )
    final_bin_roster: list[str] = []
    discovery_assets = [
        asset for asset in shard_rosters["core"]
        if asset.startswith(("discovery-", "discoveryctl-"))
    ]
    final_bin_roster.extend(discovery_assets)
    final_bin_roster.extend(shard_rosters["breg"])
    final_bin_roster.extend(shard_rosters["casework"])
    # Scheduling's operator tool predates its standalone runtime binary.
    final_bin_roster.extend(
        asset for asset in shard_rosters["scheduling"]
        if asset.startswith("schedulingctl-")
        or release_roster.scheduling_binary_in_release(release_roster.parse_version(version))
    )
    final_bin_roster.extend(shard_rosters["messaging"])
    final_bin_roster.extend(
        asset for asset in shard_rosters["core"] if asset not in discovery_assets
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
    parser.add_argument("--nightly-tag")
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--breg", required=True, type=Path)
    parser.add_argument("--casework", type=Path)
    parser.add_argument("--scheduling", type=Path)
    parser.add_argument("--messaging", type=Path)
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
            scheduling=args.scheduling,
            messaging=args.messaging,
            output=args.output,
            builder_image=args.builder_image,
            nightly_tag=args.nightly_tag,
        )
    except (OSError, UnicodeError, ShardError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
