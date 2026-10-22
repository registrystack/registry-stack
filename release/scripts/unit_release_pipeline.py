#!/usr/bin/env python3
"""Unit-specific inputs to the shared candidate and promotion workflows."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib


def prepare_unit(repo: Path, unit: str, version: str, release_id: str) -> dict:
    if unit != "discovery":
        raise ValueError("only the Discovery independent release pilot is enabled")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("version must be canonical semantic version text")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", release_id):
        raise ValueError("invalid release ID")
    for name in ("registry-discovery", "registry-discoveryctl"):
        path = repo / "crates" / name / "Cargo.toml"
        package = tomllib.loads(path.read_text())["package"]
        if package.get("version") != version:
            raise ValueError(f"{name} package version must equal {version}")
    tag = f"discovery/v{version}"
    notes = repo / "release/notes" / f"{tag}.md"
    if notes.is_symlink() or not notes.is_file() or not notes.read_text().strip():
        raise ValueError(f"release notes must be a nonempty regular file: {notes}")
    return {"unit": unit, "version": version, "release_id": release_id,
            "tag": tag, "notes": notes.relative_to(repo).as_posix(),
            "binary_groups": [unit], "images": [unit]}


def merge_unit_shard(unit: str, version: str, source_sha: str, shard: Path,
                     output: Path, builder: str) -> None:
    if unit != "discovery":
        raise ValueError("only the Discovery independent release pilot is enabled")
    spec = importlib.util.spec_from_file_location(
        "merge_release_binary_shards", Path(__file__).with_name("merge-release-binary-shards.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.VERSION.fullmatch(version) is None or module.SOURCE_SHA.fullmatch(source_sha) is None:
        raise ValueError("invalid version or source SHA")
    if output.exists() or output.is_symlink():
        raise ValueError(f"output already exists: {output}")
    assets = [f"{name}-v{version}-linux-amd64" for name in ("discovery", "discoveryctl")]
    sources = module.validate_shard(unit, shard, assets, builder, version, source_sha, None)
    (output / "bin").mkdir(parents=True)
    (output / "image-bin").mkdir()
    for name, source in sources.items():
        shutil.copyfile(source, output / "bin" / name)
        (output / "bin" / name).chmod(0o755)
    shutil.copyfile(sources[assets[0]], output / "image-bin/discovery")
    (output / "image-bin/discovery").chmod(0o755)
    (output / "image-bin/RELEASE_BUILDER_IMAGE").write_text(builder + "\n")
    module.write_sums(output / "image-bin", ["RELEASE_BUILDER_IMAGE", "discovery"])


def stage_payload(repo: Path, unit: str, version: str, binaries: Path, output: Path) -> None:
    import release_units
    expected = {name for name, kind in release_units.payload_inventory(unit, version).items()
                if kind == "binary"}
    if {p.name for p in binaries.iterdir()} != expected:
        raise ValueError("unit binary inventory differs from the release registry")
    for name in expected:
        if (binaries / name).is_symlink() or not (binaries / name).is_file():
            raise ValueError("unit binary must be a regular file")
    installer = (repo / "crates/registry-discovery/install.sh").read_text()
    if installer.count('default_version=""') != 1:
        raise ValueError("installer must contain one version placeholder")
    installer = installer.replace('default_version=""', f'default_version="v{version}"')
    output.mkdir(parents=True, exist_ok=False)
    for name in expected:
        shutil.copyfile(binaries / name, output / name)
        (output / name).chmod(0o755)
    for name in (f"discovery-v{version}-install.sh", "discovery-install.sh"):
        (output / name).write_text(installer)
        (output / name).chmod(0o755)
    shutil.copyfile(repo / "THIRD_PARTY_NOTICES", output / "THIRD_PARTY_NOTICES")
    sums = output / "SHA256SUMS"
    sums.write_text("".join(f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n"
                            for name in sorted(expected)))
    with tempfile.TemporaryDirectory(prefix="discovery-install-smoke-") as temporary:
        environment = dict(os.environ, DISCOVERY_ASSET_DIR=str(output.resolve()),
                           DISCOVERY_INSTALL_DIR=str(Path(temporary) / "bin"))
        subprocess.run(["bash", str(output / f"discovery-v{version}-install.sh")],
                       env=environment, check=True)
        for binary in ("discovery", "discoveryctl"):
            result = subprocess.run([str(Path(temporary) / "bin" / binary), "--version"],
                                    check=True, text=True, capture_output=True)
            if result.stdout.strip() != f"{binary} {version}":
                raise ValueError(f"installed {binary} reports a different version")
    sums.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--unit", required=True)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--release-id", required=True)
    prepare.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    stage = commands.add_parser("stage-payload")
    stage.add_argument("--unit", required=True)
    stage.add_argument("--version", required=True)
    stage.add_argument("--binaries", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    merge = commands.add_parser("merge-shard")
    merge.add_argument("--unit", required=True)
    merge.add_argument("--version", required=True)
    merge.add_argument("--source-sha", required=True)
    merge.add_argument("--shard", type=Path, required=True)
    merge.add_argument("--output", type=Path, required=True)
    merge.add_argument("--builder-image", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        print(json.dumps(prepare_unit(args.repo, args.unit, args.version, args.release_id)))
        return
    if args.command == "stage-payload":
        stage_payload(args.repo, args.unit, args.version, args.binaries, args.output)
        return
    merge_unit_shard(args.unit, args.version, args.source_sha, args.shard,
                     args.output, args.builder_image)


if __name__ == "__main__":
    main()
