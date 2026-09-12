#!/usr/bin/env python3
"""Build the Registry ThunderID extension from verified upstream source.

Only creates a fresh output directory. Never replaces an existing build or
starts a service. Use --image to build a local candidate container as well.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PIN = ROOT / "crates/registry-thunderid-tooling/thunderid-version.json"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("build assets must not contain symlinks")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def extract_source(archive: Path, destination: Path, expected_digest: str) -> None:
    if sha256(archive) != expected_digest:
        raise ValueError("upstream archive checksum mismatch")
    # Verify all paths before extraction; create internal symlinks last.
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        roots = {Path(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise ValueError("upstream archive must contain one source root")
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError("unsupported upstream archive entry")
            if member.issym():
                relative = Path(*path.parts[1:])
                resolved = (destination / relative.parent / member.linkname).resolve()
                if Path(member.linkname).is_absolute() or not resolved.is_relative_to(destination.resolve()):
                    raise ValueError("unsupported upstream archive link")
        destination.mkdir()
        for member in members:
            if member.issym():
                continue
            relative = Path(*Path(member.name).parts[1:])
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, target.open("xb") as output:
                    shutil.copyfileobj(data, output)
                target.chmod(member.mode & 0o755)
        for member in members:
            if member.issym():
                target = destination / Path(*Path(member.name).parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)


def run(arguments: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, cwd=cwd, env=env, check=True)


def apply_source_patch(source: Path, patch: Path) -> None:
    # Without a local Git root, git apply can discover the enclosing Registry
    # repository and silently skip paths outside the current subdirectory.
    run(["git", "init", "--quiet"], cwd=source)
    run(["git", "apply", "--check", str(patch)], cwd=source)
    run(["git", "apply", str(patch)], cwd=source)
    run(["git", "apply", "--reverse", "--check", str(patch)], cwd=source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="cached source archive, verified against the pin")
    parser.add_argument("--output", type=Path, required=True, help="fresh build directory")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--image", action="store_true", help="build a local image for this host's Docker architecture")
    args = parser.parse_args()
    if args.prepare_only and args.image:
        parser.error("--prepare-only and --image cannot be combined")
    output = args.output.resolve()
    if output.exists():
        parser.error("output already exists; choose a fresh directory")
    pin = json.loads(PIN.read_text())
    output.mkdir(parents=True)
    archive = args.archive.resolve() if args.archive else output / "upstream.tar.gz"
    if not args.archive:
        urllib.request.urlretrieve(pin["source"]["archiveUrl"], archive)
    source = output / "upstream"
    extract_source(archive, source, pin["source"]["archiveSha256"])
    patch = HERE / "registry-citizen-federation.patch"
    # Apply a captured copy so the metadata always describes the applied bytes.
    shutil.copyfile(patch, output / "thunderid.patch")
    apply_source_patch(source, output / "thunderid.patch")
    metadata = {
        "schema": "registry.thunderid-extension-build/v1",
        "upstreamVersion": pin["version"],
        "upstreamCommit": pin["source"]["commit"],
        "archiveSha256": pin["source"]["archiveSha256"],
        "patchSha256": sha256(output / "thunderid.patch"),
        "baseImage": pin["image"],
    }
    if not args.prepare_only:
        environment = os.environ.copy()
        if args.image:
            architecture = subprocess.check_output(
                ["docker", "info", "--format", "{{.Architecture}}"], text=True
            ).strip()
            go_arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(architecture)
            if go_arch is None:
                raise ValueError("supported Docker architectures are amd64 and arm64")
            environment.update(GOOS="linux", GOARCH=go_arch, CGO_ENABLED="0")
        binary = output / "thunderid"
        run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "./cmd/server"],
            cwd=source / "backend", env=environment)
        metadata["binarySha256"] = sha256(binary)
        metadata["goVersion"] = subprocess.check_output(["go", "version"], text=True).strip()
        frontend = source / "frontend"
        package = json.loads((source / "package.json").read_text())
        expected_pnpm = package["devEngines"]["packageManager"]["version"]
        actual_pnpm = subprocess.check_output(["pnpm", "--version"], cwd=frontend, text=True).strip()
        if actual_pnpm != expected_pnpm:
            raise ValueError("pnpm version does not match the pinned upstream package manager")
        run(["pnpm", "install", "--frozen-lockfile"], cwd=frontend)
        run(["pnpm", "exec", "turbo", "run", "build", "--filter=@thunderid/gate..."], cwd=frontend)
        gate = frontend / "apps/gate/dist"
        if not (gate / "index.html").is_file():
            raise ValueError("native Gate frontend build is missing")
        metadata["gateTreeSha256"] = tree_sha256(gate)
        metadata["frontendLockSha256"] = sha256(source / "pnpm-lock.yaml")
        metadata["nodeVersion"] = subprocess.check_output(["node", "--version"], text=True).strip()
        metadata["pnpmVersion"] = actual_pnpm
        if args.image:
            context = output / "image"
            context.mkdir()
            shutil.copyfile(binary, context / "thunderid")
            shutil.copytree(gate, context / "gate")
            (context / "Dockerfile").write_text(
                f"FROM {pin['image']}\n"
                "COPY --chmod=0755 --chown=10001:10001 thunderid /opt/thunderid/thunderid\n"
                "USER root\nRUN rm -rf /opt/thunderid/apps/gate\n"
                "COPY --chown=10001:10001 gate /opt/thunderid/apps/gate\nUSER 10001\n"
            )
            run(["docker", "build", "--iidfile", str(output / "image-id"), str(context)], cwd=output)
            metadata["imageId"] = (output / "image-id").read_text().strip()
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(output / "build.json")


if __name__ == "__main__":
    main()
