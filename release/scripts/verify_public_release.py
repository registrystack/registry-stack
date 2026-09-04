#!/usr/bin/env python3
"""Verify the minimum public Registry Stack Beta release contract."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_candidate
import client_registry


TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"


class PublicReleaseError(RuntimeError):
    """The public release does not satisfy its minimum contract."""


def version_uses_client_registries(version: str) -> bool:
    return (
        tuple(int(part) for part in version.split("."))
        >= release_candidate.CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION
    )


def client_registry_clients(version: str) -> tuple[str, ...]:
    if (
        tuple(int(part) for part in version.split("."))
        >= release_candidate.UNIFIED_CLIENT_PACKAGE_MINIMUM_VERSION
    ):
        return ("stack",)
    clients = ["evidence", "relay"]
    if (
        tuple(int(part) for part in version.split("."))
        >= release_candidate.DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION
    ):
        clients.insert(0, "discovery")
    return tuple(clients)


def run_text(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise PublicReleaseError(f"cannot run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise PublicReleaseError(
            f"{' '.join(command)} failed: {detail}"
        )
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_binary_smoke(path: Path) -> str:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    try:
        result = subprocess.run(
            [str(path), "--version"],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise PublicReleaseError(f"cannot smoke {path.name}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise PublicReleaseError(f"{path.name} --version failed: {detail}")
    return result.stdout.strip()


def parse_sha256sums(body: str) -> dict[str, str]:
    checksums: dict[str, str] = {}
    lines = body.splitlines()
    if not lines:
        raise PublicReleaseError("SHA256SUMS is empty")
    for number, line in enumerate(lines, start=1):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise PublicReleaseError(f"SHA256SUMS line {number} is not canonical")
        digest, name = match.groups()
        if name in {".", ".."} or Path(name).name != name:
            raise PublicReleaseError(
                f"SHA256SUMS line {number} names a nonlocal asset"
            )
        if name in checksums:
            raise PublicReleaseError(f"SHA256SUMS repeats asset {name}")
        checksums[name] = digest
    return checksums


def validate_release_metadata(
    release: Any,
    latest: Any,
    *,
    tag: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(release, dict) or not isinstance(latest, dict):
        raise PublicReleaseError("GitHub release metadata is malformed")
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"]
    ):
        raise PublicReleaseError(f"GitHub Release {tag} is not a published Beta")
    if latest.get("tag_name") != tag:
        raise PublicReleaseError(
            f"GitHub latest release is {latest.get('tag_name')!r}, not {tag}"
        )
    assets = release.get("assets")
    if not isinstance(assets, list) or not assets:
        raise PublicReleaseError(f"GitHub Release {tag} has no assets")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise PublicReleaseError("GitHub release asset metadata is malformed")
        name = asset.get("name")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise PublicReleaseError("GitHub release asset has an invalid name")
        if name in by_name:
            raise PublicReleaseError(f"GitHub Release repeats asset {name}")
        digest = asset.get("digest")
        size = asset.get("size")
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
        ):
            raise PublicReleaseError(f"GitHub asset {name} has no exact digest and size")
        by_name[name] = asset
    return by_name


def resolve_annotated_tag(repo: Path, tag: str) -> str:
    output = run_text(
        [
            "git",
            "ls-remote",
            "--tags",
            "origin",
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ],
        cwd=repo,
    )
    refs: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and HEX40.fullmatch(fields[0]):
            refs[fields[1]] = fields[0]
    tag_object = refs.get(f"refs/tags/{tag}")
    source = refs.get(f"refs/tags/{tag}^{{}}")
    if tag_object is None or source is None or tag_object == source:
        raise PublicReleaseError(f"{tag} is not one immutable annotated source tag")
    return source


def verify_downloaded_assets(
    directory: Path,
    assets: dict[str, dict[str, Any]],
    *,
    tag: str,
) -> tuple[dict[str, str], str]:
    downloaded = {
        path.name: path
        for path in directory.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if set(downloaded) != set(assets):
        raise PublicReleaseError(
            "downloaded release asset inventory differs from GitHub metadata: "
            f"missing={sorted(set(assets) - set(downloaded))!r} "
            f"unexpected={sorted(set(downloaded) - set(assets))!r}"
        )
    actual_digests: dict[str, str] = {}
    for name, path in sorted(downloaded.items()):
        expected = assets[name]
        if path.stat().st_size != expected["size"]:
            raise PublicReleaseError(f"GitHub asset {name} has the wrong downloaded size")
        actual = sha256_file(path)
        if expected["digest"] != f"sha256:{actual}":
            raise PublicReleaseError(f"GitHub asset {name} digest does not match its bytes")
        actual_digests[name] = actual

    checksum_name = "SHA256SUMS"
    bundle_name = f"registry-stack-{tag}-SHA256SUMS.sigstore.json"
    for required in (checksum_name, bundle_name):
        if required not in downloaded:
            raise PublicReleaseError(f"GitHub Release is missing {required}")
    checksums = parse_sha256sums(
        downloaded[checksum_name].read_text(encoding="utf-8")
    )
    expected_closure = set(downloaded) - {checksum_name, bundle_name}
    if set(checksums) != expected_closure:
        raise PublicReleaseError(
            "SHA256SUMS closure differs from downloadable payloads: "
            f"missing={sorted(expected_closure - set(checksums))!r} "
            f"unexpected={sorted(set(checksums) - expected_closure)!r}"
        )
    for name, expected in checksums.items():
        if actual_digests[name] != expected:
            raise PublicReleaseError(f"SHA256SUMS rejects asset {name}")
    return checksums, bundle_name


def validate_release_manifest(
    document: Any,
    *,
    repository: str,
    tag: str,
    source_sha: str,
    checksums: dict[str, str],
    assets: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    if not isinstance(document, dict):
        raise PublicReleaseError("public candidate manifest must be an object")
    validity = document.get("validity")
    created_at = validity.get("created_at") if isinstance(validity, dict) else None
    if not isinstance(created_at, str):
        raise PublicReleaseError("public candidate manifest has no creation timestamp")
    try:
        validation_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        release_candidate.validate_candidate_manifest(
            document,
            expected_source_sha=source_sha,
            expected_version=tag.removeprefix("v"),
            now=validation_time,
        )
    except (ValueError, release_candidate.CandidateError) as exc:
        raise PublicReleaseError(f"public candidate manifest is invalid: {exc}") from exc

    release = document.get("release")
    workflow = document.get("workflow")
    images = document.get("images")
    if not isinstance(release, dict) or not isinstance(workflow, dict):
        raise PublicReleaseError("public candidate manifest has no release workflow binding")
    if (
        release.get("tag") != tag
        or release.get("version") != tag.removeprefix("v")
        or release.get("source_sha") != source_sha
        or document.get("repository") != repository
    ):
        raise PublicReleaseError("public candidate manifest does not match tag identity")
    if (
        workflow.get("path") != ".github/workflows/release-candidate.yml"
        or not isinstance(workflow.get("revision"), str)
        or HEX40.fullmatch(workflow["revision"]) is None
        or workflow["revision"] != source_sha
        or not isinstance(workflow.get("run_id"), int)
        or isinstance(workflow.get("run_id"), bool)
        or workflow["run_id"] < 1
    ):
        raise PublicReleaseError("public candidate manifest has an invalid workflow identity")

    manifest_name = f"registry-stack-{tag}-release-manifest.json"
    payloads = document.get("payloads")
    payload_records = {
        payload.get("name"): payload
        for payload in payloads
        if isinstance(payloads, list)
        and isinstance(payload, dict)
        and isinstance(payload.get("name"), str)
    } if isinstance(payloads, list) else {}
    expected_payloads = set(checksums) - {manifest_name}
    if set(payload_records) != expected_payloads:
        raise PublicReleaseError(
            "public candidate manifest payload closure differs from release assets: "
            f"missing={sorted(expected_payloads - set(payload_records))!r} "
            f"unexpected={sorted(set(payload_records) - expected_payloads)!r}"
        )
    for name, payload in payload_records.items():
        if (
            name not in assets
            or payload.get("sha256") != checksums[name]
            or payload.get("size") != assets[name]["size"]
        ):
            raise PublicReleaseError(
                f"public candidate manifest payload {name} differs from release bytes"
            )

    if not isinstance(images, list) or not images:
        raise PublicReleaseError("public candidate manifest has no final image inventory")
    verified: list[dict[str, str]] = []
    final_refs: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            raise PublicReleaseError("public candidate image entry is malformed")
        digest = image.get("digest")
        final_ref = image.get("final_ref")
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(final_ref, str)
            or not final_ref.endswith(f":{tag}")
            or final_ref in final_refs
        ):
            raise PublicReleaseError("public candidate image identity is invalid")
        final_refs.add(final_ref)
        verified.append({"digest": digest, "final_ref": final_ref})
    return verified


def smoke_asset_name(tag: str) -> str:
    machine = platform.machine().lower()
    if os.sys.platform == "darwin" and machine in {"arm64", "aarch64"}:
        platform_name = "macos-arm64"
    elif os.sys.platform.startswith("linux") and machine in {"x86_64", "amd64"}:
        platform_name = "linux-amd64"
    elif os.sys.platform.startswith("linux") and machine in {"arm64", "aarch64"}:
        platform_name = "linux-arm64"
    else:
        raise PublicReleaseError(
            f"no maintained public binary smoke for {os.sys.platform}/{machine}"
        )
    return f"evidence-{tag}-{platform_name}"


def verify_client_registries(directory: Path, version: str) -> int:
    package_count = 0
    try:
        for client in client_registry_clients(version):
            client_registry.validate_distribution(directory, version, client)
            npm_packages = client_registry.npm_tarballs(directory, version, client)
            for tarball in npm_packages:
                state = client_registry.npm_registry_state(
                    tarball,
                    client_registry.npm_metadata(tarball),
                )
                if state != "present":
                    raise client_registry.ClientRegistryError(
                        f"npm package is not public: {tarball.name}"
                    )
            wheels = client_registry.wheel_paths(directory, version, client)
            state = client_registry.pypi_registry_state(
                wheels,
                version,
                client_registry.pypi_metadata(version, client),
                client,
            )
            if state != "present":
                raise client_registry.ClientRegistryError(
                    f"PyPI {client} release does not contain the complete wheel set"
                )
            package_count += len(npm_packages) + len(wheels)
    except client_registry.ClientRegistryError as exc:
        raise PublicReleaseError(
            f"client registry verification failed: {exc}"
        ) from exc
    return package_count


def verify(
    *,
    repo: Path,
    repository: str,
    tag: str,
) -> dict[str, Any]:
    if TAG_PATTERN.fullmatch(tag) is None:
        raise PublicReleaseError("tag must be canonical v<major>.<minor>.<patch> text")
    for tool in ("gh", "git", "cosign", "docker"):
        if shutil.which(tool) is None:
            raise PublicReleaseError(f"public verification requires {tool} on PATH")

    source_sha = resolve_annotated_tag(repo, tag)
    release = json.loads(
        run_text(["gh", "api", f"repos/{repository}/releases/tags/{tag}"])
    )
    latest = json.loads(
        run_text(["gh", "api", f"repos/{repository}/releases/latest"])
    )
    assets = validate_release_metadata(release, latest, tag=tag)
    manifest_name = f"registry-stack-{tag}-release-manifest.json"
    if manifest_name not in assets:
        raise PublicReleaseError(f"GitHub Release is missing {manifest_name}")

    client_registry_package_count = 0
    with tempfile.TemporaryDirectory(prefix="registry-public-release-") as temporary:
        directory = Path(temporary)
        run_text(
            [
                "gh",
                "release",
                "download",
                tag,
                "--repo",
                repository,
                "--dir",
                str(directory),
            ]
        )
        checksums, bundle_name = verify_downloaded_assets(
            directory,
            assets,
            tag=tag,
        )
        identity = (
            f"https://github.com/{repository}/.github/workflows/"
            "release.yml@refs/heads/main"
        )
        run_text(
            [
                "cosign",
                "verify-blob",
                str(directory / "SHA256SUMS"),
                "--bundle",
                str(directory / bundle_name),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                SIGNER_ISSUER,
            ]
        )
        manifest_path = directory / manifest_name
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PublicReleaseError(f"cannot read {manifest_name}: {exc}") from exc
        images = validate_release_manifest(
            manifest,
            repository=repository,
            tag=tag,
            source_sha=source_sha,
            checksums=checksums,
            assets=assets,
        )
        manifest_sha256 = sha256_file(manifest_path)
        marker = f"registry-stack-release-candidate-v2 manifest_sha256:{manifest_sha256}"
        if marker not in str(release.get("body", "")):
            raise PublicReleaseError("GitHub Release body lacks the exact manifest binding")
        for image in images:
            manifest = json.loads(
                run_text(
                    [
                        "docker",
                        "buildx",
                        "imagetools",
                        "inspect",
                        image["final_ref"],
                        "--format",
                        "{{json .Manifest}}",
                    ]
                )
            )
            observed = manifest.get("digest") if isinstance(manifest, dict) else None
            if observed != image["digest"]:
                raise PublicReleaseError(
                    f"public image {image['final_ref']} resolves to {observed}, "
                    f"not {image['digest']}"
                )

        smoke_name = smoke_asset_name(tag)
        smoke_path = directory / smoke_name
        if smoke_name not in checksums or not smoke_path.is_file():
            raise PublicReleaseError(f"GitHub Release is missing smoke asset {smoke_name}")
        smoke_path.chmod(smoke_path.stat().st_mode | stat.S_IXUSR)
        observed_version = run_binary_smoke(smoke_path)
        expected_version = f"evidence {tag.removeprefix('v')}"
        if observed_version != expected_version:
            raise PublicReleaseError(
                f"{smoke_name} reports {observed_version!r}, not {expected_version!r}"
            )
        version = tag.removeprefix("v")
        if version_uses_client_registries(version):
            client_registry_package_count = verify_client_registries(
                directory,
                version,
            )

    return {
        "tag": tag,
        "source_sha": source_sha,
        "release_url": release.get("html_url"),
        "asset_count": len(assets),
        "checksum_payload_count": len(checksums),
        "image_count": len(images),
        "smoke_asset": smoke_name,
        "client_registry_package_count": client_registry_package_count,
        "status": "verified",
    }
