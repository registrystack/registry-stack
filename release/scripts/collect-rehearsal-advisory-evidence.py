#!/usr/bin/env python3
"""Collect review-only image evidence from release-rehearsal build products."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[2]
IMAGE_NAMES = frozenset({"breg", "casework", "discovery", "evidence", "relay"})
SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
SOURCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
OCI_LABELS = {
    "org.registrystack.runtime.uid": "65532",
    "org.registrystack.runtime.gid": "65532",
}


class EvidenceError(RuntimeError):
    """Advisory evidence could not be collected or verified exactly."""


def run_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    stdout_path: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    output: TextIO | int
    if stdout_path is None:
        output = subprocess.PIPE
    else:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        output = stdout_path.open("w", encoding="utf-8")
    try:
        return subprocess.run(
            list(command),
            check=check,
            env=dict(env) if env is not None else None,
            stdout=output,
            stderr=subprocess.PIPE,
            text=True,
        )
    finally:
        if stdout_path is not None:
            output.close()


def require_identity(version: str, source: str, revision: str) -> None:
    if SEMVER_RE.fullmatch(version) is None:
        raise EvidenceError("version must be canonical semantic version text")
    if SOURCE_RE.fullmatch(source) is None:
        raise EvidenceError("source must be a canonical GitHub repository URL")
    if REVISION_RE.fullmatch(revision) is None:
        raise EvidenceError("revision must be a lowercase 40-character Git SHA")


def parse_roster(output: str) -> tuple[str, ...]:
    names = tuple(output.split())
    if not names:
        raise EvidenceError("release image roster is empty")
    if len(names) != len(set(names)):
        raise EvidenceError("release image roster contains duplicate names")
    unsupported = sorted(set(names) - IMAGE_NAMES)
    if unsupported:
        raise EvidenceError(
            f"release image roster contains unsupported names: {unsupported}"
        )
    return names


def load_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(
            f"could not read {description} at {path}: {error}"
        ) from error
    if not isinstance(value, dict) or not value:
        raise EvidenceError(f"{description} at {path} must be a nonempty JSON object")
    return value


def validate_oci_config(
    path: Path,
    *,
    source: str,
    revision: str,
    version: str,
) -> tuple[str, ...]:
    document = load_json_object(path, "OCI config")
    if document.get("architecture") != "amd64" or document.get("os") != "linux":
        raise EvidenceError(f"OCI config at {path} must describe linux/amd64")
    rootfs = document.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        raise EvidenceError(f"OCI config at {path} must contain a layers rootfs")
    diff_ids = rootfs.get("diff_ids")
    if (
        not isinstance(diff_ids, list)
        or not diff_ids
        or len(diff_ids) != len(set(diff_ids))
        or any(
            not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
            for value in diff_ids
        )
    ):
        raise EvidenceError(f"OCI config at {path} must contain unique SHA-256 DiffIDs")
    config = document.get("config")
    if not isinstance(config, dict) or config.get("User") != "65532":
        raise EvidenceError(f"OCI config at {path} must retain runtime user 65532")
    labels = config.get("Labels")
    expected = {
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.version": version,
        **OCI_LABELS,
    }
    if not isinstance(labels, dict):
        raise EvidenceError(f"OCI config at {path} must contain identity labels")
    for label, wanted in expected.items():
        if labels.get(label) != wanted:
            raise EvidenceError(
                f"OCI config at {path} has {label}={labels.get(label)!r}; expected {wanted!r}"
            )
    return tuple(diff_ids)


def validate_grype_database(descriptor: dict[str, Any]) -> None:
    database = descriptor.get("db")
    if not isinstance(database, dict):
        raise EvidenceError("Grype report lacks database metadata")
    status = database.get("status")
    status = status if isinstance(status, dict) else {}
    built = database.get("built") or status.get("built")
    checksum = database.get("checksum")
    if not isinstance(checksum, str) or not checksum:
        origin = status.get("from")
        if (
            not isinstance(origin, str)
            or re.search(r"checksum=sha256%3A[0-9a-fA-F]{64}", origin) is None
        ):
            raise EvidenceError("Grype report lacks database checksum metadata")
    if not isinstance(built, str):
        raise EvidenceError("Grype report lacks database build time")
    try:
        timestamp = datetime.fromisoformat(built.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("database build time must include a timezone")
        age = time.time() - timestamp.timestamp()
    except ValueError as error:
        raise EvidenceError("Grype database build time is invalid") from error
    if age < 0 or age > 259200:
        raise EvidenceError("Grype database is future-dated or older than three days")


def validate_scan(
    path: Path, *, tool: str, target_key: str, digest: str
) -> tuple[str, ...]:
    document = load_json_object(path, f"{tool} report")
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != tool.lower():
        raise EvidenceError(f"{tool} report at {path} has an invalid descriptor")
    source = document.get("source")
    target = source.get(target_key) if isinstance(source, dict) else None
    if (
        not isinstance(source, dict)
        or source.get("type") != "image"
        or not isinstance(target, dict)
    ):
        raise EvidenceError(f"{tool} report at {path} must describe an image")
    user_input = target.get("userInput")
    repo_digests = target.get("repoDigests")
    if (
        not isinstance(user_input, str)
        or user_input.rsplit("@", 1)[-1] != digest
        or not isinstance(repo_digests, list)
        or not any(
            isinstance(value, str) and value.rsplit("@", 1)[-1] == digest
            for value in repo_digests
        )
    ):
        raise EvidenceError(f"{tool} report at {path} is not bound to {digest}")
    if target.get("architecture") != "amd64" or target.get("os") != "linux":
        raise EvidenceError(
            f"{tool} report at {path} was not collected from linux/amd64 "
            "daemon metadata"
        )
    layers = target.get("layers")
    if not isinstance(layers, list) or not layers:
        raise EvidenceError(f"{tool} report at {path} must retain image layers")
    layer_ids = tuple(
        layer.get("digest") if isinstance(layer, dict) else None for layer in layers
    )
    if len(layer_ids) != len(set(layer_ids)) or any(
        not isinstance(layer_id, str) or SHA256_RE.fullmatch(layer_id) is None
        for layer_id in layer_ids
    ):
        raise EvidenceError(f"{tool} report at {path} has invalid image layers")
    if tool == "Syft":
        if not isinstance(document.get("artifacts"), list) or not isinstance(
            document.get("files"), list
        ):
            raise EvidenceError(
                f"Syft report at {path} must retain artifacts and file metadata"
            )
    else:
        if not isinstance(document.get("matches"), list):
            raise EvidenceError(
                f"Grype report at {path} must retain vulnerability matches"
            )
        validate_grype_database(descriptor)
    return layer_ids


def reject_special_files(rootfs: Path) -> None:
    for path in rootfs.rglob("*"):
        mode = path.lstat().st_mode
        if (
            stat.S_ISBLK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
        ):
            raise EvidenceError(
                f"exported rootfs contains a forbidden special file: {path}"
            )


def registry_address(container: str) -> str:
    result = run_command(["docker", "port", container, "5000/tcp"])
    address = result.stdout.strip()
    if re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", address) is None:
        raise EvidenceError(f"local registry returned an unsafe address: {address!r}")
    if int(address.rpartition(":")[2]) > 65535:
        raise EvidenceError(f"local registry returned an invalid port: {address!r}")
    return address


def wait_for_registry(address: str) -> None:
    for _ in range(30):
        result = run_command(
            ["curl", "--fail", "--silent", "--show-error", f"http://{address}/v2/"],
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise EvidenceError("local registry did not become ready")


def collect(args: argparse.Namespace) -> None:
    require_identity(args.version, args.source, args.revision)
    if re.search(r"@sha256:[0-9a-f]{64}$", args.registry_image) is None:
        raise EvidenceError("registry image must be pinned by SHA-256 digest")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.buildx_builder) is None:
        raise EvidenceError("Buildx builder name is invalid")
    if args.output.exists():
        raise EvidenceError(f"output path already exists: {args.output}")
    head = run_command(["git", "rev-parse", "HEAD"]).stdout.strip()
    if head != args.revision:
        raise EvidenceError(
            f"checked-out source is {head!r}, expected {args.revision!r}"
        )
    roster_result = run_command(
        [
            sys.executable,
            str(ROOT / "release/scripts/release_candidate.py"),
            "image-names",
            "--version",
            args.version,
        ]
    )
    names = parse_roster(roster_result.stdout)

    args.output.mkdir(parents=True)
    for directory in ("grype", "oci-config", "rootfs", "syft"):
        (args.output / directory).mkdir()
    registry_name = f"registry-stack-rehearsal-{os.getpid()}"
    registry_started = False
    daemon_refs: list[str] = []
    temporary_parent = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    try:
        with tempfile.TemporaryDirectory(
            prefix="registry-stack-rehearsal-images.", dir=temporary_parent
        ) as temporary:
            temporary_path = Path(temporary)
            run_command(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--rm",
                    "--name",
                    registry_name,
                    "--publish",
                    "127.0.0.1::5000",
                    args.registry_image,
                ]
            )
            registry_started = True
            address = registry_address(registry_name)
            wait_for_registry(address)
            run_command(["grype", "db", "update"])
            run_command(
                ["grype", "db", "status", "-o", "json"],
                stdout_path=args.output / "grype/grype-db-status.json",
            )
            load_json_object(
                args.output / "grype/grype-db-status.json", "Grype database status"
            )

            images: list[dict[str, str]] = []
            for name in names:
                layout = temporary_path / f"{name}.oci"
                metadata = temporary_path / f"{name}.metadata.json"
                image = f"rehearsal.invalid/{name}:{args.version}"
                build_env = {
                    **os.environ,
                    "RELEASE_BUILDX_BUILDER": args.buildx_builder,
                    "RELEASE_IMAGE_OCI_LAYOUT": str(layout),
                }
                run_command(
                    [
                        str(ROOT / "release/scripts/build-release-image.sh"),
                        name,
                        image,
                        args.source,
                        args.revision,
                        args.version,
                        str(metadata),
                    ],
                    env=build_env,
                )
                metadata_document = load_json_object(metadata, "BuildKit metadata")
                digest = metadata_document.get("containerimage.digest")
                if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                    raise EvidenceError(
                        f"BuildKit metadata for {name} has no exact image digest"
                    )
                run_command(
                    [
                        sys.executable,
                        str(ROOT / "release/scripts/check-release-image-oci-labels.py"),
                        f"oci-layout://{layout}",
                        "--source",
                        args.source,
                        "--revision",
                        args.revision,
                        "--version",
                        args.version,
                    ]
                )
                tag_ref = f"{address}/{name}:review"
                run_command(
                    [
                        "oras",
                        "cp",
                        "--from-oci-layout",
                        "--to-plain-http",
                        f"{layout}@{digest}",
                        tag_ref,
                    ]
                )
                observed = run_command(
                    ["crane", "digest", "--insecure", tag_ref]
                ).stdout.strip()
                if observed != digest:
                    raise EvidenceError(
                        f"local registry digest for {name} is {observed!r}, expected {digest!r}"
                    )
                digest_ref = f"{address}/{name}@{digest}"
                run_command(["docker", "pull", "--platform", "linux/amd64", digest_ref])
                daemon_refs.append(digest_ref)
                repo_digests = json.loads(
                    run_command(
                        [
                            "docker",
                            "image",
                            "inspect",
                            "--format",
                            "{{json .RepoDigests}}",
                            digest_ref,
                        ]
                    ).stdout
                )
                if not isinstance(repo_digests, list) or digest_ref not in repo_digests:
                    raise EvidenceError(
                        f"Docker daemon did not retain exact image {digest_ref}"
                    )
                config_path = args.output / f"oci-config/{name}.json"
                run_command(
                    ["crane", "config", "--insecure", digest_ref],
                    stdout_path=config_path,
                )
                config_layers = validate_oci_config(
                    config_path,
                    source=args.source,
                    revision=args.revision,
                    version=args.version,
                )
                syft_path = args.output / f"syft/{name}.syft.json"
                scan_env = {
                    **os.environ,
                    "SYFT_FILE_METADATA_SELECTION": "all",
                    "SYFT_FILE_METADATA_DIGESTS": "sha256",
                }
                run_command(
                    ["syft", f"docker:{digest_ref}", "-o", f"syft-json={syft_path}"],
                    env=scan_env,
                )
                grype_path = args.output / f"grype/{name}.grype.json"
                run_command(
                    ["grype", f"docker:{digest_ref}", "-o", "json"],
                    stdout_path=grype_path,
                )
                syft_layers = validate_scan(
                    syft_path, tool="Syft", target_key="metadata", digest=digest
                )
                grype_layers = validate_scan(
                    grype_path, tool="Grype", target_key="target", digest=digest
                )
                if syft_layers != grype_layers or syft_layers != config_layers:
                    raise EvidenceError(
                        f"OCI config, Syft, and Grype evidence for {name} have "
                        "different image layers"
                    )

                rootfs = temporary_path / f"{name}.rootfs"
                rootfs.mkdir()
                rootfs_tar = args.output / f"rootfs/{name}.tar"
                run_command(
                    ["crane", "export", "--insecure", digest_ref, str(rootfs_tar)]
                )
                run_command(
                    [
                        "tar",
                        "--extract",
                        f"--file={rootfs_tar}",
                        f"--directory={rootfs}",
                        "--no-same-owner",
                        "--no-same-permissions",
                    ]
                )
                reject_special_files(rootfs)
                images.append({"name": name, "digest": digest})

            manifest = {
                "schema_version": "registry-stack.rehearsal-advisory-evidence.v1",
                "purpose": "review_only",
                "publication_eligible": False,
                "advisory_accepted": False,
                "version": args.version,
                "source": args.source,
                "revision": args.revision,
                "images": images,
            }
            (args.output / "collection.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    finally:
        for image_ref in daemon_refs:
            run_command(["docker", "image", "rm", "--force", image_ref], check=False)
        if registry_started:
            run_command(["docker", "rm", "--force", registry_name], check=False)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--registry-image", required=True)
    parser.add_argument("--buildx-builder", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        collect(parse_args(argv))
    except (
        EvidenceError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        print(f"advisory evidence collection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
