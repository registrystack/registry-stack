#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Resolve one immutable Registry Stack candidate for conformance evidence."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_DIR = REPO_ROOT / "release" / "manifests"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
IMAGE_REPOSITORIES = {
    "registry-notary": "ghcr.io/registrystack/registry-notary",
    "registry-relay": "ghcr.io/registrystack/registry-relay",
}
CAPSULE_REPOSITORY = "registrystack/registry-stack"
SLSA_SOURCE_URI = "github.com/registrystack/registry-stack"
RELEASE_WORKFLOW = (
    "https://github.com/registrystack/registry-stack/.github/workflows/"
    "release.yml@refs/tags/{tag}"
)


class CandidateError(RuntimeError):
    """Candidate inputs are mutable, malformed, or disagree."""


def git_output(arguments: list[str], max_bytes: int) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise CandidateError("candidate Git binding could not be verified") from None
    if result.returncode != 0 or len(result.stdout) > max_bytes:
        raise CandidateError("candidate Git binding could not be verified")
    return result.stdout


def verify_git_binding(
    stack: dict[str, Any],
    lock: dict[str, Any],
    manifest_path: Path,
    manifest_bytes: bytes,
) -> None:
    tag_target = lock["tag_target"]
    tag_ref = f"refs/tags/{stack['source_tag']}^{{commit}}"
    resolved = git_output(["rev-parse", "--verify", tag_ref], 41)
    if resolved.strip() != tag_target.encode("ascii"):
        raise CandidateError("candidate Git binding could not be verified")
    git_output(
        ["merge-base", "--is-ancestor", stack["source_ref"], tag_target],
        0,
    )
    relative_path = manifest_path.relative_to(REPO_ROOT).as_posix()
    object_name = f"{tag_target}:{relative_path}"
    try:
        object_size = int(git_output(["cat-file", "-s", object_name], 16))
    except ValueError:
        raise CandidateError("candidate Git binding could not be verified") from None
    if not 0 < object_size <= 1024 * 1024:
        raise CandidateError("candidate Git binding could not be verified")
    tagged_manifest_bytes = git_output(["show", object_name], object_size)
    if len(tagged_manifest_bytes) != object_size:
        raise CandidateError("candidate Git binding could not be verified")
    verify_closeout_manifest_transition(
        stack, manifest_bytes, tagged_manifest_bytes
    )


def verify_closeout_manifest_transition(
    stack: dict[str, Any],
    manifest_bytes: bytes,
    tagged_manifest_bytes: bytes,
) -> None:
    if manifest_bytes == tagged_manifest_bytes:
        return
    released_line = b"  status: released\n"
    candidate_line = b"  status: release-candidate\n"
    if (
        stack.get("status") != "released"
        or manifest_bytes.count(released_line) != 1
        or tagged_manifest_bytes.count(candidate_line) != 1
        or manifest_bytes.replace(released_line, candidate_line, 1)
        != tagged_manifest_bytes
    ):
        raise CandidateError("candidate Git binding could not be verified")
    try:
        tagged_manifest = yaml.safe_load(tagged_manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise CandidateError("candidate Git binding could not be verified") from None
    tagged_stack = (
        tagged_manifest.get("stack")
        if isinstance(tagged_manifest, dict)
        else None
    )
    if (
        not isinstance(tagged_stack, dict)
        or tagged_stack.get("status") != "release-candidate"
    ):
        raise CandidateError("candidate Git binding could not be verified")


def require_regular_file(path: Path, *, max_bytes: int) -> Path:
    path = path.expanduser()
    try:
        info = path.lstat()
    except OSError as exc:
        raise CandidateError(f"required file is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise CandidateError(f"required path must be a regular file: {path}")
    if not 0 < info.st_size <= max_bytes:
        raise CandidateError(f"required file has an invalid size: {path}")
    return path.resolve()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_checksums(path: Path) -> dict[str, str]:
    path = require_regular_file(path, max_bytes=1024 * 1024)
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  \*?([^/\x00]+)", line)
        if match is None:
            raise CandidateError(
                f"SHA256SUMS line {line_number} has an unsafe format"
            )
        digest, name = match.groups()
        if name in checksums:
            raise CandidateError(f"SHA256SUMS contains duplicate entry {name}")
        checksums[name] = digest
    return checksums


def find_named(items: Any, name: str, label: str) -> dict[str, Any]:
    if not isinstance(items, list) or any(
        not isinstance(item, dict) for item in items
    ):
        raise CandidateError(f"release capsule {label} must be an object array")
    matches = [item for item in items if item.get("name") == name]
    if len(matches) != 1:
        raise CandidateError(
            f"release capsule {label} must contain exactly one {name}"
        )
    return matches[0]


def run_authenticity_command(command: list[str]) -> None:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise CandidateError(
            f"candidate authenticity command failed ({command[0]}){suffix}"
        )


def verify_release_authenticity(
    asset_dir: Path,
    tag: str,
    subjects: tuple[str, ...],
    *,
    command_runner: Callable[[list[str]], None] = run_authenticity_command,
) -> None:
    cosign = shutil.which("cosign")
    slsa = shutil.which("slsa-verifier")
    if not cosign or not slsa:
        missing = [
            name
            for name, path in (("cosign", cosign), ("slsa-verifier", slsa))
            if not path
        ]
        raise CandidateError(
            "candidate authenticity verification requires installed "
            + " and ".join(missing)
        )
    provenance = require_regular_file(
        asset_dir / f"registry-stack-{tag}-release-provenance.intoto.jsonl",
        max_bytes=128 * 1024 * 1024,
    )
    identity = RELEASE_WORKFLOW.format(tag=tag)
    for name in subjects:
        subject = require_regular_file(
            asset_dir / name, max_bytes=128 * 1024 * 1024
        )
        signature = require_regular_file(
            asset_dir / f"{name}.sig", max_bytes=1024 * 1024
        )
        certificate = require_regular_file(
            asset_dir / f"{name}.pem", max_bytes=1024 * 1024
        )
        command_runner(
            [
                cosign,
                "verify-blob",
                str(subject),
                "--signature",
                str(signature),
                "--certificate",
                str(certificate),
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-identity",
                identity,
            ]
        )
        command_runner(
            [
                slsa,
                "verify-artifact",
                str(subject),
                "--provenance-path",
                str(provenance),
                "--source-uri",
                SLSA_SOURCE_URI,
                "--source-tag",
                tag,
            ]
        )


def verify_release_asset_binding(
    stack: dict[str, Any],
    lock: dict[str, Any],
    image_lock_path: Path,
    image_lock_sha256: str,
) -> str:
    tag = lock["release_tag"]
    asset_dir = image_lock_path.parent
    lock_name = image_lock_path.name
    capsule_name = f"registry-stack-{tag}-release-capsule.json"
    capsule_path = require_regular_file(
        asset_dir / capsule_name, max_bytes=8 * 1024 * 1024
    )
    checksums = parse_checksums(asset_dir / "SHA256SUMS")
    if checksums.get(lock_name) != image_lock_sha256:
        raise CandidateError(
            "release image lock does not match its SHA256SUMS entry"
        )
    try:
        capsule = json.loads(capsule_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"release capsule is not valid JSON: {exc}") from exc
    if (
        not isinstance(capsule, dict)
        or capsule.get("release_tag") != tag
        or capsule.get("version") != stack["version"]
        or capsule.get("repository") != CAPSULE_REPOSITORY
    ):
        raise CandidateError("release capsule identity does not match the candidate")
    source = capsule.get("source")
    if (
        not isinstance(source, dict)
        or source.get("source_tag") != tag
        or source.get("source_ref") != lock["manifest_source_ref"]
        or source.get("source_commit") != lock["tag_target"]
    ):
        raise CandidateError(
            "release capsule source lineage does not match the image lock"
        )
    lineage = source.get("lineage")
    lineage_keys = {
        "tag_matches_source_tag",
        "head_matches_tag_target",
        "source_ref_ancestor_or_equal",
        "default_branch_reachable",
    }
    if (
        not isinstance(lineage, dict)
        or set(lineage) != lineage_keys
        or any(value is not True for value in lineage.values())
    ):
        raise CandidateError("release capsule does not prove source lineage")
    lock_entry = find_named(capsule.get("release_files"), lock_name, "release_files")
    if (
        lock_entry.get("kind") != "registryctl-release-image-lock"
        or lock_entry.get("sha256") != image_lock_sha256
    ):
        raise CandidateError(
            "release capsule image-lock classification or hash is invalid"
        )
    capsule_images = capsule.get("images")
    if (
        not isinstance(capsule_images, list)
        or len(capsule_images) != len(IMAGE_REPOSITORIES)
        or {
            item.get("name")
            for item in capsule_images
            if isinstance(item, dict)
        }
        != set(IMAGE_REPOSITORIES)
    ):
        raise CandidateError(
            "release capsule must contain exactly the two product images"
        )
    for component in IMAGE_REPOSITORIES:
        if (
            find_named(capsule_images, component, "images").get("digest_ref")
            != lock["images"][component]
        ):
            raise CandidateError(
                "release capsule images do not match the release image lock"
            )

    capsule_sha256 = sha256(capsule_path)
    verify_release_authenticity(asset_dir, tag, (lock_name, capsule_name))
    if sha256(image_lock_path) != image_lock_sha256 or sha256(
        capsule_path
    ) != capsule_sha256:
        raise CandidateError("a signed candidate subject changed during verification")
    return capsule_sha256


def load_candidate(
    manifest_path: Path,
    image_lock_path: Path,
    *,
    topology: str = "release-owned",
    solmara_source_ref: str | None = None,
) -> dict[str, Any]:
    manifest_path = require_regular_file(manifest_path, max_bytes=1024 * 1024)
    image_lock_path = require_regular_file(image_lock_path, max_bytes=1024 * 1024)
    if manifest_path.parent != MANIFEST_DIR.resolve():
        raise CandidateError(f"release manifest must be under {MANIFEST_DIR}")
    try:
        manifest_bytes = manifest_path.read_bytes()
        image_lock_bytes = image_lock_path.read_bytes()
        manifest = yaml.safe_load(manifest_bytes.decode("utf-8"))
        lock = json.loads(image_lock_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise CandidateError(
            f"candidate input is not valid YAML or JSON: {exc}"
        ) from exc
    stack = manifest.get("stack") if isinstance(manifest, dict) else None
    if not isinstance(stack, dict):
        raise CandidateError("release manifest is missing stack metadata")
    release_id = stack.get("release")
    version = stack.get("version")
    source_ref = stack.get("source_ref")
    if (
        not isinstance(release_id, str)
        or RELEASE_ID.fullmatch(release_id) is None
        or manifest_path.name != f"registry-stack-{release_id}.yaml"
    ):
        raise CandidateError("release manifest ID and filename disagree")
    if (
        not isinstance(version, str)
        or stack.get("source_repo") != "registrystack/registry-stack"
        or not isinstance(source_ref, str)
        or COMMIT.fullmatch(source_ref) is None
        or stack.get("source_tag") != f"v{version}"
        or stack.get("status") not in {"release-candidate", "released"}
    ):
        raise CandidateError(
            "release manifest does not identify one immutable candidate"
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or any(
        artifacts.get(component) != version for component in IMAGE_REPOSITORIES
    ):
        raise CandidateError(
            "release manifest product artifacts do not match its version"
        )

    if (
        not isinstance(lock, dict)
        or image_lock_path.name != f"registryctl-v{version}-image-lock.json"
        or set(lock)
        != {
            "schema_version",
            "release_tag",
            "manifest_source_ref",
            "tag_target",
            "platform",
            "images",
        }
        or lock.get("schema_version") != "registryctl.release_image_lock.v1"
        or lock.get("release_tag") != stack["source_tag"]
        or lock.get("manifest_source_ref") != source_ref
        or not isinstance(lock.get("tag_target"), str)
        or COMMIT.fullmatch(lock["tag_target"]) is None
        or lock.get("platform") != "linux/amd64"
    ):
        raise CandidateError("release image lock does not match the manifest")
    images = lock.get("images")
    if not isinstance(images, dict) or set(images) != set(IMAGE_REPOSITORIES):
        raise CandidateError("release image lock must contain only Notary and Relay")
    for component, repository in IMAGE_REPOSITORIES.items():
        value = images[component]
        if (
            not isinstance(value, str)
            or re.fullmatch(rf"{re.escape(repository)}@sha256:[0-9a-f]{{64}}", value)
            is None
        ):
            raise CandidateError(f"{component} is not pinned to its exact digest")
    verify_git_binding(stack, lock, manifest_path, manifest_bytes)
    image_lock_sha256 = hashlib.sha256(image_lock_bytes).hexdigest()
    capsule_sha256 = verify_release_asset_binding(
        stack, lock, image_lock_path, image_lock_sha256
    )

    if topology == "solmara":
        if (
            not isinstance(solmara_source_ref, str)
            or COMMIT.fullmatch(solmara_source_ref) is None
        ):
            raise CandidateError("Solmara topology requires one exact source commit")
    elif topology != "release-owned" or solmara_source_ref is not None:
        raise CandidateError("Solmara must be explicitly selected and commit-pinned")
    return {
        "release_id": release_id,
        "version": version,
        "source_repo": stack["source_repo"],
        "source_ref": source_ref,
        "source_tag": stack["source_tag"],
        "tag_target": lock["tag_target"],
        "manifest_path": manifest_path.relative_to(REPO_ROOT).as_posix(),
        "manifest_sha256": f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}",
        "image_lock_sha256": f"sha256:{image_lock_sha256}",
        "release_capsule_sha256": f"sha256:{capsule_sha256}",
        "notary_image": images["registry-notary"],
        "relay_image": images["registry-relay"],
        "topology": topology,
        "solmara_source_ref": solmara_source_ref,
    }
