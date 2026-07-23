#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Resolve one immutable Registry Stack candidate for conformance evidence."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_DIR = REPO_ROOT / "release" / "manifests"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
IMAGE_REPOSITORIES = {
    "registry-notary": "ghcr.io/registrystack/registry-notary",
    "registry-relay": "ghcr.io/registrystack/registry-relay",
}


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
    if object_size != len(manifest_bytes):
        raise CandidateError("candidate Git binding could not be verified")
    if git_output(["show", object_name], object_size) != manifest_bytes:
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
        "image_lock_sha256": f"sha256:{hashlib.sha256(image_lock_bytes).hexdigest()}",
        "notary_image": images["registry-notary"],
        "relay_image": images["registry-relay"],
        "topology": topology,
        "solmara_source_ref": solmara_source_ref,
    }
