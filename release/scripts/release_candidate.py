#!/usr/bin/env python3
"""Create and verify current RegistryStack release-candidate manifests."""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import hashlib
import json
import re
import stat
import sys
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


V2_SCHEMA_VERSION = "registry-stack.release-candidate.v2"
TAG_BINDING_HEADER = "registry-stack-release-candidate-v2"
REPOSITORY = "registrystack/registry-stack"
WORKFLOW_PATH = ".github/workflows/release-candidate.yml"
CANARY_WORKFLOW_PATH = ".github/workflows/release-canary.yml"
WORKFLOW_REF = "refs/heads/main"
V2_MAX_PROMOTION_AGE = timedelta(days=7)
MAX_CANARY_AGE = timedelta(hours=24)
MAX_RETENTION = timedelta(days=7)
GRYPE_VERSION = "0.114.0"
GRYPE_LINUX_AMD64_BINARY_SHA256 = (
    "33932517107dbb633f31756a757dc51433e520b81ba9b51f44c626ef9960b955"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RELAY_V2_RELEASE_MINIMUM_VERSION = (0, 19, 0)
RELAY_INSTALLER_MINIMUM_VERSION = (0, 19, 1)
DOCS_RELEASE_RESUMPTION_VERSION = (0, 19, 1)
RELAY_CLIENT_PACKAGE_MINIMUM_VERSION = (0, 19, 1)
OFFICIAL_RUNTIME_IMAGE_MINIMUM_VERSION = (0, 21, 0)
HISTORICAL_RUNTIME_IMAGE_NAMES = {"relay"}
OFFICIAL_RUNTIME_IMAGE_NAMES = {"evidence", "mint", "relay"}
CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION = (0, 21, 1)
DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION = (0, 23, 0)
DISCOVERY_RUNTIME_MINIMUM_VERSION = (0, 24, 0)
DISCOVERY_RUNTIME_IMAGE_NAMES = OFFICIAL_RUNTIME_IMAGE_NAMES | {"discovery"}
BREG_RELEASE_MINIMUM_VERSION = (0, 26, 0)
BREG_RUNTIME_IMAGE_NAMES = DISCOVERY_RUNTIME_IMAGE_NAMES | {
    "breg"
}
V2_TOP_LEVEL_FIELDS = {
    "schema_version",
    "repository",
    "release",
    "workflow",
    "validity",
    "payloads",
    "images",
    "sbom",
    "scans",
    "advisory",
    "bundle",
}
DOCS_V2_TOP_LEVEL_FIELDS = V2_TOP_LEVEL_FIELDS | {"docs"}
PAYLOAD_KINDS = {
    "binary",
    "client-package",
    "installer",
    "sbom",
    "security-evidence",
}
DOCS_V2_PAYLOAD_KINDS = PAYLOAD_KINDS | {"docs"}
SECURITY_EVIDENCE_MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
SECURITY_EVIDENCE_MAX_ENTRY_SIZE = 64 * 1024 * 1024
SECURITY_EVIDENCE_MAX_TOTAL_SIZE = 256 * 1024 * 1024
SECURITY_EVIDENCE_MAX_MEMBERS = 64
SECURITY_EVIDENCE_DIRECTORIES = {
    "images",
    "image-sbom",
    "syft",
    "grype",
}
SECURITY_EVIDENCE_COMMON_REQUIRED_FILES = {
    "grype/grype-db-status.json",
    "advisory-verdict.json",
}
SECURITY_EVIDENCE_REQUIRED_FILES = SECURITY_EVIDENCE_COMMON_REQUIRED_FILES | {
    f"{directory}/{image}.{suffix}.json"
    for image in BREG_RUNTIME_IMAGE_NAMES
    for directory, suffix in (
        ("image-sbom", "spdx"),
        ("syft", "syft"),
        ("grype", "grype"),
    )
}


class CandidateError(ValueError):
    """A candidate cannot be trusted for promotion."""


def _candidate_image_names(version: str) -> set[str]:
    parsed = tuple(int(part) for part in version.split("."))
    if parsed < RELAY_V2_RELEASE_MINIMUM_VERSION:
        raise CandidateError(
            "pre-v0.19 candidates are immutable historical evidence; verify them "
            "with the corresponding release tag"
        )
    if parsed < OFFICIAL_RUNTIME_IMAGE_MINIMUM_VERSION:
        return HISTORICAL_RUNTIME_IMAGE_NAMES
    if parsed < DISCOVERY_RUNTIME_MINIMUM_VERSION:
        return OFFICIAL_RUNTIME_IMAGE_NAMES
    if parsed < BREG_RELEASE_MINIMUM_VERSION:
        return DISCOVERY_RUNTIME_IMAGE_NAMES
    return BREG_RUNTIME_IMAGE_NAMES


def _literal_string_roster(path: Path, name: str) -> set[str]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise CandidateError(f"cannot inspect {path}: {exc}") from exc
    assignments = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]
    if len(assignments) != 1:
        raise CandidateError(f"{path} must assign {name} exactly once")
    value_node = assignments[0].value
    try:
        value = ast.literal_eval(value_node)
    except (ValueError, TypeError) as exc:
        raise CandidateError(f"{path} {name} must be a literal string roster") from exc
    if not isinstance(value, (list, tuple, set)) or not all(
        isinstance(item, str) for item in value
    ):
        raise CandidateError(f"{path} {name} must be a literal string roster")
    if len(set(value)) != len(value):
        raise CandidateError(f"{path} {name} must not contain duplicates")
    return set(value)


def _supported_release_image_names(path: Path) -> set[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CandidateError(f"cannot inspect {path}: {exc}") from exc
    case = re.search(
        r'^\s*case\s+"\$\{name\}"\s+in\s*$',
        source,
        flags=re.MULTILINE,
    )
    if case is None:
        raise CandidateError(f"{path} must dispatch on the exact image name")
    end = re.search(r"^\s*esac\s*$", source[case.end() :], flags=re.MULTILINE)
    if end is None:
        raise CandidateError(f"{path} image name case is incomplete")
    body = source[case.end() : case.end() + end.start()]
    supported: set[str] = set()
    for match in re.finditer(
        r"^\s*([a-z0-9][a-z0-9_-]*(?:\|[a-z0-9][a-z0-9_-]*)*)\)\s*$",
        body,
        flags=re.MULTILINE,
    ):
        supported.update(match.group(1).split("|"))
    return supported


def _require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink():
        raise CandidateError(f"{description} must not be a symlink: {path}")
    if not path.is_file():
        raise CandidateError(f"{description} is missing: {path}")


def check_image_onboarding(
    root: Path,
    version: str,
    *,
    allow_missing_baseline: bool = False,
) -> set[str]:
    """Require every version-selected image to have complete release source state."""

    if VERSION.fullmatch(version) is None:
        raise CandidateError("version must be canonical semantic version text")
    if not root.is_dir():
        raise CandidateError(f"repository root does not exist: {root}")
    image_names = _candidate_image_names(version)
    binary_recipe_path = root / "release/scripts/build-release-binaries.sh"
    image_recipe_path = root / "release/scripts/build-release-image.sh"
    cleanup_path = root / "release/scripts/cleanup-release-candidates.py"
    _require_regular_file(binary_recipe_path, "canonical binary recipe")
    _require_regular_file(image_recipe_path, "release image recipe")
    _require_regular_file(cleanup_path, "candidate cleanup policy")
    binary_recipe = binary_recipe_path.read_text(encoding="utf-8")
    supported_image_names = _supported_release_image_names(image_recipe_path)
    candidate_packages = _literal_string_roster(cleanup_path, "CANDIDATE_PACKAGES")
    public_packages = _literal_string_roster(cleanup_path, "PUBLIC_PACKAGES")

    for image_name in sorted(image_names):
        dockerfile = root / f"release/docker/Dockerfile.{image_name}"
        _require_regular_file(dockerfile, f"{image_name} release Dockerfile")
        staging_path = re.escape(f"dist/image-bin/{image_name}")
        if re.search(
            rf"^\s*cp\b[^\n]*{staging_path}(?:\s|$)",
            binary_recipe,
            flags=re.MULTILINE,
        ) is None:
            raise CandidateError(
                f"canonical binary recipe must stage dist/image-bin/{image_name}"
            )
        if image_name not in supported_image_names:
            raise CandidateError(
                f"release image recipe does not recognize {image_name}"
            )
        baseline = (
            root / "products/relay-v2/security/advisory-baseline.json"
            if image_name == "relay"
            else root / f"release/security/{image_name}-advisory-baseline.json"
        )
        if baseline.is_symlink():
            raise CandidateError(
                f"{image_name} advisory baseline must not be a symlink: {baseline}"
            )
        if not baseline.is_file():
            if not (allow_missing_baseline and not baseline.exists()):
                raise CandidateError(
                    f"{image_name} advisory baseline is missing: {baseline}"
                )
        else:
            document = read_json(baseline)
            if not isinstance(document, dict) or document.get("version") != 4:
                raise CandidateError(
                    f"{image_name} advisory baseline must be JSON v4"
                )
            if document.get("service") != image_name:
                raise CandidateError(
                    f"{image_name} advisory baseline service must equal {image_name}"
                )
        candidate_package = f"{image_name}-candidate"
        if candidate_package not in candidate_packages:
            raise CandidateError(
                f"CANDIDATE_PACKAGES must contain {candidate_package}"
            )
        if image_name not in public_packages:
            raise CandidateError(f"PUBLIC_PACKAGES must contain {image_name}")
    return image_names


def _version_uses_release_docs(version: tuple[int, int, int]) -> bool:
    return version >= DOCS_RELEASE_RESUMPTION_VERSION


def _relay_v2_payload_inventory(version: str) -> dict[str, str]:
    tag = f"v{version}"
    version_tuple = tuple(int(part) for part in version.split("."))
    inventory = {
        f"{name}-{tag}-linux-amd64": "binary"
        for name in (
            "registry-manifest",
            "relay",
            "relayctl",
            "evidence",
            "evidencectl",
            "mint",
            "evidence-oid4vci",
        )
    }
    for platform in ("linux-arm64", "macos-arm64"):
        for name in (
            "relayctl",
            "evidence",
            "evidencectl",
            "mint",
            "evidence-oid4vci",
        ):
            inventory[f"{name}-{tag}-{platform}"] = "binary"
    for platform in ("linux-amd64-glibc", "linux-arm64-glibc", "macos-arm64"):
        inventory[f"evidence-client-node-{tag}-{platform}.tgz"] = "client-package"
    wheel_platforms = ("linux_x86_64", "linux_aarch64", "macosx_11_0_arm64")
    if version_tuple >= CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION:
        wheel_platforms = (
            "manylinux_2_17_x86_64.manylinux2014_x86_64",
            "manylinux_2_17_aarch64.manylinux2014_aarch64",
            "macosx_11_0_arm64",
        )
    for platform in wheel_platforms:
        inventory[
            f"registry_evidence_client-{version}-cp310-abi3-{platform}.whl"
        ] = "client-package"
    inventory.update(
        {
            f"evidencectl-{tag}-install.sh": "installer",
            "evidencectl-install.sh": "installer",
            f"registry-stack-{tag}.sbom.spdx.json": "sbom",
            f"registry-stack-{tag}-security-evidence.tar.gz": (
                "security-evidence"
            ),
        }
    )
    if (
        version_tuple >= RELAY_INSTALLER_MINIMUM_VERSION
    ):
        inventory[f"relay-{tag}-install.sh"] = "installer"
        inventory["relay-install.sh"] = "installer"
    if (
        version_tuple >= DOCS_RELEASE_RESUMPTION_VERSION
    ):
        inventory[f"registry-docs-{tag}.tar.gz"] = "docs"
    if (
        version_tuple >= RELAY_CLIENT_PACKAGE_MINIMUM_VERSION
    ):
        for platform in ("linux-amd64-glibc", "linux-arm64-glibc", "macos-arm64"):
            inventory[f"relay-client-node-{tag}-{platform}.tgz"] = "client-package"
        for platform in wheel_platforms:
            inventory[
                f"registry_relay_client-{version}-cp310-abi3-{platform}.whl"
            ] = "client-package"
    if (
        version_tuple >= CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION
    ):
        for client in ("evidence", "relay"):
            inventory[f"registrystack-{client}-client-{version}.tgz"] = (
                "client-package"
            )
            for platform in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
                inventory[
                    f"registrystack-{client}-client-{platform}-{version}.tgz"
                ] = "client-package"
    if version_tuple >= DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION:
        for platform in ("linux-amd64-glibc", "linux-arm64-glibc", "macos-arm64"):
            inventory[f"discovery-client-node-{tag}-{platform}.tgz"] = "client-package"
        for platform in wheel_platforms:
            inventory[
                f"registry_discovery_client-{version}-cp310-abi3-{platform}.whl"
            ] = "client-package"
        inventory[f"registrystack-discovery-client-{version}.tgz"] = "client-package"
        for platform in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            inventory[
                f"registrystack-discovery-client-{platform}-{version}.tgz"
            ] = "client-package"
    if version_tuple >= DISCOVERY_RUNTIME_MINIMUM_VERSION:
        inventory[f"discovery-{tag}-linux-amd64"] = "binary"
    if version_tuple >= BREG_RELEASE_MINIMUM_VERSION:
        for platform in ("linux-amd64", "linux-arm64", "macos-arm64"):
            inventory[f"breg-{tag}-{platform}"] = "binary"
            inventory[f"bregctl-{tag}-{platform}"] = "binary"
        inventory[f"breg-{tag}-install.sh"] = "installer"
        inventory["breg-install.sh"] = "installer"
    return inventory


def _security_evidence_required_files(
    product_image_names: Iterable[str],
) -> set[str]:
    required = set(SECURITY_EVIDENCE_COMMON_REQUIRED_FILES)
    for image in product_image_names:
        required.update(
            {
                f"image-sbom/{image}.spdx.json",
                f"syft/{image}.syft.json",
                f"grype/{image}.grype.json",
            }
        )
    return required


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"cannot read JSON {path}: {exc}") from exc


def validate_slsa_subject_set(
    provenance_path: Path,
    contract_path: Path,
) -> set[tuple[str, str]]:
    """Require the authenticated DSSE statement subjects to equal the contract."""

    contract = read_json(contract_path)
    expected: set[tuple[str, str]] = set()
    expected_names: set[str] = set()
    for index, item_value in enumerate(require_list(contract, "subject contract")):
        item = require_object(
            item_value,
            f"subject contract[{index}]",
            {"name", "sha256"},
        )
        name = require_nonempty_string(item["name"], f"subject contract[{index}].name")
        digest = require_sha256(
            item["sha256"],
            f"subject contract[{index}].sha256",
        )
        if name in expected_names:
            raise CandidateError(f"subject contract duplicates name {name!r}")
        expected_names.add(name)
        pair = (name, digest)
        expected.add(pair)
    if not expected:
        raise CandidateError("subject contract must not be empty")

    try:
        lines = provenance_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CandidateError(
            f"cannot read SLSA provenance {provenance_path}: {exc}"
        ) from exc
    actual: set[tuple[str, str]] = set()
    actual_names: set[str] = set()
    statements = 0
    for line_number, line in enumerate(lines, start=1):
        if not line:
            continue
        try:
            provenance = json.loads(line)
            if not isinstance(provenance, dict):
                raise TypeError("provenance is not an object")
            envelope = provenance.get("dsseEnvelope", provenance)
            if not isinstance(envelope, dict):
                raise TypeError("DSSE envelope is not an object")
            encoded_payload = envelope["payload"]
            if not isinstance(encoded_payload, str):
                raise TypeError("payload is not a string")
            payload = base64.b64decode(encoded_payload, validate=True)
            statement = json.loads(payload)
            subjects = statement["subject"]
            if not isinstance(subjects, list):
                raise TypeError("subject is not an array")
        except (
            binascii.Error,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            UnicodeDecodeError,
        ) as exc:
            raise CandidateError(
                f"SLSA provenance line {line_number} is not a valid DSSE statement: {exc}"
            ) from exc
        statements += 1
        for index, item_value in enumerate(subjects):
            if not isinstance(item_value, dict):
                raise CandidateError(
                    f"SLSA provenance subject {line_number}:{index} must be an object"
                )
            name = require_nonempty_string(
                item_value.get("name"),
                f"SLSA provenance subject {line_number}:{index}.name",
            )
            digest_value = item_value.get("digest")
            if not isinstance(digest_value, dict):
                raise CandidateError(
                    f"SLSA provenance subject {line_number}:{index}.digest must be an object"
                )
            digest = require_sha256(
                digest_value.get("sha256"),
                f"SLSA provenance subject {line_number}:{index}.digest.sha256",
            )
            if name in actual_names:
                raise CandidateError(
                    f"SLSA provenance duplicates subject name {name!r}"
                )
            actual_names.add(name)
            pair = (name, digest)
            actual.add(pair)
    if statements == 0:
        raise CandidateError("SLSA provenance contains no DSSE statements")
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise CandidateError(
            f"SLSA provenance subject set mismatch: missing={missing!r}, extra={extra!r}"
        )
    return actual


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise CandidateError(
            f"candidate file must be a regular non-symlink file: {path}"
        )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CandidateError(f"cannot hash candidate file {path}: {exc}") from exc
    return digest.hexdigest()


def extract_artifact_archive(
    archive: Path,
    destination: Path,
    *,
    expected_sha256: str,
) -> None:
    """Verify and safely extract one immutable Actions artifact archive."""

    require_sha256(expected_sha256, "artifact archive sha256")
    actual_sha256 = sha256_file(archive)
    if actual_sha256 != expected_sha256:
        raise CandidateError(
            "candidate artifact archive sha256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    if destination.is_symlink() or (
        destination.exists()
        and (not destination.is_dir() or any(destination.iterdir()))
    ):
        raise CandidateError(
            f"artifact extraction destination must be an empty directory: {destination}"
        )
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members:
                raise CandidateError("candidate artifact archive is empty")
            names: set[str] = set()
            for member in members:
                name = member.filename
                path = Path(name)
                if (
                    not name
                    or "\\" in name
                    or path.is_absolute()
                    or ".." in path.parts
                    or path.as_posix() != name.rstrip("/")
                ):
                    raise CandidateError(
                        f"candidate artifact archive has unsafe path {name!r}"
                    )
                canonical = name.rstrip("/")
                if canonical in names:
                    raise CandidateError(
                        f"candidate artifact archive has duplicate path {canonical!r}"
                    )
                names.add(canonical)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise CandidateError(
                        f"candidate artifact archive has non-regular entry {name!r}"
                    )
            bundle.extractall(destination)
    except (OSError, zipfile.BadZipFile) as exc:
        raise CandidateError(
            f"cannot extract candidate artifact archive: {exc}"
        ) from exc


def extract_candidate_bundle(bundle_path: Path, destination: Path) -> Path:
    """Extract a regular-file-only candidate tarball without path traversal."""

    if destination.is_symlink() or (
        destination.exists()
        and (not destination.is_dir() or any(destination.iterdir()))
    ):
        raise CandidateError(
            f"candidate bundle destination must be an empty directory: {destination}"
        )
    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    try:
        with tarfile.open(bundle_path, mode="r:gz") as archive:
            for member in archive:
                raw_name = member.name
                if raw_name == "." and member.isdir():
                    continue
                if raw_name.startswith("./"):
                    raw_name = raw_name[2:]
                name = safe_relative_path(raw_name, "candidate bundle member")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise CandidateError(
                        f"candidate bundle has non-regular entry {name!r}"
                    )
                if name in seen:
                    raise CandidateError(
                        f"candidate bundle has duplicate path {name!r}"
                    )
                seen.add(name)
                source = archive.extractfile(member)
                if source is None:
                    raise CandidateError(
                        f"candidate bundle cannot read member {name!r}"
                    )
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read())
    except (OSError, tarfile.TarError) as exc:
        raise CandidateError(f"cannot extract candidate bundle: {exc}") from exc
    if not seen:
        raise CandidateError("candidate bundle is empty")
    return destination


def validate_candidate_artifact_inventory(
    document: Any,
    *,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    """Require exactly one unexpired v2 candidate artifact for the attempt."""

    require_positive_integer(run_id, "run_id")
    require_positive_integer(run_attempt, "run_attempt")
    if not isinstance(document, dict):
        raise CandidateError("artifact metadata must be an object")
    artifacts = require_list(document.get("artifacts"), "artifact metadata.artifacts")
    expected_name = f"registry-stack-release-candidate-{run_id}-{run_attempt}"
    matching: list[dict[str, Any]] = []
    suffix = f"-{run_id}-{run_attempt}"
    for index, value in enumerate(artifacts):
        label = f"artifact metadata.artifacts[{index}]"
        if not isinstance(value, dict):
            raise CandidateError(f"{label} must be an object")
        name = value.get("name")
        if not isinstance(name, str):
            raise CandidateError(f"{label}.name must be text")
        if name == expected_name:
            matching.append(value)
        elif name.startswith("registry-stack-release-candidate-") and name.endswith(
            suffix
        ):
            raise CandidateError(
                f"unexpected candidate artifact in current attempt: {name!r}"
            )
    if len(matching) != 1:
        raise CandidateError(
            f"candidate attempt must contain exactly one artifact {expected_name!r}"
        )
    item = matching[0]
    if item.get("expired") is not False:
        raise CandidateError(f"candidate artifact is expired: {expected_name}")
    artifact_id = require_positive_integer(item.get("id"), "candidate artifact.id")
    digest_text = require_nonempty_string(
        item.get("digest"), "candidate artifact.digest"
    )
    if not digest_text.startswith("sha256:"):
        raise CandidateError("candidate artifact.digest must use sha256")
    archive_sha256 = require_sha256(
        digest_text.removeprefix("sha256:"), "candidate artifact.digest"
    )
    workflow_run = item.get("workflow_run")
    if (
        workflow_run is not None
        and (
            not isinstance(workflow_run, dict)
            or workflow_run.get("id") != run_id
        )
    ):
        raise CandidateError("candidate artifact workflow_run does not match run")
    return {
        "id": artifact_id,
        "name": expected_name,
        "archive_sha256": archive_sha256,
    }


def require_object(value: Any, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise CandidateError(f"{label} has a non-closed schema: {'; '.join(details)}")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CandidateError(f"{label} must be an array")
    return value


def require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CandidateError(f"{label} must be a non-empty string")
    return value


def require_positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CandidateError(f"{label} must be a positive integer")
    return value


def require_sha(value: Any, label: str) -> str:
    text = require_nonempty_string(value, label)
    if SHA.fullmatch(text) is None:
        raise CandidateError(f"{label} must be 40 lowercase hexadecimal characters")
    return text


def require_sha256(value: Any, label: str) -> str:
    text = require_nonempty_string(value, label)
    if SHA256.fullmatch(text) is None:
        raise CandidateError(f"{label} must be 64 lowercase hexadecimal characters")
    return text


def require_digest(value: Any, label: str) -> str:
    text = require_nonempty_string(value, label)
    if DIGEST.fullmatch(text) is None:
        raise CandidateError(
            f"{label} must be sha256:<64 lowercase hexadecimal characters>"
        )
    return text


def parse_timestamp(value: Any, label: str) -> datetime:
    text = require_nonempty_string(value, label)
    if not text.endswith("Z"):
        raise CandidateError(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CandidateError(f"{label} is not an RFC3339 timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise CandidateError(f"{label} must use UTC")
    return parsed


def safe_relative_path(value: Any, label: str) -> str:
    text = require_nonempty_string(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text in {".", ""}:
        raise CandidateError(f"{label} must be a safe relative path")
    if path.as_posix() != text:
        raise CandidateError(f"{label} must use canonical POSIX separators")
    return text


def require_nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateError(f"{label} must be a non-negative integer")
    return value


def _validate_file_record(
    value: Any,
    label: str,
    *,
    fields: set[str],
) -> tuple[dict[str, Any], str, str]:
    record = require_object(value, label, fields)
    name = safe_relative_path(record["name"], f"{label}.name")
    digest = require_sha256(record["sha256"], f"{label}.sha256")
    if "size" in fields:
        require_nonnegative_integer(record["size"], f"{label}.size")
    return record, name, digest


def _verify_candidate_files(
    records: dict[str, tuple[str, int | None]],
    *,
    bundle_root: Path | None,
) -> None:
    if bundle_root is None:
        return
    if not bundle_root.is_dir():
        raise CandidateError(f"candidate bundle root does not exist: {bundle_root}")
    actual = {
        path.relative_to(bundle_root).as_posix()
        for path in iter_files(bundle_root)
    }
    expected = set(records)
    if actual != expected:
        raise CandidateError(
            "candidate bundle file inventory mismatch: "
            f"missing={sorted(expected - actual)!r} "
            f"unexpected={sorted(actual - expected)!r}"
        )
    for name, (digest, size) in records.items():
        path = bundle_root / name
        if sha256_file(path) != digest:
            raise CandidateError(f"candidate bundle file sha256 mismatch: {name}")
        if size is not None and path.stat().st_size != size:
            raise CandidateError(f"candidate bundle file size mismatch: {name}")


def _security_evidence_member_name(value: str) -> str:
    """Return one canonical archive path without host-path interpretation."""

    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or len(value) > 512
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise CandidateError(
            f"security evidence archive has unsafe path {value!r}"
        )
    return value


def _security_evidence_json(contents: dict[str, bytes], name: str) -> dict[str, Any]:
    try:
        document = json.loads(contents[name])
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CandidateError(
            f"security evidence member {name!r} is not valid JSON"
        ) from exc
    if not isinstance(document, dict) or not document:
        raise CandidateError(
            f"security evidence member {name!r} must be a non-empty JSON object"
        )
    return document


def _validate_image_report(
    document: dict[str, Any],
    *,
    name: str,
    expected_ref: str,
    report_kind: str,
) -> None:
    source = document.get("source")
    source_details_key = "metadata" if report_kind == "syft" else "target"
    source_details = (
        source.get(source_details_key) if isinstance(source, dict) else None
    )
    if (
        not isinstance(source, dict)
        or source.get("type") != "image"
        or not isinstance(source_details, dict)
        or source_details.get("userInput") != expected_ref
    ):
        raise CandidateError(
            f"security evidence member {name!r} is not bound to {expected_ref}"
        )
    collection = "artifacts" if report_kind == "syft" else "matches"
    if not isinstance(document.get(collection), list):
        raise CandidateError(
            f"security evidence member {name!r} must contain a {collection} array"
        )
    if report_kind == "grype":
        descriptor = document.get("descriptor")
        database = descriptor.get("db") if isinstance(descriptor, dict) else None
        status = database.get("status") if isinstance(database, dict) else None
        built = (
            database.get("built")
            if isinstance(database, dict)
            else None
        ) or (status.get("built") if isinstance(status, dict) else None)
        checksum = (
            database.get("checksum") if isinstance(database, dict) else None
        )
        source_url = status.get("from") if isinstance(status, dict) else None
        has_checksum = isinstance(checksum, str) and bool(checksum)
        if not has_checksum and isinstance(source_url, str):
            has_checksum = (
                re.search(
                    r"checksum=sha256%3A[0-9a-fA-F]{64}",
                    source_url,
                )
                is not None
            )
        if not isinstance(built, str) or not built or not has_checksum:
            raise CandidateError(
                f"security evidence member {name!r} lacks Grype database metadata"
            )


def validate_security_evidence_archive(
    path: Path,
    *,
    product_image_refs: dict[str, str],
    product_scan_sha256: dict[str, str],
    advisory_sha256: str,
) -> None:
    """Inspect the authenticated evidence tar without extracting it.

    The compressed archive is attacker-controlled promotion input even though
    its hash is bound by the candidate manifest. Resource and structure bounds
    keep validation fail closed without materializing archive paths.
    """

    if path.is_symlink() or not path.is_file():
        raise CandidateError(
            "security evidence payload must be a regular non-symlink file"
        )
    archive_size = path.stat().st_size
    if (
        archive_size <= 0
        or archive_size > SECURITY_EVIDENCE_MAX_ARCHIVE_SIZE
    ):
        raise CandidateError("security evidence archive size exceeds its bound")

    required_files = _security_evidence_required_files(product_image_refs)
    seen: set[str] = set()
    top_level: set[str] = set()
    contents: dict[str, bytes] = {}
    total_size = 0
    member_count = 0
    expected_top_level = {
        PurePosixPath(name).parts[0] for name in required_files
    }
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > SECURITY_EVIDENCE_MAX_MEMBERS:
                    raise CandidateError(
                        "security evidence archive has too many entries"
                    )
                name = _security_evidence_member_name(member.name)
                if name in seen:
                    raise CandidateError(
                        f"security evidence archive has duplicate path {name!r}"
                    )
                seen.add(name)
                parts = PurePosixPath(name).parts
                top_level.add(parts[0])
                if parts[0] not in expected_top_level:
                    raise CandidateError(
                        "security evidence archive has unexpected top-level "
                        f"structure {parts[0]!r}"
                    )
                if member.isdir():
                    if (
                        member.size != 0
                        or len(parts) != 1
                        or name not in SECURITY_EVIDENCE_DIRECTORIES
                    ):
                        raise CandidateError(
                            "security evidence archive has unexpected directory "
                            f"{name!r}"
                        )
                    continue
                if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                    raise CandidateError(
                        f"security evidence archive has non-regular entry {name!r}"
                    )
                if name not in required_files:
                    raise CandidateError(
                        f"security evidence archive has unexpected member {name!r}"
                    )
                if member.size <= 0:
                    raise CandidateError(
                        f"security evidence archive has empty entry {name!r}"
                    )
                if member.size > SECURITY_EVIDENCE_MAX_ENTRY_SIZE:
                    raise CandidateError(
                        f"security evidence entry {name!r} exceeds its size bound"
                    )
                total_size += member.size
                if total_size > SECURITY_EVIDENCE_MAX_TOTAL_SIZE:
                    raise CandidateError(
                        "security evidence archive exceeds its total size bound"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise CandidateError(
                        f"security evidence archive cannot read {name!r}"
                    )
                payload = source.read(SECURITY_EVIDENCE_MAX_ENTRY_SIZE + 1)
                if len(payload) != member.size:
                    raise CandidateError(
                        f"security evidence archive truncated member {name!r}"
                    )
                contents[name] = payload
    except (OSError, tarfile.TarError) as exc:
        raise CandidateError(
            f"cannot inspect security evidence archive: {exc}"
        ) from exc

    missing = required_files - set(contents)
    if missing:
        raise CandidateError(
            f"security evidence archive is incomplete: missing {sorted(missing)!r}"
        )
    if top_level != expected_top_level:
        raise CandidateError(
            "security evidence archive has unexpected top-level structure: "
            f"missing={sorted(expected_top_level - top_level)!r} "
            f"unexpected={sorted(top_level - expected_top_level)!r}"
        )

    for image, expected_ref in product_image_refs.items():
        spdx_name = f"image-sbom/{image}.spdx.json"
        spdx = _security_evidence_json(contents, spdx_name)
        if spdx.get("spdxVersion") != "SPDX-2.3" or not isinstance(
            spdx.get("packages"), list
        ):
            raise CandidateError(
                f"security evidence member {spdx_name!r} is not SPDX 2.3 JSON"
            )
        for report_kind in ("syft", "grype"):
            report_name = f"{report_kind}/{image}.{report_kind}.json"
            report = _security_evidence_json(contents, report_name)
            _validate_image_report(
                report,
                name=report_name,
                expected_ref=expected_ref,
                report_kind=report_kind,
            )

    for image, expected_sha256 in product_scan_sha256.items():
        name = f"grype/{image}.grype.json"
        if hashlib.sha256(contents[name]).hexdigest() != expected_sha256:
            raise CandidateError(
                f"security evidence member {name!r} does not match its scan payload"
            )

    database_status = _security_evidence_json(
        contents, "grype/grype-db-status.json"
    )
    if not database_status:
        raise CandidateError("security evidence Grype database status is empty")

    advisory = _security_evidence_json(contents, "advisory-verdict.json")
    expected_subjects = {f"{name}-image" for name in product_image_refs}
    subjects = advisory.get("subjects")
    if (
        advisory.get("schema_version") != "registry-stack.advisory-verdict.v2"
        or advisory.get("verdict") != "passed"
        or not isinstance(subjects, list)
        or any(not isinstance(subject, str) for subject in subjects)
        or len(subjects) != len(expected_subjects)
        or set(subjects) != expected_subjects
    ):
        raise CandidateError(
            "security evidence advisory verdict does not cover every runtime"
        )
    if hashlib.sha256(contents["advisory-verdict.json"]).hexdigest() != (
        advisory_sha256
    ):
        raise CandidateError(
            "security evidence advisory verdict does not match its payload"
        )


def validate_candidate_manifest(
    document: Any,
    *,
    bundle_path: Path | None = None,
    bundle_root: Path | None = None,
    expected_source_sha: str | None = None,
    expected_workflow_revision: str | None = None,
    expected_version: str | None = None,
    expected_release_id: str | None = None,
    expected_run_id: int | None = None,
    expected_run_attempt: int | None = None,
    now: datetime | None = None,
    promotion: bool = False,
    workflow_run_metadata: dict[str, Any] | None = None,
    allow_current_run_in_progress: bool = False,
) -> dict[str, Any]:
    """Validate the closed v2 candidate manifest and its workflow binding."""

    if allow_current_run_in_progress and promotion:
        raise CandidateError(
            "current in-progress run metadata cannot authorize promotion"
        )
    if allow_current_run_in_progress and workflow_run_metadata is None:
        raise CandidateError(
            "current in-progress run verification requires trusted workflow-run metadata"
        )

    release_hint = document.get("release") if isinstance(document, dict) else None
    version_hint = (
        release_hint.get("version") if isinstance(release_hint, dict) else None
    )
    parsed_version_hint = (
        tuple(int(part) for part in version_hint.split("."))
        if isinstance(version_hint, str) and VERSION.fullmatch(version_hint)
        else None
    )
    if (
        parsed_version_hint is not None
        and parsed_version_hint < RELAY_V2_RELEASE_MINIMUM_VERSION
    ):
        raise CandidateError(
            "pre-v0.19 candidates are immutable historical evidence; verify them "
            "with the corresponding release tag"
        )
    uses_release_docs = parsed_version_hint is not None and _version_uses_release_docs(
        parsed_version_hint
    )
    manifest = require_object(
        document,
        "manifest",
        DOCS_V2_TOP_LEVEL_FIELDS if uses_release_docs else V2_TOP_LEVEL_FIELDS,
    )
    if manifest["schema_version"] != V2_SCHEMA_VERSION:
        raise CandidateError(
            f"manifest.schema_version must be {V2_SCHEMA_VERSION}"
        )
    if manifest["repository"] != REPOSITORY:
        raise CandidateError(f"manifest.repository must be {REPOSITORY}")

    release = require_object(
        manifest["release"],
        "release",
        {"version", "release_id", "tag", "source_sha"},
    )
    version = require_nonempty_string(release["version"], "release.version")
    if VERSION.fullmatch(version) is None:
        raise CandidateError("release.version must be canonical semantic version text")
    release_version = tuple(int(part) for part in version.split("."))
    if release_version < RELAY_V2_RELEASE_MINIMUM_VERSION:
        raise CandidateError(
            "pre-v0.19 candidates are immutable historical evidence; verify them "
            "with the corresponding release tag"
        )
    release_id = require_nonempty_string(release["release_id"], "release.release_id")
    if RELEASE_ID.fullmatch(release_id) is None:
        raise CandidateError("release.release_id is invalid")
    source_sha = require_sha(release["source_sha"], "release.source_sha")
    if release["tag"] != f"v{version}":
        raise CandidateError("release.tag must exactly match release.version")

    workflow = require_object(
        manifest["workflow"],
        "workflow",
        {"path", "revision", "run_id", "run_attempt"},
    )
    if workflow["path"] != WORKFLOW_PATH:
        raise CandidateError(f"workflow.path must be {WORKFLOW_PATH}")
    workflow_revision = require_sha(
        workflow["revision"], "workflow.revision"
    )
    if source_sha != workflow_revision:
        raise CandidateError(
            "active candidate release.source_sha must equal workflow.revision"
        )
    run_id = require_positive_integer(workflow["run_id"], "workflow.run_id")
    run_attempt = require_positive_integer(
        workflow["run_attempt"], "workflow.run_attempt"
    )

    validity = require_object(
        manifest["validity"], "validity", {"created_at", "expires_at"}
    )
    created_at = parse_timestamp(validity["created_at"], "validity.created_at")
    expires_at = parse_timestamp(validity["expires_at"], "validity.expires_at")
    lifetime = expires_at - created_at
    if lifetime <= timedelta(0) or lifetime > V2_MAX_PROMOTION_AGE:
        raise CandidateError(
            "candidate validity must be positive and no longer than 7 days"
        )
    current = now or datetime.now(timezone.utc)
    if created_at > current + timedelta(minutes=5):
        raise CandidateError("candidate creation timestamp is future-dated")
    if current >= expires_at:
        raise CandidateError("candidate is expired")

    if promotion or workflow_run_metadata is not None:
        if workflow_run_metadata is None:
            raise CandidateError(
                "promotion requires independently fetched trusted workflow-run metadata"
            )
        trusted_run = require_object(
            workflow_run_metadata,
            "trusted workflow run",
            {
                "id",
                "run_attempt",
                "event",
                "head_sha",
                "path",
                "status",
                "conclusion",
                "created_at",
            },
        )
        trusted_created = parse_timestamp(
            trusted_run["created_at"], "trusted workflow run.created_at"
        )
        expectations = {
            "id": run_id,
            "run_attempt": run_attempt,
            "event": "repository_dispatch",
            "head_sha": workflow_revision,
            "path": WORKFLOW_PATH,
            "status": (
                "in_progress" if allow_current_run_in_progress else "completed"
            ),
            "conclusion": (
                None if allow_current_run_in_progress else "success"
            ),
        }
        for field, expected in expectations.items():
            if trusted_run[field] != expected:
                raise CandidateError(
                    f"trusted workflow run {field} mismatch: "
                    f"expected {expected!r}, got {trusted_run[field]!r}"
                )
        if created_at < trusted_created:
            raise CandidateError(
                "manifest creation timestamp predates the trusted workflow run"
            )

    files: dict[str, tuple[str, int | None]] = {}
    payloads = require_list(manifest["payloads"], "payloads")
    if not payloads:
        raise CandidateError("payloads must not be empty")
    payload_by_name: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(payloads):
        label = f"payloads[{index}]"
        record, name, digest = _validate_file_record(
            value,
            label,
            fields={"name", "kind", "size", "sha256"},
        )
        if Path(name).name != name:
            raise CandidateError(f"{label}.name must be a public asset basename")
        allowed_payload_kinds = (
            DOCS_V2_PAYLOAD_KINDS if uses_release_docs else PAYLOAD_KINDS
        )
        if record["kind"] not in allowed_payload_kinds:
            raise CandidateError(f"{label}.kind is unsupported")
        if name in files:
            raise CandidateError(f"candidate file name is duplicated: {name}")
        files[name] = (digest, record["size"])
        payload_by_name[name] = record
    singleton_kinds = (
        ("docs", "sbom", "security-evidence")
        if uses_release_docs
        else ("sbom", "security-evidence")
    )
    for singleton_kind in singleton_kinds:
        matches = [
            record for record in payloads if record["kind"] == singleton_kind
        ]
        if len(matches) != 1:
            raise CandidateError(
                f"payloads must contain exactly one {singleton_kind} payload"
            )
    expected_evidence_name = (
        f"registry-stack-v{version}-security-evidence.tar.gz"
    )
    evidence_payload = next(
        record
        for record in payloads
        if record["kind"] == "security-evidence"
    )
    if evidence_payload["name"] != expected_evidence_name:
        raise CandidateError(
            "security-evidence payload name must be "
            f"{expected_evidence_name}"
        )
    expected_payloads = _relay_v2_payload_inventory(version)
    actual_payloads = {record["name"]: record["kind"] for record in payloads}
    if actual_payloads != expected_payloads:
        missing = sorted(set(expected_payloads) - set(actual_payloads))
        unexpected = sorted(set(actual_payloads) - set(expected_payloads))
        wrong_kind = sorted(
            name
            for name in set(actual_payloads) & set(expected_payloads)
            if actual_payloads[name] != expected_payloads[name]
        )
        details = []
        if missing:
            details.append(f"missing {missing!r}")
        if unexpected:
            details.append(f"unexpected {unexpected!r}")
        if wrong_kind:
            details.append(f"wrong kind {wrong_kind!r}")
        raise CandidateError(
            "payload inventory must be exactly the supported release set: "
            f"{'; '.join(details)}"
        )

    images = require_list(manifest["images"], "images")
    if not images:
        raise CandidateError("images must not be empty")
    image_names: set[str] = set()
    final_refs: set[str] = set()
    candidate_refs: set[str] = set()
    product_image_refs: dict[str, str] = {}
    for index, value in enumerate(images):
        label = f"images[{index}]"
        image = require_object(
            value,
            label,
            {"name", "candidate_ref", "digest", "final_ref"},
        )
        name = require_nonempty_string(image["name"], f"{label}.name")
        if name in image_names:
            raise CandidateError(f"duplicate candidate image name {name!r}")
        image_names.add(name)
        digest = require_digest(image["digest"], f"{label}.digest")
        candidate_ref = require_nonempty_string(
            image["candidate_ref"], f"{label}.candidate_ref"
        )
        final_ref = require_nonempty_string(image["final_ref"], f"{label}.final_ref")
        expected_candidate = f"ghcr.io/registrystack/{name}-candidate@{digest}"
        expected_final = f"ghcr.io/registrystack/{name}:v{version}"
        if candidate_ref != expected_candidate:
            raise CandidateError(
                f"{label}.candidate_ref must be {expected_candidate}"
            )
        if final_ref != expected_final:
            raise CandidateError(f"{label}.final_ref must be {expected_final}")
        if candidate_ref in candidate_refs or final_ref in final_refs:
            raise CandidateError("candidate and final image refs must be unique")
        candidate_refs.add(candidate_ref)
        final_refs.add(final_ref)
        product_image_refs[name] = candidate_ref
    expected_image_names = _candidate_image_names(version)
    if image_names != expected_image_names:
        raise CandidateError(
            f"image inventory must be exactly {sorted(expected_image_names)!r}"
        )

    singleton_fields = ("docs", "sbom") if uses_release_docs else ("sbom",)
    for kind in singleton_fields:
        record, name, digest = _validate_file_record(
            manifest[kind],
            kind,
            fields={"name", "sha256"},
        )
        payload = payload_by_name.get(name)
        if payload is None or payload["kind"] != kind:
            raise CandidateError(f"{kind}.name must reference one {kind} payload")
        if payload["sha256"] != digest:
            raise CandidateError(f"{kind}.sha256 must match its payload hash")

    scan_images: set[str] = set()
    product_scan_sha256: dict[str, str] = {}
    for index, value in enumerate(require_list(manifest["scans"], "scans")):
        label = f"scans[{index}]"
        record, name, digest = _validate_file_record(
            value,
            label,
            fields={"image", "name", "sha256", "status"},
        )
        image = require_nonempty_string(record["image"], f"{label}.image")
        if image not in image_names or image in scan_images:
            raise CandidateError(f"{label}.image is unexpected or duplicated")
        scan_images.add(image)
        if record["status"] != "passed":
            raise CandidateError(f"{label}.status must be passed")
        if name in files:
            raise CandidateError(f"candidate file name is duplicated: {name}")
        files[name] = (digest, None)
        product_scan_sha256[image] = digest
    if scan_images != image_names:
        raise CandidateError("every candidate image must have exactly one passed scan")

    advisory, advisory_name, advisory_digest = _validate_file_record(
        manifest["advisory"],
        "advisory",
        fields={"name", "sha256", "verdict"},
    )
    if advisory["verdict"] != "passed":
        raise CandidateError("advisory.verdict must be passed")
    if advisory_name in files:
        raise CandidateError(
            f"candidate file name is duplicated: {advisory_name}"
        )
    files[advisory_name] = (advisory_digest, None)

    bundle, _, bundle_digest = _validate_file_record(
        manifest["bundle"],
        "bundle",
        fields={"name", "size", "sha256"},
    )
    if Path(bundle["name"]).name != bundle["name"]:
        raise CandidateError("bundle.name must be a basename")
    expected_bundle_name = f"registry-stack-v{version}-candidate.tar.gz"
    if bundle["name"] != expected_bundle_name:
        raise CandidateError(f"bundle.name must be {expected_bundle_name}")
    if bundle_path is not None:
        if bundle_path.name != bundle["name"]:
            raise CandidateError("candidate bundle filename mismatch")
        if sha256_file(bundle_path) != bundle_digest:
            raise CandidateError("candidate bundle sha256 mismatch")
        if bundle_path.stat().st_size != bundle["size"]:
            raise CandidateError("candidate bundle size mismatch")
    _verify_candidate_files(files, bundle_root=bundle_root)
    if promotion and bundle_root is None:
        raise CandidateError(
            "promotion requires an extracted candidate bundle root"
        )
    if bundle_root is not None:
        validate_security_evidence_archive(
            bundle_root / expected_evidence_name,
            product_image_refs=product_image_refs,
            product_scan_sha256=product_scan_sha256,
            advisory_sha256=advisory_digest,
        )

    expectations = (
        ("source SHA", expected_source_sha, source_sha),
        ("workflow revision", expected_workflow_revision, workflow_revision),
        ("version", expected_version, version),
        ("release ID", expected_release_id, release_id),
        ("run ID", expected_run_id, run_id),
        ("run attempt", expected_run_attempt, run_attempt),
    )
    for label, expected, actual in expectations:
        if expected is not None and expected != actual:
            raise CandidateError(
                f"candidate {label} mismatch: expected {expected!r}, got {actual!r}"
            )
    return manifest


def canary_run_from_json(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise CandidateError("trusted canary workflow-run metadata must be an object")
    normalized = {
        "id": document.get("id"),
        "run_attempt": document.get("run_attempt"),
        "event": document.get("event"),
        "head_sha": document.get("head_sha"),
        "path": document.get("path"),
        "conclusion": document.get("conclusion"),
        "completed_at": document.get("completed_at", document.get("updated_at")),
    }
    missing = [field for field, value in normalized.items() if value is None]
    if missing:
        raise CandidateError(
            "trusted canary workflow-run metadata is missing "
            + ", ".join(missing)
        )
    return normalized


def select_canary_run(document: Any, *, workflow_revision: str) -> dict[str, Any]:
    revision = require_sha(workflow_revision, "workflow revision")
    if not isinstance(document, dict):
        raise CandidateError("canary workflow-runs response must be an object")
    runs = require_list(document.get("workflow_runs"), "workflow_runs")
    selected: list[tuple[datetime, dict[str, Any]]] = []
    for value in runs:
        if not isinstance(value, dict):
            raise CandidateError("workflow_runs entries must be objects")
        if (
            value.get("head_sha") != revision
            or value.get("conclusion") != "success"
            or value.get("event") not in {"schedule", "workflow_dispatch"}
            or value.get("path") != CANARY_WORKFLOW_PATH
        ):
            continue
        completed_at = value.get("updated_at")
        completed = parse_timestamp(
            completed_at,
            "trusted canary workflow run.updated_at",
        )
        selected.append(
            (
                completed,
                canary_run_from_json(
                    {
                        "id": value.get("id"),
                        "run_attempt": value.get("run_attempt"),
                        "event": value.get("event"),
                        "head_sha": value.get("head_sha"),
                        "path": value.get("path"),
                        "conclusion": value.get("conclusion"),
                        "completed_at": completed_at,
                    }
                ),
            )
        )
    if not selected:
        raise CandidateError(
            "no successful trusted canary matches the workflow revision"
        )
    return max(selected, key=lambda item: item[0])[1]


def validate_canary_run(
    document: Any,
    *,
    workflow_revision: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    revision = require_sha(workflow_revision, "workflow revision")
    run = require_object(
        document,
        "trusted canary workflow run",
        {
            "id",
            "run_attempt",
            "event",
            "head_sha",
            "path",
            "conclusion",
            "completed_at",
        },
    )
    require_positive_integer(run["id"], "trusted canary workflow run.id")
    require_positive_integer(
        run["run_attempt"], "trusted canary workflow run.run_attempt"
    )
    if run["event"] not in {"schedule", "workflow_dispatch"}:
        raise CandidateError("trusted canary workflow run event is unexpected")
    if run["path"] != CANARY_WORKFLOW_PATH:
        raise CandidateError(
            f"trusted canary workflow run path must be {CANARY_WORKFLOW_PATH}"
        )
    if run["head_sha"] != revision:
        raise CandidateError(
            "trusted canary workflow run does not match the candidate workflow revision"
        )
    if run["conclusion"] != "success":
        raise CandidateError("trusted canary workflow run did not succeed")
    completed_at = parse_timestamp(
        run["completed_at"], "trusted canary workflow run.completed_at"
    )
    current = now or datetime.now(timezone.utc)
    age = current - completed_at
    if age < -timedelta(minutes=5):
        raise CandidateError("trusted canary workflow run is future-dated")
    if age > MAX_CANARY_AGE:
        raise CandidateError("trusted canary workflow run is older than 24 hours")
    return run


def workflow_run_from_json(document: Any) -> dict[str, Any]:
    """Normalize the independently fetched GitHub Actions run API response."""
    if not isinstance(document, dict):
        raise CandidateError("trusted workflow-run metadata must be an object")
    required = {
        "id",
        "run_attempt",
        "event",
        "head_sha",
        "path",
        "status",
        "conclusion",
        "created_at",
    }
    missing = sorted(required - set(document))
    if missing:
        raise CandidateError(
            f"trusted workflow-run metadata is missing {', '.join(missing)}"
        )
    return {field: document[field] for field in required}


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def write_candidate_manifest(draft_path: Path, output_path: Path) -> None:
    document = read_json(draft_path)
    validate_candidate_manifest(document)
    if output_path.is_symlink() or (output_path.exists() and not output_path.is_file()):
        raise CandidateError(
            f"manifest output must be a regular non-symlink path: {output_path}"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json(document))


def render_tag_binding(run_id: int, run_attempt: int, manifest_sha256: str) -> str:
    require_positive_integer(run_id, "run_id")
    require_positive_integer(run_attempt, "run_attempt")
    require_sha256(manifest_sha256, "manifest_sha256")
    return (
        f"{TAG_BINDING_HEADER}\n"
        f"run_id: {run_id}\n"
        f"run_attempt: {run_attempt}\n"
        f"manifest_sha256: {manifest_sha256}\n"
    )


def parse_tag_binding(message: str) -> dict[str, Any]:
    if "\r" in message:
        raise CandidateError("annotated tag binding must use LF line endings")
    match = re.fullmatch(
        re.escape(TAG_BINDING_HEADER)
        + r"\nrun_id: ([1-9][0-9]*)"
        + r"\nrun_attempt: ([1-9][0-9]*)"
        + r"\nmanifest_sha256: ([0-9a-f]{64})\n{0,2}",
        message,
    )
    if match is not None:
        return {
            "schema_version": V2_SCHEMA_VERSION,
            "run_id": int(match.group(1)),
            "run_attempt": int(match.group(2)),
            "manifest_sha256": match.group(3),
        }
    raise CandidateError(
        "annotated tag message must use the current release-candidate binding format"
    )


def iter_files(root: Path) -> Iterable[Path]:
    return sorted(
        path for path in root.rglob("*") if path.is_file() or path.is_symlink()
    )


def file_inventory(root: Path) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise CandidateError(f"artifact root does not exist: {root}")
    result = []
    for path in iter_files(root):
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    if not result:
        raise CandidateError(f"artifact root is empty: {root}")
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="release_candidate.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    seal_candidate = subparsers.add_parser("seal-candidate")
    seal_candidate.add_argument("--draft", type=Path, required=True)
    seal_candidate.add_argument("--output", type=Path, required=True)

    image_names = subparsers.add_parser("image-names")
    image_names.add_argument("--version", required=True)

    check_onboarding = subparsers.add_parser("check-image-onboarding")
    check_onboarding.add_argument("--version", required=True)
    check_onboarding.add_argument("--root", type=Path, required=True)
    check_onboarding.add_argument("--allow-missing-baseline", action="store_true")

    verify_candidate = subparsers.add_parser("verify-candidate")
    verify_candidate.add_argument("--manifest", type=Path, required=True)
    verify_candidate.add_argument("--bundle", type=Path)
    verify_candidate.add_argument("--bundle-root", type=Path)
    verify_candidate.add_argument("--source-sha")
    verify_candidate.add_argument("--workflow-revision")
    verify_candidate.add_argument("--version")
    verify_candidate.add_argument("--release-id")
    verify_candidate.add_argument("--run-id", type=int)
    verify_candidate.add_argument("--run-attempt", type=int)
    verify_candidate.add_argument("--promotion", action="store_true")
    verify_candidate.add_argument(
        "--allow-current-run-in-progress",
        action="store_true",
        help=(
            "allow only the current in-progress candidate run during its "
            "internal pre-OIDC re-verification"
        ),
    )
    verify_candidate.add_argument(
        "--trusted-run-metadata", dest="workflow_run_metadata", type=Path
    )

    verify_canary = subparsers.add_parser("verify-canary")
    verify_canary.add_argument("--metadata", type=Path, required=True)
    verify_canary.add_argument("--workflow-revision", required=True)

    select_canary = subparsers.add_parser("select-canary")
    select_canary.add_argument("--metadata", type=Path, required=True)
    select_canary.add_argument("--workflow-revision", required=True)
    select_canary.add_argument("--output", type=Path, required=True)

    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("--root", type=Path, required=True)

    extract = subparsers.add_parser("extract-artifact")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--archive-sha256", required=True)
    extract.add_argument("--destination", type=Path, required=True)

    binding = subparsers.add_parser("render-tag-binding")
    binding.add_argument("--run-id", type=int, required=True)
    binding.add_argument("--run-attempt", type=int, required=True)
    binding.add_argument("--manifest-sha256", required=True)

    verify_binding = subparsers.add_parser("verify-tag-binding")
    verify_binding.add_argument("--message", type=Path, required=True)
    verify_binding.add_argument("--manifest", type=Path, required=True)
    verify_binding.add_argument("--bundle", type=Path)
    verify_binding.add_argument("--bundle-root", type=Path)
    verify_binding.add_argument("--tag-target")
    verify_binding.add_argument("--workflow-revision")
    verify_binding.add_argument("--version")
    verify_binding.add_argument("--release-id")
    verify_binding.add_argument(
        "--trusted-run-metadata",
        dest="workflow_run_metadata",
        type=Path,
        required=True,
    )

    slsa_subjects = subparsers.add_parser("verify-slsa-subjects")
    slsa_subjects.add_argument("--provenance", type=Path, required=True)
    slsa_subjects.add_argument("--contract", type=Path, required=True)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "image-names":
            print(" ".join(sorted(_candidate_image_names(args.version))))
            return 0
        if args.command == "check-image-onboarding":
            image_names = check_image_onboarding(
                args.root,
                args.version,
                allow_missing_baseline=args.allow_missing_baseline,
            )
            print(f"checked image onboarding for {' '.join(sorted(image_names))}")
            return 0
        if args.command == "seal-candidate":
            write_candidate_manifest(args.draft, args.output)
            print(f"sealed candidate manifest {args.output}")
            return 0
        if args.command == "verify-candidate":
            if args.promotion and args.workflow_run_metadata is None:
                raise CandidateError(
                    "--promotion requires --trusted-run-metadata"
                )
            manifest = validate_candidate_manifest(
                read_json(args.manifest),
                bundle_path=args.bundle,
                bundle_root=args.bundle_root,
                expected_source_sha=args.source_sha,
                expected_workflow_revision=args.workflow_revision,
                expected_version=args.version,
                expected_release_id=args.release_id,
                expected_run_id=args.run_id,
                expected_run_attempt=args.run_attempt,
                promotion=args.promotion,
                workflow_run_metadata=(
                    workflow_run_from_json(read_json(args.workflow_run_metadata))
                    if args.workflow_run_metadata
                    else None
                ),
                allow_current_run_in_progress=(
                    args.allow_current_run_in_progress
                ),
            )
            print(
                "verified release candidate "
                f"{manifest['release']['release_id']} {manifest['release']['tag']} "
                f"from run {manifest['workflow']['run_id']}/"
                f"{manifest['workflow']['run_attempt']}"
            )
            return 0
        if args.command == "verify-canary":
            run = validate_canary_run(
                canary_run_from_json(read_json(args.metadata)),
                workflow_revision=args.workflow_revision,
            )
            print(
                "verified recent release canary "
                f"{run['id']}/{run['run_attempt']} at {run['head_sha']}"
            )
            return 0
        if args.command == "select-canary":
            run = select_canary_run(
                read_json(args.metadata),
                workflow_revision=args.workflow_revision,
            )
            args.output.write_bytes(canonical_json(run))
            print(
                "selected trusted release canary "
                f"{run['id']}/{run['run_attempt']} at {run['head_sha']}"
            )
            return 0
        if args.command == "inventory":
            print(json.dumps(file_inventory(args.root), indent=2, sort_keys=True))
            return 0
        if args.command == "extract-artifact":
            extract_artifact_archive(
                args.archive,
                args.destination,
                expected_sha256=args.archive_sha256,
            )
            print(f"verified and extracted candidate artifact {args.archive}")
            return 0
        if args.command == "render-tag-binding":
            print(
                render_tag_binding(args.run_id, args.run_attempt, args.manifest_sha256),
                end="",
            )
            return 0
        if args.command == "verify-slsa-subjects":
            subjects = validate_slsa_subject_set(
                args.provenance,
                args.contract,
            )
            print(
                f"verified exact SLSA provenance subject set ({len(subjects)} subjects)"
            )
            return 0
        if args.command == "verify-tag-binding":
            binding = parse_tag_binding(args.message.read_text(encoding="utf-8"))
            run_metadata = workflow_run_from_json(
                read_json(args.workflow_run_metadata)
            )
            required_v2 = {
                "--bundle": args.bundle,
                "--bundle-root": args.bundle_root,
                "--tag-target": args.tag_target,
                "--workflow-revision": args.workflow_revision,
                "--version": args.version,
                "--release-id": args.release_id,
            }
            missing = [
                option for option, value in required_v2.items() if value is None
            ]
            if missing:
                raise CandidateError(
                    "v2 tag verification requires " + ", ".join(missing)
                )
            if args.tag_target != args.workflow_revision:
                raise CandidateError(
                    "v2 tag target must equal the candidate workflow revision"
                )
            manifest_sha = sha256_file(args.manifest)
            if binding.get("manifest_sha256") != manifest_sha:
                raise CandidateError(
                    "annotated tag manifest_sha256 does not match manifest bytes"
                )
            manifest = validate_candidate_manifest(
                read_json(args.manifest),
                bundle_path=args.bundle,
                bundle_root=args.bundle_root,
                expected_source_sha=args.workflow_revision,
                expected_workflow_revision=args.workflow_revision,
                expected_version=args.version,
                expected_release_id=args.release_id,
                expected_run_id=binding["run_id"],
                expected_run_attempt=binding["run_attempt"],
                promotion=True,
                workflow_run_metadata=run_metadata,
            )
            workflow = manifest["workflow"]
            print(
                "verified annotated tag candidate binding for run "
                f"{workflow['run_id']}/{workflow['run_attempt']}"
            )
            return 0
        raise AssertionError(args.command)
    except (CandidateError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
