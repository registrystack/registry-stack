#!/usr/bin/env python3
"""Create and verify RegistryStack release-candidate manifests.

The compact v2 manifest is the active promotion contract.  The v1 receipt
validator remains available so historical releases can still be verified.
"""

from __future__ import annotations

import argparse
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


SCHEMA_VERSION = "registry-stack.release-candidate-receipt.v1"
V2_SCHEMA_VERSION = "registry-stack.release-candidate.v2"
LEGACY_TAG_BINDING_HEADER = "registry-stack-release-candidate-v1"
TAG_BINDING_HEADER = "registry-stack-release-candidate-v2"
REPOSITORY = "registrystack/registry-stack"
WORKFLOW_PATH = ".github/workflows/release-candidate.yml"
CANARY_WORKFLOW_PATH = ".github/workflows/release-canary.yml"
WORKFLOW_REF = "refs/heads/main"
POSTGRESQL_REF_PATH = (
    Path(__file__).resolve().parent.parent / "registryctl-postgresql-image.ref"
)
MAX_PROMOTION_AGE = timedelta(hours=72)
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
LEGACY_IMAGE_NAMES = {"registry-notary", "registry-relay"}
CURRENT_IMAGE_NAMES = {"registry-relay"}
NOTARY_RETIREMENT_MINIMUM_VERSION = (0, 17, 0)
ATTEMPT_ARTIFACT_PREFIXES = {
    "registry-stack-candidate-build-a",
    "registry-stack-candidate-macos-arm64",
    "registry-stack-candidate-linux-arm64",
    "registry-stack-release-candidate-payload",
    "registry-stack-release-candidate-receipt",
}
OPTIONAL_ATTEMPT_ARTIFACT_PREFIXES = {
    "registry-stack-candidate-build-b",
    "registry-stack-candidate-cli-linux-arm64",
    "registry-stack-candidate-cli-macos-arm64",
}
PROMOTION_STATE_SCHEMA = "registry-stack.release-promotion-state.v1"
TOP_LEVEL_FIELDS = {
    "schema_version",
    "repository",
    "workflow",
    "release",
    "validity",
    "builders",
    "builds",
    "artifacts",
    "images",
    "comparisons",
    "scans",
    "storage",
    "attestation",
    "promotion",
}
V2_TOP_LEVEL_FIELDS = {
    "schema_version",
    "repository",
    "release",
    "workflow",
    "validity",
    "payloads",
    "images",
    "docs",
    "sbom",
    "scans",
    "advisory",
    "bundle",
}
PAYLOAD_KINDS = {
    "binary",
    "installer",
    "image-lock",
    "docs",
    "sbom",
    "security-evidence",
}
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
    "images/postgresql.digest",
    "image-sbom/postgresql.spdx.json",
    "syft/postgresql.syft.json",
    "grype/postgresql.grype.json",
    "grype/grype-db-status.json",
    "advisory-verdict.json",
}
SECURITY_EVIDENCE_REQUIRED_FILES = SECURITY_EVIDENCE_COMMON_REQUIRED_FILES | {
    f"{directory}/registry-relay.{suffix}.json"
    for directory, suffix in (
        ("image-sbom", "spdx"),
        ("syft", "syft"),
        ("grype", "grype"),
    )
}
POSTGRESQL_DIGEST_REF = re.compile(
    r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$"
)


class CandidateError(ValueError):
    """A candidate cannot be trusted for promotion."""


def _candidate_image_names(version: str) -> set[str]:
    parsed = tuple(int(part) for part in version.split("."))
    if parsed >= NOTARY_RETIREMENT_MINIMUM_VERSION:
        return CURRENT_IMAGE_NAMES
    return LEGACY_IMAGE_NAMES


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


def expected_attempt_artifact_names(run_id: int, run_attempt: int) -> set[str]:
    require_positive_integer(run_id, "run_id")
    require_positive_integer(run_attempt, "run_attempt")
    suffix = f"-{run_id}-{run_attempt}"
    return {f"{prefix}{suffix}" for prefix in ATTEMPT_ARTIFACT_PREFIXES}


def validate_attempt_artifact_inventory(
    document: Any,
    *,
    run_id: int,
    run_attempt: int,
) -> dict[str, dict[str, Any]]:
    """Select the one exact, unexpired artifact set for a workflow attempt."""

    if not isinstance(document, dict):
        raise CandidateError("artifact metadata must be an object")
    artifacts = require_list(document.get("artifacts"), "artifact metadata.artifacts")
    expected = expected_attempt_artifact_names(run_id, run_attempt)
    suffix = f"-{run_id}-{run_attempt}"
    allowed = expected | {
        f"{prefix}{suffix}" for prefix in OPTIONAL_ATTEMPT_ARTIFACT_PREFIXES
    }
    selected: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(artifacts):
        label = f"artifact metadata.artifacts[{index}]"
        if not isinstance(item, dict):
            raise CandidateError(f"{label} must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name.endswith(suffix):
            continue
        if name not in allowed:
            raise CandidateError(
                f"unexpected artifact in current candidate attempt: {name!r}"
            )
        if name in selected:
            raise CandidateError(f"duplicate artifact in current attempt: {name}")
        if item.get("expired") is not False:
            raise CandidateError(f"candidate artifact is expired: {name}")
        artifact_id = require_positive_integer(item.get("id"), f"{label}.id")
        digest = require_nonempty_string(item.get("digest"), f"{label}.digest")
        if not digest.startswith("sha256:"):
            raise CandidateError(f"{label}.digest must be sha256-prefixed")
        require_sha256(digest.removeprefix("sha256:"), f"{label}.digest")
        workflow_run = item.get("workflow_run")
        if workflow_run is not None:
            if not isinstance(workflow_run, dict) or workflow_run.get("id") != run_id:
                raise CandidateError(
                    f"{label}.workflow_run does not match candidate run {run_id}"
                )
        selected[name] = {
            "id": artifact_id,
            "name": name,
            "archive_sha256": digest.removeprefix("sha256:"),
        }
    if not expected.issubset(selected):
        raise CandidateError(
            "candidate attempt artifact inventory is incomplete: "
            f"missing={sorted(expected - set(selected))!r}"
        )
    return selected


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
    expected_top_level = SECURITY_EVIDENCE_DIRECTORIES | {
        "advisory-verdict.json"
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

    try:
        postgresql_ref = contents["images/postgresql.digest"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateError(
            "security evidence PostgreSQL digest is not UTF-8 text"
        ) from exc
    canonical_postgresql_ref = postgresql_ref.removesuffix("\n")
    if (
        POSTGRESQL_DIGEST_REF.fullmatch(canonical_postgresql_ref) is None
        or postgresql_ref != canonical_postgresql_ref + "\n"
    ):
        raise CandidateError(
            "security evidence PostgreSQL digest is not canonical or immutable"
        )
    try:
        reviewed_postgresql_ref = POSTGRESQL_REF_PATH.read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError) as exc:
        raise CandidateError(
            "cannot read the reviewed PostgreSQL release image reference"
        ) from exc
    if (
        reviewed_postgresql_ref
        != reviewed_postgresql_ref.removesuffix("\n") + "\n"
        or canonical_postgresql_ref != reviewed_postgresql_ref.removesuffix("\n")
    ):
        raise CandidateError(
            "security evidence PostgreSQL digest does not match the reviewed "
            "release image reference"
        )
    postgresql_ref = canonical_postgresql_ref

    expected_refs = {**product_image_refs, "postgresql": postgresql_ref}
    for image, expected_ref in expected_refs.items():
        spdx_name = f"image-sbom/{image}.spdx.json"
        spdx = _security_evidence_json(contents, spdx_name)
        if spdx.get("spdxVersion") != "SPDX-2.3" or not isinstance(
            spdx.get("packages"), list
        ):
            raise CandidateError(
                f"security evidence member {spdx_name!r} is not SPDX 2.3 JSON"
            )
        if image == "postgresql":
            subject_id = "SPDXRef-RegistryStack-postgresql-digest-subject"
            described = spdx.get("documentDescribes")
            subject_packages = [
                package
                for package in spdx["packages"]
                if isinstance(package, dict)
                and package.get("SPDXID") == subject_id
            ]
            if (
                not isinstance(described, list)
                or subject_id not in described
                or len(subject_packages) != 1
                or subject_packages[0].get("name") != postgresql_ref
                or f"pkg:oci/postgresql@{postgresql_ref.rsplit('@', 1)[1]}"
                not in json.dumps(subject_packages[0], sort_keys=True)
            ):
                raise CandidateError(
                    "security evidence PostgreSQL SPDX subject is not bound "
                    "to the reviewed digest"
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
    expected_subjects = {"postgresql-runtime"}
    expected_subjects.update(f"{name}-image" for name in product_image_refs)
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

    manifest = require_object(document, "manifest", V2_TOP_LEVEL_FIELDS)
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
        if record["kind"] not in PAYLOAD_KINDS:
            raise CandidateError(f"{label}.kind is unsupported")
        if name in files:
            raise CandidateError(f"candidate file name is duplicated: {name}")
        files[name] = (digest, record["size"])
        payload_by_name[name] = record
    for singleton_kind in ("docs", "sbom", "security-evidence"):
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

    for kind in ("docs", "sbom"):
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


def _validate_builds(builds_value: Any) -> bool:
    if not isinstance(builds_value, dict):
        raise CandidateError("builds must be an object")
    has_build_b = "b" in builds_value
    expected_fields = (
        {"a", "b", "other_platforms"}
        if has_build_b
        else {"a", "other_platforms"}
    )
    builds = require_object(builds_value, "builds", expected_fields)
    build_a = require_object(builds["a"], "builds.a", {"job_id", "cargo_cache"})
    require_nonempty_string(build_a["job_id"], "builds.a.job_id")
    cache_a = require_object(
        build_a["cargo_cache"],
        "builds.a.cargo_cache",
        {"mode", "primary_key", "exact_key_hit", "action_output"},
    )
    if cache_a["mode"] != "exact-key-restore":
        raise CandidateError("builds.a.cargo_cache.mode must be exact-key-restore")
    require_nonempty_string(cache_a["primary_key"], "builds.a.cargo_cache.primary_key")
    if not isinstance(cache_a["exact_key_hit"], bool):
        raise CandidateError("builds.a.cargo_cache.exact_key_hit must be boolean")
    if cache_a["action_output"] not in {"true", "false", "not-reported"}:
        raise CandidateError("builds.a.cargo_cache.action_output is invalid")
    if cache_a["exact_key_hit"] != (cache_a["action_output"] == "true"):
        raise CandidateError(
            "builds.a Cargo cache exact_key_hit does not match the action output"
        )

    if has_build_b:
        build_b = require_object(
            builds["b"], "builds.b", {"job_id", "cargo_cache"}
        )
        require_nonempty_string(build_b["job_id"], "builds.b.job_id")
        cache_b = require_object(
            build_b["cargo_cache"],
            "builds.b.cargo_cache",
            {"mode", "primary_key", "exact_key_hit"},
        )
        if cache_b != {"mode": "cold", "primary_key": None, "exact_key_hit": False}:
            raise CandidateError(
                "build B must be cold and must not restore a Cargo cache"
            )
        if build_a["job_id"] == build_b["job_id"]:
            raise CandidateError(
                "canonical builds A and B must record distinct job identities"
            )

    other = require_list(builds["other_platforms"], "builds.other_platforms")
    platforms: set[str] = set()
    for index, item_value in enumerate(other):
        item = require_object(
            item_value,
            f"builds.other_platforms[{index}]",
            {"platform", "job_id"},
        )
        platform = require_nonempty_string(
            item["platform"], f"builds.other_platforms[{index}].platform"
        )
        require_nonempty_string(
            item["job_id"], f"builds.other_platforms[{index}].job_id"
        )
        if platform in platforms:
            raise CandidateError(f"duplicate other-platform build {platform}")
        platforms.add(platform)
    if platforms != {"linux-arm64", "macos-arm64"}:
        raise CandidateError(
            "other-platform build inventory must be exactly linux-arm64 and macos-arm64"
        )
    return has_build_b


def _validate_artifacts(
    artifacts_value: Any,
    *,
    artifact_root: Path | None,
    artifact_metadata: dict[int, tuple[str, str]] | None,
    expected_names: set[str],
) -> set[str]:
    artifacts = require_list(artifacts_value, "artifacts")
    if not artifacts:
        raise CandidateError("artifacts must not be empty")
    names: set[str] = set()
    ids: set[int] = set()
    paths: set[str] = set()
    for index, record_value in enumerate(artifacts):
        label = f"artifacts[{index}]"
        record = require_object(
            record_value,
            label,
            {"name", "artifact_id", "archive_sha256", "files"},
        )
        name = require_nonempty_string(record["name"], f"{label}.name")
        artifact_id = require_positive_integer(
            record["artifact_id"], f"{label}.artifact_id"
        )
        archive_sha256 = require_sha256(
            record["archive_sha256"], f"{label}.archive_sha256"
        )
        if name in names or artifact_id in ids:
            raise CandidateError("candidate artifact names and IDs must be unique")
        names.add(name)
        ids.add(artifact_id)
        if artifact_metadata is not None:
            actual = artifact_metadata.get(artifact_id)
            if actual != (name, archive_sha256):
                raise CandidateError(
                    f"artifact API metadata mismatch for {name} ({artifact_id}): "
                    f"expected digest sha256:{archive_sha256}, got {actual!r}"
                )
        files = require_list(record["files"], f"{label}.files")
        if not files:
            raise CandidateError(f"{label}.files must not be empty")
        for file_index, file_value in enumerate(files):
            file_label = f"{label}.files[{file_index}]"
            file_record = require_object(
                file_value,
                file_label,
                {"path", "sha256", "size"},
            )
            relative = safe_relative_path(file_record["path"], f"{file_label}.path")
            expected_sha = require_sha256(file_record["sha256"], f"{file_label}.sha256")
            size = file_record["size"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise CandidateError(
                    f"{file_label}.size must be a non-negative integer"
                )
            if relative in paths:
                raise CandidateError(f"duplicate candidate file path {relative}")
            paths.add(relative)
            if artifact_root is not None:
                path = artifact_root / relative
                if sha256_file(path) != expected_sha:
                    raise CandidateError(f"candidate file sha256 mismatch: {relative}")
                if path.stat().st_size != size:
                    raise CandidateError(f"candidate file size mismatch: {relative}")
    if artifact_root is not None:
        actual_paths = {
            path.relative_to(artifact_root).as_posix()
            for path in artifact_root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        if actual_paths != paths:
            missing = sorted(paths - actual_paths)
            unexpected = sorted(actual_paths - paths)
            raise CandidateError(
                "candidate file inventory mismatch: "
                f"missing={missing!r} unexpected={unexpected!r}"
            )
    if names != expected_names:
        raise CandidateError(
            "candidate artifact inventory must be the exact attempt-bound set: "
            f"missing={sorted(expected_names - names)!r} "
            f"unexpected={sorted(names - expected_names)!r}"
        )
    return paths


def _validate_images(
    images_value: Any,
    paths: set[str],
    *,
    comparisons_performed: bool,
    now: datetime,
) -> None:
    images = require_list(images_value, "images")
    seen: set[str] = set()
    for index, image_value in enumerate(images):
        label = f"images[{index}]"
        image = require_object(
            image_value,
            label,
            {
                "name",
                "staging_repository",
                "index_digest",
                "application_manifest_digest",
                "platform",
                "config_digest",
                "ordered_layer_digests",
                "topology",
                "sbom",
                "scan",
                "comparison",
            },
        )
        name = require_nonempty_string(image["name"], f"{label}.name")
        if name not in LEGACY_IMAGE_NAMES or name in seen:
            raise CandidateError(f"{label}.name is unexpected or duplicated: {name!r}")
        seen.add(name)
        expected_repository = f"ghcr.io/registrystack/{name}-candidate"
        if image["staging_repository"] != expected_repository:
            raise CandidateError(
                f"{label}.staging_repository must be {expected_repository}"
            )
        index_digest = require_digest(image["index_digest"], f"{label}.index_digest")
        application_digest = require_digest(
            image["application_manifest_digest"],
            f"{label}.application_manifest_digest",
        )
        if image["platform"] != "linux/amd64":
            raise CandidateError(f"{label}.platform must be linux/amd64")
        require_digest(image["config_digest"], f"{label}.config_digest")
        layers = require_list(
            image["ordered_layer_digests"], f"{label}.ordered_layer_digests"
        )
        if not layers:
            raise CandidateError(f"{label}.ordered_layer_digests must not be empty")
        for layer_index, layer in enumerate(layers):
            require_digest(layer, f"{label}.ordered_layer_digests[{layer_index}]")

        topology = require_object(
            image["topology"],
            f"{label}.topology",
            {"application_descriptor", "provenance_descriptors"},
        )
        application = require_object(
            topology["application_descriptor"],
            f"{label}.topology.application_descriptor",
            {"digest", "media_type", "platform"},
        )
        if application != {
            "digest": application_digest,
            "media_type": "application/vnd.oci.image.manifest.v1+json",
            "platform": "linux/amd64",
        }:
            raise CandidateError(
                f"{label} must contain exactly one linux/amd64 application descriptor"
            )
        attestations = require_list(
            topology["provenance_descriptors"],
            f"{label}.topology.provenance_descriptors",
        )
        if not attestations:
            raise CandidateError(f"{label} has no provenance attestation manifest")
        seen_attestations: set[str] = set()
        for item_index, item_value in enumerate(attestations):
            item_label = f"{label}.topology.provenance_descriptors[{item_index}]"
            item = require_object(
                item_value,
                item_label,
                {"digest", "media_type", "platform", "subject_digest", "kind"},
            )
            digest = require_digest(item["digest"], f"{item_label}.digest")
            if digest in seen_attestations:
                raise CandidateError(f"{label} has a duplicate provenance descriptor")
            seen_attestations.add(digest)
            if item["media_type"] != "application/vnd.oci.image.manifest.v1+json":
                raise CandidateError(f"{item_label}.media_type is unexpected")
            if item["platform"] != "unknown/unknown":
                raise CandidateError(f"{item_label}.platform must be unknown/unknown")
            if item["subject_digest"] != application_digest:
                raise CandidateError(
                    f"{item_label} is not bound to the application manifest"
                )
            if item["kind"] != "buildkit-provenance":
                raise CandidateError(f"{item_label}.kind must be buildkit-provenance")

        sbom = require_object(
            image["sbom"],
            f"{label}.sbom",
            {"spdx_path", "spdx_sha256", "syft_json_path", "syft_json_sha256"},
        )
        scan = require_object(
            image["scan"],
            f"{label}.scan",
            {"grype_path", "grype_sha256", "subject", "tool", "database"},
        )
        for record, prefix, path_field, hash_field in (
            (sbom, f"{label}.sbom", "spdx_path", "spdx_sha256"),
            (sbom, f"{label}.sbom", "syft_json_path", "syft_json_sha256"),
            (scan, f"{label}.scan", "grype_path", "grype_sha256"),
        ):
            evidence_path = safe_relative_path(
                record[path_field], f"{prefix}.{path_field}"
            )
            require_sha256(record[hash_field], f"{prefix}.{hash_field}")
            if evidence_path not in paths:
                raise CandidateError(
                    f"{prefix}.{path_field} is absent from artifact inventory"
                )
        expected_subject = f"{expected_repository}@{index_digest}"
        if scan["subject"] != expected_subject:
            raise CandidateError(f"{label}.scan.subject must be {expected_subject}")
        tool = require_object(
            scan["tool"],
            f"{label}.scan.tool",
            {"version", "binary_sha256"},
        )
        expected_tool = {
            "version": GRYPE_VERSION,
            "binary_sha256": GRYPE_LINUX_AMD64_BINARY_SHA256,
        }
        if tool != expected_tool:
            raise CandidateError(
                f"{label}.scan.tool must match the pinned Grype binary identity"
            )
        database = require_object(
            scan["database"],
            f"{label}.scan.database",
            {
                "checksum",
                "built",
                "fresh_until",
                "status_path",
                "status_sha256",
            },
        )
        require_nonempty_string(database["checksum"], f"{label}.scan.database.checksum")
        built = parse_timestamp(database["built"], f"{label}.scan.database.built")
        fresh_until = parse_timestamp(
            database["fresh_until"], f"{label}.scan.database.fresh_until"
        )
        if fresh_until <= built or fresh_until - built > timedelta(days=7):
            raise CandidateError(f"{label}.scan.database freshness window is invalid")
        if now >= fresh_until:
            raise CandidateError(f"{label}.scan.database is stale")
        status_path = safe_relative_path(
            database["status_path"], f"{label}.scan.database.status_path"
        )
        require_sha256(
            database["status_sha256"], f"{label}.scan.database.status_sha256"
        )
        if status_path not in paths:
            raise CandidateError(
                f"{label}.scan.database.status_path is absent from artifact inventory"
            )
        comparison = require_object(
            image["comparison"],
            f"{label}.comparison",
            {"config_equal", "layers_equal"},
        )
        expected_comparison = {
            "config_equal": comparisons_performed,
            "layers_equal": comparisons_performed,
        }
        if comparison != expected_comparison:
            raise CandidateError(
                f"{label}.comparison does not match the candidate build mode"
            )
    if seen != LEGACY_IMAGE_NAMES:
        raise CandidateError(
            f"image inventory must be exactly {sorted(LEGACY_IMAGE_NAMES)!r}"
        )


def validate_receipt(
    document: Any,
    *,
    artifact_root: Path | None = None,
    artifact_metadata: dict[int, tuple[str, str]] | None = None,
    expected_source_sha: str | None = None,
    expected_version: str | None = None,
    expected_release_id: str | None = None,
    expected_run_id: int | None = None,
    expected_run_attempt: int | None = None,
    now: datetime | None = None,
    promotion: bool = False,
    promoted_identities: set[str] | None = None,
    workflow_run_metadata: dict[str, Any] | None = None,
    expected_builders: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = require_object(document, "receipt", TOP_LEVEL_FIELDS)
    if receipt["schema_version"] != SCHEMA_VERSION:
        raise CandidateError(f"receipt.schema_version must be {SCHEMA_VERSION}")
    if receipt["repository"] != REPOSITORY:
        raise CandidateError(f"receipt.repository must be {REPOSITORY}")

    workflow = require_object(
        receipt["workflow"],
        "workflow",
        {"path", "ref", "sha", "run_id", "run_attempt", "event"},
    )
    if workflow["path"] != WORKFLOW_PATH:
        raise CandidateError(f"workflow.path must be {WORKFLOW_PATH}")
    if workflow["ref"] != WORKFLOW_REF:
        raise CandidateError(f"workflow.ref must be {WORKFLOW_REF}")
    workflow_sha = require_sha(workflow["sha"], "workflow.sha")
    run_id = require_positive_integer(workflow["run_id"], "workflow.run_id")
    run_attempt = require_positive_integer(
        workflow["run_attempt"], "workflow.run_attempt"
    )
    if workflow["event"] != "repository_dispatch":
        raise CandidateError("workflow.event must be repository_dispatch")

    release = require_object(
        receipt["release"],
        "release",
        {"version", "release_id", "source_sha", "tag", "proof_level"},
    )
    version = require_nonempty_string(release["version"], "release.version")
    if VERSION.fullmatch(version) is None:
        raise CandidateError("release.version must be canonical semantic version text")
    release_id = require_nonempty_string(release["release_id"], "release.release_id")
    if RELEASE_ID.fullmatch(release_id) is None:
        raise CandidateError("release.release_id is invalid")
    source_sha = require_sha(release["source_sha"], "release.source_sha")
    if release["tag"] != f"v{version}":
        raise CandidateError("release.tag must exactly match release.version")
    if release["proof_level"] not in {"standard", "extended"}:
        raise CandidateError("release.proof_level must be standard or extended")
    if workflow_sha != source_sha:
        raise CandidateError(
            "workflow.sha must equal release.source_sha so protected default-branch code "
            "and the candidate source are the same exact commit"
        )

    validity = require_object(
        receipt["validity"], "validity", {"created_at", "expires_at"}
    )
    created_at = parse_timestamp(validity["created_at"], "validity.created_at")
    expires_at = parse_timestamp(validity["expires_at"], "validity.expires_at")
    if expires_at <= created_at or expires_at - created_at > MAX_RETENTION:
        raise CandidateError(
            "candidate validity must be positive and no longer than 7 days"
        )
    current = now or datetime.now(timezone.utc)
    if created_at > current + timedelta(minutes=5):
        raise CandidateError("candidate creation timestamp is future-dated")
    if promotion:
        if workflow_run_metadata is None:
            raise CandidateError(
                "promotion requires independently fetched trusted workflow-run metadata"
            )
        workflow_run = require_object(
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
        workflow_run_created_at = parse_timestamp(
            workflow_run["created_at"], "trusted workflow run.created_at"
        )
        workflow_run_expectations = {
            "id": run_id,
            "run_attempt": run_attempt,
            "event": "repository_dispatch",
            "head_sha": source_sha,
            "path": WORKFLOW_PATH,
            "status": "completed",
            "conclusion": "success",
        }
        for field, expected in workflow_run_expectations.items():
            if workflow_run[field] != expected:
                raise CandidateError(
                    f"trusted workflow run {field} mismatch: "
                    f"expected {expected!r}, got {workflow_run[field]!r}"
                )
        if created_at < workflow_run_created_at:
            raise CandidateError(
                "receipt creation timestamp predates the trusted workflow run"
            )
        if (
            current - workflow_run_created_at > MAX_PROMOTION_AGE
            or current >= expires_at
        ):
            raise CandidateError(
                "candidate trusted workflow run is stale or receipt is expired for promotion"
            )

    builders = require_object(
        receipt["builders"],
        "builders",
        {
            "binary_image",
            "binary_fingerprint",
            "binary_recipe_fingerprint",
            "image_buildkit_image",
            "image_buildx_version",
            "image_recipe_fingerprint",
        },
    )
    require_nonempty_string(builders["binary_image"], "builders.binary_image")
    require_sha256(builders["binary_fingerprint"], "builders.binary_fingerprint")
    require_sha256(
        builders["binary_recipe_fingerprint"], "builders.binary_recipe_fingerprint"
    )
    require_nonempty_string(
        builders["image_buildkit_image"], "builders.image_buildkit_image"
    )
    require_nonempty_string(
        builders["image_buildx_version"], "builders.image_buildx_version"
    )
    require_sha256(
        builders["image_recipe_fingerprint"], "builders.image_recipe_fingerprint"
    )
    if expected_builders is not None and builders != expected_builders:
        raise CandidateError(
            "candidate builder or recipe fingerprints do not match the trusted source"
        )

    comparisons_performed = _validate_builds(receipt["builds"])
    expected_artifact_names = {
        f"registry-stack-candidate-build-a-{run_id}-{run_attempt}",
        f"registry-stack-candidate-macos-arm64-{run_id}-{run_attempt}",
        f"registry-stack-candidate-linux-arm64-{run_id}-{run_attempt}",
        f"registry-stack-release-candidate-payload-{run_id}-{run_attempt}",
    }
    if comparisons_performed:
        expected_artifact_names.add(
            f"registry-stack-candidate-build-b-{run_id}-{run_attempt}"
        )
    paths = _validate_artifacts(
        receipt["artifacts"],
        artifact_root=artifact_root,
        artifact_metadata=artifact_metadata,
        expected_names=expected_artifact_names,
    )
    _validate_images(
        receipt["images"],
        paths,
        comparisons_performed=comparisons_performed,
        now=current,
    )

    comparisons = require_object(
        receipt["comparisons"],
        "comparisons",
        {"binary_bytes", "image_config_and_layers"},
    )
    expected_comparisons = {
        "binary_bytes": comparisons_performed,
        "image_config_and_layers": comparisons_performed,
    }
    if comparisons != expected_comparisons:
        raise CandidateError(
            "candidate comparison record does not match the candidate build mode"
        )
    scans = require_object(receipt["scans"], "scans", {"policy", "immutable_digests"})
    if scans != {"policy": "passed", "immutable_digests": True}:
        raise CandidateError("candidate scan policy did not pass on immutable digests")

    storage = require_object(
        receipt["storage"],
        "storage",
        {"budget_status", "measurement_path", "measurement_sha256"},
    )
    if storage["budget_status"] not in {"enforced", "measurement_required"}:
        raise CandidateError("storage.budget_status is invalid")
    measurement_path = safe_relative_path(
        storage["measurement_path"], "storage.measurement_path"
    )
    require_sha256(storage["measurement_sha256"], "storage.measurement_sha256")
    if measurement_path not in paths:
        raise CandidateError("storage measurement is absent from artifact inventory")

    attestation = require_object(
        receipt["attestation"],
        "attestation",
        {"receipt_subject", "workflow_identity"},
    )
    if attestation["receipt_subject"] != "release-candidate-receipt.json":
        raise CandidateError(
            "attestation.receipt_subject must be release-candidate-receipt.json"
        )
    if attestation["workflow_identity"] != (
        f"{REPOSITORY}/{WORKFLOW_PATH}@{WORKFLOW_REF}"
    ):
        raise CandidateError("attestation.workflow_identity is unexpected")

    promotion_state = require_object(
        receipt["promotion"], "promotion", {"state", "identity"}
    )
    expected_identity = f"{release_id}:{version}"
    if promotion_state != {"state": "candidate", "identity": expected_identity}:
        raise CandidateError("promotion state or release identity is invalid")
    if promoted_identities is not None and expected_identity in promoted_identities:
        raise CandidateError(
            f"release identity {expected_identity} has already been promoted"
        )

    expectations = (
        ("source SHA", expected_source_sha, source_sha),
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
    return receipt


def artifact_metadata_from_json(document: Any) -> dict[int, tuple[str, str]]:
    if not isinstance(document, dict) or not isinstance(
        document.get("artifacts"), list
    ):
        raise CandidateError("artifact metadata must contain an artifacts array")
    metadata: dict[int, tuple[str, str]] = {}
    for index, item in enumerate(
        require_list(document["artifacts"], "artifact metadata.artifacts")
    ):
        if not isinstance(item, dict):
            raise CandidateError(
                f"artifact metadata.artifacts[{index}] must be an object"
            )
        artifact_id = require_positive_integer(
            item.get("id"), f"artifact metadata.artifacts[{index}].id"
        )
        name = require_nonempty_string(
            item.get("name"), f"artifact metadata.artifacts[{index}].name"
        )
        digest = require_nonempty_string(
            item.get("digest"), f"artifact metadata.artifacts[{index}].digest"
        )
        if not digest.startswith("sha256:"):
            raise CandidateError(
                f"artifact metadata.artifacts[{index}].digest must be sha256-prefixed"
            )
        sha = require_sha256(
            digest.removeprefix("sha256:"),
            f"artifact metadata.artifacts[{index}].digest",
        )
        if artifact_id in metadata:
            raise CandidateError(f"duplicate artifact metadata ID {artifact_id}")
        metadata[artifact_id] = (name, sha)
    return metadata


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


def validate_promotion_state(
    document: Any,
    *,
    receipt: dict[str, Any],
    receipt_sha256: str,
    phase: str,
) -> dict[str, Any]:
    """Reject replay and partial publication before a promotion side effect."""

    require_sha256(receipt_sha256, "receipt_sha256")
    if phase not in {"prewrite", "prerelease", "final"}:
        raise CandidateError(f"unknown promotion state phase {phase!r}")
    state = require_object(
        document,
        "promotion state",
        {
            "schema_version",
            "github_release",
            "public_images",
            "promoted_candidates",
        },
    )
    if state["schema_version"] != PROMOTION_STATE_SCHEMA:
        raise CandidateError(f"promotion state schema must be {PROMOTION_STATE_SCHEMA}")
    release_state = require_object(
        state["github_release"],
        "promotion state.github_release",
        {"exists", "asset_names"},
    )
    if not isinstance(release_state["exists"], bool):
        raise CandidateError("promotion state.github_release.exists must be boolean")
    asset_names = require_list(
        release_state["asset_names"], "promotion state.github_release.asset_names"
    )
    if any(not isinstance(name, str) or not name for name in asset_names):
        raise CandidateError(
            "promotion state.github_release.asset_names must contain non-empty strings"
        )
    if len(asset_names) != len(set(asset_names)):
        raise CandidateError("promotion state GitHub Release assets are duplicated")
    if not release_state["exists"] and asset_names:
        raise CandidateError("absent GitHub Release cannot contain assets")

    public_images = require_object(
        state["public_images"],
        "promotion state.public_images",
        LEGACY_IMAGE_NAMES,
    )
    expected_digests = {
        image["name"]: image["index_digest"] for image in receipt["images"]
    }
    for name, value in public_images.items():
        if value is not None:
            require_digest(value, f"promotion state.public_images.{name}")

    promoted = require_list(
        state["promoted_candidates"], "promotion state.promoted_candidates"
    )
    expected_identity = receipt["promotion"]["identity"]
    run_id = receipt["workflow"]["run_id"]
    run_attempt = receipt["workflow"]["run_attempt"]
    matching_promotions = 0
    for index, record_value in enumerate(promoted):
        record = require_object(
            record_value,
            f"promotion state.promoted_candidates[{index}]",
            {"identity", "run_id", "run_attempt", "receipt_sha256"},
        )
        require_nonempty_string(
            record["identity"],
            f"promotion state.promoted_candidates[{index}].identity",
        )
        require_positive_integer(
            record["run_id"],
            f"promotion state.promoted_candidates[{index}].run_id",
        )
        require_positive_integer(
            record["run_attempt"],
            f"promotion state.promoted_candidates[{index}].run_attempt",
        )
        require_sha256(
            record["receipt_sha256"],
            f"promotion state.promoted_candidates[{index}].receipt_sha256",
        )
        matches = (
            record["identity"] == expected_identity
            or (record["run_id"] == run_id and record["run_attempt"] == run_attempt)
            or record["receipt_sha256"] == receipt_sha256
        )
        if matches:
            matching_promotions += 1
        if matches and phase != "final":
            raise CandidateError(
                "release identity, candidate run attempt, or receipt has already "
                "been promoted"
            )

    if phase == "prewrite":
        if release_state["exists"] or any(
            public_images[name] is not None for name in LEGACY_IMAGE_NAMES
        ):
            raise CandidateError(
                "prewrite promotion state is not empty; partial publication or replay "
                "requires a new patch release"
            )
    elif phase == "prerelease":
        if release_state["exists"]:
            raise CandidateError(
                "GitHub Release already exists before release creation"
            )
        if public_images != expected_digests:
            raise CandidateError(
                "public image state does not exactly match the promoted candidate"
            )
    else:
        if not release_state["exists"]:
            raise CandidateError("final promotion state has no GitHub Release")
        if public_images != expected_digests:
            raise CandidateError(
                "final public image state does not match the candidate receipt"
            )
        if matching_promotions != 1:
            raise CandidateError(
                "final promotion state must contain exactly one public receipt "
                "for this release identity and candidate attempt"
            )
    return state


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def write_closed_receipt(draft_path: Path, output_path: Path) -> None:
    document = read_json(draft_path)
    validate_receipt(document)
    if output_path.is_symlink() or (output_path.exists() and not output_path.is_file()):
        raise CandidateError(
            f"receipt output must be a regular non-symlink path: {output_path}"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json(document))


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


def render_legacy_tag_binding(
    run_id: int, run_attempt: int, receipt_sha256: str
) -> str:
    require_positive_integer(run_id, "run_id")
    require_positive_integer(run_attempt, "run_attempt")
    require_sha256(receipt_sha256, "receipt_sha256")
    return (
        f"{LEGACY_TAG_BINDING_HEADER}\n"
        f"run_id: {run_id}\n"
        f"run_attempt: {run_attempt}\n"
        f"receipt_sha256: {receipt_sha256}\n"
    )


def parse_tag_binding(message: str) -> dict[str, Any]:
    if "\r" in message:
        raise CandidateError("annotated tag binding must use LF line endings")
    formats = (
        (TAG_BINDING_HEADER, "manifest_sha256"),
        (LEGACY_TAG_BINDING_HEADER, "receipt_sha256"),
    )
    for header, digest_field in formats:
        match = re.fullmatch(
            re.escape(header)
            + r"\nrun_id: ([1-9][0-9]*)"
            + r"\nrun_attempt: ([1-9][0-9]*)"
            + rf"\n{digest_field}: ([0-9a-f]{{64}})\n{{0,2}}",
            message,
        )
        if match is not None:
            return {
                "schema_version": (
                    V2_SCHEMA_VERSION
                    if digest_field == "manifest_sha256"
                    else SCHEMA_VERSION
                ),
                "run_id": int(match.group(1)),
                "run_attempt": int(match.group(2)),
                digest_field: match.group(3),
            }
    raise CandidateError(
        "annotated tag message must use an exact supported release-candidate "
        "binding format"
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

    seal = subparsers.add_parser("seal")
    seal.add_argument("--draft", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)

    seal_candidate = subparsers.add_parser("seal-candidate")
    seal_candidate.add_argument("--draft", type=Path, required=True)
    seal_candidate.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--artifact-root", type=Path)
    verify.add_argument("--artifact-metadata", type=Path)
    verify.add_argument("--source-sha")
    verify.add_argument("--version")
    verify.add_argument("--release-id")
    verify.add_argument("--run-id", type=int)
    verify.add_argument("--run-attempt", type=int)
    verify.add_argument("--promotion", action="store_true")
    verify.add_argument(
        "--trusted-run-metadata", dest="workflow_run_metadata", type=Path
    )
    verify.add_argument("--expected-builders", type=Path)
    verify.add_argument("--promoted-identities", type=Path)

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

    attempt_inventory = subparsers.add_parser("verify-attempt-artifacts")
    attempt_inventory.add_argument("--artifact-metadata", type=Path, required=True)
    attempt_inventory.add_argument("--run-id", type=int, required=True)
    attempt_inventory.add_argument("--run-attempt", type=int, required=True)

    binding = subparsers.add_parser("render-tag-binding")
    binding.add_argument("--run-id", type=int, required=True)
    binding.add_argument("--run-attempt", type=int, required=True)
    binding.add_argument("--manifest-sha256", required=True)

    verify_binding = subparsers.add_parser("verify-tag-binding")
    verify_binding.add_argument("--message", type=Path, required=True)
    candidate_document = verify_binding.add_mutually_exclusive_group(required=True)
    candidate_document.add_argument("--manifest", type=Path)
    candidate_document.add_argument("--receipt", type=Path)
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
    verify_binding.add_argument("--expected-builders", type=Path)

    promotion_state = subparsers.add_parser("verify-promotion-state")
    promotion_state.add_argument("--state", type=Path, required=True)
    promotion_state.add_argument("--receipt", type=Path, required=True)
    promotion_state.add_argument("--receipt-sha256", required=True)
    promotion_state.add_argument(
        "--phase",
        choices=("prewrite", "prerelease", "final"),
        required=True,
    )

    slsa_subjects = subparsers.add_parser("verify-slsa-subjects")
    slsa_subjects.add_argument("--provenance", type=Path, required=True)
    slsa_subjects.add_argument("--contract", type=Path, required=True)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "seal":
            write_closed_receipt(args.draft, args.output)
            print(f"sealed closed candidate receipt {args.output}")
            return 0
        if args.command == "seal-candidate":
            write_candidate_manifest(args.draft, args.output)
            print(f"sealed candidate manifest {args.output}")
            return 0
        if args.command == "verify":
            metadata = (
                artifact_metadata_from_json(read_json(args.artifact_metadata))
                if args.artifact_metadata
                else None
            )
            receipt = validate_receipt(
                read_json(args.receipt),
                artifact_root=args.artifact_root,
                artifact_metadata=metadata,
                expected_source_sha=args.source_sha,
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
                expected_builders=(
                    read_json(args.expected_builders)
                    if args.expected_builders
                    else None
                ),
                promoted_identities=(
                    set(
                        require_list(
                            read_json(args.promoted_identities), "promoted identities"
                        )
                    )
                    if args.promoted_identities
                    else None
                ),
            )
            print(
                "verified release candidate "
                f"{receipt['release']['release_id']} {receipt['release']['tag']} "
                f"from run {receipt['workflow']['run_id']}/"
                f"{receipt['workflow']['run_attempt']}"
            )
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
        if args.command == "verify-attempt-artifacts":
            selected = validate_attempt_artifact_inventory(
                read_json(args.artifact_metadata),
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            print(json.dumps(selected, indent=2, sort_keys=True))
            return 0
        if args.command == "render-tag-binding":
            print(
                render_tag_binding(args.run_id, args.run_attempt, args.manifest_sha256),
                end="",
            )
            return 0
        if args.command == "verify-promotion-state":
            validate_promotion_state(
                read_json(args.state),
                receipt=validate_receipt(read_json(args.receipt)),
                receipt_sha256=args.receipt_sha256,
                phase=args.phase,
            )
            print(f"verified promotion state phase {args.phase}")
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
            if args.manifest is not None:
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
            else:
                receipt_sha = sha256_file(args.receipt)
                if binding.get("receipt_sha256") != receipt_sha:
                    raise CandidateError(
                        "annotated tag receipt_sha256 does not match receipt bytes"
                    )
                if args.expected_builders is None:
                    raise CandidateError(
                        "historical receipt verification requires --expected-builders"
                    )
                receipt = validate_receipt(
                    read_json(args.receipt),
                    expected_run_id=binding["run_id"],
                    expected_run_attempt=binding["run_attempt"],
                    promotion=True,
                    workflow_run_metadata=run_metadata,
                    expected_builders=read_json(args.expected_builders),
                )
                workflow = receipt["workflow"]
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
