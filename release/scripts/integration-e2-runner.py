#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and validate candidate-neutral external integration evidence.

This tool deliberately does not drive an unreviewed live product instance. It
closes the portable plan, candidate trust checks, and public evidence boundary
while leaving instance-specific orchestration to an approved operator wrapper.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "release" / "conformance" / "integrations"
PROFILE_DIR = CONFIG_DIR / "profiles"
SCHEMA_PATH = CONFIG_DIR / "schema" / "run-result.schema.json"
PROFILE_SCHEMA = "registry.release.integration_e2_profile.v1"
RESULT_SCHEMA = "registry.release.integration_e2_run_result.v1"
SUPPORT_STATUS = "Registry Stack-supported unofficial integration profile"
CAPSULE_REPOSITORY = "registrystack/registry-stack"
SLSA_SOURCE_URI = "github.com/registrystack/registry-stack"
RELEASE_WORKFLOW = (
    "https://github.com/registrystack/registry-stack/.github/workflows/"
    "release.yml@refs/tags/{tag}"
)
PROFILE_FILES = {
    "opencrvs-dci-v1.9": "opencrvs-dci-v1.9.profile.json",
    "dhis2-tracker-2.41.9": "dhis2-tracker-2.41.9.profile.json",
}
CASE_IDS = (
    "authorized-match",
    "authorized-no-match",
    "ambiguity",
    "invalid-selector",
    "wrong-caller",
    "missing-scope",
    "wrong-purpose",
    "stale-contract",
    "subject-mismatch",
    "source-authorization-failure",
    "deadline-enforced",
)
TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_ASSET_BYTES = 128 * 1024 * 1024
SAFE_CANARY = re.compile(rb"^[A-Za-z0-9._:@-]{8,128}$")
REQUIRED_LIMITATIONS = {
    "unofficial-integration-profile",
    "single-pinned-product-version",
    "single-reviewed-read-operation",
    "non-production-instance",
    "not-product-certification",
    "not-general-country-system-conformance",
}
EXPECTED_PROFILE_BINDINGS = {
    "opencrvs-dci-v1.9": {
        "starter": "opencrvs-dci",
        "product": "opencrvs",
        "baseline": [
            ("dci-adapter", "v1.9.0-rc.1", "5e31d1e381d4bd8c7c74112d714fd49d263c6df7"),
            ("core", "v1.9.5", "7243ccb79eb84254420878ff5146c6e50f084554"),
            ("farajaland", "v1.9.5", "3c1a5612d8d7bebddd43463682860b38ef14bcb4"),
        ],
        "operations": [
            ("oauth-token", "credential", "POST", "owner-attested", 1),
            ("jwks", "verification", "GET", "owner-attested", 1),
            ("signed-uin-search", "data", "POST", "/registry/sync/search", 1),
        ],
        "inputs": (
            "OPENCRVS_SOURCE_ORIGIN",
            "OPENCRVS_OAUTH_ORIGIN",
            "OPENCRVS_OAUTH_PATH",
            "OPENCRVS_JWKS_ORIGIN",
            "OPENCRVS_JWKS_PATH",
            "OPENCRVS_SENDER_ID",
            "OPENCRVS_RECEIVER_ID",
            "OPENCRVS_CLIENT_ID",
            "OPENCRVS_CLIENT_SECRET",
            "OPENCRVS_MATCH_UIN",
            "OPENCRVS_NO_MATCH_UIN",
            "OPENCRVS_AMBIGUOUS_UIN",
            "OPENCRVS_MISMATCH_UIN",
            "REGISTRY_INTEGRATION_E2_SOURCE_PROBE",
            "REGISTRY_INTEGRATION_E2_CANARY_FILE",
        ),
        "case_access": (
            "contacted_once",
            "contacted_once",
            "contacted_once",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "contacted_once",
            "not_contacted",
            "contacted_once",
        ),
        "result_codes": (
            "match",
            "no-match",
            "ambiguous",
            "invalid-selector",
            "denied-wrong-caller",
            "denied-missing-scope",
            "denied-wrong-purpose",
            "denied-stale-contract",
            "subject-mismatch",
            "source-authorization-failure",
            "deadline-exceeded",
        ),
        "limits": (60, 1800, 8388608, 1048576, 300),
    },
    "dhis2-tracker-2.41.9": {
        "starter": "dhis2-tracker",
        "product": "dhis2-tracker",
        "baseline": [
            ("dhis2", "2.41.9", "ce6404687f6a5806e2661cffe4bc7a1d9b2ad2ed"),
        ],
        "operations": [
            (
                "tracked-entity-read",
                "data",
                "GET",
                "/api/tracker/trackedEntities/{uid}",
                1,
            ),
        ],
        "inputs": (
            "DHIS2_SOURCE_ORIGIN",
            "DHIS2_USERNAME",
            "DHIS2_PASSWORD",
            "DHIS2_CHILD_PROGRAM_UID",
            "DHIS2_MATERNAL_PROGRAM_UID",
            "DHIS2_TB_PROGRAM_UID",
            "DHIS2_CHILD_VISIT_STAGE_UID",
            "DHIS2_BCG_BIRTH_STAGE_UID",
            "DHIS2_OPV_BIRTH_STAGE_UID",
            "DHIS2_MEASLES_STAGE_UID",
            "DHIS2_FIRST_NAME_ATTRIBUTE_UID",
            "DHIS2_LAST_NAME_ATTRIBUTE_UID",
            "DHIS2_BIRTH_DATE_ATTRIBUTE_UID",
            "DHIS2_RECONCILIATION_ATTRIBUTE_UID",
            "DHIS2_MATCH_TRACKED_ENTITY",
            "DHIS2_NO_MATCH_TRACKED_ENTITY",
            "DHIS2_MISMATCH_TRACKED_ENTITY",
            "REGISTRY_INTEGRATION_E2_SOURCE_PROBE",
            "REGISTRY_INTEGRATION_E2_CANARY_FILE",
        ),
        "case_access": (
            "contacted_once",
            "contacted_once",
            "not_applicable",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "not_contacted",
            "contacted_once",
            "contacted_once",
            "contacted_once",
        ),
        "result_codes": (
            "match",
            "no-match",
            "not-applicable",
            "invalid-selector",
            "denied-wrong-caller",
            "denied-missing-scope",
            "denied-wrong-purpose",
            "denied-stale-contract",
            "subject-mismatch",
            "source-authorization-failure",
            "deadline-exceeded",
        ),
        "limits": (30, 1200, 8388608, 1048576, 300),
    },
}


class RunnerError(RuntimeError):
    """A user-actionable integration evidence error."""


def load_json(path: Path, *, max_bytes: int = 1024 * 1024) -> Any:
    require_regular_file(path, max_bytes=max_bytes)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"could not read valid JSON from {path}: {exc}") from exc


def require_regular_file(path: Path, *, max_bytes: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RunnerError(f"required file is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RunnerError(f"required path must be a regular, non-symlink file: {path}")
    if info.st_size <= 0 or info.st_size > max_bytes:
        raise RunnerError(
            f"file size for {path} must be between 1 and {max_bytes} bytes"
        )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be an object")
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise RunnerError(f"{label} has invalid fields: {'; '.join(details)}")
    return value


def load_profile(profile_id: str) -> dict[str, Any]:
    try:
        path = PROFILE_DIR / PROFILE_FILES[profile_id]
    except KeyError as exc:
        raise RunnerError(f"unknown integration profile: {profile_id}") from exc
    profile = load_json(path)
    validate_profile(profile, path.name)
    if profile["profile_id"] != profile_id:
        raise RunnerError(f"{path.name} declares the wrong profile_id")
    return profile


def validate_profile(value: Any, label: str) -> None:
    profile = require_object(
        value,
        label,
        {
            "schema_version",
            "profile_id",
            "support_status",
            "starter",
            "source",
            "authored_contract",
            "dynamic_inputs",
            "cases",
            "prerequisites",
            "limits",
        },
    )
    if profile["schema_version"] != PROFILE_SCHEMA:
        raise RunnerError(f"{label} has an unsupported schema_version")
    if profile["profile_id"] not in PROFILE_FILES:
        raise RunnerError(f"{label} has an unknown profile_id")
    expected = EXPECTED_PROFILE_BINDINGS[profile["profile_id"]]
    if profile["support_status"] != SUPPORT_STATUS:
        raise RunnerError(f"{label} must use the reviewed support wording")
    if profile["starter"] != expected["starter"]:
        raise RunnerError(f"{label} has the wrong pinned starter")
    authored = require_object(
        profile["authored_contract"],
        f"{label}.authored_contract",
        {"integration_alias", "generated_yaml_edits_allowed", "reviewed_changes"},
    )
    if authored["generated_yaml_edits_allowed"] is not False:
        raise RunnerError(f"{label} must prohibit generated YAML edits")
    if (
        not isinstance(authored["integration_alias"], str)
        or not isinstance(authored["reviewed_changes"], list)
        or not authored["reviewed_changes"]
    ):
        raise RunnerError(
            f"{label}.authored_contract must contain reviewed authored changes"
        )

    source = require_object(
        profile["source"], f"{label}.source", {"product", "baseline", "operations"}
    )
    if source["product"] != expected["product"]:
        raise RunnerError(f"{label} has the wrong pinned source product")
    baseline = source["baseline"]
    if not isinstance(baseline, list):
        raise RunnerError(f"{label}.source.baseline must be an array")
    baseline_tuples = []
    for index, item in enumerate(baseline):
        entry = require_object(
            item,
            f"{label}.source.baseline[{index}]",
            {"component", "version", "commit"},
        )
        baseline_tuples.append((entry["component"], entry["version"], entry["commit"]))
    if baseline_tuples != expected["baseline"]:
        raise RunnerError(f"{label} does not use the exact reviewed upstream baseline")
    operations = source["operations"]
    if not isinstance(operations, list):
        raise RunnerError(f"{label}.source.operations must be an array")
    operation_tuples = []
    for index, item in enumerate(operations):
        if not isinstance(item, dict):
            raise RunnerError(f"{label}.source.operations[{index}] must be an object")
        allowed = {
            "id",
            "role",
            "method",
            "path",
            "max_calls",
            "selector",
            "field_projection",
        }
        required = {"id", "role", "method", "path", "max_calls"}
        if set(item) - allowed or required - set(item):
            raise RunnerError(f"{label}.source.operations[{index}] has invalid fields")
        operation_tuples.append(
            (item["id"], item["role"], item["method"], item["path"], item["max_calls"])
        )
        expected_keys = required | (
            {"selector", "field_projection"}
            if item["id"] == "tracked-entity-read"
            else {"selector"}
            if item["id"] == "signed-uin-search"
            else set()
        )
        if set(item) != expected_keys:
            raise RunnerError(
                f"{label}.source.operations[{index}] has unexpected optional fields"
            )
    if operation_tuples != expected["operations"]:
        raise RunnerError(f"{label} does not use the exact reviewed source operations")
    data_operation = next(item for item in operations if item["role"] == "data")
    if data_operation.get("selector") not in {"exact UIN", "exact tracked entity UID"}:
        raise RunnerError(
            f"{label} data operation must use the reviewed exact selector"
        )
    if (
        profile["profile_id"].startswith("dhis2")
        and data_operation.get("field_projection")
        != "trackedEntity,attributes[attribute,value],enrollments[program,status,events[programStage,status]]"
    ):
        raise RunnerError(f"{label} does not use the reviewed DHIS2 field projection")

    dynamic = profile["dynamic_inputs"]
    if not isinstance(dynamic, list) or not dynamic:
        raise RunnerError(f"{label}.dynamic_inputs must be a non-empty list")
    env_names = []
    for index, item in enumerate(dynamic):
        entry = require_object(
            item,
            f"{label}.dynamic_inputs[{index}]",
            {"env", "classification", "purpose"},
        )
        if (
            entry["classification"] not in {"restricted", "secret", "subject"}
            or not isinstance(entry["purpose"], str)
            or not entry["purpose"]
        ):
            raise RunnerError(
                f"{label}.dynamic_inputs[{index}] has an invalid classification or purpose"
            )
        env_names.append(entry["env"])
    if tuple(env_names) != expected["inputs"]:
        raise RunnerError(
            f"{label}.dynamic_inputs does not match the reviewed input names"
        )
    cases = profile["cases"]
    if not isinstance(cases, list):
        raise RunnerError(f"{label}.cases must be an array")
    for index, case in enumerate(cases):
        require_object(
            case,
            f"{label}.cases[{index}]",
            {"id", "expected_result_code", "expected_source_data_access"},
        )
    if [case["id"] for case in cases] != list(CASE_IDS):
        raise RunnerError(f"{label}.cases must contain the closed ordered case set")
    allowed_access = {"not_contacted", "contacted_once", "not_applicable"}
    if any(
        case.get("expected_source_data_access") not in allowed_access for case in cases
    ):
        raise RunnerError(
            f"{label}.cases contains an invalid source access expectation"
        )
    if (
        tuple(case["expected_source_data_access"] for case in cases)
        != expected["case_access"]
    ):
        raise RunnerError(
            f"{label}.cases does not match the reviewed source access contract"
        )
    if (
        tuple(case["expected_result_code"] for case in cases)
        != expected["result_codes"]
    ):
        raise RunnerError(
            f"{label}.cases does not match the reviewed safe result codes"
        )
    prerequisites = profile["prerequisites"]
    if (
        not isinstance(prerequisites, list)
        or len(prerequisites) < 5
        or any(not isinstance(item, str) or not item for item in prerequisites)
    ):
        raise RunnerError(
            f"{label}.prerequisites must make external ownership explicit"
        )
    limits = require_object(
        profile["limits"],
        f"{label}.limits",
        {
            "case_timeout_seconds",
            "run_timeout_seconds",
            "raw_evidence_bytes",
            "public_result_bytes",
            "teardown_timeout_seconds",
        },
    )
    if any(not isinstance(item, int) or item <= 0 for item in limits.values()):
        raise RunnerError(f"{label}.limits must contain positive integers")
    actual_limits = tuple(
        limits[name]
        for name in (
            "case_timeout_seconds",
            "run_timeout_seconds",
            "raw_evidence_bytes",
            "public_result_bytes",
            "teardown_timeout_seconds",
        )
    )
    if actual_limits != expected["limits"]:
        raise RunnerError(
            f"{label}.limits does not match the reviewed bounded contract"
        )


def validate_packet() -> None:
    schema = load_json(SCHEMA_PATH)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise RunnerError("run result schema must use JSON Schema draft 2020-12")
    if schema.get("additionalProperties") is not False:
        raise RunnerError("run result schema must be closed")
    assert_closed_schema(schema)
    for profile_id in PROFILE_FILES:
        load_profile(profile_id)


def assert_closed_schema(value: Any, label: str = "schema") -> None:
    if isinstance(value, dict):
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            raise RunnerError(f"{label} contains an open object schema")
        for name, item in value.items():
            assert_closed_schema(item, f"{label}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_closed_schema(item, f"{label}[{index}]")


def parse_checksums(path: Path) -> dict[str, str]:
    require_regular_file(path, max_bytes=1024 * 1024)
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  \*?([^/\x00]+)", line)
        if match is None:
            raise RunnerError(f"SHA256SUMS line {line_number} has an unsafe format")
        digest, name = match.groups()
        if name in checksums:
            raise RunnerError(f"SHA256SUMS contains duplicate entry {name}")
        checksums[name] = digest
    return checksums


def signed_subject_names(tag: str) -> tuple[str, ...]:
    binary = f"registryctl-{tag}-linux-amd64"
    image_lock = f"registryctl-{tag}-image-lock.json"
    return (
        binary,
        image_lock,
        f"{image_lock}.spdx.json",
        f"registry-stack-{tag}-release-capsule.json",
        "registry-relay.digest",
        "registry-notary.digest",
    )


def required_asset_names(tag: str) -> set[str]:
    subjects = signed_subject_names(tag)
    return {
        *subjects,
        *(f"{name}.sig" for name in subjects),
        *(f"{name}.pem" for name in subjects),
        "SHA256SUMS",
        f"registry-stack-{tag}-release-provenance.intoto.jsonl",
    }


def run_authenticity_command(command: list[str]) -> None:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RunnerError(f"authenticity command failed ({command[0]}){suffix}")


def verify_authenticity(
    asset_dir: Path,
    tag: str,
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
        raise RunnerError(
            "candidate authenticity verification requires installed "
            + " and ".join(missing)
        )
    provenance = asset_dir / f"registry-stack-{tag}-release-provenance.intoto.jsonl"
    identity = RELEASE_WORKFLOW.format(tag=tag)
    for name in signed_subject_names(tag):
        subject = asset_dir / name
        command_runner(
            [
                cosign,
                "verify-blob",
                str(subject),
                "--signature",
                str(asset_dir / f"{name}.sig"),
                "--certificate",
                str(asset_dir / f"{name}.pem"),
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


def exact_digest_file(path: Path, repository: str) -> str:
    require_regular_file(path, max_bytes=1024)
    value = path.read_text(encoding="utf-8").strip()
    expected = re.compile(
        rf"^ghcr\.io/registrystack/{re.escape(repository)}@sha256:[0-9a-f]{{64}}$"
    )
    if expected.fullmatch(value) is None:
        raise RunnerError(
            f"{path.name} must contain one digest-bound {repository} reference"
        )
    return value


def find_named(items: Any, name: str, label: str) -> dict[str, Any]:
    if not isinstance(items, list):
        raise RunnerError(f"release capsule {label} must be an array")
    matches = [
        item for item in items if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise RunnerError(
            f"release capsule must contain exactly one {label} entry for {name}"
        )
    return matches[0]


def verify_file_sbom(path: Path, subject_name: str, subject_sha256: str) -> None:
    document = load_json(path, max_bytes=16 * 1024 * 1024)
    if not isinstance(document, dict):
        raise RunnerError(f"{path.name} must be an SPDX JSON object")
    described = document.get("documentDescribes")
    packages = document.get("packages")
    if not isinstance(described, list) or not isinstance(packages, list):
        raise RunnerError(f"{path.name} must contain SPDX subjects and packages")
    described_ids = {item for item in described if isinstance(item, str)}
    for package in packages:
        if not isinstance(package, dict) or package.get("SPDXID") not in described_ids:
            continue
        if (
            package.get("name") != subject_name
            and package.get("packageFileName") != subject_name
        ):
            continue
        checksums = package.get("checksums")
        if isinstance(checksums, list) and any(
            isinstance(item, dict)
            and item.get("algorithm") == "SHA256"
            and item.get("checksumValue") == subject_sha256
            for item in checksums
        ):
            return
    raise RunnerError(
        f"{path.name} does not describe {subject_name} at its actual SHA-256"
    )


def require_candidate_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RunnerError(
            f"candidate asset directory is unavailable: {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RunnerError(
            "candidate asset directory must be a real, non-symlink directory"
        )


@contextmanager
def candidate_asset_snapshot(asset_dir: Path, tag: str) -> Iterator[Path]:
    """Copy the closed candidate set through no-follow descriptors and remove it."""
    require_candidate_directory(asset_dir)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RunnerError("candidate snapshotting requires O_NOFOLLOW and O_DIRECTORY")
    directory_fd = None
    try:
        directory_fd = os.open(
            asset_dir,
            os.O_RDONLY | os.O_CLOEXEC | no_follow | directory_flag,
        )
        required = required_asset_names(tag)
        actual = set(os.listdir(directory_fd))
        missing = required - actual
        unknown = actual - required
        if missing or unknown:
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(missing)))
            if unknown:
                details.append("unexpected " + ", ".join(sorted(unknown)))
            raise RunnerError(
                "candidate asset set is not closed: " + "; ".join(details)
            )

        with tempfile.TemporaryDirectory(
            prefix="registry-integration-e2-candidate-"
        ) as temporary:
            snapshot = Path(temporary)
            snapshot.chmod(0o700)
            binary_name = f"registryctl-{tag}-linux-amd64"
            for name in sorted(required):
                source_fd = None
                destination_fd = None
                try:
                    source_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | no_follow,
                        dir_fd=directory_fd,
                    )
                    source_info = os.fstat(source_fd)
                    if not stat.S_ISREG(source_info.st_mode):
                        raise RunnerError(
                            f"candidate asset must be a regular, non-symlink file: {name}"
                        )
                    if (
                        source_info.st_size <= 0
                        or source_info.st_size > MAX_ASSET_BYTES
                    ):
                        raise RunnerError(
                            f"candidate asset size for {name} must be between 1 and {MAX_ASSET_BYTES} bytes"
                        )
                    destination = snapshot / name
                    destination_fd = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | no_follow,
                        0o600,
                    )
                    with os.fdopen(source_fd, "rb") as source_handle:
                        source_fd = None
                        with os.fdopen(destination_fd, "wb") as destination_handle:
                            destination_fd = None
                            shutil.copyfileobj(source_handle, destination_handle)
                    if destination.stat().st_size != source_info.st_size:
                        raise RunnerError(
                            f"candidate asset changed while snapshotting: {name}"
                        )
                    destination.chmod(0o500 if name == binary_name else 0o400)
                finally:
                    if source_fd is not None:
                        os.close(source_fd)
                    if destination_fd is not None:
                        os.close(destination_fd)
            snapshot.chmod(0o500)
            try:
                yield snapshot
            finally:
                snapshot.chmod(0o700)
    except OSError as exc:
        raise RunnerError(
            f"could not create private candidate snapshot: {exc}"
        ) from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def verify_candidate_assets(
    asset_dir: Path,
    tag: str,
    *,
    authenticate: Callable[[Path, str], None] = verify_authenticity,
    binary_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    tag_match = TAG.fullmatch(tag)
    if tag_match is None:
        raise RunnerError("candidate tag must be a stable vMAJOR.MINOR.PATCH tag")
    with candidate_asset_snapshot(asset_dir, tag) as snapshot:
        return verify_candidate_snapshot(
            snapshot,
            tag,
            authenticate=authenticate,
            binary_runner=binary_runner,
        )


def verify_candidate_snapshot(
    asset_dir: Path,
    tag: str,
    *,
    authenticate: Callable[[Path, str], None],
    binary_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, str]:
    tag_match = TAG.fullmatch(tag)
    if tag_match is None:
        raise RunnerError("candidate tag must be a stable vMAJOR.MINOR.PATCH tag")
    require_candidate_directory(asset_dir)
    required = required_asset_names(tag)
    actual = {path.name for path in asset_dir.iterdir()}
    missing = required - actual
    unknown = actual - required
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unexpected " + ", ".join(sorted(unknown)))
        raise RunnerError("candidate asset set is not closed: " + "; ".join(details))
    for name in sorted(required):
        require_regular_file(asset_dir / name, max_bytes=MAX_ASSET_BYTES)

    binary_name = f"registryctl-{tag}-linux-amd64"
    image_lock_name = f"registryctl-{tag}-image-lock.json"
    capsule_name = f"registry-stack-{tag}-release-capsule.json"
    checksums = parse_checksums(asset_dir / "SHA256SUMS")
    for name in (binary_name, image_lock_name):
        if checksums.get(name) != sha256(asset_dir / name):
            raise RunnerError(f"{name} does not match its SHA256SUMS entry")

    binary = asset_dir / binary_name
    lock = require_object(
        load_json(asset_dir / image_lock_name),
        image_lock_name,
        {
            "schema_version",
            "release_tag",
            "manifest_source_ref",
            "tag_target",
            "platform",
            "images",
        },
    )
    if (
        lock["schema_version"] != "registryctl.release_image_lock.v1"
        or lock["release_tag"] != tag
    ):
        raise RunnerError("candidate image lock has the wrong schema or release tag")
    if lock["platform"] != "linux/amd64":
        raise RunnerError("candidate image lock must target linux/amd64")
    if not COMMIT.fullmatch(str(lock["manifest_source_ref"])) or not COMMIT.fullmatch(
        str(lock["tag_target"])
    ):
        raise RunnerError("candidate image lock source refs must be full commits")
    images = require_object(
        lock["images"], "image lock images", {"registry-relay", "registry-notary"}
    )
    relay = exact_digest_file(asset_dir / "registry-relay.digest", "registry-relay")
    notary = exact_digest_file(asset_dir / "registry-notary.digest", "registry-notary")
    if images != {"registry-relay": relay, "registry-notary": notary}:
        raise RunnerError("candidate digest files do not match the image lock")

    capsule = load_json(asset_dir / capsule_name, max_bytes=8 * 1024 * 1024)
    if not isinstance(capsule, dict):
        raise RunnerError("release capsule must be an object")
    if capsule.get("release_tag") != tag or capsule.get("version") != tag_match.group(
        1
    ):
        raise RunnerError("release capsule identity does not match the candidate tag")
    if capsule.get("repository") != CAPSULE_REPOSITORY:
        raise RunnerError(f"release capsule repository must be {CAPSULE_REPOSITORY}")
    source = capsule.get("source")
    if (
        not isinstance(source, dict)
        or source.get("source_tag") != tag
        or source.get("source_ref") != lock["manifest_source_ref"]
        or source.get("source_commit") != lock["tag_target"]
    ):
        raise RunnerError(
            "release capsule source lineage does not match the image lock"
        )
    lineage = source.get("lineage")
    expected_lineage_keys = {
        "tag_matches_source_tag",
        "head_matches_tag_target",
        "source_ref_ancestor_or_equal",
        "default_branch_reachable",
    }
    if (
        not isinstance(lineage, dict)
        or set(lineage) != expected_lineage_keys
        or any(value is not True for value in lineage.values())
    ):
        raise RunnerError("release capsule does not prove every source lineage check")
    binary_entry = find_named(capsule.get("binaries"), binary_name, "binaries")
    lock_entry = find_named(
        capsule.get("release_files"), image_lock_name, "release_files"
    )
    if binary_entry.get("sha256") != sha256(binary):
        raise RunnerError(
            "release capsule binary hash does not match the candidate asset"
        )
    if lock_entry.get("kind") != "registryctl-release-image-lock" or lock_entry.get(
        "sha256"
    ) != sha256(asset_dir / image_lock_name):
        raise RunnerError(
            "release capsule image-lock classification or hash is invalid"
        )
    lock_sbom_name = f"{image_lock_name}.spdx.json"
    lock_sbom = asset_dir / lock_sbom_name
    verify_file_sbom(lock_sbom, image_lock_name, sha256(asset_dir / image_lock_name))
    expected_sbom = {
        "asset_name": lock_sbom_name,
        "subject": image_lock_name,
        "format": "spdx-json",
        "sha256": sha256(lock_sbom),
    }
    if lock_entry.get("sbom") != expected_sbom:
        raise RunnerError("release capsule image-lock SBOM binding is invalid")
    capsule_image_items = capsule.get("images")
    if not isinstance(capsule_image_items, list):
        raise RunnerError("release capsule images must be an array")
    capsule_image_names = [
        item.get("name") for item in capsule_image_items if isinstance(item, dict)
    ]
    if len(capsule_image_names) != 2 or set(capsule_image_names) != {
        "registry-relay",
        "registry-notary",
    }:
        raise RunnerError("release capsule must contain exactly the two product images")
    relay_entry = find_named(capsule_image_items, "registry-relay", "images")
    notary_entry = find_named(capsule_image_items, "registry-notary", "images")
    if (
        relay_entry.get("digest_ref") != relay
        or notary_entry.get("digest_ref") != notary
    ):
        raise RunnerError(
            "release capsule images do not match the candidate digest files"
        )

    signed_subject_hashes = {
        name: sha256(asset_dir / name) for name in signed_subject_names(tag)
    }
    # Candidate-controlled code must remain passive until every local binding
    # and both external authenticity mechanisms have accepted the assets.
    authenticate(asset_dir, tag)
    if any(
        sha256(asset_dir / name) != digest
        for name, digest in signed_subject_hashes.items()
    ):
        raise RunnerError("a signed candidate subject changed during verification")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    version_result = binary_runner(
        [str(binary), "--version"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if (
        version_result.returncode != 0
        or version_result.stdout.strip() != f"registryctl {tag_match.group(1)}"
    ):
        raise RunnerError(
            f"{binary_name} does not self-report registryctl {tag_match.group(1)}"
        )
    return {
        "tag": tag,
        "version": tag_match.group(1),
        "source_commit": lock["tag_target"],
        "registryctl_asset_sha256": f"sha256:{signed_subject_hashes[binary_name]}",
        "image_lock_sha256": f"sha256:{signed_subject_hashes[image_lock_name]}",
        "release_capsule_sha256": f"sha256:{signed_subject_hashes[capsule_name]}",
        "relay_image": relay,
        "notary_image": notary,
    }


def resolve_ref(schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise RunnerError(f"unsupported external schema reference: {reference}")
    value: Any = schema
    for component in reference[2:].split("/"):
        value = value[component]
    if not isinstance(value, dict):
        raise RunnerError(
            f"schema reference does not resolve to an object: {reference}"
        )
    return value


def json_value_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool-as-int equivalence."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and actual == expected
        )
    if actual is None or expected is None:
        return actual is expected
    if isinstance(actual, list) or isinstance(expected, list):
        return (
            isinstance(actual, list)
            and isinstance(expected, list)
            and len(actual) == len(expected)
            and all(
                json_value_equal(left, right) for left, right in zip(actual, expected)
            )
        )
    if isinstance(actual, dict) or isinstance(expected, dict):
        return (
            isinstance(actual, dict)
            and isinstance(expected, dict)
            and set(actual) == set(expected)
            and all(json_value_equal(actual[key], expected[key]) for key in actual)
        )
    return actual == expected


def validate_against_schema(
    value: Any, rule: dict[str, Any], schema: dict[str, Any], label: str = "result"
) -> None:
    if "$ref" in rule:
        validate_against_schema(value, resolve_ref(schema, rule["$ref"]), schema, label)
        return
    if "const" in rule and not json_value_equal(value, rule["const"]):
        raise RunnerError(f"{label} must equal {rule['const']!r}")
    if "enum" in rule and not any(
        json_value_equal(value, allowed) for allowed in rule["enum"]
    ):
        raise RunnerError(f"{label} is outside the closed allowed set")
    kind = rule.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise RunnerError(f"{label} must be an object")
        required = set(rule.get("required", []))
        missing = required - set(value)
        if missing:
            raise RunnerError(f"{label} is missing {', '.join(sorted(missing))}")
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                raise RunnerError(
                    f"{label} has unknown fields: {', '.join(sorted(unknown))}"
                )
        for name, item in value.items():
            if name in properties:
                validate_against_schema(
                    item, properties[name], schema, f"{label}.{name}"
                )
    elif kind == "array":
        if not isinstance(value, list):
            raise RunnerError(f"{label} must be an array")
        if len(value) < rule.get("minItems", 0) or len(value) > rule.get(
            "maxItems", sys.maxsize
        ):
            raise RunnerError(f"{label} has an invalid item count")
        if rule.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise RunnerError(f"{label} must contain unique values")
        for index, item in enumerate(value):
            validate_against_schema(
                item, rule.get("items", {}), schema, f"{label}[{index}]"
            )
    elif kind == "string":
        if not isinstance(value, str):
            raise RunnerError(f"{label} must be a string")
        if "pattern" in rule and re.fullmatch(rule["pattern"], value) is None:
            raise RunnerError(f"{label} has an invalid or unsafe value")
    elif kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RunnerError(f"{label} must be an integer")
        if value < rule.get("minimum", value) or value > rule.get("maximum", value):
            raise RunnerError(f"{label} is outside its allowed range")


def read_canaries(path: Path) -> list[bytes]:
    require_regular_file(path, max_bytes=64 * 1024)
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RunnerError("canary file must not grant group or other permissions")
    canaries = []
    for line_number, line in enumerate(path.read_bytes().splitlines(), 1):
        if SAFE_CANARY.fullmatch(line) is None:
            raise RunnerError(
                f"canary file line {line_number} must contain 8 to 128 safe ASCII bytes"
            )
        canaries.append(line)
    if not canaries or len(canaries) > 128 or len(set(canaries)) != len(canaries):
        raise RunnerError("canary file must contain 1 to 128 unique values")
    return canaries


def parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def elapsed_milliseconds(started: dt.datetime, completed: dt.datetime) -> int:
    elapsed = completed - started
    return (
        elapsed.days * 86_400_000
        + elapsed.seconds * 1000
        + elapsed.microseconds // 1000
    )


def validate_result(
    path: Path, profile: dict[str, Any], canary_file: Path
) -> dict[str, Any]:
    limit = profile["limits"]["public_result_bytes"]
    require_regular_file(path, max_bytes=limit)
    public_bytes = path.read_bytes()
    canaries = read_canaries(canary_file)
    if any(canary in public_bytes for canary in canaries):
        raise RunnerError("public result contains a seeded restricted-value canary")
    result = load_json(path, max_bytes=limit)
    schema = load_json(SCHEMA_PATH)
    validate_against_schema(result, schema, schema)
    if result["profile_id"] != profile["profile_id"]:
        raise RunnerError(
            "public result profile_id does not match the selected profile"
        )

    data_operation = next(
        item for item in profile["source"]["operations"] if item["role"] == "data"
    )
    expected_source = {
        "product": profile["source"]["product"],
        "baseline": profile["source"]["baseline"],
        "operation_id": data_operation["id"],
        "method": data_operation["method"],
        "path": data_operation["path"],
    }
    for key, expected in expected_source.items():
        if result["source"][key] != expected:
            raise RunnerError(
                f"public result source.{key} does not match the pinned profile"
            )
    if result["project"]["starter"] != profile["starter"]:
        raise RunnerError("public result starter does not match the pinned profile")
    if set(result["limitations"]) != REQUIRED_LIMITATIONS:
        raise RunnerError("public result must retain every profile limitation")

    cases = result["cases"]
    if [case["case_id"] for case in cases] != list(CASE_IDS):
        raise RunnerError("public result cases must use the closed ordered case set")
    expectations = {item["id"]: item for item in profile["cases"]}
    all_passed = True
    run_started = parse_timestamp(result["started_at"])
    run_completed = parse_timestamp(result["completed_at"])
    if run_completed < run_started:
        raise RunnerError("public result completes before it starts")
    latest_case_completion = run_started
    for case in cases:
        expectation = expectations[case["case_id"]]
        expected_access = expectation["expected_source_data_access"]
        if (
            case["outcome"] == "passed"
            and case["source_data_access"] != expected_access
        ):
            raise RunnerError(
                f"{case['case_id']} passed without expected source-side access evidence {expected_access}"
            )
        if (
            case["outcome"] in {"passed", "not_applicable"}
            and case["result_code"] != expectation["expected_result_code"]
        ):
            raise RunnerError(
                f"{case['case_id']} does not use the reviewed safe result code"
            )
        if expected_access == "not_applicable":
            if (
                case["outcome"] != "not_applicable"
                or case["source_data_access"] != "not_applicable"
            ):
                raise RunnerError(
                    f"{case['case_id']} must record the profile's not-applicable proof"
                )
        elif case["outcome"] != "passed":
            all_passed = False
        case_started = parse_timestamp(case["started_at"])
        case_completed = parse_timestamp(case["completed_at"])
        if case_completed < case_started:
            raise RunnerError(f"{case['case_id']} completes before it starts")
        case_elapsed_ms = elapsed_milliseconds(case_started, case_completed)
        if case["duration_ms"] != case_elapsed_ms:
            raise RunnerError(
                f"{case['case_id']} duration_ms does not match its timestamps"
            )
        if case_elapsed_ms > profile["limits"]["case_timeout_seconds"] * 1000:
            raise RunnerError(f"{case['case_id']} exceeds the profile case timeout")
        if case_started < run_started or case_completed > run_completed:
            raise RunnerError(f"{case['case_id']} falls outside the recorded run")
        latest_case_completion = max(latest_case_completion, case_completed)
    run_ms = elapsed_milliseconds(run_started, run_completed)
    if run_ms > profile["limits"]["run_timeout_seconds"] * 1000:
        raise RunnerError("public result exceeds the profile run timeout")
    if result["redaction"]["seeded_canaries"] != len(canaries):
        raise RunnerError(
            "public result seeded_canaries does not match the protected canary file"
        )
    if result["redaction"]["scanned_bytes"] < len(public_bytes):
        raise RunnerError(
            "redaction scan byte count does not include the public result"
        )
    if (
        result["redaction"]["restricted_raw_evidence_bytes"]
        > profile["limits"]["raw_evidence_bytes"]
    ):
        raise RunnerError("restricted raw evidence exceeds the profile byte limit")
    teardown_started = parse_timestamp(result["teardown"]["started_at"])
    teardown_completed = parse_timestamp(result["teardown"]["completed_at"])
    if teardown_completed < teardown_started:
        raise RunnerError("teardown completes before it starts")
    teardown_elapsed_ms = elapsed_milliseconds(teardown_started, teardown_completed)
    if result["teardown"]["duration_ms"] != teardown_elapsed_ms:
        raise RunnerError("teardown duration_ms does not match its timestamps")
    if teardown_elapsed_ms > profile["limits"]["teardown_timeout_seconds"] * 1000:
        raise RunnerError("teardown exceeds the profile timeout")
    if teardown_started < latest_case_completion:
        raise RunnerError("teardown starts before the recorded test cases complete")
    if teardown_started < run_started:
        raise RunnerError("teardown starts before the recorded run")
    if teardown_completed > run_completed:
        raise RunnerError("public result completion must include the teardown attempt")
    complete = all_passed and result["teardown"]["status"] == "completed"
    if (result["status"] == "passed") != complete:
        raise RunnerError(
            "public result status is inconsistent with cases and teardown"
        )
    return result


def plan_document(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "registry.release.integration_e2_plan.v1",
        "profile_id": profile["profile_id"],
        "support_status": profile["support_status"],
        "candidate_evidence": False,
        "status": "planned_not_executed",
        "executor": "approved_operator_wrapper",
        "starter": profile["starter"],
        "pinned_source": profile["source"]["baseline"],
        "source_operations": profile["source"]["operations"],
        "authored_contract": profile["authored_contract"],
        "required_input_names": [item["env"] for item in profile["dynamic_inputs"]],
        "cases": profile["cases"],
        "prerequisites": profile["prerequisites"],
        "limits": profile["limits"],
        "stages": [
            "Copy the closed candidate assets without following symlinks, then verify and version-check only the private non-writable snapshot.",
            "Have the operator wrapper create its own authenticated non-writable snapshot and initialize the pinned starter only from that snapshot.",
            "Apply only the profile's reviewed authored inputs; never edit generated YAML.",
            "Run the offline project test, check, build, and generated-file hash review.",
            "Deploy one digest-pinned Relay, Notary, and PostgreSQL set per authority within the approved run timeout.",
            "Probe source-side audit or request counters before and after every closed test case.",
            "Capture bounded restricted evidence and emit only hashes, timings, safe codes, and source-contact classifications.",
            "Scan the public result for seeded canaries and forbidden values.",
            "Re-hash generated project outputs and reject hand edits.",
            "Attempt scoped teardown in a finally path and record its sanitized evidence hash.",
        ],
    }


def print_plan(profile: dict[str, Any], *, as_json: bool) -> None:
    plan = plan_document(profile)
    if as_json:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return
    print(f"{plan['profile_id']}: {plan['support_status']}")
    print("Status: planned, not executed; this is not candidate evidence.")
    print(
        "Executor: approved operator wrapper; the public runner does not run live stages."
    )
    print("Prerequisites:")
    for item in plan["prerequisites"]:
        print(f"  - {item}")
    print("Stages:")
    for index, item in enumerate(plan["stages"], 1):
        print(f"  {index}. {item}")


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", choices=sorted(PROFILE_FILES), required=True)
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan", parents=[common], help="show prerequisites and bounded stages"
    )
    plan.add_argument("--json", action="store_true")
    commands.add_parser(
        "dry-run",
        parents=[common],
        help="emit the non-evidence orchestration plan as JSON",
    )
    validate = commands.add_parser(
        "validate", help="validate the source packet and optional real evidence"
    )
    validate.add_argument("--profile", choices=sorted(PROFILE_FILES))
    validate.add_argument("--candidate-dir", type=Path)
    validate.add_argument("--tag")
    validate.add_argument("--result", type=Path)
    validate.add_argument("--canary-file", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate_packet()
        if args.command == "plan":
            print_plan(load_profile(args.profile), as_json=args.json)
        elif args.command == "dry-run":
            print_plan(load_profile(args.profile), as_json=True)
        else:
            candidate_requested = args.candidate_dir is not None or args.tag is not None
            if candidate_requested and (args.candidate_dir is None or args.tag is None):
                raise RunnerError(
                    "candidate validation requires --candidate-dir and --tag together"
                )
            result_requested = args.result is not None or args.canary_file is not None
            if result_requested and not candidate_requested:
                raise RunnerError(
                    "public result validation also requires --candidate-dir and --tag"
                )
            if result_requested and (
                args.profile is None or args.result is None or args.canary_file is None
            ):
                raise RunnerError(
                    "result validation requires --profile, --result, and --canary-file together"
                )
            candidate = None
            result = None
            if candidate_requested:
                candidate = verify_candidate_assets(args.candidate_dir, args.tag)
            if result_requested:
                profile = load_profile(args.profile)
                result = validate_result(args.result, profile, args.canary_file)
            elif args.profile is not None:
                load_profile(args.profile)
            if candidate is not None and result is not None:
                expected_release = {
                    **candidate,
                    "candidate_assets_verified": True,
                    "authenticity_verified": True,
                }
                if result["release"] != expected_release:
                    raise RunnerError(
                        "public result release identity does not match verified candidate assets"
                    )
            if candidate is not None and result is not None:
                print("integration E2 candidate result validation passed")
            elif candidate is not None:
                print("integration E2 candidate asset validation passed")
            elif args.profile is not None:
                print(f"integration E2 profile validation passed: {args.profile}")
            else:
                print("integration E2 source packet validation passed")
    except (RunnerError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
