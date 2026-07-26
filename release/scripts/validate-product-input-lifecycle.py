#!/usr/bin/env python3
"""Validate a closed, redaction-safe product-input lifecycle evidence record."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from conformance_candidate import (  # noqa: E402
    CandidateError as CandidateAssetError,
    load_candidate,
    read_regular_file_no_follow,
)
from closed_json_schema import (  # noqa: E402
    SchemaValidationError,
    validate_against_schema,
)
from release_candidate import (  # noqa: E402
    CandidateError as CandidateReceiptError,
    parse_tag_binding,
    validate_receipt,
)


SCHEMA_VERSION = "registry-stack.product-input-lifecycle.v1"
STACK_REPOSITORY = "registrystack/registry-stack"
RECORD_KINDS = {"template", "candidate_evidence"}
LIFECYCLE_DIRECTORY = "product-input-lifecycle"
SCHEMA_FILENAME = "product-input-lifecycle-v1.schema.json"
TEMPLATE_FILENAME = "product-input-lifecycle-v1.template.json"
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024

SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_IDENTIFIER = (
    rf"(?:{SEMVER_NUMBER}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
VERSION = re.compile(
    rf"^v{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}"
    rf"(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?$"
)
SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PLACEHOLDER = re.compile(r"^<[A-Z0-9_]+>$")
EXERCISE_ID = re.compile(r"^product-input-lifecycle-[0-9a-f]{16,64}$")
EVIDENCE_LABEL = re.compile(r"^evidence-[0-9a-f]{16,64}$")
REVIEWER_LABEL = re.compile(r"^reviewer-[0-9a-f]{16,64}$")
ABSOLUTE_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
JWT_LIKE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
CANDIDATE_RECORD_FILENAME = re.compile(
    r"^product-input-lifecycle-[a-z0-9][a-z0-9._-]{0,127}\.json$"
)

AUTHORING_AND_BUILD_CHECKS = (
    "authored_revision_closed",
    "fixture_coverage_closed",
    "preflight_closed",
    "capabilities_closed",
    "promotion_closed",
    "deterministic_artifact_manifest_built",
    "relay_unsigned_input_built",
    "notary_unsigned_input_built",
)
PRODUCT_LIFECYCLE_CHECKS = (
    "relay_bundle_signed",
    "notary_bundle_signed",
    "relay_trust_generation_verified",
    "notary_trust_generation_verified",
    "relay_anti_rollback_lineage_verified",
    "notary_anti_rollback_lineage_verified",
    "relay_bundle_verified",
    "notary_bundle_verified",
    "cross_product_compatibility_verified",
    "relay_staged_activation",
    "notary_staged_activation",
    "consultation_contract_mismatch_zero_source_calls",
    "redacted_runtime_posture_inspected",
    "traffic_admission_after_compatible_activation",
)
ADVANCED_OPERATION_CHECKS = (
    "upgrade_exercised",
    "recovery_exercised",
    "rollback_exercised",
)
REVIEW_CLASSES = (
    "correctness",
    "security",
    "maintainability",
    "operator",
)
EVIDENCE_GROUPS = {
    "authoring_and_build": AUTHORING_AND_BUILD_CHECKS,
    "product_lifecycle": PRODUCT_LIFECYCLE_CHECKS,
    "advanced_operations": ADVANCED_OPERATION_CHECKS,
}
ALL_CHECKS = (
    *AUTHORING_AND_BUILD_CHECKS,
    *PRODUCT_LIFECYCLE_CHECKS,
    *ADVANCED_OPERATION_CHECKS,
)
LIMITATIONS = {
    "evidence_grade": "candidate_non_production",
    "retained_evidence_content_authenticated_by_validator": False,
    "live_country_interoperability_proven": False,
    "country_owner_acceptance_recorded": False,
    "legal_approval_recorded": False,
    "production_authorization_recorded": False,
    "production_signing_keys_used": False,
    "country_credentials_used": False,
    "country_personal_data_used": False,
}


class LifecycleError(ValueError):
    """A product-input lifecycle record is invalid."""


def require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown or missing:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append(f"{len(unknown)} unknown field(s)")
        raise LifecycleError(f"{label} has invalid fields: {'; '.join(details)}")
    return value


def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleError("JSON objects must not contain duplicate fields")
        value[key] = item
    return value


def load_closed_json_bytes(value: bytes) -> Any:
    try:
        return json.loads(value, object_pairs_hook=closed_object)
    except UnicodeDecodeError as error:
        raise LifecycleError("record is not valid UTF-8 JSON") from error
    except json.JSONDecodeError as error:
        raise LifecycleError("record is not valid JSON") from error


def load_closed_json_file(path: Path) -> Any:
    try:
        value = read_regular_file_no_follow(path, max_bytes=MAX_RECORD_BYTES)
    except (CandidateAssetError, OSError):
        raise LifecycleError(
            "record must be a bounded regular non-symlink JSON file"
        ) from None
    return load_closed_json_bytes(value)


@lru_cache(maxsize=1)
def lifecycle_schema() -> dict[str, Any]:
    value = load_closed_json_file(
        ROOT / "release" / "exercises" / LIFECYCLE_DIRECTORY / SCHEMA_FILENAME
    )
    if not isinstance(value, dict):
        raise LifecycleError("product-input lifecycle schema must be an object")
    return value


def validate_schema_document(value: Any) -> None:
    try:
        validate_against_schema(value, lifecycle_schema(), lifecycle_schema())
    except SchemaValidationError:
        raise LifecycleError(
            "record does not satisfy the closed product-input lifecycle schema"
        ) from None


def bounded_string(
    value: Any,
    label: str,
    pattern: re.Pattern[str],
    *,
    template: bool,
) -> str:
    if not isinstance(value, str):
        raise LifecycleError(f"{label} must be a string")
    if template and PLACEHOLDER.fullmatch(value):
        return value
    if pattern.fullmatch(value) is None:
        raise LifecycleError(f"{label} has an invalid or unsafe value")
    return value


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)


def git_bytes(root: Path, commit: str, path: Path) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path.as_posix()}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise LifecycleError(
            "candidate release manifest is unavailable at the exact commit"
        )
    return result.stdout


def parse_timestamp(value: str, label: str) -> datetime:
    if TIMESTAMP.fullmatch(value) is None:
        raise LifecycleError(f"{label} has an invalid or unsafe value")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise LifecycleError(f"{label} is not a valid UTC timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise LifecycleError(f"{label} must use UTC")
    return parsed


def reject_sensitive_sentinels(value: Any, label: str = "record") -> None:
    if isinstance(value, dict):
        for index, item in enumerate(value.values()):
            reject_sensitive_sentinels(item, f"{label}.value[{index}]")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            reject_sensitive_sentinels(item, f"{label}[{index}]")
        return
    if not isinstance(value, str) or PLACEHOLDER.fullmatch(value):
        return
    lowered = value.casefold()
    unsafe = (
        value.startswith(("/", "~/", "\\\\"))
        or ABSOLUTE_WINDOWS_PATH.search(value) is not None
        or "://" in value
        or "-----begin " in lowered
        or "bearer " in lowered
        or "password=" in lowered
        or "passwd=" in lowered
        or "token=" in lowered
        or "secret=" in lowered
        or "private_key" in lowered
        or "private-key" in lowered
        or AWS_ACCESS_KEY.search(value) is not None
        or JWT_LIKE.search(value) is not None
        or "\n" in value
        or "\r" in value
    )
    if unsafe:
        raise LifecycleError(f"{label} contains forbidden sensitive or location data")


def validate_candidate(value: Any, *, template: bool, root: Path) -> dict[str, Any]:
    candidate = require_object(
        value,
        "candidate",
        {
            "repository",
            "release_id",
            "version",
            "source_ref",
            "source_commit",
            "release_manifest_sha256",
            "image_lock_sha256",
            "release_capsule_sha256",
            "candidate_receipt_sha256",
            "relay_image_digest",
            "notary_image_digest",
        },
    )
    if candidate["repository"] != STACK_REPOSITORY:
        raise LifecycleError(f"candidate.repository must be {STACK_REPOSITORY}")
    bounded_string(
        candidate["release_id"],
        "candidate.release_id",
        SLUG,
        template=template,
    )
    bounded_string(
        candidate["version"],
        "candidate.version",
        VERSION,
        template=template,
    )
    for field in ("source_ref", "source_commit"):
        bounded_string(
            candidate[field],
            f"candidate.{field}",
            COMMIT,
            template=template,
        )
    for field in (
        "release_manifest_sha256",
        "image_lock_sha256",
        "release_capsule_sha256",
        "candidate_receipt_sha256",
        "relay_image_digest",
        "notary_image_digest",
    ):
        bounded_string(
            candidate[field],
            f"candidate.{field}",
            SHA256,
            template=template,
        )
    if template:
        return candidate
    validate_candidate_git_binding(candidate, root)
    return candidate


def validate_candidate_git_binding(candidate: dict[str, Any], root: Path) -> None:
    source_ref = candidate["source_ref"]
    source_commit = candidate["source_commit"]
    for value, label in (
        (source_ref, "source_ref"),
        (source_commit, "source_commit"),
    ):
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if resolved.returncode != 0 or resolved.stdout.strip() != value:
            raise LifecycleError(f"candidate.{label} does not resolve exactly")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_ref, source_commit],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if ancestor.returncode != 0:
        raise LifecycleError("candidate.source_ref is not an ancestor of source_commit")

    manifest_path = Path(
        "release/manifests",
        f"registry-stack-{candidate['release_id']}.yaml",
    )
    manifest_bytes = git_bytes(root, source_commit, manifest_path)
    if sha256_bytes(manifest_bytes) != candidate["release_manifest_sha256"]:
        raise LifecycleError(
            "candidate.release_manifest_sha256 does not match the exact candidate"
        )
    try:
        manifest = yaml.safe_load(manifest_bytes)
    except yaml.YAMLError as error:
        raise LifecycleError("candidate release manifest is invalid YAML") from error
    stack = manifest.get("stack") if isinstance(manifest, dict) else None
    expected = {
        "release": candidate["release_id"],
        "version": candidate["version"].removeprefix("v"),
        "source_repo": candidate["repository"],
        "source_ref": source_ref,
        "source_tag": candidate["version"],
    }
    if not isinstance(stack, dict) or any(
        str(stack.get(key)) != expected_value
        for key, expected_value in expected.items()
    ):
        raise LifecycleError(
            "candidate release manifest identity does not match the candidate coordinate"
        )
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if (
        not isinstance(artifacts, dict)
        or not artifacts
        or any(str(version) != expected["version"] for version in artifacts.values())
    ):
        raise LifecycleError(
            "candidate release manifest artifacts do not match the candidate version"
        )


def load_candidate_tag_binding(root: Path, version: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "git",
            "for-each-ref",
            "--format=%(contents)",
            "--count=1",
            f"refs/tags/{version}",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout:
        raise LifecycleError("candidate annotated tag binding is unavailable")
    try:
        # for-each-ref appends one record separator newline after the tag
        # contents. Remove only that separator and preserve the message bytes.
        return parse_tag_binding(result.stdout[:-1])
    except CandidateReceiptError as error:
        raise LifecycleError("candidate annotated tag binding is invalid") from error


def validate_candidate_assets(
    candidate: dict[str, Any],
    *,
    recorded_at: datetime,
    root: Path,
    candidate_asset_root: Path | None,
    candidate_loader: Callable[..., dict[str, Any]],
    receipt_validator: Callable[..., dict[str, Any]],
) -> None:
    if candidate_asset_root is None:
        raise LifecycleError(
            "candidate evidence requires --candidate-asset-root for authentication"
        )
    version = candidate["version"]
    candidate_asset_directory = candidate_asset_root.expanduser() / version
    manifest_path = (
        root
        / "release"
        / "manifests"
        / f"registry-stack-{candidate['release_id']}.yaml"
    )
    image_lock_path = (
        candidate_asset_directory / f"registryctl-{version}-image-lock.json"
    )
    receipt_path = candidate_asset_directory / "release-candidate-receipt.json"

    try:
        current_manifest_bytes = read_regular_file_no_follow(
            manifest_path,
            max_bytes=MAX_RELEASE_MANIFEST_BYTES,
        )
        authenticated = candidate_loader(manifest_path, image_lock_path)
    except (CandidateAssetError, OSError):
        raise LifecycleError(
            "candidate release assets could not be authenticated"
        ) from None
    expected_authenticated = {
        "release_id": candidate["release_id"],
        "version": version.removeprefix("v"),
        "source_repo": candidate["repository"],
        "source_ref": candidate["source_ref"],
        "source_tag": version,
        "tag_target": candidate["source_commit"],
        # The authenticated current manifest may contain the one permitted
        # release-candidate to released closeout transition. The candidate
        # manifest at source_commit is bound separately by the record.
        "manifest_sha256": sha256_bytes(current_manifest_bytes),
        "image_lock_sha256": candidate["image_lock_sha256"],
        "release_capsule_sha256": candidate["release_capsule_sha256"],
        "relay_image": (
            "ghcr.io/registrystack/registry-relay@" + candidate["relay_image_digest"]
        ),
        "notary_image": (
            "ghcr.io/registrystack/registry-notary@" + candidate["notary_image_digest"]
        ),
    }
    if not isinstance(authenticated, dict) or any(
        authenticated.get(field) != expected
        for field, expected in expected_authenticated.items()
    ):
        raise LifecycleError(
            "authenticated release assets do not match the candidate coordinate"
        )

    try:
        receipt_bytes = read_regular_file_no_follow(
            receipt_path,
            max_bytes=MAX_CANDIDATE_RECEIPT_BYTES,
        )
    except (CandidateAssetError, OSError):
        raise LifecycleError("candidate receipt could not be read safely") from None
    if sha256_bytes(receipt_bytes) != candidate["candidate_receipt_sha256"]:
        raise LifecycleError(
            "candidate_receipt_sha256 does not match the retained receipt bytes"
        )
    receipt_document = load_closed_json_bytes(receipt_bytes)
    try:
        receipt = receipt_validator(
            receipt_document,
            expected_source_sha=candidate["source_ref"],
            expected_version=version.removeprefix("v"),
            expected_release_id=candidate["release_id"],
            now=recorded_at,
        )
    except CandidateReceiptError:
        raise LifecycleError("candidate receipt contract is invalid") from None
    if not isinstance(receipt, dict):
        raise LifecycleError("candidate receipt contract is invalid")

    validity = receipt.get("validity")
    expires_at = validity.get("expires_at") if isinstance(validity, dict) else None
    if (
        not isinstance(expires_at, str)
        or parse_timestamp(expires_at, "candidate receipt expiry") <= recorded_at
    ):
        raise LifecycleError("candidate receipt expired before lifecycle evidence")

    images = receipt.get("images")
    if not isinstance(images, list):
        raise LifecycleError("candidate receipt image inventory is invalid")
    image_digests = {
        item.get("name"): item.get("index_digest")
        for item in images
        if isinstance(item, dict)
    }
    expected_receipt_images = {
        "registry-relay": candidate["relay_image_digest"],
        "registry-notary": candidate["notary_image_digest"],
    }
    if image_digests != expected_receipt_images:
        raise LifecycleError(
            "candidate receipt images do not match the authenticated release assets"
        )

    workflow = receipt.get("workflow")
    if not isinstance(workflow, dict):
        raise LifecycleError("candidate receipt workflow identity is invalid")
    binding = load_candidate_tag_binding(root, version)
    expected_binding = {
        "run_id": workflow.get("run_id"),
        "run_attempt": workflow.get("run_attempt"),
        "receipt_sha256": candidate["candidate_receipt_sha256"].removeprefix("sha256:"),
    }
    if binding != expected_binding:
        raise LifecycleError(
            "candidate annotated tag does not bind the retained receipt"
        )


def validate_attestations(value: Any, *, template: bool) -> None:
    attestations = require_object(
        value,
        "attestations",
        {"candidate_frozen", "candidate_independently_verified"},
    )
    for field in ("candidate_frozen", "candidate_independently_verified"):
        if not isinstance(attestations[field], bool):
            raise LifecycleError(f"attestations.{field} must be boolean")
        if template and attestations[field]:
            raise LifecycleError(f"attestations.{field} must be false in a template")
        if not template and not attestations[field]:
            raise LifecycleError(
                f"candidate evidence requires attestations.{field} to be true"
            )


def validate_product(value: Any, label: str, *, template: bool) -> dict[str, Any]:
    product = require_object(
        value,
        label,
        {
            "unsigned_input_sha256",
            "signed_bundle_sha256",
            "trust_generation",
            "trust_set_sha256",
            "anti_rollback_lineage_sha256",
        },
    )
    for field in (
        "unsigned_input_sha256",
        "signed_bundle_sha256",
        "trust_set_sha256",
        "anti_rollback_lineage_sha256",
    ):
        bounded_string(
            product[field],
            f"{label}.{field}",
            SHA256,
            template=template,
        )
    generation = product["trust_generation"]
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise LifecycleError(f"{label}.trust_generation must be an integer")
    if (template and generation != 0) or (not template and generation <= 0):
        expected = (
            "zero in a template" if template else "positive in candidate evidence"
        )
        raise LifecycleError(f"{label}.trust_generation must be {expected}")
    if (
        not template
        and product["unsigned_input_sha256"] == product["signed_bundle_sha256"]
    ):
        raise LifecycleError(
            f"{label} unsigned input and signed bundle must be distinct"
        )
    return product


def validate_product_inputs(
    value: Any,
    product_input_set_sha256: Any,
    *,
    template: bool,
) -> dict[str, Any]:
    product_inputs = require_object(
        value,
        "product_inputs",
        {"artifact_manifest_sha256", "relay", "notary"},
    )
    bounded_string(
        product_inputs["artifact_manifest_sha256"],
        "product_inputs.artifact_manifest_sha256",
        SHA256,
        template=template,
    )
    relay = validate_product(
        product_inputs["relay"],
        "product_inputs.relay",
        template=template,
    )
    notary = validate_product(
        product_inputs["notary"],
        "product_inputs.notary",
        template=template,
    )
    bounded_string(
        product_input_set_sha256,
        "product_input_set_sha256",
        SHA256,
        template=template,
    )
    if template:
        return product_inputs
    if product_input_set_sha256 != canonical_sha256(product_inputs):
        raise LifecycleError(
            "product_input_set_sha256 does not match the exact product inputs"
        )
    distinct_product_artifacts = {
        relay["unsigned_input_sha256"],
        relay["signed_bundle_sha256"],
        notary["unsigned_input_sha256"],
        notary["signed_bundle_sha256"],
    }
    if len(distinct_product_artifacts) != 4:
        raise LifecycleError(
            "Relay and Notary unsigned inputs and signed bundles must remain separate"
        )
    if relay["trust_set_sha256"] == notary["trust_set_sha256"]:
        raise LifecycleError(
            "Relay and Notary operator trust sets must remain separate"
        )
    if relay["anti_rollback_lineage_sha256"] == notary["anti_rollback_lineage_sha256"]:
        raise LifecycleError(
            "Relay and Notary anti-rollback lineages must remain separate"
        )
    return product_inputs


def validate_activation(value: Any, *, template: bool) -> dict[str, Any]:
    activation = require_object(
        value,
        "activation",
        {
            "stack_generation",
            "compatibility_report_sha256",
            "runtime_posture_sha256",
            "consultation_contract_mismatch",
        },
    )
    generation = activation["stack_generation"]
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise LifecycleError("activation.stack_generation must be an integer")
    if (template and generation != 0) or (not template and generation <= 0):
        expected = (
            "zero in a template" if template else "positive in candidate evidence"
        )
        raise LifecycleError(f"activation.stack_generation must be {expected}")
    for field in ("compatibility_report_sha256", "runtime_posture_sha256"):
        bounded_string(
            activation[field],
            f"activation.{field}",
            SHA256,
            template=template,
        )
    mismatch = require_object(
        activation["consultation_contract_mismatch"],
        "activation.consultation_contract_mismatch",
        {"failure_class", "observed_source_calls", "report_sha256"},
    )
    if mismatch["failure_class"] != "consultation_contract_mismatch":
        raise LifecycleError(
            "activation.consultation_contract_mismatch.failure_class is invalid"
        )
    calls = mismatch["observed_source_calls"]
    if isinstance(calls, bool) or not isinstance(calls, int) or calls < 0:
        raise LifecycleError(
            "activation.consultation_contract_mismatch.observed_source_calls "
            "must be a non-negative integer"
        )
    bounded_string(
        mismatch["report_sha256"],
        "activation.consultation_contract_mismatch.report_sha256",
        SHA256,
        template=template,
    )
    return activation


def result_subject_bindings(
    product_inputs: dict[str, Any],
    activation: dict[str, Any],
    *,
    candidate_binding_sha256: str,
    product_input_set_sha256: str,
) -> dict[str, str]:
    relay = product_inputs["relay"]
    notary = product_inputs["notary"]
    authoring_binding = canonical_sha256(
        {
            "candidate_binding_sha256": candidate_binding_sha256,
            "product_input_set_sha256": product_input_set_sha256,
            "artifact_manifest_sha256": product_inputs["artifact_manifest_sha256"],
        }
    )
    activation_binding = canonical_sha256(
        {
            "candidate_binding_sha256": candidate_binding_sha256,
            "product_input_set_sha256": product_input_set_sha256,
            "activation_sha256": canonical_sha256(activation),
        }
    )
    relay_trust_binding = canonical_sha256(
        {
            "trust_generation": relay["trust_generation"],
            "trust_set_sha256": relay["trust_set_sha256"],
        }
    )
    notary_trust_binding = canonical_sha256(
        {
            "trust_generation": notary["trust_generation"],
            "trust_set_sha256": notary["trust_set_sha256"],
        }
    )
    relay_lineage_binding = canonical_sha256(
        {
            "trust_generation": relay["trust_generation"],
            "trust_set_sha256": relay["trust_set_sha256"],
            "anti_rollback_lineage_sha256": relay["anti_rollback_lineage_sha256"],
        }
    )
    notary_lineage_binding = canonical_sha256(
        {
            "trust_generation": notary["trust_generation"],
            "trust_set_sha256": notary["trust_set_sha256"],
            "anti_rollback_lineage_sha256": notary["anti_rollback_lineage_sha256"],
        }
    )
    relay_verification_binding = canonical_sha256(
        {
            "candidate_binding_sha256": candidate_binding_sha256,
            "product_input_set_sha256": product_input_set_sha256,
            "product": "relay",
            "signed_bundle_sha256": relay["signed_bundle_sha256"],
            "trust_generation": relay["trust_generation"],
            "trust_set_sha256": relay["trust_set_sha256"],
            "anti_rollback_lineage_sha256": relay["anti_rollback_lineage_sha256"],
        }
    )
    notary_verification_binding = canonical_sha256(
        {
            "candidate_binding_sha256": candidate_binding_sha256,
            "product_input_set_sha256": product_input_set_sha256,
            "product": "notary",
            "signed_bundle_sha256": notary["signed_bundle_sha256"],
            "trust_generation": notary["trust_generation"],
            "trust_set_sha256": notary["trust_set_sha256"],
            "anti_rollback_lineage_sha256": notary["anti_rollback_lineage_sha256"],
        }
    )
    return {
        "authored_revision_closed": authoring_binding,
        "fixture_coverage_closed": authoring_binding,
        "preflight_closed": authoring_binding,
        "capabilities_closed": authoring_binding,
        "promotion_closed": authoring_binding,
        "deterministic_artifact_manifest_built": product_inputs[
            "artifact_manifest_sha256"
        ],
        "relay_unsigned_input_built": relay["unsigned_input_sha256"],
        "notary_unsigned_input_built": notary["unsigned_input_sha256"],
        "relay_bundle_signed": relay["signed_bundle_sha256"],
        "notary_bundle_signed": notary["signed_bundle_sha256"],
        "relay_trust_generation_verified": relay_trust_binding,
        "notary_trust_generation_verified": notary_trust_binding,
        "relay_anti_rollback_lineage_verified": relay_lineage_binding,
        "notary_anti_rollback_lineage_verified": notary_lineage_binding,
        "relay_bundle_verified": relay_verification_binding,
        "notary_bundle_verified": notary_verification_binding,
        "cross_product_compatibility_verified": activation_binding,
        "relay_staged_activation": canonical_sha256(
            {
                "activation_binding_sha256": activation_binding,
                "product": "relay",
                "signed_bundle_sha256": relay["signed_bundle_sha256"],
            }
        ),
        "notary_staged_activation": canonical_sha256(
            {
                "activation_binding_sha256": activation_binding,
                "product": "notary",
                "signed_bundle_sha256": notary["signed_bundle_sha256"],
            }
        ),
        "consultation_contract_mismatch_zero_source_calls": canonical_sha256(
            {
                "activation_binding_sha256": activation_binding,
                "mismatch_report_sha256": activation["consultation_contract_mismatch"][
                    "report_sha256"
                ],
            }
        ),
        "redacted_runtime_posture_inspected": canonical_sha256(
            {
                "activation_binding_sha256": activation_binding,
                "runtime_posture_sha256": activation["runtime_posture_sha256"],
            }
        ),
        "traffic_admission_after_compatible_activation": activation_binding,
        "upgrade_exercised": activation_binding,
        "recovery_exercised": activation_binding,
        "rollback_exercised": activation_binding,
    }


def validate_result(
    value: Any,
    label: str,
    check_id: str,
    *,
    template: bool,
    subject_binding: str | None,
) -> tuple[datetime | None, str | None]:
    result = require_object(
        value,
        label,
        {
            "check_id",
            "outcome",
            "subject_sha256",
            "observed_at",
            "evidence_label",
            "evidence_sha256",
        },
    )
    if result["check_id"] != check_id:
        raise LifecycleError(f"{label}.check_id must be {check_id}")
    outcome = result["outcome"]
    if template:
        if outcome != "not_run":
            raise LifecycleError(f"{label}.outcome must be not_run in a template")
        for field in (
            "subject_sha256",
            "observed_at",
            "evidence_label",
            "evidence_sha256",
        ):
            if result[field] is not None:
                raise LifecycleError(
                    f"{label}.{field} must be null in a non-evidence template"
                )
        return None, None
    if outcome not in {"passed", "failed"}:
        raise LifecycleError(f"{label}.outcome must be passed or failed")
    subject = bounded_string(
        result["subject_sha256"],
        f"{label}.subject_sha256",
        SHA256,
        template=False,
    )
    observed = bounded_string(
        result["observed_at"],
        f"{label}.observed_at",
        TIMESTAMP,
        template=False,
    )
    evidence_label = bounded_string(
        result["evidence_label"],
        f"{label}.evidence_label",
        EVIDENCE_LABEL,
        template=False,
    )
    bounded_string(
        result["evidence_sha256"],
        f"{label}.evidence_sha256",
        SHA256,
        template=False,
    )
    if subject_binding is not None and subject != subject_binding:
        raise LifecycleError(
            f"{label}.subject_sha256 does not match its lifecycle object"
        )
    return parse_timestamp(observed, f"{label}.observed_at"), evidence_label


def validate_evidence(
    value: Any,
    *,
    template: bool,
    subject_bindings: dict[str, str],
) -> tuple[list[dict[str, Any]], set[str], datetime | None]:
    evidence = require_object(value, "evidence", set(EVIDENCE_GROUPS))
    all_results: list[dict[str, Any]] = []
    labels: set[str] = set()
    previous: datetime | None = None
    for group_name, required_checks in EVIDENCE_GROUPS.items():
        group = evidence[group_name]
        if not isinstance(group, list):
            raise LifecycleError(f"evidence.{group_name} must be an array")
        if len(group) != len(required_checks):
            raise LifecycleError(
                f"evidence.{group_name} must contain every required check exactly once"
            )
        for index, (result, check_id) in enumerate(zip(group, required_checks)):
            label = f"evidence.{group_name}[{index}]"
            observed, evidence_label = validate_result(
                result,
                label,
                check_id,
                template=template,
                subject_binding=subject_bindings.get(check_id),
            )
            if observed is not None and previous is not None and observed < previous:
                raise LifecycleError(
                    "candidate evidence timestamps must follow lifecycle order"
                )
            if observed is not None:
                previous = observed
            if evidence_label is not None:
                if evidence_label in labels:
                    raise LifecycleError("candidate evidence labels must be unique")
                labels.add(evidence_label)
            all_results.append(result)
    if [result["check_id"] for result in all_results] != list(ALL_CHECKS):
        raise LifecycleError("evidence check order is not the closed lifecycle order")
    return all_results, labels, previous


def validate_reviews(
    value: Any,
    *,
    template: bool,
    evidence_labels: set[str],
    not_before: datetime | None,
) -> tuple[list[dict[str, Any]], datetime | None]:
    if not isinstance(value, list) or len(value) != len(REVIEW_CLASSES):
        raise LifecycleError("reviews must contain every required review exactly once")
    reviewers: set[str] = set()
    reviews: list[dict[str, Any]] = []
    latest_review = not_before
    for index, (review_value, review_class) in enumerate(zip(value, REVIEW_CLASSES)):
        label = f"reviews[{index}]"
        review = require_object(
            review_value,
            label,
            {
                "review_class",
                "outcome",
                "independence_attested",
                "reviewer_label",
                "observed_at",
                "evidence_label",
                "evidence_sha256",
            },
        )
        if review["review_class"] != review_class:
            raise LifecycleError(f"{label}.review_class must be {review_class}")
        if not isinstance(review["independence_attested"], bool):
            raise LifecycleError(f"{label}.independence_attested must be boolean")
        if template:
            if review["outcome"] != "not_run" or review["independence_attested"]:
                raise LifecycleError(
                    f"{label} must be not_run and unattested in a template"
                )
            for field in (
                "reviewer_label",
                "observed_at",
                "evidence_label",
                "evidence_sha256",
            ):
                if review[field] is not None:
                    raise LifecycleError(
                        f"{label}.{field} must be null in a non-evidence template"
                    )
        else:
            if review["outcome"] not in {"passed", "failed"}:
                raise LifecycleError(f"{label}.outcome must be passed or failed")
            if not review["independence_attested"]:
                raise LifecycleError(f"{label} must attest reviewer independence")
            reviewer = bounded_string(
                review["reviewer_label"],
                f"{label}.reviewer_label",
                REVIEWER_LABEL,
                template=False,
            )
            observed = bounded_string(
                review["observed_at"],
                f"{label}.observed_at",
                TIMESTAMP,
                template=False,
            )
            evidence_label = bounded_string(
                review["evidence_label"],
                f"{label}.evidence_label",
                EVIDENCE_LABEL,
                template=False,
            )
            bounded_string(
                review["evidence_sha256"],
                f"{label}.evidence_sha256",
                SHA256,
                template=False,
            )
            reviewed_at = parse_timestamp(observed, f"{label}.observed_at")
            if not_before is not None and reviewed_at < not_before:
                raise LifecycleError(
                    "independent reviews must follow lifecycle evidence"
                )
            if latest_review is None or reviewed_at > latest_review:
                latest_review = reviewed_at
            if reviewer in reviewers:
                raise LifecycleError(
                    "correctness, security, maintainability, and operator "
                    "reviews require distinct independent reviewer labels"
                )
            reviewers.add(reviewer)
            if evidence_label in evidence_labels:
                raise LifecycleError(
                    "review and lifecycle evidence labels must be unique"
                )
            evidence_labels.add(evidence_label)
        reviews.append(review)
    return reviews, latest_review


def validate_limitations(value: Any) -> None:
    limitations = require_object(value, "evidence_limitations", set(LIMITATIONS))
    if limitations != LIMITATIONS:
        raise LifecycleError(
            "evidence_limitations must preserve the non-production external boundary"
        )


def require_pass(
    record: dict[str, Any],
    results: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> None:
    if record["record_kind"] != "candidate_evidence":
        raise LifecycleError("a template is preparation and never passing evidence")
    if any(result["outcome"] != "passed" for result in results):
        raise LifecycleError("--require-pass requires every lifecycle check to pass")
    if any(review["outcome"] != "passed" for review in reviews):
        raise LifecycleError("--require-pass requires every independent review to pass")
    source_calls = record["activation"]["consultation_contract_mismatch"][
        "observed_source_calls"
    ]
    if source_calls != 0:
        raise LifecycleError(
            "--require-pass requires exactly zero source calls on contract mismatch"
        )


def validate_record(
    data: Any,
    *,
    allow_template: bool,
    require_all_passed: bool = False,
    root: Path = ROOT,
    candidate_asset_root: Path | None = None,
    candidate_loader: Callable[..., dict[str, Any]] = load_candidate,
    receipt_validator: Callable[..., dict[str, Any]] = validate_receipt,
) -> None:
    record = require_object(
        data,
        "record",
        {
            "schema_version",
            "record_kind",
            "exercise_id",
            "recorded_at",
            "candidate",
            "candidate_binding_sha256",
            "attestations",
            "product_inputs",
            "product_input_set_sha256",
            "activation",
            "evidence",
            "reviews",
            "evidence_limitations",
        },
    )
    reject_sensitive_sentinels(record)
    validate_schema_document(record)
    if record["schema_version"] != SCHEMA_VERSION:
        raise LifecycleError(f"schema_version must be {SCHEMA_VERSION}")
    kind = record["record_kind"]
    if kind not in RECORD_KINDS:
        raise LifecycleError("record_kind must be template or candidate_evidence")
    template = kind == "template"
    if template and not allow_template:
        raise LifecycleError(
            "template is preparation, not candidate evidence; pass --template to validate it"
        )
    if not template and allow_template:
        raise LifecycleError("--template accepts only a template record")
    bounded_string(
        record["exercise_id"],
        "exercise_id",
        EXERCISE_ID,
        template=template,
    )
    recorded_at_value = bounded_string(
        record["recorded_at"],
        "recorded_at",
        TIMESTAMP,
        template=template,
    )
    recorded_at = (
        None if template else parse_timestamp(recorded_at_value, "recorded_at")
    )
    candidate = validate_candidate(record["candidate"], template=template, root=root)
    bounded_string(
        record["candidate_binding_sha256"],
        "candidate_binding_sha256",
        SHA256,
        template=template,
    )
    if not template and record["candidate_binding_sha256"] != canonical_sha256(
        candidate
    ):
        raise LifecycleError(
            "candidate_binding_sha256 does not match the one exact candidate coordinate"
        )
    if not template:
        assert recorded_at is not None
        validate_candidate_assets(
            candidate,
            recorded_at=recorded_at,
            root=root,
            candidate_asset_root=candidate_asset_root,
            candidate_loader=candidate_loader,
            receipt_validator=receipt_validator,
        )
    validate_attestations(record["attestations"], template=template)
    product_inputs = validate_product_inputs(
        record["product_inputs"],
        record["product_input_set_sha256"],
        template=template,
    )
    activation = validate_activation(record["activation"], template=template)
    bindings = (
        {}
        if template
        else result_subject_bindings(
            product_inputs,
            activation,
            candidate_binding_sha256=record["candidate_binding_sha256"],
            product_input_set_sha256=record["product_input_set_sha256"],
        )
    )
    results, evidence_labels, last_evidence_at = validate_evidence(
        record["evidence"],
        template=template,
        subject_bindings=bindings,
    )
    mismatch_result = next(
        result
        for result in results
        if result["check_id"] == "consultation_contract_mismatch_zero_source_calls"
    )
    source_calls = activation["consultation_contract_mismatch"]["observed_source_calls"]
    if not template and mismatch_result["outcome"] == "passed" and source_calls != 0:
        raise LifecycleError(
            "a passed contract-mismatch check requires exactly zero source calls"
        )
    reviews, last_review_at = validate_reviews(
        record["reviews"],
        template=template,
        evidence_labels=evidence_labels,
        not_before=last_evidence_at,
    )
    if (
        recorded_at is not None
        and last_review_at is not None
        and recorded_at < last_review_at
    ):
        raise LifecycleError(
            "recorded_at must not precede lifecycle evidence or independent reviews"
        )
    validate_limitations(record["evidence_limitations"])
    if require_all_passed:
        require_pass(record, results, reviews)


def discover_records(
    directory: Path,
    *,
    root: Path = ROOT,
    candidate_asset_root: Path | None = None,
    candidate_loader: Callable[..., dict[str, Any]] = load_candidate,
    receipt_validator: Callable[..., dict[str, Any]] = validate_receipt,
) -> tuple[int, int]:
    records_directory = directory / LIFECYCLE_DIRECTORY
    try:
        records_directory_info = records_directory.lstat()
    except OSError as error:
        raise LifecycleError(
            "product-input lifecycle discovery directory is unavailable"
        ) from error
    if stat.S_ISLNK(records_directory_info.st_mode) or not stat.S_ISDIR(
        records_directory_info.st_mode
    ):
        raise LifecycleError(
            "product-input lifecycle discovery directory must be a real directory"
        )
    discovered_schema = load_closed_json_file(records_directory / SCHEMA_FILENAME)
    if discovered_schema != lifecycle_schema():
        raise LifecycleError(
            "discovered product-input lifecycle schema does not match the canonical schema"
        )
    json_files = sorted(records_directory.glob("*.json"))
    records: list[Path] = []
    for path in json_files:
        if path.name == SCHEMA_FILENAME:
            continue
        if CANDIDATE_RECORD_FILENAME.fullmatch(path.name) is None:
            raise LifecycleError(
                "product-input lifecycle discovery found an unrecognized JSON filename"
            )
        records.append(path)
    if not records:
        raise LifecycleError(
            f"--discover found no product-input lifecycle records in {LIFECYCLE_DIRECTORY}"
        )
    template_count = 0
    candidate_count = 0
    for path in records:
        data = load_closed_json_file(path)
        kind = data.get("record_kind") if isinstance(data, dict) else None
        if kind == "template":
            if path.name != TEMPLATE_FILENAME:
                raise LifecycleError(
                    "product-input lifecycle templates must use the canonical filename"
                )
            validate_record(data, allow_template=True, root=root)
            template_count += 1
        else:
            if path.name == TEMPLATE_FILENAME:
                raise LifecycleError(
                    "the canonical template filename cannot contain candidate evidence"
                )
            validate_record(
                data,
                allow_template=False,
                require_all_passed=True,
                root=root,
                candidate_asset_root=candidate_asset_root,
                candidate_loader=candidate_loader,
                receipt_validator=receipt_validator,
            )
            candidate_count += 1
    return template_count, candidate_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", nargs="?", type=Path)
    parser.add_argument(
        "--template",
        action="store_true",
        help="validate a preparation template; templates never count as evidence",
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="require every lifecycle check and independent review to pass",
    )
    parser.add_argument(
        "--discover",
        type=Path,
        help=(
            "validate the product-input-lifecycle subdirectory; templates are "
            "non-evidence and candidate records must pass completely"
        ),
    )
    parser.add_argument(
        "--candidate-asset-root",
        type=Path,
        help=(
            "root containing authenticated release assets and the retained "
            "candidate receipt under the exact candidate version"
        ),
    )
    args = parser.parse_args()
    try:
        if args.discover is not None:
            if args.record is not None or args.template or args.require_pass:
                raise LifecycleError(
                    "--discover cannot be combined with a record, --template, or --require-pass"
                )
            templates, candidates = discover_records(
                args.discover,
                candidate_asset_root=args.candidate_asset_root,
            )
            if candidates:
                print(
                    "product-input lifecycle discovery passed with authenticated "
                    f"candidate assets: {templates} template(s), {candidates} "
                    "candidate evidence record(s); retained evidence content "
                    "remains externally reviewed"
                )
            else:
                print(
                    "product-input lifecycle discovery passed: "
                    f"{templates} non-evidence template(s), 0 candidate evidence record(s)"
                )
            return 0
        if args.record is None:
            raise LifecycleError("a record path is required")
        if args.template and args.candidate_asset_root is not None:
            raise LifecycleError(
                "--candidate-asset-root is not used when validating a template"
            )
        data = load_closed_json_file(args.record)
        validate_record(
            data,
            allow_template=args.template,
            require_all_passed=args.require_pass,
            candidate_asset_root=args.candidate_asset_root,
        )
    except LifecycleError as error:
        print(f"product-input lifecycle validation failed: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "product-input lifecycle validation failed: operation could not be completed safely",
            file=sys.stderr,
        )
        return 1
    if args.template:
        print("product-input lifecycle template preparation validation passed")
    else:
        print(
            "product-input lifecycle candidate evidence validation passed with "
            "authenticated candidate assets; retained evidence content remains "
            "externally reviewed"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
