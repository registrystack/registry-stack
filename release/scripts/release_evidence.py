#!/usr/bin/env python3
"""Build and render the bounded public Registry Stack release evidence record."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


BUNDLE_SCHEMA = "registry-stack.release-evidence-bundle.v1"
VERIFIER_SCHEMA = "registry-stack.verify-published.v1"
REPOSITORY = "registrystack/registry-stack"
SCOPE_NAME = "pre_evidence_bundle"
EXPECTED_COUNTS = {
    "payloads": 35,
    "signatures": 35,
    "certificates": 35,
    "provenance": 1,
    "total": 106,
}
EXCLUDED_ROLES = [
    "evidence_bundle",
    "evidence_bundle_signature",
    "evidence_bundle_certificate",
    "evidence_bundle_provenance",
]
CHECK_SPECS = {
    "release_metadata": ("publication", "release", "gh"),
    "source_identity": ("publication", "source", "git"),
    "asset_inventory": ("artifacts", "release-assets", "gh"),
    "checksums": ("artifacts", "SHA256SUMS", "python"),
    "cosign_signatures": ("authenticity", "payloads", "cosign"),
    "slsa_provenance": ("authenticity", "payloads", "slsa-verifier"),
    "image_lock_bindings": ("bindings", "registryctl-image-lock", "python"),
    "capsule_bindings": ("bindings", "release-capsule", "python"),
    "sbom_bindings": ("bindings", "SPDX-subjects", "python"),
    "grype_bindings": ("bindings", "Grype-subjects", "python"),
    "image_input_bindings": ("bindings", "image-inputs", "docker"),
    "anonymous_image_access": ("images", "release-images", "docker"),
    "oci_labels": ("images", "release-images", "docker-buildx"),
    "non_root_users": ("images", "release-images", "docker-buildx"),
    "service_versions": ("images", "release-images", "docker"),
    "registryctl_authoring_build": ("journey", "registryctl", "registryctl"),
    "archived_docs": ("documentation", "archived-docset", "https"),
}
FIXED_CHECK_IDS = set(CHECK_SPECS)
FIXED_TOOL_NAMES = {"gh", "cosign", "slsa-verifier", "docker", "docker-buildx"}
IMAGE_COMPONENTS = {"registry-notary", "registry-relay"}
ROLE_COUNT_KEYS = {
    "payload": "payloads",
    "signature": "signatures",
    "certificate": "certificates",
    "provenance": "provenance",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@#=-]{0,255}$")
IMAGE_REPOSITORY = re.compile(r"^ghcr\.io/[a-z0-9._-]+/[a-z0-9._-]+$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class EvidenceError(ValueError):
    """An evidence input does not satisfy the public contract."""


def expected_artifact_names(tag: str) -> dict[str, set[str]]:
    binaries = {
        f"registry-manifest-{tag}-linux-amd64",
        f"registry-notary-{tag}-linux-amd64",
        f"registry-notary-cel-worker-{tag}-linux-amd64",
        f"registry-relay-{tag}-linux-amd64",
        f"registry-relay-rhai-worker-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-arm64",
        f"registryctl-{tag}-macos-arm64",
    }
    image_lock = f"registryctl-{tag}-image-lock.json"
    payloads = {
        *binaries,
        image_lock,
        "SHA256SUMS",
        *(f"{name}.spdx.json" for name in (*sorted(binaries), image_lock)),
        "image-binaries.SHA256SUMS",
        "release-builder-image.txt",
        *(
            f"image-input-{name}.spdx.json"
            for name in (
                "registry-notary",
                "registry-notary-cel-worker",
                "registry-relay",
                "registry-relay-rhai-worker",
            )
        ),
        *(
            f"{component}{suffix}"
            for component in sorted(IMAGE_COMPONENTS)
            for suffix in (".digest", ".metadata.json", ".spdx.json", ".grype.json")
        ),
        f"registry-stack-{tag}-release-capsule.json",
        f"registry-stack-{tag}-release-capsule.md",
    }
    if len(payloads) != EXPECTED_COUNTS["payloads"]:
        raise AssertionError("release payload contract count changed")
    return {
        "payload": payloads,
        "signature": {f"{name}.sig" for name in payloads},
        "certificate": {f"{name}.pem" for name in payloads},
        "provenance": {f"registry-stack-{tag}-release-provenance.intoto.jsonl"},
    }


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise EvidenceError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise EvidenceError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _regular_input(path: Path, maximum: int, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"{label} must be a regular, non-symlink file: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise EvidenceError(f"{label} exceeds {maximum} bytes: {path}")


def _load_json(path: Path, label: str) -> Any:
    _regular_input(path, MAX_JSON_BYTES, label)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {label} {path}: {exc}") from exc


def _load_manifest(path: Path) -> dict[str, Any]:
    _regular_input(path, MAX_MANIFEST_BYTES, "release manifest")
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"cannot read release manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError("release manifest must be an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    missing = sorted(keys - set(value))
    unknown = sorted(set(value) - keys)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing {', '.join(missing)}")
        if unknown:
            parts.append(f"unknown {', '.join(unknown)}")
        raise EvidenceError(f"{label} has {'; '.join(parts)}")
    return value


def _text(
    value: Any,
    label: str,
    *,
    maximum: int = 256,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvidenceError(
            f"{label} must be non-empty text of at most {maximum} characters"
        )
    if not value.isprintable():
        raise EvidenceError(f"{label} contains a control character")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} has an invalid value: {value!r}")
    return value


def _optional_text(
    value: Any,
    label: str,
    *,
    maximum: int = 256,
    pattern: re.Pattern[str] | None = None,
) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=maximum, pattern=pattern)


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be a boolean")
    return value


def _count(value: Any, label: str, *, maximum: int = 512) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise EvidenceError(f"{label} must be an integer from 0 through {maximum}")
    return value


def _hash(value: Any, label: str) -> str:
    return _text(value, label, maximum=64, pattern=HEX64)


def _timestamp(value: Any, label: str) -> datetime:
    text = _text(value, label, maximum=32)
    if not text.endswith("Z"):
        raise EvidenceError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{label} must be an RFC 3339 UTC timestamp") from exc
    return parsed


def _markdown_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("<", "&lt;").replace(">", "&gt;")


def _validate_manifest(
    manifest: dict[str, Any], path: Path
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    stack = manifest.get("stack")
    if not isinstance(stack, dict):
        raise EvidenceError("release manifest stack must be an object")
    release_id = _text(
        stack.get("release"), "manifest stack.release", maximum=64, pattern=RELEASE_ID
    )
    version = _text(
        stack.get("version"), "manifest stack.version", maximum=32, pattern=SEMVER
    )
    repository = _text(
        stack.get("source_repo"), "manifest stack.source_repo", maximum=64
    )
    source_ref = _text(
        stack.get("source_ref"), "manifest stack.source_ref", maximum=40, pattern=HEX40
    )
    tag = _text(stack.get("source_tag"), "manifest stack.source_tag", maximum=33)
    if repository != REPOSITORY:
        raise EvidenceError(f"manifest stack.source_repo must be {REPOSITORY}")
    if tag != f"v{version}":
        raise EvidenceError(f"manifest stack.source_tag must be v{version}")
    if path.name != f"registry-stack-{release_id}.yaml":
        raise EvidenceError(
            "release manifest filename must match manifest stack.release"
        )

    raw_warnings = manifest.get("warnings", [])
    if not isinstance(raw_warnings, list) or len(raw_warnings) > 64:
        raise EvidenceError(
            "manifest warnings must be an array with at most 64 entries"
        )
    warnings: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_warnings):
        warning = _exact_object(
            raw, {"code", "classification", "detail"}, f"manifest warning {index}"
        )
        code = _text(
            warning["code"],
            f"manifest warning {index} code",
            maximum=80,
            pattern=SAFE_NAME,
        )
        classification = _text(
            warning["classification"],
            f"manifest warning {index} classification",
            maximum=80,
            pattern=SAFE_NAME,
        )
        detail = _text(
            warning["detail"], f"manifest warning {index} detail", maximum=1000
        )
        if code in seen:
            raise EvidenceError(f"duplicate manifest warning code: {code}")
        seen.add(code)
        warnings.append(
            {"code": code, "classification": classification, "detail": detail}
        )
    warnings.sort(key=lambda item: item["code"])
    return {
        "repository": repository,
        "release_id": release_id,
        "version": version,
        "tag": tag,
        "source_ref": source_ref,
    }, warnings


def _validate_capsule(
    capsule: Any,
    identity: dict[str, str],
    manifest_sha256: str,
    verifier: dict[str, Any],
) -> None:
    if not isinstance(capsule, dict):
        raise EvidenceError("release capsule must be an object")
    for field, expected in (
        ("release_tag", identity["tag"]),
        ("version", identity["version"]),
        ("repository", identity["repository"]),
    ):
        if capsule.get(field) != expected:
            raise EvidenceError(f"release capsule {field} does not match the manifest")
    capsule_manifest = capsule.get("manifest")
    if (
        not isinstance(capsule_manifest, dict)
        or capsule_manifest.get("sha256") != manifest_sha256
    ):
        raise EvidenceError(
            "release capsule manifest SHA-256 does not match the manifest"
        )
    source = capsule.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("lineage"), dict):
        raise EvidenceError("release capsule source lineage is missing")
    lineage = verifier["lineage"]
    capsule_lineage = source["lineage"]
    bindings = {
        "source_tag": identity["tag"],
        "source_ref": identity["source_ref"],
        "source_commit": lineage["tag_target"],
        "manifest_ref": identity["source_ref"],
    }
    for field, expected in bindings.items():
        if source.get(field) != expected:
            raise EvidenceError(
                f"release capsule source {field} does not match verifier lineage"
            )
    for field in (
        "tag_matches_source_tag",
        "head_matches_tag_target",
        "source_ref_ancestor_or_equal",
        "default_branch_reachable",
    ):
        if capsule_lineage.get(field) != lineage[field]:
            raise EvidenceError(
                f"release capsule lineage {field} does not match verifier lineage"
            )
    capsule_workflow = capsule.get("workflow")
    workflow = verifier["workflow"]
    if not isinstance(capsule_workflow, dict):
        raise EvidenceError("release capsule workflow is missing")
    for capsule_field, workflow_field in (
        ("name", "name"),
        ("run_id", "run_id"),
        ("run_url", "run_url"),
    ):
        expected = workflow[workflow_field]
        if expected is not None and str(capsule_workflow.get(capsule_field)) != str(
            expected
        ):
            raise EvidenceError(
                f"release capsule workflow {capsule_field} does not match verifier workflow"
            )


def _validate_counts(value: Any, label: str) -> dict[str, int]:
    counts = _exact_object(value, set(EXPECTED_COUNTS), label)
    normalized = {key: _count(counts[key], f"{label} {key}") for key in EXPECTED_COUNTS}
    if normalized["total"] != sum(normalized[key] for key in ROLE_COUNT_KEYS.values()):
        raise EvidenceError(f"{label} total does not equal its role counts")
    return normalized


def _validate_verifier(
    verifier: Any, identity: dict[str, str], manifest_sha256: str
) -> dict[str, Any]:
    top = _exact_object(
        verifier,
        {
            "schema_version",
            "classification",
            "status",
            "release",
            "lineage",
            "workflow",
            "tools",
            "artifact_scope",
            "artifacts",
            "images",
            "checks",
            "warnings",
        },
        "published verification result",
    )
    if top["schema_version"] != VERIFIER_SCHEMA:
        raise EvidenceError(
            f"published verification schema_version must be {VERIFIER_SCHEMA}"
        )
    if top["classification"] != "public":
        raise EvidenceError("published verification classification must be public")
    status = top["status"]
    if status not in {"passed", "failed", "incomplete"}:
        raise EvidenceError(
            "published verification status must be passed, failed, or incomplete"
        )

    release = _exact_object(
        top["release"],
        {"repository", "release_id", "version", "tag", "manifest_sha256"},
        "published verification release",
    )
    for field in ("repository", "release_id", "version", "tag"):
        if release[field] != identity[field]:
            raise EvidenceError(
                f"published verification release {field} does not match the manifest"
            )
    if (
        _hash(release["manifest_sha256"], "published verification manifest_sha256")
        != manifest_sha256
    ):
        raise EvidenceError(
            "published verification manifest SHA-256 does not match the manifest"
        )

    lineage = _exact_object(
        top["lineage"],
        {
            "manifest_source_ref",
            "tag_target",
            "default_branch",
            "default_branch_commit",
            "tag_matches_source_tag",
            "head_matches_tag_target",
            "source_ref_ancestor_or_equal",
            "default_branch_reachable",
        },
        "published verification lineage",
    )
    if lineage["manifest_source_ref"] != identity["source_ref"]:
        raise EvidenceError(
            "published verification lineage does not match manifest source_ref"
        )
    _text(
        lineage["tag_target"],
        "published verification tag_target",
        maximum=40,
        pattern=HEX40,
    )
    _text(
        lineage["default_branch"],
        "published verification default_branch",
        maximum=80,
        pattern=SAFE_NAME,
    )
    _text(
        lineage["default_branch_commit"],
        "published verification default_branch_commit",
        maximum=40,
        pattern=HEX40,
    )
    for field in (
        "tag_matches_source_tag",
        "head_matches_tag_target",
        "source_ref_ancestor_or_equal",
        "default_branch_reachable",
    ):
        _bool(lineage[field], f"published verification lineage {field}")

    workflow = _exact_object(
        top["workflow"],
        {
            "name",
            "run_id",
            "run_attempt",
            "run_url",
            "event",
            "ref",
            "head_sha",
            "started_at",
            "completed_at",
            "duration_seconds",
        },
        "published verification workflow",
    )
    _optional_text(workflow["name"], "workflow name", maximum=100)
    run_id = _optional_text(
        workflow["run_id"],
        "workflow run_id",
        maximum=20,
        pattern=re.compile(r"^[1-9][0-9]*$"),
    )
    run_url = _optional_text(workflow["run_url"], "workflow run_url", maximum=256)
    if (run_id is None) != (run_url is None):
        raise EvidenceError(
            "workflow run_id and run_url must both be present or both be null"
        )
    if (
        run_url is not None
        and run_url != f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    ):
        raise EvidenceError("workflow run_url does not bind the repository and run_id")
    _optional_text(
        workflow["run_attempt"],
        "workflow run_attempt",
        maximum=10,
        pattern=re.compile(r"^[1-9][0-9]*$"),
    )
    event = _optional_text(workflow["event"], "workflow event", maximum=32)
    if event is not None and event not in {"push", "workflow_dispatch"}:
        raise EvidenceError("workflow event must be push, workflow_dispatch, or null")
    ref = _optional_text(workflow["ref"], "workflow ref", maximum=128)
    if ref is not None and ref != f"refs/tags/{identity['tag']}":
        raise EvidenceError("workflow ref does not match the release tag")
    head_sha = _optional_text(
        workflow["head_sha"], "workflow head_sha", maximum=40, pattern=HEX40
    )
    if head_sha is not None and head_sha != lineage["tag_target"]:
        raise EvidenceError("workflow head_sha does not match the tag target")
    timing = (
        workflow["started_at"],
        workflow["completed_at"],
        workflow["duration_seconds"],
    )
    if any(value is None for value in timing) and not all(
        value is None for value in timing
    ):
        raise EvidenceError("workflow timing fields must all be present or all be null")
    if all(value is not None for value in timing):
        started = _timestamp(workflow["started_at"], "workflow started_at")
        completed = _timestamp(workflow["completed_at"], "workflow completed_at")
        duration = workflow["duration_seconds"]
        if (
            not isinstance(duration, int)
            or isinstance(duration, bool)
            or not 0 <= duration <= 604800
        ):
            raise EvidenceError(
                "workflow duration_seconds must be an integer from 0 through 604800"
            )
        if (
            completed < started
            or int((completed - started).total_seconds()) != duration
        ):
            raise EvidenceError(
                "workflow duration_seconds does not match its timestamps"
            )

    tools = top["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 64:
        raise EvidenceError(
            "published verification tools must contain 1 through 64 entries"
        )
    tool_names: set[str] = set()
    for index, item in enumerate(tools):
        tool = _exact_object(item, {"name", "version", "source"}, f"tool {index}")
        name = _text(tool["name"], f"tool {index} name", maximum=80, pattern=SAFE_NAME)
        _text(tool["version"], f"tool {index} version", maximum=200)
        if tool["source"] != "observed":
            raise EvidenceError(f"tool {index} source must be observed")
        if name in tool_names:
            raise EvidenceError(f"duplicate observed tool: {name}")
        tool_names.add(name)
    if tool_names != FIXED_TOOL_NAMES:
        raise EvidenceError(
            "observed tools do not match the fixed published verifier tool set"
        )

    scope = _exact_object(
        top["artifact_scope"],
        {"name", "expected_counts", "observed_counts", "excluded_roles"},
        "published verification artifact_scope",
    )
    if scope["name"] != SCOPE_NAME:
        raise EvidenceError(f"artifact_scope name must be {SCOPE_NAME}")
    expected_counts = _validate_counts(
        scope["expected_counts"], "artifact_scope expected_counts"
    )
    if expected_counts != EXPECTED_COUNTS:
        raise EvidenceError(
            "artifact_scope expected_counts do not match the public release contract"
        )
    observed_counts = _validate_counts(
        scope["observed_counts"], "artifact_scope observed_counts"
    )
    if scope["excluded_roles"] != EXCLUDED_ROLES:
        raise EvidenceError(
            "artifact_scope excluded_roles do not match the non-recursive evidence contract"
        )

    artifacts = top["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > EXPECTED_COUNTS["total"]:
        raise EvidenceError(
            "published verification artifacts must contain at most 106 entries"
        )
    names: set[str] = set()
    role_counts = {key: 0 for key in ROLE_COUNT_KEYS.values()}
    artifact_failure = False
    for index, item in enumerate(artifacts):
        artifact = _exact_object(
            item,
            {"name", "role", "payload_name", "size_bytes", "sha256", "verification"},
            f"artifact {index}",
        )
        name = _text(
            artifact["name"], f"artifact {index} name", maximum=200, pattern=SAFE_NAME
        )
        if name in names:
            raise EvidenceError(f"duplicate artifact name: {name}")
        names.add(name)
        role = artifact["role"]
        if role not in ROLE_COUNT_KEYS:
            raise EvidenceError(f"artifact {name} has an invalid role")
        role_counts[ROLE_COUNT_KEYS[role]] += 1
        payload_name = artifact["payload_name"]
        if role == "payload":
            if payload_name is not None:
                raise EvidenceError(
                    f"payload artifact {name} payload_name must be null"
                )
        elif role in {"signature", "certificate"}:
            _text(
                payload_name,
                f"artifact {name} payload_name",
                maximum=200,
                pattern=SAFE_NAME,
            )
        elif payload_name is not None:
            _text(
                payload_name,
                f"artifact {name} payload_name",
                maximum=200,
                pattern=SAFE_NAME,
            )
        size = artifact["size_bytes"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_ARTIFACT_BYTES
        ):
            raise EvidenceError(
                f"artifact {name} size_bytes must be from 1 through {MAX_ARTIFACT_BYTES}"
            )
        _hash(artifact["sha256"], f"artifact {name} sha256")
        verification = _exact_object(
            artifact["verification"],
            {"checksum", "signature", "provenance"},
            f"artifact {name} verification",
        )
        if role == "payload":
            allowed = {"passed", "failed"}
        else:
            allowed = {"not_applicable"}
        for field in ("checksum", "signature", "provenance"):
            if verification[field] not in allowed:
                raise EvidenceError(
                    f"artifact {name} verification {field} is invalid for role {role}"
                )
            artifact_failure = artifact_failure or verification[field] == "failed"
    role_counts["total"] = len(artifacts)
    if role_counts != observed_counts:
        raise EvidenceError(
            "artifact_scope observed_counts do not match the artifact array"
        )
    payload_names = {item["name"] for item in artifacts if item["role"] == "payload"}
    for item in artifacts:
        if (
            item["role"] in {"signature", "certificate"}
            and item["payload_name"] not in payload_names
        ):
            raise EvidenceError(f"artifact {item['name']} names an unknown payload")
    for role in ("signature", "certificate"):
        bindings = [item["payload_name"] for item in artifacts if item["role"] == role]
        if len(bindings) != len(set(bindings)) or set(bindings) != payload_names:
            raise EvidenceError(
                f"{role} artifacts must bind every payload exactly once"
            )
    expected_names = expected_artifact_names(identity["tag"])
    for role, role_names in expected_names.items():
        actual_role_names = {item["name"] for item in artifacts if item["role"] == role}
        if actual_role_names != role_names:
            raise EvidenceError(
                f"{role} artifact names do not match the fixed release contract"
            )

    images = top["images"]
    if not isinstance(images, list) or len(images) != len(IMAGE_COMPONENTS):
        raise EvidenceError(
            "published verification images must contain the two fixed release images"
        )
    image_components: set[str] = set()
    image_failure = False
    for index, item in enumerate(images):
        image = _exact_object(
            item,
            {
                "component",
                "repository",
                "tag_ref",
                "digest_ref",
                "digest",
                "anonymous_tag_pull",
                "anonymous_digest_pull",
                "config_user",
                "labels",
                "reported_version",
            },
            f"image {index}",
        )
        component = _text(
            image["component"],
            f"image {index} component",
            maximum=80,
            pattern=SAFE_NAME,
        )
        if component in image_components:
            raise EvidenceError(f"duplicate image component: {component}")
        image_components.add(component)
        repository = _text(
            image["repository"],
            f"image {component} repository",
            maximum=160,
            pattern=IMAGE_REPOSITORY,
        )
        if repository != f"ghcr.io/registrystack/{component}":
            raise EvidenceError(
                f"image {component} repository does not match its component"
            )
        digest = _text(
            image["digest"],
            f"image {component} digest",
            maximum=71,
            pattern=IMAGE_DIGEST,
        )
        if image["tag_ref"] != f"{repository}:{identity['tag']}":
            raise EvidenceError(
                f"image {component} tag_ref does not match the release tag"
            )
        if image["digest_ref"] != f"{repository}@{digest}":
            raise EvidenceError(
                f"image {component} digest_ref does not match repository and digest"
            )
        for field in ("anonymous_tag_pull", "anonymous_digest_pull"):
            if image[field] not in {"passed", "failed"}:
                raise EvidenceError(
                    f"image {component} {field} must be passed or failed"
                )
            image_failure = image_failure or image[field] == "failed"
        config_user = _text(
            image["config_user"],
            f"image {component} config_user",
            maximum=80,
            pattern=SAFE_TOKEN,
        )
        if config_user != "65532":
            raise EvidenceError(
                f"image {component} config_user is not the release non-root user"
            )
        labels = _exact_object(
            image["labels"],
            {"source", "revision", "version"},
            f"image {component} labels",
        )
        if labels["source"] != f"https://github.com/{REPOSITORY}":
            raise EvidenceError(
                f"image {component} source label does not match the repository"
            )
        if labels["revision"] != lineage["tag_target"]:
            raise EvidenceError(
                f"image {component} revision label does not match the tag target"
            )
        if labels["version"] != identity["version"]:
            raise EvidenceError(
                f"image {component} version label does not match the release"
            )
        if image["reported_version"] != f"{component} {identity['version']}":
            raise EvidenceError(
                f"image {component} reported_version does not match the release"
            )
    if image_components != IMAGE_COMPONENTS:
        raise EvidenceError(
            "published verification image components do not match the fixed release images"
        )

    checks = top["checks"]
    if not isinstance(checks, list) or len(checks) != len(FIXED_CHECK_IDS):
        raise EvidenceError(
            f"published verification checks must contain exactly {len(FIXED_CHECK_IDS)} entries"
        )
    check_ids: set[str] = set()
    check_failed = False
    check_incomplete = False
    for index, item in enumerate(checks):
        check = _exact_object(
            item,
            {"id", "phase", "subject", "status", "tool", "failure_codes"},
            f"check {index}",
        )
        check_id = _text(
            check["id"], f"check {index} id", maximum=80, pattern=SAFE_NAME
        )
        if check_id in check_ids:
            raise EvidenceError(f"duplicate check id: {check_id}")
        check_ids.add(check_id)
        phase = _text(
            check["phase"], f"check {check_id} phase", maximum=80, pattern=SAFE_NAME
        )
        subject = _text(
            check["subject"],
            f"check {check_id} subject",
            maximum=200,
            pattern=SAFE_TOKEN,
        )
        tool = _text(
            check["tool"], f"check {check_id} tool", maximum=80, pattern=SAFE_NAME
        )
        if check_id in CHECK_SPECS and (phase, subject, tool) != CHECK_SPECS[check_id]:
            raise EvidenceError(
                f"check {check_id} metadata does not match the fixed contract"
            )
        check_status = check["status"]
        if check_status not in {"passed", "failed", "incomplete"}:
            raise EvidenceError(f"check {check_id} has an invalid status")
        check_failed = check_failed or check_status == "failed"
        check_incomplete = check_incomplete or check_status == "incomplete"
        failure_codes = check["failure_codes"]
        if not isinstance(failure_codes, list) or len(failure_codes) > 32:
            raise EvidenceError(
                f"check {check_id} failure_codes must be an array with at most 32 entries"
            )
        normalized_codes = [
            _text(code, f"check {check_id} failure code", maximum=80, pattern=SAFE_NAME)
            for code in failure_codes
        ]
        if len(set(normalized_codes)) != len(normalized_codes):
            raise EvidenceError(f"check {check_id} has duplicate failure codes")
        if check_status == "passed" and failure_codes:
            raise EvidenceError(
                f"check {check_id} failure_codes are inconsistent with its status"
            )
        if check_status == "failed" and not failure_codes:
            raise EvidenceError(
                f"check {check_id} failure_codes are inconsistent with its status"
            )
        if check_status == "incomplete" and failure_codes:
            raise EvidenceError(
                f"check {check_id} failure_codes are inconsistent with its status"
            )
    if check_ids != FIXED_CHECK_IDS:
        raise EvidenceError(
            "published verification check IDs do not match the fixed release checks"
        )

    warnings = top["warnings"]
    if not isinstance(warnings, list) or len(warnings) > 64:
        raise EvidenceError(
            "published verification warnings must be an array with at most 64 entries"
        )
    warning_pairs: set[tuple[str, str]] = set()
    for index, item in enumerate(warnings):
        warning = _exact_object(
            item, {"code", "subject"}, f"published verification warning {index}"
        )
        code = _text(
            warning["code"],
            f"published verification warning {index} code",
            maximum=80,
            pattern=SAFE_NAME,
        )
        subject = _text(
            warning["subject"],
            f"published verification warning {index} subject",
            maximum=80,
            pattern=SAFE_NAME,
        )
        if (code, subject) in warning_pairs:
            raise EvidenceError(f"duplicate published verification warning: {code}")
        warning_pairs.add((code, subject))

    inventory_exact = observed_counts == expected_counts == EXPECTED_COUNTS
    has_failure = artifact_failure or image_failure or check_failed
    has_incomplete = check_incomplete or not inventory_exact
    derived_status = (
        "failed" if has_failure else "incomplete" if has_incomplete else "passed"
    )
    if status != derived_status:
        raise EvidenceError(
            f"published verification status {status} is inconsistent; expected {derived_status}"
        )
    if status == "passed" and not all(
        lineage[field]
        for field in (
            "tag_matches_source_tag",
            "head_matches_tag_target",
            "source_ref_ancestor_or_equal",
            "default_branch_reachable",
        )
    ):
        raise EvidenceError(
            "passed verification requires every source lineage assertion"
        )
    return top


def _asset_inventory(
    asset_dir: Path, artifacts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if asset_dir.is_symlink() or not asset_dir.is_dir():
        raise EvidenceError(
            f"asset directory must be a non-symlink directory: {asset_dir}"
        )
    entries = list(asset_dir.iterdir())
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise EvidenceError(
                f"asset directory contains a non-regular entry: {entry.name}"
            )
    actual_names = {entry.name for entry in entries}
    expected_names = {artifact["name"] for artifact in artifacts}
    missing = sorted(expected_names - actual_names)
    unknown = sorted(actual_names - expected_names)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing {', '.join(missing)}")
        if unknown:
            parts.append(f"unknown {', '.join(unknown)}")
        raise EvidenceError(f"asset directory has {'; '.join(parts)}")
    normalized: list[dict[str, Any]] = []
    for artifact in sorted(artifacts, key=lambda item: item["name"]):
        path = asset_dir / artifact["name"]
        size = path.stat().st_size
        if not 0 < size <= MAX_ARTIFACT_BYTES:
            raise EvidenceError(
                f"artifact {artifact['name']} has an invalid actual size"
            )
        digest = _sha256(path)
        if size != artifact["size_bytes"]:
            raise EvidenceError(
                f"artifact {artifact['name']} size does not match verifier result"
            )
        if digest != artifact["sha256"]:
            raise EvidenceError(
                f"artifact {artifact['name']} SHA-256 does not match verifier result"
            )
        normalized.append(dict(artifact))
    return normalized


def build_evidence_bundle(
    manifest_path: Path,
    capsule_path: Path,
    verification_path: Path,
    asset_dir: Path,
) -> dict[str, Any]:
    """Validate source records and return a deterministic public evidence bundle."""
    manifest = _load_manifest(manifest_path)
    identity, warnings = _validate_manifest(manifest, manifest_path)
    manifest_sha256 = _sha256(manifest_path)
    verifier = _validate_verifier(
        _load_json(verification_path, "published verification result"),
        identity,
        manifest_sha256,
    )
    capsule = _load_json(capsule_path, "release capsule")
    _validate_capsule(capsule, identity, manifest_sha256, verifier)
    capsule_sha256 = _sha256(capsule_path)
    artifacts = _asset_inventory(asset_dir, verifier["artifacts"])
    bound = next(
        (item for item in artifacts if item["name"] == capsule_path.name), None
    )
    if bound is None or bound["role"] != "payload" or bound["sha256"] != capsule_sha256:
        raise EvidenceError(
            "release capsule is not bound as an exact payload in the scoped artifact inventory"
        )
    gates = [
        {
            "code": item["code"],
            "classification": item["classification"],
            "status": "held" if item["classification"].endswith("-held") else "pending",
        }
        for item in warnings
        if item["classification"].endswith(("-held", "-pending"))
    ]
    gates.sort(key=lambda item: item["code"])

    bundle = {
        "schema_version": BUNDLE_SCHEMA,
        "record_kind": "public_release_evidence",
        "classification": "public",
        "release": {
            "repository": identity["repository"],
            "release_id": identity["release_id"],
            "version": identity["version"],
            "tag": identity["tag"],
            "manifest": {"name": manifest_path.name, "sha256": manifest_sha256},
            "capsule": {"asset_name": capsule_path.name, "sha256": capsule_sha256},
        },
        "lineage": dict(verifier["lineage"]),
        "workflow": dict(verifier["workflow"]),
        "tools": sorted(
            (dict(item) for item in verifier["tools"]), key=lambda item: item["name"]
        ),
        "artifact_inventory": {
            "scope_name": SCOPE_NAME,
            "expected_counts": dict(EXPECTED_COUNTS),
            "observed_counts": dict(verifier["artifact_scope"]["observed_counts"]),
            "excluded_roles": list(EXCLUDED_ROLES),
            "artifacts": artifacts,
        },
        "verification": {
            "status": verifier["status"],
            "checks": sorted(
                (
                    {**item, "failure_codes": sorted(item["failure_codes"])}
                    for item in verifier["checks"]
                ),
                key=lambda item: item["id"],
            ),
            "images": sorted(
                (dict(item) for item in verifier["images"]),
                key=lambda item: item["component"],
            ),
            "warnings": sorted(
                (dict(item) for item in verifier["warnings"]),
                key=lambda item: (item["code"], item["subject"]),
            ),
        },
        "warnings": warnings,
        "gates": gates,
        "privacy": {
            "raw_logs_included": False,
            "environment_values_included": False,
            "commands_included": False,
            "private_evidence_included": False,
            "restricted_evidence_included": False,
            "secret_values_included": False,
        },
    }
    return bundle


def write_evidence_bundle(
    manifest_path: Path,
    capsule_path: Path,
    verification_path: Path,
    asset_dir: Path,
    output_path: Path,
) -> dict[str, Any]:
    if output_path.exists() and output_path.is_symlink():
        raise EvidenceError(
            f"evidence bundle output must not be a symlink: {output_path}"
        )
    output_resolved = output_path.resolve()
    if output_resolved in {
        manifest_path.resolve(),
        capsule_path.resolve(),
        verification_path.resolve(),
    }:
        raise EvidenceError("evidence bundle output must not overwrite an input")
    try:
        output_resolved.relative_to(asset_dir.resolve())
    except ValueError:
        pass
    else:
        raise EvidenceError(
            "evidence bundle output is outside the pre_evidence_bundle artifact scope "
            "and must not be inside asset-dir"
        )
    bundle = build_evidence_bundle(
        manifest_path, capsule_path, verification_path, asset_dir
    )
    body = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(body, encoding="utf-8")
    return bundle


def _validate_bundle_for_render(value: Any) -> dict[str, Any]:
    bundle = _exact_object(
        value,
        {
            "schema_version",
            "record_kind",
            "classification",
            "release",
            "lineage",
            "workflow",
            "tools",
            "artifact_inventory",
            "verification",
            "warnings",
            "gates",
            "privacy",
        },
        "release evidence bundle",
    )
    if (
        bundle["schema_version"] != BUNDLE_SCHEMA
        or bundle["record_kind"] != "public_release_evidence"
    ):
        raise EvidenceError("release evidence bundle has an unsupported identity")
    if bundle["classification"] != "public":
        raise EvidenceError("release evidence bundle classification must be public")
    release = _exact_object(
        bundle["release"],
        {"repository", "release_id", "version", "tag", "manifest", "capsule"},
        "bundle release",
    )
    release_id = _text(
        release["release_id"], "bundle release ID", maximum=64, pattern=RELEASE_ID
    )
    version = _text(
        release["version"], "bundle release version", maximum=32, pattern=SEMVER
    )
    if release["repository"] != REPOSITORY or release["tag"] != f"v{version}":
        raise EvidenceError("release evidence bundle identity is inconsistent")
    bindings: dict[str, dict[str, str]] = {}
    for field in ("manifest", "capsule"):
        name_field = "name" if field == "manifest" else "asset_name"
        binding = _exact_object(
            release[field], {name_field, "sha256"}, f"bundle release {field}"
        )
        bindings[field] = {
            "name": _text(
                binding[name_field],
                f"bundle release {field} {name_field}",
                maximum=200,
                pattern=SAFE_NAME,
            ),
            "sha256": _hash(binding["sha256"], f"bundle release {field} sha256"),
        }
    if bindings["manifest"]["name"] != f"registry-stack-{release_id}.yaml":
        raise EvidenceError("bundle manifest name does not match release_id")

    inventory = _exact_object(
        bundle["artifact_inventory"],
        {
            "scope_name",
            "expected_counts",
            "observed_counts",
            "excluded_roles",
            "artifacts",
        },
        "bundle artifact_inventory",
    )
    if (
        inventory["scope_name"] != SCOPE_NAME
        or inventory["excluded_roles"] != EXCLUDED_ROLES
    ):
        raise EvidenceError("bundle artifact inventory scope is invalid")
    expected = _validate_counts(inventory["expected_counts"], "bundle expected_counts")
    observed = _validate_counts(inventory["observed_counts"], "bundle observed_counts")
    if expected != EXPECTED_COUNTS:
        raise EvidenceError("bundle expected counts are invalid")
    verification = _exact_object(
        bundle["verification"],
        {"status", "checks", "images", "warnings"},
        "bundle verification",
    )
    lineage = bundle["lineage"]
    if not isinstance(lineage, dict):
        raise EvidenceError("bundle lineage must be an object")
    source_ref = lineage.get("manifest_source_ref")
    if not isinstance(source_ref, str):
        raise EvidenceError("bundle lineage manifest_source_ref must be text")

    warnings = bundle["warnings"]
    if not isinstance(warnings, list) or len(warnings) > 64:
        raise EvidenceError("bundle warnings must be an array with at most 64 entries")
    normalized_warnings: list[dict[str, str]] = []
    warning_codes: set[str] = set()
    for index, item in enumerate(warnings):
        warning = _exact_object(
            item, {"code", "classification", "detail"}, f"bundle warning {index}"
        )
        code = _text(
            warning["code"],
            f"bundle warning {index} code",
            maximum=80,
            pattern=SAFE_NAME,
        )
        classification = _text(
            warning["classification"],
            f"bundle warning {index} classification",
            maximum=80,
            pattern=SAFE_NAME,
        )
        detail = _text(
            warning["detail"], f"bundle warning {index} detail", maximum=1000
        )
        if code in warning_codes:
            raise EvidenceError(f"duplicate bundle warning code: {code}")
        warning_codes.add(code)
        normalized_warnings.append(
            {"code": code, "classification": classification, "detail": detail}
        )
    if normalized_warnings != sorted(
        normalized_warnings, key=lambda item: item["code"]
    ):
        raise EvidenceError("bundle warnings must be sorted by code")

    expected_gates = [
        {
            "code": item["code"],
            "classification": item["classification"],
            "status": "held" if item["classification"].endswith("-held") else "pending",
        }
        for item in normalized_warnings
        if item["classification"].endswith(("-held", "-pending"))
    ]
    gates = bundle["gates"]
    if not isinstance(gates, list) or len(gates) > 64:
        raise EvidenceError("bundle gates must be an array with at most 64 entries")
    normalized_gates = []
    for index, item in enumerate(gates):
        gate = _exact_object(
            item, {"code", "classification", "status"}, f"bundle gate {index}"
        )
        normalized_gates.append(
            {
                "code": _text(
                    gate["code"],
                    f"bundle gate {index} code",
                    maximum=80,
                    pattern=SAFE_NAME,
                ),
                "classification": _text(
                    gate["classification"],
                    f"bundle gate {index} classification",
                    maximum=80,
                    pattern=SAFE_NAME,
                ),
                "status": gate["status"],
            }
        )
    if normalized_gates != expected_gates:
        raise EvidenceError(
            "bundle gates do not exactly match held and pending warnings"
        )

    privacy = _exact_object(
        bundle["privacy"],
        {
            "raw_logs_included",
            "environment_values_included",
            "commands_included",
            "private_evidence_included",
            "restricted_evidence_included",
            "secret_values_included",
        },
        "release evidence bundle privacy",
    )
    if any(item is not False for item in privacy.values()):
        raise EvidenceError("release evidence bundle privacy flags must all be false")

    verifier = {
        "schema_version": VERIFIER_SCHEMA,
        "classification": "public",
        "status": verification["status"],
        "release": {
            "repository": release["repository"],
            "release_id": release_id,
            "version": version,
            "tag": release["tag"],
            "manifest_sha256": bindings["manifest"]["sha256"],
        },
        "lineage": lineage,
        "workflow": bundle["workflow"],
        "tools": bundle["tools"],
        "artifact_scope": {
            "name": inventory["scope_name"],
            "expected_counts": expected,
            "observed_counts": observed,
            "excluded_roles": inventory["excluded_roles"],
        },
        "artifacts": inventory["artifacts"],
        "images": verification["images"],
        "checks": verification["checks"],
        "warnings": verification["warnings"],
    }
    _validate_verifier(
        verifier,
        {
            "repository": release["repository"],
            "release_id": release_id,
            "version": version,
            "tag": release["tag"],
            "source_ref": source_ref,
        },
        bindings["manifest"]["sha256"],
    )
    artifact_bindings = {
        item["name"]: item
        for item in inventory["artifacts"]
        if item["role"] == "payload"
    }
    bound_capsule = artifact_bindings.get(bindings["capsule"]["name"])
    if (
        bound_capsule is None
        or bound_capsule["sha256"] != bindings["capsule"]["sha256"]
    ):
        raise EvidenceError(
            "bundle capsule binding does not match the artifact inventory"
        )
    return bundle


def render_closeout(bundle: dict[str, Any]) -> str:
    """Render a public closeout whose success wording is status-gated."""
    bundle = _validate_bundle_for_render(bundle)
    release = bundle["release"]
    verification = bundle["verification"]
    status = verification["status"]
    status_line = (
        "Release contract verification: PASSED."
        if status == "passed"
        else f"Release closeout is NOT SUCCESSFUL. Verification status: {status.upper()}."
    )
    workflow = bundle["workflow"]
    workflow_text = "manual or unavailable"
    if workflow.get("run_url") is not None:
        workflow_text = (
            f"{_markdown_text(workflow.get('name') or 'workflow')} "
            f"run {workflow['run_id']} ({workflow['run_url']})"
        )
    timing_text = "not recorded"
    if workflow.get("started_at") is not None:
        timing_text = (
            f"{workflow['started_at']} to {workflow['completed_at']} "
            f"({workflow['duration_seconds']} seconds)"
        )
    counts = bundle["artifact_inventory"]["observed_counts"]
    lines = [
        f"# Registry Stack {release['tag']} Release Closeout",
        "",
        f"**{status_line}**",
        "",
        "## Public release identity",
        "",
        "- Classification: `public`",
        f"- Repository: `{release['repository']}`",
        f"- Release ID: `{release['release_id']}`",
        f"- Version and tag: `{release['version']}` / `{release['tag']}`",
        f"- Manifest: `{release['manifest']['name']}` sha256 `{release['manifest']['sha256']}`",
        f"- Release capsule: `{release['capsule']['asset_name']}` sha256 `{release['capsule']['sha256']}`",
        "",
        "## Source and workflow",
        "",
        f"- Manifest source ref: `{bundle['lineage']['manifest_source_ref']}`",
        f"- Tag target: `{bundle['lineage']['tag_target']}`",
        f"- Default branch commit: `{bundle['lineage']['default_branch_commit']}`",
        f"- Workflow: {workflow_text}",
        f"- Timing: {timing_text}",
        "",
        "## Scoped artifact verification",
        "",
        f"- Scope: `{bundle['artifact_inventory']['scope_name']}`",
        (
            f"- Observed: {counts['total']} total, {counts['payloads']} payloads, "
            f"{counts['signatures']} signatures, {counts['certificates']} certificates, "
            f"{counts['provenance']} provenance"
        ),
        (
            "- Evidence bundle signature, certificate, and provenance are deliberately "
            "excluded from this pre-bundle scope and are produced by the subsequent "
            "signing pass."
        ),
        "",
        "## Observed tools",
        "",
    ]
    lines.extend(
        f"- `{item['name']}` `{_markdown_text(item['version'])}`"
        for item in bundle["tools"]
    )
    lines.extend(["", "## Gates and warnings", ""])
    if bundle["gates"]:
        lines.extend(
            f"- Gate `{item['code']}` remains **{item['status'].upper()}** (`{item['classification']}`)."
            for item in bundle["gates"]
        )
    else:
        lines.append("- No held or pending public gates are recorded.")
    for warning in bundle["warnings"]:
        lines.append(
            f"- Warning `{warning['code']}` (`{warning['classification']}`): "
            f"{_markdown_text(warning['detail'])}"
        )
    for warning in verification["warnings"]:
        lines.append(
            f"- Verifier warning `{warning['code']}` for `{warning['subject']}`."
        )
    lines.extend(
        [
            "",
            "## Privacy boundary",
            "",
            (
                "- Raw logs, environment values, commands, private or restricted evidence, "
                "and secret values are not included."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def render_closeout_file(bundle_path: Path, output_path: Path) -> str:
    if output_path.exists() and output_path.is_symlink():
        raise EvidenceError(
            f"release closeout output must not be a symlink: {output_path}"
        )
    if output_path.resolve() == bundle_path.resolve():
        raise EvidenceError(
            "release closeout output must not overwrite its evidence bundle"
        )
    bundle = _load_json(bundle_path, "release evidence bundle")
    body = render_closeout(bundle)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(body, encoding="utf-8")
    return bundle["verification"]["status"]
