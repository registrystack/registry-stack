#!/usr/bin/env python3
"""Validate a redaction-safe Registry Stack upgrade exercise record."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "registry-stack.upgrade-exercise/v1"
SOLMARA_REPOSITORY = "registrystack/solmara-lab"
CONFIG_SCHEMAS = {
    "registry-relay": Path("schemas/registry-relay.config.schema.json"),
    "registry-notary": Path("schemas/registry-notary.config.schema.json"),
}
REQUIRED_CHECKS = (
    "candidate_artifacts_independently_verified",
    "source_release_ready",
    "pre_upgrade_complete_backup",
    "notary_forward_schema_upgrade",
    "older_notary_rejects_newer_schema",
    "target_products_ready_before_traffic",
    "one_notary_authority_per_relay_authority",
    "registry_backed_direct_issuance",
    "registry_backed_oid4vci_issuance",
    "target_restart_retains_correctness_state",
    "rollback_before_target_traffic",
    "post_write_fix_forward_boundary",
    "complete_restore",
    "restored_products_ready",
    "anti_rollback_rejects_older_bundle",
)
REQUIRED_RECOVERY_ITEMS = (
    "relay_database",
    "notary_database",
    "config_and_bundle",
    "anti_rollback_state",
    "audit_state",
    "notary_sensitive_key_reference",
    "relay_key_lifecycle_reference",
)
SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
PLACEHOLDER = re.compile(r"^<[A-Z0-9_]+>$")


class ExerciseError(ValueError):
    """An upgrade exercise record is invalid."""


def require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExerciseError(f"{label} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown or missing:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise ExerciseError(f"{label} has invalid fields: {'; '.join(details)}")
    return value


def bounded_string(
    value: Any,
    label: str,
    pattern: re.Pattern[str],
    *,
    template: bool,
) -> str:
    if not isinstance(value, str):
        raise ExerciseError(f"{label} must be a string")
    if template and PLACEHOLDER.fullmatch(value):
        return value
    if pattern.fullmatch(value) is None:
        raise ExerciseError(f"{label} has an invalid or unsafe value")
    return value


def validate_release(value: Any, label: str, *, template: bool) -> None:
    release = require_object(
        value,
        label,
        {"version", "source_commit", "relay_image_digest", "notary_image_digest"},
    )
    bounded_string(release["version"], f"{label}.version", VERSION, template=template)
    bounded_string(release["source_commit"], f"{label}.source_commit", COMMIT, template=template)
    bounded_string(
        release["relay_image_digest"],
        f"{label}.relay_image_digest",
        SHA256,
        template=template,
    )
    bounded_string(
        release["notary_image_digest"],
        f"{label}.notary_image_digest",
        SHA256,
        template=template,
    )


def validate_config_schemas(value: Any, *, template: bool, root: Path) -> None:
    schemas = require_object(value, "config_schemas", set(CONFIG_SCHEMAS))
    for product, expected_path in CONFIG_SCHEMAS.items():
        entry = require_object(
            schemas[product], f"config_schemas.{product}", {"path", "sha256"}
        )
        if entry["path"] != expected_path.as_posix():
            raise ExerciseError(
                f"config_schemas.{product}.path must consume {expected_path.as_posix()}"
            )
        digest = bounded_string(
            entry["sha256"], f"config_schemas.{product}.sha256", SHA256, template=template
        )
        if not template:
            actual = hashlib.sha256((root / expected_path).read_bytes()).hexdigest()
            if digest.removeprefix("sha256:") != actual:
                raise ExerciseError(
                    f"config_schemas.{product}.sha256 does not match the committed schema"
                )


def validate_topology(value: Any, *, template: bool) -> None:
    topology = require_object(
        value,
        "topology",
        {
            "repository",
            "release_tag",
            "source_commit",
            "relay_authorities",
            "notary_authorities",
            "authority_pairs",
        },
    )
    if topology["repository"] != SOLMARA_REPOSITORY:
        raise ExerciseError(f"topology.repository must be {SOLMARA_REPOSITORY}")
    bounded_string(topology["release_tag"], "topology.release_tag", VERSION, template=template)
    bounded_string(topology["source_commit"], "topology.source_commit", COMMIT, template=template)
    relay = validate_authorities(
        topology["relay_authorities"], "topology.relay_authorities", template=template
    )
    notary = validate_authorities(
        topology["notary_authorities"], "topology.notary_authorities", template=template
    )
    pairs = topology["authority_pairs"]
    if not isinstance(pairs, list) or not pairs:
        raise ExerciseError("topology.authority_pairs must be a non-empty list")
    seen_relay: set[str] = set()
    seen_notary: set[str] = set()
    for index, pair_value in enumerate(pairs):
        pair = require_object(
            pair_value, f"topology.authority_pairs[{index}]", {"relay", "notary"}
        )
        pair_relay = bounded_string(
            pair["relay"], f"topology.authority_pairs[{index}].relay", SLUG, template=template
        )
        pair_notary = bounded_string(
            pair["notary"], f"topology.authority_pairs[{index}].notary", SLUG, template=template
        )
        if not template and (pair_relay not in relay or pair_notary not in notary):
            raise ExerciseError("topology.authority_pairs references an undeclared authority")
        if pair_relay in seen_relay or pair_notary in seen_notary:
            raise ExerciseError("topology.authority_pairs must be one-to-one")
        seen_relay.add(pair_relay)
        seen_notary.add(pair_notary)
    if not template and (seen_relay != relay or seen_notary != notary):
        raise ExerciseError("every Relay and Notary authority must appear in exactly one pair")


def validate_authorities(value: Any, label: str, *, template: bool) -> set[str]:
    if not isinstance(value, list) or not value:
        raise ExerciseError(f"{label} must be a non-empty list")
    result = {
        bounded_string(item, f"{label}[{index}]", SLUG, template=template)
        for index, item in enumerate(value)
    }
    if len(result) != len(value):
        raise ExerciseError(f"{label} must not contain duplicates")
    return result


def validate_recovery_set(value: Any, *, template: bool) -> None:
    if not isinstance(value, list):
        raise ExerciseError("recovery_set must be a list")
    seen: set[str] = set()
    for index, item_value in enumerate(value):
        item = require_object(
            item_value, f"recovery_set[{index}]", {"item", "artifact_sha256"}
        )
        item_name = bounded_string(
            item["item"], f"recovery_set[{index}].item", SLUG, template=template
        )
        bounded_string(
            item["artifact_sha256"],
            f"recovery_set[{index}].artifact_sha256",
            SHA256,
            template=template,
        )
        if item_name in seen:
            raise ExerciseError(f"duplicate recovery_set item: {item_name}")
        seen.add(item_name)
    if not template and seen != set(REQUIRED_RECOVERY_ITEMS):
        missing = set(REQUIRED_RECOVERY_ITEMS) - seen
        extra = seen - set(REQUIRED_RECOVERY_ITEMS)
        raise ExerciseError(
            "recovery_set must contain the complete release-specific restore set"
            + (f"; missing {', '.join(sorted(missing))}" if missing else "")
            + (f"; unknown {', '.join(sorted(extra))}" if extra else "")
        )


def validate_results(value: Any, *, template: bool) -> None:
    if not isinstance(value, list):
        raise ExerciseError("results must be a list")
    seen: set[str] = set()
    for index, result_value in enumerate(value):
        result = require_object(
            result_value,
            f"results[{index}]",
            {"check_id", "outcome", "observed_at", "evidence_label", "evidence_sha256"},
        )
        check_id = bounded_string(
            result["check_id"], f"results[{index}].check_id", SLUG, template=template
        )
        if check_id not in REQUIRED_CHECKS:
            raise ExerciseError(f"results[{index}].check_id is not a required check")
        expected_outcome = "not_run" if template else "passed"
        if result["outcome"] != expected_outcome:
            raise ExerciseError(
                f"results[{index}].outcome must be {expected_outcome!r} for this record kind"
            )
        bounded_string(
            result["observed_at"], f"results[{index}].observed_at", TIMESTAMP, template=template
        )
        bounded_string(
            result["evidence_label"],
            f"results[{index}].evidence_label",
            SLUG,
            template=template,
        )
        bounded_string(
            result["evidence_sha256"],
            f"results[{index}].evidence_sha256",
            SHA256,
            template=template,
        )
        if check_id in seen:
            raise ExerciseError(f"duplicate result check_id: {check_id}")
        seen.add(check_id)
    if seen != set(REQUIRED_CHECKS):
        raise ExerciseError("results must contain every required check exactly once")


def validate_record(data: Any, *, allow_template: bool, root: Path = ROOT) -> None:
    record = require_object(
        data,
        "record",
        {
            "schema",
            "record_kind",
            "exercise_id",
            "recorded_at",
            "source_release",
            "target_release",
            "target_release_manifest_sha256",
            "candidate_frozen",
            "candidate_independently_verified",
            "config_schemas",
            "topology",
            "recovery_set",
            "results",
        },
    )
    if record["schema"] != SCHEMA:
        raise ExerciseError(f"schema must be {SCHEMA}")
    kind = record["record_kind"]
    if kind not in {"template", "candidate_evidence"}:
        raise ExerciseError("record_kind must be template or candidate_evidence")
    template = kind == "template"
    if template and not allow_template:
        raise ExerciseError("template is preparation, not candidate evidence; pass --template to validate it")
    if not template and allow_template:
        raise ExerciseError("--template accepts only a template record")
    bounded_string(record["exercise_id"], "exercise_id", SLUG, template=template)
    bounded_string(record["recorded_at"], "recorded_at", TIMESTAMP, template=template)
    validate_release(record["source_release"], "source_release", template=template)
    validate_release(record["target_release"], "target_release", template=template)
    bounded_string(
        record["target_release_manifest_sha256"],
        "target_release_manifest_sha256",
        SHA256,
        template=template,
    )
    expected_bool = not template
    if record["candidate_frozen"] is not expected_bool:
        raise ExerciseError(f"candidate_frozen must be {str(expected_bool).lower()}")
    if record["candidate_independently_verified"] is not expected_bool:
        raise ExerciseError(
            f"candidate_independently_verified must be {str(expected_bool).lower()}"
        )
    validate_config_schemas(record["config_schemas"], template=template, root=root)
    validate_topology(record["topology"], template=template)
    validate_recovery_set(record["recovery_set"], template=template)
    validate_results(record["results"], template=template)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument(
        "--template",
        action="store_true",
        help="validate a preparation template; templates never count as candidate evidence",
    )
    args = parser.parse_args()
    try:
        data = json.loads(args.record.read_text(encoding="utf-8"))
        validate_record(data, allow_template=args.template)
    except (ExerciseError, OSError, json.JSONDecodeError) as error:
        print(f"upgrade exercise validation failed: {error}", file=sys.stderr)
        return 1
    print(f"upgrade exercise validation passed: {args.record}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
