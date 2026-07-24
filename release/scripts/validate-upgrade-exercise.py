#!/usr/bin/env python3
"""Validate a redaction-safe Registry Stack upgrade exercise record."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from conformance_candidate import CandidateError, load_candidate  # noqa: E402


SCHEMA = "registry-stack.upgrade-exercise/v1"
SOLMARA_REPOSITORY = "registrystack/solmara-lab"
STACK_REPOSITORY = "registrystack/registry-stack"
CONFIG_SCHEMAS = {
    "registry-relay": Path("schemas/registry-relay.config.schema.json"),
    "registry-notary": Path("schemas/registry-notary.config.schema.json"),
}
RELEASE_INPUTS = (
    Path(".github/workflows/release.yml"),
    Path("Cargo.lock"),
    Path("Cargo.toml"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
    Path("release/scripts/build-release-binaries.sh"),
    Path("release/scripts/build-release-image.sh"),
    Path("release/scripts/check-release-relay-features.py"),
    Path("release/scripts/compare-release-image-layouts.py"),
    Path("release/scripts/registry-release"),
    Path("rust-toolchain.toml"),
    *CONFIG_SCHEMAS.values(),
)
ARTIFACT_KEYS = {
    *(f"{phase}{run}_{kind}" for phase in ("p", "t") for run in (1, 2)
      for kind in ("binaries", "image_inputs")),
    *(f"{phase}_{product}_layouts" for phase in ("p", "t")
      for product in ("notary", "relay")),
    "image_lock",
    "manifest",
    "notary_image",
    "relay_image",
    "p_release_inputs",
    "t_release_inputs",
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


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def git_bytes(root: Path, commit: str, path: Path) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path.as_posix()}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ExerciseError(f"{path} does not exist at exact Git object {commit}")
    return result.stdout


def release_inputs_sha256(root: Path, commit: str) -> str:
    return canonical_sha256(
        [
            {"path": path.as_posix(), "sha256": sha256_bytes(git_bytes(root, commit, path))}
            for path in RELEASE_INPUTS
        ]
    )


def validate_release(value: Any, label: str, *, template: bool) -> None:
    keys = {"version", "source_commit", "relay_image_digest", "notary_image_digest"}
    if label == "target_release":
        keys.update({"release_id", "source_ref"})
    release = require_object(
        value,
        label,
        keys,
    )
    bounded_string(release["version"], f"{label}.version", VERSION, template=template)
    bounded_string(release["source_commit"], f"{label}.source_commit", COMMIT, template=template)
    bounded_string(
        release["relay_image_digest"],
        f"{label}.relay_image_digest",
        SHA256,
        template=template,
    )
    if label == "target_release":
        bounded_string(
            release["release_id"], f"{label}.release_id", SLUG, template=template
        )
        bounded_string(
            release["source_ref"], f"{label}.source_ref", COMMIT, template=template
        )
    bounded_string(
        release["notary_image_digest"],
        f"{label}.notary_image_digest",
        SHA256,
        template=template,
    )


def version_order(value: str) -> tuple[tuple[int, int, int], bool]:
    core, separator, _prerelease = value.removeprefix("v").partition("-")
    return tuple(int(part) for part in core.split(".")), not bool(separator)


def validate_config_schemas(
    value: Any, *, template: bool, root: Path, target_commit: str | None
) -> None:
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
            assert target_commit is not None
            actual = sha256_bytes(git_bytes(root, target_commit, expected_path))
            if digest.removeprefix("sha256:") != actual.removeprefix("sha256:"):
                raise ExerciseError(
                    f"config_schemas.{product}.sha256 does not match the exact target Git object"
                )


def validate_artifact_set(value: Any, record: dict[str, Any], *, template: bool) -> None:
    artifact_set = require_object(value, "candidate_artifact_set", {"sha256", "artifacts"})
    bounded_string(
        artifact_set["sha256"],
        "candidate_artifact_set.sha256",
        SHA256,
        template=template,
    )
    artifacts = require_object(
        artifact_set["artifacts"], "candidate_artifact_set.artifacts", ARTIFACT_KEYS
    )
    for name, digest in artifacts.items():
        bounded_string(
            digest,
            f"candidate_artifact_set.artifacts.{name}",
            SHA256,
            template=template,
        )
    if template:
        return
    expected = {
        "manifest": record["target_release_manifest"]["sha256"],
        "relay_image": record["target_release"]["relay_image_digest"],
        "notary_image": record["target_release"]["notary_image_digest"],
    }
    if any(
        artifacts[name].removeprefix("sha256:")
        != digest.removeprefix("sha256:")
        for name, digest in expected.items()
    ):
        raise ExerciseError("candidate_artifact_set does not match target release coordinates")
    if artifact_set["sha256"].removeprefix(
        "sha256:"
    ) != canonical_sha256(artifacts).removeprefix("sha256:"):
        raise ExerciseError("candidate_artifact_set.sha256 does not match its artifacts")


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
            raise ExerciseError("each Relay must have exactly one dedicated Notary authority")
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
        outcome = result["outcome"]
        if outcome not in {"passed", "failed", "not_run"} or template and outcome != "not_run":
            raise ExerciseError(f"results[{index}].outcome is invalid for this record kind")
        if not template and outcome == "not_run":
            if any(result[field] is not None for field in (
                "observed_at", "evidence_label", "evidence_sha256"
            )):
                raise ExerciseError("not_run result evidence fields must be null")
        else:
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


def validate_target_binding(record: dict[str, Any], root: Path) -> None:
    target = record["target_release"]
    source_ref = target["source_ref"]
    target_commit = target["source_commit"]
    tag_ref = f"refs/tags/{target['version']}^{{commit}}"
    tag_target = subprocess.run(
        ["git", "rev-parse", "--verify", tag_ref],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if tag_target.returncode != 0 or tag_target.stdout.strip() != target_commit:
        raise ExerciseError(
            f"release tag {target['version']} does not resolve to target_release.source_commit"
        )
    for value, label in ((source_ref, "source_ref"), (target_commit, "source_commit")):
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        if resolved.returncode != 0 or resolved.stdout.strip() != value:
            raise ExerciseError(f"target_release.{label} does not resolve exactly")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_ref, target_commit],
        cwd=root, capture_output=True, check=False,
    ).returncode != 0:
        raise ExerciseError("target_release.source_ref is not an ancestor of source_commit")

    coordinate = record["target_release_manifest"]
    manifest_bytes = git_bytes(root, target_commit, Path(coordinate["path"]))
    if coordinate["sha256"].removeprefix("sha256:") != sha256_bytes(
        manifest_bytes
    ).removeprefix("sha256:"):
        raise ExerciseError("target_release_manifest.sha256 does not match exact target")
    try:
        manifest = yaml.safe_load(manifest_bytes)
    except yaml.YAMLError as error:
        raise ExerciseError(f"target release manifest is invalid YAML: {error}") from error
    stack = manifest.get("stack") if isinstance(manifest, dict) else None
    expected = {
        "release": target["release_id"],
        "version": target["version"].removeprefix("v"),
        "source_repo": STACK_REPOSITORY,
        "source_ref": source_ref,
        "source_tag": target["version"],
    }
    if not isinstance(stack, dict) or any(str(stack.get(key)) != value for key, value in expected.items()):
        raise ExerciseError("target release manifest identity does not match target_release")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts or any(
        str(version) != expected["version"] for version in artifacts.values()
    ):
        raise ExerciseError("target release manifest artifact versions do not match target_release")

    artifact_set = record["candidate_artifact_set"]["artifacts"]
    for field, commit in (("p_release_inputs", source_ref), ("t_release_inputs", target_commit)):
        if artifact_set[field] != release_inputs_sha256(root, commit):
            raise ExerciseError(f"candidate_artifact_set.artifacts.{field} does not match exact Git object")


def validate_image_lock_binding(
    record: dict[str, Any],
    root: Path,
    candidate_asset_root: Path | None,
) -> None:
    if candidate_asset_root is None:
        raise ExerciseError(
            "candidate evidence requires --candidate-asset-root for image-lock authentication"
        )
    target = record["target_release"]
    candidate_asset_dir = candidate_asset_root.expanduser() / target["version"]
    image_lock_path = (
        candidate_asset_dir / f"registryctl-{target['version']}-image-lock.json"
    )
    manifest_path = root / record["target_release_manifest"]["path"]
    try:
        candidate = load_candidate(manifest_path, image_lock_path)
    except (CandidateError, OSError):
        raise ExerciseError(
            "candidate release image lock could not be authenticated"
        ) from None
    artifacts = record["candidate_artifact_set"]["artifacts"]
    expected = {
        "release_id": target["release_id"],
        "version": target["version"].removeprefix("v"),
        "source_ref": target["source_ref"],
        "source_tag": target["version"],
        "tag_target": target["source_commit"],
        "image_lock_sha256": artifacts["image_lock"],
        "relay_image": "ghcr.io/registrystack/registry-relay@sha256:"
        + target["relay_image_digest"].removeprefix("sha256:"),
        "notary_image": "ghcr.io/registrystack/registry-notary@sha256:"
        + target["notary_image_digest"].removeprefix("sha256:"),
    }
    if candidate["image_lock_sha256"].removeprefix(
        "sha256:"
    ) != expected["image_lock_sha256"].removeprefix("sha256:"):
        raise ExerciseError(
            "candidate_artifact_set.artifacts.image_lock does not match "
            "the exact authenticated release image-lock asset"
        )
    for field in (
        "release_id",
        "version",
        "source_ref",
        "source_tag",
        "tag_target",
        "relay_image",
        "notary_image",
    ):
        if candidate[field] != expected[field]:
            raise ExerciseError(
                "authenticated release image lock does not match target release coordinates"
            )


def require_pass(record: dict[str, Any]) -> None:
    if not record["candidate_frozen"] or not record["candidate_independently_verified"]:
        raise ExerciseError("--require-pass requires both candidate attestations")
    if any(result["outcome"] != "passed" for result in record["results"]):
        raise ExerciseError("--require-pass requires every check to pass")
    artifacts = record["candidate_artifact_set"]["artifacts"]
    for kind in ("binaries", "image_inputs"):
        if len({artifacts[f"{phase}{run}_{kind}"] for phase in ("p", "t") for run in (1, 2)}) != 1:
            raise ExerciseError(f"--require-pass rejects P/T {kind} drift")
    for product in ("notary", "relay"):
        if artifacts[f"p_{product}_layouts"] != artifacts[f"t_{product}_layouts"]:
            raise ExerciseError(f"--require-pass rejects P/T {product} OCI layout drift")
    if artifacts["p_release_inputs"] != artifacts["t_release_inputs"]:
        raise ExerciseError("--require-pass rejects P/T release-input drift")


def validate_record(
    data: Any,
    *,
    allow_template: bool,
    require_all_passed: bool = False,
    root: Path = ROOT,
    candidate_asset_root: Path | None = None,
) -> None:
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
            "target_release_manifest",
            "candidate_frozen",
            "candidate_independently_verified",
            "config_schemas",
            "candidate_artifact_set",
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
    if not template and version_order(record["target_release"]["version"]) <= version_order(
        record["source_release"]["version"]
    ):
        raise ExerciseError("target_release.version must be newer than source_release.version")
    manifest = require_object(
        record["target_release_manifest"], "target_release_manifest", {"path", "sha256"}
    )
    if not (template and PLACEHOLDER.fullmatch(str(manifest["path"]))):
        path = Path(str(manifest["path"]))
        if path.is_absolute() or ".." in path.parts or not path.as_posix().startswith("release/manifests/"):
            raise ExerciseError("target_release_manifest.path must be a safe release manifest path")
    bounded_string(manifest["sha256"], "target_release_manifest.sha256", SHA256, template=template)
    for field in ("candidate_frozen", "candidate_independently_verified"):
        if not isinstance(record[field], bool) or template and record[field]:
            raise ExerciseError(f"{field} must be false in a template and boolean in evidence")
    validate_config_schemas(
        record["config_schemas"],
        template=template,
        root=root,
        target_commit=None if template else record["target_release"]["source_commit"],
    )
    validate_artifact_set(record["candidate_artifact_set"], record, template=template)
    validate_topology(record["topology"], template=template)
    validate_recovery_set(record["recovery_set"], template=template)
    validate_results(record["results"], template=template)
    if not template:
        validate_target_binding(record, root)
        validate_image_lock_binding(record, root, candidate_asset_root)
    if require_all_passed:
        require_pass(record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", nargs="?", type=Path)
    parser.add_argument(
        "--template",
        action="store_true",
        help="validate a preparation template; templates never count as candidate evidence",
    )
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--discover", type=Path)
    parser.add_argument(
        "--candidate-asset-root",
        type=Path,
        help=(
            "root containing one downloaded and authenticated asset directory "
            "per target version"
        ),
    )
    args = parser.parse_args()
    try:
        if args.discover:
            records = sorted(args.discover.glob("*.json"))
            if not records:
                raise ExerciseError("--discover found no JSON records")
            for path in records:
                data = json.loads(path.read_text(encoding="utf-8"))
                template = data.get("record_kind") == "template"
                validate_record(
                    data,
                    allow_template=template,
                    require_all_passed=not template,
                    candidate_asset_root=args.candidate_asset_root,
                )
            print(f"upgrade exercise discovery passed: {len(records)} record(s)")
            return 0
        if args.record is None:
            raise ExerciseError("a record path is required")
        data = json.loads(args.record.read_text(encoding="utf-8"))
        validate_record(
            data,
            allow_template=args.template,
            require_all_passed=args.require_pass,
            candidate_asset_root=args.candidate_asset_root,
        )
    except (ExerciseError, OSError, json.JSONDecodeError) as error:
        print(f"upgrade exercise validation failed: {error}", file=sys.stderr)
        return 1
    print(f"upgrade exercise validation passed: {args.record}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
