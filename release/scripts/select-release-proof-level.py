#!/usr/bin/env python3
"""Select the fail-closed standard or extended release proof level."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple


SEMVER_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SENSITIVE_PATHS = (
    ".github/actions/release/**",
    ".github/workflows/release*.yml",
    ".github/workflows/release*.yaml",
    ".github/workflows/ci.yml",
    "release/docker/**",
    "release/schemas/**",
    "release/scripts/**",
    "Cargo.lock",
    "deny.toml",
    "rust-toolchain*",
    "crates/registry-relay/release/**",
    "crates/registry-relay/scripts/check_advisory_baselines.py",
    "crates/registry-relay/security/advisory-baseline*.json",
    "products/relay-v2/security/advisory-baseline*.json",
)
BUILDER_FIELDS = {
    "binary_image",
    "binary_fingerprint",
    "binary_recipe_fingerprint",
    "image_buildkit_image",
    "image_buildx_version",
    "image_recipe_fingerprint",
}


class SelectionError(ValueError):
    """Raised when a caller supplies an invalid selection input."""


class Selection(NamedTuple):
    schema_version: str
    proof_level: str
    requested: str
    version: str
    source_sha: str
    comparison_base: str | None
    comparison_base_kind: str | None
    changed_paths: list[str]
    sensitive_paths: list[str]
    reasons: list[str]


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def resolve_commit(repo: Path, ref: str) -> str:
    return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")


def load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SelectionError(f"could not read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{label} must be a JSON object")
    return value


def validate_builders(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BUILDER_FIELDS:
        raise SelectionError(f"{label} must have the exact builder fingerprint fields")
    for field, item in value.items():
        if not isinstance(item, str) or not item:
            raise SelectionError(f"{label}.{field} must be a non-empty string")
    for field in (
        "binary_fingerprint",
        "binary_recipe_fingerprint",
        "image_recipe_fingerprint",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise SelectionError(f"{label}.{field} must be a SHA-256 value")
    return value


def receipt_context(
    path: Path, *, expected_tag: str | None
) -> tuple[str, dict[str, Any]]:
    value = load_json_object(path, label="previous promoted receipt")
    if value.get("schema_version") != "registry-stack.release-candidate-receipt.v1":
        raise SelectionError(
            "previous promoted receipt has an unsupported schema_version"
        )
    if value.get("repository") != "registrystack/registry-stack":
        raise SelectionError("previous promoted receipt has an untrusted repository")
    workflow = value.get("workflow")
    if not isinstance(workflow, dict):
        raise SelectionError("previous promoted receipt has no workflow object")
    expected_workflow = {
        "path": ".github/workflows/release-candidate.yml",
        "ref": "refs/heads/main",
        "event": "repository_dispatch",
    }
    for field, expected in expected_workflow.items():
        if workflow.get(field) != expected:
            raise SelectionError(
                f"previous promoted receipt workflow.{field} is not authoritative"
            )
    release = value.get("release")
    if not isinstance(release, dict):
        raise SelectionError("previous promoted receipt has no release object")
    version = release.get("version")
    tag = release.get("tag")
    if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
        raise SelectionError(
            "previous promoted receipt release.version is not canonical"
        )
    if tag != f"v{version}":
        raise SelectionError(
            "previous promoted receipt release.tag does not match release.version"
        )
    if expected_tag is not None and tag != expected_tag:
        raise SelectionError(
            "previous promoted receipt release.tag does not match the promoted tag"
        )
    source_sha = release.get("source_sha")
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise SelectionError(
            "previous promoted receipt release.source_sha is not a full commit"
        )
    builders = validate_builders(
        value.get("builders"), label="previous promoted receipt.builders"
    )
    return source_sha, builders


def is_sensitive(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in SENSITIVE_PATHS)


def normalize_version(value: str) -> tuple[str, int, int, int]:
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        raise SelectionError(
            f"release version must be an exact semantic version, got {value!r}"
        )
    major, minor, patch = (int(part) for part in match.groups())
    return f"{major}.{minor}.{patch}", major, minor, patch


def select(
    *,
    repo: Path,
    requested: str,
    version: str,
    source_ref: str,
    previous_receipt: Path | None,
    previous_tag: str | None,
    current_builders: Path | None,
    milestone: str,
    candidate_evidence: str,
) -> Selection:
    normalized_version, major, _minor, _patch = normalize_version(version)
    if requested not in {"auto", "extended"}:
        raise SelectionError("requested proof level must be auto or extended")
    if milestone not in {"beta", "stable", "audit"}:
        raise SelectionError("milestone must be beta, stable, or audit")
    if candidate_evidence not in {"complete", "incomplete", "disagree"}:
        raise SelectionError(
            "candidate evidence must be complete, incomplete, or disagree"
        )

    try:
        source_sha = resolve_commit(repo, source_ref)
    except subprocess.CalledProcessError:
        raise SelectionError(
            f"source ref {source_ref!r} does not resolve to a commit"
        ) from None

    reasons: list[str] = []
    comparison_base: str | None = None
    comparison_base_kind: str | None = None
    ambiguous_history = False

    receipt_base: str | None = None
    previous_builders: dict[str, Any] | None = None
    tag_base: str | None = None
    if previous_receipt is not None:
        try:
            receipt_sha, previous_builders = receipt_context(
                previous_receipt, expected_tag=previous_tag
            )
            receipt_base = resolve_commit(repo, receipt_sha)
        except (SelectionError, subprocess.CalledProcessError) as error:
            reasons.append(f"previous promoted receipt is not authoritative: {error}")
            ambiguous_history = True
    if previous_tag is not None:
        try:
            tag_base = resolve_commit(repo, f"refs/tags/{previous_tag}")
        except subprocess.CalledProcessError:
            reasons.append(f"previous promoted tag {previous_tag!r} does not resolve")
            ambiguous_history = True

    if receipt_base is not None and tag_base is not None and receipt_base != tag_base:
        reasons.append("previous promoted receipt and tag resolve to different commits")
        ambiguous_history = True
    elif receipt_base is not None:
        comparison_base = receipt_base
        comparison_base_kind = "promoted_receipt"
    elif tag_base is not None:
        comparison_base = tag_base
        comparison_base_kind = "promoted_tag"
    else:
        reasons.append("no authoritative previous promoted receipt or tag is available")
        ambiguous_history = True

    changed_paths: list[str] = []
    sensitive_paths: list[str] = []
    if comparison_base is not None:
        try:
            if git(repo, "merge-base", comparison_base, source_sha) != comparison_base:
                reasons.append(
                    "previous promoted base is not an ancestor of the release source"
                )
                ambiguous_history = True
            else:
                output = git(
                    repo,
                    "diff",
                    "--name-only",
                    "--diff-filter=ACDMRTUXB",
                    comparison_base,
                    source_sha,
                )
                changed_paths = sorted(path for path in output.splitlines() if path)
                sensitive_paths = [path for path in changed_paths if is_sensitive(path)]
        except subprocess.CalledProcessError:
            reasons.append("release history could not be compared")
            ambiguous_history = True

    if previous_builders is not None:
        if current_builders is None:
            reasons.append(
                "current trust-anchor fingerprints are missing for receipt comparison"
            )
            ambiguous_history = True
        else:
            try:
                current_builder_values = validate_builders(
                    load_json_object(
                        current_builders, label="current trust-anchor fingerprints"
                    ),
                    label="current trust-anchor fingerprints",
                )
            except SelectionError as error:
                reasons.append(str(error))
                ambiguous_history = True
            else:
                changed_fields = sorted(
                    field
                    for field in BUILDER_FIELDS
                    if previous_builders[field] != current_builder_values[field]
                )
                if changed_fields:
                    reasons.append(
                        "trust-anchor fingerprints changed: "
                        + ", ".join(changed_fields)
                    )
                    sensitive_paths.append("<receipt-trust-anchor-mismatch>")

    if requested == "extended":
        reasons.append("operator explicitly requested extended proof")
    if milestone in {"stable", "audit"}:
        reasons.append(f"{milestone} milestone requires extended proof")
    if major >= 1:
        reasons.append("1.0 or later milestone requires extended proof")
    if candidate_evidence != "complete":
        reasons.append(f"candidate evidence is {candidate_evidence}")
    if sensitive_paths:
        reasons.append("release-system or trust-anchor paths changed")
    if ambiguous_history:
        reasons.append("release history is incomplete or ambiguous")

    force_extended = (
        requested == "extended"
        or milestone in {"stable", "audit"}
        or major >= 1
        or candidate_evidence != "complete"
        or bool(sensitive_paths)
        or ambiguous_history
    )
    if not force_extended:
        reasons.append("beta release changed no release-system or trust-anchor path")

    return Selection(
        schema_version="registry-stack.release-proof-selection.v1",
        proof_level="extended" if force_extended else "standard",
        requested=requested,
        version=normalized_version,
        source_sha=source_sha,
        comparison_base=comparison_base,
        comparison_base_kind=comparison_base_kind,
        changed_paths=changed_paths,
        sensitive_paths=sensitive_paths,
        reasons=reasons,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Select standard or extended proof. Operators may request auto or "
            "extended; there is intentionally no standard override."
        )
    )
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--requested", choices=("auto", "extended"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--previous-receipt", type=Path)
    parser.add_argument("--previous-tag")
    parser.add_argument(
        "--current-builders",
        type=Path,
        help=(
            "closed current builder and recipe fingerprint JSON; required to "
            "select standard when a previous promoted receipt is supplied"
        ),
    )
    parser.add_argument(
        "--milestone", choices=("beta", "stable", "audit"), default="beta"
    )
    parser.add_argument(
        "--candidate-evidence",
        choices=("complete", "incomplete", "disagree"),
        default="complete",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        selection = select(
            repo=args.repo.resolve(),
            requested=args.requested,
            version=args.version,
            source_ref=args.source_ref,
            previous_receipt=args.previous_receipt,
            previous_tag=args.previous_tag,
            current_builders=args.current_builders,
            milestone=args.milestone,
            candidate_evidence=args.candidate_evidence,
        )
    except SelectionError as error:
        print(f"release proof selection failed: {error}", file=sys.stderr)
        return 2

    rendered = json.dumps(selection._asdict(), indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"proof_level={selection.proof_level}\n")
            handle.write(f"source_sha={selection.source_sha}\n")
            handle.write(f"comparison_base={selection.comparison_base or ''}\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
