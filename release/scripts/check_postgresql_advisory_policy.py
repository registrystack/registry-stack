#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail candidate releases on PostgreSQL image vulnerabilities.

The official PostgreSQL image is an external runtime, not a product image. It
does not carry a Registry Stack Git revision label, so its Grype and Syft
evidence is bound to the reviewed immutable image digest and ordered rootfs
layers instead. The policy contains no accepted-risk mechanism: every fixable
finding and every High or Critical finding blocks the candidate.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "unknown": 0,
    "undefined": 0,
    "informational": 0,
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
FIX_STATES = {"fixed", "not-fixed", "wont-fix"}


def fail(message: str) -> None:
    print(f"PostgreSQL advisory policy check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def severity_rank(value: Any) -> int:
    if not isinstance(value, str) or value.casefold() not in SEVERITY_ORDER:
        fail(f"unknown severity value: {value}")
    return SEVERITY_ORDER[value.casefold()]


def image_evidence(report: Any, report_name: str, target_key: str) -> tuple[str, ...]:
    if not isinstance(report, dict):
        fail(f"{report_name} report must be a JSON object")
    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        fail(f"{report_name} report source must describe an image")
    target = source.get(target_key)
    if not isinstance(target, dict):
        fail(f"{report_name} report source must contain image metadata")
    user_input = target.get("userInput")
    if not isinstance(user_input, str) or "@" not in user_input:
        fail(f"{report_name} image target must be pinned by digest")
    digest = user_input.rsplit("@", 1)[1]
    if SHA256_DIGEST.fullmatch(digest) is None:
        fail(f"{report_name} image target must use a sha256 digest")
    repo_digests = target.get("repoDigests")
    if (
        not isinstance(repo_digests, list)
        or not any(
            isinstance(repo_digest, str)
            and "@" in repo_digest
            and repo_digest.rsplit("@", 1)[1] == digest
            for repo_digest in repo_digests
        )
    ):
        fail(f"{report_name} image target digest must appear in repoDigests")
    if target.get("architecture") != "amd64" or target.get("os") != "linux":
        fail(f"{report_name} image target must be linux/amd64")
    layers = target.get("layers")
    if not isinstance(layers, list) or not layers:
        fail(f"{report_name} image target must contain rootfs layers")
    layer_ids = []
    for layer in layers:
        layer_id = layer.get("digest") if isinstance(layer, dict) else None
        if not isinstance(layer_id, str) or SHA256_DIGEST.fullmatch(layer_id) is None:
            fail(f"{report_name} image target layers must use sha256 digests")
        layer_ids.append(layer_id)
    return (user_input, *layer_ids)


def load_policy(path: Path) -> None:
    baseline = load_json(path)
    expected = {
        "version": 1,
        "subject": "postgresql-runtime",
        "minimum_severity": "high",
        "block_fixable": True,
    }
    if baseline != expected:
        fail("policy must enforce Grype High/Critical and every fixable finding")


def require_rootfs(path: Path) -> None:
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        fail(f"candidate rootfs is unavailable: {exc}")
    if not root.is_dir():
        fail("candidate rootfs must be a directory")
    for entry in root.rglob("*"):
        try:
            mode = entry.lstat().st_mode
        except OSError as exc:
            fail(f"cannot inspect candidate rootfs entry {entry}: {exc}")
        if (
            stat.S_ISBLK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
        ):
            fail(f"candidate rootfs contains forbidden special file: {entry}")


def syft_artifacts(report: Any) -> dict[str, dict[str, Any]]:
    artifacts = report.get("artifacts") if isinstance(report, dict) else None
    if not isinstance(artifacts, list):
        fail("syft report must contain an artifacts list")
    indexed = {}
    for artifact in artifacts:
        artifact_id = artifact.get("id") if isinstance(artifact, dict) else None
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in indexed:
            fail("syft report artifacts must have unique non-blank ids")
        indexed[artifact_id] = artifact
    return indexed


def finding_blocks(item: Any, artifacts: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    if not isinstance(item, dict):
        fail("grype report matches must be objects")
    vulnerability = item.get("vulnerability")
    artifact = item.get("artifact")
    if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
        fail("grype report matches must contain vulnerability and artifact objects")
    artifact_id = artifact.get("id")
    syft_artifact = artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
    bound_fields = ("id", "name", "version", "type", "locations")
    if not isinstance(syft_artifact, dict) or any(
        artifact.get(field) != syft_artifact.get(field) for field in bound_fields
    ):
        fail("grype finding artifact does not match the Syft package model")
    vulnerability_id = vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id:
        fail("grype finding vulnerability id must be non-blank")
    fix = vulnerability.get("fix")
    if not isinstance(fix, dict):
        fail(f"grype finding {vulnerability_id} must contain a fix object")
    versions = fix.get("versions", [])
    if versions is None:
        versions = []
    if not isinstance(versions, list) or any(not isinstance(version, str) for version in versions):
        fail(f"grype finding {vulnerability_id} has malformed fix versions")
    fix_state = fix.get("state")
    if not isinstance(fix_state, str) or fix_state.casefold() not in FIX_STATES:
        fail(f"grype finding {vulnerability_id} has unsupported fix state")
    severity = vulnerability.get("severity")
    fixable = bool([version for version in versions if version.strip()]) or (
        fix_state.casefold() == "fixed"
    )
    blocking = fixable or severity_rank(severity) >= SEVERITY_ORDER["high"]
    summary = (
        f"{vulnerability_id} severity={severity} "
        f"package={artifact.get('name', '<unknown>')} {artifact.get('version', '<unknown>')} "
        f"fixable={fixable}"
    )
    return blocking, summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--syft-report", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--expected-image", required=True)
    args = parser.parse_args()

    load_policy(args.baseline)
    require_rootfs(args.rootfs)
    grype = load_json(args.report)
    syft = load_json(args.syft_report)
    grype_evidence = image_evidence(grype, "grype", "target")
    syft_evidence = image_evidence(syft, "syft", "metadata")
    if grype_evidence != syft_evidence:
        fail("Grype and Syft reports do not describe the same image evidence")
    if grype_evidence[0] != args.expected_image:
        fail("scan evidence does not describe the locked PostgreSQL image")
    artifacts = syft_artifacts(syft)
    matches = grype.get("matches") if isinstance(grype, dict) else None
    if not isinstance(matches, list):
        fail("grype report must contain a matches list")
    blockers = []
    for item in matches:
        blocking, summary = finding_blocks(item, artifacts)
        if blocking:
            blockers.append(summary)
    print(f"PostgreSQL advisory policy: blocking={len(blockers)}")
    if blockers:
        for blocker in blockers:
            print(f"blocking finding: {blocker}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
