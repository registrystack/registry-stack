#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail CI when advisory security tools report unreviewed blocking findings."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = ROOT / "products" / "relay-v2" / "security" / "advisory-baseline.json"

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
GRYPE_FIX_STATES = {"fixed", "not-fixed", "wont-fix"}
SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
SEMVER_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
SUPPORTED_SYFT_SCHEMA_MAJOR = 16
REQUIRED_INVALIDATION_TRIGGERS = {
    "package_version_changed",
    "fix_available",
    "expired",
    "material_finding_changed",
}
V3_TOP_LEVEL_FIELDS = {"version", "service", "policies", "exceptions"}
V3_EXCEPTION_FIELDS = {
    "vulnerability_id",
    "package",
    "installed_version",
    "severity",
    "status",
    "owner",
    "rationale",
    "reviewed_at",
    "expires_at",
    "invalidation_triggers",
}
V3_EXCEPTION_STATUSES = {"accepted_risk", "false_positive", "tool_noise"}


@dataclass(frozen=True)
class Finding:
    tool: str
    fingerprint: str
    rule_id: str
    severity: str
    location: str
    summary: str
    package: str = ""
    installed_version: str = ""
    package_type: str = ""
    fix_versions: tuple[str, ...] = ()
    fix_state: str = ""
    image_digest: str = ""

    @property
    def fixable(self) -> bool:
        return bool(self.fix_versions) or self.fix_state == "fixed"

    @property
    def exception_key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.package, self.installed_version)

    @property
    def advisory_key(self) -> tuple[str, str]:
        return (self.rule_id, self.package)

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "vulnerability_id": self.rule_id,
            "package": self.package,
            "installed_version": self.installed_version,
            "severity": self.severity,
            "location": self.location,
            "summary": self.summary,
            "fixable": self.fixable,
            "fix_versions": list(self.fix_versions),
            "fix_state": self.fix_state,
            "image_digest": self.image_digest,
        }


def fail(message: str) -> None:
    print(f"advisory baseline check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {display_path(path)}")
    except json.JSONDecodeError as exc:
        fail(f"{display_path(path)} is not valid JSON: {exc}")


def nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{field} must be a non-blank string")
    return value.strip()


def severity_rank(value: Any) -> int:
    if not isinstance(value, str) or value.casefold() not in SEVERITY_ORDER:
        fail(f"unknown severity value: {value}")
    return SEVERITY_ORDER[value.casefold()]


def parse_date(value: Any, field: str) -> dt.date:
    if not isinstance(value, str):
        fail(f"{field} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        fail(f"{field} must be an ISO date: {value}")


def normalize_path(value: str | None) -> str:
    if not value:
        return "<unknown>"
    return value[2:] if value.startswith("./") else value


def route_key(route: Any) -> str:
    if not isinstance(route, dict) or not isinstance(route.get("route"), list):
        return ""
    parts = []
    for entry in route["route"]:
        if isinstance(entry, dict) and "Key" in entry:
            parts.append(f"k:{entry['Key']}")
        elif isinstance(entry, dict) and "Index" in entry:
            parts.append(f"i:{entry['Index']}")
    return "/".join(parts)


def primary_location(locations: Any) -> dict[str, Any]:
    if not isinstance(locations, list):
        return {}
    for location in locations:
        if not isinstance(location, dict):
            continue
        symbolic = location.get("symbolic", {})
        if isinstance(symbolic, dict) and symbolic.get("kind") == "Primary":
            return location
    return locations[0] if locations and isinstance(locations[0], dict) else {}


def normalize_zizmor(report: Any) -> list[Finding]:
    if not isinstance(report, list):
        fail("zizmor report must be a JSON list")
    findings: list[Finding] = []
    for item in report:
        if not isinstance(item, dict):
            fail("zizmor findings must be objects")
        if item.get("ignored"):
            continue
        determinations = item.get("determinations")
        if not isinstance(determinations, dict):
            fail("zizmor finding determinations must be an object")
        severity = nonblank(determinations.get("severity"), "zizmor severity").lower()
        severity_rank(severity)
        ident = nonblank(item.get("ident"), "zizmor ident")
        location = primary_location(item.get("locations"))
        symbolic = location.get("symbolic", {}) if isinstance(location, dict) else {}
        concrete = location.get("concrete", {}) if isinstance(location, dict) else {}
        key = symbolic.get("key", {}) if isinstance(symbolic, dict) else {}
        local = key.get("Local", {}) if isinstance(key, dict) else {}
        path = normalize_path(
            local.get("given_path") if isinstance(local, dict) else None
        )
        annotation = (
            str(symbolic.get("annotation", "")) if isinstance(symbolic, dict) else ""
        )
        feature = str(concrete.get("feature", "")) if isinstance(concrete, dict) else ""
        route = route_key(symbolic.get("route") if isinstance(symbolic, dict) else None)
        detail = (
            feature if ident == "unpinned-uses" and feature else annotation or feature
        )
        findings.append(
            Finding(
                tool="zizmor",
                fingerprint="|".join(["zizmor", ident, path, route, detail]),
                rule_id=ident,
                severity=severity,
                location=path,
                summary=str(item.get("desc") or annotation or feature or ident),
            )
        )
    return findings


def validate_descriptor(report: dict[str, Any], tool: str) -> None:
    descriptor = report.get("descriptor")
    if not isinstance(descriptor, dict):
        fail(f"{tool} report must contain a descriptor object")
    if descriptor.get("name") != tool:
        fail(f"unsupported {tool} report descriptor name: {descriptor.get('name')}")
    version = nonblank(descriptor.get("version"), f"{tool} descriptor version")
    if SEMVER_RE.fullmatch(version.lstrip("v")) is None:
        fail(f"{tool} descriptor version is unsupported: {version}")
    if tool == "syft":
        schema = report.get("schema")
        if not isinstance(schema, dict):
            fail("syft report must contain a schema object")
        schema_version = nonblank(schema.get("version"), "syft schema version")
        if (
            SEMVER_RE.fullmatch(schema_version) is None
            or int(schema_version.split(".", 1)[0]) != SUPPORTED_SYFT_SCHEMA_MAJOR
        ):
            fail(f"unsupported syft schema version: {schema_version}")


def image_evidence(report: Any, tool: str, target_key: str) -> str:
    if not isinstance(report, dict):
        fail(f"{tool} report must be a JSON object")
    validate_descriptor(report, tool)
    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        fail(f"{tool} report source must describe an image")
    target = source.get(target_key)
    if not isinstance(target, dict):
        fail(f"{tool} report source must contain image metadata")
    user_input = target.get("userInput")
    if not isinstance(user_input, str) or "@" not in user_input:
        fail(f"{tool} image target must be pinned by digest")
    digest = user_input.rsplit("@", 1)[1]
    if SHA256_DIGEST_RE.fullmatch(digest) is None:
        fail(f"{tool} image target must use a sha256 digest")
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
        fail(f"{tool} image target digest must appear in repoDigests")
    if target.get("architecture") != "amd64" or target.get("os") != "linux":
        fail(f"{tool} image target must be linux/amd64")
    return digest


def syft_artifacts(report: Any) -> dict[str, dict[str, Any]]:
    artifacts = report.get("artifacts") if isinstance(report, dict) else None
    if not isinstance(artifacts, list):
        fail("syft report must contain an artifacts list")
    indexed: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("syft report artifacts must be objects")
        artifact_id = nonblank(artifact.get("id"), "syft artifact id")
        if artifact_id in indexed:
            fail(f"syft report contains duplicate artifact id: {artifact_id}")
        for field in ("name", "version", "type"):
            nonblank(artifact.get(field), f"syft artifact {field}")
        indexed[artifact_id] = artifact
    return indexed


def normalize_grype(
    report: Any, subject: str, syft_report: Any | None = None
) -> list[Finding]:
    if syft_report is None:
        fail("grype checks require native Syft JSON evidence")
    image_digest = image_evidence(report, "grype", "target")
    syft_digest = image_evidence(syft_report, "syft", "metadata")
    if image_digest != syft_digest:
        fail("Grype and Syft reports do not describe the same image digest")
    artifacts = syft_artifacts(syft_report)
    matches = report.get("matches") if isinstance(report, dict) else None
    if not isinstance(matches, list):
        fail("grype report must contain a matches list")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in matches:
        if not isinstance(item, dict):
            fail("grype report matches must be objects")
        vulnerability = item.get("vulnerability")
        artifact = item.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            fail("grype report matches must contain vulnerability and artifact objects")
        artifact_id = nonblank(artifact.get("id"), "grype artifact id")
        syft_artifact = artifacts.get(artifact_id)
        if syft_artifact is None or any(
            artifact.get(field) != syft_artifact.get(field)
            for field in ("id", "name", "version", "type")
        ):
            fail("grype finding artifact does not match the Syft package model")
        vulnerability_id = nonblank(
            vulnerability.get("id"), "grype vulnerability id"
        )
        package = nonblank(artifact.get("name"), "grype package name")
        installed_version = nonblank(
            artifact.get("version"), "grype installed package version"
        )
        package_type = nonblank(artifact.get("type"), "grype package type")
        severity = nonblank(
            vulnerability.get("severity"), "grype vulnerability severity"
        ).lower()
        severity_rank(severity)
        fix = vulnerability.get("fix")
        if not isinstance(fix, dict):
            fail(f"grype finding {vulnerability_id} must contain a fix object")
        versions = fix.get("versions")
        if not isinstance(versions, list) or any(
            not isinstance(version, str) for version in versions
        ):
            fail(f"grype finding {vulnerability_id} has malformed fix versions")
        fix_versions = tuple(version.strip() for version in versions if version.strip())
        fix_state = fix.get("state")
        if (
            not isinstance(fix_state, str)
            or fix_state.casefold() not in GRYPE_FIX_STATES
        ):
            fail(f"grype finding {vulnerability_id} has unsupported fix state")
        key = (vulnerability_id, package, installed_version)
        if key in seen:
            fail(
                "grype report contains duplicate stable finding identity: "
                f"{vulnerability_id} {package} {installed_version}"
            )
        seen.add(key)
        findings.append(
            Finding(
                tool="grype",
                fingerprint="|".join(
                    [
                        "grype",
                        subject,
                        vulnerability_id,
                        package,
                        installed_version,
                        package_type,
                    ]
                ),
                rule_id=vulnerability_id,
                severity=severity,
                location=subject,
                summary=f"{vulnerability_id} in {package} {installed_version}",
                package=package,
                installed_version=installed_version,
                package_type=package_type,
                fix_versions=fix_versions,
                fix_state=fix_state.casefold(),
                image_digest=image_digest,
            )
        )
    return findings


def validate_policies(policies: Any) -> None:
    if not isinstance(policies, list) or not policies:
        fail("baseline must contain non-empty policies")
    seen_tools: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            fail("baseline policies must be objects")
        tool = nonblank(policy.get("tool"), "baseline policy tool")
        expected_fields = {"tool", "minimum_severity", "action"}
        if tool == "grype":
            expected_fields.add("block_fixable")
        if set(policy) != expected_fields:
            fail(f"baseline policy for {tool} has missing or unknown fields")
        if tool not in {"zizmor", "grype"} or tool in seen_tools:
            fail(f"unsupported or duplicate baseline policy tool: {tool}")
        seen_tools.add(tool)
        severity_rank(policy["minimum_severity"])
        if policy["action"] != "block_unreviewed":
            fail(f"unsupported policy action: {policy['action']}")
        if tool == "grype" and policy["block_fixable"] is not True:
            fail("grype policy must set block_fixable to true")
    if seen_tools != {"zizmor", "grype"}:
        fail("baseline must define exactly the zizmor and grype policies")


def validate_v3_exception(exception: Any) -> None:
    if not isinstance(exception, dict) or set(exception) != V3_EXCEPTION_FIELDS:
        fail("v3 advisory exceptions must have the exact stable field set")
    for field in (
        "vulnerability_id",
        "package",
        "installed_version",
        "owner",
        "rationale",
    ):
        nonblank(exception.get(field), f"advisory exception {field}")
    if severity_rank(exception["severity"]) < SEVERITY_ORDER["high"]:
        fail("advisory exception severity must be high or critical")
    if exception["status"] not in V3_EXCEPTION_STATUSES:
        fail(f"unsupported advisory exception status: {exception['status']}")
    reviewed_at = parse_date(exception["reviewed_at"], "reviewed_at")
    expires_at = parse_date(exception["expires_at"], "expires_at")
    if expires_at < reviewed_at:
        fail("advisory exception expires_at must not precede reviewed_at")
    triggers = exception["invalidation_triggers"]
    if (
        not isinstance(triggers, list)
        or len(triggers) != len(set(triggers))
        or set(triggers) != REQUIRED_INVALIDATION_TRIGGERS
    ):
        fail(
            "advisory exception must contain exactly the required invalidation triggers"
        )


def validate_v2_baseline(data: dict[str, Any]) -> None:
    reviewed = data.get("reviewed_findings")
    if not isinstance(reviewed, list):
        fail("v2 baseline reviewed_findings must be a list")
    for review in reviewed:
        if not isinstance(review, dict):
            fail("v2 reviewed findings must be objects")
        for field in (
            "tool",
            "fingerprint",
            "rule_id",
            "severity",
            "status",
            "owner",
            "reason",
            "reviewed_at",
            "expires_at",
        ):
            if field not in review:
                fail(f"v2 reviewed finding missing field: {field}")
        for field in ("tool", "fingerprint", "rule_id", "owner", "reason"):
            nonblank(review[field], f"v2 reviewed finding {field}")
        severity_rank(review["severity"])
        reviewed_at = parse_date(review["reviewed_at"], "reviewed_at")
        expires_at = parse_date(review["expires_at"], "expires_at")
        if expires_at < reviewed_at:
            fail("v2 reviewed finding expires_at must not precede reviewed_at")


def validate_v3_baseline(data: dict[str, Any]) -> None:
    if set(data) != V3_TOP_LEVEL_FIELDS:
        fail("v3 baseline must have the exact top-level field set")
    nonblank(data.get("service"), "baseline service")
    validate_policies(data.get("policies"))
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        fail("v3 baseline exceptions must be a list")
    seen: set[tuple[str, str, str]] = set()
    for exception in exceptions:
        validate_v3_exception(exception)
        key = exception_key(exception)
        if key in seen:
            fail(f"duplicate advisory exception identity: {' '.join(key)}")
        seen.add(key)


def load_baseline(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        fail("baseline must be a JSON object")
    version = data.get("version")
    if version == 3:
        validate_v3_baseline(data)
    elif version == 2:
        validate_policies(data.get("policies"))
        validate_v2_baseline(data)
    else:
        fail(f"unsupported baseline version: {version}")
    return data


def exception_key(exception: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(exception["vulnerability_id"]),
        str(exception["package"]),
        str(exception["installed_version"]),
    )


def v2_exception(review: dict[str, Any]) -> dict[str, Any] | None:
    if review.get("tool") != "grype":
        return None
    parts = str(review["fingerprint"]).split("|")
    if len(parts) != 6 or parts[0] != "grype":
        fail("v2 grype reviewed finding has an unsupported fingerprint")
    return {
        "vulnerability_id": str(review["rule_id"]),
        "package": parts[3],
        "installed_version": parts[4],
        "severity": str(review["severity"]),
        "status": str(review["status"]),
        "owner": str(review["owner"]),
        "rationale": str(review["reason"]),
        "reviewed_at": str(review["reviewed_at"]),
        "expires_at": str(review["expires_at"]),
        "invalidation_triggers": sorted(REQUIRED_INVALIDATION_TRIGGERS),
    }


def baseline_exceptions(baseline: dict[str, Any]) -> list[dict[str, Any]]:
    if baseline["version"] == 3:
        return baseline["exceptions"]
    return [
        exception
        for review in baseline["reviewed_findings"]
        if (exception := v2_exception(review)) is not None
    ]


def policy_threshold(baseline: dict[str, Any], tool: str) -> str:
    matches = [policy for policy in baseline["policies"] if policy["tool"] == tool]
    if not matches:
        fail(f"baseline has no policy for {tool}")
    return str(matches[0]["minimum_severity"]).lower()


def finding_is_blocking(finding: Finding, tool: str, threshold_rank: int) -> bool:
    return (tool == "grype" and finding.fixable) or severity_rank(
        finding.severity
    ) >= threshold_rank


def check_grype_findings(
    findings: list[Finding], baseline: dict[str, Any], today: dt.date
) -> int:
    threshold = policy_threshold(baseline, "grype")
    threshold_rank = severity_rank(threshold)
    blocking = [
        finding
        for finding in findings
        if finding_is_blocking(finding, "grype", threshold_rank)
    ]
    exceptions = baseline_exceptions(baseline)
    by_key = {exception_key(exception): exception for exception in exceptions}
    finding_by_key = {finding.exception_key: finding for finding in findings}
    findings_by_advisory: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        findings_by_advisory.setdefault(finding.advisory_key, []).append(finding)
    reported_version_mismatches: set[tuple[str, str, str]] = set()
    invalid: list[str] = []

    for exception in exceptions:
        key = exception_key(exception)
        advisory_key = key[:2]
        finding = finding_by_key.get(key)
        if parse_date(exception["reviewed_at"], "reviewed_at") > today:
            invalid.append(f"future-dated exception: {' '.join(key)}")
        if parse_date(exception["expires_at"], "expires_at") < today:
            invalid.append(f"expired exception: {' '.join(key)}")
        if finding is None:
            changed = findings_by_advisory.get(advisory_key, [])
            if changed:
                installed_versions = sorted(
                    {candidate.installed_version for candidate in changed}
                )
                reported_version_mismatches.update(
                    candidate.exception_key for candidate in changed
                )
                invalid.append(
                    "version-mismatched exception: "
                    f"{key[0]} {key[1]} reviewed={key[2]} "
                    f"installed={installed_versions}"
                )
            else:
                invalid.append(
                    "fixed or absent finding still has an exception: " + " ".join(key)
                )
            continue
        if finding.fixable:
            invalid.append(
                "fixable finding cannot be excepted: "
                f"{finding.rule_id} {finding.package} {finding.installed_version}"
            )
        if str(exception["severity"]).casefold() != finding.severity.casefold():
            invalid.append(
                "material finding change invalidates exception: "
                f"{finding.rule_id} {finding.package} {finding.installed_version} "
                f"reviewed_severity={exception['severity']} "
                f"current_severity={finding.severity}"
            )

    for finding in blocking:
        if finding.fixable:
            if finding.exception_key not in by_key:
                invalid.append(
                    "fixable finding blocks: "
                    f"{finding.rule_id} {finding.package} {finding.installed_version} "
                    f"fixes={list(finding.fix_versions)}"
                )
            continue
        if finding.exception_key not in by_key:
            reviewed_versions = [
                key[2] for key in by_key if key[:2] == finding.advisory_key
            ]
            if reviewed_versions:
                if finding.exception_key not in reported_version_mismatches:
                    invalid.append(
                        "version-mismatched finding: "
                        f"{finding.rule_id} {finding.package} "
                        f"reviewed={reviewed_versions} "
                        f"installed={finding.installed_version}"
                    )
            else:
                invalid.append(
                    "unreviewed blocking finding: "
                    f"{finding.rule_id} {finding.severity} "
                    f"{finding.package} {finding.installed_version}"
                )

    for message in invalid:
        print(message, file=sys.stderr)
    print(
        "advisory baseline: "
        f"grype image={findings[0].image_digest if findings else '<none>'} "
        f"threshold={threshold} findings={len(findings)} blocking={len(blocking)} "
        f"exceptions={len(exceptions)} invalid={len(invalid)}"
    )
    return int(bool(invalid))


def check_zizmor_findings(
    findings: list[Finding], baseline: dict[str, Any], today: dt.date
) -> int:
    threshold = policy_threshold(baseline, "zizmor")
    threshold_rank = severity_rank(threshold)
    blocking = [
        finding
        for finding in findings
        if severity_rank(finding.severity) >= threshold_rank
    ]
    legacy_reviews = {}
    if baseline["version"] == 2:
        legacy_reviews = {
            str(review["fingerprint"]): review
            for review in baseline["reviewed_findings"]
            if review.get("tool") == "zizmor"
        }
    invalid = []
    for finding in blocking:
        review = legacy_reviews.get(finding.fingerprint)
        if review is None:
            invalid.append(f"unreviewed blocking finding: {finding.fingerprint}")
        elif parse_date(review["expires_at"], "expires_at") < today:
            invalid.append(f"expired reviewed finding: {finding.fingerprint}")
        elif str(review["severity"]).casefold() != finding.severity.casefold():
            invalid.append(f"reviewed finding changed: {finding.fingerprint}")
    for message in invalid:
        print(message, file=sys.stderr)
    print(
        "advisory baseline: "
        f"zizmor threshold={threshold} blocking={len(blocking)} invalid={len(invalid)}"
    )
    return int(bool(invalid))


def check_findings(
    tool: str,
    findings: list[Finding],
    baseline: dict[str, Any],
    today: dt.date,
) -> int:
    if tool == "grype":
        return check_grype_findings(findings, baseline, today)
    return check_zizmor_findings(findings, baseline, today)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=["zizmor", "grype"])
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--subject", default="image")
    parser.add_argument("--today", default=dt.date.today().isoformat())
    parser.add_argument(
        "--syft-report",
        type=Path,
        help="Native Syft JSON for the same digest-bound candidate image.",
    )
    parser.add_argument(
        "--dump-blocking-findings",
        action="store_true",
        help="Print normalized findings at or above the configured threshold.",
    )
    args = parser.parse_args()

    report = load_json(args.report)
    baseline = load_baseline(args.baseline)
    today = parse_date(args.today, "today")
    if args.tool == "zizmor":
        if args.syft_report is not None:
            fail("--syft-report is only valid for grype")
        findings = normalize_zizmor(report)
    else:
        if args.syft_report is None:
            fail("grype checks require --syft-report native Syft JSON evidence")
        findings = normalize_grype(
            report, args.subject, load_json(args.syft_report)
        )

    if args.dump_blocking_findings:
        threshold_rank = severity_rank(policy_threshold(baseline, args.tool))
        print(
            json.dumps(
                [
                    finding.to_json()
                    for finding in findings
                    if finding_is_blocking(finding, args.tool, threshold_rank)
                ],
                indent=2,
                sort_keys=True,
            )
        )
        return
    raise SystemExit(check_findings(args.tool, findings, baseline, today))


if __name__ == "__main__":
    main()
