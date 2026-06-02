#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail CI when advisory security tools report unreviewed blocking findings."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "security" / "advisory-baseline.json"

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

REQUIRED_REVIEW_FIELDS = {
    "tool",
    "fingerprint",
    "severity",
    "status",
    "owner",
    "reason",
    "reviewed_at",
    "expires_at",
}


@dataclass(frozen=True)
class Finding:
    tool: str
    fingerprint: str
    rule_id: str
    severity: str
    location: str
    summary: str

    def to_json(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "summary": self.summary,
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


def severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER[value.lower()]
    except KeyError:
        fail(f"unknown severity value: {value}")


def normalize_path(value: str | None) -> str:
    if not value:
        return "<unknown>"
    if value.startswith("./"):
        return value[2:]
    return value


def route_key(route: Any) -> str:
    if not isinstance(route, dict):
        return ""
    route_list = route.get("route")
    if not isinstance(route_list, list):
        return ""
    parts = []
    for entry in route_list:
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
        if not isinstance(item, dict) or item.get("ignored"):
            continue
        determinations = item.get("determinations")
        if not isinstance(determinations, dict):
            determinations = {}
        severity = str(determinations.get("severity", "informational")).lower()
        ident = str(item.get("ident", "<unknown>"))
        location = primary_location(item.get("locations"))
        symbolic = location.get("symbolic", {}) if isinstance(location, dict) else {}
        concrete = location.get("concrete", {}) if isinstance(location, dict) else {}
        key = symbolic.get("key", {}) if isinstance(symbolic, dict) else {}
        local = key.get("Local", {}) if isinstance(key, dict) else {}
        path = normalize_path(local.get("given_path") if isinstance(local, dict) else None)
        annotation = str(symbolic.get("annotation", "")) if isinstance(symbolic, dict) else ""
        feature = str(concrete.get("feature", "")) if isinstance(concrete, dict) else ""
        route = route_key(symbolic.get("route") if isinstance(symbolic, dict) else None)
        detail = feature if ident == "unpinned-uses" and feature else annotation or feature
        fingerprint = "|".join(["zizmor", ident, path, route, detail])
        summary = str(item.get("desc") or annotation or feature or ident)
        findings.append(
            Finding(
                tool="zizmor",
                fingerprint=fingerprint,
                rule_id=ident,
                severity=severity,
                location=path,
                summary=summary,
            )
        )
    return findings


def normalize_grype(report: Any, subject: str) -> list[Finding]:
    if not isinstance(report, dict):
        fail("grype report must be a JSON object")
    matches = report.get("matches")
    if not isinstance(matches, list):
        fail("grype report must contain a matches list")
    findings: list[Finding] = []
    for item in matches:
        if not isinstance(item, dict):
            continue
        vulnerability = item.get("vulnerability", {})
        artifact = item.get("artifact", {})
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            continue
        vuln_id = str(vulnerability.get("id", "<unknown>"))
        severity = str(vulnerability.get("severity", "negligible")).lower()
        package_name = str(artifact.get("name", "<unknown>"))
        package_version = str(artifact.get("version", "<unknown>"))
        package_type = str(artifact.get("type", "<unknown>"))
        fingerprint = "|".join(
            [
                "grype",
                subject,
                vuln_id,
                package_name,
                package_version,
                package_type,
            ]
        )
        findings.append(
            Finding(
                tool="grype",
                fingerprint=fingerprint,
                rule_id=vuln_id,
                severity=severity,
                location=subject,
                summary=f"{vuln_id} in {package_name} {package_version}",
            )
        )
    return findings


def load_baseline(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        fail("baseline must be a JSON object")
    if data.get("version") != 1:
        fail("baseline version must be 1")
    policies = data.get("policies")
    if not isinstance(policies, list) or not policies:
        fail("baseline must contain non-empty policies")
    reviewed = data.get("reviewed_findings")
    if not isinstance(reviewed, list):
        fail("baseline reviewed_findings must be a list")
    for policy in policies:
        if not isinstance(policy, dict):
            fail("baseline policies must be objects")
        for field in ("tool", "minimum_severity", "action"):
            if field not in policy:
                fail(f"baseline policy missing {field}")
        severity_rank(str(policy["minimum_severity"]))
        if policy["action"] != "block_unreviewed":
            fail(f"unsupported policy action: {policy['action']}")
    seen_reviews: set[str] = set()
    for review in reviewed:
        validate_review_entry(review)
        fingerprint = str(review["fingerprint"])
        if fingerprint in seen_reviews:
            fail(f"duplicate reviewed finding fingerprint: {fingerprint}")
        seen_reviews.add(fingerprint)
    return data


def validate_review_entry(review: Any) -> None:
    if not isinstance(review, dict):
        fail("reviewed findings must be objects")
    missing = REQUIRED_REVIEW_FIELDS - set(review)
    if missing:
        fail(f"reviewed finding missing fields: {sorted(missing)}")
    if review["status"] not in {"accepted_risk", "false_positive", "tool_noise"}:
        fail(f"unsupported reviewed finding status: {review['status']}")
    severity_rank(str(review["severity"]))
    for field in ("reviewed_at", "expires_at"):
        parse_date(str(review[field]), field)
    for field in ("fingerprint", "owner", "reason"):
        value = review.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"reviewed finding {field} must be a non-blank string")


def parse_date(value: str, field: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        fail(f"{field} must be an ISO date: {value}")


def policy_threshold(baseline: dict[str, Any], tool: str) -> str:
    matches = [p for p in baseline["policies"] if p.get("tool") == tool]
    if not matches:
        fail(f"baseline has no policy for {tool}")
    return str(matches[0]["minimum_severity"]).lower()


def check_findings(
    tool: str,
    findings: list[Finding],
    baseline: dict[str, Any],
    today: dt.date,
    review_scope: str | None = None,
) -> int:
    threshold = policy_threshold(baseline, tool)
    threshold_rank = severity_rank(threshold)
    blocking = [f for f in findings if severity_rank(f.severity) >= threshold_rank]
    active_fingerprints = {finding.fingerprint for finding in blocking}
    reviews = {
        str(review["fingerprint"]): review
        for review in baseline["reviewed_findings"]
        if review.get("tool") == tool
        and (
            review_scope is None
            or str(review["fingerprint"]).startswith(f"{tool}|{review_scope}|")
        )
    }
    expired = [
        review
        for review in reviews.values()
        if review["fingerprint"] in active_fingerprints
        and parse_date(str(review["expires_at"]), "expires_at") < today
    ]
    if expired:
        for review in expired:
            print(
                f"expired reviewed finding: {review['tool']} {review['fingerprint']} "
                f"expired_at={review['expires_at']}",
                file=sys.stderr,
            )
        return 1

    unreviewed = [finding for finding in blocking if finding.fingerprint not in reviews]
    if unreviewed:
        for finding in unreviewed:
            print(
                "unreviewed blocking finding: "
                f"{finding.tool} {finding.rule_id} {finding.severity} "
                f"{finding.location} fingerprint={finding.fingerprint}",
                file=sys.stderr,
            )
        return 1

    stale = sorted(set(reviews) - active_fingerprints)
    print(
        "advisory baseline: "
        f"{tool} threshold={threshold} blocking={len(blocking)} "
        f"reviewed={len(blocking) - len(unreviewed)} "
        f"unreviewed={len(unreviewed)} expired={len(expired)} stale={len(stale)}"
    )
    if stale:
        print(f"advisory baseline: {tool} has stale reviewed entries: {len(stale)}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=["zizmor", "grype"])
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--subject", default="image")
    parser.add_argument("--today", default=dt.date.today().isoformat())
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
        findings = normalize_zizmor(report)
    else:
        findings = normalize_grype(report, args.subject)

    if args.dump_blocking_findings:
        threshold = policy_threshold(baseline, args.tool)
        threshold_rank = severity_rank(threshold)
        blocking = [
            finding.to_json()
            for finding in findings
            if severity_rank(finding.severity) >= threshold_rank
        ]
        print(json.dumps(blocking, indent=2, sort_keys=True))
        return

    review_scope = args.subject if args.tool == "grype" else None
    raise SystemExit(check_findings(args.tool, findings, baseline, today, review_scope))


if __name__ == "__main__":
    main()
