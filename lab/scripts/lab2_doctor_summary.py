#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize Lab 2 Relay and Notary deployment-profile doctor reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


FINDING_STATUSES = {"active", "warning", "failed"}
FINDING_SEVERITIES = {
    "finding_warn",
    "finding_error",
    "readiness_fail",
    "startup_fail",
    "warning",
    "error",
}


def load_report(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} did not contain a JSON doctor report: {exc}") from exc


def compact_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item[key]
        for key in ("id", "code", "severity", "status", "message", "action")
        if key in item
    }


def is_finding_like(item: dict[str, Any]) -> bool:
    status = item.get("status")
    severity = item.get("severity")
    return status in FINDING_STATUSES or severity in FINDING_SEVERITIES


def report_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings")
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    diagnostics = report.get("diagnostics")
    if isinstance(diagnostics, list):
        return [
            item
            for item in diagnostics
            if isinstance(item, dict) and is_finding_like(item)
        ]
    return []


def summarize(product: str, status: int, path: Path, profile: str) -> dict[str, Any]:
    report = load_report(path)
    items = report_items(report)
    return {
        "product": product,
        "exit_status": status,
        "ok": bool(report.get("ok", status == 0)),
        "profile": report.get("deployment_profile", {"value": profile, "source": "override"}),
        "report": str(path),
        "finding_count": len(items),
        "findings": [compact_item(item) for item in items],
    }


def build_summary(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "profile": args.profile,
        "strict": args.strict,
        "reports": [
            summarize(
                "registry-relay",
                args.relay_status,
                args.relay_report,
                args.profile,
            ),
            summarize(
                "registry-notary",
                args.notary_status,
                args.notary_report,
                args.profile,
            ),
        ],
    }


def strict_failed(summary: dict[str, Any]) -> bool:
    return any(
        report["exit_status"] != 0 or not report["ok"] or report["finding_count"] > 0
        for report in summary["reports"]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--relay-status", type=int, required=True)
    parser.add_argument("--relay-report", type=Path, required=True)
    parser.add_argument("--notary-status", type=int, required=True)
    parser.add_argument("--notary-report", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = build_summary(args)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.strict and strict_failed(summary):
        raise SystemExit("doctor reported findings under LAB2_DOCTOR_STRICT=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
