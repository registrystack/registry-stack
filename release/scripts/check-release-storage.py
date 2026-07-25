#!/usr/bin/env python3
"""Fail-closed release storage preflight and peak-storage sampler."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "registry-stack.release-storage-budget.v1"
TOP_LEVEL_KEYS = {
    "blocker",
    "measurement",
    "required_available_bytes",
    "runner_scope",
    "safety_margin_ratio",
    "schema_version",
    "status",
}


class StorageError(ValueError):
    """Raised when storage policy or measurements are invalid."""


def load_budget(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StorageError(f"could not read storage budget {path}: {error}") from error
    if not isinstance(value, dict) or set(value) != TOP_LEVEL_KEYS:
        raise StorageError("storage budget must have the exact v1 field set")
    if value["schema_version"] != SCHEMA_VERSION:
        raise StorageError("storage budget has an unsupported schema_version")
    if value["runner_scope"] != "per-job":
        raise StorageError("storage budget runner_scope must be per-job")
    margin = value["safety_margin_ratio"]
    if (
        not isinstance(margin, (int, float))
        or isinstance(margin, bool)
        or not 0 < margin < 1
    ):
        raise StorageError(
            "storage budget safety_margin_ratio must be between zero and one"
        )
    status = value["status"]
    if status == "measurement_required":
        if (
            value["required_available_bytes"] is not None
            or value["measurement"] is not None
        ):
            raise StorageError(
                "measurement_required budget cannot contain an invented numeric budget"
            )
        if not isinstance(value["blocker"], str) or not value["blocker"].strip():
            raise StorageError("measurement_required budget must document its blocker")
    elif status == "enforced":
        required = value["required_available_bytes"]
        if not isinstance(required, int) or isinstance(required, bool) or required <= 0:
            raise StorageError(
                "enforced budget required_available_bytes must be a positive integer"
            )
        measurement = value["measurement"]
        if not isinstance(measurement, dict):
            raise StorageError("enforced budget must cite its real measurement")
        required_measurement = {
            "candidate_run_url",
            "measured_at",
            "peak_filesystem_used_bytes",
            "peak_workspace_bytes",
        }
        if set(measurement) != required_measurement:
            raise StorageError("enforced budget measurement has an invalid field set")
        if not isinstance(measurement["candidate_run_url"], str) or not measurement[
            "candidate_run_url"
        ].startswith("https://github.com/registrystack/registry-stack/actions/runs/"):
            raise StorageError(
                "enforced budget must cite a Registry Stack candidate run"
            )
        for field in ("peak_filesystem_used_bytes", "peak_workspace_bytes"):
            if (
                not isinstance(measurement[field], int)
                or isinstance(measurement[field], bool)
                or measurement[field] <= 0
            ):
                raise StorageError(f"measurement {field} must be a positive integer")
        parse_timestamp(measurement["measured_at"], field="measurement.measured_at")
    else:
        raise StorageError(
            "storage budget status must be measurement_required or enforced"
        )
    return value


def parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise StorageError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StorageError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise StorageError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def preflight(
    budget: dict[str, Any],
    *,
    available_bytes: int,
    measurement_run: bool,
) -> dict[str, Any]:
    if available_bytes < 0:
        raise StorageError("available storage cannot be negative")
    if budget["status"] == "measurement_required":
        if not measurement_run:
            raise StorageError(
                "release storage budget is blocked on a real peak measurement; "
                "run the explicitly authorized bootstrap measurement path"
            )
        return {
            "schema_version": "registry-stack.release-storage-preflight.v1",
            "budget_status": "measurement_required",
            "mode": "bootstrap_measurement",
            "available_bytes": available_bytes,
            "required_available_bytes": None,
            "passed": True,
        }
    required = budget["required_available_bytes"]
    if available_bytes < required:
        raise StorageError(
            f"insufficient release storage: {available_bytes} bytes available, "
            f"{required} bytes required"
        )
    return {
        "schema_version": "registry-stack.release-storage-preflight.v1",
        "budget_status": "enforced",
        "mode": "enforced",
        "available_bytes": available_bytes,
        "required_available_bytes": required,
        "passed": True,
    }


def workspace_size(path: Path) -> int:
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        directories[:] = [
            name for name in directories if not (Path(root) / name).is_symlink()
        ]
        for name in files:
            candidate = Path(root) / name
            try:
                if not candidate.is_symlink():
                    total += candidate.stat().st_size
            except FileNotFoundError:
                continue
    return total


def sample_once(
    workspace: Path, *, label: str, now: datetime | None = None
) -> dict[str, Any]:
    usage = shutil.disk_usage(workspace)
    timestamp = (
        (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    )
    return {
        "timestamp": timestamp,
        "label": label,
        "filesystem_total_bytes": usage.total,
        "filesystem_used_bytes": usage.used,
        "filesystem_available_bytes": usage.free,
        "workspace_bytes": workspace_size(workspace),
    }


def render_samples(samples: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    if not samples:
        raise StorageError("at least one storage sample is required")
    return {
        "schema_version": "registry-stack.release-storage-measurement.v1",
        "workspace": str(workspace.resolve()),
        "sample_count": len(samples),
        "peak_filesystem_used_bytes": max(
            sample["filesystem_used_bytes"] for sample in samples
        ),
        "peak_workspace_bytes": max(sample["workspace_bytes"] for sample in samples),
        "minimum_available_bytes": min(
            sample["filesystem_available_bytes"] for sample in samples
        ),
        "samples": samples,
    }


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def monitor(
    *,
    workspace: Path,
    output: Path,
    stop_file: Path,
    interval_seconds: float,
    label: str,
    max_samples: int | None = None,
) -> dict[str, Any]:
    if interval_seconds <= 0:
        raise StorageError("sample interval must be positive")
    samples: list[dict[str, Any]] = []
    while True:
        samples.append(sample_once(workspace, label=label))
        rendered = render_samples(samples, workspace)
        write_json_atomic(output, rendered)
        if stop_file.exists() or (
            max_samples is not None and len(samples) >= max_samples
        ):
            return rendered
        time.sleep(interval_seconds)


def append_github_output(path: Path, result: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"storage_budget_status={result['budget_status']}\n")
        handle.write(f"storage_preflight_mode={result['mode']}\n")
        handle.write(f"storage_available_bytes={result['available_bytes']}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser(
        "preflight", help="fail before a build when measured runway is insufficient"
    )
    preflight_parser.add_argument("--budget", type=Path, required=True)
    preflight_parser.add_argument("--workspace", type=Path, required=True)
    preflight_parser.add_argument(
        "--measurement-run",
        action="store_true",
        help=(
            "explicitly authorize the first instrumented run while the budget "
            "truthfully remains measurement_required"
        ),
    )
    preflight_parser.add_argument("--output", type=Path)
    preflight_parser.add_argument("--github-output", type=Path)

    sample_parser = subparsers.add_parser(
        "sample", help="sample runner and workspace storage until a stop file exists"
    )
    sample_parser.add_argument("--workspace", type=Path, required=True)
    sample_parser.add_argument("--output", type=Path, required=True)
    sample_parser.add_argument("--stop-file", type=Path, required=True)
    sample_parser.add_argument("--interval-seconds", type=float, default=15.0)
    sample_parser.add_argument("--label", default="release-build")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if not args.workspace.is_dir():
            raise StorageError(f"workspace is not a directory: {args.workspace}")
        if args.command == "preflight":
            budget = load_budget(args.budget)
            result = preflight(
                budget,
                available_bytes=shutil.disk_usage(args.workspace).free,
                measurement_run=args.measurement_run,
            )
            if args.output is not None:
                write_json_atomic(args.output, result)
            if args.github_output is not None:
                append_github_output(args.github_output, result)
        else:
            result = monitor(
                workspace=args.workspace,
                output=args.output,
                stop_file=args.stop_file,
                interval_seconds=args.interval_seconds,
                label=args.label,
            )
    except StorageError as error:
        print(f"release storage check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
