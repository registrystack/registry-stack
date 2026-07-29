#!/usr/bin/env python3
"""Best-effort storage telemetry for GitHub-hosted release jobs."""

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


MEASUREMENT_SCHEMA = "registry-stack.release-storage-measurement.v2"


class StorageError(ValueError):
    """Raised when a storage measurement cannot be collected."""


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
            except OSError:
                continue
    return total


def sample_once(
    workspace: Path, *, label: str, now: datetime | None = None
) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(workspace)
    except OSError as error:
        raise StorageError(f"cannot inspect workspace storage: {error}") from error
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
    baseline_used = samples[0]["filesystem_used_bytes"]
    peak_used = max(sample["filesystem_used_bytes"] for sample in samples)
    return {
        "schema_version": MEASUREMENT_SCHEMA,
        "status": "measured",
        "blocking": False,
        "runner_scope": "github-hosted-per-job",
        "workspace": str(workspace.resolve()),
        "job_label": samples[0]["label"],
        "sample_count": len(samples),
        "baseline_filesystem_used_bytes": baseline_used,
        "peak_filesystem_used_bytes": peak_used,
        "peak_additional_filesystem_used_bytes": peak_used - baseline_used,
        "peak_workspace_bytes": max(sample["workspace_bytes"] for sample in samples),
        "minimum_available_bytes": min(
            sample["filesystem_available_bytes"] for sample in samples
        ),
        "samples": samples,
    }


def unavailable_result(error: Exception) -> dict[str, Any]:
    return {
        "schema_version": MEASUREMENT_SCHEMA,
        "status": "unavailable",
        "blocking": False,
        "runner_scope": "github-hosted-per-job",
        "warning": str(error),
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    sample_parser = subparsers.add_parser(
        "sample",
        help="collect nonblocking GitHub-hosted runner storage telemetry",
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
        result = monitor(
            workspace=args.workspace,
            output=args.output,
            stop_file=args.stop_file,
            interval_seconds=args.interval_seconds,
            label=args.label,
        )
    except (OSError, StorageError) as error:
        result = unavailable_result(error)
        print(f"release storage telemetry warning: {error}", file=sys.stderr)
        try:
            write_json_atomic(args.output, result)
        except OSError as write_error:
            print(
                "release storage telemetry warning: cannot write result: "
                f"{write_error}",
                file=sys.stderr,
            )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
