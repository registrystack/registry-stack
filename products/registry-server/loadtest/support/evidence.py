#!/usr/bin/env python3
"""Safe evidence capture and mechanical summaries for Registry Server load tests."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ALLOWED_PARAMETERS = {
    "baselineDuration",
    "baselineOps",
    "duration",
    "followCursor",
    "offeredOps",
    "peakDuration",
    "peakOps",
    "rampDuration",
    "randomSeed",
    "rateOps",
    "recoveryDuration",
    "vus",
    "warmupDuration",
    "warmupOps",
}
SAFE_SEED_FIELDS = {
    "seed",
    "establishments",
    "businesses",
    "assignments",
    "establishment_id_count",
    "business_id_count",
}
SAFE_SAMPLE_TAGS = {"status", "method", "name", "scenario", "expected_response"}
SAFE_METRIC_LABELS = {"route", "method", "status", "state", "le"}
PROMETHEUS_LINE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+(?P<value>[-+0-9.eE]+|NaN|Inf|-Inf)$'
)
PROMETHEUS_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
JWT_PATTERN = re.compile(rb"[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}")
SQL_TEXT_PATTERN = re.compile(
    rb"\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM)\b",
    re.IGNORECASE,
)
FORBIDDEN_ARTIFACT_MARKERS = (
    b"Authorization:",
    b'"access_token"',
    b'"client_secret"',
    b'"requestBody"',
    b'"responseBody"',
)


class EvidenceError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = (result.stdout or result.stderr).strip().splitlines()
    return lines[0] if lines else ""


def _git_metadata(repository: Path) -> dict[str, Any]:
    revision = _command_output(["git", "-C", str(repository), "rev-parse", "HEAD"])
    status = _command_output(["git", "-C", str(repository), "status", "--porcelain"])
    if not revision or status is None:
        raise EvidenceError(f"cannot resolve Git revision for {repository}")
    return {"revision": revision, "dirty": bool(status)}


def _parameters(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, content = value.partition("=")
        if not separator or name not in ALLOWED_PARAMETERS or not content:
            raise EvidenceError(f"unsupported manifest parameter: {value}")
        result[name] = content
    return result


def create_manifest(arguments: argparse.Namespace) -> None:
    environment = _json_object(arguments.environment)
    seed = _json_object(arguments.seed_summary)
    manifest = {
        "schemaVersion": 1,
        "profile": arguments.profile,
        "status": "running",
        "startedAt": _utc_now(),
        "git": _git_metadata(arguments.repository),
        "configuration": {
            "poolMax": int(environment["pool_max"]),
            "parameters": _parameters(arguments.parameter),
        },
        "seed": {key: seed[key] for key in sorted(SAFE_SEED_FIELDS) if key in seed},
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "tools": {
            "k6": _command_output(["k6", "version"]),
            "docker": _command_output(["docker", "--version"]),
            "python": platform.python_version(),
        },
        "evidencePolicy": {
            "systemTags": sorted(SAFE_SAMPLE_TAGS),
            "excluded": [
                "bearer tokens",
                "client secrets",
                "cursor values",
                "request and response bodies",
                "record identifiers",
                "raw principals",
                "SQL text and bound values",
            ],
        },
    }
    if arguments.out.exists():
        raise EvidenceError(f"manifest already exists: {arguments.out}")
    _write_json(arguments.out, manifest)


def finish_manifest(arguments: argparse.Namespace) -> None:
    manifest = _json_object(arguments.path)
    if manifest.get("status") != "running":
        raise EvidenceError("only a running manifest can be finished")
    manifest["status"] = arguments.status
    manifest["finishedAt"] = _utc_now()
    manifest["exitCode"] = arguments.exit_code
    manifest["k6ExitCode"] = arguments.k6_exit_code
    _write_json(arguments.path, manifest)


def _parse_prometheus(body: str) -> list[dict[str, Any]]:
    metrics = []
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        match = PROMETHEUS_LINE.match(line)
        if not match or not match.group("name").startswith("registry_server_"):
            continue
        labels: dict[str, str] = {}
        raw_labels = match.group("labels") or ""
        for label in PROMETHEUS_LABEL.finditer(raw_labels):
            name = label.group(1)
            if name not in SAFE_METRIC_LABELS:
                raise EvidenceError(f"metrics endpoint exposed unexpected label {name}")
            labels[name] = bytes(label.group(2), "utf-8").decode("unicode_escape")
        metrics.append({"name": match.group("name"), "labels": labels, "value": float(match.group("value"))})
    return metrics


def _process_sample(pid_file: Path) -> dict[str, Any] | None:
    try:
        pid_text = pid_file.read_text(encoding="ascii").strip()
        if not pid_text.isdigit():
            return None
        output = subprocess.run(
            ["ps", "-p", pid_text, "-o", "%cpu=", "-o", "rss="],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        cpu, rss = output.split()
        return {"cpuPercent": float(cpu), "rssBytes": int(rss) * 1024}
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def sample_metrics(arguments: argparse.Namespace) -> None:
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    with arguments.out.open("a", encoding="utf-8", buffering=1) as handle:
        while True:
            try:
                with urllib.request.urlopen(arguments.url, timeout=5) as response:
                    body = response.read().decode("utf-8")
                sample: dict[str, Any] = {"timestamp": _utc_now(), "metrics": _parse_prometheus(body)}
                processes = {
                    name: reading
                    for name, path in (("server", arguments.server_pid), ("mint", arguments.mint_pid))
                    if path is not None and (reading := _process_sample(path)) is not None
                }
                if processes:
                    sample["processes"] = processes
                handle.write(json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n")
            except (OSError, UnicodeError, EvidenceError) as error:
                handle.write(
                    json.dumps({"timestamp": _utc_now(), "sampleError": type(error).__name__}, sort_keys=True)
                    + "\n"
                )
            time.sleep(arguments.interval)


def _metric_values(summary: dict[str, Any], name: str) -> dict[str, Any]:
    metric = summary.get("metrics", {}).get(name, {})
    values = metric.get("values", {}) if isinstance(metric, dict) else {}
    return values if isinstance(values, dict) else {}


def _quantile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    result = ordered[lower] * (upper - position) + ordered[upper] * (position - lower)
    return round(result, 3)


def _latency_summary(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "p50Ms": _quantile(values, 0.50),
        "p95Ms": _quantile(values, 0.95),
        "p99Ms": _quantile(values, 0.99),
        "maxMs": round(max(values), 3) if values else None,
    }


def _sample_summary(path: Path) -> dict[str, Any]:
    latencies: dict[str, list[float]] = defaultdict(list)
    phase_latencies: dict[str, list[float]] = defaultdict(list)
    phase_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"operations": 0, "httpRequests": 0, "droppedOperations": 0, "failedRequests": 0, "timeouts504": 0}
    )
    statuses: dict[str, int] = defaultdict(int)
    allowed_tag_violation: str | None = None
    if not path.exists():
        return {
            "operations": {},
            "phases": {},
            "phaseResults": {},
            "statuses": {},
            "tagViolation": "samples file missing",
        }
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise EvidenceError(f"invalid k6 sample JSON at line {line_number}: {error}") from error
            if item.get("type") != "Point":
                continue
            data = item.get("data", {})
            tags = data.get("tags", {})
            if not isinstance(tags, dict):
                raise EvidenceError(f"k6 sample tags are not an object at line {line_number}")
            unexpected = set(tags) - SAFE_SAMPLE_TAGS
            if unexpected and allowed_tag_violation is None:
                allowed_tag_violation = f"line {line_number}: {sorted(unexpected)}"
            metric = item.get("metric")
            phase = str(tags.get("scenario", "unassigned"))
            if metric == "http_req_duration":
                value = float(data["value"])
                latencies[str(tags.get("name", "unnamed"))].append(value)
                phase_latencies[phase].append(value)
            elif metric == "http_reqs":
                count = int(float(data.get("value", 0)))
                status = str(tags.get("status", "unknown"))
                statuses[status] += count
                phase_counts[phase]["httpRequests"] += count
                if status == "504":
                    phase_counts[phase]["timeouts504"] += count
            elif metric == "iterations":
                phase_counts[phase]["operations"] += int(float(data.get("value", 0)))
            elif metric == "dropped_iterations":
                phase_counts[phase]["droppedOperations"] += int(float(data.get("value", 0)))
            elif metric == "http_req_failed":
                phase_counts[phase]["failedRequests"] += int(float(data.get("value", 0)))
    phases = {}
    for name in sorted(set(phase_latencies) | set(phase_counts)):
        phases[name] = {**phase_counts[name], "latency": _latency_summary(phase_latencies[name])}
    return {
        "operations": {name: _latency_summary(values) for name, values in sorted(latencies.items())},
        "phases": {name: _latency_summary(values) for name, values in sorted(phase_latencies.items())},
        "phaseResults": phases,
        "statuses": dict(sorted(statuses.items())),
        "tagViolation": allowed_tag_violation,
    }


def _telemetry_summary(path: Path) -> dict[str, Any]:
    waiting_peak = 0.0
    cpu_peak: dict[str, float] = defaultdict(float)
    rss_peak: dict[str, int] = defaultdict(int)
    samples = 0
    errors = 0
    if not path.exists():
        return {"samples": 0, "sampleErrors": 0, "poolWaitingPeak": None, "processes": {}}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            if "sampleError" in item:
                errors += 1
                continue
            samples += 1
            for metric in item.get("metrics", []):
                if (
                    metric.get("name") == "registry_server_pool_connections"
                    and metric.get("labels", {}).get("state") == "waiting"
                ):
                    waiting_peak = max(waiting_peak, float(metric["value"]))
            for name, process in item.get("processes", {}).items():
                cpu_peak[name] = max(cpu_peak[name], float(process["cpuPercent"]))
                rss_peak[name] = max(rss_peak[name], int(process["rssBytes"]))
    return {
        "samples": samples,
        "sampleErrors": errors,
        "poolWaitingPeak": waiting_peak if samples else None,
        "processes": {
            name: {"cpuPercentPeak": cpu_peak[name], "rssBytesPeak": rss_peak[name]}
            for name in sorted(set(cpu_peak) | set(rss_peak))
        },
    }


def _db_wait_summary(path: Path) -> dict[str, Any]:
    peaks = {"auditLockWaiters": 0, "lockWaiters": 0, "blockedBackends": 0}
    samples = 0
    if not path.exists():
        return {"samples": 0, **{f"{name}Peak": None for name in peaks}}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise EvidenceError(f"invalid DB wait sample at line {line_number}: {error}") from error
            samples += 1
            for name in peaks:
                peaks[name] = max(peaks[name], int(item.get(name, 0)))
    return {"samples": samples, **{f"{name}Peak": value for name, value in peaks.items()}}


def summarize(arguments: argparse.Namespace) -> None:
    manifest = _json_object(arguments.manifest)
    summary = _json_object(arguments.k6_summary)
    sample_details = _sample_summary(arguments.samples)
    duration_ms = float(summary.get("state", {}).get("testRunDurationMs") or 0)
    duration_seconds = duration_ms / 1000 if duration_ms > 0 else None
    iterations = int(_metric_values(summary, "iterations").get("count", 0))
    http_requests = int(_metric_values(summary, "http_reqs").get("count", 0))
    dropped = int(_metric_values(summary, "dropped_iterations").get("count", 0))
    failed_rate = float(_metric_values(summary, "http_req_failed").get("rate", 0))
    thresholds: dict[str, Any] = {}
    for metric_name, metric in summary.get("metrics", {}).items():
        if not isinstance(metric, dict) or not isinstance(metric.get("thresholds"), dict):
            continue
        thresholds[metric_name] = {
            expression: bool(detail.get("ok"))
            for expression, detail in metric["thresholds"].items()
            if isinstance(detail, dict)
        }
    threshold_pass = all(all(expressions.values()) for expressions in thresholds.values())
    db_after = _json_object(arguments.db_after) if arguments.db_after.exists() else None
    safety = _json_object(arguments.safety) if arguments.safety.exists() else {"safe": False}
    result = {
        "schemaVersion": 1,
        "profile": manifest["profile"],
        "manifest": arguments.manifest.name,
        "durationSeconds": round(duration_seconds, 3) if duration_seconds is not None else None,
        "offered": manifest["configuration"]["parameters"],
        "execution": summary.get("options", {}).get("scenarios"),
        "achieved": {
            "operations": iterations,
            "operationsPerSecond": round(iterations / duration_seconds, 3) if duration_seconds else None,
            "httpRequests": http_requests,
            "httpRequestsPerSecond": round(http_requests / duration_seconds, 3) if duration_seconds else None,
            "droppedOperations": dropped,
            "failedRequestRate": round(failed_rate, 6),
            "timeouts504": sample_details["statuses"].get("504", 0),
        },
        "latency": {
            "overall": {
                "p50Ms": _metric_values(summary, "http_req_duration").get("med"),
                "p95Ms": _metric_values(summary, "http_req_duration").get("p(95)"),
                "p99Ms": _metric_values(summary, "http_req_duration").get("p(99)"),
                "maxMs": _metric_values(summary, "http_req_duration").get("max"),
            },
            "byOperation": sample_details["operations"],
            "byPhase": sample_details["phases"],
        },
        "httpStatuses": sample_details["statuses"],
        "phases": sample_details["phaseResults"],
        "telemetry": _telemetry_summary(arguments.telemetry),
        "database": {"snapshot": db_after, "waits": _db_wait_summary(arguments.db_waits)},
        "thresholds": thresholds,
        "pass": (
            arguments.k6_exit_code == 0
            and safety.get("safe") is True
            and threshold_pass
            and dropped == 0
            and sample_details["tagViolation"] is None
        ),
    }
    if sample_details["tagViolation"] is not None:
        result["unsafeSampleTags"] = sample_details["tagViolation"]
    _write_json(arguments.out, result)


def aggregate_sweep(arguments: argparse.Namespace) -> None:
    rows = []
    for path in sorted(arguments.root.glob("rate-*/result.json")):
        result = _json_object(path)
        rate = float(result["offered"]["rateOps"])
        rows.append(
            {
                "offeredOperationsPerSecond": rate,
                "achievedOperationsPerSecond": result["achieved"]["operationsPerSecond"],
                "httpRequestsPerSecond": result["achieved"]["httpRequestsPerSecond"],
                "droppedOperations": result["achieved"]["droppedOperations"],
                "failedRequestRate": result["achieved"]["failedRequestRate"],
                "p95Ms": result["latency"]["overall"]["p95Ms"],
                "p99Ms": result["latency"]["overall"]["p99Ms"],
                "pass": result["pass"],
                "artifact": str(path.parent.relative_to(arguments.root)),
            }
        )
    rows.sort(key=lambda row: row["offeredOperationsPerSecond"])
    knee = next((row["offeredOperationsPerSecond"] for row in rows if not row["pass"]), None)
    _write_json(arguments.out, {"schemaVersion": 1, "profile": "sweep", "firstFailingRate": knee, "rates": rows})


def assert_safe(arguments: argparse.Namespace) -> None:
    secrets = []
    for path in arguments.secret_file:
        value = path.read_bytes().strip()
        if value:
            secrets.append((path.name, value))
    seed_canaries = []
    for seed_pool in arguments.seed_pool:
        if not seed_pool.exists():
            continue
        for line in seed_pool.read_bytes().splitlines()[:20]:
            seed_canaries.extend(value for value in line.split()[:2] if value)
    violations = []
    for path in sorted(arguments.artifact_dir.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            for line in handle:
                for name, secret in secrets:
                    if secret in line:
                        violations.append(f"{path.name} contains {name}")
                if JWT_PATTERN.search(line):
                    violations.append(f"{path.name} contains a compact-JWT-shaped value")
                if SQL_TEXT_PATTERN.search(line):
                    violations.append(f"{path.name} contains SQL text")
                for marker in FORBIDDEN_ARTIFACT_MARKERS:
                    if marker in line:
                        violations.append(f"{path.name} contains forbidden marker {marker.decode('ascii')}")
                if any(canary in line for canary in seed_canaries):
                    violations.append(f"{path.name} contains a seeded record identifier")
    sample_details = _sample_summary(arguments.samples)
    if sample_details["tagViolation"]:
        violations.append(f"k6 samples contain unsafe tags ({sample_details['tagViolation']})")
    report = {"safe": not violations, "checkedAt": _utc_now(), "violations": sorted(set(violations))}
    _write_json(arguments.out, report)
    if violations:
        raise EvidenceError("unsafe load-test evidence: " + "; ".join(sorted(set(violations))))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser("manifest")
    manifest.add_argument("--out", type=Path, required=True)
    manifest.add_argument("--repository", type=Path, required=True)
    manifest.add_argument("--environment", type=Path, required=True)
    manifest.add_argument("--seed-summary", type=Path, required=True)
    manifest.add_argument("--profile", required=True)
    manifest.add_argument("--parameter", action="append", default=[])

    finish = commands.add_parser("finish")
    finish.add_argument("--path", type=Path, required=True)
    finish.add_argument("--status", choices=("passed", "failed"), required=True)
    finish.add_argument("--exit-code", type=int, required=True)
    finish.add_argument("--k6-exit-code", type=int, required=True)

    sample = commands.add_parser("sample-metrics")
    sample.add_argument("--url", required=True)
    sample.add_argument("--out", type=Path, required=True)
    sample.add_argument("--interval", type=float, default=1.0)
    sample.add_argument("--server-pid", type=Path)
    sample.add_argument("--mint-pid", type=Path)

    summary = commands.add_parser("summarize")
    summary.add_argument("--manifest", type=Path, required=True)
    summary.add_argument("--k6-summary", type=Path, required=True)
    summary.add_argument("--samples", type=Path, required=True)
    summary.add_argument("--telemetry", type=Path, required=True)
    summary.add_argument("--db-after", type=Path, required=True)
    summary.add_argument("--db-waits", type=Path, required=True)
    summary.add_argument("--safety", type=Path, required=True)
    summary.add_argument("--k6-exit-code", type=int, required=True)
    summary.add_argument("--out", type=Path, required=True)

    aggregate = commands.add_parser("aggregate-sweep")
    aggregate.add_argument("--root", type=Path, required=True)
    aggregate.add_argument("--out", type=Path, required=True)

    safety = commands.add_parser("assert-safe")
    safety.add_argument("--artifact-dir", type=Path, required=True)
    safety.add_argument("--samples", type=Path, required=True)
    safety.add_argument("--secret-file", type=Path, action="append", default=[])
    safety.add_argument("--seed-pool", type=Path, action="append", default=[])
    safety.add_argument("--out", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "manifest":
            create_manifest(arguments)
        elif arguments.command == "finish":
            finish_manifest(arguments)
        elif arguments.command == "sample-metrics":
            sample_metrics(arguments)
        elif arguments.command == "summarize":
            summarize(arguments)
        elif arguments.command == "aggregate-sweep":
            aggregate_sweep(arguments)
        elif arguments.command == "assert-safe":
            assert_safe(arguments)
    except (EvidenceError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"load-test evidence error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
