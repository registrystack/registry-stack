#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Perf report generator for Registry Relay.

Reads a k6 summary-export JSON and an optional proc-stats JSON from
run_scenario.py, then writes a markdown report under target/perf/reports/
(or a path you specify with --out).

Usage:
    uv run perf/scripts/report.py --k6-summary target/perf/reports/cached_304.json
    uv run perf/scripts/report.py \\
        --k6-summary target/perf/reports/cached_304.json \\
        --proc-stats target/perf/reports/cached_304-20250516T120000Z.proc.json \\
        --out /tmp/report.md
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---- helpers -----------------------------------------------------------------

def _safe(d: dict, *keys, default: object = "n/a") -> object:
    """Walk a nested dict by keys; return default on any missing key or None."""
    val: object = d
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k)
        if val is None:
            return default
    return val


def _to_float(val: object) -> float:
    """Coerce a _safe() result to float; raises ValueError/TypeError on bad input."""
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        return float(val)
    raise TypeError(f"cannot convert {type(val).__name__} to float")


def _to_int(val: object) -> int:
    """Coerce a _safe() result to int; raises ValueError/TypeError on bad input."""
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    if isinstance(val, str):
        return int(val)
    raise TypeError(f"cannot convert {type(val).__name__} to int")


def _run(*cmd) -> str:
    """Run a command and return stripped stdout, or 'unknown' on failure."""
    try:
        return subprocess.check_output(list(cmd), stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def _human_bytes(n) -> str:
    """Format bytes as a human-readable string."""
    if n is None or n == "n/a":
        return "n/a"
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}"
        n //= 1024
    return f"{n} TB"


def _fmt(val, default="n/a") -> str:
    """Convert a value to string, substituting default for None."""
    if val is None:
        return default
    return str(val)


# ---- k6 summary parsing ------------------------------------------------------

def _latency_table(metrics: dict) -> str:
    dur = metrics.get("http_req_duration", {}).get("values", {})
    p50  = _fmt(dur.get("med"))
    p90  = _fmt(dur.get("p(90)"))
    p95  = _fmt(dur.get("p(95)"))
    p99  = _fmt(dur.get("p(99)"))
    vmax = _fmt(dur.get("max"))

    def _ms(v: str) -> str:
        # k6 reports milliseconds already; round to two decimals for readability.
        try:
            return f"{float(v):.2f}"
        except (ValueError, TypeError):
            return v

    return (
        "| p50 | p90 | p95 | p99 | max |\n"
        "| --- | --- | --- | --- | --- |\n"
        f"| {_ms(p50)} | {_ms(p90)} | {_ms(p95)} | {_ms(p99)} | {_ms(vmax)} |"
    )


def _thresholds_section(metrics: dict) -> str:
    lines = []
    for metric_name, metric_data in metrics.items():
        thresholds = metric_data.get("thresholds")
        if not thresholds:
            continue
        for expr, result in thresholds.items():
            ok = result.get("ok", None)
            status = "PASS" if ok else "FAIL"
            lines.append(f"- `{metric_name}` / `{expr}`: {status}")
    if not lines:
        return "- No thresholds declared in this summary."
    return "\n".join(lines)


def _status_distribution(metrics: dict) -> str:
    """Build a status-count summary from http_req_duration tags or checks."""
    # k6 summary-export does not break out status codes directly unless the
    # scenario tags them. We report what we can find in http_req_failed and
    # note the limitation.
    failed_count = _safe(metrics, "http_req_failed", "values", "passes", default=None)
    passed_count = _safe(metrics, "http_req_failed", "values", "fails", default=None)

    lines = []
    if passed_count is not None:
        lines.append(f"- Non-failed requests: {passed_count}")
    if failed_count is not None:
        lines.append(f"- Failed requests (http_req_failed): {failed_count}")
    if not lines:
        lines.append("- Status distribution not available in summary (tag responses in k6 for per-code counts).")
    return "\n".join(lines)


# ---- report assembly ---------------------------------------------------------

def build_report(
    k6: dict,
    proc: dict | None,
    scenario_name: str,
    config_path: str,
    audit_sink: str,
    profile: str,
) -> str:
    metrics = k6.get("metrics", {})
    root = k6  # some fields live at the top level in summary-export format

    # Environment metadata.
    git_commit  = _run("git", "rev-parse", "HEAD")
    machine     = platform.platform()
    os_name     = platform.system()
    os_release  = platform.release()
    rust_ver    = _run("rustc", "--version")
    k6_ver      = _run("k6", "version")

    # Run metadata from k6 summary.
    # k6 summary-export puts state at root or in 'state' key depending on version.
    state = root.get("state", root)
    start_time  = _fmt(state.get("testRunDurationMs") and root.get("timestamp"))
    # k6 --summary-export: 'timestamp' is the end time; derive duration.
    duration_ms = state.get("testRunDurationMs")
    duration_str = f"{duration_ms / 1000:.1f}s" if isinstance(duration_ms, (int, float)) else "n/a"

    req_count   = _safe(metrics, "http_reqs", "values", "count", default="n/a")
    req_rate    = _safe(metrics, "http_reqs", "values", "rate", default="n/a")
    try:
        req_rate_str = f"{_to_float(req_rate):.2f} req/s"
    except (ValueError, TypeError):
        req_rate_str = "n/a"

    data_received_bytes = _safe(metrics, "data_received", "values", "count", default=None)
    data_total_human    = _human_bytes(data_received_bytes)
    mean_per_response   = "n/a"
    if data_received_bytes is not None and req_count not in ("n/a", 0, "0"):
        try:
            mean_per_response = _human_bytes(_to_int(data_received_bytes) // _to_int(req_count))
        except (TypeError, ValueError, ZeroDivisionError):
            pass

    # CPU / memory from proc stats.
    if proc is not None:
        summary = proc.get("summary", {})
        peak_rss     = summary.get("peak_rss_bytes")
        mean_cpu     = summary.get("mean_cpu_percent")
        max_fds      = summary.get("max_open_fds")
        fds_note     = summary.get("open_fds_note", "")
        peak_rss_str = f"{_human_bytes(peak_rss)} ({peak_rss} bytes)" if peak_rss else "n/a"
        # Normalize aggregate CPU% to per-core; assumes report is generated on the same host as the run.
        if isinstance(mean_cpu, float):
            cpu_count = os.cpu_count()
            if cpu_count:
                per_core = mean_cpu / cpu_count
                mean_cpu_str = f"{per_core:.2f}% per-core ({cpu_count} cores, aggregate {mean_cpu:.2f}%)"
            else:
                mean_cpu_str = f"{mean_cpu:.2f}% (aggregate, core count unavailable)"
        else:
            mean_cpu_str = "n/a"
        max_fds_str  = _fmt(max_fds) if max_fds is not None else "n/a (macOS sampler limit)"
        cpu_mem_section = f"""\
## CPU and memory
- Peak RSS: {peak_rss_str}
- Mean CPU: {mean_cpu_str}
- Max FDs: {max_fds_str}"""
        if fds_note:
            cpu_mem_section += f"\n- FD note: {fds_note}"
    else:
        cpu_mem_section = """\
## CPU and memory
- No proc-stats file provided. Re-run with --proc-stats to include CPU and memory data."""

    # Start time: prefer the timestamp field from k6 summary, else note unknown.
    ts_raw = root.get("timestamp")
    start_time_str = ts_raw if ts_raw else "n/a"

    sections = [
        f"# Perf Report: {scenario_name}",
        "",
        "## Environment",
        f"- Git commit: {git_commit}",
        "- Build profile: release",
        f"- Machine: {machine}",
        f"- OS: {os_name} {os_release}",
        f"- Rust version: {rust_ver}",
        f"- Server config: {config_path}",
        f"- Audit sink: {audit_sink}",
        f"- Profile: {profile if profile else '(not specified)'}",
        "- HTTP version: 1.1",
        "- Compression: identity",
        f"- Tool versions: k6 {k6_ver}, psutil n/a (stdlib report)",
        "",
        "## Run",
        f"- Start time: {start_time_str}",
        f"- Duration: {duration_str}",
        f"- Request count: {req_count}",
        f"- RPS: {req_rate_str}",
        "- Status distribution:",
        _status_distribution(metrics),
        "",
        "## Latency (ms)",
        _latency_table(metrics),
        "",
        "## Response bytes",
        f"- Total: {data_total_human}",
        f"- Mean per response: {mean_per_response}",
        "",
        cpu_mem_section,
        "",
        "## Thresholds",
        _thresholds_section(metrics),
        "",
        "## Notes",
        "- Review logs for panics, restarts, or audit sink errors.",
        "- Compare against a known baseline before declaring a regression or improvement.",
    ]

    return "\n".join(sections) + "\n"


# ---- argument parsing --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a markdown perf report from k6 and proc-stats JSON."
    )
    parser.add_argument(
        "--k6-summary",
        required=True,
        type=Path,
        metavar="PATH",
        help="Path to k6's --summary-export JSON.",
    )
    parser.add_argument(
        "--proc-stats",
        type=Path,
        metavar="PATH",
        help="Path to the proc-stats JSON from run_scenario.py (optional).",
    )
    parser.add_argument(
        "--scenario",
        metavar="NAME",
        help="Scenario name (defaults to the k6 summary filename stem).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        metavar="PATH",
        help="Output markdown path (default: <k6-summary>.md alongside the input).",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default="unknown",
        help="Server config used for this run (for the report metadata).",
    )
    parser.add_argument(
        "--audit-sink",
        metavar="LABEL",
        default="file",
        help="Audit sink label (default: file).",
    )
    parser.add_argument(
        "--profile",
        metavar="LABEL",
        default="",
        help="Profile label: small, medium, large, or empty (default: empty).",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        metavar="PATH",
        help="Optional baseline JSON for comparison (not yet implemented; no-op).",
    )
    return parser


# ---- main --------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    k6_path: Path = args.k6_summary.resolve()
    if not k6_path.exists():
        print(f"Error: k6 summary not found: {k6_path}", file=sys.stderr)
        sys.exit(1)

    try:
        k6_data = json.loads(k6_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error: could not parse k6 summary: {exc}", file=sys.stderr)
        sys.exit(1)

    proc_data: dict | None = None
    if args.proc_stats is not None:
        proc_path = args.proc_stats.resolve()
        if not proc_path.exists():
            print(f"Error: proc-stats file not found: {proc_path}", file=sys.stderr)
            sys.exit(1)
        try:
            proc_data = json.loads(proc_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Error: could not parse proc-stats: {exc}", file=sys.stderr)
            sys.exit(1)

    scenario_name = args.scenario or k6_path.stem

    out_path: Path = args.out if args.out is not None else k6_path.with_suffix(".md")

    if args.baseline is not None:
        print(
            "Note: --baseline is accepted but comparison is not yet implemented.",
            file=sys.stderr,
        )

    report = build_report(
        k6=k6_data,
        proc=proc_data,
        scenario_name=scenario_name,
        config_path=args.config,
        audit_sink=args.audit_sink,
        profile=args.profile,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"Report written: {out_path}", flush=True)


if __name__ == "__main__":
    main()
