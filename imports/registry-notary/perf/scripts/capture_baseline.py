#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["psutil"]
# ///
"""
Capture a Stage 0 performance baseline for registry-notary.

Runs the full scenario set (single-subject evaluate, batch_evaluate at
10/100/1000, politeness_concurrent) against the current binary and the source
stub, then reads the k6 JSON summary files from target/perf/results/ to
extract p50/p99 latency, throughput, and peak stub concurrency. Writes the
composite result to perf/baselines/<tag>.json.

Usage:
    uv run perf/scripts/capture_baseline.py \\
        --env-file target/perf/perf.env \\
        --tag pre-stage-1

Options:
    --env-file PATH         Env file with credentials (default: target/perf/perf.env).
    --tag NAME              Baseline tag written to filename and JSON (default: pre-stage-1).
    --notary-config PATH   Notary config (default: perf/config/medium.yaml).
    --notary-binary PATH   Built binary (default: target/release/registry-notary).
    --stub-profile NAME     Stub profile (default: small -- fast for baseline capture).
    --stub-latency-ms N     Median latency for the stub in ms (default: 0).
    --stub-jitter-ms N      Jitter for the stub in ms (default: 0).
    --duration S            k6 duration per scenario (default: 20s).
    --k6-binary PATH        k6 executable (default: k6).
    --skip-1000             Skip the batch_evaluate_1000 scenario (it expects 400 today).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

READY_POLL_INTERVAL = 0.2
READY_TIMEOUT = 30.0
SIGTERM_WAIT = 5.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        env[key.strip()] = value
    return env


def _wait_for(url: str, headers: dict[str, str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, headers=headers)
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=1.0) as resp:
                if 200 <= resp.status < 300:
                    return True
                last_err = RuntimeError(f"unexpected status {resp.status}")
        except urllib.error.HTTPError as err:
            if 400 <= err.code < 500:
                return True
            last_err = err
        except (urllib.error.URLError, OSError) as err:
            last_err = err
        time.sleep(READY_POLL_INTERVAL)
    print(f"readiness probe failed for {url}: {last_err}", file=sys.stderr)
    return False


def _spawn(cmd: list[str], env: dict[str, str], log_path: Path) -> tuple[subprocess.Popen, typing.IO[str]]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("a", encoding="utf-8")
    log_file.write(f"--- spawn {_now_iso()} cmd={cmd!r}\n")
    log_file.flush()
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return proc, log_file


def _terminate(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=SIGTERM_WAIT)
        return
    except subprocess.TimeoutExpired:
        pass
    print(f"{name} did not exit on SIGTERM; sending SIGKILL", file=sys.stderr)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait(timeout=SIGTERM_WAIT)


def _extract_metric(summary: dict, metric: str, stat: str) -> float | None:
    """Pull a single statistic from a k6 summary JSON."""
    try:
        return summary["metrics"][metric]["values"][stat]
    except (KeyError, TypeError):
        return None


def _read_result(results_dir: Path, scenario: str) -> dict | None:
    path = results_dir / f"{scenario}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as err:
        print(f"warning: could not read {path}: {err}", file=sys.stderr)
        return None


def _summarise_scenario(results_dir: Path, scenario: str) -> dict:
    """Return latency percentiles and throughput from a k6 result file.

    k6 computes med (p50), p(90), p(95), avg, min, max by default. p(99)
    requires explicit --summary-trend-stats configuration. We use med for
    the p50 slot and p(95) as the near-p99 proxy unless p(99) is present.
    """
    data = _read_result(results_dir, scenario)
    if data is None:
        return {"error": "result file missing"}
    duration_key = "http_req_duration"
    values = {}
    try:
        values = data["metrics"][duration_key]["values"]
    except (KeyError, TypeError):
        pass
    p50 = values.get("med") or values.get("p(50)")
    p99 = values.get("p(99)") or values.get("p(95)")
    return {
        "p50_ms": p50,
        "p99_ms": p99,
        "p95_ms": values.get("p(95)"),
        "avg_ms": values.get("avg"),
        "requests_per_sec": _extract_metric(data, "http_reqs", "rate"),
        "iterations": _extract_metric(data, "iterations", "count"),
        "check_pass_rate": _extract_metric(data, "checks", "rate"),
    }


def _stub_peak_inflight(stub_bind: str) -> int | None:
    try:
        with urllib.request.urlopen(f"http://{stub_bind}/_stats", timeout=3.0) as resp:
            body = json.loads(resp.read())
            return body.get("peak_in_flight")
    except Exception as err:  # noqa: BLE001
        print(f"warning: could not query stub /_stats: {err}", file=sys.stderr)
        return None


def _reset_stub(stub_bind: str) -> None:
    try:
        req = urllib.request.Request(
            f"http://{stub_bind}/_stats/reset", method="POST", data=b""
        )
        urllib.request.urlopen(req, timeout=3.0)
    except Exception as err:  # noqa: BLE001
        print(f"warning: could not reset stub /_stats: {err}", file=sys.stderr)


def _run_k6(
    k6_binary: str,
    scenario_path: str,
    env: dict[str, str],
    log_path: Path,
    extra_env: dict[str, str] | None = None,
) -> int:
    merged = {**env, **(extra_env or {})}
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"--- k6 start {_now_iso()} scenario={scenario_path}\n")
        log_file.flush()
        result = subprocess.run(
            [k6_binary, "run", scenario_path],
            env=merged,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default="target/perf/perf.env")
    parser.add_argument("--tag", default="pre-stage-1")
    parser.add_argument("--notary-config", default="perf/config/medium.yaml")
    parser.add_argument("--notary-binary", default="target/release/registry-notary")
    parser.add_argument("--stub-profile", default="small")
    parser.add_argument("--stub-latency-ms", type=float, default=0.0)
    parser.add_argument("--stub-jitter-ms", type=float, default=0.0)
    parser.add_argument("--duration", default="20s")
    parser.add_argument("--k6-binary", default="k6")
    parser.add_argument("--skip-1000", action="store_true")
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if not env_path.exists():
        print(f"missing env file: {env_path}", file=sys.stderr)
        return 2
    env_overrides = _load_env_file(env_path)
    # Subject count must match the stub profile so k6 does not cycle to unknown subjects.
    # small=1000, medium=100000. The env file default is 100000 (medium), so override.
    stub_subject_counts = {"small": "1000", "medium": "100000"}
    subject_count_override = stub_subject_counts.get(args.stub_profile, "1000")
    env = {
        **os.environ,
        **env_overrides,
        "REGISTRY_NOTARY_DURATION": args.duration,
        "REGISTRY_NOTARY_SUBJECT_COUNT": subject_count_override,
    }

    bearer = env_overrides.get("REGISTRY_NOTARY_BEARER_TOKEN", "")
    if not bearer:
        print("REGISTRY_NOTARY_BEARER_TOKEN missing from env file", file=sys.stderr)
        return 2

    base_url = env_overrides.get("REGISTRY_NOTARY_BASE_URL", "http://127.0.0.1:14255")
    stub_bind = env_overrides.get("EVIDENCE_SOURCE_STUB_BIND", "127.0.0.1:14256")

    results_dir = Path("target/perf/results")
    reports_dir = Path("target/perf/reports")
    baselines_dir = Path("perf/baselines")
    results_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    baselines_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    stub_cmd = [
        "uv", "run", "perf/stub/source_stub.py",
        "--profile", args.stub_profile,
        "--bind", stub_bind,
    ]
    if args.stub_latency_ms > 0:
        stub_cmd += ["--median-latency-ms", str(args.stub_latency_ms)]
    if args.stub_jitter_ms > 0:
        stub_cmd += ["--jitter-ms", str(args.stub_jitter_ms)]

    print(f"[{_now_iso()}] starting source stub: {stub_bind} profile={args.stub_profile}")
    stub_proc, stub_log_file = _spawn(
        stub_cmd, env=env, log_path=reports_dir / f"baseline-{timestamp}.stub.log"
    )
    notary_proc: subprocess.Popen | None = None
    notary_log_file: typing.IO[str] | None = None

    try:
        if not _wait_for(f"http://{stub_bind}/health", headers={}, timeout=READY_TIMEOUT):
            print("source stub failed to come up; aborting", file=sys.stderr)
            return 3

        print(f"[{_now_iso()}] starting notary: {args.notary_binary}")
        notary_proc, notary_log_file = _spawn(
            [args.notary_binary, "--config", args.notary_config],
            env=env,
            log_path=reports_dir / f"baseline-{timestamp}.notary.log",
        )
        if not _wait_for(f"{base_url}/ready", headers={}, timeout=READY_TIMEOUT):
            print("notary failed to become ready; aborting", file=sys.stderr)
            return 3

        if not _wait_for(
            f"{base_url}/v1/claims",
            headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
            timeout=READY_TIMEOUT,
        ):
            print("notary failed authenticated catalog probe; aborting", file=sys.stderr)
            return 3

        scenarios = [
            ("perf/k6/evaluate_extract.js", "evaluate_extract"),
            ("perf/k6/batch_evaluate_10.js", "batch_evaluate_10"),
            ("perf/k6/batch_evaluate_100.js", "batch_evaluate_100"),
            ("perf/k6/politeness_concurrent.js", "politeness_concurrent"),
        ]
        if not args.skip_1000:
            scenarios.append(("perf/k6/batch_evaluate_1000.js", "batch_evaluate_1000"))

        scenario_results: dict[str, dict] = {}

        for scenario_path, name in scenarios:
            print(f"[{_now_iso()}] running scenario: {name}")
            _reset_stub(stub_bind)
            log_path = reports_dir / f"baseline-{timestamp}-{name}.k6.log"
            rc = _run_k6(args.k6_binary, scenario_path, env, log_path)
            peak = _stub_peak_inflight(stub_bind)
            summary = _summarise_scenario(results_dir, name)
            summary["stub_peak_in_flight"] = peak
            summary["k6_exit_code"] = rc
            scenario_results[name] = summary
            status = "ok" if rc == 0 else f"k6 exit {rc}"
            print(
                f"  {name}: p50={summary.get('p50_ms')}ms p95={summary.get('p95_ms')}ms"
                f" rps={summary.get('requests_per_sec'):.1f}"
                f" peak_inflight={peak} [{status}]"
            )

        baseline = {
            "tag": args.tag,
            "captured_at": _now_iso(),
            "git_describe": _git_describe(),
            "stub_profile": args.stub_profile,
            "stub_latency_ms": args.stub_latency_ms,
            "stub_jitter_ms": args.stub_jitter_ms,
            "duration_per_scenario": args.duration,
            "scenarios": scenario_results,
        }

        baseline_path = baselines_dir / f"{args.tag}.json"
        baseline_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        print(f"\n[{_now_iso()}] baseline written: {baseline_path}")
        return 0

    finally:
        if notary_proc is not None:
            _terminate(notary_proc, "notary")
        if notary_log_file is not None:
            notary_log_file.close()
        _terminate(stub_proc, "stub")
        stub_log_file.close()


def _git_describe() -> str:
    try:
        return subprocess.check_output(
            ["git", "describe", "--always", "--dirty"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


if __name__ == "__main__":
    sys.exit(main())
