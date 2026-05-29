#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["psutil"]
# ///
"""
Orchestrator for a single registry-notary perf run.

Starts the source stub and the notary binary, waits until both are
responsive, runs the requested k6 scenario while sampling the notary
process, then tears both down cleanly.

Notary has no /ready endpoint, so readiness is probed with an
authenticated GET /claims (the harness must already know the bearer token,
which it reads from the env file).

Usage:
    uv run perf/scripts/run_scenario.py \\
        --scenario perf/k6/evaluate_extract.js \\
        --notary-config perf/config/medium.yaml \\
        --stub-profile medium \\
        --env-file target/perf/perf.env
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import typing
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psutil

READY_POLL_INTERVAL_SEC = 0.2
READY_TIMEOUT_SEC = 30.0
SIGTERM_WAIT_SEC = 5.0
SAMPLE_INTERVAL_SEC = 1.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sample_process(proc: psutil.Process) -> dict | None:
    try:
        with proc.oneshot():
            cpu = proc.cpu_percent(interval=None)
            mem = proc.memory_info()
            num_threads = proc.num_threads()
            try:
                open_fds = proc.num_fds()
            except AttributeError:
                # macOS: num_fds() is unavailable.
                open_fds = None
    except psutil.NoSuchProcess:
        return None
    return {
        "ts": _now_iso(),
        "cpu_percent": cpu,
        "rss_bytes": mem.rss,
        "open_fds": open_fds,
        "num_threads": num_threads,
    }


def _run_sampler(
    proc: psutil.Process,
    interval: float,
    stop_event: threading.Event,
    samples: list,
) -> None:
    try:
        proc.cpu_percent(interval=None)
    except psutil.NoSuchProcess:
        return
    while not stop_event.is_set():
        sample = _sample_process(proc)
        if sample is None:
            break
        samples.append(sample)
        stop_event.wait(timeout=interval)


def _load_env_file(env_file: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file. No shell quoting; no comments."""
    env: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        env[key.strip()] = value
    return env


def _spawn(
    cmd: list[str], env: dict[str, str], log_path: Path
) -> tuple[subprocess.Popen, typing.IO[str]]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("a", encoding="utf-8")
    log_file.write(f"--- spawn {_now_iso()} cmd={cmd!r}\n")
    log_file.flush()
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # so SIGTERM does not propagate to the runner
    )
    return proc, log_file


def _wait_for(url: str, headers: dict[str, str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, headers=headers)
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=1.0) as response:
                if 200 <= response.status < 300:
                    return True
                # 3xx/5xx: keep polling until we get a clean 2xx or time out.
                last_err = RuntimeError(f"unexpected status {response.status}")
        except urllib.error.HTTPError as err:
            # urlopen raises HTTPError for 4xx and 5xx. A 4xx means the service
            # is up and responding (we just lack the right credentials for the
            # probe), which is enough to declare it ready.
            if 400 <= err.code < 500:
                return True
            last_err = err
        except (urllib.error.URLError, OSError) as err:
            last_err = err
        time.sleep(READY_POLL_INTERVAL_SEC)
    print(f"readiness probe failed for {url}: {last_err}", file=sys.stderr)
    return False


def _terminate(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=SIGTERM_WAIT_SEC)
        return
    except subprocess.TimeoutExpired:
        pass
    print(f"{name} did not exit on SIGTERM; sending SIGKILL", file=sys.stderr)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        return
    proc.wait(timeout=SIGTERM_WAIT_SEC)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, help="Path to a k6 scenario file.")
    parser.add_argument(
        "--notary-config",
        default="perf/config/medium.yaml",
        help="Notary config (default: perf/config/medium.yaml).",
    )
    parser.add_argument(
        "--notary-binary",
        default="target/release/registry-notary-bin",
        help="Built notary binary (default: target/release/registry-notary-bin).",
    )
    parser.add_argument(
        "--stub-profile",
        choices=["small", "medium"],
        default="medium",
        help="Source stub profile (default: medium).",
    )
    parser.add_argument(
        "--stub-script",
        default="perf/stub/source_stub.py",
        help="Source stub script path.",
    )
    parser.add_argument(
        "--env-file",
        default="target/perf/perf.env",
        help="Env file with credentials and routing defaults.",
    )
    parser.add_argument(
        "--reports-dir",
        default="target/perf/reports",
        help="Directory for scenario logs and proc-stats output.",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=SAMPLE_INTERVAL_SEC,
        help=f"Process-sample interval in seconds (default: {SAMPLE_INTERVAL_SEC}).",
    )
    parser.add_argument(
        "--k6-binary",
        default="k6",
        help="k6 executable (default: k6 on PATH).",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if not env_path.exists():
        print(f"missing env file: {env_path}", file=sys.stderr)
        return 2
    env_overrides = _load_env_file(env_path)
    env = {**os.environ, **env_overrides}

    bearer = env_overrides.get("REGISTRY_NOTARY_BEARER_TOKEN")
    if not bearer:
        print("REGISTRY_NOTARY_BEARER_TOKEN missing from env file", file=sys.stderr)
        return 2
    base_url = env_overrides.get("REGISTRY_NOTARY_BASE_URL", "http://127.0.0.1:14255")
    stub_bind = env_overrides.get("EVIDENCE_SOURCE_STUB_BIND", "127.0.0.1:14256")

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    Path("target/perf").mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scenario_name = Path(args.scenario).stem
    stub_log = reports_dir / f"{scenario_name}-{timestamp}.stub.log"
    notary_log = reports_dir / f"{scenario_name}-{timestamp}.notary.log"
    k6_log = reports_dir / f"{scenario_name}-{timestamp}.k6.log"
    proc_stats_path = reports_dir / f"{scenario_name}-{timestamp}.proc-stats.json"

    print(f"[{_now_iso()}] starting source stub: {stub_bind} profile={args.stub_profile}")
    stub_proc, stub_log_file = _spawn(
        ["uv", "run", args.stub_script, "--profile", args.stub_profile, "--bind", stub_bind],
        env=env,
        log_path=stub_log,
    )
    notary_proc: subprocess.Popen | None = None
    notary_log_file: typing.IO[str] | None = None

    try:
        if not _wait_for(f"http://{stub_bind}/health", headers={}, timeout=READY_TIMEOUT_SEC):
            print("source stub failed to come up; aborting", file=sys.stderr)
            return 3

        print(f"[{_now_iso()}] starting notary: {args.notary_binary} --config {args.notary_config}")
        notary_proc, notary_log_file = _spawn(
            [args.notary_binary, "--config", args.notary_config],
            env=env,
            log_path=notary_log,
        )

        if not _wait_for(
            f"{base_url}/claims",
            headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
            timeout=READY_TIMEOUT_SEC,
        ):
            print("notary failed to become ready; aborting", file=sys.stderr)
            return 3

        # Begin sampling notary.
        samples: list = []
        stop_event = threading.Event()
        sampler_proc = psutil.Process(notary_proc.pid)
        sampler_thread = threading.Thread(
            target=_run_sampler,
            args=(sampler_proc, args.sample_interval, stop_event, samples),
            daemon=True,
        )
        sampler_thread.start()

        print(f"[{_now_iso()}] running k6 scenario: {args.scenario}")
        with k6_log.open("a", encoding="utf-8") as k6_log_file:
            k6_log_file.write(f"--- k6 start {_now_iso()} scenario={args.scenario}\n")
            k6_log_file.flush()
            k6_result = subprocess.run(
                [args.k6_binary, "run", args.scenario],
                env=env,
                stdout=k6_log_file,
                stderr=subprocess.STDOUT,
                check=False,
            )

        stop_event.set()
        sampler_thread.join(timeout=SIGTERM_WAIT_SEC)

        proc_stats_path.write_text(
            json.dumps(
                {
                    "scenario": args.scenario,
                    "notary_pid": notary_proc.pid,
                    "stub_bind": stub_bind,
                    "started_at": timestamp,
                    "platform": sys.platform,
                    "samples": samples,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"[{_now_iso()}] proc stats written: {proc_stats_path}")
        return k6_result.returncode
    finally:
        if notary_proc is not None:
            _terminate(notary_proc, "notary")
        if notary_log_file is not None:
            notary_log_file.close()
        _terminate(stub_proc, "stub")
        stub_log_file.close()


if __name__ == "__main__":
    sys.exit(main())
