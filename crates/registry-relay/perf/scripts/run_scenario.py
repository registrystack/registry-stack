#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "psutil",
# ]
# ///
"""
Orchestrator for a single Registry Relay perf run.

Optionally starts the release binary, waits for /ready, samples the server
process (CPU, RSS, FDs, threads) while k6 runs the given scenario, writes a
proc-stats JSON, and exits with k6's exit code.

Usage:
    # Attach to a running server:
    uv run perf/scripts/run_scenario.py \\
        --scenario perf/k6/cached_304.js \\
        --server-pid 12345

    # Start and stop the server ourselves:
    uv run perf/scripts/run_scenario.py \\
        --scenario perf/k6/cached_304.js \\
        --start-server \\
        --config perf/config/medium.yaml \\
        --env-file target/perf/perf.env
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

# ---- macOS FD note -----------------------------------------------------------
# psutil.Process.num_fds() is Linux-only and raises AttributeError on macOS.
# On macOS we record None and note it in the summary. This is simpler and
# more honest than approximating via open_files() + connections(), which
# double-counts and misses kernel-side descriptors.

READY_POLL_INTERVAL_SEC = 0.2
READY_TIMEOUT_SEC = 30.0
SIGTERM_WAIT_SEC = 5.0


# ---- sampler -----------------------------------------------------------------

def _sample_process(proc: psutil.Process) -> dict | None:
    """Take one sample from proc. Returns None if the process is gone."""
    try:
        with proc.oneshot():
            cpu = proc.cpu_percent(interval=None)
            mem = proc.memory_info()
            num_threads = proc.num_threads()
            try:
                open_fds = proc.num_fds()
            except AttributeError:
                # macOS: num_fds() is not available; record None.
                open_fds = None
    except psutil.NoSuchProcess:
        return None

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "rss_bytes": mem.rss,
        "open_fds": open_fds,
        "num_threads": num_threads,
    }


def run_sampler(
    proc: psutil.Process,
    interval: float,
    stop_event: threading.Event,
    samples: list,
) -> None:
    """Thread target. Appends samples until stop_event is set or process exits."""
    # Warm up cpu_percent so the first real reading is not 0.0.
    try:
        proc.cpu_percent(interval=None)
    except psutil.NoSuchProcess:
        return

    while not stop_event.is_set():
        sample = _sample_process(proc)
        if sample is None:
            # Process exited; stop sampling.
            break
        samples.append(sample)
        stop_event.wait(timeout=interval)


# ---- proc stats JSON ---------------------------------------------------------

def _summarise_samples(samples: list, interval: float) -> dict:
    if not samples:
        return {
            "sample_count": 0,
            "sample_interval_sec": interval,
            "peak_rss_bytes": None,
            "mean_cpu_percent": None,
            "max_open_fds": None,
            "open_fds_note": "no samples collected",
        }

    rss_values = [s["rss_bytes"] for s in samples]
    cpu_values = [s["cpu_percent"] for s in samples]
    fd_values = [s["open_fds"] for s in samples if s["open_fds"] is not None]

    fd_note = None
    if not fd_values:
        fd_note = "open_fds not available on this platform (macOS); recorded None"

    return {
        "sample_count": len(samples),
        "sample_interval_sec": interval,
        "peak_rss_bytes": max(rss_values),
        "mean_cpu_percent": sum(cpu_values) / len(cpu_values),
        "max_open_fds": max(fd_values) if fd_values else None,
        "open_fds_note": fd_note,
    }


def write_proc_stats(
    out_dir: Path,
    scenario_stem: str,
    samples: list,
    interval: float,
) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{scenario_stem}-{ts}.proc.json"
    out_path = out_dir / filename

    payload = {
        "summary": _summarise_samples(samples, interval),
        "samples": samples,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


# ---- server lifecycle --------------------------------------------------------

def wait_for_ready(base_url: str) -> None:
    """Poll <base_url>/ready until 200 or timeout."""
    import urllib.request

    url = base_url.rstrip("/") + "/ready"
    deadline = time.monotonic() + READY_TIMEOUT_SEC
    last_err = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_err = exc
        time.sleep(READY_POLL_INTERVAL_SEC)

    raise RuntimeError(
        f"Server did not become ready within {READY_TIMEOUT_SEC}s at {url}. "
        f"Last error: {last_err}"
    )


def start_server(binary: Path, config: Path, env_file: Path | None) -> subprocess.Popen:
    """Spawn the release binary. Returns the Popen object."""
    cmd = [str(binary), "--config", str(config)]
    env = os.environ.copy()
    if env_file is not None:
        env.update(_load_env_file(env_file))
    print(f"Starting server: {' '.join(cmd)}", flush=True)
    # stdout/stderr inherited so server logs appear in the terminal.
    proc = subprocess.Popen(cmd, env=env)
    return proc


def stop_server(proc: subprocess.Popen) -> None:
    """Send SIGTERM; wait up to SIGTERM_WAIT_SEC; then SIGKILL."""
    if proc.poll() is not None:
        return
    print("Stopping server (SIGTERM)...", flush=True)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=SIGTERM_WAIT_SEC)
    except subprocess.TimeoutExpired:
        print("Server did not exit after SIGTERM; sending SIGKILL.", flush=True)
        proc.kill()
        proc.wait()


# ---- env-file loading --------------------------------------------------------

def _load_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file. Skips blank lines and comments."""
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


# ---- k6 runner ---------------------------------------------------------------

def run_k6(scenario: Path, env_file: Path | None) -> int:
    """Run k6 with the given scenario. Returns k6's exit code."""
    cmd = ["k6", "run", str(scenario)]
    env = os.environ.copy()
    # Include p(99) in the k6 summary JSON; env-file values can override this.
    env["K6_SUMMARY_TREND_STATS"] = "min,med,avg,max,p(90),p(95),p(99)"
    if env_file is not None:
        env.update(_load_env_file(env_file))
        print(f"Loaded env from: {env_file}", flush=True)
    print(f"Running: {' '.join(cmd)}", flush=True)
    # Inherit stdin/stdout/stderr so k6 output streams live to the console.
    result = subprocess.run(cmd, env=env)
    return result.returncode


# ---- argument parsing --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a k6 scenario against Registry Relay, sampling the server process "
            "and writing proc-stats to the output directory."
        )
    )

    parser.add_argument(
        "--scenario",
        required=True,
        type=Path,
        metavar="PATH",
        help="Path to the .js k6 scenario file.",
    )

    server_group = parser.add_mutually_exclusive_group()
    server_group.add_argument(
        "--server-pid",
        type=int,
        metavar="PID",
        help="PID of an already-running Registry Relay process to sample.",
    )
    server_group.add_argument(
        "--start-server",
        action="store_true",
        help=(
            "Start the release binary ourselves before the run. "
            "Requires --config."
        ),
    )

    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="Server config file (required when --start-server is used).",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help="Env file passed through to the server and to k6.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("target/perf/reports"),
        metavar="PATH",
        help="Directory for report artifacts (default: target/perf/reports/).",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Process-stats sample interval in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:18080",
        metavar="URL",
        help=(
            "Server base URL used for /ready polling when --start-server is "
            "given (default: http://127.0.0.1:18080)."
        ),
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip writing the proc-stats JSON (useful when the scenario writes its own).",
    )

    return parser


# ---- main --------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validate --start-server requirements.
    if args.start_server and args.config is None:
        parser.error("--start-server requires --config.")

    scenario: Path = args.scenario.resolve()
    if not scenario.exists():
        print(f"Error: scenario not found: {scenario}", file=sys.stderr)
        sys.exit(1)

    out_dir: Path = args.out_dir
    server_proc: subprocess.Popen | None = None
    psutil_proc: psutil.Process | None = None
    samples: list = []
    stop_event = threading.Event()
    sampler_thread: threading.Thread | None = None
    k6_exit_code = 0

    try:
        # Resolve the server process to sample.
        if args.start_server:
            binary = Path("target/release/registry-relay")
            if not binary.exists():
                print(
                    f"Error: release binary not found at {binary}. "
                    "Run `cargo build --release` first.",
                    file=sys.stderr,
                )
                sys.exit(1)
            server_proc = start_server(binary, args.config, args.env_file)
            base_url: str = args.base_url
            # Pull BASE_URL from env file if set there.
            if args.env_file is not None:
                env_vars = _load_env_file(args.env_file)
                base_url = env_vars.get("REGISTRY_RELAY_BASE_URL") or base_url
            print(f"Waiting for server at {base_url}/ready ...", flush=True)
            wait_for_ready(base_url)
            if server_proc.poll() is not None:
                raise RuntimeError(
                    "Started server exited before the scenario began. "
                    f"Exit code: {server_proc.returncode}"
                )
            print("Server is ready.", flush=True)
            psutil_proc = psutil.Process(server_proc.pid)

        elif args.server_pid is not None:
            psutil_proc = psutil.Process(args.server_pid)
            print(f"Attaching sampler to PID {args.server_pid}.", flush=True)

        else:
            print(
                "No server target specified. k6 will run without process sampling.",
                flush=True,
            )

        # Create output directory only when we are about to run (not on --help).
        out_dir.mkdir(parents=True, exist_ok=True)

        # Start the sampler thread if we have a process to watch.
        if psutil_proc is not None:
            sampler_thread = threading.Thread(
                target=run_sampler,
                args=(psutil_proc, args.sample_interval, stop_event, samples),
                daemon=True,
                name="proc-sampler",
            )
            sampler_thread.start()

        # Run k6.
        k6_exit_code = run_k6(scenario, args.env_file)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    finally:
        # Stop sampler.
        stop_event.set()
        if sampler_thread is not None:
            sampler_thread.join(timeout=args.sample_interval + 1.0)

        # Stop server if we started it.
        if server_proc is not None:
            stop_server(server_proc)

        # Write proc stats unless suppressed or we have no samples at all.
        if not args.no_summary and (samples or psutil_proc is not None):
            try:
                stats_path = write_proc_stats(
                    out_dir,
                    scenario.stem,
                    samples,
                    args.sample_interval,
                )
                print(f"Proc stats written: {stats_path}", flush=True)
            except Exception as exc:
                print(f"Warning: could not write proc stats: {exc}", file=sys.stderr)

    sys.exit(k6_exit_code)


if __name__ == "__main__":
    main()
