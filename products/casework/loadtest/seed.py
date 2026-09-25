#!/usr/bin/env python3
"""Seed the load-test Casework runtime with synthetic open review requests.

Drives the public producer contract directly (POST /v1/review-requests with an
idempotency key per request) as the synthetic producer client, then lists the
Staff inbox to learn the task opened for each request, because an accepted
request reports no task identifier. The oldest tasks become the read pool the
k6 profiles never mutate, so inbox pages stay stable across runs; the rest
become the flow pool that decision flows consume in order.

Every generated value is synthetic; nothing here resembles a real case,
person, or identifier. Pool files hold record identifiers and stay under the
ignored, owner-only .run directory. seed-summary.json holds integer counts only.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


HEADER_REFRESH_SECONDS = 210
PRODUCER_CLIENT = "loadtest-producer"
STAFF_CLIENT = "loadtest-staff"
MINIMUM_READ_POOL = 100
LIST_LIMIT = 100


class SeedError(RuntimeError):
    pass


class DevTokenSource:
    """Fresh owner-only headers acquired through the stock dev lifecycle."""

    def __init__(self, helper: Path, caseworkctl: Path, project: Path, client_id: str) -> None:
        self._helper = helper
        self._caseworkctl = caseworkctl
        self._project = project
        self._client_id = client_id
        self._lock = threading.Lock()
        self._authorization = ""
        self._expires_at = 0.0

    def authorization(self) -> str:
        with self._lock:
            if time.monotonic() >= self._expires_at:
                self._refresh()
            return self._authorization

    def _refresh(self) -> None:
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(self._helper),
                    "header",
                    "--caseworkctl",
                    str(self._caseworkctl),
                    "--project",
                    str(self._project),
                    "--client",
                    self._client_id,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            path = Path(result.stdout.strip())
            if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise SeedError("caseworkctl dev token header is not an owner-only regular file")
            value = path.read_text(encoding="ascii").strip()
        except (OSError, subprocess.SubprocessError, UnicodeError) as error:
            raise SeedError("could not acquire a fresh caseworkctl dev token") from error
        if not value.startswith("Authorization: Bearer ") or value.count(".") != 2:
            raise SeedError("caseworkctl dev token header is malformed")
        self._authorization = value.split(": ", 1)[1]
        self._expires_at = time.monotonic() + HEADER_REFRESH_SECONDS


class Client:
    """One keep-alive loopback connection per worker thread."""

    def __init__(self, origin: str) -> None:
        parsed = urlparse(origin)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise SeedError("Casework origin must be a loopback HTTP origin")
        self._host = parsed.hostname
        self._port = parsed.port
        self._local = threading.local()

    def _connection(self) -> http.client.HTTPConnection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = http.client.HTTPConnection(self._host, self._port, timeout=60)
            self._local.connection = connection
        return connection

    def request(
        self, method: str, path: str, headers: dict[str, str], body: bytes | None, label: str
    ) -> tuple[int, Any]:
        for attempt in range(2):
            connection = self._connection()
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read()
                break
            except (http.client.HTTPException, OSError) as error:
                connection.close()
                self._local.connection = None
                if attempt == 1:
                    raise SeedError(f"{label} failed before a response: {type(error).__name__}") from error
        document = json.loads(payload) if payload else None
        return response.status, document


def subject_digest(nonce: str, index: int) -> str:
    return "sha256:" + hashlib.sha256(f"casework-loadtest/{nonce}/{index}".encode("ascii")).hexdigest()


def create_body(nonce: str, index: int) -> bytes:
    reference = f"lt-{nonce}-{index:07d}"
    return json.dumps(
        {
            "kind": "decision",
            "subject": {
                "source": "standalone",
                "type": "batch",
                "id": reference,
                "version": "1",
                "digest": subject_digest(nonce, index),
            },
            "requesterReference": reference,
            "context": {
                "strategy": "submitted",
                "snapshot": {
                    "reference": reference,
                    "summary": f"Synthetic load-test batch {index:07d}",
                },
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def create_requests(
    client: Client, tokens: DevTokenSource, count: int, workers: int, nonce: str
) -> set[str]:
    request_ids: list[str] = [""] * count
    started = time.monotonic()
    done = 0
    lock = threading.Lock()

    def run(index: int) -> None:
        nonlocal done
        status, document = client.request(
            "POST",
            "/v1/review-requests",
            {
                "Authorization": tokens.authorization(),
                "Registry-Casework-Profile": "requester",
                "Content-Type": "application/json",
                "Idempotency-Key": f"lt-seed-{nonce}-{index:07d}",
            },
            create_body(nonce, index),
            "create review request",
        )
        if status != 201 or not isinstance(document, dict) or not isinstance(document.get("requestId"), str):
            raise SeedError(f"create review request returned HTTP {status}")
        request_ids[index] = document["requestId"]
        with lock:
            done += 1
            if done % 500 == 0 or done == count:
                elapsed = time.monotonic() - started
                rate = done / elapsed if elapsed > 0 else 0.0
                print(f"  review requests: {done}/{count} ({rate:.0f} requests/s)", flush=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for outcome in list(pool.map(run, range(count))):
            _ = outcome
    if any(not value for value in request_ids) or len(set(request_ids)) != count:
        raise SeedError("review request creation left requests without distinct identifiers")
    return set(request_ids)


def staff_tasks(client: Client, tokens: DevTokenSource, wanted: set[str]) -> list[tuple[str, str]]:
    """Every open first-stage task for the seeded requests, in inbox order."""
    tasks: list[tuple[str, str]] = []
    cursor: str | None = None
    pages = 0
    while True:
        path = f"/v1/review-tasks?queue=decisions&limit={LIST_LIMIT}"
        if cursor:
            path += f"&cursor={cursor}"
        status, document = client.request(
            "GET",
            path,
            {"Authorization": tokens.authorization(), "Registry-Casework-Profile": "staff"},
            None,
            "list review tasks",
        )
        if status != 200 or not isinstance(document, dict) or not isinstance(document.get("items"), list):
            raise SeedError(f"list review tasks returned HTTP {status}")
        pages += 1
        for item in document["items"]:
            if (
                isinstance(item, dict)
                and item.get("requestId") in wanted
                and item.get("state") == "open"
                and item.get("revision") == 1
                and isinstance(item.get("taskId"), str)
            ):
                tasks.append((item["taskId"], item["requestId"]))
        next_cursor = document.get("nextCursor")
        if not next_cursor:
            break
        if next_cursor == cursor:
            raise SeedError("the Staff inbox returned the same continuation twice")
        cursor = str(next_cursor)
    print(f"  listed {pages} Staff inbox pages", flush=True)
    return tasks


def write_private(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the load-test Casework runtime")
    parser.add_argument("--count", type=int, default=2000, help="open review requests to create")
    parser.add_argument(
        "--read-count",
        type=int,
        help="oldest tasks kept for reads and never mutated (default: half, at most 500)",
    )
    parser.add_argument("--workers", type=int, default=8, help="concurrent create requests")
    parser.add_argument("--run-dir", type=Path, default=Path(__file__).resolve().parent / ".run")
    arguments = parser.parse_args()

    read_count = arguments.read_count if arguments.read_count is not None else min(500, arguments.count // 2)
    if read_count < MINIMUM_READ_POOL or arguments.count - read_count < 1:
        print(
            f"--count must leave at least {MINIMUM_READ_POOL} read-pool tasks and one flow-pool task",
            file=sys.stderr,
        )
        return 2
    if not 1 <= arguments.workers <= 32:
        print("--workers must be between 1 and 32", file=sys.stderr)
        return 2
    env_path = arguments.run_dir / "env.json"
    if not env_path.is_file():
        print(f"no load-test environment at {env_path}; run up.sh first", file=sys.stderr)
        return 2
    seed_dir = arguments.run_dir / "seed"
    if seed_dir.exists() or seed_dir.is_symlink():
        print(f"seed evidence already exists at {seed_dir}; start a fresh environment to reseed", file=sys.stderr)
        return 2
    repository = Path(__file__).resolve().parents[3]
    helper = Path(__file__).resolve().parent / "support/loadenv.py"
    try:
        described = subprocess.run(
            [sys.executable, str(helper), "describe", "--root", str(arguments.run_dir), "--repository", str(repository)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
    except subprocess.CalledProcessError as error:
        print(error.stderr.strip() or "load-test environment is not usable", file=sys.stderr)
        return 2
    casework_url, caseworkctl, project = described[:3]
    runtime_library_path = described[3] if len(described) > 3 else ""
    if runtime_library_path:
        existing = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH")
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = (
            f"{runtime_library_path}:{existing}" if existing else runtime_library_path
        )
    producer = DevTokenSource(helper, Path(caseworkctl), Path(project), PRODUCER_CLIENT)
    staff = DevTokenSource(helper, Path(caseworkctl), Path(project), STAFF_CLIENT)
    nonce = f"{int(time.time())}-{os.getpid()}"

    print(f"Seeding {arguments.count} open review requests ({read_count} kept for reads)")
    started = time.monotonic()
    try:
        client = Client(casework_url)
        request_ids = create_requests(client, producer, arguments.count, arguments.workers, nonce)
        created_ms = int((time.monotonic() - started) * 1000)
        tasks = staff_tasks(client, staff, request_ids)
    except (SeedError, ValueError) as error:
        print(f"seeding failed: {error}", file=sys.stderr)
        return 1
    if len(tasks) != arguments.count:
        print(
            f"seeding failed: the Staff inbox showed {len(tasks)} of {arguments.count} seeded tasks",
            file=sys.stderr,
        )
        return 1

    os.umask(0o077)
    seed_dir.mkdir(mode=0o700)
    read_pool = tasks[:read_count]
    flow_pool = tasks[read_count:]
    write_private(seed_dir / "read-tasks.txt", "".join(f"{task} {request}\n" for task, request in read_pool))
    write_private(seed_dir / "flow-tasks.txt", "".join(f"{task} {request}\n" for task, request in flow_pool))
    write_private(seed_dir / "flow-offset", "0\n")
    write_private(
        seed_dir / "seed-summary.json",
        json.dumps(
            {
                "reviewRequests": arguments.count,
                "readPoolTasks": len(read_pool),
                "flowPoolTasks": len(flow_pool),
                "createWorkers": arguments.workers,
                "createMilliseconds": created_ms,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    print(f"Seeded and recorded task pools under {seed_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
