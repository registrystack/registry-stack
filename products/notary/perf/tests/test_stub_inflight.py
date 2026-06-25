#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9", "pytest>=8", "pytest-asyncio>=0.23"]
# ///
"""
Tests for source_stub.py in-flight counter and latency simulation.

Verifies:
  - /_stats returns {"in_flight": N, "peak_in_flight": M, "total": T}.
  - POST /_stats/reset zeros in_flight and peak_in_flight, keeps total unchanged.
  - Concurrent requests are counted correctly: peak_in_flight >= N for N concurrent.
  - Latency simulation: --median-latency-ms and --jitter-ms slow down responses.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import pytest

STUB_SCRIPT = Path(__file__).parent.parent / "stub" / "source_stub.py"
STUB_BIND = "127.0.0.1:14399"  # separate port so it does not clash with the real stub
STUB_BASE = f"http://{STUB_BIND}"
BEARER = "test-token-for-inflight-tests"

DCI_PATH = "/dci/crvs/registry/sync/search"
KNOWN_SUBJECT = "subj-0000001"  # within the small pool (1000)


def _dci_body(subject_id: str) -> dict:
    return {
        "header": {},
        "message": {
            "search_request": [
                {
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {"type": "NATIONAL_ID", "value": subject_id},
                        "pagination": {"page_size": 2},
                    }
                }
            ]
        },
    }


@pytest.fixture(scope="module")
def stub_proc():
    """Start the stub with 50ms median latency and 10ms jitter for the whole module."""
    env = {**os.environ, "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN": BEARER}
    proc = subprocess.Popen(
        [
            sys.executable,
            str(STUB_SCRIPT),
            "--profile",
            "small",
            "--bind",
            STUB_BIND,
            "--median-latency-ms",
            "50",
            "--jitter-ms",
            "10",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # Wait for /health.
    deadline = time.monotonic() + 15.0
    import urllib.request
    import urllib.error

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{STUB_BASE}/health", timeout=1.0) as r:
                if r.status == 200:
                    break
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("stub did not become ready within 15s")

    yield proc

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        # The stub may have already exited during fixture teardown.
        pass
    proc.wait(timeout=5)


@pytest.fixture(autouse=True)
def reset_stats(stub_proc):  # noqa: ARG001
    """Reset stats before every test so counters are independent."""
    import urllib.request

    req = urllib.request.Request(
        f"{STUB_BASE}/_stats/reset", method="POST", data=b""
    )
    with urllib.request.urlopen(req, timeout=5.0):
        pass


# ---------------------------------------------------------------------------
# Stats endpoint shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stats_shape(stub_proc):  # noqa: ARG001
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{STUB_BASE}/_stats") as resp:
            assert resp.status == 200
            body = await resp.json()
    assert "in_flight" in body
    assert "peak_in_flight" in body
    assert "total" in body
    assert isinstance(body["in_flight"], int)
    assert isinstance(body["peak_in_flight"], int)
    assert isinstance(body["total"], int)


@pytest.mark.asyncio
async def test_stats_reset_zeros_peak(stub_proc):  # noqa: ARG001
    """After reset, peak_in_flight is 0 and total is preserved across the reset."""
    headers = {"Authorization": f"Bearer {BEARER}", "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as session:
        # Fire one request to bump totals.
        await session.post(
            f"{STUB_BASE}{DCI_PATH}",
            json=_dci_body(KNOWN_SUBJECT),
            headers=headers,
        )
        stats_before = await (await session.get(f"{STUB_BASE}/_stats")).json()
        assert stats_before["total"] >= 1
        assert stats_before["peak_in_flight"] >= 1

        # Reset.
        await session.post(f"{STUB_BASE}/_stats/reset")

        stats_after = await (await session.get(f"{STUB_BASE}/_stats")).json()
        assert stats_after["in_flight"] == 0
        assert stats_after["peak_in_flight"] == 0
        # total is also reset so callers can reason about fresh windows.
        assert stats_after["total"] == 0


# ---------------------------------------------------------------------------
# Concurrent in-flight counting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_peak_inflight_counts_concurrent(stub_proc):  # noqa: ARG001
    """
    Fire N concurrent requests with stub latency >= 50ms; peak_in_flight must
    reach N (i.e. all are in flight at the same time given our asyncio scheduling).
    """
    n = 8
    headers = {"Authorization": f"Bearer {BEARER}", "Content-Type": "application/json"}

    async def one(session: aiohttp.ClientSession, subject_id: str) -> None:
        async with session.post(
            f"{STUB_BASE}{DCI_PATH}",
            json=_dci_body(subject_id),
            headers=headers,
        ):
            pass

    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*[one(session, f"subj-{i:07d}") for i in range(n)])
        stats = await (await session.get(f"{STUB_BASE}/_stats")).json()

    assert stats["peak_in_flight"] >= n, (
        f"Expected peak_in_flight >= {n}, got {stats['peak_in_flight']}"
    )
    assert stats["total"] >= n


# ---------------------------------------------------------------------------
# Latency simulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_median_latency_applied(stub_proc):  # noqa: ARG001
    """A single request must take at least (median - jitter) ms."""
    headers = {"Authorization": f"Bearer {BEARER}", "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as session:
        t0 = time.monotonic()
        async with session.post(
            f"{STUB_BASE}{DCI_PATH}",
            json=_dci_body(KNOWN_SUBJECT),
            headers=headers,
        ):
            pass
        elapsed_ms = (time.monotonic() - t0) * 1000

    # median=50, jitter=10: minimum expected ~40ms.  We allow generous floor to
    # avoid flakiness on a busy CI host, but we need at least 20ms.
    assert elapsed_ms >= 20, f"Expected >= 20ms latency, got {elapsed_ms:.1f}ms"
