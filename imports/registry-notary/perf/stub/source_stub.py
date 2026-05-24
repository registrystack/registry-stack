#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["aiohttp>=3.9"]
# ///
"""
Deterministic DCI source stub for registry-witness perf testing.

Witness's claim evaluation reads from an upstream over HTTP using the DCI
search protocol. To isolate witness latency from any specific upstream, this
stub serves the two DCI paths that the perf configs point at:

    POST /dci/crvs/registry/sync/search        (birth_date)
    POST /dci/fr/registry/sync/search          (farmed_land_size_hectares)

Records are derived from a fixed seed (42). The profile controls how many
distinct subject ids resolve to a record; subjects outside that pool produce
an empty response, which witness surfaces as SourceNotFound.

Request shape expected (witness constructs this in standalone.rs::dci_search_request_body):

    {
      "header": {...},
      "message": {
        "transaction_id": "...",
        "search_request": [{
          "search_criteria": {
            "query_type": "idtype-value",
            "query": {"type": "NATIONAL_ID", "value": "<subject_id>"},
            "pagination": {"page_size": N},
            ...
          },
          ...
        }]
      }
    }

Response shape returned (mirrors what witness parses at
standalone.rs::read_external_dci_http_one):

    {"message": {"search_response": [{"data": {"reg_records": [<row>]}}]}}

Only the records_path that the perf configs declare is populated; the rest of
the envelope is left empty / minimal.

Auth: Authorization: Bearer <EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN> is
required on every search path. Any other header returns 401.

Latency simulation:
    --median-latency-ms N  Artificial delay added to every search response (default: 0).
    --jitter-ms J          Uniform random jitter in [-J, +J] ms around the median (default: 0).

Observability:
    GET  /_stats        Returns {"in_flight": N, "peak_in_flight": M, "total": T}.
    POST /_stats/reset  Resets in_flight, peak_in_flight, and total to 0.

Run:
    uv run perf/stub/source_stub.py --profile medium
    uv run perf/stub/source_stub.py --profile small --bind 127.0.0.1:14256 \\
        --median-latency-ms 100 --jitter-ms 20
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import random
import sys
from dataclasses import dataclass, field

from aiohttp import web

LOGGER = logging.getLogger("source_stub")

PROFILES: dict[str, int] = {
    "small": 1_000,
    "medium": 100_000,
}

DEFAULT_BIND = "127.0.0.1:14256"
SUBJECT_PREFIX = "subj-"
SEED = 42

# Birth dates and land sizes are derived deterministically per subject id by
# hashing (seed, subject_id). The shape and range are chosen so the resulting
# claim values exercise both branches of farmer-under-4ha (the CEL claim
# returns true for ~half the subjects).
BIRTH_YEAR_MIN = 1940
BIRTH_YEAR_MAX = 2010
LAND_SIZE_MIN_DECILITRES = 0  # 0.0 ha
LAND_SIZE_MAX_DECILITRES = 80  # 8.0 ha


@dataclass
class InFlightCounter:
    """Thread-safe (asyncio) in-flight request counter.

    Tracks:
      in_flight       -- requests currently being processed.
      peak_in_flight  -- highest in_flight value observed since last reset.
      total           -- cumulative requests started since last reset.

    Used by Stage 1 DoD as the assertion surface: "two concurrent
    batch_evaluate calls observe combined inbound concurrency capped at
    max_in_flight."
    """

    _in_flight: int = field(default=0, init=False)
    _peak_in_flight: int = field(default=0, init=False)
    _total: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    async def enter(self) -> None:
        async with self._lock:
            self._in_flight += 1
            self._total += 1
            if self._in_flight > self._peak_in_flight:
                self._peak_in_flight = self._in_flight

    async def exit(self) -> None:
        async with self._lock:
            self._in_flight -= 1

    async def snapshot(self) -> dict:
        async with self._lock:
            return {
                "in_flight": self._in_flight,
                "peak_in_flight": self._peak_in_flight,
                "total": self._total,
            }

    async def reset(self) -> None:
        async with self._lock:
            self._in_flight = 0
            self._peak_in_flight = 0
            self._total = 0


@dataclass(frozen=True)
class StubConfig:
    bind: str
    subject_count: int
    bearer_token: str
    median_latency_ms: float
    jitter_ms: float


def _digest(*parts: str) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(str(SEED).encode("ascii"))
    for part in parts:
        hasher.update(b"\x00")
        hasher.update(part.encode("utf-8"))
    return hasher.digest()


def birth_date_for(subject_id: str) -> str:
    digest = _digest("birth_date", subject_id)
    year = BIRTH_YEAR_MIN + int.from_bytes(digest[:2], "big") % (
        BIRTH_YEAR_MAX - BIRTH_YEAR_MIN + 1
    )
    month = 1 + int.from_bytes(digest[2:3], "big") % 12
    day = 1 + int.from_bytes(digest[3:4], "big") % 28  # safe for every month
    return f"{year:04d}-{month:02d}-{day:02d}"


def land_size_for(subject_id: str) -> float:
    digest = _digest("land_size", subject_id)
    decilitres = LAND_SIZE_MIN_DECILITRES + int.from_bytes(digest[:2], "big") % (
        LAND_SIZE_MAX_DECILITRES - LAND_SIZE_MIN_DECILITRES + 1
    )
    return decilitres / 10.0


def is_known_subject(subject_id: str, subject_count: int) -> bool:
    """Subject ids match the deterministic pool `subj-{0..N-1}` (zero-padded)."""
    if not subject_id.startswith(SUBJECT_PREFIX):
        return False
    suffix = subject_id[len(SUBJECT_PREFIX):]
    if not suffix.isdigit():
        return False
    return 0 <= int(suffix) < subject_count


def _extract_subject_id(payload: dict) -> str | None:
    """Pull NATIONAL_ID value out of the DCI request body witness sends."""
    try:
        criteria = payload["message"]["search_request"][0]["search_criteria"]
    except (KeyError, IndexError, TypeError):
        return None
    query = criteria.get("query")
    if not isinstance(query, dict):
        return None
    value = query.get("value")
    return value if isinstance(value, str) else None


def _envelope(records: list[dict]) -> dict:
    return {
        "header": {"version": "1.0.0", "status": "succ"},
        "message": {
            "transaction_id": "perf-stub",
            "search_response": [
                {
                    "reference_id": "perf-stub",
                    "timestamp": "1970-01-01T00:00:00Z",
                    "status": "succ",
                    "data": {"reg_records": records},
                }
            ],
        },
    }


def _unauthorized(detail: str) -> web.Response:
    return web.json_response(
        {"code": "unauthorized", "detail": detail},
        status=401,
    )


async def _require_bearer(request: web.Request) -> str | None:
    """Return None if the bearer matches; otherwise return a 401 response body string."""
    expected = request.app["config"].bearer_token
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return "missing bearer"
    if header[len("Bearer "):] != expected:
        return "invalid bearer"
    return None


def _simulate_delay(config: StubConfig) -> float:
    """Return a latency in seconds to sleep, derived from median and jitter."""
    if config.median_latency_ms <= 0 and config.jitter_ms <= 0:
        return 0.0
    jitter = 0.0
    if config.jitter_ms > 0:
        jitter = random.uniform(-config.jitter_ms, config.jitter_ms)
    delay_ms = max(0.0, config.median_latency_ms + jitter)
    return delay_ms / 1000.0


async def _handle_search(
    request: web.Request, value_field: str, value_fn
) -> web.Response:
    config: StubConfig = request.app["config"]
    counter: InFlightCounter = request.app["counter"]

    err = await _require_bearer(request)
    if err is not None:
        return _unauthorized(err)

    await counter.enter()
    try:
        try:
            payload = await request.json()
        except ValueError:
            return web.json_response({"code": "invalid_request"}, status=400)

        subject_id = _extract_subject_id(payload)
        if subject_id is None:
            return web.json_response({"code": "invalid_request"}, status=400)

        delay = _simulate_delay(config)
        if delay > 0:
            await asyncio.sleep(delay)

        if not is_known_subject(subject_id, config.subject_count):
            return web.json_response(_envelope([]))

        record = {
            "NATIONAL_ID": subject_id,
            value_field: value_fn(subject_id),
        }
        return web.json_response(_envelope([record]))
    finally:
        await counter.exit()


async def handle_crvs(request: web.Request) -> web.Response:
    return await _handle_search(request, "birth_date", birth_date_for)


async def handle_farmer(request: web.Request) -> web.Response:
    return await _handle_search(request, "farmed_land_size_hectares", land_size_for)


async def handle_health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def handle_stats(request: web.Request) -> web.Response:
    """GET /_stats -- return current in-flight and peak counters."""
    counter: InFlightCounter = request.app["counter"]
    return web.json_response(await counter.snapshot())


async def handle_stats_reset(request: web.Request) -> web.Response:
    """POST /_stats/reset -- zero all counters."""
    counter: InFlightCounter = request.app["counter"]
    await counter.reset()
    return web.json_response({"reset": True})


def build_app(config: StubConfig) -> web.Application:
    app = web.Application()
    app["config"] = config
    app["counter"] = InFlightCounter()
    app.router.add_post("/dci/crvs/registry/sync/search", handle_crvs)
    app.router.add_post("/dci/fr/registry/sync/search", handle_farmer)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/_stats", handle_stats)
    app.router.add_post("/_stats/reset", handle_stats_reset)
    return app


def parse_bind(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port:
        raise argparse.ArgumentTypeError(f"invalid --bind: {value!r}")
    try:
        return host, int(port)
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"invalid --bind port: {value!r}") from err


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES.keys()),
        default="medium",
        help="Subject pool size (small=1k, medium=100k). Default: medium.",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("EVIDENCE_SOURCE_STUB_BIND", DEFAULT_BIND),
        help=f"Listen address (default: {DEFAULT_BIND}).",
    )
    parser.add_argument(
        "--token-env",
        default="EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN",
        help="Env var holding the bearer token the stub will accept.",
    )
    parser.add_argument(
        "--median-latency-ms",
        type=float,
        default=0.0,
        metavar="MS",
        help=(
            "Artificial median latency added to every search response in milliseconds "
            "(default: 0, i.e. no added delay). Combines with --jitter-ms."
        ),
    )
    parser.add_argument(
        "--jitter-ms",
        type=float,
        default=0.0,
        metavar="MS",
        help=(
            "Uniform random jitter applied around --median-latency-ms in milliseconds "
            "(default: 0). The actual delay is median + U(-jitter, +jitter), floored at 0."
        ),
    )
    args = parser.parse_args()

    token = os.environ.get(args.token_env, "")
    if not token:
        print(
            f"error: ${args.token_env} is not set; the stub cannot authenticate witness",
            file=sys.stderr,
        )
        sys.exit(2)

    host, port = parse_bind(args.bind)
    config = StubConfig(
        bind=args.bind,
        subject_count=PROFILES[args.profile],
        bearer_token=token,
        median_latency_ms=args.median_latency_ms,
        jitter_ms=args.jitter_ms,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    LOGGER.info(
        "starting source stub: bind=%s profile=%s subjects=%d "
        "median_latency_ms=%.1f jitter_ms=%.1f",
        args.bind,
        args.profile,
        config.subject_count,
        config.median_latency_ms,
        config.jitter_ms,
    )

    web.run_app(build_app(config), host=host, port=port, print=lambda _: None)


if __name__ == "__main__":
    main()
