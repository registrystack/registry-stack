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

Run:
    uv run perf/stub/source_stub.py --profile medium
    uv run perf/stub/source_stub.py --profile small --bind 127.0.0.1:14256
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from dataclasses import dataclass

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


@dataclass(frozen=True)
class StubConfig:
    bind: str
    subject_count: int
    bearer_token: str


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
    suffix = subject_id[len(SUBJECT_PREFIX) :]
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
    if header[len("Bearer ") :] != expected:
        return "invalid bearer"
    return None


async def _handle_search(
    request: web.Request, value_field: str, value_fn
) -> web.Response:
    config: StubConfig = request.app["config"]
    err = await _require_bearer(request)
    if err is not None:
        return _unauthorized(err)
    try:
        payload = await request.json()
    except ValueError:
        return web.json_response({"code": "invalid_request"}, status=400)
    subject_id = _extract_subject_id(payload)
    if subject_id is None:
        return web.json_response({"code": "invalid_request"}, status=400)
    if not is_known_subject(subject_id, config.subject_count):
        return web.json_response(_envelope([]))
    record = {
        "NATIONAL_ID": subject_id,
        value_field: value_fn(subject_id),
    }
    return web.json_response(_envelope([record]))


async def handle_crvs(request: web.Request) -> web.Response:
    return await _handle_search(request, "birth_date", birth_date_for)


async def handle_farmer(request: web.Request) -> web.Response:
    return await _handle_search(request, "farmed_land_size_hectares", land_size_for)


async def handle_health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def build_app(config: StubConfig) -> web.Application:
    app = web.Application()
    app["config"] = config
    app.router.add_post("/dci/crvs/registry/sync/search", handle_crvs)
    app.router.add_post("/dci/fr/registry/sync/search", handle_farmer)
    app.router.add_get("/health", handle_health)
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
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    LOGGER.info(
        "starting source stub: bind=%s profile=%s subjects=%d",
        args.bind,
        args.profile,
        config.subject_count,
    )

    web.run_app(build_app(config), host=host, port=port, print=lambda _msg: None)


if __name__ == "__main__":
    main()
