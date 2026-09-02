#!/usr/bin/env python3
"""Seed the load-test Registry with deterministic synthetic records.

Drives the public batch HTTP contract directly (POST /v1/records/{route}:batch
with an idempotency key per chunk), which is the same surface
`registry-serverctl data import` uses, but with bounded parallelism so
hundred-thousand-record seeds finish in minutes instead of hours. Record ids
returned by the batch responses are captured so operator assignments can
reference real establishments and businesses, and so the k6 harness has an
id pool for point reads.

Every generated value is synthetic and derived from a fixed seed; nothing
here resembles a real business, person, or identifier.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any


AREAS = [
    "north-loadtest", "south-loadtest", "east-loadtest", "west-loadtest",
    "central-loadtest", "highland-loadtest", "coastal-loadtest", "delta-loadtest",
    "plateau-loadtest", "valley-loadtest", "basin-loadtest", "ridge-loadtest",
]
KINDS = ["production", "warehouse", "office"]
STATUSES = ["operating", "operating", "operating", "operating", "suspended", "closed"]
LANGUAGES = ["en", "en", "en", "es", "fr"]
RELATIONSHIPS = ["head-office", "regional-office", "branch", "depot", "other"]
BUSINESS_TYPES = ["private", "cooperative", "public-enterprise"]
NAME_ADJECTIVES = [
    "Northern", "Southern", "Eastern", "Western", "Central", "Coastal", "Inland",
    "Highland", "Meridian", "Riverside", "Lakeside", "Summit", "Harbor", "Meadow",
]
NAME_NOUNS = [
    "Fabrication", "Logistics", "Provisioning", "Milling", "Packaging", "Assembly",
    "Distribution", "Refrigeration", "Textiles", "Components", "Bottling", "Grading",
]
BATCH_ITEMS = 100
TOKEN_REFRESH_MARGIN_SECONDS = 60


class SeedError(RuntimeError):
    pass


class TokenSource:
    """client_secret_post token acquisition with expiry tracking."""

    def __init__(self, token_url: str, client_id: str, secret: str) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._secret = secret
        self._lock = threading.Lock()
        self._token = ""
        self._expires_at = 0.0

    def token(self) -> str:
        with self._lock:
            if time.monotonic() >= self._expires_at:
                self._refresh()
            return self._token

    def _refresh(self) -> None:
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._secret,
            }
        ).encode("ascii")
        request = urllib.request.Request(
            self._token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read().decode("utf-8"))
        token = document.get("access_token")
        lifetime = document.get("expires_in")
        if not isinstance(token, str) or not isinstance(lifetime, (int, float)):
            raise SeedError("Mint did not return an access token with expires_in")
        self._token = token
        self._expires_at = time.monotonic() + float(lifetime) - TOKEN_REFRESH_MARGIN_SECONDS


def canonical_body(items: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {"items": [{"operation": "create", "data": item} for item in items]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def post_batch(
    server_url: str,
    route: str,
    items: list[dict[str, Any]],
    tokens: TokenSource,
    idempotency_suffix: str,
) -> list[dict[str, Any]]:
    body = canonical_body(items)
    request = urllib.request.Request(
        f"{server_url}/v1/records/{route}:batch?accessProfile=business-operator",
        data=body,
        headers={
            "Authorization": f"Bearer {tokens.token()}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"loadtest-seed-{route}-{idempotency_suffix}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:2000]
        raise SeedError(f"batch to {route} failed with {error.code}: {detail}") from error
    results = document.get("results")
    if not isinstance(results, list) or len(results) != len(items):
        raise SeedError(f"batch to {route} returned {len(results) if isinstance(results, list) else 'malformed'} results for {len(items)} items")
    return results


def record_id(result: Any) -> str:
    if not isinstance(result, dict):
        raise SeedError("batch result is not an object")
    record = result.get("data")
    if isinstance(record, dict):
        identifier = record.get("recordIdentifier")
        if isinstance(identifier, str):
            return identifier
    for key in ("id", "recordId", "record_id"):
        value = result.get(key)
        if isinstance(value, str):
            return value
    raise SeedError(f"batch result carries no record identifier: {sorted(result)[:8]}")


def generate_businesses(count: int, rng: random.Random) -> list[dict[str, Any]]:
    return [
        {
            "businessCode": f"LT-B-{index:07d}",
            "localRegistrationNumber": index,
            "registeredName": f"{NAME_ADJECTIVES[index % len(NAME_ADJECTIVES)]} {NAME_NOUNS[(index // 7) % len(NAME_NOUNS)]} {index:05d}",
            "administrativeArea": AREAS[index % len(AREAS)],
            "businessType": BUSINESS_TYPES[index % len(BUSINESS_TYPES)],
        }
        for index in range(1, count + 1)
    ]


def generate_establishments(count: int, rng: random.Random) -> list[dict[str, Any]]:
    records = []
    for index in range(1, count + 1):
        opened_year = rng.randint(1960, 2025)
        records.append(
            {
                "establishmentCode": f"LT-E-{index:07d}",
                "siteName": f"{NAME_ADJECTIVES[index % len(NAME_ADJECTIVES)]} {NAME_NOUNS[(index // 11) % len(NAME_NOUNS)]} Site {index:06d}",
                "locality": AREAS[index % len(AREAS)],
                "openedOn": f"{opened_year:04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                "establishmentKind": KINDS[index % len(KINDS)],
                "operatingStatus": rng.choice(STATUSES),
                "preferredLanguage": rng.choice(LANGUAGES),
            }
        )
    return records


def generate_assignments(
    count: int,
    establishment_ids: list[str],
    business_ids: list[str],
    rng: random.Random,
) -> list[dict[str, Any]]:
    if count > len(establishment_ids):
        raise SeedError(
            f"cannot generate {count} non-overlapping assignments over "
            f"{len(establishment_ids)} establishments"
        )
    # One open-ended assignment per distinct establishment keeps the temporal
    # non-overlap constraint satisfied by construction.
    records = []
    for index, establishment in enumerate(rng.sample(establishment_ids, count), start=1):
        valid_year = rng.randint(1990, 2025)
        records.append(
            {
                "establishment": establishment,
                "business": rng.choice(business_ids),
                "relationship": RELATIONSHIPS[index % len(RELATIONSHIPS)],
                "validFrom": f"{valid_year:04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            }
        )
    return records


def seed_entity(
    server_url: str,
    route: str,
    records: list[dict[str, Any]],
    tokens: TokenSource,
    workers: int,
    label: str,
) -> list[str]:
    chunks = [
        (chunk_index, records[chunk_index * BATCH_ITEMS:(chunk_index + 1) * BATCH_ITEMS])
        for chunk_index in range((len(records) + BATCH_ITEMS - 1) // BATCH_ITEMS)
    ]
    ids: list[str] = [""] * len(records)
    started = time.monotonic()
    done = 0
    lock = threading.Lock()

    def run(chunk: tuple[int, list[dict[str, Any]]]) -> None:
        nonlocal done
        chunk_index, items = chunk
        results = post_batch(server_url, route, items, tokens, f"{chunk_index:07d}")
        for offset, result in enumerate(results):
            ids[chunk_index * BATCH_ITEMS + offset] = record_id(result)
        with lock:
            done += len(items)
            if done % 5000 == 0 or done == len(records):
                elapsed = time.monotonic() - started
                rate = done / elapsed if elapsed > 0 else 0.0
                print(f"  {label}: {done}/{len(records)} ({rate:.0f} records/s)", flush=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for outcome in list(pool.map(run, chunks)):
            _ = outcome
    if any(not value for value in ids):
        raise SeedError(f"{label} left records without ids")
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the load-test Registry")
    parser.add_argument("--count", type=int, default=100_000, help="establishments to seed")
    parser.add_argument("--seed", type=int, default=20260902, help="deterministic RNG seed")
    parser.add_argument("--workers", type=int, default=4, help="concurrent batch requests")
    parser.add_argument("--run-dir", type=Path, default=Path(__file__).resolve().parent / ".run")
    arguments = parser.parse_args()

    if arguments.count < 1:
        print("--count must be at least 1", file=sys.stderr)
        return 2
    env_path = arguments.run_dir / "env.json"
    if not env_path.is_file():
        print(f"no load-test environment at {env_path}; run up.sh first", file=sys.stderr)
        return 2
    environment = json.loads(env_path.read_text(encoding="utf-8"))
    secret = (arguments.run_dir / "secrets/driver-client-secret").read_text(encoding="ascii").strip()
    tokens = TokenSource(environment["token_url"], environment["driver_client_id"], secret)
    seed_dir = arguments.run_dir / "seed"
    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_summary = seed_dir / "seed-summary.json"
    seed_summary.unlink(missing_ok=True)
    rng = random.Random(arguments.seed)

    business_count = max(8, arguments.count // 50)
    assignment_count = arguments.count // 20
    print(f"Seeding {business_count} businesses, {arguments.count} establishments, {assignment_count} assignments")

    businesses = generate_businesses(business_count, rng)
    establishments = generate_establishments(arguments.count, rng)

    try:
        business_ids = seed_entity(
            environment["server_url"], "businesses", businesses, tokens, arguments.workers, "businesses"
        )
        establishment_ids = seed_entity(
            environment["server_url"], "establishments", establishments, tokens, arguments.workers, "establishments"
        )
        assignments = generate_assignments(assignment_count, establishment_ids, business_ids, rng)
        seed_entity(
            environment["server_url"], "operator-assignments", assignments, tokens, arguments.workers, "assignments"
        )
    except SeedError as error:
        print(f"seeding failed: {error}", file=sys.stderr)
        return 1

    (seed_dir / "establishment-ids.txt").write_text(
        "".join(f"{identifier} {record['establishmentCode']}\n" for identifier, record in zip(establishment_ids, establishments)),
        encoding="utf-8",
    )
    (seed_dir / "business-ids.txt").write_text(
        "".join(f"{identifier} {record['businessCode']}\n" for identifier, record in zip(business_ids, businesses)),
        encoding="utf-8",
    )
    if arguments.count >= 100_000:
        print("Refreshing PostgreSQL planner statistics after the full-scale seed")
        try:
            subprocess.run(
                [str(Path(__file__).resolve().parent / "dbstats.sh"), "analyze"],
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"seeding completed, but ANALYZE failed: {error}", file=sys.stderr)
            return 1
    seed_summary.write_text(
        json.dumps(
            {
                "seed": arguments.seed,
                "establishments": arguments.count,
                "businesses": business_count,
                "assignments": assignment_count,
                "establishment_id_count": len(establishment_ids),
                "business_id_count": len(business_ids),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Seeded and recorded id pools under {seed_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
