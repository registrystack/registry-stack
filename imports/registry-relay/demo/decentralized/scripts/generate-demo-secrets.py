#!/usr/bin/env python3
"""Generate local credentials for the decentralized evidence demo.

The Relay side stores SHA-256 fingerprints in config through hash env vars.
Raw values are used only by demo clients and Evidence Server source connectors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

RELAY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RELAY_ROOT / "demo/scripts"))

from generate_demo_keys import (  # noqa: E402
    generate_audit_hash_secret,
    generate_registry_notary_issuer_jwk,
    generate_raw_key,
    write_secret_file,
)

TOKEN_NAMES = [
    "CIVIL_METADATA_CLIENT",
    "CIVIL_EVIDENCE_SOURCE",
    "CIVIL_EVIDENCE_ONLY",
    "CIVIL_ROW_READER",
    "CIVIL_AGGREGATE_READER",
    "SHARED_CIVIL_EVIDENCE_SOURCE",
    "SOCIAL_METADATA_CLIENT",
    "SOCIAL_EVIDENCE_SOURCE",
    "SOCIAL_EVIDENCE_ONLY",
    "SOCIAL_ROW_READER",
    "SOCIAL_AGGREGATE_READER",
    "SHARED_SOCIAL_EVIDENCE_SOURCE",
    "HEALTH_METADATA_CLIENT",
    "HEALTH_EVIDENCE_SOURCE",
    "HEALTH_EVIDENCE_ONLY",
    "HEALTH_ROW_READER",
    "HEALTH_AGGREGATE_READER",
    "SHARED_HEALTH_EVIDENCE_SOURCE",
]

EVIDENCE_CLIENT_NAMES = [
    "CIVIL_EVIDENCE_CLIENT",
    "SOCIAL_EVIDENCE_CLIENT",
    "SHARED_EVIDENCE_CLIENT",
]


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline")
    return f"{key}={value}"


def generate_env() -> dict[str, str]:
    issuer_jwk = generate_registry_notary_issuer_jwk()
    values: dict[str, str] = {
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": generate_audit_hash_secret(),
        "REGISTRY_NOTARY_ISSUER_JWK": issuer_jwk,
        "CIVIL_EVIDENCE_ISSUER_JWK": issuer_jwk,
        "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK": issuer_jwk,
        "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK": issuer_jwk,
    }
    for name in TOKEN_NAMES:
        raw = generate_raw_key()
        values[f"{name}_RAW"] = raw
        values[f"{name}_HASH"] = fingerprint(raw)
    values["SOCIAL_PROTECTION_EVIDENCE_SOURCE_RAW"] = values["SOCIAL_EVIDENCE_SOURCE_RAW"]
    values["SOCIAL_PROTECTION_EVIDENCE_SOURCE_HASH"] = values["SOCIAL_EVIDENCE_SOURCE_HASH"]
    for name in EVIDENCE_CLIENT_NAMES:
        values[f"{name}_TOKEN"] = generate_raw_key()
        values[f"{name}_BEARER"] = generate_raw_key()
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_TOKEN"] = values["SOCIAL_EVIDENCE_CLIENT_TOKEN"]
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_BEARER"] = values["SOCIAL_EVIDENCE_CLIENT_BEARER"]
    return values


def write_env_file(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated local credentials for the decentralized evidence demo.",
        "# Do not commit this file. Regenerate with scripts/generate-demo-secrets.py.",
        "",
    ]
    for key in sorted(values):
        lines.append(env_line(key, values[key]))
    write_secret_file(path, "\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        default=Path(__file__).resolve().parents[1] / ".env",
        type=Path,
        help="destination .env file, default: demo/decentralized/.env",
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="print generated variable names without raw secret values",
    )
    args = parser.parse_args()

    values = generate_env()
    write_env_file(args.env_file, values)
    print(
        f"wrote local demo credentials to {args.env_file}; raw values are for this machine only",
        file=sys.stderr,
    )
    if args.print_summary:
        summary = {
            "raw_token_variables": sorted(k for k in values if k.endswith(("_RAW", "_TOKEN", "_BEARER"))),
            "hash_variables": sorted(k for k in values if k.endswith("_HASH")),
            "issuer_jwk": "REGISTRY_NOTARY_ISSUER_JWK",
            "audit_hash_secret": "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
