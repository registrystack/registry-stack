#!/usr/bin/env python3
"""Generate local credentials for the decentralized evidence demo.

Relay and Notary configs reference SHA-256 fingerprint env values. Raw values
are used only by demo clients and Relay source consultations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path

DEMO_ROOT = Path(__file__).resolve().parents[1]


def resolve_relay_scripts_dir() -> Path:
    if configured := os.environ.get("REGISTRY_RELAY_SOURCE_DIR"):
        candidates = [Path(configured).resolve() / "demo/scripts"]
    else:
        candidates = [
            DEMO_ROOT.parent / "crates" / "registry-relay" / "demo/scripts",
            DEMO_ROOT / "vendor" / "registry-relay" / "demo/scripts",
        ]
        candidates.extend(parent / "registry-relay" / "demo/scripts" for parent in DEMO_ROOT.parents)
    for candidate in candidates:
        if (candidate / "generate_demo_keys.py").exists():
            return candidate
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise ImportError(
        "could not find registry-relay demo/scripts/generate_demo_keys.py; "
        "set REGISTRY_RELAY_SOURCE_DIR to a registry-relay checkout. "
        f"Searched: {searched}"
    )


sys.path.insert(0, str(resolve_relay_scripts_dir()))

from generate_demo_keys import generate_raw_key  # noqa: E402

try:  # noqa: E402
    from generate_demo_keys import generate_registry_notary_issuer_jwk
except ImportError:  # noqa: E402
    from generate_demo_keys import (
        generate_registry_witness_issuer_jwk as generate_registry_notary_issuer_jwk,
    )

TOKEN_NAMES = [
    "CIVIL_RELAY_OPS",
    "CIVIL_METADATA_CLIENT",
    "CIVIL_EVIDENCE_SOURCE",
    "CIVIL_EVIDENCE_ONLY",
    "CIVIL_ROW_READER",
    "CIVIL_ESIGNET_IDENTITY_RELEASE",
    "CIVIL_AGGREGATE_READER",
    "POPULATION_METADATA_CLIENT",
    "POPULATION_ESIGNET_IDENTITY_RELEASE",
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
    "AGRI_METADATA_CLIENT",
    "AGRI_EVIDENCE_SOURCE",
    "AGRI_EVIDENCE_ONLY",
    "AGRI_ROW_READER",
    "AGRI_AGGREGATE_READER",
]

EVIDENCE_CLIENT_NAMES = ["SELF_ATTESTED_EVIDENCE_CLIENT"]


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline")
    return f"{key}={shlex.quote(value)}"


def generate_env() -> dict[str, str]:
    issuer_jwk = generate_registry_notary_issuer_jwk()
    values: dict[str, str] = {
        "CLAIM_VERIFICATION_BINDING_KEY": generate_raw_key(),
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_REDIS_URL": "redis://127.0.0.1:6379/0",
        "REGISTRY_NOTARY_REPLAY_REDIS_URL": "redis://127.0.0.1:6379/0",
        "REGISTRY_NOTARY_ISSUER_JWK": issuer_jwk,
        "REGISTRY_ESIGNET_KYC_TOKEN_SECRET": generate_raw_key(),
        "REGISTRY_ESIGNET_PSUT_SECRET": generate_raw_key(),
        "REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD": generate_raw_key(),
    }
    for name in TOKEN_NAMES:
        raw = generate_raw_key()
        values[f"{name}_RAW"] = raw
        values[f"{name}_HASH"] = fingerprint(raw)
    values["SOCIAL_PROTECTION_EVIDENCE_SOURCE_RAW"] = values["SOCIAL_EVIDENCE_SOURCE_RAW"]
    values["SOCIAL_PROTECTION_EVIDENCE_SOURCE_HASH"] = values["SOCIAL_EVIDENCE_SOURCE_HASH"]
    for name in EVIDENCE_CLIENT_NAMES:
        token = generate_raw_key()
        bearer = generate_raw_key()
        values[f"{name}_TOKEN"] = token
        values[f"{name}_TOKEN_HASH"] = fingerprint(token)
        values[f"{name}_BEARER"] = bearer
        values[f"{name}_BEARER_HASH"] = fingerprint(bearer)
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        default=DEMO_ROOT / ".env",
        type=Path,
        help="destination .env file, default: ./.env",
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
            "raw_secret_variables": sorted(
                k
                for k in values
                if k.endswith(("_RAW", "_TOKEN", "_BEARER", "_AUDIT_HASH_SECRET"))
            ),
            "hash_variables": sorted(k for k in values if k.endswith("_HASH")),
            "issuer_jwk": "REGISTRY_NOTARY_ISSUER_JWK",
            "binding_key": "CLAIM_VERIFICATION_BINDING_KEY",
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
