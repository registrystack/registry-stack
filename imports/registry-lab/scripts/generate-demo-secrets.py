#!/usr/bin/env python3
"""Generate local credentials for the decentralized evidence demo.

The Relay side stores SHA-256 fingerprints in config through hash env vars.
Raw values are used only by demo clients and Evidence Server source connectors.
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
RELAY_ROOT = Path(os.environ.get("REGISTRY_RELAY_SOURCE_DIR", DEMO_ROOT / "vendor" / "registry-relay")).resolve()
sys.path.insert(0, str(RELAY_ROOT / "demo/scripts"))

from generate_demo_keys import (  # noqa: E402
    generate_registry_notary_issuer_jwk,
    generate_raw_key,
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
    "AGRI_METADATA_CLIENT",
    "AGRI_EVIDENCE_SOURCE",
    "AGRI_EVIDENCE_ONLY",
    "AGRI_ROW_READER",
    "AGRI_AGGREGATE_READER",
]

EVIDENCE_CLIENT_NAMES = [
    "CIVIL_EVIDENCE_CLIENT",
    "SOCIAL_EVIDENCE_CLIENT",
    "SHARED_EVIDENCE_CLIENT",
    "AGRI_EVIDENCE_CLIENT",
]


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline")
    return f"{key}={shlex.quote(value)}"


def generate_env() -> dict[str, str]:
    issuer_jwk = generate_registry_notary_issuer_jwk()
    static_metadata_federation_jwk = generate_registry_notary_issuer_jwk()
    default_federation_client_jwk = generate_registry_notary_issuer_jwk()
    civil_federation_response_jwk = generate_registry_notary_issuer_jwk()
    social_federation_response_jwk = generate_registry_notary_issuer_jwk()
    agri_federation_client_jwk = generate_registry_notary_issuer_jwk()
    agri_federation_response_jwk = generate_registry_notary_issuer_jwk()
    openfn_sidecar_token = generate_raw_key()
    values: dict[str, str] = {
        "CLAIM_VERIFICATION_BINDING_KEY": generate_raw_key(),
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_ISSUER_JWK": issuer_jwk,
        "CIVIL_EVIDENCE_ISSUER_JWK": issuer_jwk,
        "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK": issuer_jwk,
        "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK": issuer_jwk,
        "STATIC_METADATA_FEDERATION_JWK": static_metadata_federation_jwk,
        "DEFAULT_FEDERATION_CLIENT_JWK": default_federation_client_jwk,
        "CIVIL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET": generate_raw_key(),
        "CIVIL_FEDERATION_RESPONSE_JWK": civil_federation_response_jwk,
        "SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET": generate_raw_key(),
        "SOCIAL_FEDERATION_RESPONSE_JWK": social_federation_response_jwk,
        "AGRI_FEDERATION_CLIENT_JWK": agri_federation_client_jwk,
        "AGRI_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET": generate_raw_key(),
        "AGRI_FEDERATION_RESPONSE_JWK": agri_federation_response_jwk,
        "OPENFN_SIDECAR_TOKEN_RAW": openfn_sidecar_token,
        "OPENFN_SIDECAR_TOKEN_HASH": fingerprint(openfn_sidecar_token),
        "OPENFN_MOCK_REGISTRY_TOKEN_RAW": generate_raw_key(),
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
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_TOKEN"] = values["SOCIAL_EVIDENCE_CLIENT_TOKEN"]
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_TOKEN_HASH"] = values[
        "SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH"
    ]
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_BEARER"] = values["SOCIAL_EVIDENCE_CLIENT_BEARER"]
    values["SOCIAL_PROTECTION_EVIDENCE_CLIENT_BEARER_HASH"] = values[
        "SOCIAL_EVIDENCE_CLIENT_BEARER_HASH"
    ]
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
            "static_metadata_federation_jwk": "STATIC_METADATA_FEDERATION_JWK",
            "default_federation_client_jwk": "DEFAULT_FEDERATION_CLIENT_JWK",
            "civil_federation_response_jwk": "CIVIL_FEDERATION_RESPONSE_JWK",
            "social_federation_response_jwk": "SOCIAL_FEDERATION_RESPONSE_JWK",
            "agri_federation_client_jwk": "AGRI_FEDERATION_CLIENT_JWK",
            "agri_federation_response_jwk": "AGRI_FEDERATION_RESPONSE_JWK",
            "binding_key": "CLAIM_VERIFICATION_BINDING_KEY",
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
