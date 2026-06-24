#!/usr/bin/env python3
"""Generate scoped local credentials for the decentralized evidence demo.

Relay containers receive only SHA-256 fingerprints and the audit hash secret.
Registry Notary containers receive only their own source/client credentials and
issuer key. The demo client receives only the raw tokens needed for the demo
walkthrough.
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

EVIDENCE_CLIENT_IDS = {
    "CIVIL_EVIDENCE_CLIENT": "civil_evidence_client",
    "SOCIAL_EVIDENCE_CLIENT": "social_protection_evidence_client",
    "SHARED_EVIDENCE_CLIENT": "shared_evidence_client",
}

SCOPED_ENV_FILES: dict[str, list[str]] = {
    "civil-registry-relay.env": [
        "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        "CIVIL_METADATA_CLIENT_HASH",
        "CIVIL_EVIDENCE_SOURCE_HASH",
        "CIVIL_EVIDENCE_ONLY_HASH",
        "CIVIL_ROW_READER_HASH",
        "SHARED_CIVIL_EVIDENCE_SOURCE_HASH",
    ],
    "social-protection-registry-relay.env": [
        "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        "SOCIAL_METADATA_CLIENT_HASH",
        "SOCIAL_EVIDENCE_SOURCE_HASH",
        "SOCIAL_EVIDENCE_ONLY_HASH",
        "SOCIAL_ROW_READER_HASH",
        "SOCIAL_AGGREGATE_READER_HASH",
        "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH",
    ],
    "health-registry-relay.env": [
        "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        "HEALTH_METADATA_CLIENT_HASH",
        "HEALTH_EVIDENCE_SOURCE_HASH",
        "HEALTH_EVIDENCE_ONLY_HASH",
        "HEALTH_ROW_READER_HASH",
        "SHARED_HEALTH_EVIDENCE_SOURCE_HASH",
    ],
    "civil-registry-notary.env": [
        "CIVIL_EVIDENCE_CLIENT_TOKEN_COMMITMENT",
        "CIVIL_EVIDENCE_CLIENT_TOKEN_HASH",
        "CIVIL_EVIDENCE_CLIENT_BEARER_COMMITMENT",
        "CIVIL_EVIDENCE_CLIENT_BEARER_HASH",
        "CIVIL_EVIDENCE_SOURCE_RAW",
        "CIVIL_EVIDENCE_ISSUER_JWK",
    ],
    "social-protection-registry-notary.env": [
        "SOCIAL_EVIDENCE_CLIENT_TOKEN_COMMITMENT",
        "SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH",
        "SOCIAL_EVIDENCE_CLIENT_BEARER_COMMITMENT",
        "SOCIAL_EVIDENCE_CLIENT_BEARER_HASH",
        "SOCIAL_EVIDENCE_SOURCE_RAW",
        "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK",
    ],
    "shared-eligibility-registry-notary.env": [
        "SHARED_EVIDENCE_CLIENT_TOKEN_COMMITMENT",
        "SHARED_EVIDENCE_CLIENT_TOKEN_HASH",
        "SHARED_EVIDENCE_CLIENT_BEARER_COMMITMENT",
        "SHARED_EVIDENCE_CLIENT_BEARER_HASH",
        "SHARED_CIVIL_EVIDENCE_SOURCE_RAW",
        "SHARED_SOCIAL_EVIDENCE_SOURCE_RAW",
        "SHARED_HEALTH_EVIDENCE_SOURCE_RAW",
        "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK",
    ],
    "demo-client.env": [
        "CIVIL_METADATA_CLIENT_RAW",
        "SOCIAL_METADATA_CLIENT_RAW",
        "HEALTH_METADATA_CLIENT_RAW",
        "SOCIAL_EVIDENCE_ONLY_RAW",
        "SOCIAL_ROW_READER_RAW",
        "SOCIAL_AGGREGATE_READER_RAW",
        "CIVIL_EVIDENCE_CLIENT_BEARER",
        "SOCIAL_EVIDENCE_CLIENT_BEARER",
        "SHARED_EVIDENCE_CLIENT_BEARER",
    ],
}


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def credential_commitment(
    credential_id: str,
    credential_type: str,
    credential_fingerprint: str,
) -> str:
    payload = {
        "product": "registry-notary",
        "credential_type": credential_type,
        "credential_id": credential_id,
        "fingerprint": credential_fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline")
    return f"{key}={value}"


def generate_env() -> dict[str, str]:
    values: dict[str, str] = {
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": generate_audit_hash_secret(),
        "CIVIL_EVIDENCE_ISSUER_JWK": generate_registry_notary_issuer_jwk(),
        "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK": generate_registry_notary_issuer_jwk(),
        "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK": generate_registry_notary_issuer_jwk(),
    }
    for name in TOKEN_NAMES:
        raw = generate_raw_key()
        values[f"{name}_RAW"] = raw
        values[f"{name}_HASH"] = fingerprint(raw)
    for name in EVIDENCE_CLIENT_NAMES:
        credential_id = EVIDENCE_CLIENT_IDS[name]
        token = generate_raw_key()
        token_hash = fingerprint(token)
        values[f"{name}_TOKEN"] = token
        values[f"{name}_TOKEN_HASH"] = token_hash
        values[f"{name}_TOKEN_COMMITMENT"] = credential_commitment(
            credential_id,
            "api_key",
            token_hash,
        )

        bearer = generate_raw_key()
        bearer_hash = fingerprint(bearer)
        values[f"{name}_BEARER"] = bearer
        values[f"{name}_BEARER_HASH"] = bearer_hash
        values[f"{name}_BEARER_COMMITMENT"] = credential_commitment(
            credential_id,
            "bearer_token",
            bearer_hash,
        )
    return values


def scoped_values(values: dict[str, str], names: list[str]) -> dict[str, str]:
    missing = [name for name in names if name not in values]
    if missing:
        raise KeyError(f"missing generated values: {', '.join(missing)}")
    return {name: values[name] for name in names}


def write_env_file(path: Path, values: dict[str, str], scope: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Generated local credentials for {scope}.",
        "# Do not commit this file. Regenerate with demo/decentralized/scripts/generate-demo-secrets.py.",
        "",
    ]
    for key in sorted(values):
        lines.append(env_line(key, values[key]))
    write_secret_file(path, "\n".join(lines) + "\n")


def write_scoped_env_files(env_dir: Path, values: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    for filename, names in SCOPED_ENV_FILES.items():
        path = env_dir / filename
        write_env_file(path, scoped_values(values, names), filename)
        paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-dir",
        default=Path(__file__).resolve().parents[1] / "env",
        type=Path,
        help="destination directory for scoped env files, default: demo/decentralized/env",
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="print generated file and variable names without raw secret values",
    )
    args = parser.parse_args()

    values = generate_env()
    written = write_scoped_env_files(args.env_dir, values)
    print(
        f"wrote scoped local demo credentials to {args.env_dir}; raw values are for this machine only",
        file=sys.stderr,
    )
    if args.print_summary:
        summary = {
            path.name: sorted(SCOPED_ENV_FILES[path.name])
            for path in written
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
