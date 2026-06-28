#!/usr/bin/env python3
"""Generate local credentials for the decentralized evidence demo.

Relay and Notary configs reference SHA-256 fingerprint env values. Raw values
are used only by demo clients and Evidence Server source connectors.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
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

EVIDENCE_CLIENT_NAMES = [
    "CIVIL_NOTARY_OPS",
    "CIVIL_EVIDENCE_CLIENT",
    "SOCIAL_EVIDENCE_CLIENT",
    "SHARED_EVIDENCE_CLIENT",
    "SHARED_EVIDENCE_DENY_ASSURANCE",
    "SHARED_EVIDENCE_DENY_JURISDICTION",
    "SHARED_EVIDENCE_DENY_LEGAL_BASIS",
    "SHARED_EVIDENCE_DENY_CONSENT",
    "OPENCRVS_EVIDENCE_DENY_ASSURANCE",
    "OPENCRVS_EVIDENCE_DENY_JURISDICTION",
    "OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS",
    "OPENCRVS_EVIDENCE_DENY_CONSENT",
    "DHIS2_EVIDENCE_CLIENT",
    "AGRI_EVIDENCE_CLIENT",
    "FHIR_EVIDENCE_CLIENT",
]


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline")
    return f"{key}={shlex.quote(value)}"


def generate_env() -> dict[str, str]:
    issuer_jwk = generate_registry_notary_issuer_jwk()
    rotated_issuer_jwk = generate_registry_notary_issuer_jwk()
    static_metadata_federation_jwk = generate_registry_notary_issuer_jwk()
    default_federation_client_jwk = generate_registry_notary_issuer_jwk()
    civil_federation_response_jwk = generate_registry_notary_issuer_jwk()
    social_federation_response_jwk = generate_registry_notary_issuer_jwk()
    agri_federation_client_jwk = generate_registry_notary_issuer_jwk()
    agri_federation_response_jwk = generate_registry_notary_issuer_jwk()
    access_token_jwk = generate_registry_notary_issuer_jwk()
    esignet_rp_jwk = generate_rs256_jwk("registry-lab-live-client-key-1")
    openfn_sidecar_token = generate_raw_key()
    fhir_sidecar_token = generate_raw_key()
    opencrvs_evidence_client_token = generate_raw_key()
    values: dict[str, str] = {
        "CLAIM_VERIFICATION_BINDING_KEY": generate_raw_key(),
        "REGISTRY_RELAY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_AUDIT_HASH_SECRET": generate_raw_key(),
        "REGISTRY_NOTARY_REDIS_URL": "redis://127.0.0.1:6379/0",
        "REGISTRY_NOTARY_REPLAY_REDIS_URL": "redis://127.0.0.1:6379/0",
        "REGISTRY_NOTARY_ISSUER_JWK": issuer_jwk,
        "REGISTRY_NOTARY_ISSUER_PUBLIC_JWK": public_jwk_env_value(
            issuer_jwk,
            "did:web:civil-evidence.demo.example#civil-evidence-demo-key-1",
        ),
        "REGISTRY_NOTARY_ACCESS_TOKEN_JWK": access_token_jwk,
        "REGISTRY_NOTARY_ESIGNET_RP_JWK": esignet_rp_jwk,
        "REGISTRY_NOTARY_ROTATED_ISSUER_JWK": rotated_issuer_jwk,
        "REGISTRY_ESIGNET_KYC_TOKEN_SECRET": generate_raw_key(),
        "REGISTRY_ESIGNET_PSUT_SECRET": generate_raw_key(),
        "REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD": generate_raw_key(),
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
        "FHIR_SIDECAR_TOKEN_RAW": fhir_sidecar_token,
        "FHIR_SIDECAR_TOKEN_HASH": fingerprint(fhir_sidecar_token),
        "OPENFN_MOCK_REGISTRY_TOKEN_RAW": generate_raw_key(),
        "OPENCRVS_EVIDENCE_CLIENT_TOKEN": opencrvs_evidence_client_token,
        "OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH": fingerprint(opencrvs_evidence_client_token),
        "OPENCRVS_DCI_CLIENT_ID": "registry-lab-opencrvs-dci-doctor",
        "OPENCRVS_DCI_CLIENT_SECRET": generate_raw_key(),
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


def public_jwk_env_value(private_jwk: str, kid: str) -> str:
    jwk = json.loads(private_jwk)
    jwk.pop("d", None)
    jwk["kid"] = kid
    jwk["alg"] = jwk.get("alg") or "EdDSA"
    return json.dumps(jwk, separators=(",", ":"), sort_keys=True)


def generate_rs256_jwk(kid: str) -> str:
    """Generate an RSA private JWK using OpenSSL for eSignet client assertions."""

    try:
        key = subprocess.run(
            ["openssl", "genrsa", "2048"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        text = subprocess.run(
            ["openssl", "rsa", "-text", "-noout"],
            input=key.stdout,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("openssl is required to generate the RS256 eSignet RP key") from exc

    public_exponent = parse_public_exponent(text)
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": parse_rsa_component(text, "modulus"),
        "e": int_to_base64url(public_exponent),
        "d": parse_rsa_component(text, "privateExponent"),
        "p": parse_rsa_component(text, "prime1"),
        "q": parse_rsa_component(text, "prime2"),
        "dp": parse_rsa_component(text, "exponent1"),
        "dq": parse_rsa_component(text, "exponent2"),
        "qi": parse_rsa_component(text, "coefficient"),
    }
    return json.dumps(jwk, separators=(",", ":"), sort_keys=True)


def parse_public_exponent(text: str) -> int:
    match = re.search(r"^publicExponent:\s+(\d+)", text, flags=re.MULTILINE)
    if not match:
        raise ValueError("could not parse RSA public exponent from openssl output")
    return int(match.group(1))


def parse_rsa_component(text: str, label: str) -> str:
    match = re.search(
        rf"^{re.escape(label)}:\n((?:\s+(?:[0-9a-fA-F]{{2}}:)*[0-9a-fA-F]{{2}}:?\n)+)",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        raise ValueError(f"could not parse RSA component {label!r} from openssl output")
    hex_value = "".join(part.strip().replace(":", "") for part in match.group(1).splitlines())
    value = int(hex_value, 16)
    return int_to_base64url(value)


def int_to_base64url(value: int) -> str:
    if value < 0:
        raise ValueError("RSA components must be non-negative")
    size = max(1, (value.bit_length() + 7) // 8)
    encoded = base64.urlsafe_b64encode(value.to_bytes(size, "big")).decode("ascii")
    return encoded.rstrip("=")


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
            "issuer_public_jwk": "REGISTRY_NOTARY_ISSUER_PUBLIC_JWK",
            "rotated_issuer_jwk": "REGISTRY_NOTARY_ROTATED_ISSUER_JWK",
            "access_token_jwk": "REGISTRY_NOTARY_ACCESS_TOKEN_JWK",
            "esignet_rp_jwk": "REGISTRY_NOTARY_ESIGNET_RP_JWK",
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
