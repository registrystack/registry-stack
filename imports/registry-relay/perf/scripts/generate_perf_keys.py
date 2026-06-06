#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""
Synthetic API-key generator for Registry Relay performance testing.

Hashing scheme: Registry Relay expects env vars holding sha256:<64 lowercase hex chars>
where the hex is SHA-256(raw_token_bytes). This is stdlib hashlib.

The `cryptography` dep is used solely to derive the Ed25519 public half from
the freshly generated private seed when assembling the provenance JWK.

Generates 5 tokens, writes an env file, and prints only the variable names and
the output path. Raw tokens and hashes are never printed to stdout.

Also emits:

- REGISTRY_RELAY_AUDIT_HASH_SECRET: per-deployment audit HMAC secret used to
  hash sensitive audit identifiers.
- REGISTRY_RELAY_PROVENANCE_JWK: JSON-encoded Ed25519 private JWK used by
  the provenance signer to issue signed VC-JWT responses.

If the env file already exists and is being reused (--force not set), this
script exits without writing. When --force is set a new file is written with
fresh values for all variables (tokens, audit secret, signing JWK).

Usage:
    uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env
    uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env --force
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Key definitions: (id, fingerprint_env_var, scopes list or None)
# Scopes are informational for the comment; the env file carries the hash only.
KEY_DEFS = [
    ("perf_rows",               "PERF_ROWS_KEY_HASH",               ["clinic_capacity:rows"]),
    ("perf_metadata",           "PERF_METADATA_KEY_HASH",           ["clinic_capacity:metadata"]),
    ("perf_aggregate",          "PERF_AGGREGATE_KEY_HASH",          ["clinic_capacity:aggregate"]),
    ("perf_no_scope",           "PERF_NO_SCOPE_KEY_HASH",           ["other:metadata"]),
    ("perf_evidence_verification", "PERF_EVIDENCE_VERIFICATION_KEY_HASH", ["clinic_capacity:evidence_verification"]),
]

INVALID_TOKEN_VALUE = "not-a-real-token-xxxx"
PERF_ROOT = Path(__file__).resolve().parents[1]

AUTH_LIST_RE = re.compile(r"^(\s*)api_keys:\s*$")
ENTRY_ID_RE = re.compile(r"^(\s*)-\s+id:\s*(.+?)\s*$")
FINGERPRINT_NAME_RE = re.compile(r"^(\s*)name:\s*(.+?)\s*$")
FINGERPRINT_COMMITMENT_RE = re.compile(r"^(\s*)commitment:\s*(.+?)\s*$")


def yaml_scalar_text(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def sha256_fingerprint(raw: str) -> str:
    """Return sha256:<64 lowercase hex chars> of the UTF-8-encoded raw token."""
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def credential_commitment(credential_id: str, credential_fingerprint: str) -> str:
    payload = {
        "product": "registry-relay",
        "credential_type": "api_key",
        "credential_id": credential_id,
        "fingerprint": credential_fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def generate_token() -> str:
    """Return a URL-safe random token (~32 bytes of entropy, 43 chars)."""
    return secrets.token_urlsafe(32)


def generate_audit_hash_secret() -> str:
    """Return a per-deployment audit HMAC secret for perf smoke runs."""
    return secrets.token_urlsafe(48)


def _b64url(raw: bytes) -> str:
    """Unpadded base64url encoding per RFC 7515."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# kid for the perf provenance signer. Must match the fragment in
# provenance.issuer.verification_method_id in perf/config/*.yaml.
PROVENANCE_KID = "perf-evidence-verification-v1"


def generate_provenance_jwk() -> str:
    """Return a JSON-encoded Ed25519 private JWK with kid + alg fields.

    The value is consumed by the software signer via
    `provenance.issuer.signer.jwk_env`. Format matches docs/provenance.md.
    """
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": PROVENANCE_KID,
        "d": _b64url(seed),
        "x": _b64url(public),
    }
    # Compact, no whitespace. The env var is a single JSON string.
    return json.dumps(jwk, separators=(",", ":"))


def build_env_lines(
    tokens: dict[str, str],
    audit_hash_secret: str,
    provenance_jwk: str,
) -> list[str]:
    """Build the env file lines from the token map. Never includes raw tokens."""
    lines = [
        "# Registry Relay perf test environment",
        "# Generated by generate_perf_keys.py. Do NOT commit this file.",
        "#",
        "# Token variables (raw bearer tokens for k6 / curl)",
        f"REGISTRY_RELAY_TOKEN={tokens['perf_rows']}",
        f"REGISTRY_RELAY_TOKEN_METADATA={tokens['perf_metadata']}",
        f"REGISTRY_RELAY_TOKEN_AGGREGATE={tokens['perf_aggregate']}",
        f"REGISTRY_RELAY_TOKEN_NO_SCOPE={tokens['perf_no_scope']}",
        f"REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION={tokens['perf_evidence_verification']}",
        f"REGISTRY_RELAY_TOKEN_INVALID={INVALID_TOKEN_VALUE}",
        "#",
        "# Routing defaults",
        "REGISTRY_RELAY_BASE_URL=http://127.0.0.1:18080",
        "REGISTRY_RELAY_DATASET_ID=clinic_capacity",
        "REGISTRY_RELAY_ENTITY=facility",
        "#",
        "# SHA-256 fingerprints consumed by Registry Relay at startup",
        "# (sha256:<64 lowercase hex chars> of the raw token above)",
    ]
    for key_id, hash_env, _ in KEY_DEFS:
        fingerprint = sha256_fingerprint(tokens[key_id])
        lines.append(f"{hash_env}={fingerprint}")
    lines += [
        "#",
        "# Audit HMAC secret for sensitive audit identifiers.",
        "# Must remain stable across server restarts for consistent audit lookups.",
        f"REGISTRY_RELAY_AUDIT_HASH_SECRET={audit_hash_secret}",
        "#",
        "# Provenance signing key: JSON-encoded Ed25519 private JWK.",
        "# Read by the software signer at startup. NEVER commit this file.",
        f"REGISTRY_RELAY_PROVENANCE_JWK={provenance_jwk}",
    ]
    return lines


def refresh_config_commitments(tokens: dict[str, str]) -> int:
    fingerprints = {
        hash_env: sha256_fingerprint(tokens[key_id])
        for key_id, hash_env, _scopes in KEY_DEFS
    }
    updated = 0
    for path in sorted((PERF_ROOT / "config").glob("*.yaml")):
        if refresh_config_file(path, fingerprints):
            updated += 1
    return updated


def refresh_config_file(path: Path, fingerprints: dict[str, str]) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    rewritten: list[str] = []
    index = 0
    changed = False
    in_api_keys = False
    list_indent = 0
    while index < len(lines):
        line = lines[index]
        if match := AUTH_LIST_RE.match(line):
            in_api_keys = True
            list_indent = len(match.group(1))
            rewritten.append(line)
            index += 1
            continue
        if in_api_keys:
            if line.strip() and leading_spaces(line) <= list_indent:
                in_api_keys = False
                rewritten.append(line)
                index += 1
                continue
            if entry_match := ENTRY_ID_RE.match(line):
                entry_indent = len(entry_match.group(1))
                block_end = index + 1
                while block_end < len(lines):
                    candidate = lines[block_end]
                    if candidate.strip() and leading_spaces(candidate) <= list_indent:
                        break
                    if ENTRY_ID_RE.match(candidate) and leading_spaces(candidate) == entry_indent:
                        break
                    block_end += 1
                block, block_changed = refresh_credential_block(
                    lines[index:block_end],
                    yaml_scalar_text(entry_match.group(2)),
                    fingerprints,
                )
                rewritten.extend(block)
                changed = changed or block_changed
                index = block_end
                continue
        rewritten.append(line)
        index += 1
    if changed:
        path.write_text("".join(rewritten), encoding="utf-8")
    return changed


def refresh_credential_block(
    block: list[str],
    credential_id: str,
    fingerprints: dict[str, str],
) -> tuple[list[str], bool]:
    credential_id = yaml_scalar_text(credential_id)
    env_name = None
    commitment_index = None
    for index, line in enumerate(block):
        if name_match := FINGERPRINT_NAME_RE.match(line):
            env_name = yaml_scalar_text(name_match.group(2))
        if FINGERPRINT_COMMITMENT_RE.match(line):
            commitment_index = index
    if env_name is None or commitment_index is None or env_name not in fingerprints:
        return block, False
    commitment = credential_commitment(credential_id, fingerprints[env_name])
    commitment_match = FINGERPRINT_COMMITMENT_RE.match(block[commitment_index])
    assert commitment_match is not None
    new_line = f"{commitment_match.group(1)}commitment: {commitment}\n"
    if block[commitment_index] == new_line:
        return block, False
    rewritten = list(block)
    rewritten[commitment_index] = new_line
    return rewritten, True


def leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic API keys for Registry Relay perf testing."
    )
    parser.add_argument(
        "--env-file",
        default="target/perf/perf.env",
        help="Destination env file (default: target/perf/perf.env).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing env file.",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)

    if env_path.exists() and not args.force:
        print(
            f"Error: {env_path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    env_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate one random token per keyed entry, the audit secret, and the
    # Ed25519 private JWK for the provenance signer.
    tokens: dict[str, str] = {key_id: generate_token() for key_id, _, _ in KEY_DEFS}
    audit_hash_secret = generate_audit_hash_secret()
    provenance_jwk = generate_provenance_jwk()

    env_lines = build_env_lines(tokens, audit_hash_secret, provenance_jwk)
    env_content = "\n".join(env_lines) + "\n"

    env_path.write_text(env_content, encoding="utf-8")
    # Restrict to owner read/write only.
    os.chmod(env_path, 0o600)
    updated_configs = refresh_config_commitments(tokens)

    # Report only the path and variable names, never values.
    print(f"Wrote: {env_path}")
    if updated_configs:
        print(f"Updated fingerprint commitments in {updated_configs} perf config files")
    print("Variables written:")
    var_names = [
        "REGISTRY_RELAY_TOKEN",
        "REGISTRY_RELAY_TOKEN_METADATA",
        "REGISTRY_RELAY_TOKEN_AGGREGATE",
        "REGISTRY_RELAY_TOKEN_NO_SCOPE",
        "REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION",
        "REGISTRY_RELAY_TOKEN_INVALID",
        "REGISTRY_RELAY_BASE_URL",
        "REGISTRY_RELAY_DATASET_ID",
        "REGISTRY_RELAY_ENTITY",
    ] + [hash_env for _, hash_env, _ in KEY_DEFS] + [
        "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        "REGISTRY_RELAY_PROVENANCE_JWK",
    ]
    for name in var_names:
        print(f"  {name}")


if __name__ == "__main__":
    main()
