#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Generate demo API key pairs for registry-relay local review.

Each persona gets a freshly generated raw key (32 random bytes, base64url-encoded,
no padding) and a SHA-256 fingerprint of that key. The fingerprint is what goes
in the registry-relay config's hash_env; the raw key is what Bruno sends as Bearer.

The script also emits the internal HMAC binding key used by evidence
verification rulesets and a local Ed25519 JWK for the focused Evidence Server
demo issuer.

Re-running always generates fresh keys. Old keys are not preserved.
"""

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

PERSONAS = [
    "catalog_viewer",
    "planning_analyst",
    "casework_system",
    "verification_service",
    "linkage_service",
    "operations_admin",
]

# Bruno env variable names mirror the spec's Bruno env-vars table.
# Maps persona name -> Bruno var name.
BRUNO_VAR_MAP = {
    "catalog_viewer": "metadataKey",
    "planning_analyst": "aggregateKey",
    "casework_system": "rowsKey",
    "verification_service": "evidenceVerificationKey",
    "linkage_service": "linkageKey",
    "operations_admin": "adminKey",
}

# Bruno reads a `.env` at the collection root and exposes its keys to environment
# files via `{{process.env.NAME}}`. We mirror demo/.env.local's variable names
# (PERSONA_RAW) here so one rotation seeds both consumers.
BRUNO_ENV_PATH = Path("bruno/registry-relay-demo/.env")

FALLBACK_REGISTRY_WITNESS_ISSUER_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    "alg": "EdDSA",
}


def generate_raw_key() -> str:
    """Return 32 random bytes as a base64url string with no padding."""
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_claim_verification_binding_key() -> str:
    """Return the configured hex: form expected by the ruleset hasher."""
    return f"hex:{secrets.token_bytes(32).hex()}"


def generate_registry_witness_issuer_jwk() -> str:
    """Return a private Ed25519 JWK for local SD-JWT VC issuance demos."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "issuer.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            text = subprocess.check_output(
                ["openssl", "pkey", "-in", str(key_path), "-text", "-noout"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            private_hex = parse_openssl_hex_block(text, "priv")
            public_hex = parse_openssl_hex_block(text, "pub")
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "d": b64url(bytes.fromhex(private_hex)),
                "x": b64url(bytes.fromhex(public_hex)),
                "alg": "EdDSA",
            }
    except Exception:
        jwk = FALLBACK_REGISTRY_WITNESS_ISSUER_JWK
    return json.dumps(jwk, separators=(",", ":"))


def parse_openssl_hex_block(text: str, label: str) -> str:
    collecting = False
    chunks: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == f"{label}:":
            collecting = True
            continue
        if collecting and stripped.endswith(":") and not all(
            part in "0123456789abcdefABCDEF" for part in stripped.replace(":", "")
        ):
            break
        if collecting:
            chunks.append(stripped.replace(":", "").replace(" ", ""))
    value = "".join(chunks)
    if len(value) != 64:
        raise RuntimeError(f"unexpected Ed25519 {label} length from openssl")
    return value


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def env_var_name(persona: str) -> str:
    return persona.upper()


def generate_pairs() -> list[tuple[str, str, str]]:
    """Return [(persona, raw_key, fingerprint), ...].

    The raw key has 256 bits of entropy; the stored value is a fast
    fingerprint, not a password hash.
    """
    pairs = []
    for persona in PERSONAS:
        raw = generate_raw_key()
        fingerprint = f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"
        pairs.append((persona, raw, fingerprint))
    return pairs


def self_verify(pairs: list[tuple[str, str, str]]) -> None:
    """Verify every (raw, fingerprint) pair before emitting output."""
    for persona, raw, fingerprint in pairs:
        expected = f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"
        if fingerprint != expected:
            raise RuntimeError(
                f"self-verification failed for persona {persona!r}; aborting"
            )


def format_export_block(
    pairs: list[tuple[str, str, str]],
    claim_verification_binding_key: str,
    registry_witness_issuer_jwk: str,
) -> str:
    lines = []
    for persona, raw, fingerprint in pairs:
        var = env_var_name(persona)
        lines.append(f"export {var}_RAW='{raw}'")
        lines.append(f"export {var}_HASH='{fingerprint}'")
    lines.append(
        f"export CLAIM_VERIFICATION_BINDING_KEY='{claim_verification_binding_key}'"
    )
    lines.append(f"export REGISTRY_WITNESS_ISSUER_JWK='{registry_witness_issuer_jwk}'")
    return "\n".join(lines) + "\n"


def format_bruno_env_block(pairs: list[tuple[str, str, str]]) -> str:
    """
    Emit a `.env`-style block for the Bruno collection root.

    Lines are `<PERSONA>_RAW=<raw_key>`. Bruno reads this file at collection load
    and exposes the values to environment files via `{{process.env.<NAME>}}`.
    The variable names mirror demo/.env.local's PERSONA_RAW so a single rotation
    seeds both the server (via `source demo/.env.local`) and Bruno.
    """
    lines = []
    for persona, raw, _fingerprint in pairs:
        var = env_var_name(persona)
        lines.append(f"{var}_RAW={raw}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--bruno",
        action="store_true",
        help="also print the Bruno-collection .env contents to stdout (preview)",
    )
    parser.add_argument(
        "--env-file",
        nargs="?",
        const="demo/.env.local",
        metavar="PATH",
        help=(
            "write the export-style block to PATH and write the Bruno-collection "
            f"env file to {BRUNO_ENV_PATH} (default PATH when flag is given "
            "without value: demo/.env.local)"
        ),
    )
    args = parser.parse_args()

    try:
        pairs = generate_pairs()
        self_verify(pairs)
        claim_verification_binding_key = generate_claim_verification_binding_key()
        registry_witness_issuer_jwk = generate_registry_witness_issuer_jwk()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    export_block = format_export_block(
        pairs, claim_verification_binding_key, registry_witness_issuer_jwk
    )
    bruno_env_block = format_bruno_env_block(pairs)

    if args.env_file:
        dest = Path(args.env_file)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(export_block, encoding="utf-8")
        print(
            f"wrote {len(pairs)} key pairs, evidence-verification binding key, and Evidence Server issuer JWK to {dest}",
            file=sys.stderr,
        )

        BRUNO_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
        BRUNO_ENV_PATH.write_text(bruno_env_block, encoding="utf-8")
        print(f"wrote {len(pairs)} key entries to {BRUNO_ENV_PATH}", file=sys.stderr)
    else:
        print(export_block, end="")

    if args.bruno:
        print(bruno_env_block, end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
