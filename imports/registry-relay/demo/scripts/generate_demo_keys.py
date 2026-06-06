#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Generate demo API key pairs for registry-relay local review.

Each persona gets a freshly generated raw key (32 random bytes, base64url-encoded,
no padding) and a SHA-256 fingerprint of that key. The fingerprint is what goes
in registry-relay config fingerprint refs; the raw key is what Bruno sends as Bearer.

The script also emits a local Ed25519 JWK for the focused Registry Notary
demo issuer.

Re-running always generates fresh keys. Old keys are not preserved.
"""

import argparse
import base64
import hashlib
import json
import os
import re
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
DEMO_ROOT = Path(__file__).resolve().parents[1]

AUTH_LIST_RE = re.compile(r"^(\s*)api_keys:\s*$")
ENTRY_ID_RE = re.compile(r"^(\s*)-\s+id:\s*(.+?)\s*$")
FINGERPRINT_NAME_RE = re.compile(r"^(\s*)name:\s*(.+?)\s*$")
FINGERPRINT_COMMITMENT_RE = re.compile(r"^(\s*)commitment:\s*(.+?)\s*$")


def yaml_scalar_text(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def generate_raw_key() -> str:
    """Return 32 random bytes as a base64url string with no padding."""
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_audit_hash_secret() -> str:
    """Return a per-deployment audit HMAC secret for local demos."""
    return secrets.token_urlsafe(48)


def generate_registry_notary_issuer_jwk() -> str:
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
    except Exception as exc:
        raise RuntimeError("openssl Ed25519 key generation failed") from exc
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


def credential_commitment(credential_id: str, credential_fingerprint: str) -> str:
    payload = {
        "product": "registry-relay",
        "credential_type": "api_key",
        "credential_id": credential_id,
        "fingerprint": credential_fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def refresh_config_commitments(pairs: list[tuple[str, str, str]]) -> int:
    fingerprints = {
        f"{env_var_name(persona)}_HASH": fingerprint
        for persona, _raw, fingerprint in pairs
    }
    updated = 0
    for path in sorted((DEMO_ROOT / "config").glob("*.yaml")):
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
    audit_hash_secret: str,
    registry_notary_issuer_jwk: str,
) -> str:
    lines = []
    for persona, raw, fingerprint in pairs:
        var = env_var_name(persona)
        lines.append(f"export {var}_RAW='{raw}'")
        lines.append(f"export {var}_HASH='{fingerprint}'")
    lines.append(f"export REGISTRY_RELAY_AUDIT_HASH_SECRET='{audit_hash_secret}'")
    lines.append(f"export REGISTRY_NOTARY_ISSUER_JWK='{registry_notary_issuer_jwk}'")
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


def write_secret_file(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(contents)
    finally:
        if fd != -1:
            os.close(fd)
    if not hasattr(os, "fchmod"):
        os.chmod(path, 0o600)


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
        audit_hash_secret = generate_audit_hash_secret()
        registry_notary_issuer_jwk = generate_registry_notary_issuer_jwk()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    export_block = format_export_block(
        pairs,
        audit_hash_secret,
        registry_notary_issuer_jwk,
    )
    bruno_env_block = format_bruno_env_block(pairs)

    if args.env_file:
        dest = Path(args.env_file)
        write_secret_file(dest, export_block)
        print(
            f"wrote {len(pairs)} key pairs, audit hash secret, and Registry Notary issuer JWK to {dest}",
            file=sys.stderr,
        )

        write_secret_file(BRUNO_ENV_PATH, bruno_env_block)
        print(f"wrote {len(pairs)} key entries to {BRUNO_ENV_PATH}", file=sys.stderr)
        updated_configs = refresh_config_commitments(pairs)
        if updated_configs:
            print(
                f"updated fingerprint commitments in {updated_configs} demo config files",
                file=sys.stderr,
            )
    else:
        print(export_block, end="")

    if args.bruno:
        print(bruno_env_block, end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
