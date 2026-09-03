#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""Disposable local-development key material shared by Registry Mint demos."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def ed25519_jwk(kid: str) -> tuple[dict, dict]:
    """Return a disposable Ed25519 (private JWK, public JWK) pair."""
    private = ed25519.Ed25519PrivateKey.generate()
    x = b64(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    d = b64(
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x}
    return {**public_jwk, "d": d}, public_jwk


def p256_jwk() -> tuple[dict, dict]:
    """Return a disposable ES256 pair with an RFC 7638 key identifier."""
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.private_numbers()
    public_numbers = numbers.public_numbers
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": b64(public_numbers.x.to_bytes(32, "big")),
        "y": b64(public_numbers.y.to_bytes(32, "big")),
    }
    thumbprint_members = {
        member: public_jwk[member] for member in ("crv", "kty", "x", "y")
    }
    thumbprint = json.dumps(
        thumbprint_members, sort_keys=True, separators=(",", ":")
    ).encode()
    public_jwk["kid"] = b64(hashlib.sha256(thumbprint).digest())
    private_jwk = {
        **public_jwk,
        "d": b64(numbers.private_value.to_bytes(32, "big")),
    }
    return private_jwk, public_jwk


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    """Write public local-development material."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def write_secret(path: Path, text: str) -> Path:
    """Create or replace one secret without a wider intermediate mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    path.chmod(0o600)
    return path


def _new_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise SystemExit(f"refusing to replace existing output: {path}")


def _generate_p256(private_out: Path, public_out: Path) -> None:
    _new_output(private_out)
    _new_output(public_out)
    private, public = p256_jwk()
    write_secret(
        private_out, json.dumps(private, sort_keys=True, separators=(",", ":"))
    )
    write(public_out, json.dumps(public, sort_keys=True, separators=(",", ":")))


def _generate_secret(output: Path) -> None:
    _new_output(output)
    write_secret(output, secrets.token_hex(32))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    p256 = commands.add_parser("p256")
    p256.add_argument("--private-out", required=True, type=Path)
    p256.add_argument("--public-out", required=True, type=Path)
    secret = commands.add_parser("secret-hex")
    secret.add_argument("--out", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "p256":
        _generate_p256(args.private_out, args.public_out)
    elif args.command == "secret-hex":
        _generate_secret(args.out)
    else:  # pragma: no cover
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
