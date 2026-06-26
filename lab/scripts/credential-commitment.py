#!/usr/bin/env python3
"""Compute credential fingerprints and canonical commitments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ALLOWED_CREDENTIAL_TYPES = {
    "registry-notary": {"api_key", "bearer_token"},
    "registry-relay": {"api_key"},
}

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"


def credential_commitment(
    product: str,
    credential_type: str,
    credential_id: str,
    credential_fingerprint: str,
) -> str:
    validate_product_type(product, credential_type)
    validate_credential_id(credential_id)
    validate_fingerprint(credential_fingerprint)

    payload = {
        "product": product,
        "credential_type": credential_type,
        "credential_id": credential_id,
        "fingerprint": credential_fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def raw_env_value(env_name: str) -> str:
    validate_env_name(env_name)
    try:
        return os.environ[env_name]
    except KeyError:
        raise ValueError(f"{env_name} is not set") from None


def validate_product_type(product: str, credential_type: str) -> None:
    allowed_types = ALLOWED_CREDENTIAL_TYPES.get(product)
    if allowed_types is None:
        allowed_products = ", ".join(sorted(ALLOWED_CREDENTIAL_TYPES))
        raise ValueError(f"unsupported product {product!r}; allowed: {allowed_products}")
    if credential_type not in allowed_types:
        allowed = ", ".join(sorted(allowed_types))
        raise ValueError(
            f"unsupported credential type {credential_type!r} for {product}; "
            f"allowed: {allowed}"
        )


def validate_credential_id(credential_id: str) -> None:
    if credential_id == "":
        raise ValueError("credential id must not be empty")


def validate_env_name(env_name: str) -> None:
    if not ENV_NAME_RE.fullmatch(env_name):
        raise ValueError(f"invalid environment variable name {env_name!r}")


def validate_fingerprint(value: str) -> None:
    if not FINGERPRINT_RE.fullmatch(value):
        raise ValueError("fingerprint must match sha256:<64 lowercase hex characters>")


def fingerprint_command(args: argparse.Namespace) -> int:
    print(fingerprint(raw_env_value(args.raw_env)))
    return 0


def commitment_command(args: argparse.Namespace) -> int:
    print(
        credential_commitment(
            args.product,
            args.credential_type,
            args.credential_id,
            args.fingerprint,
        )
    )
    return 0


def env_pair_command(args: argparse.Namespace) -> int:
    raw = raw_env_value(args.raw_env)
    fp = fingerprint(raw)
    commitment = credential_commitment(
        args.product,
        args.credential_type,
        args.credential_id,
        fp,
    )
    print(f"{args.raw_env}_HASH={fp}")
    print(f"{args.raw_env}_COMMITMENT={commitment}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute credential fingerprints and commitments."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    fingerprint_parser = subparsers.add_parser("fingerprint")
    fingerprint_parser.add_argument("--raw-env", required=True)
    fingerprint_parser.set_defaults(func=fingerprint_command)

    commitment_parser = subparsers.add_parser("commitment")
    commitment_parser.add_argument("--product", required=True)
    commitment_parser.add_argument("--credential-type", required=True)
    commitment_parser.add_argument("--credential-id", required=True)
    commitment_parser.add_argument("--fingerprint", required=True)
    commitment_parser.set_defaults(func=commitment_command)

    env_pair_parser = subparsers.add_parser("env-pair")
    env_pair_parser.add_argument("--product", required=True)
    env_pair_parser.add_argument("--credential-type", required=True)
    env_pair_parser.add_argument("--credential-id", required=True)
    env_pair_parser.add_argument("--raw-env", required=True)
    env_pair_parser.set_defaults(func=env_pair_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
