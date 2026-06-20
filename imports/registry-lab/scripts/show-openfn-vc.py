#!/usr/bin/env python3
"""Issue and inspect the civil sidecar SD-JWT VC demo credential."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from dotenv_util import load_dotenv_file

DEMO_ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "https://demo.example.gov/purpose/openfn-sidecar-demo"
SD_JWT_FORMAT = "application/dc+sd-jwt"
CLAIM_ID = "date-of-birth"
PROFILE_ID = "openfn_civil_sd_jwt"


class DemoError(RuntimeError):
    pass


def load_dotenv(path: Path) -> None:
    if not path.exists():
        raise DemoError(f"missing {path}; run scripts/generate-demo-secrets.py first")
    load_dotenv_file(path)


def env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise DemoError(f"missing required environment variable: {name}")
    return value


def post_json(url: str, token: str, body: dict[str, Any], purpose: str | None = None) -> Any:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }
    if purpose:
        headers["Data-Purpose"] = purpose
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise DemoError(f"POST {url} returned HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise DemoError(f"POST {url} failed: {error.reason}") from error


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_json_segment(value: str) -> Any:
    return json.loads(b64url_decode(value))


def decode_disclosure(value: str) -> dict[str, Any]:
    salt, name, content = json.loads(b64url_decode(value))
    return {
        "name": name,
        "salt": salt,
        "value": content,
        "digest": base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("="),
    }


def print_json(title: str, value: Any) -> None:
    print(f"\n{title}:")
    print(json.dumps(value, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", default="person-123")
    parser.add_argument("--notary-url", default="http://127.0.0.1:4324")
    parser.add_argument("--env-file", type=Path, default=DEMO_ROOT / ".env")
    args = parser.parse_args()

    load_dotenv(args.env_file)
    token = env("CIVIL_EVIDENCE_CLIENT_BEARER")
    base_url = args.notary_url.rstrip("/")

    evaluation = post_json(
        f"{base_url}/v1/evaluations",
        token,
        {
            "target": {
                "type": "Person",
                "identifiers": [{"scheme": "national_id", "value": args.subject}],
            },
            "claims": [CLAIM_ID],
            "disclosure": "value",
            "format": SD_JWT_FORMAT,
        },
        purpose=PURPOSE,
    )
    evaluation_id = evaluation["results"][0]["evaluation_id"]

    issued = post_json(
        f"{base_url}/v1/credentials",
        token,
        {
            "evaluation_id": evaluation_id,
            "format": SD_JWT_FORMAT,
            "credential_profile": PROFILE_ID,
            "disclosure": "value",
            "claims": [CLAIM_ID],
        },
    )

    credential = issued["credential"]
    parts = credential.split("~")
    issuer_signed_jwt = issued.get("issuer_signed_jwt") or parts[0]
    disclosures = issued.get("disclosures") or [part for part in parts[1:] if part]

    jwt_segments = issuer_signed_jwt.split(".")
    if len(jwt_segments) != 3:
        raise DemoError("issuer-signed JWT is not a 3-segment compact JWT")
    header = decode_json_segment(jwt_segments[0])
    payload = decode_json_segment(jwt_segments[1])
    decoded_disclosures = [decode_disclosure(value) for value in disclosures]
    payload_digests = set(payload.get("_sd") or [])
    disclosure_digests = {item["digest"] for item in decoded_disclosures}

    print(f"Evaluation ID: {evaluation_id}")
    print("\nIssuer-signed JWT for jwt.io:")
    print(issuer_signed_jwt)
    print_json("JWT header", header)
    print_json("JWT payload", payload)
    print_json("Disclosed values", decoded_disclosures)
    print_json(
        "Disclosure digest check",
        {
            "payload_sd": sorted(payload_digests),
            "disclosure_digests": sorted(disclosure_digests),
            "all_disclosures_bound": disclosure_digests.issubset(payload_digests),
        },
    )
    print("\nFull SD-JWT VC compact credential:")
    print(credential)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
