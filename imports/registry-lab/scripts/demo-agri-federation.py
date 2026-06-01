#!/usr/bin/env python3
"""Federated delegated-evaluation demo for the NAgDI agriculture Notary."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from agri_demo_common import (
    DEFAULT_CORRELATION_ID,
    DEMO_ROOT,
    LIVESTOCK_PURPOSE,
    PURPOSE,
    DemoError,
    env,
    load_dotenv,
    parse_dotenv_file,
    prepare_output_dir,
    save_json,
)

FEDERATION_PROTOCOL = "registry-notary-federation/v0.1"
REQUEST_TYP = "registry-notary-request+jwt"
RESPONSE_TYP = "registry-notary-response+jwt"
CLIENT_NODE_ID = "did:web:nagdi-benefits.demo.example.gov"
CLIENT_ISSUER = "https://nagdi-benefits.demo.example.gov"
CLIENT_KID = "did:web:nagdi-benefits.demo.example.gov#federation-client-1"
AGRI_NODE_ID = "did:web:nagdi-agriculture-notary.demo.example.gov"
AGRI_ISSUER = "https://nagdi-agriculture-notary.demo.example.gov"
AGRI_RESPONSE_KID = "did:web:nagdi-agriculture-notary.demo.example.gov#federation-response-1"
ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def dotenv_value(name: str, path: Path = DEMO_ROOT / ".env") -> str | None:
    return parse_dotenv_file(path).get(name)


def secret_json_env(name: str) -> dict[str, Any]:
    value = dotenv_value(name) or env(name)
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise DemoError(f"{name} is not valid JSON; regenerate .env with scripts/generate-demo-secrets.py") from exc


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_ulid() -> str:
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def pem(label: str, der: bytes) -> str:
    body = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def private_pem_from_jwk(jwk: dict[str, Any]) -> str:
    seed = b64url_decode(str(jwk["d"]))
    if len(seed) != 32:
        raise DemoError("Ed25519 private JWK seed must be 32 bytes")
    return pem("PRIVATE KEY", bytes.fromhex("302e020100300506032b657004220420") + seed)


def public_pem_from_jwk(jwk: dict[str, Any]) -> str:
    public = b64url_decode(str(jwk["x"]))
    if len(public) != 32:
        raise DemoError("Ed25519 public JWK x coordinate must be 32 bytes")
    return pem("PUBLIC KEY", bytes.fromhex("302a300506032b6570032100") + public)


def openssl_required() -> None:
    if shutil.which("openssl") is None:
        raise DemoError("openssl is required for Ed25519 JWS signing and verification")


def sign_compact_jws(private_jwk: dict[str, Any], kid: str, typ: str, payload: dict[str, Any]) -> str:
    openssl_required()
    header = {"alg": "EdDSA", "typ": typ, "kid": kid}
    signing_input = ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
            b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        ]
    ).encode("ascii")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "key.pem"
        input_path = tmp_path / "input"
        sig_path = tmp_path / "signature"
        key_path.write_text(private_pem_from_jwk(private_jwk), encoding="utf-8")
        input_path.write_bytes(signing_input)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(input_path),
                "-out",
                str(sig_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return f"{signing_input.decode('ascii')}.{b64url(sig_path.read_bytes())}"


def verify_compact_jws(public_jwk: dict[str, Any], token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    openssl_required()
    parts = token.split(".")
    if len(parts) != 3:
        raise DemoError("response is not compact JWS")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = b64url_decode(parts[2])
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "key.pem"
        input_path = tmp_path / "input"
        sig_path = tmp_path / "signature"
        key_path.write_text(public_pem_from_jwk(public_jwk), encoding="utf-8")
        input_path.write_bytes(signing_input)
        sig_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(input_path),
                "-sigfile",
                str(sig_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if result.returncode != 0:
        raise DemoError("response JWS signature verification failed")
    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    return header, payload


def request_jwt(base_url: str, token: str) -> tuple[int, str, dict[str, str]]:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "federation/v1/evaluations")
    req = urllib.request.Request(
        url,
        data=token.encode("ascii"),
        headers={
            "Accept": "application/jwt",
            "Content-Type": "application/jwt",
            "x-request-id": os.environ.get("DEMO_CORRELATION_ID", DEFAULT_CORRELATION_ID),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)
    except urllib.error.URLError as exc:
        raise DemoError(f"POST {url} failed: {exc}") from exc


def federation_payload(
    *,
    jti: str,
    profile: str,
    purpose: str,
    target_id: str,
    target_identifier_scheme: str,
    claim_id: str,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": CLIENT_ISSUER,
        "sub": CLIENT_NODE_ID,
        "aud": AGRI_NODE_ID,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": jti,
        "protocol": FEDERATION_PROTOCOL,
        "action": "evaluate",
        "profile": profile,
        "purpose": purpose,
        "request": {
            "target": {
                "type": "Herd" if target_identifier_scheme == "herd_id" else "Farmer",
                "identifiers": [{"scheme": target_identifier_scheme, "value": target_id}],
            },
            "claims": [claim_id],
        },
    }


def parse_problem(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def verified_response_payload(response_key: dict[str, Any], raw: str, request_jti: str, profile: str) -> dict[str, Any]:
    header, payload = verify_compact_jws(response_key, raw)
    if header.get("typ") != RESPONSE_TYP or header.get("alg") != "EdDSA" or header.get("kid") != AGRI_RESPONSE_KID:
        raise DemoError(f"unexpected response JWT header: {header}")
    expected = {
        "iss": AGRI_ISSUER,
        "sub": AGRI_NODE_ID,
        "aud": CLIENT_NODE_ID,
        "request_jti": request_jti,
        "protocol": FEDERATION_PROTOCOL,
        "action": "evaluate",
        "profile": profile,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise DemoError(f"response payload {key}={payload.get(key)!r}, expected {value!r}")
    if "result" not in payload:
        raise DemoError(f"response payload has no result: {payload}")
    subject_hash = payload["result"].get("subject_ref", {}).get("hash", "")
    if not isinstance(subject_hash, str) or not subject_hash.startswith("hmac-sha256:"):
        raise DemoError(f"response subject hash is not pairwise HMAC: {subject_hash!r}")
    serialized = json.dumps(payload, sort_keys=True)
    forbidden_fragments = ["voucher_snapshot", "livestock_snapshot", "source_records", "raw_evidence"]
    leaked = [fragment for fragment in forbidden_fragments if fragment in serialized]
    if leaked:
        raise DemoError(f"response appears to contain raw source details: {leaked}")
    return payload


def call_profile(
    notary_url: str,
    client_key: dict[str, Any],
    response_key: dict[str, Any],
    out: Path,
    label: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    token = sign_compact_jws(client_key, CLIENT_KID, REQUEST_TYP, payload)
    save_json(out / f"{label}-request-payload.json", payload)
    status, raw, headers = request_jwt(notary_url, token)
    save_json(out / f"{label}-http-response.json", {"status": status, "headers": headers, "body": raw})
    if status != 200:
        raise DemoError(f"{label} returned HTTP {status}: {raw}")
    verified = verified_response_payload(response_key, raw, str(payload["jti"]), str(payload["profile"]))
    save_json(out / f"{label}-verified-response.json", verified)
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEMO_ROOT / "output" / "agri-federation",
    )
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    notary_url = env("AGRI_WITNESS_URL", "http://127.0.0.1:4342")
    client_key = secret_json_env("AGRI_FEDERATION_CLIENT_JWK")
    response_key = secret_json_env("AGRI_FEDERATION_RESPONSE_JWK")

    print("NAgDI federated delegated-evaluation demo")
    print(f"  notary: {notary_url}")
    print(f"  artifacts: {out}")

    voucher_payload = federation_payload(
        jti=new_ulid(),
        profile="climate_smart_input_voucher_predicate",
        purpose=PURPOSE,
        target_id="FARMER-1001",
        target_identifier_scheme="farmer_id",
        claim_id="eligible-for-climate-smart-input-voucher",
    )
    voucher = call_profile(notary_url, client_key, response_key, out, "voucher-eligible", voucher_payload)
    voucher_claim = voucher["result"]["claims"]["eligible-for-climate-smart-input-voucher"]
    if voucher_claim.get("satisfied") is not True:
        raise DemoError(f"FARMER-1001 should be eligible, got {voucher_claim}")

    denied_payload = federation_payload(
        jti=new_ulid(),
        profile="climate_smart_input_voucher_predicate",
        purpose=PURPOSE,
        target_id="FARMER-1002",
        target_identifier_scheme="farmer_id",
        claim_id="eligible-for-climate-smart-input-voucher",
    )
    denied = call_profile(notary_url, client_key, response_key, out, "voucher-not-eligible", denied_payload)
    denied_claim = denied["result"]["claims"]["eligible-for-climate-smart-input-voucher"]
    if denied_claim.get("satisfied") is not False:
        raise DemoError(f"FARMER-1002 should not be eligible, got {denied_claim}")

    livestock_payload = federation_payload(
        jti=new_ulid(),
        profile="livestock_movement_permit_predicate",
        purpose=LIVESTOCK_PURPOSE,
        target_id="HERD-2001",
        target_identifier_scheme="herd_id",
        claim_id="eligible-for-livestock-movement-permit",
    )
    livestock = call_profile(notary_url, client_key, response_key, out, "livestock-eligible", livestock_payload)
    livestock_claim = livestock["result"]["claims"]["eligible-for-livestock-movement-permit"]
    if livestock_claim.get("satisfied") is not True:
        raise DemoError(f"HERD-2001 should be eligible, got {livestock_claim}")

    replay_token = sign_compact_jws(client_key, CLIENT_KID, REQUEST_TYP, voucher_payload)
    replay_status, replay_body, replay_headers = request_jwt(notary_url, replay_token)
    save_json(
        out / "voucher-replay-denial.json",
        {"status": replay_status, "headers": replay_headers, "body": parse_problem(replay_body)},
    )
    if replay_status != 409:
        raise DemoError(f"replayed request should return 409, got {replay_status}: {replay_body}")

    bad_purpose = dict(voucher_payload)
    bad_purpose["jti"] = new_ulid()
    bad_purpose["purpose"] = "https://demo.example.gov/purpose/nagdi/not-allowed"
    bad_token = sign_compact_jws(client_key, CLIENT_KID, REQUEST_TYP, bad_purpose)
    bad_status, bad_body, bad_headers = request_jwt(notary_url, bad_token)
    save_json(
        out / "unsupported-purpose-denial.json",
        {"status": bad_status, "headers": bad_headers, "body": parse_problem(bad_body)},
    )
    if bad_status != 403:
        raise DemoError(f"unsupported purpose should return 403, got {bad_status}: {bad_body}")

    composed = {
        "artifact_type": "demo.nagdi-federated-composed-decision.v1",
        "computed_by": CLIENT_NODE_ID,
        "source_mode": "signed peer evaluation responses",
        "inputs": {
            "voucher_request_jti": voucher_payload["jti"],
            "livestock_request_jti": livestock_payload["jti"],
            "voucher_evaluation_id": voucher["result"]["evaluation_id"],
            "livestock_evaluation_id": livestock["result"]["evaluation_id"],
        },
        "decision": {
            "farmer_input_support": "approved" if voucher_claim.get("satisfied") is True else "not_approved",
            "livestock_movement_permit": "approved" if livestock_claim.get("satisfied") is True else "not_approved",
        },
        "boundary": {
            "raw_registry_rows_embedded": False,
            "serving_notary": AGRI_NODE_ID,
        },
    }
    save_json(out / "composed-benefits-decision.json", composed)
    print("federated agriculture demo OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"demo-agri-federation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
