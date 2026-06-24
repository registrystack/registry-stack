#!/usr/bin/env python3
"""Federated delegated-evaluation demo for the default Registry Lab topology."""

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
    DEMO_ROOT,
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
PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"
CLIENT_NODE_ID = "did:web:benefits.demo.example.gov"
CLIENT_ISSUER = "https://benefits.demo.example.gov"
CLIENT_KID = "did:web:benefits.demo.example.gov#federation-client-1"
CIVIL_NODE_ID = "did:web:civil-notary.demo.example.gov"
CIVIL_ISSUER = "https://civil-notary.demo.example.gov"
CIVIL_RESPONSE_KID = "did:web:civil-notary.demo.example.gov#federation-response-1"
SOCIAL_NODE_ID = "did:web:social-protection-notary.demo.example.gov"
SOCIAL_ISSUER = "https://social-protection-notary.demo.example.gov"
SOCIAL_RESPONSE_KID = "did:web:social-protection-notary.demo.example.gov#federation-response-1"
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


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def new_ulid() -> str:
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


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
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(input_path), "-out", str(sig_path)],
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
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin", "-in", str(input_path), "-sigfile", str(sig_path)],
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
        headers={"Accept": "application/jwt", "Content-Type": "application/jwt"},
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
    audience: str,
    jti: str,
    profile: str,
    target_id: str,
    target_identifier_scheme: str,
    claim_id: str,
    purpose: str = PURPOSE,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": CLIENT_ISSUER,
        "sub": CLIENT_NODE_ID,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": jti,
        "protocol": FEDERATION_PROTOCOL,
        "action": "evaluate",
        "profile": profile,
        "purpose": purpose,
        "request": {
            "subject": {"id": target_id, "id_type": target_identifier_scheme},
            "claims": [claim_id],
        },
    }


def parse_problem(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def verified_response_payload(
    response_key: dict[str, Any],
    response_kid: str,
    issuer: str,
    node_id: str,
    raw: str,
    request_jti: str,
    profile: str,
) -> dict[str, Any]:
    header, payload = verify_compact_jws(response_key, raw)
    if header.get("typ") != RESPONSE_TYP or header.get("alg") != "EdDSA" or header.get("kid") != response_kid:
        raise DemoError(f"unexpected response JWT header: {header}")
    expected = {
        "iss": issuer,
        "sub": node_id,
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
    forbidden_fragments = ["source_records", "raw_evidence", "given_name", "surname", "poverty_score", "benefit_amount"]
    leaked = [fragment for fragment in forbidden_fragments if fragment in serialized]
    if leaked:
        raise DemoError(f"response appears to contain raw source details: {leaked}")
    return payload


def call_profile(
    *,
    notary_url: str,
    client_key: dict[str, Any],
    response_key: dict[str, Any],
    response_kid: str,
    issuer: str,
    node_id: str,
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
    verified = verified_response_payload(
        response_key,
        response_kid,
        issuer,
        node_id,
        raw,
        str(payload["jti"]),
        str(payload["profile"]),
    )
    save_json(out / f"{label}-verified-response.json", verified)
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEMO_ROOT / "output" / "federation")
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    civil_url = env("CIVIL_WITNESS_URL", "http://127.0.0.1:4321")
    social_url = env("SOCIAL_WITNESS_URL", "http://127.0.0.1:4322")
    client_key = secret_json_env("DEFAULT_FEDERATION_CLIENT_JWK")
    civil_response_key = secret_json_env("CIVIL_FEDERATION_RESPONSE_JWK")
    social_response_key = secret_json_env("SOCIAL_FEDERATION_RESPONSE_JWK")

    print("Default Registry Lab federated delegated-evaluation demo")
    print(f"  civil notary: {civil_url}")
    print(f"  social notary: {social_url}")
    print(f"  artifacts: {out}")

    civil_common = {
        "notary_url": civil_url,
        "client_key": client_key,
        "response_key": civil_response_key,
        "response_kid": CIVIL_RESPONSE_KID,
        "issuer": CIVIL_ISSUER,
        "node_id": CIVIL_NODE_ID,
        "out": out,
    }
    social_common = {
        "notary_url": social_url,
        "client_key": client_key,
        "response_key": social_response_key,
        "response_kid": SOCIAL_RESPONSE_KID,
        "issuer": SOCIAL_ISSUER,
        "node_id": SOCIAL_NODE_ID,
        "out": out,
    }

    age_payload = federation_payload(
        audience=CIVIL_NODE_ID,
        jti=new_ulid(),
        profile="civil_age_band_value",
        target_id="NID-1001",
        target_identifier_scheme="national_id",
        claim_id="age-band",
    )
    age = call_profile(label="civil-age-band", payload=age_payload, **civil_common)
    age_claim = age["result"]["claims"]["age-band"]
    if age_claim.get("value") != "child" or age_claim.get("disclosure") != "value":
        raise DemoError(f"NID-1001 should disclose child age band, got {age_claim}")

    alive_payload = federation_payload(
        audience=CIVIL_NODE_ID,
        jti=new_ulid(),
        profile="civil_alive_predicate",
        target_id="NID-1001",
        target_identifier_scheme="national_id",
        claim_id="person-is-alive",
    )
    alive = call_profile(label="civil-alive", payload=alive_payload, **civil_common)
    alive_claim = alive["result"]["claims"]["person-is-alive"]
    if alive_claim.get("satisfied") is not True or alive_claim.get("disclosure") != "predicate":
        raise DemoError(f"NID-1001 should satisfy alive predicate, got {alive_claim}")

    active_payload = federation_payload(
        audience=SOCIAL_NODE_ID,
        jti=new_ulid(),
        profile="beneficiary_active_predicate",
        target_id="NID-1001",
        target_identifier_scheme="national_id",
        claim_id="beneficiary-active",
    )
    active = call_profile(label="social-beneficiary-active", payload=active_payload, **social_common)
    active_claim = active["result"]["claims"]["beneficiary-active"]
    if active_claim.get("satisfied") is not True or active_claim.get("disclosure") != "predicate":
        raise DemoError(f"NID-1001 should satisfy beneficiary active predicate, got {active_claim}")

    band_payload = federation_payload(
        audience=SOCIAL_NODE_ID,
        jti=new_ulid(),
        profile="household_eligibility_band_value",
        target_id="NID-1001",
        target_identifier_scheme="national_id",
        claim_id="household-eligibility-band",
    )
    band = call_profile(label="social-household-band", payload=band_payload, **social_common)
    band_claim = band["result"]["claims"]["household-eligibility-band"]
    if band_claim.get("value") != "priority" or band_claim.get("disclosure") != "value":
        raise DemoError(f"NID-1001 should disclose priority household band, got {band_claim}")

    replay_token = sign_compact_jws(client_key, CLIENT_KID, REQUEST_TYP, age_payload)
    replay_status, replay_body, replay_headers = request_jwt(civil_url, replay_token)
    save_json(out / "replay-denial.json", {"status": replay_status, "headers": replay_headers, "body": parse_problem(replay_body)})
    if replay_status != 409:
        raise DemoError(f"replayed request should return 409, got {replay_status}: {replay_body}")

    bad_purpose = dict(age_payload)
    bad_purpose["jti"] = new_ulid()
    bad_purpose["purpose"] = "https://demo.example.gov/purpose/not-allowed"
    bad_token = sign_compact_jws(client_key, CLIENT_KID, REQUEST_TYP, bad_purpose)
    bad_status, bad_body, bad_headers = request_jwt(civil_url, bad_token)
    save_json(
        out / "unsupported-purpose-denial.json",
        {"status": bad_status, "headers": bad_headers, "body": parse_problem(bad_body)},
    )
    if bad_status != 403:
        raise DemoError(f"unsupported purpose should return 403, got {bad_status}: {bad_body}")

    composed = {
        "artifact_type": "demo.default-federated-benefit-screen.v1",
        "computed_by": CLIENT_NODE_ID,
        "source_mode": "signed peer evaluation responses",
        "inputs": {
            "civil_age_band_request_jti": age_payload["jti"],
            "civil_alive_request_jti": alive_payload["jti"],
            "beneficiary_active_request_jti": active_payload["jti"],
            "household_band_request_jti": band_payload["jti"],
        },
        "decision": {
            "child_support_screen": "eligible_for_review"
            if age_claim.get("value") == "child"
            and alive_claim.get("satisfied") is True
            and active_claim.get("satisfied") is True
            and band_claim.get("value") == "priority"
            else "not_eligible_for_review",
            "age_band": age_claim.get("value"),
            "household_eligibility_band": band_claim.get("value"),
        },
        "boundary": {
            "raw_registry_rows_embedded": False,
            "serving_notaries": [CIVIL_NODE_ID, SOCIAL_NODE_ID],
        },
    }
    save_json(out / "composed-benefit-screen.json", composed)
    print("default federation demo OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"demo-federation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
