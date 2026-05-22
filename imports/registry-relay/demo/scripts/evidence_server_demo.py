#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Narrated Evidence Server demo for a split local deployment.

The demo starts two processes when requested: one registry-relay source registry
API and one standalone Evidence Server. The Evidence Server computes evidence by
calling the source registry API, which is the product shape we want to show:

1. discover claims and formats;
2. show that the evidence client cannot read raw registry rows directly;
2. compute value evidence from CRVS and farmer registries;
3. compute a derived predicate without returning raw registry rows;
4. batch-evaluate subjects with a partial failure;
5. render CCCEV JSON-LD;
6. issue an SD-JWT VC with a holder proof.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:4255"
DEFAULT_REGISTRY_BASE_URL = "http://127.0.0.1:4256"
DEFAULT_CONFIG = Path("demo/config/evidence_server.yaml")
DEFAULT_REGISTRY_CONFIG = Path("demo/config/evidence_registries.yaml")
DEFAULT_OUTPUT_DIR = Path("demo/output/evidence-server-demo")
DEFAULT_FEATURES = "spdci-api-standards"
PURPOSE = "https://demo.example.gov/purpose/agricultural-subsidy-eligibility"
CLAIM_RESULT_FORMAT = "application/vnd.evidence-server.claim-result+json"
CCCEV_FORMAT = 'application/ld+json; profile="cccev"'
SD_JWT_FORMAT = "application/dc+sd-jwt"

DEMO_ISSUER_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    "alg": "EdDSA",
}

DEMO_HOLDER_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINpAgYVDwfGjJ/3AJ6IKwVqB8vpnxoX4E4RbnLSFarM+
-----END PRIVATE KEY-----
"""

DEMO_HOLDER_PUBLIC_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "gpb08DSqiqOybeHIDCLRcPdnDbhGL1ypfkLEFd977d8",
    "alg": "EdDSA",
}


@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


class DemoError(RuntimeError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def raw_key_hash(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip("'").strip('"')
    return values


def demo_env(env_file: Path) -> tuple[dict[str, str], str, str]:
    values = load_env_file(env_file)
    verification_raw = values.get(
        "VERIFICATION_SERVICE_RAW", "demo-evidence-verification-service"
    )
    casework_raw = values.get("CASEWORK_SYSTEM_RAW", "demo-evidence-casework-system")

    env = os.environ.copy()
    env["VERIFICATION_SERVICE_RAW"] = verification_raw
    env["VERIFICATION_SERVICE_HASH"] = values.get(
        "VERIFICATION_SERVICE_HASH", raw_key_hash(verification_raw)
    )
    env["CASEWORK_SYSTEM_RAW"] = casework_raw
    env["CASEWORK_SYSTEM_HASH"] = values.get(
        "CASEWORK_SYSTEM_HASH", raw_key_hash(casework_raw)
    )
    env["EVIDENCE_SERVER_ISSUER_JWK"] = values.get(
        "EVIDENCE_SERVER_ISSUER_JWK",
        json.dumps(DEMO_ISSUER_JWK, separators=(",", ":")),
    )
    env["EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN"] = casework_raw
    return env, verification_raw, casework_raw


def request(
    base_url: str,
    method: str,
    path: str,
    token: str,
    body: Any | None = None,
    extra_headers: dict[str, str] | None = None,
) -> HttpResult:
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else None
            return HttpResult(resp.status, parsed, dict(resp.headers))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode("utf-8", errors="replace")
        return HttpResult(exc.code, parsed, dict(exc.headers))
    except urllib.error.URLError as exc:
        raise DemoError(f"server is not reachable at {base_url}: {exc}") from exc


def require_status(result: HttpResult, expected: int, label: str) -> Any:
    if result.status != expected:
        raise DemoError(
            f"{label} returned HTTP {result.status}, expected {expected}: {result.body}"
        )
    return result.body


def save_json(output_dir: Path, index: int, name: str, payload: Any) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{index:02d}-{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def start_server(
    config: Path, env: dict[str, str], name: str, features: str
) -> subprocess.Popen[str]:
    log_dir = Path("target/evidence-server-demo")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.log"
    log = log_path.open("w", encoding="utf-8")
    command = ["cargo", "run"]
    if features:
        command.extend(["--features", features])
    command.extend(["--", "--config", str(config)])
    process = subprocess.Popen(
        command,
        cwd=Path.cwd(),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process._demo_log = log  # type: ignore[attr-defined]
    print(f"Started {name} for the demo, log: {log_path}", flush=True)
    return process


def wait_for_evidence_server(
    base_url: str, token: str, process: subprocess.Popen[str] | None
) -> None:
    deadline = time.time() + 240
    last_error = "server did not answer"
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            raise DemoError(f"server exited early with code {process.returncode}")
        try:
            result = request(base_url, "GET", "/.well-known/evidence-service", token)
            if result.status == 200:
                return
            last_error = f"HTTP {result.status}: {result.body}"
        except DemoError as exc:
            last_error = str(exc)
        time.sleep(1)
    raise DemoError(f"timed out waiting for {base_url}: {last_error}")


def wait_for_registry_server(
    base_url: str, token: str, process: subprocess.Popen[str] | None
) -> None:
    deadline = time.time() + 240
    last_error = "registry server did not answer"
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            raise DemoError(f"registry server exited early with code {process.returncode}")
        try:
            result = request(
                base_url,
                "GET",
                "/datasets/farmer_registry/farmer?limit=1&fields=id",
                token,
                extra_headers={"Data-Purpose": PURPOSE},
            )
            if result.status == 200:
                return
            last_error = f"HTTP {result.status}: {result.body}"
        except DemoError as exc:
            last_error = str(exc)
        time.sleep(1)
    raise DemoError(f"timed out waiting for registry at {base_url}: {last_error}")


def stop_server(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
    log = getattr(process, "_demo_log", None)
    if log is not None:
        log.close()


def holder_did() -> str:
    encoded = b64url(json.dumps(DEMO_HOLDER_PUBLIC_JWK, separators=(",", ":")).encode())
    return f"did:jwk:{encoded}"


def sign_holder_proof(
    evaluation_id: str,
    credential_profile: str,
    disclosure: str,
    claims: list[str],
) -> tuple[str, str]:
    if shutil.which("openssl") is None:
        raise DemoError("openssl is required to sign the demo holder proof")
    holder_id = holder_did()
    now = int(time.time())
    jti = b64url(
        hashlib.sha256(f"{holder_id}:{evaluation_id}:{time.time_ns()}".encode()).digest()[:16]
    )
    header = b64url(
        json.dumps(
            {"alg": "EdDSA", "typ": "JWT", "kid": holder_id},
            separators=(",", ":"),
        ).encode()
    )
    payload = b64url(
        json.dumps(
            {
                "sub": holder_id,
                "aud": "evidence-server",
                "exp": now + 300,
                "iat": now,
                "jti": jti,
                "evaluation_id": evaluation_id,
                "credential_profile": credential_profile,
                "disclosure": disclosure,
                "claims": claims,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "holder.pem"
        input_path = tmp_path / "input"
        sig_path = tmp_path / "signature"
        key_path.write_text(DEMO_HOLDER_PRIVATE_KEY, encoding="utf-8")
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
        signature = b64url(sig_path.read_bytes())
    return holder_id, f"{signing_input.decode('ascii')}.{signature}"


def print_step(label: str, message: str) -> None:
    print(f"\n{label}")
    print(message)


def run_demo(base_url: str, registry_base_url: str, token: str, output_dir: Path) -> None:
    step = 1

    service = require_status(
        request(base_url, "GET", "/.well-known/evidence-service", token),
        200,
        "service discovery",
    )
    save_json(output_dir, step, "service", service)
    print_step(
        "1. Service discovery",
        f"Service {service['service_id']} exposes operations: {', '.join(service['operations'].keys())}.",
    )
    step += 1

    claims = require_status(request(base_url, "GET", "/claims", token), 200, "claim list")
    save_json(output_dir, step, "claims", claims)
    claim_ids = [claim["id"] for claim in claims["data"]]
    print_step("2. Claim catalog", f"Claims available to the evidence client: {claim_ids}.")
    step += 1

    formats = require_status(request(base_url, "GET", "/formats", token), 200, "formats")
    save_json(output_dir, step, "formats", formats)
    print_step(
        "3. Output formats",
        f"Formats include: {[item['format'] for item in formats['data']]}.",
    )
    step += 1

    raw_row = request(
        registry_base_url,
        "GET",
        "/datasets/farmer_registry/farmer/FR-MEMBER-001",
        token,
        extra_headers={"Data-Purpose": PURPOSE},
    )
    save_json(output_dir, step, "raw-row-denied", {"status": raw_row.status, "body": raw_row.body})
    print_step(
        "4. Privacy boundary",
        f"The evidence client tried to read a raw farmer row and received HTTP {raw_row.status}.",
    )
    step += 1

    value_eval = require_status(
        request(
            base_url,
            "POST",
            "/claims/evaluate",
            token,
            {
                "subject": {"id": "FAKE-830001", "id_type": "common_subject_id"},
                "claims": ["date-of-birth", "farmed-land-size"],
                "disclosure": "value",
                "format": CLAIM_RESULT_FORMAT,
            },
            {"Data-Purpose": PURPOSE},
        ),
        200,
        "value evaluation",
    )
    save_json(output_dir, step, "value-evaluation", value_eval)
    values = {item["claim_id"]: item["value"] for item in value_eval["results"]}
    print_step("5. Value evidence", f"CRVS and farmer registry values returned: {values}.")
    step += 1

    predicate_eval = require_status(
        request(
            base_url,
            "POST",
            "/claims/evaluate",
            token,
            {
                "subject": {"id": "FAKE-830001", "id_type": "common_subject_id"},
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate",
                "format": CCCEV_FORMAT,
            },
            {"Data-Purpose": PURPOSE},
        ),
        200,
        "predicate evaluation",
    )
    save_json(output_dir, step, "predicate-evaluation", predicate_eval)
    evaluation_id = predicate_eval["results"][0]["evaluation_id"]
    print_step(
        "6. Derived predicate",
        f"farmer-under-4ha is {predicate_eval['results'][0]['satisfied']} with evaluation_id {evaluation_id}.",
    )
    step += 1

    batch = require_status(
        request(
            base_url,
            "POST",
            "/claims/batch-evaluate",
            token,
            {
                "subjects": [
                    {"id": "FAKE-830001", "id_type": "common_subject_id"},
                    {"id": "FAKE-830002", "id_type": "common_subject_id"},
                    {"id": "FAKE-839999", "id_type": "common_subject_id"},
                ],
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate",
                "format": CLAIM_RESULT_FORMAT,
            },
            {"Data-Purpose": PURPOSE, "Idempotency-Key": "evidence-demo-batch-001"},
        ),
        200,
        "batch evaluation",
    )
    save_json(output_dir, step, "batch-evaluation", batch)
    batch_summary = [
        item["status"] if item["status"] == "error" else item["results"][0]["satisfied"]
        for item in batch["items"]
    ]
    print_step("7. Batch evaluation", f"Batch results by subject: {batch_summary}.")
    step += 1

    cccev = require_status(
        request(
            base_url,
            "POST",
            "/evidence/render",
            token,
            {
                "evaluation_id": evaluation_id,
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate",
                "format": CCCEV_FORMAT,
            },
        ),
        200,
        "CCCEV render",
    )
    save_json(output_dir, step, "cccev-render", cccev)
    print_step("8. CCCEV render", "Rendered the same evaluation as CCCEV JSON-LD.")
    step += 1

    holder_id, proof = sign_holder_proof(
        evaluation_id,
        "smallholder_sd_jwt",
        "predicate",
        ["farmer-under-4ha"],
    )
    credential = require_status(
        request(
            base_url,
            "POST",
            "/credentials/issue",
            token,
            {
                "evaluation_id": evaluation_id,
                "credential_profile": "smallholder_sd_jwt",
                "format": SD_JWT_FORMAT,
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate",
                "holder": {
                    "binding": "did",
                    "id": holder_id,
                    "proof": proof,
                },
            },
        ),
        200,
        "credential issuance",
    )
    save_json(output_dir, step, "sd-jwt-credential", credential)
    compact = credential["credential"]
    print_step(
        "9. SD-JWT VC issuance",
        f"Issued {credential['format']} with {compact.count('~')} disclosure separator(s).",
    )
    step += 1

    jwks = require_status(
        request(base_url, "GET", "/.well-known/evidence/jwks.json", token),
        200,
        "issuer JWKS",
    )
    save_json(output_dir, step, "issuer-jwks", jwks)
    print_step("10. Issuer JWKS", f"Published {len(jwks['keys'])} public issuer key(s).")
    print(f"\nSaved demo responses under {output_dir}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--registry-base-url", default=DEFAULT_REGISTRY_BASE_URL)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--registry-config", default=str(DEFAULT_REGISTRY_CONFIG))
    parser.add_argument("--env-file", default="demo/.env.local")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument(
        "--features",
        default=DEFAULT_FEATURES,
        help="cargo features used when --start-server starts the demo processes",
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="start split registry and evidence-server processes, then stop them when done",
    )
    args = parser.parse_args()

    env, token, registry_token = demo_env(Path(args.env_file))
    evidence_process: subprocess.Popen[str] | None = None
    registry_process: subprocess.Popen[str] | None = None
    try:
        if args.start_server:
            registry_process = start_server(
                Path(args.registry_config), env, "source-registries", args.features
            )
            wait_for_registry_server(args.registry_base_url, registry_token, registry_process)
            evidence_process = start_server(
                Path(args.config), env, "evidence-server", args.features
            )
        wait_for_evidence_server(args.base_url, token, evidence_process)
        run_demo(args.base_url, args.registry_base_url, token, Path(args.output_dir))
    except (DemoError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_server(evidence_process)
        stop_server(registry_process)
    return 0


if __name__ == "__main__":
    sys.exit(main())
