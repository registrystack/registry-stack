#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Narrated Registry Notary demo for a split local deployment.

The demo starts two processes when requested: one registry-relay source registry
API and one standalone Registry Notary. The Registry Notary computes evidence by
calling the source registry through its DCI API, which is the product shape we
want to show:

1. discover the Registry Notary endpoint from source registry metadata;
2. discover what the Registry Notary can compute;
3. show that the evidence client cannot read raw registry rows directly;
4. compute value evidence from CRVS and farmer registries;
5. compute a derived predicate without returning raw registry rows;
6. batch-evaluate subjects with a partial failure;
7. render CCCEV JSON-LD;
8. issue an SD-JWT VC with a holder proof.
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
from textwrap import fill
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:4255"
DEFAULT_REGISTRY_BASE_URL = "http://127.0.0.1:4256"
RELAY_ROOT = Path(__file__).resolve().parents[2]
APPS_ROOT = RELAY_ROOT.parent
SIBLING_REGISTRY_NOTARY_ROOT = APPS_ROOT / "registry-notary"
CLONED_REGISTRY_NOTARY_ROOT = RELAY_ROOT / "target/registry-notary-demo/registry-notary"
REGISTRY_NOTARY_GIT_URL = "https://github.com/jeremi/registry-notary"
REGISTRY_NOTARY_GIT_REV = "67924098738024843d62e7e4df4d468629a5407a"
DEFAULT_REGISTRY_CONFIG = RELAY_ROOT / "demo/config/evidence_registries.yaml"
DEFAULT_OUTPUT_DIR = RELAY_ROOT / "demo/output/registry-notary-demo"
DEFAULT_FEATURES = "spdci-api-standards"
PURPOSE = "https://demo.example.gov/purpose/agricultural-subsidy-eligibility"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
CCCEV_FORMAT = 'application/ld+json; profile="cccev"'
SD_JWT_FORMAT = "application/dc+sd-jwt"

@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


class DemoError(RuntimeError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_json(value: str) -> dict[str, Any]:
    decoded = json.loads(b64url_decode(value).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise DemoError("expected base64url JSON object")
    return decoded


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
    issuer_jwk = values.get("REGISTRY_NOTARY_ISSUER_JWK")
    if not issuer_jwk:
        raise DemoError(
            f"{env_file} must define REGISTRY_NOTARY_ISSUER_JWK; run just demo-keys first"
        )
    env["REGISTRY_NOTARY_ISSUER_JWK"] = issuer_jwk
    env["REGISTRY_NOTARY_API_KEY"] = values.get(
        "REGISTRY_NOTARY_API_KEY", f"{verification_raw}-api"
    )
    env["REGISTRY_NOTARY_BEARER_TOKEN"] = values.get(
        "REGISTRY_NOTARY_BEARER_TOKEN", verification_raw
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


def preflight() -> None:
    if shutil.which("openssl") is None:
        raise DemoError("openssl is required to sign the demo holder proof")


def default_registry_notary_root() -> Path:
    configured = os.environ.get("REGISTRY_NOTARY_ROOT")
    if configured:
        return Path(configured)
    if (SIBLING_REGISTRY_NOTARY_ROOT / "Cargo.toml").exists():
        return SIBLING_REGISTRY_NOTARY_ROOT
    return CLONED_REGISTRY_NOTARY_ROOT


def ensure_registry_notary_root(root: Path, explicit: bool) -> Path:
    if (root / "Cargo.toml").exists():
        return root
    if explicit:
        raise DemoError(f"Registry Notary checkout is missing Cargo.toml: {root}")
    if shutil.which("git") is None:
        raise DemoError("git is required to clone the Registry Notary demo dependency")
    git_rev = os.environ.get("REGISTRY_NOTARY_GIT_REV", REGISTRY_NOTARY_GIT_REV)
    if len(git_rev) != 40 or any(ch not in "0123456789abcdef" for ch in git_rev):
        raise DemoError("REGISTRY_NOTARY_GIT_REV must be a 40-character lowercase commit SHA")
    root.parent.mkdir(parents=True, exist_ok=True)
    print(
        f"Cloning Registry Notary commit {git_rev} into {root}",
        flush=True,
    )
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", str(root)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", REGISTRY_NOTARY_GIT_URL],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "fetch", "--depth", "1", "origin", git_rev],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "checkout", "--detach", "FETCH_HEAD"],
        check=True,
    )
    return root


def prepare_registry_notary_runtime_dirs(root: Path) -> None:
    (root / "demo/var").mkdir(parents=True, exist_ok=True)


def prepare_output_dir(output_dir: Path) -> None:
    resolved = output_dir.resolve()
    if resolved in [Path.cwd().resolve(), Path.home().resolve(), Path("/")]:
        raise DemoError(f"refusing to clear unsafe output directory: {output_dir}")
    if output_dir.exists():
        for child in output_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)


def save_json(output_dir: Path, index: int, name: str, payload: Any) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{index:02d}-{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def start_server(
    config: Path,
    env: dict[str, str],
    name: str,
    *,
    cwd: Path,
    features: str = "",
    package: str | None = None,
) -> subprocess.Popen[str]:
    log_dir = RELAY_ROOT / "target/registry-notary-demo"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.log"
    log = log_path.open("w", encoding="utf-8")
    command = ["cargo", "run"]
    if package:
        command.extend(["-p", package])
    if features:
        command.extend(["--features", features])
    command.extend(["--", "--config", str(config)])
    process_env = env.copy()
    process_env.setdefault(
        "CARGO_TARGET_DIR", str(RELAY_ROOT / "target/registry-notary-demo-cargo" / name)
    )
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=process_env,
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
                "/v1/datasets/farmer_registry/entities/farmer/records?limit=1&fields=id",
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
        raise DemoError(f"unexpected Ed25519 {label} length from openssl")
    return value


def generate_holder_key(key_path: Path) -> dict[str, str]:
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
    public_hex = parse_openssl_hex_block(text, "pub")
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(bytes.fromhex(public_hex)),
        "alg": "EdDSA",
    }


def holder_did(public_jwk: dict[str, str]) -> str:
    encoded = b64url(json.dumps(public_jwk, separators=(",", ":")).encode())
    return f"did:jwk:{encoded}"


def sign_holder_proof(
    evaluation_id: str,
    credential_profile: str,
    disclosure: str,
    claims: list[str],
) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "holder.pem"
        input_path = tmp_path / "input"
        sig_path = tmp_path / "signature"
        holder_id = holder_did(generate_holder_key(key_path))
        now = int(time.time())
        jti = b64url(
            hashlib.sha256(f"{holder_id}:{evaluation_id}:{time.time_ns()}".encode()).digest()[
                :16
            ]
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


def sd_jwt_summary(credential: dict[str, Any], holder_id: str) -> dict[str, Any]:
    compact = credential.get("credential")
    if not isinstance(compact, str) or not compact:
        raise DemoError("credential response did not include a compact SD-JWT")
    parts = compact.split("~")
    jwt = parts[0]
    jwt_parts = jwt.split(".")
    if len(jwt_parts) != 3:
        raise DemoError("issued SD-JWT VC must contain a three-segment JWS")
    header = b64url_json(jwt_parts[0])
    payload = b64url_json(jwt_parts[1])
    disclosures = [part for part in parts[1:] if part]
    sd_entries = payload.get("_sd")
    if not isinstance(sd_entries, list) or not sd_entries:
        raise DemoError("issued SD-JWT VC payload must contain at least one _sd entry")
    if header.get("typ") != "dc+sd-jwt" or header.get("alg") != "EdDSA":
        raise DemoError("issued SD-JWT VC header did not use the expected profile")
    if payload.get("_sd_alg") != "sha-256":
        raise DemoError("issued SD-JWT VC payload must use _sd_alg sha-256")
    if payload.get("cnf", {}).get("kid") != holder_id:
        raise DemoError("issued SD-JWT VC cnf.kid did not match the holder did:jwk")
    if "evaluation_id" in payload:
        raise DemoError("issued SD-JWT VC must not embed the evaluation_id")
    return {
        "credential_id": credential.get("credential_id"),
        "format": credential.get("format"),
        "issuer": credential.get("issuer"),
        "expires_at": credential.get("expires_at"),
        "jwt_segments": len(jwt_parts),
        "disclosure_count": len(disclosures),
        "header": {
            "alg": header.get("alg"),
            "typ": header.get("typ"),
            "kid": header.get("kid"),
        },
        "payload": {
            "iss": payload.get("iss"),
            "vct": payload.get("vct"),
            "id": payload.get("id"),
            "sd_alg": payload.get("_sd_alg"),
            "sd_count": len(sd_entries),
            "has_cnf": "cnf" in payload,
            "cnf_kid_matches_holder": payload.get("cnf", {}).get("kid") == holder_id,
            "has_evaluation_id": "evaluation_id" in payload,
            "payload_keys": sorted(payload.keys()),
        },
    }


def issuer_jwks_summary(jwks: dict[str, Any]) -> dict[str, Any]:
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise DemoError("issuer JWKS did not include any public keys")
    summaries = []
    for key in keys:
        if not isinstance(key, dict):
            raise DemoError("issuer JWKS key must be an object")
        has_private_material = any(field in key for field in ["d", "p", "q", "dp", "dq", "qi"])
        if has_private_material:
            raise DemoError("issuer JWKS leaked private key material")
        summaries.append(
            {
                "kid": key.get("kid"),
                "kty": key.get("kty"),
                "crv": key.get("crv"),
                "alg": key.get("alg"),
                "has_private_material": has_private_material,
            }
        )
    return {"key_count": len(keys), "keys": summaries}


def production_readiness_report(service: dict[str, Any]) -> dict[str, Any]:
    identity = service.get("identity", {})
    return {
        "status": "demo_only",
        "suitable_for": ["local demo", "implementation walkthrough"],
        "not_yet_suitable_for": ["production credential issuance", "federated exchange"],
        "checks": {
            "credential_status": False,
            "credential_revocation": False,
            "production_mapper": bool(identity.get("production_mapper")),
            "holder_methods": ["did:jwk"],
            "holder_proof_profile": "demo EdDSA JWT, not SD-JWT KB-JWT",
            "issuer_key_management": "static demo key from environment",
            "key_rotation": False,
            "oots_wire_exchange": False,
        },
        "notes": [
            "The demo proves evaluation-bound SD-JWT VC issuance and JWKS publication.",
            "Production needs managed issuer keys, key history, credential status or "
            "revocation, verifier metadata, and production identity mapping.",
        ],
    }


def listed_format_ids(response: dict[str, Any]) -> list[str]:
    if isinstance(response.get("data"), list):
        return [item["format"] for item in response["data"]]
    if isinstance(response.get("formats"), list):
        return [item["id"] for item in response["formats"]]
    raise DemoError(f"formats response has unsupported shape: {response}")


def batch_item_outcome(item: dict[str, Any]) -> Any:
    if item.get("status") == "ok":
        return item["results"][0]["satisfied"]
    if item.get("status") == "succeeded":
        return item["claim_results"][0].get("satisfied")
    if item.get("status") in {"error", "failed"}:
        return item["status"]
    return item.get("status", "unknown")


def line(char: str = "-") -> str:
    return char * 78


def print_wrapped(label: str, text: str) -> None:
    prefix = f"  {label:<10} "
    wrapped = fill(
        text,
        width=78,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
    )
    print(wrapped)


def print_kv(label: str, value: Any) -> None:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    print_wrapped(label, str(value))


def json_bool(value: bool) -> str:
    return "true" if value else "false"


def plural(count: int, singular: str, plural_value: str | None = None) -> str:
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural_value or singular + 's'}"


def find_evidence_server_offering(catalog: dict[str, Any]) -> tuple[dict[str, Any], str]:
    for offering in catalog.get("evidence_offerings", []):
        access = offering.get("access", {})
        endpoint_url = access.get("endpoint_url")
        if access.get("kind") == "evidence-server" and endpoint_url:
            return offering, endpoint_url
    raise DemoError("source registry catalog did not advertise an evidence-server offering")


def print_demo_header(base_url: str, registry_base_url: str, output_dir: Path) -> None:
    print("\n" + line("="))
    print("Registry Notary demo: computed evidence without raw registry disclosure")
    print(line("="))
    print_wrapped(
        "Story",
        "A relying party asks for evidence. It talks to the Registry Notary, not "
        "directly to source registries. The Registry Notary calls CRVS and farmer "
        "registry APIs, applies configured rules, then returns only the requested "
        "evidence shape.",
    )
    print()
    print("  Topology")
    print("    evidence client")
    print(f"      -> source registry metadata  {registry_base_url}")
    print(f"      -> Registry Notary          discovered, demo default {base_url}")
    print(f"          -> source registry DCI   {registry_base_url}")
    print()
    print_kv("Purpose", PURPOSE)
    print_kv("Artifacts", output_dir)


def print_step(
    number: int,
    title: str,
    *,
    actor: str,
    request_line: str,
    why: str,
    observed: str,
    artifact: Path | None = None,
) -> None:
    print("\n" + line())
    print(f"{number}. {title}")
    print(line())
    print_kv("Actor", actor)
    print_kv("Request", request_line)
    print_kv("Why", why)
    print_kv("Observed", observed)
    if artifact is not None:
        print_kv("Saved", artifact)


def run_demo(base_url: str, registry_base_url: str, token: str, output_dir: Path) -> None:
    step = 1
    run_id = b64url(os.urandom(8))
    print_demo_header(base_url, registry_base_url, output_dir)

    source_catalog = require_status(
        request(registry_base_url, "GET", "/metadata/catalog", token),
        200,
        "source registry catalog",
    )
    source_dcat = require_status(
        request(registry_base_url, "GET", "/metadata/dcat/bregdcat-ap", token),
        200,
        "source registry BRegDCAT-AP",
    )
    offering, discovered_base_url = find_evidence_server_offering(source_catalog)
    artifact = save_json(
        output_dir,
        step,
        "source-registry-evidence-discovery",
        {"catalog": source_catalog, "breg_dcat_ap": source_dcat},
    )
    print_step(
        step,
        "Discover the Registry Notary from source registry metadata",
        actor="evidence client -> source registry metadata",
        request_line="GET /metadata/catalog and GET /metadata/dcat/bregdcat-ap",
        why=(
            "A client may start from a known registry, not from a known Registry "
            "Notary. The source registry advertises an evidence offering that "
            "points to the Registry Notary endpoint, while the Registry Notary "
            "keeps the runtime rule and disclosure contract."
        ),
        observed=(
            f"Offering {offering['id']} advertises {discovered_base_url}. "
            "The DCAT-AP artifact carries the same discovery story for catalog "
            "consumers; runtime calls still use explicit Registry Notary APIs."
        ),
        artifact=artifact,
    )
    if discovered_base_url != base_url:
        print_wrapped(
            "Note",
            f"Using discovered Registry Notary URL {discovered_base_url} instead "
            f"of configured demo default {base_url}.",
        )
    base_url = discovered_base_url
    step += 1

    service = require_status(
        request(base_url, "GET", "/.well-known/evidence-service", token),
        200,
        "service discovery",
    )
    artifact = save_json(output_dir, step, "service", service)
    operations = ", ".join(service["operations"].keys())
    print_step(
        step,
        "Discover the Registry Notary contract",
        actor="evidence client -> Registry Notary",
        request_line="GET /.well-known/evidence-service",
        why=(
            "The client starts with capability discovery. It learns whether this "
            "server can evaluate claims, render evidence, batch requests, and "
            "issue credentials."
        ),
        observed=(
            f"Service {service['service_id']} is running API {service['api_version']} "
            f"and exposes: {operations}. Identity mapping is advertised as "
            f"{service['identity']['mapper']} with production_mapper="
            f"{json_bool(service['identity']['production_mapper'])}."
        ),
        artifact=artifact,
    )
    step += 1

    claims = require_status(request(base_url, "GET", "/claims", token), 200, "claim list")
    artifact = save_json(output_dir, step, "claims", claims)
    claim_ids = [claim["id"] for claim in claims["data"]]
    print_step(
        step,
        "List configured claims",
        actor="evidence client -> Registry Notary",
        request_line="GET /claims",
        why=(
            "Claims are the product vocabulary. Source registries keep their own "
            "data models; the Evidence Server publishes the evidence it knows how "
            "to compute."
        ),
        observed=(
            f"The client can request {claim_ids}. The first two are value claims; "
            "farmer-under-4ha is a derived predicate."
        ),
        artifact=artifact,
    )
    step += 1

    formats = require_status(request(base_url, "GET", "/formats", token), 200, "formats")
    artifact = save_json(output_dir, step, "formats", formats)
    format_values = listed_format_ids(formats)
    print_step(
        step,
        "List output formats",
        actor="evidence client -> Registry Notary",
        request_line="GET /formats",
        why=(
            "The same claim can be projected into multiple artifacts. "
            "The canonical claim result stays internal; renderers produce JSON, "
            "CCCEV JSON-LD, or SD-JWT VC."
        ),
        observed=f"Enabled formats: {format_values}.",
        artifact=artifact,
    )
    step += 1

    raw_row = request(
        registry_base_url,
        "GET",
        "/v1/datasets/farmer_registry/entities/farmer/records/FR-MEMBER-001",
        token,
        extra_headers={"Data-Purpose": PURPOSE},
    )
    artifact = save_json(
        output_dir, step, "raw-row-denied", {"status": raw_row.status, "body": raw_row.body}
    )
    print_step(
        step,
        "Prove the privacy boundary",
        actor="evidence client -> source registry",
        request_line="GET /v1/datasets/farmer_registry/entities/farmer/records/FR-MEMBER-001",
        why=(
            "The relying party should not need broad row access to source "
            "registries. This call intentionally tries to bypass the Registry "
            "Notary."
        ),
        observed=(
            f"The source registry returned HTTP {raw_row.status}. The client can "
            "ask for evidence, but cannot inspect the raw farmer row."
        ),
        artifact=artifact,
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
            {"Accept": CLAIM_RESULT_FORMAT, "Data-Purpose": PURPOSE},
        ),
        200,
        "value evaluation",
    )
    artifact = save_json(output_dir, step, "value-evaluation", value_eval)
    values = {item["claim_id"]: item["value"] for item in value_eval["results"]}
    print_step(
        step,
        "Compute value evidence",
        actor="evidence client -> Registry Notary -> CRVS and farmer registry",
        request_line="POST /claims/evaluate date-of-birth, farmed-land-size",
        why=(
            "Some consumers are allowed to receive a specific value, such as date "
            "of birth or farmed land size. The Evidence Server still projects only "
            "the requested fields, not whole registry records."
        ),
        observed=f"Returned values: {values}.",
        artifact=artifact,
    )
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
            {"Accept": CCCEV_FORMAT, "Data-Purpose": PURPOSE},
        ),
        200,
        "predicate evaluation",
    )
    artifact = save_json(output_dir, step, "predicate-evaluation", predicate_eval)
    evaluation_id = predicate_eval["results"][0]["evaluation_id"]
    predicate_satisfied = predicate_eval["results"][0]["satisfied"]
    print_step(
        step,
        "Compute a derived predicate",
        actor="evidence client -> Registry Notary -> farmer registry",
        request_line="POST /claims/evaluate farmer-under-4ha with disclosure=predicate",
        why=(
            "This is the core selective-disclosure case. The server checks the "
            "configured CEL rule farmed_land_size < 4.0 and returns the boolean "
            "answer, not the underlying hectare value."
        ),
        observed=(
            f"farmer-under-4ha is {predicate_satisfied}. Stored evaluation_id "
            f"{evaluation_id} can be rendered or credentialed later by the same "
            "client."
        ),
        artifact=artifact,
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
            {
                "Accept": CLAIM_RESULT_FORMAT,
                "Data-Purpose": PURPOSE,
                "Idempotency-Key": f"notary-demo-batch-{run_id}",
            },
        ),
        200,
        "batch evaluation",
    )
    artifact = save_json(output_dir, step, "batch-evaluation", batch)
    batch_summary = [batch_item_outcome(item) for item in batch["items"]]
    print_step(
        step,
        "Evaluate a batch with partial failure",
        actor="evidence client -> Registry Notary",
        request_line="POST /claims/batch-evaluate farmer-under-4ha for three subjects",
        why=(
            "Batch evaluation is useful for casework queues. One missing subject "
            "must not erase successful answers for other subjects."
        ),
        observed=(
            f"Per-subject outcomes: {batch_summary}. The third subject is missing "
            "and is returned as an item-level error."
        ),
        artifact=artifact,
    )
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
    artifact = save_json(output_dir, step, "cccev-render", cccev)
    graph_size = len(cccev.get("@graph", []))
    print_step(
        step,
        "Render the stored evaluation as CCCEV",
        actor="evidence client -> Registry Notary",
        request_line="POST /evidence/render with the prior evaluation_id",
        why=(
            "Evaluation and rendering are separate. The server does not recompute "
            "or widen disclosure; it projects the already-bound result into a "
            "standards-friendly JSON-LD shape."
        ),
        observed=f"Rendered CCCEV JSON-LD with {plural(graph_size, 'graph node')}.",
        artifact=artifact,
    )
    step += 1

    credential_eval = require_status(
        request(
            base_url,
            "POST",
            "/claims/evaluate",
            token,
            {
                "subject": {"id": "FAKE-830001", "id_type": "common_subject_id"},
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate",
                "format": SD_JWT_FORMAT,
            },
            {"Accept": SD_JWT_FORMAT, "Data-Purpose": PURPOSE},
        ),
        200,
        "credential-bound evaluation",
    )
    artifact = save_json(output_dir, step, "credential-evaluation", credential_eval)
    credential_evaluation_id = credential_eval["results"][0]["evaluation_id"]
    print_step(
        step,
        "Bind the predicate for credential issuance",
        actor="evidence client -> Registry Notary",
        request_line="POST /claims/evaluate farmer-under-4ha with format=application/dc+sd-jwt",
        why=(
            "Credential issuance is bound to the original evaluation format. The "
            "client asks for the same predicate again with the SD-JWT VC format so "
            "issuance cannot widen the earlier CCCEV evaluation."
        ),
        observed=f"Stored credential-bound evaluation_id {credential_evaluation_id}.",
        artifact=artifact,
    )
    step += 1

    holder_id, proof = sign_holder_proof(
        credential_evaluation_id,
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
                "evaluation_id": credential_evaluation_id,
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
    artifact = save_json(output_dir, step, "sd-jwt-credential", credential)
    compact = credential["credential"]
    jwt_segment_count = len(compact.split("~")[0].split("."))
    summary = sd_jwt_summary(credential, holder_id)
    summary_artifact = save_json(output_dir, step, "sd-jwt-summary", summary)
    print_step(
        step,
        "Issue an SD-JWT VC",
        actor="holder/evidence client -> Registry Notary",
        request_line="POST /credentials/issue with holder did:jwk proof",
        why=(
            "When evidence becomes a product artifact, the server can issue a "
            "signed credential. The holder proves control of the did:jwk key, and "
            "the credential omits the evaluation_id to avoid verifier linkage."
        ),
        observed=(
            f"Issued {credential['format']} as a {jwt_segment_count}-segment JWS "
            f"with {summary['disclosure_count']} disclosure(s). The decoded summary "
            "confirms cnf.kid is bound and evaluation_id is absent."
        ),
        artifact=artifact,
    )
    print_kv("Summary", summary_artifact)
    step += 1

    jwks = require_status(
        request(base_url, "GET", "/.well-known/evidence/jwks.json", token),
        200,
        "issuer JWKS",
    )
    artifact = save_json(output_dir, step, "issuer-jwks", jwks)
    jwks_summary = issuer_jwks_summary(jwks)
    jwks_summary_artifact = save_json(output_dir, step, "issuer-jwks-summary", jwks_summary)
    key_ids = [key["kid"] for key in jwks_summary["keys"]]
    print_step(
        step,
        "Publish issuer verification keys",
        actor="verifier -> Registry Notary",
        request_line="GET /.well-known/evidence/jwks.json",
        why=(
            "Verifiers need public keys to validate issued credentials. The JWKS "
            "contains public key material only."
        ),
        observed=f"Published {len(jwks['keys'])} public issuer key(s): {key_ids}.",
        artifact=artifact,
    )
    print_kv("Summary", jwks_summary_artifact)
    step += 1

    readiness = production_readiness_report(service)
    artifact = save_json(output_dir, step, "production-readiness-gaps", readiness)
    print_step(
        step,
        "Record production readiness gaps",
        actor="demo runner",
        request_line="local artifact",
        why=(
            "The SD-JWT VC flow is useful demo evidence, but it should not be "
            "mistaken for production credential infrastructure."
        ),
        observed=(
            "Wrote an explicit demo-only readiness report covering static keys, "
            "missing revocation/status, did:jwk-only holder binding, and demo "
            "identity mapping."
        ),
        artifact=artifact,
    )

    print("\n" + line("="))
    print("What this demo proved")
    print(line("="))
    print("  1. Source registries stayed simple and source-owned.")
    print("  2. The Registry Notary computed reusable claims over multiple registries.")
    print("  3. The client got least-disclosure evidence, not raw registry rows.")
    print("  4. The same claim was projected as JSON, CCCEV JSON-LD, and SD-JWT VC.")
    print("  5. v0 identity mapping is intentionally demo-grade: common_subject_id only.")
    print("  6. Production gaps are explicit rather than hidden in the demo story.")
    print(f"\nFull JSON responses are saved under {output_dir}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--registry-base-url", default=DEFAULT_REGISTRY_BASE_URL)
    parser.add_argument(
        "--registry-notary-root",
        default=None,
        help=(
            "Registry Notary checkout used with --start-server; defaults to "
            "REGISTRY_NOTARY_ROOT, ../registry-notary, or a tagged clone under target/"
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "Registry Notary config path; defaults to "
            "<registry-notary-root>/demo/config/registry-notary.yaml"
        ),
    )
    parser.add_argument("--registry-config", default=str(DEFAULT_REGISTRY_CONFIG))
    parser.add_argument("--env-file", default="demo/.env.local")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument(
        "--features",
        default=DEFAULT_FEATURES,
        help="registry-relay cargo features used when --start-server starts the source registry",
    )
    parser.add_argument(
        "--notary-features",
        default="",
        help="Registry Notary cargo features used when --start-server starts the standalone server",
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="start split registry and registry-notary processes, then stop them when done",
    )
    args = parser.parse_args()

    preflight()
    output_dir = Path(args.output_dir)
    prepare_output_dir(output_dir)
    env, token, registry_token = demo_env(Path(args.env_file))
    notary_process: subprocess.Popen[str] | None = None
    registry_process: subprocess.Popen[str] | None = None
    try:
        explicit_notary_root = args.registry_notary_root is not None
        registry_notary_root = (
            Path(args.registry_notary_root)
            if explicit_notary_root
            else default_registry_notary_root()
        )
        if args.start_server:
            registry_notary_root = ensure_registry_notary_root(
                registry_notary_root, explicit_notary_root
            )
            prepare_registry_notary_runtime_dirs(registry_notary_root)
        notary_config = (
            Path(args.config)
            if args.config is not None
            else registry_notary_root / "demo/config/registry-notary.yaml"
        )
        if args.start_server:
            registry_process = start_server(
                Path(args.registry_config),
                env,
                "source-registries",
                cwd=RELAY_ROOT,
                features=args.features,
            )
            wait_for_registry_server(args.registry_base_url, registry_token, registry_process)
            notary_process = start_server(
                notary_config,
                env,
                "registry-notary",
                cwd=registry_notary_root,
                features=args.notary_features,
                package="registry-notary-bin",
            )
        wait_for_evidence_server(args.base_url, token, notary_process)
        run_demo(args.base_url, args.registry_base_url, token, output_dir)
    except (DemoError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_server(notary_process)
        stop_server(registry_process)
    return 0


if __name__ == "__main__":
    sys.exit(main())
