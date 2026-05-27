#!/usr/bin/env python3
"""Narrated client flow for the NAgDI agricultural registries demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PURPOSE = os.environ.get(
    "AGRI_DATA_PURPOSE",
    "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
)
MARKET_PURPOSE = os.environ.get(
    "AGRI_MARKET_DATA_PURPOSE",
    "https://demo.example.gov/purpose/nagdi/agricultural-market-sizing",
)
CLAIM_RESULT_FORMAT = "application/vnd.registry-witness.claim-result+json"
SD_JWT_FORMAT = "application/dc+sd-jwt"
CORRELATION_ID = os.environ.get("DEMO_CORRELATION_ID", "nagdi-agri-demo-correlation-001")
LIVESTOCK_PURPOSE = os.environ.get(
    "AGRI_LIVESTOCK_DATA_PURPOSE",
    "https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review",
)

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


@dataclass(frozen=True)
class Endpoint:
    name: str
    url: str
    token_env: str | None = None


@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


class DemoError(RuntimeError):
    pass


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise DemoError(f"missing required environment variable: {name}")
    return value


def output_dir(path: Path) -> Path:
    if path.exists():
        for child in path.iterdir():
            if child.name == ".gitignore":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_body(raw: bytes) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> HttpResult:
    req_headers = {
        "Accept": "*/*",
        "x-request-id": CORRELATION_ID,
    }
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, parse_body(resp.read()), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, parse_body(exc.read()), dict(exc.headers))
    except urllib.error.URLError as exc:
        raise DemoError(f"{method} {url} failed: {exc}") from exc


def save(out: Path, index: int, label: str, payload: Any) -> Path:
    path = out / f"{index:02d}-{label}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def write_text(out: Path, name: str, lines: list[str]) -> Path:
    path = out / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def add_transcript(transcript: list[str], text: str) -> None:
    number = sum(1 for line in transcript if line[:1].isdigit() and ". " in line) + 1
    transcript.append(f"{number}. {text}")


def require(result: HttpResult, expected: int, label: str) -> Any:
    if result.status != expected:
        raise DemoError(f"{label} returned HTTP {result.status}, expected {expected}: {result.body}")
    return result.body


def require_problem_code(result: HttpResult, expected_status: int, expected_code: str, label: str) -> None:
    if result.status != expected_status:
        raise DemoError(f"{label} returned HTTP {result.status}, expected {expected_status}: {result.body}")
    if not isinstance(result.body, dict) or result.body.get("code") != expected_code:
        raise DemoError(f"{label} returned problem code {result.body!r}, expected {expected_code}")


def wait_for(label: str, fn, timeout: int = 120) -> None:
    deadline = time.time() + timeout
    last = "not attempted"
    while time.time() < deadline:
        try:
            fn()
            print(f"  ready: {label}")
            return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            time.sleep(2)
    raise DemoError(f"timed out waiting for {label}: {last}")


def evaluation_payload(subject: str, claim: str, disclosure: str = "predicate", fmt: str = CLAIM_RESULT_FORMAT, id_type: str = "farmer_id") -> dict[str, Any]:
    return {
        "subject": {"id": subject, "id_type": id_type},
        "claims": [claim],
        "disclosure": disclosure,
        "format": fmt,
    }


def first_result(evaluation: dict[str, Any]) -> dict[str, Any]:
    results = evaluation.get("results") or evaluation.get("claim_results") or []
    if not results:
        raise DemoError(f"evaluation response has no results: {evaluation}")
    first = results[0]
    if not isinstance(first, dict):
        raise DemoError(f"evaluation result is not an object: {first!r}")
    return first


def result_for_claim(evaluation: dict[str, Any], claim: str) -> dict[str, Any]:
    results = evaluation.get("results") or evaluation.get("claim_results") or []
    for item in results:
        if isinstance(item, dict) and item.get("claim") in (claim, None):
            return item
        if isinstance(item, dict) and item.get("claim_id") == claim:
            return item
    return first_result(evaluation)


def outcome(result: dict[str, Any]) -> Any:
    for key in ("value", "satisfied", "outcome", "decision", "verified", "result", "status"):
        if key in result:
            return result[key]
    return None


def require_outcome(evaluation: dict[str, Any], expected: str, label: str) -> dict[str, Any]:
    result = first_result(evaluation)
    actual = outcome(result)
    allowed_by_expected = {
        "eligible": {True, "true", "eligible", "pass", "passed", "satisfied", "approved"},
        "not_eligible": {False, "false", "not_eligible", "denied", "failed", "unsatisfied", "ineligible"},
        "manual_review": {"manual_review", "review_required", "needs_review"},
    }
    if actual not in allowed_by_expected[expected]:
        raise DemoError(f"{label} expected {expected}, got {actual!r}: {result}")
    return result


def require_value(evaluation: dict[str, Any], expected: str, label: str) -> dict[str, Any]:
    result = first_result(evaluation)
    actual = outcome(result)
    if actual != expected:
        raise DemoError(f"{label} expected value {expected!r}, got {actual!r}: {result}")
    return result


def require_policy_controls(policies: Any) -> None:
    graph = policies.get("@graph") if isinstance(policies, dict) else None
    if not isinstance(graph, list):
        raise DemoError("policy metadata has no @graph")
    controls = next(
        (item for item in graph if isinstance(item, dict) and item.get("@id") == "#policy-nagdi-agriculture-governance-controls"),
        None,
    )
    if not isinstance(controls, dict):
        raise DemoError("policy metadata missing NAgDI agricultural governance controls")
    expectations = {
        "registry_manifest:minimumCellCount": 5,
        "registry_manifest:geographyFloor": "district",
        "registry_manifest:onwardSharingAllowed": False,
        "registry_manifest:automatedDecisionAllowed": False,
        "registry_manifest:auditRequired": True,
    }
    for key, expected in expectations.items():
        if controls.get(key) != expected:
            raise DemoError(f"policy control {key} expected {expected!r}, got {controls.get(key)!r}")
    purposes = set(controls.get("registry_manifest:allowedPurposes") or [])
    required = {PURPOSE, MARKET_PURPOSE, LIVESTOCK_PURPOSE}
    if not required.issubset(purposes):
        raise DemoError(f"policy controls missing purposes: {sorted(required - purposes)}")


def minimized_row_response(response: Any, redacted_fields: set[str]) -> dict[str, Any]:
    if not isinstance(response, dict):
        return {"minimized": True, "body": response}
    copy = json.loads(json.dumps(response))
    rows = copy.get("data")
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                for field in redacted_fields:
                    if field in row:
                        row[field] = "[redacted]"
    copy["artifact_note"] = "Authorized row-read proof with direct identifiers redacted for the demo artifact."
    copy["minimized"] = True
    return copy


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def holder_did() -> str:
    encoded = b64url(json.dumps(DEMO_HOLDER_PUBLIC_JWK, separators=(",", ":")).encode())
    return f"did:jwk:{encoded}"


def sign_holder_proof(
    evaluation_id: str,
    credential_profile: str,
    claims: list[str],
    disclosure: str,
    audience: str,
) -> tuple[str, str]:
    if shutil.which("openssl") is None:
        raise DemoError("openssl is required for the demo holder proof")
    holder_id = holder_did()
    now = int(time.time())
    jti = b64url(hashlib.sha256(f"{holder_id}:{evaluation_id}:{time.time_ns()}".encode()).digest()[:16])
    header = b64url(json.dumps({"alg": "EdDSA", "typ": "kb+jwt", "kid": holder_id}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "sub": holder_id,
                "aud": audience,
                "exp": now + 300,
                "iat": now,
                "jti": jti,
                "evaluation_id": evaluation_id,
                "credential_profile": credential_profile,
                "disclosure": b64url(hashlib.sha256(disclosure.encode("utf-8")).digest()),
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
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(input_path), "-out", str(sig_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return holder_id, f"{signing_input.decode('ascii')}.{b64url(sig_path.read_bytes())}"


def first_result_id(evaluation: dict[str, Any]) -> str:
    evaluation_id = first_result(evaluation).get("evaluation_id")
    if not evaluation_id:
        raise DemoError(f"evaluation response has no evaluation_id: {evaluation}")
    return str(evaluation_id)


def extract_evidence_urls(
    payload: Any,
    allowed_purposes: set[str] | None = None,
    allowed_dataset_ids: set[str] | None = None,
) -> set[str]:
    urls: set[str] = set()
    if isinstance(payload, dict):
        candidates = payload.get("evidence_offerings") or payload.get("data") or []
        if isinstance(candidates, list):
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                dataset_id = item.get("dataset_id")
                if allowed_dataset_ids and dataset_id is not None and dataset_id not in allowed_dataset_ids:
                    continue
                if allowed_purposes:
                    policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
                    purposes = set(policy.get("purpose") or [])
                    if not purposes.intersection(allowed_purposes):
                        continue
                access = item.get("access", {})
                if isinstance(access, dict):
                    for key in ("discovery_url", "endpoint_url", "url"):
                        if access.get(key):
                            urls.add(str(access[key]))
    return urls


def offering_access(payload: Any, *, purpose: str | None = None, offering_id: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    candidates = payload.get("evidence_offerings") or payload.get("data") or []
    if not isinstance(candidates, list):
        return {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        if offering_id and item.get("id") != offering_id:
            continue
        if purpose:
            policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
            purposes = policy.get("purpose") if isinstance(policy, dict) else []
            if purpose not in purposes:
                continue
        access = item.get("access")
        if isinstance(access, dict):
            return access
    return {}


def service_base_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise DemoError(f"metadata URL is not absolute: {url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_service_base_url(metadata_url: str, transport_override: str | None) -> str:
    metadata_base = service_base_url(metadata_url)
    if not transport_override:
        return metadata_base
    metadata = urllib.parse.urlparse(metadata_base)
    override = urllib.parse.urlparse(transport_override)
    compose_names = {
        "agri-registry-relay",
        "nagdi-agriculture-witness",
        "agri-static-metadata-publisher",
    }
    local_hosts = {"127.0.0.1", "localhost", "::1"}
    if metadata.hostname in compose_names and override.hostname in local_hosts:
        return transport_override.rstrip("/")
    return metadata_base


def aggregate_query_path(path: str) -> str:
    parsed = urllib.parse.urlparse(path)
    return f"{parsed.path.rstrip('/')}/query"


def aggregate_summary(response: Any) -> dict[str, Any]:
    rows = response.get("data") if isinstance(response, dict) else None
    if not isinstance(rows, list):
        rows = []
    disclosure = response.get("disclosure_control") if isinstance(response, dict) else None
    suppressed_rows = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else None
    return {
        "artifact_type": "nagdi.agricultural-market-sizing-summary.v1",
        "correlation_id": CORRELATION_ID,
        "purpose": MARKET_PURPOSE,
        "aggregate_rows_seen": len(rows),
        "suppressed_rows": suppressed_rows,
        "contains_personal_rows": False,
        "planning_only": True,
        "aggregate_scope": "district crop risk_band input_type",
        "policy_controls": {
            "minimum_cell_count_required": True,
            "geography_floor_required": True,
            "rare_category_suppression_required": True,
            "row_export_allowed": False,
        },
    }


def scenario_summary(
    evaluations: dict[str, tuple[str, dict[str, Any]]],
    reasons: dict[str, str],
    livestock_evaluations: dict[str, tuple[str, dict[str, Any]]],
    livestock_reasons: dict[str, str],
    denied_controls: dict[str, int],
    manual_review_reasons: dict[str, str],
    credential: dict[str, Any],
    aggregate_summary_doc: dict[str, Any],
    filtered_aggregate: dict[str, Any],
    livestock_aggregate: dict[str, Any],
) -> dict[str, Any]:
    def observed_label(body: dict[str, Any]) -> str:
        value = outcome(first_result(body))
        if value is True:
            return "eligible"
        if value is False:
            return "not_eligible"
        return str(value)

    filtered_body = filtered_aggregate.get("body") if isinstance(filtered_aggregate, dict) else {}
    filtered_disclosure = filtered_body.get("disclosure_control") if isinstance(filtered_body, dict) else {}
    livestock_disclosure = livestock_aggregate.get("disclosure_control") if isinstance(livestock_aggregate, dict) else {}
    return {
        "artifact_type": "nagdi.agricultural-registries-demo-summary.v1",
        "correlation_id": CORRELATION_ID,
        "evaluation_as_of": "2026-05-01",
        "season": "2026A",
        "purpose": PURPOSE,
        "framing": "Evidence for review, planning, or program integrity. Not automatic entitlement or permit issuance.",
        "source_workbooks": [
            "farmer-registry.xlsx",
            "farm-holdings-registry.xlsx",
            "agri-program-registry.xlsx",
            "agroclimate-market-registry.xlsx",
            "livestock-registry.xlsx",
            "nagdi-reference-data.xlsx",
            "nagdi-evidence-snapshots.xlsx",
        ],
        "demo_surfaces": {
            "static_metadata": "service, policy, requirement, and offering discovery",
            "registry_relay": "purpose-bound row reads and aggregate-only market sizing",
            "registry_witness": "voucher and livestock evidence evaluation plus credential issuance",
        },
        "golden_subjects": {
            subject: {
                "expected": expected,
                "observed": observed_label(body),
                "reason_code": reasons.get(subject),
                "reason_codes": first_result(body).get("reason_codes") or first_result(body).get("reasons") or [],
            }
            for subject, (expected, body) in evaluations.items()
        },
        "livestock_subjects": {
            subject: {
                "expected": expected,
                "observed": observed_label(body),
                "reason_code": livestock_reasons.get(subject),
            }
            for subject, (expected, body) in livestock_evaluations.items()
        },
        "market_sizing": {
            "aggregate_rows_seen": aggregate_summary_doc.get("aggregate_rows_seen"),
            "suppressed_rows": aggregate_summary_doc.get("suppressed_rows"),
            "filtered_rows_seen": len(filtered_body.get("data") or []) if isinstance(filtered_body, dict) else None,
            "filtered_suppressed_rows": filtered_disclosure.get("suppressed_rows"),
            "row_export_allowed": False,
        },
        "livestock_planning": {
            "aggregate_rows_seen": len(livestock_aggregate.get("data") or []) if isinstance(livestock_aggregate, dict) else None,
            "suppressed_rows": livestock_disclosure.get("suppressed_rows") if isinstance(livestock_disclosure, dict) else None,
            "contains_individual_animal_rows": False,
            "row_export_allowed": False,
        },
        "manual_review_reasons": manual_review_reasons,
        "denial_controls": denied_controls,
        "credential_issuance": {
            "format": credential.get("format"),
            "credential_type": "climate_smart_input_voucher_sd_jwt",
            "holder_bound": True,
            "credential_present": bool(credential.get("credential")),
        },
        "boundaries": {
            "central_agricultural_database": False,
            "client_wrote_to_relay": False,
            "raw_registry_rows_embedded_in_evidence": False,
            "private_sector_farmer_identification_right": False,
        },
    }


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(os.environ.get("DEMO_OUTPUT_DIR", "output/agri-client")))
    args = parser.parse_args()

    demo_root = Path(__file__).resolve().parents[1]
    load_dotenv(demo_root / ".env")
    out = output_dir(args.output_dir)

    relay = Endpoint("agri-registry-relay", env("AGRI_RELAY_URL", "http://127.0.0.1:4341"), "AGRI_METADATA_CLIENT_RAW")
    witness = Endpoint("nagdi-agriculture-witness", env("AGRI_WITNESS_URL", "http://127.0.0.1:4342"), "AGRI_EVIDENCE_CLIENT_BEARER")
    static = Endpoint("agri-static-metadata-publisher", env("AGRI_STATIC_METADATA_URL", "http://127.0.0.1:4343"))

    dataset = env("AGRI_FARMER_DATASET", "agri_registry")
    entity = env("AGRI_FARMER_ENTITY", "farmer")
    claim = env("AGRI_INPUT_VOUCHER_CLAIM", "eligible-for-climate-smart-input-voucher")
    manual_review_claim = env("AGRI_INPUT_VOUCHER_REASON_CLAIM", "voucher-eligibility-reason-code")
    livestock_claim = env("AGRI_LIVESTOCK_MOVEMENT_CLAIM", "eligible-for-livestock-movement-permit")
    livestock_reason_claim = env("AGRI_LIVESTOCK_MOVEMENT_REASON_CLAIM", "livestock-movement-reason-code")
    aggregate_path = env(
        "AGRI_MARKET_SIZING_PATH",
        "/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input",
    )
    suppressed_aggregate_path = env(
        "AGRI_SUPPRESSED_AGGREGATE_PATH",
        "/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input",
    )
    suppressed_aggregate_filter = env("AGRI_SUPPRESSED_AGGREGATE_FILTER_DISTRICT", "D-WEST")
    livestock_aggregate_path = env(
        "AGRI_LIVESTOCK_AGGREGATE_PATH",
        "/datasets/agri_registry/aggregates/livestock_herds_by_species_district",
    )

    transcript = [
        "# NAgDI Agricultural Registries Demo Transcript",
        "",
        f"- Correlation ID: `{CORRELATION_ID}`",
        "- Evaluation date: `2026-05-01`",
        "- Season: `2026A`",
        "- Framing: evidence for review, planning, or program integrity.",
        "- Demo posture: realistic XLSX registries, decentralized authorities, and purpose-bound APIs.",
        "",
    ]

    print("NAgDI agricultural registries demo")
    print(f"  correlation id: {CORRELATION_ID}")
    print(f"  artifacts: {out}")

    wait_for(
        "agricultural relay /ready",
        lambda: require(request("GET", relay.url, "/ready", env(relay.token_env or "")), 200, "agricultural relay ready"),
    )
    wait_for(
        "agricultural static metadata index",
        lambda: require(request("GET", static.url, "/metadata/index.json"), 200, "agricultural static metadata index"),
    )

    step = 1
    print("\nDiscover static NAgDI metadata")
    api_catalog = require(request("GET", static.url, "/.well-known/api-catalog"), 200, "api catalog")
    save(out, step, "static-api-catalog", api_catalog)
    add_transcript(transcript, f"Discovered the agricultural API catalog at `{static.url}/.well-known/api-catalog`.")
    step += 1

    index = require(request("GET", static.url, "/metadata/index.json"), 200, "metadata index")
    save(out, step, "static-metadata-index", index)
    add_transcript(transcript, "Followed metadata index links without reading any source workbook.")
    step += 1

    offerings = require(request("GET", static.url, "/metadata/evidence-offerings.json"), 200, "static evidence offerings")
    save(out, step, "static-evidence-offerings", offerings)
    story_purposes = {PURPOSE, MARKET_PURPOSE, LIVESTOCK_PURPOSE}
    discovered_urls = extract_evidence_urls(offerings, story_purposes, {"agricultural_registry", "agri_registry"})
    voucher_access = offering_access(offerings, purpose=PURPOSE) or offering_access(offerings, offering_id="climate_smart_input_voucher_evidence_service")
    livestock_access = offering_access(offerings, purpose=LIVESTOCK_PURPOSE) or offering_access(offerings, offering_id="composed_livestock_movement_eligibility_service")
    if not voucher_access.get("discovery_url"):
        raise DemoError("static metadata did not advertise a climate-smart input voucher Witness discovery URL")
    witness = Endpoint(
        "nagdi-agriculture-witness",
        resolve_service_base_url(str(voucher_access["discovery_url"]), env("AGRI_WITNESS_URL", "http://127.0.0.1:4342")),
        "AGRI_EVIDENCE_CLIENT_BEARER",
    )
    add_transcript(transcript, "Found agricultural evidence offerings for voucher, livestock, and market-sizing services.")
    step += 1

    policies = require(request("GET", static.url, "/metadata/policies.jsonld"), 200, "policy metadata")
    require_policy_controls(policies)
    save(out, step, "static-policies", policies)
    add_transcript(transcript, "Confirmed purpose-bound policies and non-automatic decision framing.")
    step += 1

    print("\nDiscover Relay datasets and protected evidence offerings")
    relay_token = env(relay.token_env or "")
    relay_metadata = require(request("GET", relay.url, "/metadata", relay_token), 200, "agricultural relay metadata")
    save(out, step, "relay-metadata", relay_metadata)
    step += 1
    datasets = require(request("GET", relay.url, "/datasets", relay_token), 200, "agricultural datasets")
    save(out, step, "relay-datasets", datasets)
    step += 1
    relay_offerings = require(request("GET", relay.url, "/metadata/evidence-offerings", relay_token), 200, "relay evidence offerings")
    save(out, step, "relay-evidence-offerings", relay_offerings)
    discovered_urls.update(extract_evidence_urls(relay_offerings, story_purposes, {"agri_registry"}))
    relay_voucher_access = offering_access(relay_offerings, purpose=PURPOSE)
    if relay_voucher_access.get("discovery_url"):
        witness = Endpoint(
            "nagdi-agriculture-witness",
            resolve_service_base_url(str(relay_voucher_access["discovery_url"]), witness.url),
            "AGRI_EVIDENCE_CLIENT_BEARER",
        )
    add_transcript(transcript, "Relay exposed metadata, row, aggregate, and evidence-offering surfaces under scoped access.")
    step += 1

    wait_for(
        "agriculture Witness discovery",
        lambda: require(
            request("GET", witness.url, "/.well-known/evidence-service", env(witness.token_env or "")),
            200,
            "agriculture Witness discovery",
        ),
    )

    print("\nDiscover Witness claims")
    witness_token = env(witness.token_env or "")
    discovery = require(request("GET", witness.url, "/.well-known/evidence-service", witness_token), 200, "Witness discovery")
    save(out, step, "witness-discovery", discovery)
    discovery_resolution = {
        "voucher_metadata_discovery_url": voucher_access.get("discovery_url"),
        "livestock_metadata_discovery_url": livestock_access.get("discovery_url"),
        "resolved_witness_base_url": witness.url,
        "transport_override_env": "AGRI_WITNESS_URL",
    }
    step += 1
    claims = require(request("GET", witness.url, "/claims", witness_token), 200, "Witness claims")
    save(out, step, "witness-claims", claims)
    add_transcript(transcript, f"Selected `{claim}` from the agriculture Witness claim catalog.")
    step += 1
    save(out, step, "discovered-evidence-urls", {"discovery_urls": sorted(discovered_urls), "resolution": discovery_resolution})
    step += 1

    print("\nProve evidence clients cannot read personal rows")
    row_path = f"/datasets/{dataset}/{entity}?limit=1"
    evidence_row_denial = request(
        "GET",
        relay.url,
        row_path,
        env("AGRI_EVIDENCE_ONLY_RAW"),
        headers={"Data-Purpose": PURPOSE},
    )
    save(out, step, "row-denial-evidence-only", {"status": evidence_row_denial.status, "body": evidence_row_denial.body})
    require_problem_code(evidence_row_denial, 403, "auth.scope_denied", "evidence-only row denial")
    step += 1
    aggregate_row_denial = request(
        "GET",
        relay.url,
        row_path,
        env("AGRI_AGGREGATE_READER_RAW"),
        headers={"Data-Purpose": PURPOSE},
    )
    save(out, step, "row-denial-aggregate-only", {"status": aggregate_row_denial.status, "body": aggregate_row_denial.body})
    require_problem_code(aggregate_row_denial, 403, "auth.scope_denied", "aggregate-only row denial")
    step += 1
    aggregate_only_entity_denials: dict[str, int] = {}
    for protected_entity in [
        "parcel",
        "voucher_entitlement",
        "voucher_redemption",
        "livestock_holding",
        "herd",
        "movement_permit",
    ]:
        denial = request(
            "GET",
            relay.url,
            f"/datasets/{dataset}/{protected_entity}?limit=1",
            env("AGRI_AGGREGATE_READER_RAW"),
            headers={"Data-Purpose": PURPOSE},
        )
        if denial.status != 403:
            raise DemoError(f"aggregate-only credential row denial for {protected_entity} expected 403, got {denial.status}: {denial.body}")
        aggregate_only_entity_denials[protected_entity] = denial.status
    save(out, step, "row-denial-aggregate-only-sensitive-entities", aggregate_only_entity_denials)
    add_transcript(transcript, "Aggregate-only credentials were denied on farmer, parcel, voucher, livestock, herd, and permit rows.")
    step += 1
    missing_purpose = request("GET", relay.url, row_path, env("AGRI_ROW_READER_RAW"))
    save(out, step, "row-denial-missing-purpose", {"status": missing_purpose.status, "body": missing_purpose.body})
    if missing_purpose.status not in {400, 403, 422}:
        raise DemoError(f"missing Data-Purpose expected 400/403/422, got {missing_purpose.status}")
    denied_controls = {
        "evidence_only_row_read": evidence_row_denial.status,
        "aggregate_only_row_read": aggregate_row_denial.status,
        "aggregate_only_sensitive_entity_row_reads": aggregate_only_entity_denials,
        "missing_data_purpose": missing_purpose.status,
    }
    add_transcript(transcript, "Row export controls denied evidence-only, aggregate-only, and missing-purpose access.")
    step += 1

    print("\nRead one authorized farmer row for operational review context")
    row = require(
        request("GET", relay.url, row_path, env("AGRI_ROW_READER_RAW"), headers={"Data-Purpose": PURPOSE}),
        200,
        "authorized farmer row read",
    )
    save(out, step, "positive-farmer-row-read", minimized_row_response(row, {"national_id", "given_name", "family_name"}))
    add_transcript(transcript, "A row-reader credential could inspect an authorized row only with `Data-Purpose`; direct identifiers were redacted in the demo artifact.")
    step += 1

    print("\nEvaluate climate-smart input voucher evidence")
    eval_specs = {
        "FARMER-1001": "eligible",
        "FARMER-1002": "not_eligible",
        "FARMER-1003": "not_eligible",
        "FARMER-1004": "not_eligible",
        "FARMER-1005": "not_eligible",
    }
    evaluations: dict[str, tuple[str, dict[str, Any]]] = {}
    voucher_reasons: dict[str, str] = {}
    for subject, expected in eval_specs.items():
        body = require(
            request(
                "POST",
                witness.url,
                "/claims/evaluate",
                witness_token,
                evaluation_payload(subject, claim),
                {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} input voucher evaluation",
        )
        save(out, step, f"evaluation-{subject.lower()}", body)
        require_outcome(body, expected, f"{subject} input voucher evaluation")
        evaluations[subject] = (expected, body)
        add_transcript(transcript, f"`{subject}` evaluated as `{expected}` for voucher review evidence.")
        step += 1

    reason_expectations = {
        "FARMER-1002": "parcel.status:not_active",
        "FARMER-1003": "voucher.redemption:already_redeemed",
        "FARMER-1004": "farmer.registration_status:not_active",
        "FARMER-1005": "data_quality:manual_review_required",
    }
    manual_review_reasons: dict[str, str] = {}
    for subject, expected_reason in reason_expectations.items():
        reason_body = require(
            request(
                "POST",
                witness.url,
                "/claims/evaluate",
                witness_token,
                evaluation_payload(subject, manual_review_claim, "value"),
                {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} voucher reason",
        )
        save(out, step, f"evaluation-{subject.lower()}-reason", reason_body)
        reason_result = require_value(reason_body, expected_reason, f"{subject} voucher reason")
        voucher_reasons[subject] = str(outcome(reason_result))
        if subject == "FARMER-1005":
            manual_review_reasons[subject] = str(outcome(reason_result))
        add_transcript(transcript, f"`{subject}` carried reason code `{expected_reason}`.")
        step += 1

    credential_eval = require(
        request(
            "POST",
            witness.url,
            "/claims/evaluate",
            witness_token,
            evaluation_payload("FARMER-1001", claim, "predicate", SD_JWT_FORMAT),
            {"Data-Purpose": PURPOSE, "Accept": SD_JWT_FORMAT},
        ),
        200,
        "FARMER-1001 credential-bound evaluation",
    )
    save(out, step, "credential-bound-evaluation-farmer-1001", credential_eval)
    step += 1
    holder_id, proof = sign_holder_proof(
        first_result_id(credential_eval),
        "climate_smart_input_voucher_sd_jwt",
        [claim],
        "predicate",
        witness.name,
    )
    credential = require(
        request(
            "POST",
            witness.url,
            "/credentials/issue",
            witness_token,
            {
                "evaluation_id": first_result_id(credential_eval),
                "credential_profile": "climate_smart_input_voucher_sd_jwt",
                "format": SD_JWT_FORMAT,
                "claims": [claim],
                "disclosure": "predicate",
                "holder": {"binding": "did", "id": holder_id, "proof": proof},
            },
        ),
        200,
        "climate-smart input voucher credential issuance",
    )
    save(out, step, "climate-smart-input-voucher-credential", credential)
    add_transcript(transcript, "Issued a holder-bound SD-JWT VC for the eligible voucher evidence result.")
    step += 1

    credential_without_holder = request(
        "POST",
        witness.url,
        "/credentials/issue",
        witness_token,
        {
            "evaluation_id": first_result_id(credential_eval),
            "credential_profile": "climate_smart_input_voucher_sd_jwt",
            "format": SD_JWT_FORMAT,
            "claims": [claim],
            "disclosure": "predicate",
        },
    )
    save(
        out,
        step,
        "credential-denial-missing-holder-proof",
        {"status": credential_without_holder.status, "body": credential_without_holder.body},
    )
    if credential_without_holder.status not in {400, 403, 422}:
        raise DemoError(f"credential issuance without holder proof expected denial, got {credential_without_holder.status}")
    add_transcript(transcript, "Credential issuance without holder proof was denied.")
    step += 1

    print("\nEvaluate livestock movement evidence")
    livestock_specs = {
        "HERD-2001": "eligible",
        "HERD-2002": "not_eligible",
        "HERD-2003": "not_eligible",
    }
    livestock_reason_expectations = {
        "HERD-2002": "livestock.vaccination:expired",
        "HERD-2003": "quarantine.origin:active",
    }
    livestock_evaluations: dict[str, tuple[str, dict[str, Any]]] = {}
    livestock_reasons: dict[str, str] = {}
    for subject, expected in livestock_specs.items():
        body = require(
            request(
                "POST",
                witness.url,
                "/claims/evaluate",
                witness_token,
                evaluation_payload(subject, livestock_claim, id_type="herd_id"),
                {"Data-Purpose": LIVESTOCK_PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} livestock movement evaluation",
        )
        save(out, step, f"livestock-evaluation-{subject.lower()}", body)
        require_outcome(body, expected, f"{subject} livestock movement evaluation")
        livestock_evaluations[subject] = (expected, body)
        add_transcript(transcript, f"`{subject}` evaluated as `{expected}` for livestock movement permit review.")
        step += 1
    for subject, expected_reason in livestock_reason_expectations.items():
        reason_body = require(
            request(
                "POST",
                witness.url,
                "/claims/evaluate",
                witness_token,
                evaluation_payload(subject, livestock_reason_claim, "value", id_type="herd_id"),
                {"Data-Purpose": LIVESTOCK_PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} livestock movement reason",
        )
        save(out, step, f"livestock-evaluation-{subject.lower()}-reason", reason_body)
        reason_result = require_value(reason_body, expected_reason, f"{subject} livestock movement reason")
        livestock_reasons[subject] = str(outcome(reason_result))
        add_transcript(transcript, f"`{subject}` carried livestock reason code `{expected_reason}`.")
        step += 1

    print("\nRequest livestock herd aggregate without row access")
    livestock_aggregate = require(
        request("GET", relay.url, livestock_aggregate_path, env("AGRI_AGGREGATE_READER_RAW"), headers={"Data-Purpose": LIVESTOCK_PURPOSE}),
        200,
        "livestock herd planning aggregate",
    )
    save(out, step, "positive-livestock-herd-aggregate", livestock_aggregate)
    livestock_rows = livestock_aggregate.get("data") if isinstance(livestock_aggregate, dict) else None
    if not isinstance(livestock_rows, list) or not livestock_rows:
        raise DemoError(f"livestock herd aggregate expected publishable rows, got {livestock_rows!r}")
    livestock_disclosure = livestock_aggregate.get("disclosure_control") if isinstance(livestock_aggregate, dict) else None
    livestock_suppressed_rows = livestock_disclosure.get("suppressed_rows") if isinstance(livestock_disclosure, dict) else None
    if not isinstance(livestock_suppressed_rows, int) or livestock_suppressed_rows <= 0:
        raise DemoError(f"livestock herd aggregate expected suppressed_rows > 0, got {livestock_suppressed_rows!r}")
    add_transcript(transcript, "Livestock planning used herd-count aggregates while row access to herds and animal records stayed blocked.")
    step += 1

    print("\nRequest market-sizing aggregate without row access")
    aggregate = require(
        request("GET", relay.url, aggregate_path, env("AGRI_AGGREGATE_READER_RAW"), headers={"Data-Purpose": MARKET_PURPOSE}),
        200,
        "agricultural market sizing aggregate",
    )
    save(out, step, "positive-market-sizing-aggregate", aggregate)
    disclosure = aggregate.get("disclosure_control") if isinstance(aggregate, dict) else None
    suppressed_rows = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else None
    if not isinstance(suppressed_rows, int) or suppressed_rows <= 0:
        raise DemoError(f"market sizing aggregate expected suppressed_rows > 0, got {suppressed_rows!r}")
    step += 1
    summary = aggregate_summary(aggregate)
    save(out, step, "market-sizing-summary", summary)
    add_transcript(transcript, "Market sizing used aggregate output and kept row export disabled.")
    step += 1

    row_reader_aggregate_denial = request(
        "GET",
        relay.url,
        aggregate_path,
        env("AGRI_ROW_READER_RAW"),
        headers={"Data-Purpose": MARKET_PURPOSE},
    )
    save(out, step, "aggregate-denial-row-reader", {"status": row_reader_aggregate_denial.status, "body": row_reader_aggregate_denial.body})
    require_problem_code(row_reader_aggregate_denial, 403, "auth.scope_denied", "row-reader aggregate denial")
    denied_controls["row_reader_aggregate"] = row_reader_aggregate_denial.status
    step += 1

    suppressed = request(
        "POST",
        relay.url,
        aggregate_query_path(suppressed_aggregate_path),
        env("AGRI_AGGREGATE_READER_RAW"),
        {"filters": {"district_code": suppressed_aggregate_filter}},
        headers={"Data-Purpose": MARKET_PURPOSE},
    )
    save(out, step, "suppressed-or-denied-rare-cell-aggregate", {"status": suppressed.status, "body": suppressed.body})
    if suppressed.status != 200:
        raise DemoError(f"suppressed aggregate expected 200 with suppressed_groups, got {suppressed.status}")
    disclosure = suppressed.body.get("disclosure_control") if isinstance(suppressed.body, dict) else None
    suppressed_rows = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else None
    if not isinstance(suppressed_rows, int) or suppressed_rows <= 0:
        raise DemoError(f"suppressed aggregate expected suppressed_rows > 0, got {suppressed_rows!r}")
    filtered_rows = suppressed.body.get("data") if isinstance(suppressed.body, dict) else None
    if filtered_rows:
        raise DemoError(f"suppressed aggregate filter expected no publishable rows, got {filtered_rows!r}")
    denied_controls["suppressed_aggregate"] = suppressed.status
    add_transcript(transcript, f"Filtering market sizing to `{suppressed_aggregate_filter}` produced no publishable rows and a suppressed-row count.")
    step += 1

    summary_doc = scenario_summary(
        evaluations,
        voucher_reasons,
        livestock_evaluations,
        livestock_reasons,
        denied_controls,
        manual_review_reasons,
        credential,
        summary,
        {"status": suppressed.status, "body": suppressed.body},
        livestock_aggregate,
    )
    save(out, step, "scenario-summary", summary_doc)
    add_transcript(transcript, "Wrote a scenario summary with no raw secrets and no Relay write-back.")
    step += 1

    write_text(out, "transcript.md", transcript)
    print("\nAgricultural demo client OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
