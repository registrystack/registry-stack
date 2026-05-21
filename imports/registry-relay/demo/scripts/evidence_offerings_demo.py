#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Narrated evidence-offerings demo for a local registry-relay server.

The script is intentionally educational: it prints each request, explains why
that step exists, stores full responses under an output directory, and shows the
privacy boundary between evidence verification and row access.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


EVIDENCE_RECEIPT_MEDIA_TYPE = "application/vnd.registry-relay.evidence-verification+jwt"


@dataclass(frozen=True)
class Scenario:
    name: str
    offering_id: str
    subject_id: str
    claims: dict[str, Any]
    mismatch_claims: dict[str, Any]
    row_path: str
    purpose: str
    explanation: str


SCENARIOS = {
    "benefits": Scenario(
        name="benefits",
        offering_id="benefits_person_evidence",
        subject_id="per-2001",
        claims={
            "id": "per-2001",
            "eligibility_status": "eligible",
            "benefit_role": "member",
        },
        mismatch_claims={
            "id": "per-2001",
            "eligibility_status": "ineligible",
            "benefit_role": "member",
        },
        row_path="/datasets/benefits_casework/person/per-2001",
        purpose="https://demo.example.gov/purpose/social-protection-eligibility",
        explanation=(
            "A downstream service submits benefits status facts and receives a "
            "registry-backed match decision without reading the person row."
        ),
    ),
    "education": Scenario(
        name="education",
        offering_id="education_student_evidence",
        subject_id="stu-2001",
        claims={
            "id": "stu-2001",
            "enrollment_status": "active",
            "grade_level": "g5",
            "home_district": "central",
        },
        mismatch_claims={
            "id": "stu-2001",
            "enrollment_status": "withdrawn",
            "grade_level": "g5",
            "home_district": "central",
        },
        row_path="/datasets/education_registry/student/stu-2001",
        purpose="https://demo.example.gov/purpose/student-support-planning",
        explanation=(
            "A scholarship or support workflow verifies current enrollment "
            "facts before doing any broader linkage or casework."
        ),
    ),
    "disability": Scenario(
        name="disability",
        offering_id="disability_status_evidence_offering",
        subject_id="DR-MEMBER-001",
        claims={
            "member_identifier": "DR-MEMBER-001",
            "disability_status": "Approved",
        },
        mismatch_claims={
            "member_identifier": "DR-MEMBER-001",
            "disability_status": "Not Certified",
        },
        row_path="/datasets/disability_registry/disabled_person/drp-7001",
        purpose="https://demo.example.gov/purpose/disability-benefit-eligibility",
        explanation=(
            "A benefits workflow verifies certified disability status through "
            "the disability registry, not by reading the disability row."
        ),
    ),
    "farmer": Scenario(
        name="farmer",
        offering_id="farmer_status_evidence_offering",
        subject_id="FAKE-830001",
        claims={
            "national_id": "FAKE-830001",
            "farm_type": "Small subsistence-oriented farms",
            "district": "central",
        },
        mismatch_claims={
            "national_id": "FAKE-830001",
            "farm_type": "Cooperative farm",
            "district": "central",
        },
        row_path="/datasets/farmer_registry/farmer/FR-MEMBER-001",
        purpose="https://demo.example.gov/purpose/agricultural-subsidy-eligibility",
        explanation=(
            "An agricultural subsidy workflow verifies farmer registration "
            "facts through the farmer registry using the advertised national_id lookup."
        ),
    ),
}


@dataclass
class HttpResult:
    status: int
    content_type: str
    body: bytes
    path: Path

    def json_body(self) -> Any | None:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def text_body(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("utf-8", errors="replace")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        if "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        try:
            parts = shlex.split(raw_value, comments=False, posix=True)
        except ValueError:
            parts = []
        values[name.strip()] = parts[0] if parts else raw_value.strip().strip("'\"")
    return values


def bearer(env: dict[str, str], name: str) -> str:
    token = env.get(name)
    if not token:
        raise SystemExit(
            f"missing {name}; run `just demo-run ...` once or regenerate demo/.env.local"
        )
    return token


def url_join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def request(
    *,
    base_url: str,
    method: str,
    path: str,
    token: str | None,
    output_dir: Path,
    step: str,
    json_body: Any | None = None,
    headers: dict[str, str] | None = None,
    accept: str | None = None,
) -> HttpResult:
    body_bytes = None
    request_headers = dict(headers or {})
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if accept:
        request_headers["Accept"] = accept
    if json_body is not None:
        body_bytes = json.dumps(json_body, sort_keys=True).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    req = Request(
        url_join(base_url, path),
        data=body_bytes,
        headers=request_headers,
        method=method,
    )
    try:
        with urlopen(req, timeout=10) as resp:
            status = resp.status
            content_type = resp.headers.get("content-type", "")
            body = resp.read()
    except HTTPError as exc:
        status = exc.code
        content_type = exc.headers.get("content-type", "")
        body = exc.read()
    except URLError as exc:
        raise SystemExit(
            f"cannot reach {base_url}: {exc.reason}. Start the demo server first."
        ) from exc

    media_type = content_type.split(";", 1)[0].strip().lower()
    suffix = ".jwt" if media_type == EVIDENCE_RECEIPT_MEDIA_TYPE else ".json"
    if not (media_type == "application/json" or media_type.endswith("+json")) and suffix == ".json":
        suffix = ".txt"
    out_path = output_dir / f"{step}{suffix}"
    out_path.write_bytes(body)
    return HttpResult(status=status, content_type=content_type, body=body, path=out_path)


def chapter(index: int, total: int, title: str, why: str) -> None:
    print(f"\n[{index}/{total}] {title}")
    print(f"Why this matters: {why}")


def print_request(method: str, path: str, body: Any | None = None) -> None:
    print(f"Request: {method} {path}")
    if body is not None:
        print("Submitted body:")
        print(indent(json.dumps(body, indent=2, sort_keys=True)))


def indent(value: str, spaces: int = 2) -> str:
    pad = " " * spaces
    return "\n".join(f"{pad}{line}" for line in value.splitlines())


def print_result(result: HttpResult, summary: str | None = None) -> None:
    print(f"HTTP {result.status}")
    if summary:
        print(summary)
    print(f"Full response written to: {result.path}")


def summarize_offerings(payload: Any) -> str:
    offerings = payload.get("evidence_offerings", []) if isinstance(payload, dict) else []
    lines = [f"Found {len(offerings)} evidence offering(s):"]
    for offering in offerings:
        lines.append(
            f"  - {offering.get('id', '(unknown)')}: "
            f"{offering.get('title', '(untitled)')}"
        )
    return "\n".join(lines)


def summarize_offering(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "Offering response was not JSON."
    authority = payload.get("issuing_authority", {})
    access = payload.get("access", {})
    lines = [
        "Semantic binding:",
        f"  offering id: {payload.get('id')}",
        f"  evidence type: {payload.get('evidence_type')}",
        f"  entity binding: {payload.get('dataset_id')}/{payload.get('entity')}",
        f"  lookup keys: {', '.join(payload.get('lookup_keys', []))}",
        f"  ruleset selected by offering: {access.get('ruleset')}",
        f"  authority: {authority.get('name')} ({authority.get('iri')})",
        f"  level of assurance: {payload.get('level_of_assurance')}",
    ]
    return "\n".join(lines)


def summarize_verification(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "Verification response was not JSON."
    lines = [
        f"Decision: {payload.get('decision')}",
        f"Verification id: {payload.get('verification_id')}",
        f"Requirement: {payload.get('requirement')}",
        f"Evidence type: {payload.get('evidence_type')}",
        f"Evidence offering: {payload.get('evidence_offering')}",
        f"Authority: {payload.get('issuing_authority', {}).get('name')}",
        f"Claim hash present: {'yes' if payload.get('claim_hash') else 'no'}",
        f"Raw claims echoed: {'yes' if 'claims' in payload else 'no'}",
    ]
    return "\n".join(lines)


def ensure_expected(result: HttpResult, expected: set[int], label: str) -> None:
    if result.status not in expected:
        print(f"\nUnexpected status for {label}: HTTP {result.status}", file=sys.stderr)
        print(f"Full response: {result.path}", file=sys.stderr)
        raise SystemExit(1)


def old_route_for(scenario: Scenario) -> str:
    parsed = scenario.row_path.strip("/").split("/")
    dataset_id, entity, record_id = parsed[1], parsed[2], parsed[3]
    return f"/datasets/{dataset_id}/{entity}/verify?id={record_id}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:4242")
    parser.add_argument("--env", default="demo/.env.local", type=Path)
    parser.add_argument(
        "--output",
        default="demo/output/evidence-offerings-demo",
        type=Path,
        help="directory for full responses",
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS),
        default="benefits",
        help="demo story to run. benefits/education use all_demos.yaml; disability/farmer use all_standards.yaml or disability_registry.yaml with SP DCI features.",
    )
    parser.add_argument(
        "--offering",
        help="override the scenario's evidence offering id",
    )
    parser.add_argument(
        "--catalog-token-env",
        default="CATALOG_VIEWER_RAW",
        help="env-file variable containing the catalog viewer token",
    )
    parser.add_argument(
        "--verification-token-env",
        default="VERIFICATION_SERVICE_RAW",
        help="env-file variable containing the evidence verification token",
    )
    parser.add_argument(
        "--signed-receipt",
        action="store_true",
        help="request an evidence-verification JWT receipt for the match step",
    )
    args = parser.parse_args()

    parsed_base = urlparse(args.base_url)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        raise SystemExit("--base-url must be an absolute http(s) URL")

    scenario = SCENARIOS[args.scenario]
    offering_id = args.offering or scenario.offering_id
    env = parse_env_file(args.env)
    catalog_token = bearer(env, args.catalog_token_env)
    verification_token = bearer(env, args.verification_token_env)
    args.output.mkdir(parents=True, exist_ok=True)

    print("Registry Relay evidence-offerings demo")
    print(f"Base URL: {args.base_url}")
    print(f"Scenario: {scenario.name}")
    print(f"Output directory: {args.output}")
    print(f"Demo claim: {scenario.explanation}")

    total_steps = 8

    chapter(1, total_steps, "Check server health", "The relay must be running before discovery and verification.")
    print_request("GET", "/health")
    result = request(
        base_url=args.base_url,
        method="GET",
        path="/health",
        token=None,
        output_dir=args.output,
        step="01-health",
    )
    ensure_expected(result, {200}, "health")
    print_result(result, result.text_body().strip())

    chapter(
        2,
        total_steps,
        "Discover evidence offerings",
        "A caller discovers evidence services by semantics instead of hard-coding datasets and rulesets.",
    )
    print_request("GET", "/metadata/evidence-offerings")
    result = request(
        base_url=args.base_url,
        method="GET",
        path="/metadata/evidence-offerings",
        token=catalog_token,
        output_dir=args.output,
        step="02-evidence-offerings",
    )
    ensure_expected(result, {200}, "evidence offering discovery")
    print_result(result, summarize_offerings(result.json_body()))

    chapter(
        3,
        total_steps,
        "Inspect one offering",
        "The offering tells us which requirement and evidence type it satisfies, who stands behind it, and which registry binding the relay owns.",
    )
    offering_path = f"/metadata/evidence-offerings/{offering_id}"
    print_request("GET", offering_path)
    result = request(
        base_url=args.base_url,
        method="GET",
        path=offering_path,
        token=catalog_token,
        output_dir=args.output,
        step="03-evidence-offering",
    )
    ensure_expected(result, {200}, "evidence offering detail")
    offering_payload = result.json_body()
    print_result(result, summarize_offering(offering_payload))

    chapter(
        4,
        total_steps,
        "Filter discovery by evidence type",
        "This proves discovery is semantic: datasets that merely contain similar fields do not become providers unless they publish a matching offering.",
    )
    evidence_type = (
        offering_payload.get("evidence_type_iri")
        if isinstance(offering_payload, dict)
        else None
    ) or (
        offering_payload.get("evidence_type")
        if isinstance(offering_payload, dict)
        else offering_id
    )
    filtered_path = f"/metadata/evidence-offerings?evidence_type={quote(str(evidence_type), safe=':/')}"
    print_request("GET", filtered_path)
    result = request(
        base_url=args.base_url,
        method="GET",
        path=filtered_path,
        token=catalog_token,
        output_dir=args.output,
        step="04-filtered-evidence-offerings",
    )
    ensure_expected(result, {200}, "filtered evidence offering discovery")
    filtered_payload = result.json_body()
    filtered_items = (
        filtered_payload.get("evidence_offerings", [])
        if isinstance(filtered_payload, dict)
        else []
    )
    filtered_ids = [item.get("id") for item in filtered_items if isinstance(item, dict)]
    if offering_id not in filtered_ids:
        raise SystemExit(
            f"filtered discovery did not include {offering_id}; response written to {result.path}"
        )
    print_result(
        result,
        f"Filtered discovery returned {len(filtered_ids)} provider offering(s): {', '.join(filtered_ids)}",
    )

    chapter(
        5,
        total_steps,
        "Verify submitted facts",
        "The caller submits a predicate about the subject; the relay returns a decision and hashes, not the registry row.",
    )
    verification_path = f"/evidence-offerings/{offering_id}/verifications"
    match_body = {"claims": scenario.claims}
    print_request("POST", verification_path, match_body)
    result = request(
        base_url=args.base_url,
        method="POST",
        path=verification_path,
        token=verification_token,
        output_dir=args.output,
        step="05-verification-match",
        json_body=match_body,
        headers={"Data-Purpose": scenario.purpose},
        accept=EVIDENCE_RECEIPT_MEDIA_TYPE if args.signed_receipt else None,
    )
    ensure_expected(result, {200}, "matching verification")
    if args.signed_receipt:
        print_result(
            result,
            f"Received signed evidence receipt ({len(result.body)} bytes). The compact JWT is written to disk.",
        )
    else:
        print_result(result, summarize_verification(result.json_body()))

    chapter(
        6,
        total_steps,
        "Submit a wrong predicate",
        "A real evidence verifier must prove mismatches too; otherwise this is just an existence lookup.",
    )
    mismatch_body = {"claims": scenario.mismatch_claims}
    print_request("POST", verification_path, mismatch_body)
    result = request(
        base_url=args.base_url,
        method="POST",
        path=verification_path,
        token=verification_token,
        output_dir=args.output,
        step="06-verification-mismatch",
        json_body=mismatch_body,
        headers={"Data-Purpose": scenario.purpose},
    )
    ensure_expected(result, {200}, "mismatching verification")
    print_result(result, summarize_verification(result.json_body()))

    chapter(
        7,
        total_steps,
        "Prove the privacy boundary",
        "The same verification persona can verify submitted facts but must not read source rows.",
    )
    print_request("GET", scenario.row_path)
    result = request(
        base_url=args.base_url,
        method="GET",
        path=scenario.row_path,
        token=verification_token,
        output_dir=args.output,
        step="07-row-access-denied",
        headers={"Data-Purpose": scenario.purpose},
    )
    ensure_expected(result, {403, 404}, "row access boundary")
    print_result(result, "Expected: verification persona cannot read the source row.")

    chapter(
        8,
        total_steps,
        "Show the retired route",
        "The legacy dataset-first verification API is gone; callers should use evidence offerings.",
    )
    removed_path = old_route_for(scenario)
    print_request("GET", removed_path)
    result = request(
        base_url=args.base_url,
        method="GET",
        path=removed_path,
        token=verification_token,
        output_dir=args.output,
        step="08-legacy-route-removed",
        headers={"Data-Purpose": scenario.purpose},
    )
    ensure_expected(result, {404}, "legacy route removal")
    payload = result.json_body()
    code = payload.get("code") if isinstance(payload, dict) else "(unknown)"
    print_result(result, f"Expected legacy route response code: {code}")

    print("\nDemo complete")
    print(
        "Story: Requirement -> Evidence Type -> Evidence Offering -> "
        "Registry Binding -> Verification Decision."
    )
    print("The caller learned what can be verified, got a match/mismatch decision, and never read the private row.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
