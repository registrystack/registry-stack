#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate and summarize the DHIS2 programme participation VC smoke artifacts."""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_PROFILE = "dhis2_programme_participation_sd_jwt"
EXPECTED_FORMAT = "application/dc+sd-jwt"
EXPECTED_ISSUER = "did:web:dhis2-health-notary.demo.example.gov"
EXPECTED_VCT = "https://demo.example.gov/credentials/dhis2/programme-participation/v1"
EXPECTED_VALIDITY_SECONDS = 31_536_000
EXPECTED_CLAIMS = {
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-age-band",
    "dhis2-programme-code",
    "dhis2-child-program-active",
    "dhis2-reconciliation-ref",
}


def b64url_json(value: str):
    padded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def disclosure_claims(disclosures: list[str]) -> dict[str, dict]:
    claims: dict[str, dict] = {}
    for raw in disclosures:
        decoded = b64url_json(raw)
        require(isinstance(decoded, list) and len(decoded) == 3, f"unexpected disclosure: {decoded!r}")
        claim_id = decoded[1]
        value = decoded[2]
        require(isinstance(claim_id, str), f"disclosure claim id is not a string: {decoded!r}")
        require(isinstance(value, dict), f"disclosure value is not an object: {decoded!r}")
        claims[claim_id] = value
    return claims


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: summarize-dhis2-programme-vc.py <evaluation.json> <credential.json> <holder.json> <followup.json> <summary.json>",
            file=sys.stderr,
        )
        return 2

    evaluation = read_json(Path(sys.argv[1]))
    credential = read_json(Path(sys.argv[2]))
    holder = read_json(Path(sys.argv[3]))
    followup = read_json(Path(sys.argv[4]))
    summary_path = Path(sys.argv[5])

    results = {item.get("claim_id"): item for item in evaluation.get("results") or []}
    require(set(results) == EXPECTED_CLAIMS, f"unexpected evaluation claims: {sorted(results)}")
    require(results["dhis2-child-age-band"].get("value") == "5_to_17", "unexpected child age band")
    require(results["dhis2-programme-code"].get("value") == "DHIS2_CHILD_PROGRAM", "unexpected programme code")
    require(results["dhis2-child-program-active"].get("value") is True, "programme active value must be true")
    require(results["dhis2-child-program-active"].get("satisfied") is True, "programme active must be satisfied")
    reconciliation_ref = results["dhis2-reconciliation-ref"].get("value")
    require(
        isinstance(reconciliation_ref, str) and reconciliation_ref.startswith("dhis2:tracked-entity:"),
        "reconciliation ref has unexpected shape",
    )

    require(credential.get("credential_profile") == EXPECTED_PROFILE, "unexpected credential profile")
    require(credential.get("format") == EXPECTED_FORMAT, "unexpected credential format")
    require(credential.get("issuer") == EXPECTED_ISSUER, "unexpected issuer")
    require(credential.get("credential_id"), "missing credential_id")
    require(credential.get("credential"), "missing compact credential")
    require(credential.get("issuer_signed_jwt"), "missing issuer signed JWT")
    disclosures = credential.get("disclosures") or []
    require(len(disclosures) == len(EXPECTED_CLAIMS), "unexpected disclosure count")

    issuer_payload = b64url_json(credential["issuer_signed_jwt"].split(".")[1])
    require(issuer_payload.get("iss") == EXPECTED_ISSUER, "issuer JWT iss mismatch")
    require(issuer_payload.get("vct") == EXPECTED_VCT, "issuer JWT vct mismatch")
    require(issuer_payload.get("sub") == holder.get("holder_id"), "issuer JWT sub must be holder DID")
    require(issuer_payload.get("cnf", {}).get("kid") == holder.get("holder_id"), "missing holder cnf kid")
    validity = int(issuer_payload["exp"]) - int(issuer_payload["iat"])
    require(
        EXPECTED_VALIDITY_SECONDS - 60 <= validity <= EXPECTED_VALIDITY_SECONDS + 60,
        f"unexpected validity seconds: {validity}",
    )

    claims = disclosure_claims(disclosures)
    require(set(claims) == EXPECTED_CLAIMS, f"unexpected disclosure claim ids: {sorted(claims)}")
    require(claims["dhis2-child-age-band"].get("value") == "5_to_17", "age-band disclosure mismatch")
    require(claims["dhis2-programme-code"].get("value") == "DHIS2_CHILD_PROGRAM", "programme disclosure mismatch")
    require(claims["dhis2-child-program-active"].get("value") is True, "active disclosure mismatch")
    require(
        claims["dhis2-reconciliation-ref"].get("value") == reconciliation_ref,
        "reconciliation disclosure mismatch",
    )

    followup_results = followup.get("results") or []
    require(len(followup_results) == 1, "follow-up evaluation must return one result")
    require(followup_results[0].get("claim_id") == "dhis2-child-program-active", "follow-up claim mismatch")
    require(followup_results[0].get("satisfied") is True, "follow-up evidence must satisfy claim")

    expires_at = parse_time(credential["expires_at"])
    issued_at = datetime.fromtimestamp(int(issuer_payload["iat"]), tz=timezone.utc)
    require(abs((expires_at - issued_at).total_seconds() - EXPECTED_VALIDITY_SECONDS) <= 60, "expires_at mismatch")

    summary = {
        "credential_id": credential.get("credential_id"),
        "credential_profile": credential.get("credential_profile"),
        "format": credential.get("format"),
        "issuer": credential.get("issuer"),
        "vct": EXPECTED_VCT,
        "expires_at": credential.get("expires_at"),
        "validity_seconds": validity,
        "holder_bound": True,
        "holder_binding": "did:jwk",
        "holder_id_prefix": str(holder.get("holder_id", ""))[:24],
        "disclosure_count": len(disclosures),
        "disclosure_claim_ids": sorted(claims),
        "child_age_band": claims["dhis2-child-age-band"].get("value"),
        "programme_code": claims["dhis2-programme-code"].get("value"),
        "programme_active": claims["dhis2-child-program-active"].get("value"),
        "reconciliation_ref_available": True,
        "reconciliation_ref_redacted": "dhis2:tracked-entity:<redacted>",
        "followup_evaluation_id": followup_results[0].get("evaluation_id"),
        "followup_satisfied": followup_results[0].get("satisfied"),
        "credential_compact_length": len(credential.get("credential") or ""),
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
