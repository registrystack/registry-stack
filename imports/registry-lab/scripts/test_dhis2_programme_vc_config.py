#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused regression checks for the DHIS2 programme participation VC demo."""

from __future__ import annotations

import hashlib
import json
import os
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCAL_NOTARY = ROOT / "config/notary/dhis2-health-notary.yaml"
COOLIFY_NOTARY = ROOT / "config/coolify/notary/dhis2-health-notary.yaml"
OPENFN_JOB = ROOT / "config/openfn/jobs/dhis2-health-lookup.js"
LOCAL_SIDECAR = ROOT / "config/openfn/openfn-dhis2-sidecar.yaml.template"
COOLIFY_SIDECAR = ROOT / "config/coolify/openfn/openfn-dhis2-sidecar.yaml.template"
SMOKE = ROOT / "scripts/smoke-dhis2-openfn.sh"
HOLDER_PROOF = ROOT / "scripts/generate-holder-proof.js"
SUMMARY = ROOT / "scripts/summarize-dhis2-programme-vc.py"
TUTORIAL = ROOT / "docs/dhis2-openfn-notary-tutorial.md"
BRUNO_PROGRAMME_VC_DIR = ROOT / "requests/registry-lab/31 - DHIS2 Programme VC"

EXPECTED_CLAIMS = [
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-age-band",
    "dhis2-programme-code",
    "dhis2-child-program-active",
    "dhis2-reconciliation-ref",
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def claim_block(body: str, claim_id: str) -> str:
    marker = f"    - id: {claim_id}\n"
    start = body.index(marker)
    next_claim = body.find("\n    - id: ", start + len(marker))
    if next_claim == -1:
        return body[start:]
    return body[start:next_claim]


def credential_commitment(credential_type: str, credential_id: str, fingerprint: str) -> str:
    payload = {
        "product": "registry-notary",
        "credential_type": credential_type,
        "credential_id": credential_id,
        "fingerprint": fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def credential_commitment_for_env(body: str, env_name: str) -> str:
    pattern = re.compile(
        rf"name:\s*{re.escape(env_name)}\n\s+commitment:\s*(sha256:[0-9a-f]{{64}})"
    )
    match = pattern.search(body)
    if match is None:
        raise AssertionError(f"{env_name} commitment was not found")
    return match.group(1)


def fingerprint(raw: str) -> str:
    return f"sha256:{hashlib.sha256(raw.encode('ascii')).hexdigest()}"


class Dhis2ProgrammeVcConfigTest(unittest.TestCase):
    def assert_notary_profile(self, path: Path, issuer: str, vct: str) -> None:
        body = read(path)
        self.assertIn("max_credential_validity_seconds: 31536000", body)
        self.assertRegex(body, r"concurrency:\n\s+bindings: 4")
        self.assertIn("dhis2_programme_participation_sd_jwt:", body)
        self.assertIn("format: application/dc+sd-jwt", body)
        self.assertIn(f"issuer: {issuer}", body)
        self.assertIn(f"vct: {vct}", body)
        self.assertIn("validity_seconds: 31536000", body)
        self.assertRegex(
            body,
            r"holder_binding:\n\s+mode: did\n\s+proof_of_possession: required\n\s+allowed_did_methods:\n\s+- did:jwk",
        )
        for claim_id in EXPECTED_CLAIMS:
            self.assertIn(f"- {claim_id}", body)
            self.assertIn(
                "- dhis2_programme_participation_sd_jwt",
                claim_block(body, claim_id),
                msg=f"{claim_id} must allow the programme participation profile",
            )
        for field in ("child_age_band", "child_program_code", "reconciliation_ref"):
            self.assertIn(f"field: {field}", body)

    def test_local_notary_profile(self) -> None:
        self.assert_notary_profile(
            LOCAL_NOTARY,
            "did:web:dhis2-health-notary.demo.example.gov",
            "https://demo.example.gov/credentials/dhis2/programme-participation/v1",
        )

    def test_coolify_notary_profile(self) -> None:
        self.assert_notary_profile(
            COOLIFY_NOTARY,
            "did:web:dhis2-notary.lab.registrystack.org",
            "https://dhis2-notary.lab.registrystack.org/credentials/dhis2/programme-participation/v1",
        )

    def test_coolify_dhis2_commitments_match_supplied_hosted_hashes(self) -> None:
        token_hash = os.environ.get("DHIS2_EVIDENCE_CLIENT_TOKEN_HASH")
        bearer_hash = os.environ.get("DHIS2_EVIDENCE_CLIENT_BEARER_HASH")
        if not token_hash or not bearer_hash:
            self.skipTest("set hosted DHIS2 hash envs to verify hosted commitments")

        body = read(COOLIFY_NOTARY)
        self.assertEqual(
            credential_commitment("api_key", "dhis2_evidence_client", token_hash),
            credential_commitment_for_env(body, "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH"),
        )
        self.assertEqual(
            credential_commitment("bearer_token", "dhis2_evidence_client", bearer_hash),
            credential_commitment_for_env(body, "DHIS2_EVIDENCE_CLIENT_BEARER_HASH"),
        )

    def test_coolify_dhis2_raw_credentials_match_supplied_hosted_hashes(self) -> None:
        values = {
            "DHIS2_EVIDENCE_CLIENT_TOKEN": os.environ.get("DHIS2_EVIDENCE_CLIENT_TOKEN"),
            "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH": os.environ.get("DHIS2_EVIDENCE_CLIENT_TOKEN_HASH"),
            "DHIS2_EVIDENCE_CLIENT_BEARER": os.environ.get("DHIS2_EVIDENCE_CLIENT_BEARER"),
            "DHIS2_EVIDENCE_CLIENT_BEARER_HASH": os.environ.get("DHIS2_EVIDENCE_CLIENT_BEARER_HASH"),
        }
        if not all(values.values()):
            self.skipTest("set hosted DHIS2 raw and hash envs to verify credential pairs")

        self.assertEqual(
            fingerprint(values["DHIS2_EVIDENCE_CLIENT_TOKEN"]),
            values["DHIS2_EVIDENCE_CLIENT_TOKEN_HASH"],
        )
        self.assertEqual(
            fingerprint(values["DHIS2_EVIDENCE_CLIENT_BEARER"]),
            values["DHIS2_EVIDENCE_CLIENT_BEARER_HASH"],
        )

    def test_openfn_job_normalizes_programme_fields(self) -> None:
        body = read(OPENFN_JOB)
        self.assertIn("CHILD_PROGRAM_CODE = 'DHIS2_CHILD_PROGRAM'", body)
        self.assertIn("TRACKED_ENTITY_REF_PREFIX = 'dhis2:tracked-entity:'", body)
        self.assertIn("child_program_code: CHILD_PROGRAM_CODE", body)
        self.assertIn("child_program_status: childEnrollment?.status ?? null", body)
        self.assertIn("child_program_active", body)
        self.assertIn("child_age_band: childEnrollment ? '5_to_17' : 'unknown'", body)
        self.assertIn("reconciliation_ref: `${TRACKED_ENTITY_REF_PREFIX}${trackedEntity.trackedEntity}`", body)
        self.assertIn("lookupValue.startsWith(TRACKED_ENTITY_REF_PREFIX)", body)
        self.assertIn("lookupValue.slice(TRACKED_ENTITY_REF_PREFIX.length)", body)

    def test_sidecar_smoke_fields_include_programme_context(self) -> None:
        for path in (LOCAL_SIDECAR, COOLIFY_SIDECAR):
            body = read(path)
            for field in (
                "tracked_entity",
                "child_program_active",
                "child_age_band",
                "child_program_code",
                "reconciliation_ref",
            ):
                self.assertIn(field, body)

    def test_smoke_programme_flow_is_covered(self) -> None:
        body = read(SMOKE)
        self.assertIn("dhis2_programme_participation_sd_jwt", body)
        self.assertIn("smoke-dhis2-programme-participation-evaluation.json", body)
        self.assertIn("smoke-dhis2-programme-participation-holder.json", body)
        self.assertIn("smoke-dhis2-programme-participation-credential.json", body)
        self.assertIn("smoke-dhis2-programme-participation-followup.json", body)
        self.assertIn("smoke-dhis2-programme-participation-credential-summary.json", body)
        self.assertIn("generate-holder-proof.js", body)
        self.assertIn("summarize-dhis2-programme-vc.py", body)
        self.assertIn('claims: ["dhis2-child-program-active"]', body)

    def test_holder_and_summary_helpers_encode_contract(self) -> None:
        holder = read(HOLDER_PROOF)
        self.assertIn("crypto.generateKeyPairSync('ed25519')", holder)
        self.assertIn("typ: 'kb+jwt'", holder)
        self.assertIn("binding: 'did'", holder)
        self.assertIn("did:jwk:", holder)
        self.assertIn("evaluation_id: arg('evaluation-id')", holder)
        self.assertIn("credential_profile: arg('credential-profile')", holder)

        summary = read(SUMMARY)
        self.assertIn('EXPECTED_VALIDITY_SECONDS = 31_536_000', summary)
        self.assertIn('"dhis2-child-age-band"', summary)
        self.assertIn('"dhis2-programme-code"', summary)
        self.assertIn('"dhis2-reconciliation-ref"', summary)
        self.assertIn('"holder_bound": True', summary)
        self.assertIn('"reconciliation_ref_redacted": "dhis2:tracked-entity:<redacted>"', summary)

    def test_tutorial_describes_demo_contract(self) -> None:
        body = read(TUTORIAL)
        self.assertIn("one-year holder-bound credential", body)
        self.assertIn("dhis2_programme_participation_sd_jwt", body)
        self.assertIn("child_age_band: \"5_to_17\"", body)
        self.assertIn("reconciliation reference", body)
        self.assertIn("smoke-dhis2-programme-participation-credential-summary.json", body)

    def test_bruno_programme_vc_walkthrough_is_scripted(self) -> None:
        files = sorted(path.name for path in BRUNO_PROGRAMME_VC_DIR.glob("*.bru"))
        self.assertEqual(
            [
                "01 - Evaluate programme participation claims.bru",
                "02 - Issue holder-bound programme participation VC.bru",
                "03 - Reconcile with fresh online evidence.bru",
            ],
            files,
        )

        evaluate = read(BRUNO_PROGRAMME_VC_DIR / files[0])
        self.assertIn('crypto.generateKeyPairSync("ed25519")', evaluate)
        self.assertIn('bru.setVar("dhis2_programme_evaluation_id"', evaluate)
        self.assertIn('bru.setVar("dhis2_programme_reconciliation_ref"', evaluate)
        self.assertIn("dhis2-reconciliation-ref", evaluate)

        issue = read(BRUNO_PROGRAMME_VC_DIR / files[1])
        self.assertIn("dhis2_programme_participation_sd_jwt", issue)
        self.assertIn("{{dhis2_programme_holder_proof}}", issue)
        self.assertIn("31535940", issue)
        self.assertIn("dhis2_programme_vc_issuer", issue)

        followup = read(BRUNO_PROGRAMME_VC_DIR / files[2])
        self.assertIn("{{dhis2_programme_reconciliation_ref}}", followup)
        self.assertIn('claims": [\n      "dhis2-child-program-active"', followup)


if __name__ == "__main__":
    unittest.main()
