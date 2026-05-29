#!/usr/bin/env python3
"""Voucher MIS consumer for the NAgDI agriculture demo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agri_demo_common import (
    CLAIM_RESULT_FORMAT,
    PURPOSE,
    DemoError,
    assert_no_secret_values,
    env,
    evaluation_payload,
    first_result,
    load_dotenv,
    outcome,
    prepare_output_dir,
    request,
    require,
    require_denial,
    save_json,
)


CLAIM = "eligible-for-climate-smart-input-voucher"
REASON_CLAIM = "voucher-eligibility-reason-code"
EXPECTED = {
    "FARMER-1001": ("ready_for_program_review", None),
    "FARMER-1002": ("not_ready_for_program_review", "parcel.status:not_active"),
    "FARMER-1003": ("not_ready_for_program_review", "voucher.redemption:already_redeemed"),
    "FARMER-1004": ("not_ready_for_program_review", "farmer.registration_status:not_active"),
    "FARMER-1005": ("manual_review_required", "data_quality:manual_review_required"),
}


def state_from_result(subject: str, value: object, reason: str | None) -> str:
    if subject == "FARMER-1005" or reason == "data_quality:manual_review_required":
        return "manual_review_required"
    if value in {True, "true", "eligible", "pass", "passed", "satisfied", "approved"}:
        return "ready_for_program_review"
    return "not_ready_for_program_review"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("output/agri-voucher-mis"))
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    relay_url = env("AGRI_RELAY_URL", "http://127.0.0.1:4341")
    notary_url = env("AGRI_WITNESS_URL", "http://127.0.0.1:4342")
    notary_token = env("AGRI_EVIDENCE_CLIENT_BEARER")

    cases: dict[str, dict[str, object]] = {}
    for subject, (expected_state, expected_reason) in EXPECTED.items():
        evaluation = require(
            request(
                "POST",
                notary_url,
                "/claims/evaluate",
                notary_token,
                evaluation_payload(subject, CLAIM),
                {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} voucher evaluation",
        )
        save_json(out / f"voucher-mis-{subject.lower()}-evaluation.json", evaluation)
        reason = None
        if expected_reason:
            reason_doc = require(
                request(
                    "POST",
                    notary_url,
                    "/claims/evaluate",
                    notary_token,
                    evaluation_payload(subject, REASON_CLAIM, "value"),
                    {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
                ),
                200,
                f"{subject} voucher reason",
            )
            save_json(out / f"voucher-mis-{subject.lower()}-reason.json", reason_doc)
            reason = str(outcome(reason_doc))
        state = state_from_result(subject, outcome(evaluation), reason)
        if state != expected_state or reason != expected_reason:
            raise DemoError(
                f"{subject} expected ({expected_state}, {expected_reason}), got ({state}, {reason})"
            )
        cases[subject] = {
            "program_review_state": state,
            "reason_code": reason,
            "evidence_result_id": first_result(evaluation).get("evaluation_id"),
        }

    evidence_denial = request(
        "GET",
        relay_url,
        "/datasets/agri_registry/farmer?limit=1",
        env("AGRI_EVIDENCE_ONLY_RAW"),
        headers={"Data-Purpose": PURPOSE},
    )
    require_denial(evidence_denial, "evidence-only row read")
    save_json(out / "voucher-mis-row-denial-evidence-only.json", {"status": evidence_denial.status, "body": evidence_denial.body})

    missing_purpose = request(
        "GET",
        relay_url,
        "/datasets/agri_registry/farmer?limit=1",
        env("AGRI_ROW_READER_RAW"),
    )
    require_denial(missing_purpose, "missing-purpose row read")
    save_json(out / "voucher-mis-row-denial-missing-purpose.json", {"status": missing_purpose.status, "body": missing_purpose.body})

    summary = {
        "artifact_type": "nagdi.voucher-mis-summary.v1",
        "consumer": "voucher-mis",
        "purpose": PURPOSE,
        "cases": cases,
        "denial_controls": {
            "evidence_only_row_read": evidence_denial.status,
            "missing_data_purpose": missing_purpose.status,
        },
        "source_workbooks_read": False,
    }
    save_json(out / "voucher-mis-summary.json", summary)
    assert_no_secret_values(out)
    print(f"voucher MIS demo OK: {out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
