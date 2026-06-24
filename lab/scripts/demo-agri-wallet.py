#!/usr/bin/env python3
"""Wallet-holder credential probe for the agriculture demo."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from agri_demo_common import (
    CLAIM_RESULT_FORMAT,
    PURPOSE,
    SD_JWT_FORMAT,
    DemoError,
    assert_no_secret_values,
    env,
    evaluation_payload,
    first_result_id,
    load_dotenv,
    outcome,
    prepare_output_dir,
    request,
    require,
    save_json,
)


CLAIM = "eligible-for-climate-smart-input-voucher"


def load_agri_flow_module():
    path = Path(__file__).with_name("demo-agri-flow.py")
    spec = importlib.util.spec_from_file_location("demo_agri_flow_wallet_adapter", path)
    if spec is None or spec.loader is None:
        raise DemoError("cannot load demo-agri-flow.py for holder proof signing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("output/agri-wallet"))
    args = parser.parse_args()

    load_dotenv()
    out = prepare_output_dir(args.output_dir)
    notary_url = env("AGRI_WITNESS_URL", "http://127.0.0.1:4342")
    notary_token = env("AGRI_EVIDENCE_CLIENT_BEARER")
    flow = load_agri_flow_module()

    offer = {
        "artifact_type": "nagdi.wallet-holder-credential-offer.v1",
        "issuer": "nagdi-agriculture-notary",
        "credential_profile": "climate_smart_input_voucher_sd_jwt",
        "format": SD_JWT_FORMAT,
        "claim": CLAIM,
        "subject": "FARMER-1001",
        "holder_binding_required": True,
    }
    save_json(out / "wallet-holder-credential-offer.json", offer)

    eligible_eval = require(
        request(
            "POST",
            notary_url,
            "/v1/evaluations",
            notary_token,
            evaluation_payload("FARMER-1001", CLAIM, "predicate", SD_JWT_FORMAT),
            {"Data-Purpose": PURPOSE, "Accept": SD_JWT_FORMAT},
        ),
        200,
        "FARMER-1001 credential evaluation",
    )
    if outcome(eligible_eval) not in {True, "true", "eligible", "pass", "passed", "satisfied", "approved"}:
        raise DemoError(f"FARMER-1001 must be eligible for wallet credential issuance: {eligible_eval}")
    holder_id, proof = flow.sign_holder_proof(
        first_result_id(eligible_eval),
        "climate_smart_input_voucher_sd_jwt",
        [CLAIM],
        "predicate",
        "nagdi-agriculture-notary",
    )
    credential = require(
        request(
            "POST",
            notary_url,
            "/v1/credentials",
            notary_token,
            {
                "evaluation_id": first_result_id(eligible_eval),
                "credential_profile": "climate_smart_input_voucher_sd_jwt",
                "format": SD_JWT_FORMAT,
                "claims": [CLAIM],
                "disclosure": "predicate",
                "holder": {"binding": "did", "id": holder_id, "proof": proof},
            },
        ),
        200,
        "wallet credential issuance",
    )
    save_json(out / "wallet-holder-credential.json", credential)

    negative_controls = {}
    for subject in ["FARMER-1002", "FARMER-1005"]:
        evaluation = require(
            request(
                "POST",
                notary_url,
                "/v1/evaluations",
                notary_token,
                evaluation_payload(subject, CLAIM),
                {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
            ),
            200,
            f"{subject} negative wallet evaluation",
        )
        value = outcome(evaluation)
        if value in {True, "true", "eligible", "pass", "passed", "satisfied", "approved"}:
            raise DemoError(f"{subject} unexpectedly eligible for wallet credential issuance")
        negative_controls[subject] = {
            "credential_issued": False,
            "observed": value,
        }
    save_json(out / "wallet-holder-negative-control.json", negative_controls)

    summary = {
        "artifact_type": "nagdi.wallet-holder-summary.v1",
        "holder_bound_credential_issued": bool(credential.get("credential")),
        "eligible_subject": "FARMER-1001",
        "negative_controls": negative_controls,
        "raw_source_rows_embedded": False,
        "source_workbooks_read": False,
    }
    if not summary["holder_bound_credential_issued"]:
        raise DemoError("wallet credential response did not contain a credential")
    save_json(out / "wallet-holder-summary.json", summary)
    assert_no_secret_values(out)
    print(f"wallet holder demo OK: {out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
