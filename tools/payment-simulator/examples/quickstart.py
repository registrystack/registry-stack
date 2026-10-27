"""Exercise all five G2P APIs using synthetic data and ordinary HTTP."""

import argparse
import json
import re
import time
from decimal import Decimal
from pathlib import Path

import httpx

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base-url", default="http://127.0.0.1:8008")
parser.add_argument("--token-file", type=Path, required=True)
parser.add_argument(
    "--run-id", default="demo", help="1–6 lowercase letters/digits; reuse to replay"
)
parser.add_argument("--expect", choices=("completed", "partial"), default="completed")
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9]{1,6}", args.run_id):
    parser.error("--run-id must contain 1–6 lowercase letters/digits")

run = args.run_id
headers = {
    "Authorization": f"Bearer {args.token_file.read_text().strip()}",
    "Platform-TenantId": "pilot",
    "X-Registering-Institution-ID": "ministry",
    "X-Callback-URL": "https://programme.example.test/callback",
}


def decoded(response, status=200):
    if response.status_code != status:
        raise SystemExit(f"Unexpected HTTP {response.status_code}: {response.text}")
    return json.loads(response.content, parse_float=Decimal)


with httpx.Client(base_url=args.base_url, headers=headers, timeout=5) as client:
    decoded(
        client.post(
            "/identityAccountMapper/beneficiary",
            json={
                "RequestID": f"reg-{run}",
                "Beneficiaries": [
                    {
                        "payeeIdentity": f"person{i}-{run}",
                        "PaymentModality": "00",
                        "FinancialAddress": f"account{i}-{run}",
                    }
                    for i in (1, 2)
                ],
            },
        )
    )
    decoded(
        client.put(
            "/identityAccountMapper/beneficiary",
            json={
                "requestID": f"upd-{run}",
                "sourceBBID": "registry",
                "beneficiaries": [
                    {
                        "payeeIdentity": f"person2-{run}",
                        "paymentModality": "00",
                        "financialAddress": f"updated2-{run}",
                    }
                ],
            },
        )
    )
    lookup = decoded(
        client.get(
            "/beneficiary/",
            headers={"registeringInstitutionId": "ministry"},
            params={"payeeIdentity": f"person2-{run}", "requestId": f"lk-{run}"},
        )
    )
    assert lookup["paymentModalityList"][0]["financialAddress"] == f"updated2-{run}"

    instructions = [
        {
            "requestId": f"pay{i}-{run}",
            "creditParty": [{"key": "payeeIdentity", "value": f"person{i}-{run}"}],
            "debitParty": [{"key": "accountId", "value": "programme-account"}],
            "paymentMode": "00",
            "amount": amount,
            "currency": "USD",
        }
        for i, amount in ((1, 100), (2, 150))
    ]
    submission_headers = {"X-CorrelationID": f"bat-{run}", "X-Program-Id": "cash-support"}
    accepted = decoded(
        client.post("/batchtransactions?type=raw", headers=submission_headers, json=instructions),
        202,
    )
    replay = decoded(
        client.post("/batchtransactions?type=raw", headers=submission_headers, json=instructions),
        202,
    )
    assert accepted == replay
    batch = accepted["batchId"]
    deadline = time.monotonic() + 10
    while True:
        rows = decoded(
            client.get("/api/v1/batch/detail", params={"batchId": batch, "pageSize": 50})
        )
        assert {row["requestId"] for row in rows} == {item["requestId"] for item in instructions}
        assert all(row["batchId"] == batch for row in rows)
        assert sum((row["amount"] for row in rows), Decimal(0)) == Decimal(250)
        statuses = {row["status"] for row in rows}
        if statuses <= {"ACCC", "RJCT"}:
            break
        if not statuses <= {"PDNG", "ACSP", "ACCC", "RJCT"}:
            raise SystemExit("Unknown payment state; hold for investigation")
        if time.monotonic() >= deadline:
            raise SystemExit(
                "Still pending; retain the original command and retry this same run ID"
            )
        time.sleep(0.1)
    outcome = (
        "completed" if statuses == {"ACCC"} else "failed" if statuses == {"RJCT"} else "partial"
    )
    assert outcome == args.expect, f"expected {args.expect}, observed {outcome}"
    print(
        json.dumps(
            {
                "batchId": batch,
                "outcome": outcome,
                "sameBatchOnReplay": True,
                "instructions": len(rows),
                "amount": "250.00",
                "currency": "USD",
            },
            indent=2,
        )
    )
