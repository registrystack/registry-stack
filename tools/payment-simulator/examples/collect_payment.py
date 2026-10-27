"""Request a synthetic citizen payment and poll for confirmed payment evidence."""

import argparse
import hashlib
import json
import re
import time
from decimal import Decimal
from pathlib import Path

import httpx
import simplejson

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base-url", default="http://127.0.0.1:8008")
parser.add_argument("--token-file", type=Path, required=True)
parser.add_argument(
    "--run-id", default="demo", help="1–6 lowercase letters/digits; reuse to replay"
)
parser.add_argument("--expect", choices=("paid", "failed", "expired"), default="paid")
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9]{1,6}", args.run_id):
    parser.error("--run-id must contain 1–6 lowercase letters/digits")

run = args.run_id
request_id = f"fee-{run}"
bill_id = f"b-{run}"
# Stable synthetic numeric identity, so a rerun recovers the same intent.
rtp_id = int.from_bytes(hashlib.sha256(run.encode()).digest()[:6], "big") or 1
headers = {
    "Authorization": f"Bearer {args.token_file.read_text().strip()}",
    "X-Platform-TenantId": "pilot",
    "X-billerId": "ministry",
    "X-CorrelationID": request_id,
    "X-Callback-URL": "https://programme.example.test/callback",
    "Content-Type": "application/json",
}
# Preserve Decimal as a JSON number without binary float coercion.
payload = simplejson.dumps(
    {
        "requestId": request_id,
        "rtpId": rtp_id,
        "billID": bill_id,
        "requestType": "00",
        "payerFiDetails": {"payerFIBIC": "TESTBANK", "financialAddress": f"citizen-{run}"},
        "billDetails": {"billerName": "Ministry", "amount": Decimal("25.50"), "currency": "USD"},
    },
    use_decimal=True,
)


def decoded(response):
    if response.status_code != 200:
        raise SystemExit(f"Unexpected HTTP {response.status_code}: {response.text}")
    return json.loads(response.content, parse_float=Decimal)


with httpx.Client(base_url=args.base_url, headers=headers, timeout=5) as client:
    accepted = decoded(client.post("/rtpRequest", content=payload))
    assert accepted["responseCode"] == "00" and accepted["requestID"] == request_id
    assert accepted["rtpId"] == rtp_id
    replay = decoded(client.post("/rtpRequest", content=payload))
    assert replay == accepted
    transfer_id = accepted["transferRequestId"]
    deadline = time.monotonic() + 10
    while True:
        result = decoded(
            client.get(
                f"/transferRequests/{transfer_id}", headers={"X-CorrelationID": f"poll-{run}"}
            )
        )
        assert result["transferRequestId"] == transfer_id
        assert result["RequestId"] == request_id and result["rtpId"] == rtp_id
        assert result["billId"] == bill_id
        assert result["amount"] == Decimal("25.50") and result["currency"] == "USD"
        pair = (result["requestStatus"], result["paymentStatus"])
        if pair in {("COM", "PAID"), ("RJC", "FAILED"), ("EXP", "EXPIRED")}:
            break
        if pair not in {("PND", "PENDING"), ("COM", "PENDING")}:
            raise SystemExit("Unknown or inconsistent status; hold for investigation")
        assert "PaymentReferenceID" not in result
        if time.monotonic() >= deadline:
            raise SystemExit(
                "Still pending; retain the original command and retry this same run ID"
            )
        time.sleep(0.1)
    assert result["paymentStatus"] == args.expect.upper()
    if result["paymentStatus"] == "PAID":
        assert 1 <= len(result["PaymentReferenceID"]) <= 20
    else:
        assert "PaymentReferenceID" not in result
    print(
        json.dumps(
            {
                "transferRequestId": transfer_id,
                "paymentStatus": result["paymentStatus"],
                "sameRequestOnReplay": True,
                **(
                    {"PaymentReferenceID": result["PaymentReferenceID"]}
                    if "PaymentReferenceID" in result
                    else {}
                ),
            },
            indent=2,
        )
    )
