from __future__ import annotations

import copy
from decimal import Decimal

import httpx
import pytest

from tests.contract.p2g_support import (
    assert_collection_ack,
    assert_collection_state,
    collection_headers,
    collection_request,
    read_collection,
    submit_collection,
    wait_for_collection_payment_status,
)
from tests.contract.support import assert_problem, exact_json
from tests.fixtures import ContractTarget
from tests.fixtures.lost_response import lost_response_relay
from tests.fixtures.target import decimal_json


def _rtp_id(ids, offset: int = 0) -> int:
    return int(ids.suffix, 16) + 1 + offset


def test_paid_collection_core_is_portable(target: ContractTarget, ids) -> None:
    """P2G-01: a paid collection is correlated, replayable, and stable."""
    test_id = "P2G-01"
    target.configure_collection_scenario("paid", test_id)
    request_id = ids.value("pay", limit=12)
    bill_id = ids.value("b1", limit=10)
    rtp_id = _rtp_id(ids)
    amount = Decimal("10.10")
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=bill_id,
        amount=amount,
    )

    with target.client() as client:
        acknowledgement = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        transfer_request_id = acknowledgement["transferRequestId"]
        replay = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        assert replay == acknowledgement

        if target.is_local_simulator:
            target.advance(test_id, steps=2)
        paid_response = wait_for_collection_payment_status(
            client,
            target,
            transfer_request_id,
            ids.value("paid", limit=20),
            "PAID",
        )
        payment_reference_id = decimal_json(paid_response)["PaymentReferenceID"]
        paid = assert_collection_state(
            paid_response,
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="COM",
            payment_status="PAID",
            payment_reference_id=payment_reference_id,
        )
        repeated = assert_collection_state(
            read_collection(client, target, transfer_request_id, ids.value("rd2", limit=20)),
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="COM",
            payment_status="PAID",
            payment_reference_id=paid["PaymentReferenceID"],
        )
        assert repeated["PaymentReferenceID"] == paid["PaymentReferenceID"]


def test_paid_collection_separates_rtp_completion_from_payment(target: ContractTarget, ids) -> None:
    """P2G-01-STEP: a completed RTP stays unpaid until the payment step commits."""
    test_id = "P2G-01-STEP"
    target.require("hold-processing", test_id)
    target.configure_collection_scenario("paid", test_id)
    request_id = ids.value("step", limit=12)
    bill_id = ids.value("b2", limit=10)
    rtp_id = _rtp_id(ids, 1)
    amount = Decimal("11.11")
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=bill_id,
        amount=amount,
    )

    with target.client() as client:
        acknowledgement = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        transfer_request_id = acknowledgement["transferRequestId"]
        initial = assert_collection_state(
            read_collection(client, target, transfer_request_id, ids.value("rd1", limit=20)),
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="PND",
            payment_status="PENDING",
        )

        target.advance(test_id, steps=1)
        rtp_complete = assert_collection_state(
            read_collection(client, target, transfer_request_id, ids.value("rd2", limit=20)),
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="COM",
            payment_status="PENDING",
        )
        assert rtp_complete["lastUpdateDate"] >= initial["lastUpdateDate"]


@pytest.mark.parametrize(
    ("outcome", "request_status", "payment_status", "failure_reason"),
    [
        ("failed", "RJC", "FAILED", "payer-rejected"),
        ("expired", "EXP", "EXPIRED", "request-expired"),
    ],
)
def test_nonpayment_collection_outcomes(
    target: ContractTarget,
    ids,
    outcome: str,
    request_status: str,
    payment_status: str,
    failure_reason: str,
) -> None:
    """P2G-02/03: failed and expired requests expose their closed terminal state."""
    test_id = f"P2G-{outcome}"
    target.configure_collection_scenario(outcome, test_id)
    request_id = ids.value(outcome[:3], limit=12)
    bill_id = ids.value("bill", limit=10)
    rtp_id = _rtp_id(ids)
    amount = Decimal("20.25")
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=bill_id,
        amount=amount,
    )

    with target.client() as client:
        acknowledgement = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        transfer_request_id = acknowledgement["transferRequestId"]
        assert_collection_state(
            read_collection(client, target, transfer_request_id, ids.value("rd1", limit=20)),
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="PND",
            payment_status="PENDING",
        )

        target.advance(test_id, steps=2)
        assert_collection_state(
            read_collection(client, target, transfer_request_id, ids.value("rd2", limit=20)),
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status=request_status,
            payment_status=payment_status,
            failure_reason=failure_reason,
        )


def test_collection_replay_and_uniqueness_conflicts(target: ContractTarget, ids) -> None:
    """P2G-04: replay is stable and command, RTP, and bill keys cannot be repurposed."""
    request_id = ids.value("req", limit=12)
    bill_id = ids.value("bill", limit=10)
    rtp_id = _rtp_id(ids)
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=bill_id,
        amount=Decimal("30.30"),
    )

    with target.client() as client:
        accepted = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        replay = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        assert replay == accepted

        changed = copy.deepcopy(request)
        changed["billDetails"]["amount"] = Decimal("30.31")
        assert_problem(
            submit_collection(client, target, changed),
            409,
            "request.id-reused",
        )

        reused_rtp = collection_request(
            target,
            request_id=ids.value("r2", limit=12),
            rtp_id=rtp_id,
            bill_id=ids.value("b2", limit=10),
            amount=Decimal("40.40"),
        )
        assert_problem(
            submit_collection(client, target, reused_rtp),
            409,
            "payment.id-reused",
        )

        reused_bill = collection_request(
            target,
            request_id=ids.value("r3", limit=12),
            rtp_id=_rtp_id(ids, 1),
            bill_id=bill_id,
            amount=Decimal("50.50"),
        )
        assert_problem(
            submit_collection(client, target, reused_bill),
            409,
            "collection.bill-in-use",
        )


def test_collection_read_authentication_scope_and_not_found(target: ContractTarget, ids) -> None:
    """P2G-AUTH: reads require valid credentials and the accepted tenant and biller scope."""
    request_id = ids.value("auth", limit=12)
    rtp_id = _rtp_id(ids)
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=ids.value("bill", limit=10),
        amount=Decimal("60.60"),
    )

    with target.client() as client:
        acknowledgement = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        transfer_request_id = acknowledgement["transferRequestId"]
        correlation_id = ids.value("read", limit=20)
        base_headers = {
            "X-Platform-TenantId": target.settings.tenant,
            "X-billerId": target.settings.biller,
            "X-CorrelationID": correlation_id,
        }

        assert_problem(
            read_collection(
                client,
                target,
                transfer_request_id,
                correlation_id,
                headers=base_headers,
            ),
            401,
            "auth.required",
        )
        assert_problem(
            read_collection(
                client,
                target,
                transfer_request_id,
                correlation_id,
                headers={**base_headers, "Authorization": "Bearer invalid-synthetic-token"},
            ),
            401,
            "auth.required",
        )
        assert_problem(
            read_collection(
                client,
                target,
                transfer_request_id,
                correlation_id,
                headers={
                    **base_headers,
                    "Authorization": f"Bearer {target.token()}",
                    "X-Platform-TenantId": ids.value("other", limit=20),
                },
            ),
            403,
            "auth.forbidden",
        )
        assert_problem(
            read_collection(
                client,
                target,
                transfer_request_id,
                correlation_id,
                headers={
                    **base_headers,
                    "Authorization": f"Bearer {target.token()}",
                    "X-billerId": ids.value("other", limit=20),
                },
            ),
            403,
            "auth.forbidden",
        )
        assert_problem(
            read_collection(
                client,
                target,
                ids.value("missing", limit=50),
                correlation_id,
            ),
            404,
            "resource.not-found",
        )


def test_collection_lost_response_restart_replay_and_receipt_witness(
    target: ContractTarget, ids
) -> None:
    """P2G-REC: acceptance and its single paid receipt survive a lost response and restart."""
    test_id = "P2G-REC"
    for capability in ("collection-paid", "lost-response", "restart", "effect-witness"):
        target.require(capability, test_id)
    if not target.is_local_simulator:
        pytest.skip(
            "NOT VERIFIED [P2G-REC]: no external lost-response/restart driver was configured"
        )

    target.configure_collection_scenario("paid", test_id)
    request_id = ids.value("lost", limit=12)
    bill_id = ids.value("bill", limit=10)
    rtp_id = _rtp_id(ids)
    amount = Decimal("70.70")
    request = collection_request(
        target,
        request_id=request_id,
        rtp_id=rtp_id,
        bill_id=bill_id,
        amount=amount,
    )

    with lost_response_relay(target.base_url, expected_status=200) as (relay_url, receipt):
        try:
            httpx.post(
                f"{relay_url}/rtpRequest",
                headers=collection_headers(target, request_id),
                content=exact_json(request).encode("utf-8"),
                timeout=2.0,
            )
        except httpx.TransportError:
            pass
        else:
            raise AssertionError("relay delivered a response that should be lost")
        assert receipt.event.wait(timeout=5), "relay did not receive an upstream response"
        assert receipt.error is None
        hidden_response = receipt.body
        assert hidden_response is not None

    hidden_ack = assert_collection_ack(
        httpx.Response(200, content=hidden_response),
        request_id=request_id,
        rtp_id=rtp_id,
    )
    target.restart(test_id)
    with target.client() as client:
        recovered = assert_collection_ack(
            submit_collection(client, target, request),
            request_id=request_id,
            rtp_id=rtp_id,
        )
        assert recovered == hidden_ack
        transfer_request_id = recovered["transferRequestId"]

        changed = copy.deepcopy(request)
        changed["billDetails"]["amount"] = Decimal("70.71")
        assert_problem(
            submit_collection(client, target, changed),
            409,
            "request.id-reused",
        )

        target.advance(test_id, steps=2)
        paid_response = read_collection(
            client, target, transfer_request_id, ids.value("paid", limit=20)
        )
        paid = decimal_json(paid_response)
        payment_reference_id = paid["PaymentReferenceID"]
        assert_collection_state(
            paid_response,
            transfer_request_id=transfer_request_id,
            request_id=request_id,
            rtp_id=rtp_id,
            bill_id=bill_id,
            amount=amount,
            currency=target.settings.currency,
            request_status="COM",
            payment_status="PAID",
            payment_reference_id=payment_reference_id,
        )

    witness = target.inspect_collections(test_id, transfer_request_id=transfer_request_id)
    assert witness["requestCount"] == 1
    assert len(witness["payments"]) == 1
    assert witness["payments"][0] == {
        "transferRequestId": transfer_request_id,
        "RequestId": request_id,
        "rtpId": rtp_id,
        "billId": bill_id,
        "billerId": target.settings.biller,
        "PaymentReferenceID": payment_reference_id,
        "amount": amount,
        "currency": target.settings.currency,
    }
