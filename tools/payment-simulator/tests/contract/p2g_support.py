from __future__ import annotations

import time
from decimal import Decimal
from typing import Any

import httpx

from tests.contract.support import exact_json
from tests.fixtures import ContractTarget
from tests.fixtures.target import decimal_json

SYNTHETIC_BILLER_NAME = "TestBiller"


def collection_request(
    target: ContractTarget,
    *,
    request_id: str,
    rtp_id: int,
    bill_id: str,
    amount: Decimal,
) -> dict[str, Any]:
    return {
        "requestId": request_id,
        "rtpId": rtp_id,
        "billID": bill_id,
        "requestType": "00",
        "payerFiDetails": {
            "payerFIBIC": "TESTBANK",
            "financialAddress": "payer@example.test",
        },
        "billDetails": {
            "billerName": SYNTHETIC_BILLER_NAME,
            "amount": amount,
            "currency": target.settings.currency,
        },
    }


def collection_headers(
    target: ContractTarget,
    correlation_id: str,
    *,
    tenant: str | None = None,
    biller: str | None = None,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {target.token()}",
        "Content-Type": "application/json",
        "X-Platform-TenantId": tenant or target.settings.tenant,
        "X-billerId": biller or target.settings.biller,
        "X-CorrelationID": correlation_id,
        "X-Callback-URL": target.settings.batch_callback_url,
    }


def submit_collection(
    client: httpx.Client,
    target: ContractTarget,
    request: dict[str, Any],
) -> httpx.Response:
    return client.post(
        "/rtpRequest",
        headers=collection_headers(target, request["requestId"]),
        content=exact_json(request).encode("utf-8"),
    )


def assert_collection_ack(
    response: httpx.Response, *, request_id: str, rtp_id: int
) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    body = decimal_json(response)
    assert set(body) == {
        "responseCode",
        "responseDescription",
        "requestID",
        "rtpId",
        "transferRequestId",
    }
    assert body["responseCode"] == "00"
    assert isinstance(body["responseDescription"], str)
    assert len(body["responseDescription"]) <= 200
    assert body["requestID"] == request_id
    assert body["rtpId"] == rtp_id
    assert isinstance(body["transferRequestId"], str)
    assert 1 <= len(body["transferRequestId"]) <= 50
    return body


def read_collection(
    client: httpx.Client,
    target: ContractTarget,
    transfer_request_id: str,
    correlation_id: str,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    read_headers = (
        {
            "Authorization": f"Bearer {target.token()}",
            "X-Platform-TenantId": target.settings.tenant,
            "X-billerId": target.settings.biller,
            "X-CorrelationID": correlation_id,
        }
        if headers is None
        else headers
    )
    return client.get(f"/transferRequests/{transfer_request_id}", headers=read_headers)


def wait_for_collection_payment_status(
    client: httpx.Client,
    target: ContractTarget,
    transfer_request_id: str,
    correlation_id: str,
    payment_status: str,
) -> httpx.Response:
    deadline = time.monotonic() + target.settings.poll_timeout
    latest: httpx.Response | None = None
    while time.monotonic() < deadline:
        latest = read_collection(client, target, transfer_request_id, correlation_id)
        assert latest.status_code == 200, latest.text
        if decimal_json(latest).get("paymentStatus") == payment_status:
            return latest
        time.sleep(target.settings.poll_interval)
    latest_body = None if latest is None else decimal_json(latest)
    raise AssertionError(
        f"collection {transfer_request_id!r} did not reach payment status "
        f"{payment_status!r}: {latest_body!r}"
    )


def assert_collection_state(
    response: httpx.Response,
    *,
    transfer_request_id: str,
    request_id: str,
    rtp_id: int,
    bill_id: str,
    amount: Decimal,
    currency: str,
    request_status: str,
    payment_status: str,
    payment_reference_id: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    assert response.headers["X-CorrelationID"] == response.request.headers["X-CorrelationID"]
    body = decimal_json(response)
    expected_keys = {
        "transferRequestId",
        "RequestId",
        "rtpId",
        "billId",
        "amount",
        "currency",
        "requestStatus",
        "paymentStatus",
        "lastUpdateDate",
    }
    if payment_reference_id is not None:
        expected_keys.add("PaymentReferenceID")
    if failure_reason is not None:
        expected_keys.add("failureReason")
    assert set(body) == expected_keys
    assert body["transferRequestId"] == transfer_request_id
    assert body["RequestId"] == request_id
    assert body["rtpId"] == rtp_id
    assert body["billId"] == bill_id
    assert body["amount"] == amount
    assert body["currency"] == currency
    assert body["requestStatus"] == request_status
    assert body["paymentStatus"] == payment_status
    assert isinstance(body["lastUpdateDate"], int) and not isinstance(body["lastUpdateDate"], bool)
    if payment_reference_id is not None:
        assert body["PaymentReferenceID"] == payment_reference_id
        assert 1 <= len(body["PaymentReferenceID"]) <= 20
    if failure_reason is not None:
        assert body["failureReason"] == failure_reason
    return body
