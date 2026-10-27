from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any

import httpx

from tests.fixtures import ContractTarget
from tests.fixtures.target import decimal_json


def exact_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite Decimal cannot be encoded as JSON")
        return format(value, "f")
    if isinstance(value, list):
        return "[" + ",".join(exact_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(f"{json.dumps(str(key))}:{exact_json(item)}" for key, item in value.items())
            + "}"
        )
    raise TypeError(f"unsupported exact JSON value: {type(value).__name__}")


def assert_problem(response: httpx.Response, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"].split(";", 1)[0] == "application/problem+json"
    problem = decimal_json(response)
    assert problem["type"] == "about:blank"
    assert problem["status"] == status
    assert problem["code"] == code
    return problem


def assert_acknowledgement(response: httpx.Response, request_id: str) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    body = decimal_json(response)
    assert body["responseCode"] == "00"
    assert body["requestID"] == request_id
    assert isinstance(body["responseDescription"], str)
    return body


def register(
    client: httpx.Client,
    target: ContractTarget,
    request_id: str,
    beneficiaries: list[dict[str, Any]],
) -> httpx.Response:
    return client.post(
        "/identityAccountMapper/beneficiary",
        headers=target.headers(
            **{
                "X-Registering-Institution-ID": target.settings.institution,
                "X-Callback-URL": target.settings.registration_callback_url,
            }
        ),
        json={"RequestID": request_id, "Beneficiaries": beneficiaries},
    )


def update(
    client: httpx.Client,
    target: ContractTarget,
    request_id: str,
    beneficiaries: list[dict[str, Any]],
) -> httpx.Response:
    return client.put(
        "/identityAccountMapper/beneficiary",
        headers=target.headers(**{"X-Registering-Institution-ID": target.settings.institution}),
        json={
            "requestID": request_id,
            "sourceBBID": target.settings.source_id,
            "beneficiaries": beneficiaries,
        },
    )


def lookup(
    client: httpx.Client,
    target: ContractTarget,
    payee_identity: str,
    request_id: str,
) -> httpx.Response:
    return client.get(
        "/beneficiary/",
        headers=target.headers(registeringInstitutionId=target.settings.institution),
        params={"payeeIdentity": payee_identity, "requestId": request_id},
    )


def submit(
    client: httpx.Client,
    target: ContractTarget,
    correlation_id: str,
    instructions: list[dict[str, Any]],
) -> httpx.Response:
    return client.post(
        "/batchtransactions",
        params={"type": "raw"},
        headers=target.headers(
            **{
                "Content-Type": "application/json",
                "X-CorrelationID": correlation_id,
                "X-Program-Id": target.settings.programme,
                "X-Registering-Institution-Id": target.settings.institution,
                "X-Callback-URL": target.settings.batch_callback_url,
            }
        ),
        content=exact_json(instructions).encode("utf-8"),
    )


def submission_headers(target: ContractTarget, correlation_id: str) -> dict[str, str]:
    return target.headers(
        **{
            "Content-Type": "application/json",
            "X-CorrelationID": correlation_id,
            "X-Program-Id": target.settings.programme,
            "X-Registering-Institution-Id": target.settings.institution,
            "X-Callback-URL": target.settings.batch_callback_url,
        }
    )


def payment_instruction(
    request_id: str,
    payee_identity: str,
    amount: Decimal,
    target: ContractTarget,
) -> dict[str, Any]:
    return {
        "requestId": request_id,
        "creditParty": [{"key": "payeeIdentity", "value": payee_identity}],
        "debitParty": [{"key": "accountId", "value": target.settings.payer_account}],
        "paymentMode": "00",
        "amount": amount,
        "currency": target.settings.currency,
    }


def batch_page(
    client: httpx.Client,
    target: ContractTarget,
    batch_id: str,
    *,
    page_no: int = 0,
    page_size: int = 10,
    correlation_id: str | None = None,
) -> tuple[httpx.Response, list[dict[str, Any]]]:
    headers = target.headers()
    if correlation_id is not None:
        headers["X-CorrelationID"] = correlation_id
    response = client.get(
        "/api/v1/batch/detail",
        headers=headers,
        params={"batchId": batch_id, "pageNo": page_no, "pageSize": page_size},
    )
    if response.status_code != 200:
        return response, []
    body = decimal_json(response)
    assert isinstance(body, list)
    return response, body


def all_batch_rows(
    client: httpx.Client,
    target: ContractTarget,
    batch_id: str,
    *,
    page_size: int = 1,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page_no in range(101):
        response, page = batch_page(client, target, batch_id, page_no=page_no, page_size=page_size)
        assert response.status_code == 200, response.text
        if not page:
            return rows
        rows.extend(page)
    raise AssertionError("batch pagination did not terminate within 100 pages")


def wait_for_terminal_rows(
    client: httpx.Client,
    target: ContractTarget,
    batch_id: str,
    *,
    page_size: int = 1,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + target.settings.poll_timeout
    latest: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        latest = all_batch_rows(client, target, batch_id, page_size=page_size)
        if latest and all(row.get("status") in {"ACCC", "RJCT"} for row in latest):
            return latest
        time.sleep(target.settings.poll_interval)
    raise AssertionError(f"batch {batch_id!r} did not become terminal: {latest!r}")


def assert_row_identity(
    row: dict[str, Any],
    *,
    request_id: str,
    batch_id: str,
    amount: Decimal,
    address: str,
    currency: str,
) -> None:
    assert row["requestId"] == request_id
    assert row["batchId"] == batch_id
    assert isinstance(row["transactionId"], str) and row["transactionId"]
    assert row["amount"] == amount
    assert row["currency"] == currency
    assert row["direction"] == "OUTGOING"
    assert row["payeePartyId"] == address
    assert row["payeePartyIdType"] == "FINANCIAL_ADDRESS"
    assert isinstance(row["startedAt"], str) and row["startedAt"]
