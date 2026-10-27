"""Implementation checks for the collection profile and additive state upgrade."""

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from payment_simulator.api import Settings, create_app
from payment_simulator.store import SCHEMA_VERSION, Store, dumps
from tests.test_service import headers as g2p_headers
from tests.test_service import submit as submit_g2p


@pytest.fixture
def service(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-p2g-token")
    token.chmod(0o600)
    settings = Settings(token_file=token, manual=True)
    store = Store(tmp_path / "state.sqlite")
    with TestClient(create_app(settings, store)) as client:
        yield client, settings, store


def headers(**extra):
    return {
        "Authorization": "Bearer synthetic-p2g-token",
        "X-Platform-TenantId": "pilot",
        "X-billerId": "ministry",
        "X-CorrelationID": "fee-001",
        "X-Callback-URL": "https://programme.example.test/callback",
        **extra,
    }


def intent(**extra):
    return {
        "requestId": "fee-001",
        "rtpId": 1001,
        "billID": "bill-001",
        "requestType": "00",
        "payerFiDetails": {"payerFIBIC": "TESTBANK", "financialAddress": "synthetic-citizen"},
        "billDetails": {"billerName": "Ministry", "amount": Decimal("25.50"), "currency": "USD"},
        **extra,
    }


def create(client, request=None, **extra):
    request = request if request is not None else intent()
    return client.post(
        "/rtpRequest",
        content=dumps(request),
        headers=headers(
            **{
                "Content-Type": "application/json",
                "X-CorrelationID": request["requestId"],
                **extra,
            }
        ),
    )


def status(client, transfer_id, **extra):
    return client.get(f"/transferRequests/{transfer_id}", headers=headers(**extra))


@pytest.mark.parametrize(
    "changes",
    [
        {"rtpId": True},
        {"rtpId": "1001"},
        {"rtpId": 0},
        {"rtpId": 9007199254740992},
        {"requestType": "01"},
        {"payerFiDetails": None},
        {"paymentStatus": "PAID"},
        {"payerFiDetails": {"payerFIBIC": "TESTBANK", "financialAddress": ""}},
        {"billDetails": {"billerName": "Ministry", "amount": "25.50", "currency": "USD"}},
        {"billDetails": {"billerName": "Ministry", "amount": Decimal("0.001"), "currency": "USD"}},
    ],
)
def test_invalid_collection_does_not_spend_command(service, changes):
    client, _, store = service
    response = create(client, intent(**changes))
    assert response.status_code == 400
    assert response.json()["code"] == "request.invalid"
    assert store.inspect_collections() == {"requestCount": 0, "payments": []}
    assert create(client).status_code == 200


def test_correlation_and_operation_spelling(service):
    client, _, store = service
    assert create(client, **{"X-CorrelationID": "different"}).status_code == 400
    wrong_tenant_header = headers()
    wrong_tenant_header["Platform-TenantId"] = wrong_tenant_header.pop("X-Platform-TenantId")
    assert (
        client.post(
            "/rtpRequest",
            json=intent(billDetails={"billerName": "Ministry", "amount": 1, "currency": "USD"}),
            headers=wrong_tenant_header,
        ).status_code
        == 400
    )
    accepted = create(client).json()
    transfer_id = accepted["transferRequestId"]
    response = status(client, transfer_id, **{"X-CorrelationID": "poll-02"})
    assert response.json()["RequestId"] == "fee-001"
    assert response.headers["X-CorrelationID"] == "poll-02"
    assert (
        client.get(f"/transferRequests/{transfer_id}?status=PAID", headers=headers()).status_code
        == 400
    )
    assert (
        client.request(
            "GET", f"/transferRequests/{transfer_id}", headers=headers(), json={"rtpId": 1001}
        ).status_code
        == 400
    )
    assert (
        client.post("/billTransferRequests", headers=headers(), json={"status": "PAID"}).status_code
        == 404
    )
    assert (
        client.post(
            f"/transferRequests/{transfer_id}", headers=headers(), json={"paymentStatus": "PAID"}
        ).status_code
        == 405
    )
    assert store.inspect_collections()["payments"] == []


def test_concurrent_collection_replay_is_single_acceptance(service):
    client, _, store = service
    with ThreadPoolExecutor(max_workers=3) as pool:
        responses = list(pool.map(lambda _: create(client), range(6)))
    assert all(response.status_code == 200 for response in responses)
    assert len({response.json()["transferRequestId"] for response in responses}) == 1
    store.advance(3)
    witness = store.inspect_collections()
    assert witness["requestCount"] == 1
    assert len(witness["payments"]) == 1


def test_collection_snapshots_survive_config_changes_and_restart(service):
    client, settings, store = service
    original = intent()
    accepted = create(client, original).json()
    store.advance(1)
    store.collection_scenario("registry", "pilot", "ministry", "expired")
    restored = Store(store.path, create=False)
    with TestClient(create_app(replace(settings, currencies={"USD": 0}), restored)) as restarted:
        equivalent = copy.deepcopy(original)
        equivalent["billDetails"]["amount"] = Decimal("25.5000")
        assert create(restarted, equivalent).json() == accepted
        changed = copy.deepcopy(original)
        changed["billDetails"]["amount"] = Decimal("26.00")
        conflict = create(restarted, changed)
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "request.id-reused"
        restored.advance(2)
        result = json.loads(
            status(restarted, accepted["transferRequestId"]).content, parse_float=Decimal
        )
        assert result["paymentStatus"] == "PAID"
        assert result["amount"] == Decimal("25.50")
        assert len(restored.inspect_collections()["payments"]) == 1


def test_current_biller_authority_precedes_receipt_disclosure(service):
    client, settings, store = service
    accepted = create(client).json()
    with TestClient(create_app(replace(settings, billers=()), store)) as restricted:
        assert create(restricted).status_code == 403
        assert create(restricted, intent(billID="different")).status_code == 403
        assert status(restricted, accepted["transferRequestId"]).status_code == 403
    with TestClient(create_app(replace(settings, producer="other-producer"), store)) as other:
        assert status(other, accepted["transferRequestId"]).status_code == 404
        assert create(other).status_code == 200
    settings.token_file.write_text("synthetic-rotated-p2g-token")
    assert create(client).status_code == 401
    renewed = {"Authorization": "Bearer synthetic-rotated-p2g-token"}
    assert create(client, **renewed).json() == accepted


def test_v1_additive_upgrade_preserves_g2p_receipts_and_credits(service):
    client, _, store = service
    authorization = {"Authorization": "Bearer synthetic-p2g-token"}
    assert (
        client.post(
            "/identityAccountMapper/beneficiary",
            headers=g2p_headers(**authorization),
            json={
                "RequestID": "reg-01",
                "Beneficiaries": [
                    {
                        "payeeIdentity": "person-01",
                        "PaymentModality": "00",
                        "FinancialAddress": "original-account",
                    }
                ],
            },
        ).status_code
        == 200
    )
    accepted = submit_g2p(client, **authorization).json()
    store.advance(2)
    before = store.inspect()
    assert len(before["credits"]) == 1
    # Removing only the new, empty tables recreates the exact v1 layout in this
    # disposable fixture. The existing G2P tables, receipts and credits stay intact.
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TABLE collection_payments")
        db.execute("DROP TABLE collection_requests")
        db.execute("DROP TABLE collection_scenarios")
        db.execute("PRAGMA user_version=1")
    with pytest.raises(ValueError, match="start serve"):
        Store(store.path, create=False)
    upgraded = Store(store.path)
    assert upgraded.inspect() == before
    assert submit_g2p(client, **authorization).json() == accepted
    assert create(client).status_code == 200
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
