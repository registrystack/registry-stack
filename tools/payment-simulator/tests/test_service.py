"""Focused simulator implementation checks, separate from portable HTTP assertions."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from payment_simulator.api import Settings, create_app
from payment_simulator.store import Store, dumps


@pytest.fixture
def service(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-service-token")
    token.chmod(0o600)
    settings = Settings(token_file=token, manual=True)
    store = Store(tmp_path / "state.sqlite")
    with TestClient(create_app(settings, store)) as client:
        yield client, settings, store


def headers(**extra):
    return {
        "Authorization": "Bearer synthetic-service-token",
        "Platform-TenantId": "pilot",
        "X-Registering-Institution-ID": "ministry",
        "X-CorrelationID": "batch-01",
        "X-Program-Id": "cash-support",
        "X-Callback-URL": "https://programme.example.test/callback",
        **extra,
    }


def instruction(**extra):
    return {
        "requestId": "pay-01",
        "creditParty": [{"key": "payeeIdentity", "value": "person-01"}],
        "debitParty": [{"key": "accountId", "value": "programme-account"}],
        "amount": Decimal("1.00"),
        "currency": "USD",
        "paymentMode": "00",
        **extra,
    }


def submit(client, body=None, **kwargs):
    return client.post(
        "/batchtransactions?type=raw",
        headers=headers(**{"Content-Type": "application/json", **kwargs}),
        content=dumps(body if body is not None else [instruction()]),
    )


@pytest.mark.parametrize(
    "amount",
    [
        "1.00",
        True,
        None,
        Decimal("0"),
        Decimal("-1"),
        Decimal("0.001"),
        Decimal("1e999999"),
        Decimal("1e-999999"),
        Decimal("90071992547409.92"),
    ],
)
def test_invalid_money_never_spends_identity(service, amount):
    client, _, store = service
    response = submit(client, [instruction(amount=amount)])
    assert response.status_code == 400
    assert response.json()["code"] == "request.invalid"
    assert store.inspect()["batchCount"] == 0
    assert submit(client).status_code == 202


@pytest.mark.parametrize(
    "content",
    [
        b'[{"requestId":"first","requestId":"second"}]',
        b'[{"amount":NaN}]',
        b'[{"amount":Infinity}]',
        b'[{"requestId":"\\ud800"}]',
        b"\xff",
        b"[" * 1200,
    ],
)
def test_malformed_json_is_a_bounded_problem(service, content):
    client, _, store = service
    response = client.post(
        "/batchtransactions?type=raw",
        headers=headers(**{"Content-Type": "application/json"}),
        content=content,
    )
    assert response.status_code == 400
    assert response.headers["content-type"] == "application/problem+json"
    assert len(response.content) < 200
    assert store.inspect()["batchCount"] == 0


def test_batch_limits_duplicate_identity_and_decimal_replay(service):
    client, _, store = service
    assert submit(client, [instruction()] * 101).status_code == 413
    assert submit(client, [instruction()] * 2).status_code == 400
    assert (
        submit(
            client,
            [
                instruction(amount=Decimal("90071992547409.91")),
                instruction(requestId="pay-02", amount=Decimal("0.01")),
            ],
        ).status_code
        == 400
    )
    assert store.inspect()["batchCount"] == 0
    accepted = submit(client).json()
    assert submit(client, [instruction(amount=Decimal("1e0"))]).json() == accepted
    refused = submit(client, **{"X-CorrelationID": "batch-02"})
    assert refused.status_code == 409
    assert refused.json()["code"] == "payment.id-reused"
    assert store.inspect()["batchCount"] == 1


def test_missing_mapping_remains_rejected_after_registration(service):
    client, _, store = service
    batch = submit(client).json()["batchId"]
    response = client.post(
        "/identityAccountMapper/beneficiary",
        headers=headers(),
        json={
            "RequestID": "reg-01",
            "Beneficiaries": [
                {
                    "payeeIdentity": "person-01",
                    "PaymentModality": "00",
                    "FinancialAddress": "synthetic-account",
                }
            ],
        },
    )
    assert response.status_code == 200
    store.advance(2)
    row = client.get("/api/v1/batch/detail", headers=headers(), params={"batchId": batch}).json()[0]
    assert row["status"] == "RJCT"
    assert row["errorInformation"] == "mapping-not-found"
    assert "payeePartyId" not in row
    assert store.inspect()["credits"] == []


def test_concurrent_replays_converge(service):
    client, _, store = service
    with ThreadPoolExecutor(max_workers=3) as pool:
        responses = list(pool.map(lambda _: submit(client), range(6)))
    assert all(response.status_code == 202 for response in responses)
    assert len({response.json()["batchId"] for response in responses}) == 1
    assert store.inspect()["batchCount"] == 1


@pytest.mark.parametrize(
    "changed",
    [
        {"currencies": {"USD": 0}},
        {"currencies": {"EUR": 2}},
        {"modes": ("01",)},
    ],
)
def test_replay_survives_payment_configuration_changes(service, changed):
    client, settings, store = service
    original = [instruction(amount=Decimal("1.23"))]
    accepted = submit(client, original).json()
    restored = Store(store.path, create=False)
    with TestClient(create_app(replace(settings, **changed), restored)) as restarted:
        replay = submit(restarted, original)
        assert replay.status_code == 202
        assert replay.json() == accepted
        conflict = submit(restarted, [instruction(amount=Decimal("1.24"))])
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "request.id-reused"
        assert (
            submit(
                restarted,
                [instruction(requestId="pay-02", amount=Decimal("1.23"))],
                **{"X-CorrelationID": "batch-02"},
            ).status_code
            == 400
        )
        rows = restarted.get("/api/v1/batch/detail", headers=headers(), params=accepted).json()
        assert rows[0]["amount"] == 1.23
    assert restored.inspect()["batchCount"] == 1


def test_current_authority_precedes_receipts_and_protected_reads(service):
    client, settings, store = service
    batch = submit(client).json()["batchId"]
    settings.token_file.write_text("synthetic-rotated-token")
    assert submit(client).status_code == 401
    assert submit(client, [instruction(amount=Decimal("2.00"))]).status_code == 401
    renewed = {"Authorization": "Bearer synthetic-rotated-token"}
    assert submit(client, **renewed).json()["batchId"] == batch
    for restriction in ({"programs": ()}, {"institutions": ()}, {"payer_accounts": ()}):
        with TestClient(create_app(replace(settings, **restriction), store)) as restricted:
            assert submit(restricted, **renewed).status_code == 403
            response = restricted.get(
                "/api/v1/batch/detail", headers=headers(**renewed), params={"batchId": batch}
            )
            assert response.status_code == 404
    for isolation in ({"producer": "another"}, {"tenants": ("pilot", "other")}):
        with TestClient(create_app(replace(settings, **isolation), store)) as other:
            scope = (
                renewed if "producer" in isolation else {**renewed, "Platform-TenantId": "other"}
            )
            assert (
                other.get(
                    "/api/v1/batch/detail", headers=headers(**scope), params={"batchId": batch}
                ).status_code
                == 404
            )
            assert submit(other, **scope).status_code == 202


@pytest.mark.parametrize(
    "query",
    [
        "pageNo=-1",
        "pageSize=0",
        "pageSize=51",
        "pageNo=1.0",
        "status=ACCC",
        "direction=INCOMING",
        "pageSize=1&pageSize=2",
    ],
)
def test_detail_refuses_incomplete_or_ambiguous_selectors(service, query):
    client, _, _ = service
    batch = submit(client).json()["batchId"]
    assert (
        client.get(f"/api/v1/batch/detail?batchId={batch}&{query}", headers=headers()).status_code
        == 400
    )


def test_scope_and_decoder_errors_do_not_echo_values(service):
    client, _, store = service
    assert submit(client, **{"X-Program-Id": "other"}).status_code == 403
    assert submit(client, **{"X-Callback-URL": "https://unapproved.test/"}).status_code == 403
    raw_headers = list(headers(**{"Content-Type": "application/json"}).items())
    raw_headers.append(("Platform-TenantId", "other"))
    response = client.post(
        "/batchtransactions?type=raw", headers=raw_headers, content=dumps([instruction()])
    )
    assert response.status_code == 400
    response = submit(
        client,
        [instruction(descriptionText="synthetic-private-canary", unexpected="private-address")],
    )
    assert response.status_code == 400
    assert "canary" not in response.text and "private-address" not in response.text
    assert (
        client.post(
            "/batchtransactions?type=raw",
            headers=headers(**{"Content-Type": "text/plain"}),
            content="x",
        ).status_code
        == 415
    )
    assert (
        client.post(
            "/batchtransactions?type=raw",
            headers=headers(**{"Content-Type": "application/json"}),
            content=b" " * 65537,
        ).status_code
        == 413
    )
    assert store.inspect()["batchCount"] == 0


def test_refuses_incompatible_database_without_erasing_it(tmp_path):
    path = tmp_path / "foreign.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE original(value)")
        db.execute("INSERT INTO original VALUES ('keep')")
    with pytest.raises(ValueError, match="unrecognized"):
        Store(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM original").fetchone()[0] == "keep"
        db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="incompatible"):
        Store(path)


def test_generated_openapi_matches_runtime_contract():
    schema = create_app().openapi()
    expected = Path(__file__).resolve().parents[1] / "contracts" / "openapi.json"
    assert json.loads(expected.read_text()) == schema
    assert sum(len(operations) for operations in schema["paths"].values()) == 7
    for operations in schema["paths"].values():
        for operation in operations.values():
            assert "422" not in operation["responses"]
    assert (
        schema["components"]["schemas"]["Instruction"]["properties"]["amount"]["type"] == "number"
    )
