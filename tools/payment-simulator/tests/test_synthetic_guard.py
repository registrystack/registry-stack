"""The simulator must never pass for a real payment service."""

import pytest
from fastapi.testclient import TestClient

from payment_simulator import cli
from payment_simulator.api import Settings, create_app
from payment_simulator.store import Store
from tests.test_p2g_service import create as create_collection
from tests.test_p2g_service import status as collection_status


@pytest.fixture
def served(tmp_path, monkeypatch):
    """Run `payment-simulator serve` with uvicorn replaced; yield (run, calls)."""
    token = tmp_path / "token"
    token.write_text("synthetic-guard-token")
    token.chmod(0o600)
    calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))

    def run(*extra):
        argv = [
            "payment-simulator",
            "serve",
            "--database",
            str(tmp_path / "state.sqlite"),
            "--token-file",
            str(token),
            *extra,
        ]
        monkeypatch.setattr("sys.argv", argv)
        cli.main()

    return run, calls


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "payments.example.test"])
def test_serve_refuses_non_loopback_host_without_flag(served, capsys, host):
    run, calls = served
    with pytest.raises(SystemExit) as exit_info:
        run("--host", host)
    assert exit_info.value.code == 2
    assert "--allow-network" in capsys.readouterr().err
    assert calls == []


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_serve_accepts_loopback_host(served, host):
    run, calls = served
    run("--host", host)
    assert [call["host"] for call in calls] == [host]


def test_serve_defaults_to_loopback(served):
    run, calls = served
    run()
    assert [call["host"] for call in calls] == ["127.0.0.1"]


def test_serve_allows_network_host_with_explicit_flag(served):
    run, calls = served
    run("--host", "0.0.0.0", "--allow-network")
    assert [call["host"] for call in calls] == ["0.0.0.0"]


@pytest.fixture
def client(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-p2g-token")
    token.chmod(0o600)
    store = Store(tmp_path / "state.sqlite")
    with TestClient(create_app(Settings(token_file=token, manual=True), store)) as client:
        yield client, store


def test_every_response_carries_the_synthetic_header(client):
    client, _ = client
    ok = client.get("/healthz")
    assert ok.headers["X-Payment-Simulator"] == "synthetic"
    denied = client.get("/beneficiary/")
    assert denied.status_code >= 400
    assert denied.headers["X-Payment-Simulator"] == "synthetic"


def test_payment_reference_is_visibly_synthetic(client):
    client, store = client
    created = create_collection(client)
    assert created.status_code in (200, 202)
    transfer_id = created.json()["transferRequestId"]
    store.advance(2)
    body = collection_status(client, transfer_id).json()
    assert body["paymentStatus"] == "PAID"
    assert body["PaymentReferenceID"].startswith("SIM-")
    assert len(body["PaymentReferenceID"]) <= 20
