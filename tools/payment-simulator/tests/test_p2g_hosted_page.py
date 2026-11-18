"""Hosted payment page, return URL, cancelled outcome and per-payer outcomes."""

import re
import sqlite3
import uuid
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from payment_simulator import cli
from payment_simulator.api import Settings, create_app
from payment_simulator.store import Store
from tests.test_p2g_service import create, intent, status

RETURN = "https://portal.example.test/paid"
RETURN_HEADER = {"X-Return-URL": RETURN}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture
def service(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-p2g-token")
    token.chmod(0o600)
    settings = Settings(
        token_file=token,
        manual=True,
        return_urls=(RETURN, "https://portal.example.test/done?lang=en"),
    )
    store = Store(tmp_path / "state.sqlite")
    # Redirects point at an unreachable synthetic host, so never follow them.
    with TestClient(create_app(settings, store), follow_redirects=False) as client:
        yield client, settings, store


def page(client, transfer_id):
    return client.get(f"/pay/{transfer_id}")


def token_of(html):
    match = re.search(r'name="token" value="([^"]+)"', html)
    assert match, html
    return match.group(1)


def decide(client, transfer_id, decision, *, token=None, **extra):
    if token is None:
        token = token_of(page(client, transfer_id).text)
    body = f"token={token}&decision={decision}" if token else f"decision={decision}"
    return client.post(f"/pay/{transfer_id}", content=body, headers={**FORM, **extra})


def accept(client, request=None, **extra):
    response = create(client, request, **extra)
    assert response.status_code == 200, response.text
    return response.json()["transferRequestId"]


def poll(client, transfer_id):
    response = status(client, transfer_id)
    assert response.status_code == 200
    return response.json()


def test_return_url_must_be_allow_listed(service):
    client, settings, store = service
    response = create(client, **{"X-Return-URL": "https://evil.example.test/steal"})
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"
    problem = response.json()
    assert problem["code"] == "auth.forbidden"
    assert problem["field"] == "X-Return-URL"
    assert "return-url" in problem["title"].lower()
    assert store.inspect_collections()["requestCount"] == 0
    with TestClient(create_app(replace(settings, return_urls=()), store)) as closed:
        assert create(closed, **RETURN_HEADER).status_code == 403
    # The refusal spends no command identity.
    assert create(client, **RETURN_HEADER).status_code == 200


def test_return_url_header_is_optional_and_single(service):
    client, _, _ = service
    assert create(client).status_code == 200
    blank = create(
        client,
        intent(requestId="fee-003", rtpId=1003, billID="bill-003"),
        **{"X-Return-URL": ""},
    )
    assert blank.status_code == 400


def test_return_url_takes_part_in_the_idempotency_fingerprint(service):
    client, _, _ = service
    first = create(client, **RETURN_HEADER)
    assert create(client, **RETURN_HEADER).json() == first.json()
    changed = create(client, **{"X-Return-URL": "https://portal.example.test/done?lang=en"})
    assert changed.status_code == 409
    assert changed.json()["code"] == "request.id-reused"
    assert create(client).status_code == 409


def test_requests_without_return_url_keep_their_fingerprint(service):
    client, _, _ = service
    accepted = create(client).json()
    assert create(client).json() == accepted


def test_transfer_ids_are_random_uuid4(service):
    client, _, _ = service
    ids = [
        accept(client, intent(requestId=f"fee-{n}", rtpId=2000 + n, billID=f"b-{n}"))
        for n in range(20)
    ]
    assert len(set(ids)) == 20
    for transfer_id in ids:
        parsed = uuid.UUID(transfer_id)
        # UUIDv4 carries 122 random bits from the operating system's CSPRNG.
        assert parsed.version == 4 and str(parsed) == transfer_id


def test_page_shows_banner_bill_and_three_choices(service):
    client, _, _ = service
    transfer_id = accept(client, **RETURN_HEADER)
    response = page(client, transfer_id)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["X-Payment-Simulator"] == "synthetic"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    html = response.text
    assert "Synthetic payment simulator, no real money" in html
    assert "Ministry" in html and "bill-001" in html
    assert "25.50 USD" in html
    for decision in ("pay", "decline", "cancel"):
        assert f'name="decision" value="{decision}"' in html
    assert '<form method="post"' in html
    assert "<script" not in html.lower()
    assert not re.search(r"(src|href)=", html)
    assert not re.search(r"url\(|@import", html)


def test_page_formats_amount_with_the_configured_scale(service):
    client, settings, store = service
    with TestClient(create_app(replace(settings, currencies={"JPY": 0}), store)) as yen:
        request = intent()
        request["billDetails"] = {**request["billDetails"], "amount": 1200, "currency": "JPY"}
        transfer_id = accept(yen, request)
        assert "1200 JPY" in page(yen, transfer_id).text


def test_page_escapes_synthetic_input(service):
    client, _, _ = service
    request = intent()
    request["billDetails"] = {**request["billDetails"], "billerName": "<b>x</b>"}
    transfer_id = accept(client, request)
    html = page(client, transfer_id).text
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html


def test_page_needs_no_bearer_token(service):
    client, _, _ = service
    transfer_id = accept(client)
    assert "Authorization" not in client.headers
    assert page(client, transfer_id).status_code == 200


@pytest.mark.parametrize("transfer_id", ["unknown", "x" * 51, str(uuid.uuid4())])
def test_unknown_transfer_is_404_for_both_methods(service, transfer_id):
    client, _, _ = service
    assert page(client, transfer_id).status_code == 404
    response = client.post(f"/pay/{transfer_id}", content="decision=pay&token=t", headers=FORM)
    assert response.status_code == 404
    assert response.json()["code"] == "resource.not-found"


@pytest.mark.parametrize(
    ("decision", "request_status", "payment_status", "reason", "label"),
    [
        ("pay", "COM", "PAID", None, "paid"),
        ("decline", "RJC", "FAILED", "payer-rejected", "failed"),
        ("cancel", "RJC", "FAILED", "payer-cancelled", "cancelled"),
    ],
)
def test_decision_settles_and_redirects(
    service, decision, request_status, payment_status, reason, label
):
    client, _, store = service
    transfer_id = accept(client, **RETURN_HEADER)
    response = decide(client, transfer_id, decision)
    assert response.status_code == 303
    location = urlsplit(response.headers["Location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == RETURN
    assert parse_qs(location.query) == {"transferRequestId": [transfer_id], "status": [label]}
    result = poll(client, transfer_id)
    assert (result["requestStatus"], result["paymentStatus"]) == (request_status, payment_status)
    assert result.get("failureReason") == reason
    assert ("PaymentReferenceID" in result) == (decision == "pay")
    assert len(store.inspect_collections()["payments"]) == (decision == "pay")


def test_redirect_preserves_an_existing_query(service):
    client, _, _ = service
    transfer_id = accept(client, **{"X-Return-URL": "https://portal.example.test/done?lang=en"})
    location = urlsplit(decide(client, transfer_id, "pay").headers["Location"])
    assert parse_qs(location.query) == {
        "lang": ["en"],
        "transferRequestId": [transfer_id],
        "status": ["paid"],
    }


def test_without_return_url_a_result_page_is_shown(service):
    client, _, _ = service
    transfer_id = accept(client)
    response = decide(client, transfer_id, "pay")
    assert response.status_code == 200
    assert "Synthetic payment simulator, no real money" in response.text
    assert "paid" in response.text.lower()
    assert 'name="decision"' not in response.text
    assert poll(client, transfer_id)["paymentStatus"] == "PAID"


@pytest.mark.parametrize("token", [None, "", "wrong-token"])
def test_missing_or_wrong_form_token_is_refused(service, token):
    client, _, store = service
    transfer_id = accept(client, **RETURN_HEADER)
    other = accept(client, intent(requestId="fee-002", rtpId=1002, billID="bill-002"))
    real = token_of(page(client, other).text)
    body = "decision=pay" if token is None else f"decision=pay&token={token}"
    for candidate in (body, f"decision=pay&token={real}"):
        response = client.post(f"/pay/{transfer_id}", content=candidate, headers=FORM)
        assert response.status_code == 403
        assert response.json()["code"] == "auth.forbidden"
    assert poll(client, transfer_id)["paymentStatus"] == "PENDING"
    assert store.inspect_collections()["payments"] == []


@pytest.mark.parametrize(
    ("body", "headers", "code"),
    [
        ("token={t}&decision=refund", FORM, 400),
        ("token={t}", FORM, 400),
        ("token={t}&token={t}&decision=pay", FORM, 400),
        ("token={t}&decision=pay&extra=1", FORM, 400),
        ('{{"decision":"pay"}}', {"Content-Type": "application/json"}, 415),
    ],
)
def test_malformed_submissions_change_nothing(service, body, headers, code):
    client, _, _ = service
    transfer_id = accept(client, **RETURN_HEADER)
    token = token_of(page(client, transfer_id).text)
    response = client.post(f"/pay/{transfer_id}", content=body.format(t=token), headers=headers)
    assert response.status_code == code
    assert poll(client, transfer_id)["paymentStatus"] == "PENDING"


def test_oversized_submission_is_refused(service):
    client, _, _ = service
    transfer_id = accept(client)
    response = client.post(f"/pay/{transfer_id}", content="a=" + "b" * 10000, headers=FORM)
    assert response.status_code == 413


def test_second_submit_shows_the_final_state_and_changes_nothing(service):
    client, _, store = service
    transfer_id = accept(client, **RETURN_HEADER)
    token = token_of(page(client, transfer_id).text)
    assert decide(client, transfer_id, "pay", token=token).status_code == 303
    before = poll(client, transfer_id)
    for decision in ("pay", "decline", "cancel"):
        again = decide(client, transfer_id, decision, token=token)
        assert again.status_code == 200
        assert "paid" in again.text.lower()
        assert 'name="decision"' not in again.text
        assert RETURN in again.text
    assert poll(client, transfer_id) == before
    assert len(store.inspect_collections()["payments"]) == 1
    assert 'name="decision"' not in page(client, transfer_id).text


def test_return_url_requests_wait_for_the_payer(service):
    client, _, store = service
    waiting = accept(client, **RETURN_HEADER)
    plain = accept(client, intent(requestId="fee-002", rtpId=1002, billID="bill-002"))
    store.advance(3)
    assert poll(client, waiting)["requestStatus"] == "PND"
    assert poll(client, waiting)["paymentStatus"] == "PENDING"
    assert poll(client, plain)["paymentStatus"] == "PAID"
    assert decide(client, waiting, "pay").status_code == 303
    assert poll(client, waiting)["paymentStatus"] == "PAID"


def test_page_on_a_finished_transfer_shows_the_final_state(service):
    client, _, store = service
    transfer_id = accept(client)
    store.advance(2)
    html = page(client, transfer_id).text
    assert "paid" in html.lower() and 'name="decision"' not in html
    # A finished page carries no form, and a guessed token is still refused.
    assert decide(client, transfer_id, "decline", token="whatever").status_code == 403
    assert poll(client, transfer_id)["paymentStatus"] == "PAID"


def test_hosted_decision_beats_the_global_scenario(service):
    client, _, store = service
    store.collection_scenario("registry", "pilot", "ministry", "failed")
    transfer_id = accept(client)
    assert decide(client, transfer_id, "pay").status_code == 200
    assert poll(client, transfer_id)["paymentStatus"] == "PAID"
    store.advance(3)
    assert poll(client, transfer_id)["paymentStatus"] == "PAID"
    assert len(store.inspect_collections()["payments"]) == 1


def test_global_scenario_still_applies_without_the_page(service):
    client, _, store = service
    store.collection_scenario("registry", "pilot", "ministry", "failed")
    transfer_id = accept(client)
    store.advance(2)
    assert poll(client, transfer_id)["failureReason"] == "payer-rejected"


def test_cancelled_global_scenario(service):
    client, _, store = service
    store.collection_scenario("registry", "pilot", "ministry", "cancelled")
    transfer_id = accept(client)
    store.advance(1)
    assert poll(client, transfer_id)["paymentStatus"] == "PENDING"
    store.advance(1)
    result = poll(client, transfer_id)
    assert (result["requestStatus"], result["paymentStatus"]) == ("RJC", "FAILED")
    assert result["failureReason"] == "payer-cancelled"
    assert "PaymentReferenceID" not in result


def test_payer_rule_beats_the_global_scenario(service):
    client, _, store = service
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", "failed")
    mine = accept(client)
    other_request = intent(requestId="fee-002", rtpId=1002, billID="bill-002")
    other_request["payerFiDetails"] = {"payerFIBIC": "TESTBANK", "financialAddress": "someone-else"}
    other = accept(client, other_request)
    store.advance(2)
    assert poll(client, mine)["failureReason"] == "payer-rejected"
    assert poll(client, other)["paymentStatus"] == "PAID"


def test_payer_rule_releases_a_waiting_return_url_request(service):
    client, _, store = service
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", "cancelled")
    transfer_id = accept(client, **RETURN_HEADER)
    store.advance(2)
    assert poll(client, transfer_id)["failureReason"] == "payer-cancelled"
    assert "cancelled" in page(client, transfer_id).text.lower()


def test_hosted_decision_beats_the_payer_rule(service):
    client, _, store = service
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", "failed")
    store.collection_scenario("registry", "pilot", "ministry", "expired")
    transfer_id = accept(client)
    assert decide(client, transfer_id, "pay").status_code == 200
    store.advance(3)
    assert poll(client, transfer_id)["paymentStatus"] == "PAID"


def test_payer_rule_can_be_replaced_and_removed(service):
    client, _, store = service
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", "failed")
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", "expired")
    first = accept(client)
    store.payer_outcome("registry", "pilot", "ministry", "synthetic-citizen", None)
    second = accept(client, intent(requestId="fee-002", rtpId=1002, billID="bill-002"))
    store.advance(2)
    assert poll(client, first)["paymentStatus"] == "EXPIRED"
    assert poll(client, second)["paymentStatus"] == "PAID"


def test_requests_from_before_the_upgrade_get_a_page(service):
    client, _, store = service
    transfer_id = accept(client)
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TABLE collection_hosted")
        db.execute("DROP TABLE payer_outcomes")
        db.execute("PRAGMA user_version=2")
    Store(store.path)
    assert "Synthetic payment simulator" in page(client, transfer_id).text
    assert decide(client, transfer_id, "decline").status_code == 200
    assert poll(client, transfer_id)["failureReason"] == "payer-rejected"


def run_cli(monkeypatch, *arguments):
    monkeypatch.setattr("sys.argv", ["payment-simulator", *arguments])
    cli.main()


def test_payer_outcome_command(service, monkeypatch, capsys):
    client, _, store = service
    database = str(store.path)
    run_cli(
        monkeypatch,
        "payer-outcome",
        "--database",
        database,
        "--address",
        "synthetic-citizen",
        "--outcome",
        "failed",
    )
    transfer_id = accept(client)
    store.advance(2)
    assert poll(client, transfer_id)["paymentStatus"] == "FAILED"
    run_cli(
        monkeypatch,
        "payer-outcome",
        "--database",
        database,
        "--address",
        "synthetic-citizen",
        "--remove",
    )
    again = accept(client, intent(requestId="fee-002", rtpId=1002, billID="bill-002"))
    store.advance(2)
    assert poll(client, again)["paymentStatus"] == "PAID"
    for bad in (
        ["--address", "x"],
        ["--address", "x", "--outcome", "paid", "--remove"],
        ["--address", "x" * 31, "--outcome", "paid"],
    ):
        with pytest.raises(SystemExit) as exit_info:
            run_cli(monkeypatch, "payer-outcome", "--database", database, *bad)
        assert exit_info.value.code == 2
    capsys.readouterr()


def test_collection_scenario_accepts_cancelled(service, monkeypatch):
    client, _, store = service
    run_cli(
        monkeypatch,
        "collection-scenario",
        "--database",
        str(store.path),
        "--outcome",
        "cancelled",
    )
    transfer_id = accept(client)
    store.advance(2)
    assert poll(client, transfer_id)["failureReason"] == "payer-cancelled"


@pytest.fixture
def served(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("synthetic-guard-token")
    token.chmod(0o600)
    calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda app, **kwargs: calls.append(app))

    def run(*extra):
        run_cli(
            monkeypatch,
            "serve",
            "--database",
            str(tmp_path / "state.sqlite"),
            "--token-file",
            str(token),
            *extra,
        )

    return run, calls


def test_serve_return_url_option(served):
    run, calls = served
    run("--return-url", RETURN, "--return-url", "http://localhost:3000/back")
    assert len(calls) == 1
    run()
    assert len(calls) == 2


@pytest.mark.parametrize("url", ["ftp://x.example.test/a", "/relative", "https://" + "a" * 200])
def test_serve_rejects_bad_return_urls(served, capsys, url):
    run, calls = served
    with pytest.raises(SystemExit) as exit_info:
        run("--return-url", url)
    assert exit_info.value.code == 2
    assert "--return-url" in capsys.readouterr().err
    assert calls == []
