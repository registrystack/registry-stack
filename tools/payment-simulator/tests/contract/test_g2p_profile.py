from __future__ import annotations

import copy
from decimal import Decimal

import httpx
import pytest

from tests.contract.support import (
    all_batch_rows,
    assert_acknowledgement,
    assert_problem,
    assert_row_identity,
    batch_page,
    contract_amount,
    equivalent_notation,
    exact_json,
    lookup,
    payment_instruction,
    register,
    submission_headers,
    submit,
    update,
    wait_for_terminal_rows,
)
from tests.fixtures import ContractTarget
from tests.fixtures.lost_response import lost_response_relay
from tests.fixtures.target import decimal_json


def _beneficiary(payee: str, address: str) -> dict[str, str]:
    return {
        "payeeIdentity": payee,
        "PaymentModality": "00",
        "FinancialAddress": address,
        "bankingInstitutionCode": "TESTBANK",
    }


def _updated_beneficiary(payee: str, address: str) -> dict[str, str]:
    return {
        "payeeIdentity": payee,
        "paymentModality": "00",
        "financialAddress": address,
    }


def _lookup_address(
    client: httpx.Client,
    target: ContractTarget,
    payee: str,
    request_id: str,
) -> str:
    response = lookup(client, target, payee, request_id)
    assert response.status_code == 200, response.text
    body = decimal_json(response)
    assert body["requestId"] == request_id
    assert len(body["paymentModalityList"]) == 1
    mapping = body["paymentModalityList"][0]
    assert mapping["payeeIdentity"] == payee
    assert mapping["paymentModality"] == "00"
    assert mapping["bankingInstitutionCode"] == "TESTBANK"
    return mapping["financialAddress"]


def _prepare_two_mappings(client: httpx.Client, target: ContractTarget, ids):
    payee_one = ids.value("p1", limit=20)
    payee_two = ids.value("p2", limit=20)
    address_one = ids.value("acct1", limit=30)
    address_two = ids.value("acct2", limit=30)
    updated_two = ids.value("acct2b", limit=30)
    registration_id = ids.value("reg", limit=12)
    response = register(
        client,
        target,
        registration_id,
        [
            _beneficiary(payee_one, address_one),
            _beneficiary(payee_two, address_two),
        ],
    )
    assert_acknowledgement(response, registration_id)
    update_id = ids.value("upd", limit=12)
    assert_acknowledgement(
        update(
            client,
            target,
            update_id,
            [_updated_beneficiary(payee_two, updated_two)],
        ),
        update_id,
    )
    assert _lookup_address(client, target, payee_two, ids.value("look", limit=12)) == updated_two
    return payee_one, payee_two, address_one, updated_two


def test_mapping_round_trip_replay_and_atomic_update(target: ContractTarget, ids) -> None:
    """MAP-01..03: mapping writes are correlated, replayable, and atomic."""
    payee_one = ids.value("p1", limit=20)
    payee_two = ids.value("p2", limit=20)
    missing = ids.value("miss", limit=20)
    address_one = ids.value("acct1", limit=30)
    address_two = ids.value("acct2", limit=30)
    registration_id = ids.value("reg", limit=12)
    beneficiaries = [
        _beneficiary(payee_one, address_one),
        _beneficiary(payee_two, address_two),
    ]

    with target.client() as client:
        first = register(client, target, registration_id, beneficiaries)
        first_body = assert_acknowledgement(first, registration_id)
        replay = register(client, target, registration_id, beneficiaries)
        assert assert_acknowledgement(replay, registration_id) == first_body

        changed = copy.deepcopy(beneficiaries)
        changed[0]["FinancialAddress"] = ids.value("other", limit=30)
        assert_problem(
            register(client, target, registration_id, changed),
            409,
            "request.id-reused",
        )

        assert _lookup_address(client, target, payee_one, ids.value("lk1", limit=12)) == address_one

        refused_update_id = ids.value("badup", limit=12)
        refused = update(
            client,
            target,
            refused_update_id,
            [
                _updated_beneficiary(payee_one, ids.value("atomic", limit=30)),
                _updated_beneficiary(missing, ids.value("unused", limit=30)),
            ],
        )
        assert_problem(refused, 404, "resource.not-found")
        assert _lookup_address(client, target, payee_one, ids.value("lk2", limit=12)) == address_one

        first_update_id = ids.value("up1", limit=12)
        first_update = update(
            client,
            target,
            first_update_id,
            [_updated_beneficiary(payee_two, ids.value("acct2b", limit=30))],
        )
        first_update_body = assert_acknowledgement(first_update, first_update_id)

        second_address = ids.value("acct2c", limit=30)
        second_update_id = ids.value("up2", limit=12)
        assert_acknowledgement(
            update(
                client,
                target,
                second_update_id,
                [_updated_beneficiary(payee_two, second_address)],
            ),
            second_update_id,
        )
        old_replay = update(
            client,
            target,
            first_update_id,
            [_updated_beneficiary(payee_two, ids.value("acct2b", limit=30))],
        )
        assert assert_acknowledgement(old_replay, first_update_id) == first_update_body
        assert (
            _lookup_address(client, target, payee_two, ids.value("lk3", limit=12)) == second_address
        )


def test_all_success_and_stable_pagination(target: ContractTarget, ids) -> None:
    """PAY-01/PAY-06/PAGE-01: scenario 1 completes exactly once per row."""
    target.configure_scenario("success", "PAY-01")
    with target.client() as client:
        payee_one, payee_two, address_one, address_two = _prepare_two_mappings(client, target, ids)
        request_one = ids.value("i1", limit=16)
        request_two = ids.value("i2", limit=16)
        correlation_id = ids.value("bat", limit=12)
        instructions = [
            payment_instruction(request_one, payee_one, contract_amount(target, 10000), target),
            payment_instruction(request_two, payee_two, contract_amount(target, 15000), target),
        ]
        accepted = submit(client, target, correlation_id, instructions)
        assert accepted.status_code == 202, accepted.text
        accepted_body = decimal_json(accepted)
        batch_id = accepted_body["batchId"]
        assert isinstance(batch_id, str) and 0 < len(batch_id) <= 50

        initial = all_batch_rows(client, target, batch_id, page_size=1)
        assert [row["requestId"] for row in initial] == sorted([request_one, request_two])
        by_request = {row["requestId"]: row for row in initial}
        assert_row_identity(
            by_request[request_one],
            request_id=request_one,
            batch_id=batch_id,
            amount=contract_amount(target, 10000),
            address=address_one,
            currency=target.settings.currency,
        )
        assert_row_identity(
            by_request[request_two],
            request_id=request_two,
            batch_id=batch_id,
            amount=contract_amount(target, 15000),
            address=address_two,
            currency=target.settings.currency,
        )
        stable_identity = {
            row["requestId"]: (row["transactionId"], row["amount"]) for row in initial
        }
        beyond_response, beyond = batch_page(client, target, batch_id, page_no=2, page_size=1)
        assert beyond_response.status_code == 200
        assert beyond == []

        target.finish_processing("PAY-01")
        final = wait_for_terminal_rows(client, target, batch_id, page_size=1)
        assert all(row["status"] == "ACCC" for row in final)
        assert all("completedAt" in row for row in final)
        assert sum((row["amount"] for row in final), Decimal("0")) == contract_amount(target, 25000)
        assert {
            row["requestId"]: (row["transactionId"], row["amount"]) for row in final
        } == stable_identity

        replay = submit(client, target, correlation_id, instructions)
        assert replay.status_code == 202
        assert decimal_json(replay)["batchId"] == batch_id


def test_partial_outcome_preserves_both_instructions(target: ContractTarget, ids) -> None:
    """PAY-02: scenario 2 reports one credit and one stable rejection."""
    request_one = ids.value("i1", limit=16)
    request_two = ids.value("i2", limit=16)
    target.configure_scenario("partial", "PAY-02", reject_request=request_two)
    with target.client() as client:
        payee_one, payee_two, _, _ = _prepare_two_mappings(client, target, ids)
        correlation_id = ids.value("bat", limit=12)
        instructions = [
            payment_instruction(request_one, payee_one, contract_amount(target, 10000), target),
            payment_instruction(request_two, payee_two, contract_amount(target, 15000), target),
        ]
        accepted = submit(client, target, correlation_id, instructions)
        assert accepted.status_code == 202, accepted.text
        batch_id = decimal_json(accepted)["batchId"]
        target.finish_processing("PAY-02")
        final = wait_for_terminal_rows(client, target, batch_id)
        assert {row["requestId"] for row in final} == {request_one, request_two}
        by_request = {row["requestId"]: row for row in final}
        assert by_request[request_one]["status"] == "ACCC"
        assert by_request[request_one]["amount"] == contract_amount(target, 10000)
        assert by_request[request_two]["status"] == "RJCT"
        assert by_request[request_two]["amount"] == contract_amount(target, 15000)
        assert by_request[request_two]["errorInformation"] == "account-rejected"
        replay = submit(client, target, correlation_id, instructions)
        assert replay.status_code == 202
        assert decimal_json(replay)["batchId"] == batch_id

    if target.is_local_simulator:
        witness = target.inspect("PAY-02", batch_id=batch_id)
        assert witness["batchCount"] == 1
        assert [credit["requestId"] for credit in witness["credits"]] == [request_one]


def test_exact_decimal_amounts_and_equivalent_replay(target: ContractTarget, ids) -> None:
    """PAY-09: numeric decimals stay exact and equivalent notation replays."""
    target.configure_scenario("success", "PAY-09")
    with target.client() as client:
        payee_one, payee_two, _, _ = _prepare_two_mappings(client, target, ids)
        request_one = ids.value("i1", limit=16)
        request_two = ids.value("i2", limit=16)
        correlation_id = ids.value("bat", limit=12)
        instructions = [
            payment_instruction(request_one, payee_one, contract_amount(target, 10), target),
            payment_instruction(request_two, payee_two, contract_amount(target, 20), target),
        ]
        accepted = submit(client, target, correlation_id, instructions)
        assert accepted.status_code == 202, accepted.text
        batch_id = decimal_json(accepted)["batchId"]

        equivalent = copy.deepcopy(instructions)
        equivalent[0]["amount"] = equivalent_notation(target, contract_amount(target, 10))
        equivalent[1]["amount"] = equivalent_notation(target, contract_amount(target, 20))
        replay = submit(client, target, correlation_id, equivalent)
        assert replay.status_code == 202, replay.text
        assert decimal_json(replay)["batchId"] == batch_id

        target.finish_processing("PAY-09")
        rows = wait_for_terminal_rows(client, target, batch_id, page_size=1)
        assert all(row["status"] == "ACCC" for row in rows)
        assert sum((row["amount"] for row in rows), Decimal("0")) == contract_amount(target, 30)
        assert sorted(row["amount"] for row in rows) == [
            contract_amount(target, 10),
            contract_amount(target, 20),
        ]


def test_destination_is_frozen_at_acceptance(target: ContractTarget, ids) -> None:
    """PAY-08: an accepted batch retains the mapped destination snapshot."""
    target.require("hold-processing", "PAY-08")
    target.require("effect-witness", "PAY-08")
    target.configure_scenario("success", "PAY-08")
    payee = ids.value("p1", limit=20)
    old_address = ids.value("old", limit=30)
    new_address = ids.value("new", limit=30)
    first_request = ids.value("i1", limit=16)
    second_request = ids.value("i2", limit=16)

    with target.client() as client:
        registration_id = ids.value("reg", limit=12)
        assert_acknowledgement(
            register(
                client,
                target,
                registration_id,
                [_beneficiary(payee, old_address)],
            ),
            registration_id,
        )
        first = submit(
            client,
            target,
            ids.value("bat1", limit=12),
            [payment_instruction(first_request, payee, contract_amount(target, 100), target)],
        )
        assert first.status_code == 202, first.text
        first_batch = decimal_json(first)["batchId"]

        update_id = ids.value("upd", limit=12)
        assert_acknowledgement(
            update(
                client,
                target,
                update_id,
                [_updated_beneficiary(payee, new_address)],
            ),
            update_id,
        )
        assert _lookup_address(client, target, payee, ids.value("look", limit=12)) == new_address
        first_rows = all_batch_rows(client, target, first_batch)
        assert first_rows[0]["payeePartyId"] == old_address

        second = submit(
            client,
            target,
            ids.value("bat2", limit=12),
            [payment_instruction(second_request, payee, contract_amount(target, 200), target)],
        )
        assert second.status_code == 202, second.text
        second_batch = decimal_json(second)["batchId"]
        second_rows = all_batch_rows(client, target, second_batch)
        assert second_rows[0]["payeePartyId"] == new_address

        target.advance("PAY-08", steps=2)
        assert wait_for_terminal_rows(client, target, first_batch)[0]["payeePartyId"] == old_address
        assert (
            wait_for_terminal_rows(client, target, second_batch)[0]["payeePartyId"] == new_address
        )

    first_witness = target.inspect("PAY-08", batch_id=first_batch)
    assert len(first_witness["credits"]) == 1
    credit = first_witness["credits"][0]
    assert credit["batchId"] == first_batch
    assert credit["requestId"] == first_request
    assert credit["financialAddress"] == old_address
    assert credit["amount"] == contract_amount(target, 100)
    assert credit["currency"] == target.settings.currency


def test_authentication_and_tenant_scope(target: ContractTarget, ids) -> None:
    """AUTH-01: credentials and tenant/institution scope protect reads."""
    payee = ids.value("p1", limit=20)
    registration_id = ids.value("reg", limit=12)
    with target.client() as client:
        assert_acknowledgement(
            register(
                client,
                target,
                registration_id,
                [_beneficiary(payee, ids.value("acct", limit=30))],
            ),
            registration_id,
        )
        params = {
            "payeeIdentity": payee,
            "requestId": ids.value("look", limit=12),
        }
        no_token = client.get(
            "/beneficiary/",
            headers={
                "Platform-TenantId": target.settings.tenant,
                "registeringInstitutionId": target.settings.institution,
            },
            params=params,
        )
        assert_problem(no_token, 401, "auth.required")

        invalid_token = client.get(
            "/beneficiary/",
            headers={
                "Authorization": "Bearer invalid-synthetic-token",
                "Platform-TenantId": target.settings.tenant,
                "registeringInstitutionId": target.settings.institution,
            },
            params=params,
        )
        assert_problem(invalid_token, 401, "auth.required")

        wrong_tenant = client.get(
            "/beneficiary/",
            headers=target.headers(
                **{
                    "Platform-TenantId": ids.value("other", limit=20),
                    "registeringInstitutionId": target.settings.institution,
                }
            ),
            params=params,
        )
        assert_problem(wrong_tenant, 403, "auth.forbidden")

        wrong_institution = client.get(
            "/beneficiary/",
            headers=target.headers(registeringInstitutionId=ids.value("other", limit=12)),
            params=params,
        )
        assert_problem(wrong_institution, 403, "auth.forbidden")


def test_lost_response_restart_replay_and_effect_witness(target: ContractTarget, ids) -> None:
    """REC-01/02: proven acceptance survives a lost response and restart."""
    for capability in ("lost-response", "restart", "effect-witness"):
        target.require(capability, "REC-01/02")
    if not target.is_local_simulator:
        # Declaring a capability does not invent the provider-specific control.
        pytest.skip(
            "NOT VERIFIED [REC-01/02]: no external lost-response/restart driver was configured"
        )

    target.configure_scenario("success", "REC-01/02")
    request_one = ids.value("i1", limit=16)
    request_two = ids.value("i2", limit=16)
    correlation_id = ids.value("bat", limit=12)
    with target.client() as client:
        payee_one, payee_two, _, _ = _prepare_two_mappings(client, target, ids)
        instructions = [
            payment_instruction(request_one, payee_one, contract_amount(target, 10000), target),
            payment_instruction(request_two, payee_two, contract_amount(target, 15000), target),
        ]
        with lost_response_relay(target.base_url, "/batchtransactions?type=raw") as (
            relay_url,
            receipt,
        ):
            try:
                httpx.post(
                    relay_url,
                    headers=submission_headers(target, correlation_id),
                    content=exact_json(instructions).encode("utf-8"),
                    timeout=2.0,
                )
            except httpx.TransportError:
                pass
            else:
                raise AssertionError("relay delivered a response that should be lost")
            assert receipt.event.wait(timeout=5), "relay did not receive an upstream response"
            assert receipt.error is None
            assert receipt.status_code == 202
            hidden_response = receipt.body
            assert hidden_response is not None

    target.restart("REC-01/02")
    with target.client() as client:
        recovered = submit(client, target, correlation_id, instructions)
        assert recovered.status_code == 202, recovered.text
        recovered_batch = decimal_json(recovered)["batchId"]
        hidden_batch = decimal_json(httpx.Response(202, content=hidden_response))["batchId"]
        assert recovered_batch == hidden_batch

        changed = copy.deepcopy(instructions)
        changed[0]["amount"] = contract_amount(target, 10100)
        assert_problem(
            submit(client, target, correlation_id, changed),
            409,
            "request.id-reused",
        )

        target.finish_processing("REC-01/02")
        final = wait_for_terminal_rows(client, target, recovered_batch)
        assert {row["requestId"] for row in final} == {request_one, request_two}
        assert all(row["status"] == "ACCC" for row in final)
        assert sum((row["amount"] for row in final), Decimal("0")) == contract_amount(target, 25000)

    witness = target.inspect("REC-01/02", batch_id=recovered_batch)
    assert witness["batchCount"] == 1
    credits = witness["credits"]
    assert len(credits) == 2
    assert {credit["requestId"] for credit in credits} == {
        request_one,
        request_two,
    }
    assert all(credit["batchId"] == recovered_batch for credit in credits)
