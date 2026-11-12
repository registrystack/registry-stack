// SPDX-License-Identifier: Apache-2.0
use registry_adapter::payments::config::PaymentsConfig;
use serde_json::{json, Value};

fn config() -> Value {
    json!({ "connections": [{ "id":"fees", "institutionId":"ministry", "serviceId":"permit",
      "allowedClients":["payment-coordinator"], "requiredScope":"payments:collections",
      "binding": { "simulation":true, "currency":"USD", "currencyScale":2, "providerCredentialRef":"secret:env/SIMULATOR_TOKEN",
        "providerCredentialIdentity":"synthetic-producer", "replayWindowSeconds":3600,
        "provider": { "type":"simulator", "connection": {
          "baseUrl":"http://127.0.0.1:8099/", "tenant":"pilot", "biller":"ministry",
          "billerName":"Ministry", "callbackUrl":"https://programme.example.test/callback", "payerFiBic":"SIMBANK" } },
        "registry": { "baseUrl":"http://127.0.0.1:8080/", "readProfile":"payment-adapter-reporter", "bindProfile":"payment-adapter-binder", "receiptProfile":"payment-adapter-reporter", "recordType":"service-fee-bill", "recordRoute":"service-fee-bills",
          "bindAction":"bind-payment-attempt", "receiptAction":"record-payment-receipt",
          "credentialRef":"secret:env/PAYMENT_REPORTER_TOKEN", "credentialIdentity":"payment-adapter" }
      }
    }] })
}

fn mifos_config() -> Value {
    let mut value = config();
    value["connections"][0]["binding"]["simulation"] = json!(false);
    value["connections"][0]["binding"]["currency"] = json!("KES");
    value["connections"][0]["binding"]["provider"] = json!({
        "type": "mifos",
        "connection": {
            "channelBaseUrl": "https://channel.example.test/",
            "bulkBaseUrl": "https://bulk.example.test/",
            "operationsBaseUrl": "https://operations.example.test/",
            "tenant": "pilot",
            "paymentScheme": "mpesa"
        },
        "payer": {
            "financialAddressKey": "MSISDN",
            "payerIdKey": "ACCOUNTID"
        },
        "transactionType": {
            "scenario": "MPESA",
            "subScenario": "BUYGOODS",
            "initiator": "PAYEE",
            "initiatorType": "BUSINESS"
        }
    });
    value
}

fn http_config() -> Value {
    let mut value = mifos_config();
    value["connections"][0]["binding"]["providerPack"] = json!({
        "id": "mifos-payment-hub", "version": "1",
        "digest": format!("sha256:{}", "a".repeat(64))
    });
    value["connections"][0]["binding"]["provider"] = json!({
        "type": "http",
        "submitBaseUrl": "https://channel.example.test/",
        "statusBaseUrl": "https://operations.example.test/",
        "settings": {"tenant":"pilot", "paymentScheme":"mpesa"}
    });
    value
}

#[test]
fn mapped_http_provider_requires_a_pin_and_bounded_separate_origins() {
    let valid: PaymentsConfig = serde_json::from_value(http_config()).unwrap();
    assert!(valid.validate().is_ok());
    let mut missing_pin = http_config();
    missing_pin["connections"][0]["binding"]
        .as_object_mut()
        .unwrap()
        .remove("providerPack");
    assert!(serde_json::from_value::<PaymentsConfig>(missing_pin)
        .unwrap()
        .validate()
        .is_err());
    for pointer in [
        "/connections/0/binding/provider/submitBaseUrl",
        "/connections/0/binding/provider/statusBaseUrl",
    ] {
        let mut invalid = http_config();
        *invalid.pointer_mut(pointer).unwrap() = json!("http://example.test/path");
        assert!(serde_json::from_value::<PaymentsConfig>(invalid)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut oversized = http_config();
    oversized["connections"][0]["binding"]["provider"]["settings"]["tenant"] =
        json!("x".repeat(20_000));
    assert!(serde_json::from_value::<PaymentsConfig>(oversized)
        .unwrap()
        .validate()
        .is_err());
}
#[test]
fn connections_are_explicit_scoped_and_synthetic() {
    let valid: PaymentsConfig = serde_json::from_value(config()).unwrap();
    assert!(valid.validate().is_ok());
    for pointer in ["/connections/0/allowedClients", "/connections"] {
        let mut value = config();
        *value.pointer_mut(pointer).unwrap() = json!([]);
        assert!(serde_json::from_value::<PaymentsConfig>(value)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut live = config();
    live["connections"][0]["binding"]["simulation"] = json!(false);
    assert!(serde_json::from_value::<PaymentsConfig>(live)
        .unwrap()
        .validate()
        .is_err());
    let mut unusable = config();
    unusable["connections"][0]["id"] = json!("MixedCase");
    assert!(serde_json::from_value::<PaymentsConfig>(unusable)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn only_mifos_can_back_a_non_simulation_collection() {
    let live: PaymentsConfig = serde_json::from_value(mifos_config()).unwrap();
    assert!(live.validate().is_ok());

    let mut simulated_mifos = mifos_config();
    simulated_mifos["connections"][0]["binding"]["simulation"] = json!(true);
    assert!(serde_json::from_value::<PaymentsConfig>(simulated_mifos)
        .unwrap()
        .validate()
        .is_err());

    let mut unknown = mifos_config();
    unknown["connections"][0]["binding"]["provider"]["connection"]["extra"] = json!(true);
    assert!(serde_json::from_value::<PaymentsConfig>(unknown).is_err());

    for provider in [
        json!({"connection": {}}),
        json!({"type": "unknown", "connection": {}}),
    ] {
        let mut invalid = mifos_config();
        invalid["connections"][0]["binding"]["provider"] = provider;
        assert!(serde_json::from_value::<PaymentsConfig>(invalid).is_err());
    }
}
#[test]
fn routing_or_credential_identity_changes_the_frozen_binding() {
    let original: PaymentsConfig = serde_json::from_value(config()).unwrap();
    let digest = original.connections[0].binding.revision().unwrap();
    for pointer in [
        "/connections/0/binding/provider/connection/tenant",
        "/connections/0/binding/provider/connection/biller",
        "/connections/0/binding/providerCredentialIdentity",
        "/connections/0/binding/registry/credentialIdentity",
    ] {
        let mut changed = config();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        let parsed: PaymentsConfig = serde_json::from_value(changed).unwrap();
        assert_ne!(digest, parsed.connections[0].binding.revision().unwrap());
    }
}

#[test]
fn the_reviewed_provider_pack_is_part_of_the_frozen_binding() {
    let original: PaymentsConfig = serde_json::from_value(config()).unwrap();
    let original_revision = original.connections[0].binding.revision().unwrap();
    let mut pinned = config();
    pinned["connections"][0]["binding"]["providerPack"] = json!({
        "id": "mifos-payment-hub",
        "version": "1",
        "digest": format!("sha256:{}", "a".repeat(64))
    });
    let pinned: PaymentsConfig = serde_json::from_value(pinned).unwrap();
    assert!(pinned.validate().is_ok());
    assert_ne!(
        original_revision,
        pinned.connections[0].binding.revision().unwrap()
    );
}

fn attempt() -> registry_adapter::payments::model::Attempt {
    use registry_adapter::payments::model::{Attempt, BillSnapshot};
    use registry_payment_protocol::Money;
    let config: PaymentsConfig = serde_json::from_value(config()).unwrap();
    let binding = config.connections[0].binding.clone();
    let bill = BillSnapshot {
        bill_id: uuid::Uuid::new_v4(),
        bill_version: 1,
        bill_digest: "a".repeat(64),
        institution_id: "ministry".into(),
        service_id: "permit".into(),
        request_id: "request-1".into(),
        tariff_id: "permit-fee".into(),
        tariff_version: 1,
        tariff_digest: "b".repeat(64),
        payer_id: "payer-1".into(),
        payer_financial_address: "synthetic-payer".into(),
        money: Money {
            value: "25.00".into(),
            currency: "USD".into(),
            scale: 2,
        },
        simulation: true,
    };
    Attempt {
        id: uuid::Uuid::new_v4(),
        connection: "fees".into(),
        principal: "caller".into(),
        bill_snapshot_digest: bill.digest().unwrap(),
        binding_revision: binding.revision().unwrap(),
        provider_command: bill.provider_command(&binding).unwrap(),
        provider_command_digest: None,
        bill,
        binding,
        bind_action: None,
        bound: false,
        first_send_at: None,
        transfer_id: None,
        provider_acceptance: None,
        observation: None,
        report_action: None,
        receipt_digest: None,
        receipt: None,
    }
}

#[test]
fn provider_identity_is_stable_bounded_and_independent_of_store_or_credentials() {
    let first = attempt();
    let mut independent = first.clone();
    independent.id = uuid::Uuid::new_v4();
    independent.connection = "other-connection".into();
    independent.binding.provider_credential_ref =
        serde_json::from_value(json!("secret:env/ROTATED_TOKEN")).unwrap();
    independent.binding.replay_window_seconds = 1;
    independent.binding.simulator_mut().unwrap().base_url.pop(); // Equivalent root URL without its slash.
    assert_eq!(
        first.provider_command,
        independent
            .bill
            .provider_command(&independent.binding)
            .unwrap()
    );
    let command = first.provider_command.simulator().unwrap();
    assert_eq!(command.request_id.len(), 12);
    assert_eq!(command.bill_id.len(), 10);
    first.provider_command.validate().unwrap();
    let mut other_bill = first.bill.clone();
    other_bill.bill_id = uuid::Uuid::new_v4();
    assert_ne!(
        first.provider_command,
        other_bill.provider_command(&first.binding).unwrap()
    );
}

#[test]
fn v1_provider_identity_matches_the_retained_command_golden_vector() {
    let mut saved = attempt();
    saved.bill.bill_id = "9303e1c2-9c2c-4c1e-8ecb-06bfa02d70cf".parse().unwrap();
    let command = saved.bill.provider_command(&saved.binding).unwrap();
    let simulator = command.simulator().unwrap();
    assert_eq!(simulator.request_id, "90RVxEyflgHP");
    assert_eq!(simulator.bill_id, "emwUe0iT0w");
    assert_eq!(simulator.rtp_id, 1_364_251_476_903_812);
    saved.binding.simulator_mut().unwrap().base_url.pop();
    assert_eq!(
        saved.bill.provider_command(&saved.binding).unwrap(),
        command
    );
}

#[test]
fn sequence_based_development_snapshots_are_held_without_rewriting_the_command() {
    use registry_payment_protocol::PaymentProblemCode;
    let mut saved = attempt();
    let command = saved.provider_command.simulator_mut().unwrap();
    command.request_id = "p1".into();
    command.rtp_id = 1;
    command.bill_id = "1".into();
    let prior = serde_json::to_value(&saved).unwrap();
    assert_eq!(
        saved.validate_integrity(),
        Err(PaymentProblemCode::Unavailable)
    );
    assert_eq!(serde_json::to_value(&saved).unwrap(), prior);
}

#[test]
fn restored_http_attempt_refuses_tampered_prepared_request_bytes_or_authority() {
    use registry_adapter::payments::{
        model::{digest, BillSnapshot, CollectionProviderCommand, HttpCollectionCommand},
        provider_mapping::{PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest},
    };
    use registry_payment_protocol::Money;
    use std::collections::BTreeMap;

    let parsed: PaymentsConfig = serde_json::from_value(http_config()).unwrap();
    let binding = parsed.connections[0].binding.clone();
    let bill = BillSnapshot {
        bill_id: uuid::Uuid::new_v4(),
        bill_version: 1,
        bill_digest: "a".repeat(64),
        institution_id: "ministry".into(),
        service_id: "permit".into(),
        request_id: "request-1".into(),
        tariff_id: "permit-fee".into(),
        tariff_version: 1,
        tariff_digest: "b".repeat(64),
        payer_id: "payer-1".into(),
        payer_financial_address: "254700000001".into(),
        money: Money {
            value: "25.00".into(),
            currency: "KES".into(),
            scale: 2,
        },
        simulation: false,
    };
    let provider_command = CollectionProviderCommand::Http(HttpCollectionCommand {
        intent: bill.http_intent(&binding).unwrap(),
        prepared_submit: PreparedProviderRequest {
            provider_pack: binding.provider_pack.clone().unwrap(),
            role: PaymentEndpointRole::CollectionSubmit,
            method: PaymentHttpMethod::Post,
            path: "/channel/collection".into(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("platform-tenantid".into(), "pilot".into())]),
            body: Some(br#"{"amount":{"amount":"25.00","currency":"KES"}}"#.to_vec()),
        },
    });
    let mut saved = registry_adapter::payments::model::Attempt {
        id: uuid::Uuid::new_v4(),
        connection: "fees".into(),
        principal: "caller".into(),
        bill_snapshot_digest: bill.digest().unwrap(),
        binding_revision: binding.revision().unwrap(),
        provider_command_digest: Some(digest(&provider_command).unwrap()),
        provider_command,
        bill,
        binding,
        bind_action: None,
        bound: false,
        first_send_at: None,
        transfer_id: None,
        provider_acceptance: None,
        observation: None,
        report_action: None,
        receipt_digest: None,
        receipt: None,
    };
    assert!(saved.validate_integrity().is_ok());

    if let CollectionProviderCommand::Http(command) = &mut saved.provider_command {
        command
            .prepared_submit
            .headers
            .insert("authorization".into(), "script-selected".into());
    } else {
        unreachable!()
    }
    saved.provider_command_digest = Some(digest(&saved.provider_command).unwrap());
    assert_eq!(
        saved.validate_integrity(),
        Err(registry_payment_protocol::PaymentProblemCode::Unavailable)
    );

    if let CollectionProviderCommand::Http(command) = &mut saved.provider_command {
        command.prepared_submit.headers.remove("authorization");
        command.prepared_submit.body = Some(br#"{ "amount": "25.00" }"#.to_vec());
    } else {
        unreachable!()
    }
    saved.provider_command_digest = Some(digest(&saved.provider_command).unwrap());
    assert_eq!(
        saved.validate_integrity(),
        Err(registry_payment_protocol::PaymentProblemCode::Unavailable)
    );
}

#[test]
fn mifos_command_uses_only_the_frozen_bill_and_provider_mapping() {
    use registry_adapter::payments::model::{BillSnapshot, CollectionProviderCommand};
    use registry_payment_mifos_connector::{PartyIdentifier, TransactionType};
    use registry_payment_protocol::Money;

    let parsed: PaymentsConfig = serde_json::from_value(mifos_config()).unwrap();
    let binding = &parsed.connections[0].binding;
    let bill = BillSnapshot {
        bill_id: "9303e1c2-9c2c-4c1e-8ecb-06bfa02d70cf".parse().unwrap(),
        bill_version: 4,
        bill_digest: "a".repeat(64),
        institution_id: "ministry".into(),
        service_id: "permit".into(),
        request_id: "request-1".into(),
        tariff_id: "permit-fee".into(),
        tariff_version: 2,
        tariff_digest: "b".repeat(64),
        payer_id: "payer-account-1".into(),
        payer_financial_address: "254700000001".into(),
        money: Money {
            value: "25.00".into(),
            currency: "KES".into(),
            scale: 2,
        },
        simulation: false,
    };
    let CollectionProviderCommand::Mifos(command) = bill.provider_command(binding).unwrap() else {
        panic!("live Mifos binding must create a Mifos command");
    };
    assert_eq!(
        command.payer,
        [
            PartyIdentifier {
                key: "MSISDN".into(),
                value: "254700000001".into()
            },
            PartyIdentifier {
                key: "ACCOUNTID".into(),
                value: "payer-account-1".into()
            },
        ]
    );
    assert_eq!(command.money.amount, "25.00");
    assert_eq!(command.money.currency, "KES");
    assert_eq!(
        command.transaction_type,
        TransactionType {
            scenario: "MPESA".into(),
            sub_scenario: "BUYGOODS".into(),
            initiator: "PAYEE".into(),
            initiator_type: "BUSINESS".into(),
        }
    );
    command.validate().unwrap();

    let mut changed = bill.clone();
    changed.money.value = "25.01".into();
    assert_ne!(
        CollectionProviderCommand::Mifos(command),
        changed.provider_command(binding).unwrap()
    );
}

#[test]
fn persisted_command_cannot_be_borrowed_by_another_bill_or_provider_namespace() {
    use registry_adapter::payments::model::Attempt;
    use registry_payment_protocol::PaymentProblemCode;
    let original = attempt();
    original.validate_integrity().unwrap();
    for (pointer, replacement) in [
        ("/bill/billId", json!(uuid::Uuid::new_v4())),
        ("/bill/billVersion", json!(2)),
        ("/bill/billDigest", json!("c".repeat(64))),
        ("/bill/institutionId", json!("another-institution")),
        ("/bill/serviceId", json!("another-service")),
        ("/bill/requestId", json!("another-request")),
        ("/bill/tariffDigest", json!("d".repeat(64))),
        (
            "/binding/provider/connection/tenant",
            json!("another-tenant"),
        ),
        (
            "/binding/provider/connection/biller",
            json!("another-biller"),
        ),
        (
            "/binding/providerCredentialIdentity",
            json!("another-producer"),
        ),
    ] {
        let mut document = serde_json::to_value(&original).unwrap();
        *document.pointer_mut(pointer).unwrap() = replacement;
        let mut changed: Attempt = serde_json::from_value(document).unwrap();
        changed.bill_snapshot_digest = changed.bill.digest().unwrap();
        changed.binding_revision = changed.binding.revision().unwrap();
        assert_eq!(
            changed.validate_integrity(),
            Err(PaymentProblemCode::Unavailable),
            "{pointer}"
        );
    }
}

#[cfg(feature = "schema")]
#[test]
fn authored_connections_allow_the_strict_mifos_shape_and_require_scope() {
    let schema = serde_json::to_value(schemars::schema_for!(PaymentsConfig)).unwrap();
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(compiled.is_valid(&config()));
    assert!(compiled.is_valid(&mifos_config()));
    assert!(compiled.is_valid(&http_config()));
    let mut value = config();
    value["connections"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredScope");
    assert!(!compiled.is_valid(&value));
    let mut value = config();
    value["connections"] = json!([]);
    assert!(compiled.is_valid(&value));
    assert!(serde_json::from_value::<PaymentsConfig>(value)
        .unwrap()
        .validate()
        .is_err());
    for provider_type in [None, Some("unknown")] {
        let mut value = mifos_config();
        match provider_type {
            Some(provider_type) => {
                value["connections"][0]["binding"]["provider"]["type"] = json!(provider_type);
            }
            None => {
                value["connections"][0]["binding"]["provider"]
                    .as_object_mut()
                    .unwrap()
                    .remove("type");
            }
        }
        assert!(!compiled.is_valid(&value));
    }
}
