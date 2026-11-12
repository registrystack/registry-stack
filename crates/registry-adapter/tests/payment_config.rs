// SPDX-License-Identifier: Apache-2.0
use registry_adapter::payments::config::PaymentsConfig;
use serde_json::{json, Value};

fn config() -> Value {
    json!({ "connections": [{ "id":"fees", "institutionId":"ministry", "serviceId":"permit",
      "allowedClients":["payment-coordinator"], "requiredScope":"payments:collections",
      "binding": { "simulation":true, "currency":"USD", "currencyScale":2, "providerCredentialRef":"secret:env/SIMULATOR_TOKEN",
        "providerCredentialIdentity":"synthetic-producer", "replayWindowSeconds":3600,
        "provider": { "baseUrl":"http://127.0.0.1:8099/", "tenant":"pilot", "biller":"ministry",
          "billerName":"Ministry", "callbackUrl":"https://programme.example.test/callback", "payerFiBic":"SIMBANK" },
        "registry": { "baseUrl":"http://127.0.0.1:8080/", "readProfile":"payment-adapter-reporter", "bindProfile":"payment-adapter-binder", "receiptProfile":"payment-adapter-reporter", "recordType":"service-fee-bill", "recordRoute":"service-fee-bills",
          "bindAction":"bind-payment-attempt", "receiptAction":"record-payment-receipt",
          "credentialRef":"secret:env/PAYMENT_REPORTER_TOKEN", "credentialIdentity":"payment-adapter" }
      }
    }] })
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
fn routing_or_credential_identity_changes_the_frozen_binding() {
    let original: PaymentsConfig = serde_json::from_value(config()).unwrap();
    let digest = original.connections[0].binding.revision().unwrap();
    for pointer in [
        "/connections/0/binding/provider/tenant",
        "/connections/0/binding/provider/biller",
        "/connections/0/binding/providerCredentialIdentity",
        "/connections/0/binding/registry/credentialIdentity",
    ] {
        let mut changed = config();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        let parsed: PaymentsConfig = serde_json::from_value(changed).unwrap();
        assert_ne!(digest, parsed.connections[0].binding.revision().unwrap());
    }
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
        bill,
        binding,
        bind_action: None,
        bound: false,
        first_send_at: None,
        transfer_id: None,
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
    independent.binding.provider.base_url.pop(); // Equivalent root URL without its slash.
    assert_eq!(
        first.provider_command,
        independent
            .bill
            .provider_command(&independent.binding)
            .unwrap()
    );
    assert_eq!(first.provider_command.request_id.len(), 12);
    assert_eq!(first.provider_command.bill_id.len(), 10);
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
    assert_eq!(command.request_id, "90RVxEyflgHP");
    assert_eq!(command.bill_id, "emwUe0iT0w");
    assert_eq!(command.rtp_id, 1_364_251_476_903_812);
    saved.binding.provider.base_url.pop();
    assert_eq!(
        saved.bill.provider_command(&saved.binding).unwrap(),
        command
    );
}

#[test]
fn sequence_based_development_snapshots_are_held_without_rewriting_the_command() {
    use registry_payment_protocol::PaymentProblemCode;
    let mut saved = attempt();
    saved.provider_command.request_id = "p1".into();
    saved.provider_command.rtp_id = 1;
    saved.provider_command.bill_id = "1".into();
    let prior = serde_json::to_value(&saved).unwrap();
    assert_eq!(
        saved.validate_integrity(),
        Err(PaymentProblemCode::Unavailable)
    );
    assert_eq!(serde_json::to_value(&saved).unwrap(), prior);
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
        ("/binding/provider/tenant", json!("another-tenant")),
        ("/binding/provider/biller", json!("another-biller")),
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
fn authored_connections_cannot_enable_live_mode_or_omit_scope() {
    let schema = serde_json::to_value(schemars::schema_for!(PaymentsConfig)).unwrap();
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(compiled.is_valid(&config()));
    let mut value = config();
    value["connections"][0]["binding"]["simulation"] = json!(false);
    assert!(!compiled.is_valid(&value));
    let mut value = config();
    value["connections"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredScope");
    assert!(!compiled.is_valid(&value));
    let mut value = config();
    value["connections"] = json!([]);
    assert!(!compiled.is_valid(&value));
}
