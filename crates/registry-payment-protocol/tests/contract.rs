// SPDX-License-Identifier: Apache-2.0
use registry_payment_protocol::{
    CollectionState, CollectionStatus, DisbursementState, DisbursementStatus, Money,
    ProviderConfirmation, RequestCollection, RequestDisbursement,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn collection_intent_names_only_the_authoritative_bill() {
    let bill = Uuid::new_v4();
    let intent: RequestCollection = serde_json::from_value(json!({
        "billId": bill, "billVersion": 1
    }))
    .unwrap();
    assert!(intent.validate().is_ok());
    for extra in [
        "amount",
        "paid",
        "providerUrl",
        "tenant",
        "biller",
        "receiptAction",
    ] {
        let mut value = serde_json::to_value(&intent).unwrap();
        value[extra] = json!("caller-owned");
        assert!(
            serde_json::from_value::<RequestCollection>(value).is_err(),
            "{extra}"
        );
    }
    assert!(RequestCollection {
        bill_id: bill,
        bill_version: 0
    }
    .validate()
    .is_err());
}

#[test]
fn disbursement_intent_names_only_the_authoritative_instruction() {
    let instruction = Uuid::new_v4();
    let intent: RequestDisbursement = serde_json::from_value(json!({
        "instructionRecordId": instruction, "instructionVersion": 1
    }))
    .unwrap();
    assert!(intent.validate().is_ok());
    for extra in [
        "amount",
        "recipient",
        "fundingAccount",
        "providerUrl",
        "approved",
    ] {
        let mut value = serde_json::to_value(&intent).unwrap();
        value[extra] = json!("caller-owned");
        assert!(
            serde_json::from_value::<RequestDisbursement>(value).is_err(),
            "{extra}"
        );
    }
    assert!(RequestDisbursement {
        instruction_record_id: instruction,
        instruction_version: 0,
    }
    .validate()
    .is_err());
}

#[test]
fn only_provider_confirmed_disbursements_carry_provider_evidence() {
    let mut status = DisbursementStatus {
        disbursement_id: Uuid::new_v4(),
        instruction_record_id: Uuid::new_v4(),
        instruction_id: Uuid::new_v4(),
        instruction_version: 1,
        binding_revision: "mifos-legacy-v1".into(),
        simulation: true,
        state: DisbursementState::Pending,
        money: Money {
            value: "25.00".into(),
            currency: "USD".into(),
            scale: 2,
        },
        provider_reference: None,
        failure_reason: None,
    };
    assert!(status.validate().is_ok());
    status.provider_reference = Some("batch-1:transaction-1".into());
    assert!(status.validate().is_err());
    status.state = DisbursementState::ProviderConfirmed;
    assert!(status.validate().is_ok());
    status.state = DisbursementState::Failed;
    assert!(status.validate().is_err());
    status.provider_reference = None;
    status.failure_reason = Some("provider-refused".into());
    assert!(status.validate().is_ok());
}

#[test]
fn reported_disbursement_completion_requires_exact_evidence_digest() {
    let mut confirmation = ProviderConfirmation {
        disbursement_id: Uuid::new_v4(),
        instruction_record_id: Uuid::new_v4(),
        instruction_id: Uuid::new_v4(),
        instruction_version: 1,
        binding_revision: "sha256:binding".into(),
        simulation: true,
        money: Money {
            value: "25.00".into(),
            currency: "USD".into(),
            scale: 2,
        },
        provider_reference: "batch-1:transaction-1".into(),
        provider_result_digest: "a".repeat(64),
    };
    assert!(confirmation.validate().is_ok());
    confirmation.provider_result_digest = "a".repeat(63);
    assert!(confirmation.validate().is_err());
}

#[test]
fn money_is_exact_positive_bounded_decimal_text() {
    for (value, scale, expected) in [
        ("0.10", 2, 10),
        ("1000000.01", 2, 100_000_001),
        ("25.5", 2, 2550),
        ("250", 0, 250),
    ] {
        let money = Money {
            value: value.to_owned(),
            currency: "USD".into(),
            scale,
        };
        assert_eq!(money.minor_units().unwrap(), expected);
        assert!(serde_json::to_value(&money).unwrap()["value"].is_string());
    }
    for value in [
        "0",
        "-1",
        "+1",
        "1e2",
        "NaN",
        "0.001",
        "01.00",
        "1.",
        ".1",
        "90071992547409.92",
    ] {
        assert!(
            Money {
                value: value.into(),
                currency: "USD".into(),
                scale: 2
            }
            .minor_units()
            .is_err(),
            "{value}"
        );
    }
    assert!(
        serde_json::from_value::<Money>(json!({"value": 25.5, "currency": "USD", "scale": 2}))
            .is_err()
    );
}

#[test]
fn only_confirmed_collections_carry_payment_evidence() {
    let mut status = CollectionStatus {
        collection_id: Uuid::new_v4(),
        bill_id: Uuid::new_v4(),
        bill_version: 1,
        binding_revision: "synthetic-v1".into(),
        simulation: true,
        state: CollectionState::Pending,
        money: Money {
            value: "25.00".into(),
            currency: "USD".into(),
            scale: 2,
        },
        provider_reference: None,
        failure_reason: None,
    };
    assert!(status.validate().is_ok());
    status.provider_reference = Some("SIM-confirmed-1".into());
    assert!(status.validate().is_err());
    status.state = CollectionState::Confirmed;
    assert!(status.validate().is_ok());
    status.provider_reference = Some("".into());
    assert!(status.validate().is_err());
    status.state = CollectionState::Failed;
    status.provider_reference = None;
    assert!(status.validate().is_err());
    status.failure_reason = Some("payer-rejected".into());
    assert!(status.validate().is_ok());
}

#[cfg(feature = "schema")]
#[test]
fn authored_bill_references_obey_the_runtime_identity_bounds() {
    let schema = serde_json::to_value(schemars::schema_for!(RequestCollection)).unwrap();
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let id = Uuid::new_v4();
    assert!(compiled.is_valid(&json!({"billId":id,"billVersion":1})));
    assert!(!compiled.is_valid(&json!({"billId":id,"billVersion":0})));
    assert!(!compiled.is_valid(&json!({"billId":id,"billVersion":9_007_199_254_740_992_u64})));
    assert!(!compiled.is_valid(&json!({"billId":Uuid::nil(),"billVersion":1})));
}

#[cfg(feature = "schema")]
#[test]
fn authored_money_refuses_zero_and_unsupported_fractional_precision() {
    let schema = serde_json::to_value(schemars::schema_for!(Money)).unwrap();
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(compiled.is_valid(&json!({"value":"0.10","currency":"USD","scale":2})));
    for value in ["0", "0.0", "0.00", "0.000000", "0.0000001"] {
        assert!(
            !compiled.is_valid(&json!({"value":value,"currency":"USD","scale":6})),
            "{value}"
        );
    }
}
