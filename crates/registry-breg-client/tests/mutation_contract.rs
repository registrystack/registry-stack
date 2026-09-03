// SPDX-License-Identifier: Apache-2.0

use registry_breg_client::{
    BRegCreateRequest, BRegIdempotencyKey, BRegMutationRequestError, BRegPatchRequest,
    MAXIMUM_BREG_PATCH_OPERATIONS,
};
use serde_json::{json, Map, Value};

#[test]
fn idempotency_key_uses_the_exact_header_grammar_and_redacts_debug() {
    for value in ["a", "request-42_!", &"k".repeat(256)] {
        let key = BRegIdempotencyKey::parse(value).expect("valid key");
        assert_eq!(key.as_str(), value);
    }
    let canary = "secret-idempotency-canary-42";
    let key = BRegIdempotencyKey::parse(canary).unwrap();
    assert!(!format!("{key:?}").contains(canary));

    for value in [
        "",
        "has space",
        "has,comma",
        "has;semicolon",
        "has\nnewline",
        "non-ascii-é",
        &"k".repeat(257),
    ] {
        let error = BRegIdempotencyKey::parse(value).expect_err("invalid key");
        let diagnostic = format!("{error:?} {error}");
        if !value.is_empty() {
            assert!(!diagnostic.contains(value));
        }
    }
}

#[test]
fn mutation_debug_never_exposes_field_names_or_values() {
    let create = BRegCreateRequest::new(Map::from_iter([(
        "secretCanaryField".into(),
        json!("secret-canary-value"),
    )]))
    .unwrap();
    let create_debug = format!("{create:?}");
    assert!(!create_debug.contains("secretCanaryField"));
    assert!(!create_debug.contains("secret-canary-value"));

    let patch = BRegPatchRequest::builder()
        .replace("secretCanaryField", json!("secret-canary-value"))
        .unwrap()
        .build()
        .unwrap();
    let patch_debug = format!("{patch:?}");
    assert!(!patch_debug.contains("secretCanaryField"));
    assert!(!patch_debug.contains("secret-canary-value"));
}

#[test]
fn patch_builder_refuses_raw_paths_test_only_and_excessive_documents() {
    for invalid in [
        "",
        "LegalName",
        "legal_name",
        "legal-name",
        "/data/legalName",
        "legalName/other",
        "legalName~other",
        &"a".repeat(65),
    ] {
        let error = BRegPatchRequest::builder()
            .replace(invalid, Value::Null)
            .expect_err("invalid API field name");
        assert_eq!(error, BRegMutationRequestError::InvalidFieldName);
        if !invalid.is_empty() {
            assert!(!format!("{error:?} {error}").contains(invalid));
        }
    }

    assert_eq!(
        BRegPatchRequest::builder()
            .test("status", json!("draft"))
            .unwrap()
            .build()
            .unwrap_err(),
        BRegMutationRequestError::PatchRequiresMutation
    );

    let mut builder = BRegPatchRequest::builder();
    for _ in 0..MAXIMUM_BREG_PATCH_OPERATIONS {
        builder = builder.test("status", Value::Null).unwrap();
    }
    assert_eq!(
        builder.add("status", json!("active")).unwrap_err(),
        BRegMutationRequestError::TooManyPatchOperations
    );
}

#[test]
fn mutation_values_reject_inexact_integers_at_every_depth() {
    let inexact = Value::Number(serde_json::Number::from(9_007_199_254_740_993_u64));
    let exact = Value::Number(serde_json::Number::from(9_007_199_254_740_994_u64));

    let create_error = BRegCreateRequest::new(Map::from_iter([(
        "payload".into(),
        json!({"nested": [inexact.clone()]}),
    )]))
    .unwrap_err();
    assert_eq!(create_error, BRegMutationRequestError::InvalidJsonValue);

    let patch_error = BRegPatchRequest::builder()
        .replace("payload", json!({"nested": [inexact]}))
        .unwrap_err();
    assert_eq!(patch_error, BRegMutationRequestError::InvalidJsonValue);

    BRegCreateRequest::new(Map::from_iter([("payload".into(), exact)]))
        .expect("an exactly representable integer remains valid");
}

#[test]
fn create_body_enforces_field_and_encoded_body_bounds() {
    assert_eq!(
        BRegCreateRequest::new(Map::from_iter([("bad-field".into(), Value::Null)])).unwrap_err(),
        BRegMutationRequestError::InvalidFieldName
    );

    let oversized = "x".repeat(2 * 1024 * 1024);
    assert_eq!(
        BRegCreateRequest::new(Map::from_iter([("payload".into(), json!(oversized))])).unwrap_err(),
        BRegMutationRequestError::BodyTooLarge
    );
}
