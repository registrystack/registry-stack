// SPDX-License-Identifier: Apache-2.0
use registry_mcp::casework::{parse_context_arguments, parse_list_arguments, CaseworkOptions};
use serde_json::json;

#[test]
fn staff_queries_cannot_select_another_principal_profile_or_ownership() {
    for arguments in [
        json!({"subject":"another-person"}),
        json!({"ownership":"unclaimed"}),
        json!({"profile":"supervisor"}),
        json!({"limit":101}),
        json!({"cursor":"https://elsewhere.invalid/"}),
    ] {
        assert!(parse_list_arguments(Some(arguments.as_object().unwrap())).is_err());
    }
    assert!(parse_list_arguments(None).is_ok());
    assert!(parse_list_arguments(Some(
        json!({"cursor":"49b8fe54-5991-4d4c-9759-90c7cda066fe"})
            .as_object()
            .unwrap()
    ))
    .is_ok());
}

#[test]
fn staff_context_requires_one_exact_task_identifier() {
    assert!(parse_context_arguments(None).is_err());
    assert!(parse_context_arguments(Some(
        json!({"taskId":"49b8fe54-5991-4d4c-9759-90c7cda066fe","sourceProfile":"admin"})
            .as_object()
            .unwrap()
    ))
    .is_err());
    assert!(parse_context_arguments(Some(
        json!({"taskId":"49b8fe54-5991-4d4c-9759-90c7cda066fe"})
            .as_object()
            .unwrap()
    ))
    .is_ok());
}

#[test]
fn staff_read_bounds_are_checked_before_credentials_or_io() {
    let base = url::Url::parse("https://casework.example.invalid/prefix/").unwrap();
    assert!(CaseworkOptions::new(base.clone(), "reviewer".into(), "source".into(), 0).is_err());
    assert!(CaseworkOptions::new(base.clone(), "reviewer".into(), "source".into(), 101).is_err());
    assert!(CaseworkOptions::new(base, "reviewer".into(), "source".into(), 20).is_ok());
}

#[test]
fn context_profile_retry_is_limited_to_the_exact_product_problem() {
    use registry_casework_client::{CaseworkClientError, CaseworkProblemCode};
    for (code, expected) in [
        (CaseworkProblemCode::SourceProfileRequired, true),
        (CaseworkProblemCode::SourceProfileNotApplicable, false),
        (CaseworkProblemCode::AuthenticationRefused, false),
        (CaseworkProblemCode::OperationNotAuthorized, false),
        (CaseworkProblemCode::ServiceUnavailable, false),
    ] {
        let error = CaseworkClientError::Problem {
            status: 403,
            code,
            detail: None,
            trace_id: None,
            validation: None,
        };
        assert_eq!(
            registry_mcp::casework::requires_source_profile(&error),
            expected
        );
    }
}

#[test]
fn staff_policy_and_source_ids_use_the_shared_local_identifier_contract() {
    let base = url::Url::parse("https://casework.example.invalid/").unwrap();
    assert!(CaseworkOptions::new(
        base.clone(),
        "assistant_reader".into(),
        "source_reader".into(),
        20
    )
    .is_ok());
    let oversized = "a".repeat(65);
    for id in ["-", "0reader", "Upper", "bad space", oversized.as_str()] {
        assert!(
            CaseworkOptions::new(base.clone(), id.into(), "source".into(), 20).is_err(),
            "accepted reader policy {id}"
        );
        assert!(
            CaseworkOptions::new(base.clone(), "reader".into(), id.into(), 20).is_err(),
            "accepted source profile {id}"
        );
    }
}
