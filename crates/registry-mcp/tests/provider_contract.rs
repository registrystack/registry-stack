// SPDX-License-Identifier: Apache-2.0
use registry_mcp::casework::{
    classify_casework_error, parse_context_arguments, parse_list_arguments, CaseworkFailureClass,
    CaseworkOptions,
};
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
    assert!(
        CaseworkOptions::new(base.clone(), "reviewer".into(), Some("source".into()), 0).is_err()
    );
    assert!(
        CaseworkOptions::new(base.clone(), "reviewer".into(), Some("source".into()), 101).is_err()
    );
    assert!(
        CaseworkOptions::new(base.clone(), "reviewer".into(), Some("source".into()), 20).is_ok()
    );
    assert!(CaseworkOptions::new(base, "reviewer".into(), None, 20).is_ok());
}

#[test]
fn casework_failures_have_static_actionable_classes_and_preserve_safe_trace() {
    use registry_casework_client::{
        CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure,
    };
    use registry_platform_httputil::client::TransportKind;

    let trace = "0123456789abcdef0123456789abcdef";
    let problems = [
        (
            404,
            CaseworkProblemCode::RequestNotFound,
            CaseworkFailureClass::Concealed,
        ),
        (
            410,
            CaseworkProblemCode::CursorExpired,
            CaseworkFailureClass::CursorExpired,
        ),
        (
            400,
            CaseworkProblemCode::RequestInvalid,
            CaseworkFailureClass::InvalidRequest,
        ),
        (
            401,
            CaseworkProblemCode::AuthenticationRefused,
            CaseworkFailureClass::AccessRefused,
        ),
        (
            403,
            CaseworkProblemCode::OperationNotAuthorized,
            CaseworkFailureClass::AccessRefused,
        ),
        (
            400,
            CaseworkProblemCode::SourceProfileRequired,
            CaseworkFailureClass::SourceProfileRequired,
        ),
        (
            409,
            CaseworkProblemCode::ReviewPolicyMismatch,
            CaseworkFailureClass::ContextChanged,
        ),
        (
            410,
            CaseworkProblemCode::ReviewResultExpired,
            CaseworkFailureClass::ContextChanged,
        ),
        (
            502,
            CaseworkProblemCode::SourceVersionMismatch,
            CaseworkFailureClass::ContextChanged,
        ),
        (
            503,
            CaseworkProblemCode::ServiceUnavailable,
            CaseworkFailureClass::Unavailable,
        ),
        (
            502,
            CaseworkProblemCode::SourceBadGateway,
            CaseworkFailureClass::Protocol,
        ),
        (
            418,
            CaseworkProblemCode::Unknown("remote-private-canary".into()),
            CaseworkFailureClass::Protocol,
        ),
    ];
    for (status, code, expected) in problems {
        let error = CaseworkClientError::Problem {
            status,
            code,
            detail: Some("remote-detail-canary".into()),
            trace_id: Some(trace.into()),
            validation: None,
        };
        let classified = classify_casework_error(&error);
        assert_eq!(classified.class(), expected);
        assert_eq!(classified.status(), Some(status));
        assert_eq!(classified.trace_id(), Some(trace));
    }

    let local = classify_casework_error(&CaseworkClientError::InvalidRequest {
        reason: "synthetic invalid request",
    });
    assert_eq!(local.class(), CaseworkFailureClass::InvalidRequest);
    assert_eq!(local.status(), None);
    assert_eq!(local.trace_id(), None);

    let transport = classify_casework_error(&CaseworkClientError::Transport {
        kind: TransportKind::Timeout,
    });
    assert_eq!(transport.class(), CaseworkFailureClass::Unavailable);

    let oversized = classify_casework_error(&CaseworkClientError::Transport {
        kind: TransportKind::ResponseTooLarge,
    });
    assert_eq!(oversized.class(), CaseworkFailureClass::Protocol);

    let protocol_error = CaseworkClientError::Protocol {
        status: 502,
        failure: CaseworkProtocolFailure::Problem,
        trace_id: Some(trace.into()),
    };
    let protocol = classify_casework_error(&protocol_error);
    assert_eq!(protocol.class(), CaseworkFailureClass::Protocol);
    assert_eq!(protocol.status(), Some(502));
    assert_eq!(protocol.trace_id(), Some(trace));
}

#[test]
fn staff_policy_and_source_ids_use_the_shared_local_identifier_contract() {
    let base = url::Url::parse("https://casework.example.invalid/").unwrap();
    assert!(CaseworkOptions::new(
        base.clone(),
        "assistant_reader".into(),
        Some("source_reader".into()),
        20
    )
    .is_ok());
    let oversized = "a".repeat(65);
    for id in ["-", "0reader", "Upper", "bad space", oversized.as_str()] {
        assert!(
            CaseworkOptions::new(base.clone(), id.into(), Some("source".into()), 20).is_err(),
            "accepted reader policy {id}"
        );
        assert!(
            CaseworkOptions::new(base.clone(), "reader".into(), Some(id.into()), 20).is_err(),
            "accepted source profile {id}"
        );
    }
}
