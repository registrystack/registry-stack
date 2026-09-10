use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use registry_casework_client::{
    BearerToken, CaseworkAction, CaseworkAuth, CaseworkClient, CaseworkClientConfig,
    CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure, DecideRequest,
    HostedDecisionRequest, HostedValidationReason, RecoverAttemptRequest, SourceBinding,
};
use url::Url;
use uuid::Uuid;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

#[tokio::test]
async fn mutation_forwards_one_call_token_profile_revision_and_key_once() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route("/v1/work-items/{item}/claim", post(capture_headers))
        .with_state(observations.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let action = CaseworkAction {
        operation: "claim".into(),
        href: format!("/v1/work-items/{}/claim", Uuid::nil()),
        if_match: "\"7\"".into(),
    };
    let result = client
        .claim_work_item(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            &action,
            "attempt-7",
        )
        .await;

    assert!(matches!(
        result,
        Err(CaseworkClientError::Protocol {
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "a mutation is never retried");
    let headers = &observations[0];
    assert_eq!(headers["authorization"], "Bearer one-call-secret");
    assert_eq!(headers["registry-casework-profile"], "staff");
    assert_eq!(headers["registry-source-profile"], "reviewer");
    assert_eq!(headers["if-match"], "\"7\"");
    assert_eq!(headers["idempotency-key"], "attempt-7");
    server.abort();
}

#[tokio::test]
async fn recovery_by_key_uses_bound_profiles_and_never_invents_a_revision() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route(
            "/v1/work-items/{item}/attempts/recover",
            post(capture_headers),
        )
        .with_state(observations.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client
        .recover_decision_by_key(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
            "attempt-7",
            &RecoverAttemptRequest {
                source_profile_id: "reviewer".into(),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(CaseworkClientError::Protocol {
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "recovery is never retried");
    let headers = &observations[0];
    assert_eq!(headers["authorization"], "Bearer one-call-secret");
    assert_eq!(headers["registry-casework-profile"], "staff");
    assert_eq!(headers["registry-source-profile"], "reviewer");
    assert_eq!(headers["idempotency-key"], "attempt-7");
    assert!(!headers.contains_key("if-match"));
    server.abort();
}

#[tokio::test]
async fn decision_forwards_the_selected_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route("/v1/work-items/{item}/decisions", post(capture_headers))
        .with_state(observations.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let action = CaseworkAction {
        operation: "approve".into(),
        href: format!("/v1/work-items/{}/decisions", Uuid::nil()),
        if_match: "\"9\"".into(),
    };
    let binding = SourceBinding {
        source_revision: "revision-9".into(),
        version: "version-9".into(),
        integrity: None,
        generation: "generation-9".into(),
    };
    let result = client
        .decide_work_item(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            &action,
            "attempt-9",
            &DecideRequest {
                displayed_binding: binding,
                source_profile_id: "reviewer".into(),
                operation: registry_casework_client::OperationName::parse("approve")
                    .expect("approve operation"),
                reason: None,
                flagged_fields: Vec::new(),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(CaseworkClientError::Protocol {
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "a decision is never retried");
    let headers = &observations[0];
    assert_eq!(headers["registry-source-profile"], "reviewer");
    assert_eq!(headers["if-match"], "\"9\"");
    assert_eq!(headers["idempotency-key"], "attempt-9");
    server.abort();
}

#[tokio::test]
async fn hosted_decision_uses_the_offered_outcome_without_a_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route(
            "/v1/work-items/{item}/hosted-decisions",
            post(capture_headers),
        )
        .with_state(observations.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let action = CaseworkAction {
        operation: "confirmed".into(),
        href: format!("/v1/work-items/{}/hosted-decisions", Uuid::nil()),
        if_match: "\"3\"".into(),
    };
    let result = client
        .decide_hosted_work_item(
            CaseworkAuth::new(&token, "staff"),
            &action,
            "hosted-attempt-3",
            &HostedDecisionRequest {
                outcome: "confirmed".into(),
                reason: None,
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(CaseworkClientError::Protocol {
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    let headers = &observations[0];
    assert_eq!(headers["registry-casework-profile"], "staff");
    assert_eq!(headers["if-match"], "\"3\"");
    assert_eq!(headers["idempotency-key"], "hosted-attempt-3");
    assert!(!headers.contains_key("registry-source-profile"));
    server.abort();
}

async fn capture_headers(
    State(observations): State<Arc<Mutex<Vec<HeaderMap>>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observations.lock().expect("observations").push(headers);
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        "{}",
    )
}

#[tokio::test]
async fn invalid_mutation_input_fails_before_network_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let action = CaseworkAction {
        operation: "claim".into(),
        href: format!("/v1/work-items/{}/claim", Uuid::nil()),
        if_match: "\"1\"".into(),
    };
    let result = client
        .claim_work_item(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            &action,
            "",
        )
        .await;
    assert!(matches!(
        result,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
}

#[tokio::test]
async fn hosted_client_refuses_a_source_profile_before_network_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client
        .list_hosted_work_items(
            CaseworkAuth::new(&token, "staff").with_source_profile("reader"),
            &registry_casework_client::ListWorkItemsQuery {
                view: registry_casework_client::InboxView::MyTeams,
                queue: None,
                cursor: None,
                limit: Some(10),
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
    let requester_notes = client
        .requester_hosted_notes(
            CaseworkAuth::new(&token, "requester").with_source_profile("reader"),
            Uuid::nil(),
            &registry_casework_client::HostedPageQuery::default(),
        )
        .await;
    assert!(matches!(
        requester_notes,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
    let staff_history = client
        .hosted_work_item_history(
            CaseworkAuth::new(&token, "staff").with_source_profile("reader"),
            Uuid::nil(),
            &registry_casework_client::HostedPageQuery::default(),
        )
        .await;
    assert!(matches!(
        staff_history,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
    let accountability = client
        .hosted_accountability_record(
            CaseworkAuth::new(&token, "supervisor").with_source_profile("reader"),
            Uuid::nil(),
        )
        .await;
    assert!(matches!(
        accountability,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
}

#[tokio::test]
async fn exact_problem_document_maps_to_the_typed_runtime_code() {
    let app = Router::new().route("/v1/casework", get(problem_response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client.description(CaseworkAuth::new(&token, "staff")).await;
    assert_eq!(
        result.as_ref().expect_err("problem response").to_string(),
        "Registry Casework refused the request (HTTP 401, problem authentication.refused)"
    );
    assert!(matches!(
        result,
        Err(CaseworkClientError::Problem {
            status: 401,
            code: CaseworkProblemCode::AuthenticationRefused,
            ref detail,
            ..
        }) if detail.as_deref() == Some("The bearer credential is missing, invalid, or expired. Sign in again.")
    ));
    server.abort();
}

#[tokio::test]
async fn hosted_validation_headers_preserve_only_path_and_closed_reason() {
    let app = Router::new().route("/v1/casework", get(validation_problem_response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client
        .description(CaseworkAuth::new(&token, "requester"))
        .await;
    assert!(matches!(
        result,
        Err(CaseworkClientError::Problem {
            code: CaseworkProblemCode::RequestInvalid,
            validation: Some(ref validation),
            ..
        }) if validation.path == "$.display/summary"
            && validation.reason == HostedValidationReason::SchemaMismatch
    ));
    server.abort();
}

#[tokio::test]
async fn recovery_pending_problem_preserves_the_original_attempt_reference() {
    let app = Router::new().route("/v1/casework", get(recovery_pending_response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client.description(CaseworkAuth::new(&token, "staff")).await;
    assert!(matches!(
        result,
        Err(CaseworkClientError::Problem {
            status: 409,
            code: CaseworkProblemCode::WorkItemRecoveryPending,
            original_attempt_id: Some(attempt_id),
            ..
        }) if attempt_id == Uuid::parse_str("10000000-0000-4000-8000-000000000001").expect("attempt UUID")
    ));
    server.abort();
}

#[tokio::test]
async fn unknown_future_problem_code_remains_a_safe_typed_problem() {
    let app = Router::new().route("/v1/casework", get(unknown_problem_response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });

    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client.description(CaseworkAuth::new(&token, "staff")).await;
    assert_eq!(
        result.as_ref().expect_err("problem response").to_string(),
        "Registry Casework refused the request (HTTP 409, problem unknown)"
    );
    assert!(matches!(
        result,
        Err(CaseworkClientError::Problem {
            status: 409,
            code: CaseworkProblemCode::Unknown(code),
            detail: None,
            original_attempt_id: None,
            ..
        }) if code == "work-item.future-safe"
    ));
    server.abort();
}

#[tokio::test]
async fn recovery_attempt_header_must_be_single_and_canonical() {
    assert_problem_protocol(Router::new().route(
        "/v1/casework",
        get(recovery_pending_malformed_header_response),
    ))
    .await;
    assert_problem_protocol(Router::new().route(
        "/v1/casework",
        get(recovery_pending_multiple_header_response),
    ))
    .await;
}

async fn assert_problem_protocol(app: Router) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let result = client.description(CaseworkAuth::new(&token, "staff")).await;
    assert!(matches!(
        result,
        Err(CaseworkClientError::Protocol {
            status: 409,
            failure: CaseworkProtocolFailure::Problem,
            ..
        })
    ));
    server.abort();
}

async fn problem_response() -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
        ],
        concat!(
            "{\"type\":\"https://id.registrystack.org/problems/registry-casework/",
            "authentication/refused\",\"title\":\"Authentication refused\",",
            "\"status\":401,\"detail\":\"The bearer credential is missing, invalid, or expired. Sign in again.\",",
            "\"code\":\"authentication.refused\",",
            "\"traceId\":\"0123456789abcdef0123456789abcdef\"}"
        ),
    )
}

async fn validation_problem_response() -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
            ("registry-casework-validation-path", "$.display/summary"),
            ("registry-casework-validation-reason", "schema_mismatch"),
        ],
        concat!(
            "{\"type\":\"https://id.registrystack.org/problems/registry-casework/",
            "request/invalid\",\"title\":\"Invalid request\",",
            "\"status\":400,\"detail\":\"The Casework request is invalid.\",",
            "\"code\":\"request.invalid\",",
            "\"traceId\":\"0123456789abcdef0123456789abcdef\"}"
        ),
    )
}

fn problem_json(code: &str, status: u16) -> String {
    let path = code.replace('.', "/");
    let (title, detail) = match code {
        "work-item.recovery-pending" => (
            "Work item recovery pending",
            "We could not confirm the result of your last action. Recover the original attempt; do not decide again.",
        ),
        _ => (code, "Safe detail."),
    };
    format!(
        "{{\"type\":\"https://id.registrystack.org/problems/registry-casework/{path}\",\"title\":\"{title}\",\"status\":{status},\"detail\":\"{detail}\",\"code\":\"{code}\",\"traceId\":\"0123456789abcdef0123456789abcdef\"}}"
    )
}

async fn recovery_pending_response() -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
            (
                "registry-casework-attempt",
                "10000000-0000-4000-8000-000000000001",
            ),
        ],
        problem_json("work-item.recovery-pending", 409),
    )
}

async fn unknown_problem_response() -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
        ],
        problem_json("work-item.future-safe", 409),
    )
}

async fn recovery_pending_malformed_header_response() -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
            ("registry-casework-attempt", "not-a-canonical-uuid"),
        ],
        problem_json("work-item.recovery-pending", 409),
    )
}

async fn recovery_pending_multiple_header_response() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/problem+json".parse().expect("header"),
    );
    headers.insert("traceparent", TRACEPARENT.parse().expect("header"));
    headers.append(
        "registry-casework-attempt",
        "10000000-0000-4000-8000-000000000001"
            .parse()
            .expect("header"),
    );
    headers.append(
        "registry-casework-attempt",
        "20000000-0000-4000-8000-000000000002"
            .parse()
            .expect("header"),
    );
    (
        StatusCode::CONFLICT,
        headers,
        problem_json("work-item.recovery-pending", 409),
    )
}
