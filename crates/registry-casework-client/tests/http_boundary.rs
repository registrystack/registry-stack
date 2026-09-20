use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use registry_casework_client::{
    AbsencesQuery, BearerToken, CaseworkAction, CaseworkAuth, CaseworkClient, CaseworkClientConfig,
    CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure, ContentDigest,
    DecideRequest, DirectoryTargetPurpose, DirectoryTargetsQuery, HoldingsQuery,
    RecoverAttemptRequest, ReviewCancelRequest, ReviewCancelResponse, ReviewContext,
    ReviewCreateRequest, ReviewHistoryAudience, ReviewNoteRequest, ReviewTaskContextData,
    ReviewValidationReason, SourceBinding, SourceContextBinding,
};
use registry_casework_core::{
    ReviewContextStrategy, ReviewKindPolicy, ReviewKindPurpose, ReviewRetentionPolicy,
    ReviewStagePolicy, SubjectBinding,
};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
type HistoryObservations = Arc<Mutex<Vec<(String, HeaderMap)>>>;

#[tokio::test]
async fn review_create_refuses_an_accepted_binding_for_another_policy() {
    let digest = ContentDigest::for_bytes(b"submission");
    let request = ReviewCreateRequest {
        kind: "registry-correction".to_owned(),
        subject: SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "change-request".to_owned(),
            id: "proposal-7".to_owned(),
            version: "3".to_owned(),
            digest: ContentDigest::for_bytes(b"proposal-7"),
        },
        requester_reference: "proposal-7".to_owned(),
        initiator: None,
        context: ReviewContext::Source {
            binding: SourceContextBinding {
                reference: "proposal-7".to_owned(),
            },
        },
        result_constraints: None,
    };
    let response = json!({
        "requestId": Uuid::from_u128(7),
        "subject": request.subject.clone(),
        "policy": {
            "id": "another-review-kind",
            "version": "1",
            "digest": ContentDigest::for_bytes(b"another-review-kind")
        },
        "submissionDigest": digest.clone(),
    });
    let app = Router::new()
        .route("/v1/review-requests", post(review_create_fixture_response))
        .with_state(response);
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

    assert!(matches!(
        client
            .create_or_recover_review_request(
                CaseworkAuth::new(&token, "requester"),
                "submission-7",
                &request,
                &digest,
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 201,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

async fn review_create_fixture_response(State(response): State<Value>) -> impl IntoResponse {
    (
        StatusCode::CREATED,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        response.to_string(),
    )
}

#[tokio::test]
async fn review_task_context_preserves_the_frozen_source_neutral_shape() {
    let task_id = Uuid::nil();
    let app = Router::new().route(
        "/v1/review-tasks/{task}/context",
        get(task_context_response),
    );
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
    let context = client
        .review_task_context(CaseworkAuth::new(&token, "staff"), task_id)
        .await
        .expect("review task context");
    assert_eq!(context.value.task_id, task_id);
    assert_eq!(context.value.requester_reference, "requester-reference");
    assert!(matches!(
        context.value.context,
        ReviewTaskContextData::Submitted { snapshot }
            if snapshot == serde_json::json!({"summary":"Frozen review"})
    ));
    server.abort();
}

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
async fn review_note_forwards_the_selected_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/notes",
            post(capture_review_note),
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
    let response = client
        .add_review_note(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
            "note-1",
            &ReviewNoteRequest {
                audience: ReviewHistoryAudience::Reviewers,
                note: "Review note".to_owned(),
            },
        )
        .await
        .expect("source-context review note");

    assert_eq!(response.value.kind, "note");
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "a review note is never retried");
    assert_eq!(observations[0]["authorization"], "Bearer one-call-secret");
    assert_eq!(observations[0]["registry-casework-profile"], "staff");
    assert_eq!(observations[0]["registry-source-profile"], "reviewer");
    assert_eq!(observations[0]["idempotency-key"], "note-1");
    server.abort();
}

async fn capture_review_note(
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
        r#"{"eventId":"10000000-0000-4000-8000-000000000001","requestId":"00000000-0000-0000-0000-000000000000","kind":"note","detail":{"audience":"reviewers","note":"Review note"},"occurredAt":"2026-09-20T00:00:00Z"}"#,
    )
}

#[tokio::test]
async fn review_clocks_forward_the_selected_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/clocks",
            get(capture_review_clocks),
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
    let response = client
        .review_clocks(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
        )
        .await
        .expect("source-context review clocks");

    assert!(response.value.is_empty());
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "review clocks are never retried");
    assert_eq!(observations[0]["authorization"], "Bearer one-call-secret");
    assert_eq!(observations[0]["registry-casework-profile"], "staff");
    assert_eq!(observations[0]["registry-source-profile"], "reviewer");
    server.abort();
}

async fn capture_review_clocks(
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
        "[]",
    )
}

#[tokio::test]
async fn cancellation_accepts_only_a_valid_result_bound_to_the_request_and_subject() {
    let request_id = Uuid::from_u128(7);
    let subject = SubjectBinding {
        source: "registry".to_owned(),
        subject_type: "change-request".to_owned(),
        id: "proposal-7".to_owned(),
        version: "3".to_owned(),
        digest: ContentDigest::parse(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("fixture digest"),
    };
    let cancellation = ReviewCancelRequest {
        subject: subject.clone(),
        reason: "source proposal withdrawn".to_owned(),
    };

    let valid = cancel_response(request_id, "proposal-7", "cancelled", "cancelled");
    let complete = cancel_with_response(request_id, &cancellation, valid)
        .await
        .expect("valid cancellation response");
    assert!(matches!(
        complete.value,
        ReviewCancelResponse::Cancelled { .. }
    ));

    for invalid in [
        cancel_response(Uuid::from_u128(8), "proposal-7", "cancelled", "cancelled"),
        cancel_response(request_id, "other-proposal", "cancelled", "cancelled"),
        cancel_response(request_id, "proposal-7", "cancelled", "approved"),
        cancel_response(request_id, "proposal-7", "cancelled", "invalid_window"),
    ] {
        assert!(matches!(
            cancel_with_response(request_id, &cancellation, invalid).await,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }

    let already_terminal =
        cancel_response(request_id, "proposal-7", "already_terminal", "approved");
    let complete = cancel_with_response(request_id, &cancellation, already_terminal)
        .await
        .expect("a correlated valid prior terminal result");
    assert!(matches!(
        complete.value,
        ReviewCancelResponse::AlreadyTerminal { .. }
    ));
}

async fn cancel_with_response(
    request_id: Uuid,
    cancellation: &ReviewCancelRequest,
    response: Value,
) -> Result<registry_casework_client::CaseworkComplete<ReviewCancelResponse>, CaseworkClientError> {
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/cancel",
            post(cancel_fixture_response),
        )
        .with_state(response);
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
        .cancel_review_request(
            CaseworkAuth::new(&token, "requester"),
            request_id,
            "cancel-7",
            cancellation,
        )
        .await;
    server.abort();
    result
}

async fn cancel_fixture_response(State(response): State<Value>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        response.to_string(),
    )
}

fn cancel_response(request_id: Uuid, subject_id: &str, outcome: &str, status: &str) -> Value {
    let available_until = if status == "invalid_window" {
        "2026-09-19T00:00:00Z"
    } else {
        "2026-10-19T00:00:00Z"
    };
    let status = if status == "invalid_window" {
        "cancelled"
    } else {
        status
    };
    json!({"outcome": outcome, "result": {
        "resultId": Uuid::from_u128(99),
        "requestId": request_id,
        "subject": {
            "source": "registry",
            "type": "change-request",
            "id": subject_id,
            "version": "3",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "policy": {
            "id": "registry-correction",
            "version": "1",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "submissionDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "status": status,
        "completedAt": "2026-09-19T00:00:00Z",
        "availableUntil": available_until
    }})
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
async fn source_history_forwards_the_bounded_page_query_and_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<(String, HeaderMap)>::new()));
    let app = Router::new()
        .route("/v1/work-items/{item}/history", get(capture_history_query))
        .route(
            "/v1/review-requests/{request}/history",
            get(capture_history_query),
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
    let first_page = client
        .work_item_history(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
            &registry_casework_client::WorkItemHistoryQuery {
                cursor: None,
                limit: Some(1),
            },
        )
        .await
        .expect("first history page");
    let next_cursor = first_page.value.next_cursor.expect("continuation");
    let second_page = client
        .work_item_history(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
            &registry_casework_client::WorkItemHistoryQuery {
                cursor: Some(next_cursor),
                limit: Some(1),
            },
        )
        .await
        .expect("second history page");

    assert_eq!(
        second_page.value.next_cursor.as_deref(),
        Some("10000000-0000-4000-8000-000000000001")
    );
    {
        let observed = observations.lock().expect("observations");
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[0].0,
            "/v1/work-items/00000000-0000-0000-0000-000000000000/history?limit=1"
        );
        assert_eq!(observed[0].1["registry-source-profile"], "reviewer");
        assert_eq!(
            observed[1].0,
            "/v1/work-items/00000000-0000-0000-0000-000000000000/history?cursor=10000000-0000-4000-8000-000000000001&limit=1"
        );
        assert_eq!(observed[1].1["registry-source-profile"], "reviewer");
    }

    let review_page = client
        .review_history(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::nil(),
            &registry_casework_client::ReviewPageQuery {
                cursor: None,
                limit: Some(1),
            },
        )
        .await
        .expect("source-context review history");
    assert_eq!(
        review_page.value.next_cursor,
        Some(
            Uuid::parse_str("10000000-0000-4000-8000-000000000001")
                .expect("fixture review history cursor")
        )
    );
    let observed = observations.lock().expect("observations");
    assert_eq!(observed.len(), 3);
    assert_eq!(
        observed[2].0,
        "/v1/review-requests/00000000-0000-0000-0000-000000000000/history?limit=1"
    );
    assert_eq!(observed[2].1["registry-source-profile"], "reviewer");
    server.abort();
}

async fn capture_history_query(
    State(observations): State<HistoryObservations>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    observations
        .lock()
        .expect("observations")
        .push((uri.to_string(), headers));
    let body = if uri.path().starts_with("/v1/review-requests/") {
        r#"{"items":[],"nextCursor":"10000000-0000-4000-8000-000000000001"}"#
    } else {
        r#"{"items":[],"nextCursor":"10000000-0000-4000-8000-000000000001","status":"complete"}"#
    };
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        body,
    )
}

#[tokio::test]
async fn holdings_forwards_and_validates_its_bounded_page_query() {
    let observations = Arc::new(Mutex::new(Vec::<(String, HeaderMap)>::new()));
    let app = Router::new()
        .route("/v1/holdings", get(capture_history_query))
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
    client
        .holdings(
            CaseworkAuth::new(&token, "supervisor").with_source_profile("reviewer"),
            &HoldingsQuery {
                cursor: Some("opaque-holdings-cursor".into()),
                limit: Some(25),
            },
        )
        .await
        .expect("holdings page");

    assert!(matches!(
        client
            .holdings(
                CaseworkAuth::new(&token, "supervisor").with_source_profile("reviewer"),
                &HoldingsQuery {
                    cursor: None,
                    limit: Some(101),
                },
            )
            .await,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].0,
        "/v1/holdings?cursor=opaque-holdings-cursor&limit=25"
    );
    assert_eq!(observations[0].1["registry-source-profile"], "reviewer");
    server.abort();
}

#[tokio::test]
async fn next_work_item_preserves_the_page_envelope_and_rejects_multiple_items() {
    let observations = Arc::new(Mutex::new(Vec::<(String, HeaderMap)>::new()));
    let app = Router::new()
        .route("/v1/work-items/next", get(capture_next_query))
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
    let page = client
        .next_work_item(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            &registry_casework_client::NextWorkItemQuery {
                queue: Some("review".into()),
                cursor: Some("opaque-next".into()),
            },
        )
        .await
        .expect("bounded next page");
    assert!(page.value.items.is_empty());
    assert_eq!(
        page.value.status,
        registry_casework_client::PageStatus::BudgetExhausted
    );
    assert_eq!(page.value.next_cursor.as_deref(), Some("resume-next"));
    assert_eq!(page.value.served_queues, ["review"]);

    let too_many = client
        .next_work_item(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            &registry_casework_client::NextWorkItemQuery {
                queue: Some("review".into()),
                cursor: Some("too-many".into()),
            },
        )
        .await;
    assert!(matches!(
        too_many,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].0,
        "/v1/work-items/next?queue=review&cursor=opaque-next"
    );
    assert_eq!(observations[0].1["registry-source-profile"], "reviewer");
    server.abort();
}

async fn capture_next_query(
    State(observations): State<HistoryObservations>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    observations
        .lock()
        .expect("observations")
        .push((uri.to_string(), headers));
    let item = serde_json::json!({
        "itemId": "00000000-0000-4000-8000-000000000001",
        "subject": {"sourceId": "source-one", "kind": "case", "id": "case-one"},
        "occurrenceKind": "review",
        "binding": {
            "sourceRevision": "revision-1",
            "version": "version-1",
            "generation": "generation-1"
        },
        "bindingReference": "binding-one",
        "state": "open",
        "queueId": "review",
        "revision": 1,
        "firstObservedAt": "2026-09-11T03:00:00Z",
        "updatedAt": "2026-09-11T03:00:00Z",
        "actions": []
    });
    let body = if uri
        .query()
        .is_some_and(|query| query.contains("cursor=too-many"))
    {
        serde_json::json!({
            "items": [item.clone(), item],
            "status": "complete",
            "servedQueues": ["review"]
        })
    } else {
        serde_json::json!({
            "items": [],
            "nextCursor": "resume-next",
            "status": "budget_exhausted",
            "servedQueues": ["review"]
        })
    };
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        body.to_string(),
    )
}

#[tokio::test]
async fn directory_targets_forward_the_exact_context_without_a_source_profile() {
    let observations = Arc::new(Mutex::new(Vec::<(String, HeaderMap)>::new()));
    let app = Router::new()
        .route("/v1/directory/targets", get(capture_directory_targets))
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
    let page = client
        .directory_targets(
            CaseworkAuth::new(&token, "supervisor"),
            &DirectoryTargetsQuery {
                purpose: DirectoryTargetPurpose::AbsenceCover,
                queue: None,
                person_issuer: Some("https://id.example".into()),
                person_subject: Some("absent-officer".into()),
                cursor: Some("opaque-target-cursor".into()),
                limit: Some(25),
            },
        )
        .await
        .expect("directory target page");

    assert_eq!(page.value.items[0].subject, "cover-officer");
    assert_eq!(
        page.value.items[0].display_name.as_deref(),
        Some("Cover Officer")
    );
    assert_eq!(page.value.next_cursor.as_deref(), Some("target-next"));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].0,
        "/v1/directory/targets?purpose=absence_cover&personIssuer=https%3A%2F%2Fid.example&personSubject=absent-officer&cursor=opaque-target-cursor&limit=25"
    );
    assert_eq!(observations[0].1["registry-casework-profile"], "supervisor");
    assert!(!observations[0].1.contains_key("registry-source-profile"));
    server.abort();
}

async fn capture_directory_targets(
    State(observations): State<HistoryObservations>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    observations
        .lock()
        .expect("observations")
        .push((uri.to_string(), headers));
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        r#"{"items":[{"issuer":"https://id.example","subject":"cover-officer","displayName":"Cover Officer"}],"nextCursor":"target-next","status":"complete"}"#,
    )
}

#[tokio::test]
async fn absence_list_propagates_pagination_and_decodes_the_next_cursor() {
    let observations = Arc::new(Mutex::new(Vec::<(String, HeaderMap)>::new()));
    let app = Router::new()
        .route("/v1/directory/absences", get(capture_absences))
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
    let absences = client
        .absences_page(
            CaseworkAuth::new(&token, "staff"),
            &AbsencesQuery {
                cursor: Some("opaque-absence-cursor".into()),
                limit: Some(1000),
            },
        )
        .await
        .expect("absence list");

    assert_eq!(absences.value.directory_revision, 12);
    assert!(absences.value.items.is_empty());
    assert_eq!(absences.value.next_cursor.as_deref(), Some("absence-next"));
    client
        .absences(CaseworkAuth::new(&token, "staff"))
        .await
        .expect("default absence list");
    let invalid = client
        .absences_page(
            CaseworkAuth::new(&token, "staff"),
            &AbsencesQuery {
                cursor: None,
                limit: Some(1001),
            },
        )
        .await
        .expect_err("oversized absence page must be rejected");
    assert!(matches!(
        invalid,
        CaseworkClientError::InvalidRequest { .. }
    ));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].0,
        "/v1/directory/absences?cursor=opaque-absence-cursor&limit=1000"
    );
    assert_eq!(observations[1].0, "/v1/directory/absences");
    assert_eq!(observations[0].1["registry-casework-profile"], "staff");
    assert!(!observations[0].1.contains_key("registry-source-profile"));
    server.abort();
}

async fn capture_absences(
    State(observations): State<HistoryObservations>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    observations
        .lock()
        .expect("observations")
        .push((uri.to_string(), headers));
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        r#"{"directoryRevision":12,"items":[],"nextCursor":"absence-next"}"#,
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
async fn invalid_subject_selectors_fail_before_network_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let partial = registry_casework_client::ListWorkItemsQuery {
        view: registry_casework_client::InboxView::MyTeams,
        sort: registry_casework_client::InboxSort::Due,
        queue: None,
        source_id: Some("source-one".into()),
        subject_kind: None,
        subject_id: None,
        reference: None,
        cursor: None,
        limit: Some(10),
    };
    assert!(matches!(
        client
            .list_work_items(
                CaseworkAuth::new(&token, "staff").with_source_profile("reader"),
                &partial,
            )
            .await,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));

    let reference_and_subject = registry_casework_client::ListWorkItemsQuery {
        reference: Some("CASE-42".into()),
        subject_kind: Some("resident-record".into()),
        subject_id: Some("human-reference-42".into()),
        ..partial
    };
    assert!(matches!(
        client
            .list_work_items(
                CaseworkAuth::new(&token, "staff").with_source_profile("reader"),
                &reference_and_subject,
            )
            .await,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));
}

#[tokio::test]
async fn invalid_directory_target_queries_fail_before_network_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let missing_queue = DirectoryTargetsQuery {
        purpose: DirectoryTargetPurpose::Assignment,
        queue: None,
        person_issuer: None,
        person_subject: None,
        cursor: None,
        limit: Some(25),
    };
    assert!(matches!(
        client
            .directory_targets(CaseworkAuth::new(&token, "staff"), &missing_queue)
            .await,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));

    let partial_person = DirectoryTargetsQuery {
        purpose: DirectoryTargetPurpose::AbsenceCover,
        queue: None,
        person_issuer: Some("https://id.example".into()),
        person_subject: None,
        cursor: None,
        limit: Some(25),
    };
    assert!(matches!(
        client
            .directory_targets(CaseworkAuth::new(&token, "supervisor"), &partial_person)
            .await,
        Err(CaseworkClientError::InvalidRequest { .. })
    ));

    let source_selected = DirectoryTargetsQuery {
        purpose: DirectoryTargetPurpose::AbsencePerson,
        queue: None,
        person_issuer: None,
        person_subject: None,
        cursor: None,
        limit: Some(25),
    };
    assert!(matches!(
        client
            .directory_targets(
                CaseworkAuth::new(&token, "supervisor").with_source_profile("reader"),
                &source_selected,
            )
            .await,
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
async fn review_validation_headers_preserve_only_path_and_closed_reason() {
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
            && validation.reason == ReviewValidationReason::SchemaMismatch
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

async fn task_context_response() -> impl IntoResponse {
    let snapshot = ReviewKindPolicy {
        id: "standalone-answer".to_owned(),
        version: "1".to_owned(),
        purpose: ReviewKindPurpose::Approval,
        context_strategy: ReviewContextStrategy::Submitted,
        stages: vec![ReviewStagePolicy {
            id: "answer".to_owned(),
            queue: "answers".to_owned(),
            deciding_profiles: vec!["staff".to_owned()],
            required_approvals: 1,
            exclude_initiator: false,
            exclude_previous_stage_reviewers: false,
        }],
        clocks: Vec::new(),
        retention: ReviewRetentionPolicy {
            terminal_days: 30,
            accountability_days: 30,
        },
        display_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        result_schema: None,
        outcomes: Vec::new(),
    }
    .snapshot()
    .expect("fixture policy snapshot");
    let body = json!({
        "taskId": Uuid::nil(),
        "requestId": "10000000-0000-4000-8000-000000000001",
        "subject": {
            "source": "registry", "type": "record", "id": "record-1", "version": "1",
            "digest": ContentDigest::for_bytes(b"record-1")
        },
        "requesterReference": "requester-reference",
        "policy": snapshot.identity.clone(),
        "policySnapshot": snapshot,
        "context": {"strategy": "submitted", "snapshot": {"summary": "Frozen review"}}
    });
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        body.to_string(),
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
