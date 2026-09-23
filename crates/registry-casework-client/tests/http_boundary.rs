use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::Router;
use registry_casework_client::{
    AbsencesQuery, AssignmentRequest, BearerToken, CaseworkAction, CaseworkAuth, CaseworkClient,
    CaseworkClientConfig, CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure,
    ContentDigest, DecideRequest, DelegateRequest, DirectoryTargetPurpose, DirectoryTargetsQuery,
    HoldingsQuery, IssuerPrincipal, RecoverAttemptRequest, ReviewCancelRequest,
    ReviewCancelResponse, ReviewContext, ReviewCreateRequest, ReviewHistoryAudience,
    ReviewNoteRequest, ReviewRequestAccepted, ReviewTaskContextData, ReviewTaskDraftInput,
    ReviewValidationReason, SourceBinding, SourceContextBinding,
};
use registry_casework_core::{
    ReviewContextStrategy, ReviewKindPolicy, ReviewKindPurpose, ReviewRetentionPolicy,
    ReviewStagePolicy, SubjectBinding, TaskApprovalRequest,
};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
type HistoryObservations = Arc<Mutex<Vec<(String, HeaderMap)>>>;

#[tokio::test]
async fn review_kind_refuses_a_valid_snapshot_for_another_identifier() {
    let snapshot = ReviewKindPolicy {
        id: "returned-kind".to_owned(),
        version: "1".to_owned(),
        purpose: ReviewKindPurpose::Approval,
        context_strategy: ReviewContextStrategy::Submitted,
        stages: vec![ReviewStagePolicy {
            id: "review".to_owned(),
            queue: "reviews".to_owned(),
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
            "type":"object",
            "additionalProperties":false,
            "properties":{}
        }),
        result_schema: None,
        outcomes: Vec::new(),
    }
    .snapshot()
    .expect("fixture snapshot");
    let app = Router::new()
        .route(
            "/v1/review-kinds/requested-kind",
            get(review_kind_fixture_response),
        )
        .with_state(serde_json::to_value(snapshot).expect("snapshot JSON"));
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
            .review_kind(CaseworkAuth::new(&token, "staff"), "requested-kind")
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

async fn review_kind_fixture_response(State(response): State<Value>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        response.to_string(),
    )
}

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
async fn review_result_feed_refuses_unbounded_or_invalid_continuations() {
    let entry = json!({
        "eventId": Uuid::from_u128(8),
        "requestId": Uuid::from_u128(7),
        "resultId": Uuid::from_u128(99),
        "completedAt": "2026-09-19T00:00:00Z"
    });
    let cursor = Uuid::from_u128(8).to_string();
    let responses = Arc::new(Mutex::new(VecDeque::from([
        json!({"items": vec![entry.clone(); 100], "nextCursor": cursor}),
        json!({"items": vec![entry.clone(); 101]}),
        json!({"items": [], "nextCursor": ""}),
        json!({"items": [], "nextCursor": "x".repeat(4097)}),
        json!({"items": [], "nextCursor": "cursor\n8"}),
        json!({"items": [], "nextCursor": "not-an-event-uuid"}),
    ])));
    let app = Router::new()
        .route(
            "/v1/review-results",
            get(review_result_feed_fixture_response),
        )
        .with_state(responses);
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
    let query = registry_casework_client::ReviewPageQuery {
        cursor: None,
        limit: Some(100),
    };

    let boundary = client
        .review_results(CaseworkAuth::new(&token, "requester"), &query)
        .await
        .expect("bounded result feed page");
    assert_eq!(boundary.value.items.len(), 100);
    assert_eq!(
        boundary.value.next_cursor,
        Some(Uuid::parse_str(&cursor).unwrap())
    );

    for _ in 0..5 {
        assert!(matches!(
            client
                .review_results(CaseworkAuth::new(&token, "requester"), &query)
                .await,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                trace_id: Some(ref trace_id),
            }) if trace_id == "0123456789abcdef0123456789abcdef"
        ));
    }
    server.abort();
}

async fn review_result_feed_fixture_response(
    State(responses): State<Arc<Mutex<VecDeque<Value>>>>,
) -> impl IntoResponse {
    let response = responses
        .lock()
        .expect("responses")
        .pop_front()
        .expect("fixture response");
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        response.to_string(),
    )
}

#[tokio::test]
async fn review_tasks_refuses_an_oversized_response_page() {
    let task = json!({
        "taskId": Uuid::from_u128(7),
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 1,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let app = Router::new()
        .route("/v1/review-tasks", get(review_task_fixture_response))
        .with_state(json!({"items": vec![task; 101]}));
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
            .review_tasks(
                CaseworkAuth::new(&token, "staff"),
                &registry_casework_client::ReviewTaskQuery {
                    queue: None,
                    cursor: None,
                    limit: Some(100),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_tasks_refuses_a_page_outside_the_requested_inbox() {
    let foreign_queue = json!({
        "taskId": Uuid::from_u128(7),
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "intake",
        "revision": 1,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let foreign_profile = json!({
        "taskId": Uuid::from_u128(10),
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 1,
        "eligibleProfiles": ["supervisor"],
        "state": "open",
    });
    let app = Router::new()
        .route("/v1/review-tasks", get(review_task_fixture_response))
        .with_state(json!({"items": [foreign_queue, foreign_profile]}));
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
            .review_tasks(
                CaseworkAuth::new(&token, "staff"),
                &registry_casework_client::ReviewTaskQuery {
                    queue: Some("reviews".to_owned()),
                    cursor: None,
                    limit: Some(100),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_note_refuses_a_response_for_another_request() {
    let requested_id = Uuid::from_u128(7);
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/notes",
            post(review_task_fixture_response),
        )
        .with_state(json!({
            "eventId": Uuid::from_u128(8),
            "requestId": Uuid::from_u128(9),
            "kind": "note",
            "detail": {"audience": "reviewers", "note": "Review note"},
            "occurredAt": "2026-09-20T00:00:00Z",
        }));
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
            .add_review_note(
                CaseworkAuth::new(&token, "staff"),
                requested_id,
                "note-7",
                &ReviewNoteRequest {
                    audience: ReviewHistoryAudience::Reviewers,
                    note: "Review note".to_owned(),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_note_refuses_a_response_whose_event_is_not_a_note() {
    let requested_id = Uuid::from_u128(7);
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/notes",
            post(review_task_fixture_response),
        )
        .with_state(json!({
            "eventId": Uuid::from_u128(8),
            "requestId": requested_id,
            "taskId": Uuid::from_u128(11),
            "kind": "stage_advanced",
            "detail": {"audience": "reviewers", "note": "Review note"},
            "occurredAt": "2026-09-20T00:00:00Z",
        }));
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
            .add_review_note(
                CaseworkAuth::new(&token, "staff"),
                requested_id,
                "note-7",
                &ReviewNoteRequest {
                    audience: ReviewHistoryAudience::Reviewers,
                    note: "Review note".to_owned(),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_note_refuses_a_response_whose_note_detail_was_substituted() {
    let requested_id = Uuid::from_u128(7);
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/notes",
            post(review_task_fixture_response),
        )
        .with_state(json!({
            "eventId": Uuid::from_u128(8),
            "requestId": requested_id,
            "kind": "note",
            "detail": {"audience": "requester", "note": "Substituted note"},
            "occurredAt": "2026-09-20T00:00:00Z",
        }));
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
            .add_review_note(
                CaseworkAuth::new(&token, "staff"),
                requested_id,
                "note-7",
                &ReviewNoteRequest {
                    audience: ReviewHistoryAudience::Reviewers,
                    note: "Review note".to_owned(),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_accountability_refuses_a_response_for_another_event() {
    let requested_id = Uuid::from_u128(7);
    let app = Router::new()
        .route(
            "/v1/review-accountability/{event}",
            get(review_task_fixture_response),
        )
        .with_state(json!({
            "eventId": Uuid::from_u128(8),
            "requestId": Uuid::from_u128(9),
            "taskId": Uuid::from_u128(10),
            "actorRef": "actor_fixture",
            "actor": {"issuer": "https://issuer.example", "subject": "reviewer"},
            "profileId": "staff",
            "decision": "approve",
            "occurredAt": "2026-09-20T00:00:00Z",
            "retainedUntil": "2026-10-20T00:00:00Z",
        }));
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
            .review_accountability(CaseworkAuth::new(&token, "staff"), requested_id)
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn review_task_grant_revocation_requires_the_selected_invalidated_grant() {
    let task_id = Uuid::from_u128(7);
    let grant_id = Uuid::from_u128(8);
    let responses = Arc::new(Mutex::new(VecDeque::from([
        json!({"id": Uuid::from_u128(9), "invalidated": true}),
        json!({"id": grant_id, "invalidated": false}),
    ])));
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/task-grants/{grant}/revoke",
            post(review_result_feed_fixture_response),
        )
        .with_state(responses);
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

    for _ in 0..2 {
        assert!(matches!(
            client
                .revoke_review_task_grant(CaseworkAuth::new(&token, "staff"), task_id, grant_id,)
                .await,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    server.abort();
}

#[tokio::test]
async fn review_task_grant_approval_requires_the_selected_active_template() {
    let task_id = Uuid::from_u128(7);
    let approval = TaskApprovalRequest {
        template_id: "verify-status".into(),
        template_version: "1".into(),
    };
    let grant = |template_id: &str, template_version: &str, invalidated: bool| {
        json!({
            "id": Uuid::from_u128(8),
            "templateId": template_id,
            "templateVersion": template_version,
            "agent": {"issuer": "https://issuer.example", "subject": "agent-one"},
            "client": "agent-client",
            "resource": "urn:evidence",
            "scopes": ["evidence:invoke"],
            "purpose": "verify-status",
            "bounds": {"type": "evidence", "requirement": "status"},
            "expiresAt": 2_000_000_900_u64,
            "invalidated": invalidated,
        })
    };
    let responses = Arc::new(Mutex::new(VecDeque::from([
        grant("other-template", "1", false),
        grant("verify-status", "2", false),
        grant("verify-status", "1", true),
        grant("verify-status", "1", false),
    ])));
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/task-grants",
            post(review_result_feed_fixture_response),
        )
        .with_state(responses);
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

    for index in 0..3 {
        assert!(matches!(
            client
                .approve_review_task_grant(
                    CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                    task_id,
                    index,
                    &format!("approve-{index}"),
                    &approval,
                )
                .await,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    let approved = client
        .approve_review_task_grant(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            task_id,
            3,
            "approve-3",
            &approval,
        )
        .await
        .expect("matching active grant");
    assert_eq!(approved.value.template_id, approval.template_id);
    assert_eq!(approved.value.template_version, approval.template_version);
    assert!(!approved.value.invalidated);
    server.abort();
}

#[tokio::test]
async fn review_result_refuses_a_non_object_payload() {
    let request_id = Uuid::from_u128(7);
    let digest = ContentDigest::for_bytes(b"fixture");
    let accepted: registry_casework_client::ReviewRequestAccepted = serde_json::from_value(json!({
        "requestId": request_id,
        "subject": {
            "source": "registry",
            "type": "change-request",
            "id": "proposal-7",
            "version": "3",
            "digest": digest,
        },
        "policy": {"id": "registry-correction", "version": "1", "digest": digest},
        "submissionDigest": digest,
    }))
    .expect("accepted binding fixture");
    let response = json!({
        "resultId": Uuid::from_u128(99),
        "requestId": request_id,
        "subject": accepted.subject,
        "policy": accepted.policy,
        "submissionDigest": accepted.submission_digest,
        "status": "changes_requested",
        "outcome": "needs-correction",
        "result": ["not", "an", "object"],
        "completedAt": "2026-09-19T00:00:00Z",
        "availableUntil": "2026-10-19T00:00:00Z",
    });
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/result",
            get(review_result_fixture_response),
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

    assert!(matches!(
        client
            .review_result(CaseworkAuth::new(&token, "requester"), &accepted)
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

async fn review_result_fixture_response(State(response): State<Value>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        response.to_string(),
    )
}

#[tokio::test]
async fn exact_claim_and_release_refuse_a_response_for_another_task() {
    let requested_task_id = Uuid::from_u128(7);
    let returned_task_id = Uuid::from_u128(8);
    let response = json!({
        "taskId": returned_task_id,
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 2,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let app = Router::new()
        .route("/v1/review-tasks/{task}", get(review_task_fixture_response))
        .route(
            "/v1/review-tasks/{task}/claim",
            post(review_task_fixture_response),
        )
        .route(
            "/v1/review-tasks/{task}/release",
            post(review_task_fixture_response),
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

    let responses = [
        client
            .review_task(CaseworkAuth::new(&token, "staff"), requested_task_id)
            .await,
        client
            .claim_review_task(
                CaseworkAuth::new(&token, "staff"),
                requested_task_id,
                1,
                "claim-7",
            )
            .await,
        client
            .release_review_task(
                CaseworkAuth::new(&token, "staff"),
                requested_task_id,
                1,
                "release-7",
            )
            .await,
    ];
    for response in responses {
        assert!(matches!(
            response,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    server.abort();
}

#[tokio::test]
async fn claim_refuses_a_response_that_left_the_task_open() {
    let task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": task_id,
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 2,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/claim",
            post(review_task_fixture_response),
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

    assert!(matches!(
        client
            .claim_review_task(CaseworkAuth::new(&token, "staff"), task_id, 1, "claim-7")
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn release_refuses_a_response_that_left_the_task_held() {
    let task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": task_id,
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 2,
        "eligibleProfiles": ["staff"],
        "state": {"held": {"holder": {"issuer": "https://issuer.example.test", "subject": "someone"}}},
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/release",
            post(review_task_fixture_response),
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

    assert!(matches!(
        client
            .release_review_task(CaseworkAuth::new(&token, "staff"), task_id, 1, "release-7")
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn exact_assignment_and_delegation_refuse_a_response_for_another_task() {
    let requested_task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": Uuid::from_u128(8),
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 2,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/assign",
            post(review_task_fixture_response),
        )
        .route(
            "/v1/review-tasks/{task}/delegate",
            post(review_task_fixture_response),
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
    let assignee = IssuerPrincipal {
        issuer: "https://issuer.example".to_owned(),
        subject: "reviewer".to_owned(),
    };

    let responses = [
        client
            .assign_review_task(
                CaseworkAuth::new(&token, "supervisor"),
                requested_task_id,
                1,
                "assign-7",
                &AssignmentRequest {
                    assignee: assignee.clone(),
                    reason: Some("reassign".to_owned()),
                },
            )
            .await,
        client
            .delegate_review_task(
                CaseworkAuth::new(&token, "staff"),
                requested_task_id,
                1,
                "delegate-7",
                &DelegateRequest {
                    delegate: assignee,
                    reason: Some("coverage".to_owned()),
                },
            )
            .await,
    ];
    for response in responses {
        assert!(matches!(
            response,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    server.abort();
}

#[tokio::test]
async fn assignment_and_delegation_refuse_a_response_that_did_not_advance_the_revision() {
    let task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": task_id,
        "requestId": Uuid::from_u128(9),
        "stageIndex": 0,
        "stageId": "review",
        "queue": "reviews",
        "revision": 1,
        "eligibleProfiles": ["staff"],
        "state": "open",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/assign",
            post(review_task_fixture_response),
        )
        .route(
            "/v1/review-tasks/{task}/delegate",
            post(review_task_fixture_response),
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
    let assignee = IssuerPrincipal {
        issuer: "https://issuer.example".to_owned(),
        subject: "reviewer".to_owned(),
    };

    let responses = [
        client
            .assign_review_task(
                CaseworkAuth::new(&token, "supervisor"),
                task_id,
                1,
                "assign-7",
                &AssignmentRequest {
                    assignee: assignee.clone(),
                    reason: Some("reassign".to_owned()),
                },
            )
            .await,
        client
            .delegate_review_task(
                CaseworkAuth::new(&token, "staff"),
                task_id,
                1,
                "delegate-7",
                &DelegateRequest {
                    delegate: assignee,
                    reason: Some("coverage".to_owned()),
                },
            )
            .await,
    ];
    for response in responses {
        assert!(matches!(
            response,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    server.abort();
}

#[tokio::test]
async fn exact_draft_read_refuses_a_response_for_another_task() {
    let requested_task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": Uuid::from_u128(8),
        "author": {
            "issuer": "https://issuer.example",
            "subject": "reviewer",
        },
        "body": {"note": "bounded draft"},
        "revision": 2,
        "updatedAt": "2026-09-20T00:00:00Z",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/draft",
            get(review_task_fixture_response),
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

    assert!(matches!(
        client
            .review_task_draft(
                CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                requested_task_id,
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn exact_draft_save_refuses_a_response_for_another_task() {
    let requested_task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": Uuid::from_u128(8),
        "author": {
            "issuer": "https://issuer.example",
            "subject": "reviewer",
        },
        "body": {"note": "bounded draft"},
        "revision": 2,
        "updatedAt": "2026-09-20T00:00:00Z",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/draft",
            put(review_task_fixture_response),
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

    assert!(matches!(
        client
            .save_review_task_draft(
                CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                requested_task_id,
                1,
                "draft-7",
                &ReviewTaskDraftInput {
                    body: json!({"note": "bounded draft"}),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn draft_save_refuses_a_response_echoing_a_different_body() {
    let requested_task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": requested_task_id,
        "author": {
            "issuer": "https://issuer.example",
            "subject": "reviewer",
        },
        "body": {"note": "substituted draft"},
        "revision": 2,
        "updatedAt": "2026-09-20T00:00:00Z",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/draft",
            put(review_task_fixture_response),
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

    assert!(matches!(
        client
            .save_review_task_draft(
                CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                requested_task_id,
                1,
                "draft-7",
                &ReviewTaskDraftInput {
                    body: json!({"note": "bounded draft"}),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn draft_save_refuses_a_response_without_a_valid_draft_revision() {
    let requested_task_id = Uuid::from_u128(7);
    let response = json!({
        "taskId": requested_task_id,
        "author": {
            "issuer": "https://issuer.example",
            "subject": "reviewer",
        },
        "body": {"note": "bounded draft"},
        "revision": 0,
        "updatedAt": "2026-09-20T00:00:00Z",
    });
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/draft",
            put(review_task_fixture_response),
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

    assert!(matches!(
        client
            .save_review_task_draft(
                CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                requested_task_id,
                1,
                "draft-7",
                &ReviewTaskDraftInput {
                    body: json!({"note": "bounded draft"}),
                },
            )
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn decided_by_caller_appears_only_on_a_single_decided_task_read() {
    let task_id = Uuid::from_u128(7);
    let task = |state: Value, decided_by_caller: Option<bool>| {
        let mut task = json!({
            "taskId": task_id,
            "requestId": Uuid::from_u128(9),
            "stageIndex": 0,
            "stageId": "review",
            "queue": "reviews",
            "revision": 2,
            "eligibleProfiles": ["staff"],
            "state": state,
        });
        if let Some(decided) = decided_by_caller {
            task["decidedByCaller"] = json!(decided);
        }
        task
    };
    let held = json!({"held": {"holder": {"issuer": "https://issuer.example.test", "subject": "someone"}}});
    let serve = |router: Router| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve fixture");
        });
        let client = CaseworkClient::new(CaseworkClientConfig::new(
            Url::parse(&format!("http://{address}/")).expect("fixture URL"),
        ))
        .expect("client");
        (client, server)
    };
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    fn refused<T>(result: Result<T, CaseworkClientError>) -> bool {
        matches!(
            result,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        )
    }

    for (read, accepted) in [
        (task(json!("decided"), Some(true)), true),
        (task(json!("decided"), Some(false)), true),
        (task(json!("decided"), None), false),
        (task(json!("open"), Some(false)), false),
        (task(held.clone(), Some(true)), false),
    ] {
        let (client, server) = serve(
            Router::new()
                .route("/v1/review-tasks/{task}", get(review_task_fixture_response))
                .with_state(read.clone()),
        )
        .await;
        let result = client
            .review_task(CaseworkAuth::new(&token, "staff"), task_id)
            .await;
        if accepted {
            assert_eq!(
                result
                    .expect("a conforming decided read")
                    .value
                    .decided_by_caller,
                read["decidedByCaller"].as_bool()
            );
        } else {
            assert!(refused(result), "{read}");
        }
        server.abort();
    }

    let (client, server) = serve(
        Router::new()
            .route("/v1/review-tasks", get(review_task_fixture_response))
            .with_state(json!({"items": [task(json!("decided"), Some(true))]})),
    )
    .await;
    assert!(refused(
        client
            .review_tasks(
                CaseworkAuth::new(&token, "staff"),
                &registry_casework_client::ReviewTaskQuery {
                    queue: None,
                    cursor: None,
                    limit: Some(100),
                },
            )
            .await
    ));
    server.abort();

    let (client, server) = serve(
        Router::new()
            .route(
                "/v1/review-tasks/{task}/claim",
                post(review_task_fixture_response),
            )
            .with_state(task(held, Some(false))),
    )
    .await;
    assert!(refused(
        client
            .claim_review_task(CaseworkAuth::new(&token, "staff"), task_id, 1, "claim-7")
            .await
    ));
    server.abort();
}

async fn review_task_fixture_response(State(response): State<Value>) -> impl IntoResponse {
    (
        StatusCode::OK,
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

fn context_body(strategy: ReviewContextStrategy, display_schema: Value, context: Value) -> Value {
    let snapshot = ReviewKindPolicy {
        id: "standalone-answer".to_owned(),
        version: "1".to_owned(),
        purpose: ReviewKindPurpose::Approval,
        context_strategy: strategy,
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
        display_schema,
        result_schema: None,
        outcomes: Vec::new(),
    }
    .snapshot()
    .expect("fixture policy snapshot");
    json!({
        "taskId": Uuid::nil(),
        "requestId": "10000000-0000-4000-8000-000000000001",
        "subject": {
            "source": "registry", "type": "record", "id": "record-1", "version": "1",
            "digest": ContentDigest::for_bytes(b"record-1")
        },
        "requesterReference": "requester-reference",
        "policy": snapshot.identity.clone(),
        "policySnapshot": snapshot,
        "context": context,
    })
}

async fn task_context_fixture_response(State(body): State<Value>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("traceparent", TRACEPARENT),
        ],
        body.to_string(),
    )
}

async fn serve_context(
    body: Value,
) -> Result<
    registry_casework_client::CaseworkComplete<registry_casework_core::ReviewTaskContext>,
    CaseworkClientError,
> {
    let app = Router::new()
        .route(
            "/v1/review-tasks/{task}/context",
            get(task_context_fixture_response),
        )
        .with_state(body);
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
    let outcome = client
        .review_task_context(CaseworkAuth::new(&token, "staff"), Uuid::nil())
        .await;
    server.abort();
    outcome
}

async fn serve_context_rejection(body: Value) -> CaseworkClientError {
    serve_context(body)
        .await
        .expect_err("context rejection fixture returns a protocol error")
}

#[tokio::test]
async fn review_task_context_refuses_a_submitted_context_that_violates_the_display_schema() {
    let error = serve_context_rejection(context_body(
        ReviewContextStrategy::Submitted,
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        json!({"strategy": "submitted", "snapshot": {"summary": "undisclosed"}}),
    ))
    .await;
    assert!(matches!(
        error,
        CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        }
    ));
}

#[tokio::test]
async fn review_task_context_refuses_a_context_for_another_strategy() {
    let error = serve_context_rejection(context_body(
        ReviewContextStrategy::Source,
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        json!({"strategy": "submitted", "snapshot": {}}),
    ))
    .await;
    assert!(matches!(
        error,
        CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        }
    ));
}

#[tokio::test]
async fn review_task_context_refuses_a_binding_changed_context_that_still_carries_a_projection() {
    let error = serve_context_rejection(context_body(
        ReviewContextStrategy::Source,
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        json!({
            "strategy": "source",
            "reference": "registry/record-1",
            "bindingStatus": "binding_changed",
            "projection": {
                "binding": {
                    "sourceRevision": "source-revision-1",
                    "version": "1",
                    "generation": "review-source-generation"
                },
                "display": {}
            }
        }),
    ))
    .await;
    assert!(matches!(
        error,
        CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        }
    ));
}

fn source_context(binding_status: &str, projection: Option<Value>) -> Value {
    let mut context = json!({
        "strategy": "source",
        "reference": "registry/record-1",
        "bindingStatus": binding_status,
    });
    if let Some(projection) = projection {
        context["projection"] = projection;
    }
    context
}

fn matching_projection(version: &str, integrity: Value) -> Value {
    json!({
        "binding": {
            "sourceRevision": "source-revision-1",
            "version": version,
            "integrity": integrity,
            "generation": "review-source-generation"
        },
        "display": {}
    })
}

fn empty_display_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    })
}

#[tokio::test]
async fn review_task_context_accepts_a_current_binding_with_a_matching_projection() {
    let complete = serve_context(context_body(
        ReviewContextStrategy::Source,
        empty_display_schema(),
        source_context(
            "current",
            Some(matching_projection(
                "1",
                json!(ContentDigest::for_bytes(b"record-1")),
            )),
        ),
    ))
    .await
    .expect("a current projection of the pinned occurrence is the reviewable context");
    assert!(matches!(
        complete.value.context,
        ReviewTaskContextData::Source {
            binding_status: registry_casework_core::ReviewSourceBindingStatus::Current,
            ..
        }
    ));
}

#[tokio::test]
async fn review_task_context_refuses_a_current_binding_without_a_projection() {
    let error = serve_context_rejection(context_body(
        ReviewContextStrategy::Source,
        empty_display_schema(),
        source_context("current", None),
    ))
    .await;
    assert!(matches!(
        error,
        CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        }
    ));
}

#[tokio::test]
async fn review_task_context_refuses_a_current_projection_that_does_not_match_the_pinned_subject() {
    for projection in [
        matching_projection("2", json!(ContentDigest::for_bytes(b"record-1"))),
        matching_projection("1", Value::Null),
        matching_projection("1", json!(ContentDigest::for_bytes(b"another-occurrence"))),
    ] {
        let error = serve_context_rejection(context_body(
            ReviewContextStrategy::Source,
            empty_display_schema(),
            source_context("current", Some(projection)),
        ))
        .await;
        assert!(
            matches!(
                error,
                CaseworkClientError::Protocol {
                    status: 200,
                    failure: CaseworkProtocolFailure::Body,
                    ..
                }
            ),
            "a projection of another occurrence must not present itself as current"
        );
    }
}

#[tokio::test]
async fn review_task_context_refuses_a_current_projection_that_violates_the_display_schema() {
    let error = serve_context_rejection(context_body(
        ReviewContextStrategy::Source,
        empty_display_schema(),
        source_context(
            "current",
            Some(json!({
                "binding": {
                    "sourceRevision": "source-revision-1",
                    "version": "1",
                    "integrity": ContentDigest::for_bytes(b"record-1"),
                    "generation": "review-source-generation"
                },
                "display": {"undisclosed": true}
            })),
        ),
    ))
    .await;
    assert!(matches!(
        error,
        CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        }
    ));
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

    assert_eq!(response.value.len(), 1);
    assert_eq!(response.value[0].request_id, Uuid::nil());
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
        r#"[{"clockOccurrenceId":"10000000-0000-4000-8000-000000000001","clockId":"review-deadline","requestId":"00000000-0000-0000-0000-000000000000","correlation":{"scope":"subject","source":"registry","subjectType":"record","id":"record-1"},"state":"running","policyDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","anchorAt":"2026-09-20T00:00:00Z"}]"#,
    )
}

#[tokio::test]
async fn review_clocks_refuse_occurrences_for_another_request() {
    let request_id = Uuid::from_u128(7);
    let response = json!([{
        "clockOccurrenceId": Uuid::from_u128(8),
        "clockId": "review-deadline",
        "requestId": Uuid::from_u128(9),
        "correlation": {
            "scope": "subject",
            "source": "registry",
            "subjectType": "record",
            "id": "record-1",
        },
        "state": "running",
        "policyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "anchorAt": "2026-09-20T00:00:00Z",
    }]);
    let app = Router::new()
        .route(
            "/v1/review-requests/{request}/clocks",
            get(review_task_fixture_response),
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

    assert!(matches!(
        client
            .review_clocks(CaseworkAuth::new(&token, "requester"), request_id)
            .await,
        Err(CaseworkClientError::Protocol {
            status: 200,
            failure: CaseworkProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn cancellation_accepts_only_a_result_bound_to_the_full_accepted_binding() {
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

    let mut wrong_policy = cancel_response(request_id, "proposal-7", "cancelled", "cancelled");
    wrong_policy["result"]["policy"]["version"] = json!("2");
    let mut wrong_submission = cancel_response(request_id, "proposal-7", "cancelled", "cancelled");
    wrong_submission["result"]["submissionDigest"] =
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    for invalid in [
        cancel_response(Uuid::from_u128(8), "proposal-7", "cancelled", "cancelled"),
        cancel_response(request_id, "other-proposal", "cancelled", "cancelled"),
        wrong_policy,
        wrong_submission,
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
    let expected: ReviewRequestAccepted = serde_json::from_value(json!({
        "requestId": request_id,
        "subject": cancellation.subject,
        "policy": {
            "id": "registry-correction",
            "version": "1",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "submissionDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }))
    .expect("accepted binding fixture");
    let result = client
        .cancel_review_request(
            CaseworkAuth::new(&token, "requester"),
            &expected,
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
        // Review history pages bind a present cursor to the final returned
        // event, so the fixture serves the one entry the cursor names.
        r#"{"items":[{"eventId":"10000000-0000-4000-8000-000000000001","requestId":"00000000-0000-0000-0000-000000000000","kind":"note","detail":{},"occurredAt":"2026-09-20T00:00:00Z"}],"nextCursor":"10000000-0000-4000-8000-000000000001"}"#
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
async fn review_history_refuses_oversized_or_cross_request_pages() {
    let requested_request_id = Uuid::from_u128(7);
    let matching_entry = json!({
        "eventId": Uuid::from_u128(8),
        "requestId": requested_request_id,
        "kind": "note",
        "detail": {},
        "occurredAt": "2026-09-20T00:00:00Z",
    });
    let cases = [
        json!({"items": vec![matching_entry; 101]}),
        json!({
            "items": [{
                "eventId": Uuid::from_u128(9),
                "requestId": Uuid::from_u128(10),
                "kind": "note",
                "detail": {},
                "occurredAt": "2026-09-20T00:00:00Z",
            }],
        }),
    ];

    for response in cases {
        let app = Router::new()
            .route(
                "/v1/review-requests/{request}/history",
                get(review_task_fixture_response),
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

        assert!(matches!(
            client
                .review_history(
                    CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
                    requested_request_id,
                    &registry_casework_client::ReviewPageQuery::default(),
                )
                .await,
            Err(CaseworkClientError::Protocol {
                status: 200,
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
        server.abort();
    }
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

#[tokio::test]
async fn draft_read_maps_a_problem_bearing_404_to_the_typed_problem() {
    let app = Router::new().route(
        "/v1/review-tasks/{task}/draft",
        get(not_found_problem_response),
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

    let error = client
        .review_task_draft(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::from_u128(7),
        )
        .await
        .expect_err("a problem-bearing 404 names the refusal, not an absent draft");
    assert!(
        matches!(
            error,
            CaseworkClientError::Problem {
                status: 404,
                code: CaseworkProblemCode::RequestNotFound,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    server.abort();
}

async fn not_found_problem_response() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
        ],
        concat!(
            "{\"type\":\"https://id.registrystack.org/problems/registry-casework/",
            "request/not-found\",\"title\":\"Route not found\",",
            "\"status\":404,\"detail\":\"The requested Casework route does not exist.\",",
            "\"code\":\"request.not-found\",",
            "\"traceId\":\"0123456789abcdef0123456789abcdef\"}"
        ),
    )
}

#[tokio::test]
async fn draft_read_keeps_an_empty_404_as_an_absent_draft() {
    let app = Router::new().route(
        "/v1/review-tasks/{task}/draft",
        get(empty_not_found_response),
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

    let complete = client
        .review_task_draft(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            Uuid::from_u128(7),
        )
        .await
        .expect("an empty 404 means no draft exists yet");
    assert!(complete.value.is_none());
    server.abort();
}

async fn empty_not_found_response() -> axum::http::Response<axum::body::Body> {
    axum::http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("traceparent", TRACEPARENT)
        .body(axum::body::Body::empty())
        .expect("fixture response")
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
            "properties": {"summary": {"type": "string"}}
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
