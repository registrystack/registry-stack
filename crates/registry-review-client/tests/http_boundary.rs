use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use registry_review_client::{
    BearerToken, ContentDigest, ReviewAuth, ReviewCancelRequest, ReviewClient, ReviewClientConfig,
    ReviewClientError, ReviewContext, ReviewCreateRequest, ReviewMutationErrorClass,
    ReviewProtocolFailure, ReviewRequestAccepted, ReviewResultLookup, ReviewResultResponse,
    ReviewResultsQuery, ReviewValidationReason, SourceContextBinding, SubjectBinding, Uuid,
};
use serde_json::json;
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const OTHER_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
type Observations = Arc<Mutex<Vec<(Method, String, HeaderMap)>>>;

fn create_request() -> ReviewCreateRequest {
    ReviewCreateRequest {
        policy: registry_review_client::PolicyBinding {
            id: "registry-correction".to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::parse(DIGEST).expect("policy digest fixture"),
        }
        .into(),
        subject: subject(),
        requester_reference: "proposal-7".to_owned(),
        initiator: None,
        context: ReviewContext::CurrentSource {
            binding: SourceContextBinding {
                reference: "proposal-7".to_owned(),
            },
        },
        result_constraints: None,
    }
}

fn subject() -> SubjectBinding {
    SubjectBinding {
        source: "registry".to_owned(),
        subject_type: "change-request".to_owned(),
        id: "proposal-7".to_owned(),
        version: "3".to_owned(),
        digest: ContentDigest::parse(DIGEST).expect("fixture digest"),
    }
}

fn accepted_json(request_id: Uuid) -> serde_json::Value {
    json!({
        "requestId": request_id,
        "subject": {
            "source": "registry",
            "type": "change-request",
            "id": "proposal-7",
            "version": "3",
            "digest": DIGEST
        },
        "policy": {"id": "registry-correction", "version": "1", "digest": DIGEST},
        "submissionDigest": DIGEST
    })
}

fn expected_binding(request_id: Uuid) -> ReviewRequestAccepted {
    serde_json::from_value(accepted_json(request_id)).expect("accepted binding fixture")
}

fn expected_submission_digest() -> ContentDigest {
    ContentDigest::parse(DIGEST).expect("submission digest fixture")
}

fn result_json(request_id: Uuid) -> serde_json::Value {
    json!({
        "resultId": Uuid::from_u128(99),
        "requestId": request_id,
        "subject": {
            "source": "registry",
            "type": "change-request",
            "id": "proposal-7",
            "version": "3",
            "digest": DIGEST
        },
        "policy": {"id": "registry-correction", "version": "1", "digest": DIGEST},
        "submissionDigest": DIGEST,
        "status": "approved",
        "outcome": "approved",
        "completedAt": "2026-09-19T00:00:00Z",
        "availableUntil": "2026-10-19T00:00:00Z"
    })
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(value.to_string()))
        .expect("fixture response")
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("traceparent", TRACEPARENT)
        .body(Body::empty())
        .expect("fixture response")
}

async fn serve(app: Router) -> (ReviewClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let client = ReviewClient::new(ReviewClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    (client, server)
}

#[tokio::test]
async fn create_posts_once_with_caller_auth_and_stable_idempotency_key() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/review-requests", post(capture_create))
        .with_state(observations.clone());
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let accepted = client
        .create_or_recover_request(
            ReviewAuth::new(&token, "producer"),
            "submission-7",
            &create_request(),
            &expected_submission_digest(),
        )
        .await
        .expect("accepted request");

    assert_eq!(accepted.value.request_id, Uuid::from_u128(7));
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    let (method, path, headers) = &observations[0];
    assert_eq!(method, Method::POST);
    assert_eq!(path, "/v1/review-requests");
    assert_eq!(headers["authorization"], "Bearer one-call-secret");
    assert_eq!(headers["registry-review-profile"], "producer");
    assert!(headers.get("registry-casework-profile").is_none());
    assert_eq!(headers["idempotency-key"], "submission-7");
    assert_eq!(headers["accept"], "application/json");
    assert_eq!(headers["content-type"], "application/json");
    server.abort();
}

async fn capture_create(
    State(observations): State<Observations>,
    request: Request<Body>,
) -> Response<Body> {
    observations.lock().expect("observations").push((
        request.method().clone(),
        request.uri().to_string(),
        request.headers().clone(),
    ));
    let bytes = axum::body::to_bytes(request.into_body(), 128 * 1024)
        .await
        .expect("bounded create body");
    let sent: serde_json::Value = serde_json::from_slice(&bytes).expect("create body JSON");
    assert_eq!(
        sent,
        json!(create_request()),
        "send the complete original request"
    );
    assert_eq!(sent["policy"], json!(create_request().policy));
    assert!(sent.get("kind").is_none());
    json_response(StatusCode::OK, accepted_json(Uuid::from_u128(7)))
}

#[tokio::test]
async fn current_policy_create_accepts_a_concrete_binding_and_refuses_partial_pins_before_io() {
    let app = Router::new().route(
        "/v1/review-requests",
        post(|| async { json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7))) }),
    );
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").unwrap();
    let mut request = create_request();
    request.policy = registry_review_client::PolicySelection::current("registry-correction");
    let accepted = client
        .create_or_recover_request(
            ReviewAuth::new(&token, "producer"),
            "current-policy",
            &request,
            &expected_submission_digest(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.value.policy.version, "1");
    assert_eq!(request.policy.version, None);
    request.policy.version = Some("1".into());
    assert!(matches!(
        client
            .create_or_recover_request(
                ReviewAuth::new(&token, "producer"),
                "partial-pin",
                &request,
                &expected_submission_digest()
            )
            .await,
        Err(ReviewClientError::InvalidRequest { .. })
    ));
    server.abort();
}

#[tokio::test]
async fn create_refuses_each_mismatched_policy_binding() {
    for (field, changed) in [
        ("id", json!("another-policy")),
        ("version", json!("2")),
        ("digest", json!(OTHER_DIGEST)),
    ] {
        let mut accepted = accepted_json(Uuid::from_u128(7));
        accepted["policy"][field] = changed;
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || async move { json_response(StatusCode::CREATED, accepted) }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("one-call-secret").expect("fixture token");
        let error = client
            .create_or_recover_request(
                ReviewAuth::new(&token, "producer"),
                "submission-7",
                &create_request(),
                &expected_submission_digest(),
            )
            .await
            .expect_err("the accepted policy must match every submitted policy field");
        assert!(
            matches!(
                error,
                ReviewClientError::Protocol {
                    status: 201,
                    failure: ReviewProtocolFailure::Body,
                    ..
                }
            ),
            "mismatched policy {field}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn create_refuses_a_mismatched_submission_digest() {
    let app = Router::new().route("/v1/review-requests", post(wrong_submission_digest));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let error = client
        .create_or_recover_request(
            ReviewAuth::new(&token, "producer"),
            "submission-7",
            &create_request(),
            &ContentDigest::parse(OTHER_DIGEST).expect("other digest fixture"),
        )
        .await
        .expect_err("the accepted binding must match the expected submission digest");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            status: 200,
            failure: ReviewProtocolFailure::Body,
            ..
        }
    ));
    server.abort();
}

async fn wrong_submission_digest() -> Response<Body> {
    json_response(StatusCode::OK, accepted_json(Uuid::from_u128(7)))
}

#[tokio::test]
async fn create_refuses_a_nil_request_identifier_in_the_accepted_binding() {
    let app = Router::new().route("/v1/review-requests", post(nil_request_id));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let error = client
        .create_or_recover_request(
            ReviewAuth::new(&token, "producer"),
            "submission-7",
            &create_request(),
            &expected_submission_digest(),
        )
        .await
        .expect_err("a nil request identifier cannot anchor later correlations");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            status: 200,
            failure: ReviewProtocolFailure::Body,
            ..
        }
    ));
    server.abort();
}

async fn nil_request_id() -> Response<Body> {
    json_response(StatusCode::OK, accepted_json(Uuid::nil()))
}

#[tokio::test]
async fn ambiguous_create_failure_is_not_retried_by_the_client() {
    let attempts = Arc::new(Mutex::new(0usize));
    let app = Router::new()
        .route("/v1/review-requests", post(fail_then_accept))
        .with_state(attempts.clone());
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let error = client
        .create_or_recover_request(
            ReviewAuth::new(&token, "producer"),
            "submission-7",
            &create_request(),
            &expected_submission_digest(),
        )
        .await
        .expect_err("the first ambiguous response must be returned");

    assert!(matches!(
        &error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::Status,
            status: 503,
            ..
        }
    ));
    assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);
    assert_eq!(*attempts.lock().expect("attempts"), 1);
    server.abort();
}

async fn fail_then_accept(State(attempts): State<Arc<Mutex<usize>>>) -> Response<Body> {
    let mut attempts = attempts.lock().expect("attempts");
    *attempts += 1;
    if *attempts == 1 {
        empty_response(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7)))
    }
}

#[tokio::test]
async fn request_feed_and_cancel_use_the_product_neutral_routes() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/review-requests/{id}", get(capture_request))
        .route("/v1/review-results", get(capture_feed))
        .route("/v1/review-requests/{id}/cancel", post(capture_cancel))
        .with_state(observations.clone());
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let request_id = Uuid::from_u128(7);
    let result_cursor = Uuid::from_u128(8);

    client
        .request(ReviewAuth::new(&token, "producer"), request_id)
        .await
        .expect("request view");
    client
        .requester_results(
            ReviewAuth::new(&token, "producer"),
            &ReviewResultsQuery {
                cursor: Some(result_cursor),
                limit: Some(25),
            },
        )
        .await
        .expect("result feed");
    client
        .cancel_request(
            ReviewAuth::new(&token, "producer"),
            &expected_binding(request_id),
            "cancel-7",
            &ReviewCancelRequest {
                subject: subject(),
                reason: "source proposal withdrawn".to_owned(),
            },
        )
        .await
        .expect("cancel response");

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 3);
    for (_, _, headers) in observations.iter() {
        assert_eq!(headers["registry-review-profile"], "producer");
    }
    assert_eq!(observations[0].0, Method::GET);
    assert_eq!(
        observations[0].1,
        format!("/v1/review-requests/{request_id}")
    );
    assert_eq!(observations[1].0, Method::GET);
    assert_eq!(
        observations[1].1,
        "/v1/review-results?cursor=00000000-0000-0000-0000-000000000008&limit=25"
    );
    assert_eq!(observations[2].0, Method::POST);
    assert_eq!(
        observations[2].1,
        format!("/v1/review-requests/{request_id}/cancel")
    );
    assert_eq!(observations[2].2["idempotency-key"], "cancel-7");
    server.abort();
}

#[tokio::test]
async fn result_feed_rejects_an_invalid_page_size_before_http() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/review-results", get(capture_feed))
        .with_state(observations.clone());
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let error = client
        .requester_results(
            ReviewAuth::new(&token, "producer"),
            &ReviewResultsQuery {
                cursor: Some(Uuid::from_u128(8)),
                limit: Some(0),
            },
        )
        .await
        .expect_err("an invalid page size must be rejected");

    assert!(matches!(error, ReviewClientError::InvalidRequest { .. }));
    assert!(observations.lock().expect("observations").is_empty());
    server.abort();
}

#[tokio::test]
async fn result_feed_refuses_nil_correlation_identifiers_anywhere_in_a_page() {
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let mut accepted = Vec::new();
    for field in ["requestId", "resultId"] {
        for position in 0..2 {
            for continued in [false, true] {
                let mut entries = vec![feed_entry_json(8), feed_entry_json(9)];
                entries[position][field] = json!(Uuid::nil());
                let body = json!({
                    "items": entries,
                    "nextCursor": continued.then_some(Uuid::from_u128(9))
                });
                let observations = Arc::new(Mutex::new(Vec::new()));
                let app = Router::new().route(
                    "/v1/review-results",
                    get({
                        let observations = observations.clone();
                        move |request: Request<Body>| {
                            capture(&observations, &request);
                            let body = body.clone();
                            async move { json_response(StatusCode::OK, body) }
                        }
                    }),
                );
                let (client, server) = serve(app).await;

                let result = client
                    .requester_results(
                        ReviewAuth::new(&token, "producer"),
                        &ReviewResultsQuery {
                            cursor: Some(Uuid::from_u128(6)),
                            limit: Some(2),
                        },
                    )
                    .await;
                if !matches!(
                    result,
                    Err(ReviewClientError::Protocol {
                        status: 200,
                        failure: ReviewProtocolFailure::Body,
                        trace_id: Some(ref trace_id),
                    }) if trace_id == "0123456789abcdef0123456789abcdef"
                ) {
                    accepted.push(format!(
                        "nil {field} at position {position}, continued={continued}"
                    ));
                }
                assert_eq!(observations.lock().expect("observations").len(), 1);
                server.abort();
            }
        }
    }
    assert!(accepted.is_empty(), "unusable pages accepted: {accepted:?}");
}

#[tokio::test]
async fn result_feed_preserves_independent_identifiers_and_caller_controlled_pagination() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let responses = Arc::new(Mutex::new(VecDeque::from([
        json!({"items": [feed_entry_json(8)], "nextCursor": Uuid::from_u128(8)}),
        json!({"items": [feed_entry_json(9)]}),
        json!({"items": []}),
    ])));
    let app = Router::new().route(
        "/v1/review-results",
        get({
            let observations = observations.clone();
            let responses = responses.clone();
            move |request: Request<Body>| {
                capture(&observations, &request);
                let body = responses
                    .lock()
                    .expect("responses")
                    .pop_front()
                    .expect("page");
                async move { json_response(StatusCode::OK, body) }
            }
        }),
    );
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let mut query = ReviewResultsQuery {
        cursor: None,
        limit: Some(1),
    };

    for (index, event_id) in [8, 9].into_iter().enumerate() {
        let page = client
            .requester_results(ReviewAuth::new(&token, "producer"), &query)
            .await
            .expect("usable feed page")
            .value;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].event_id, Uuid::from_u128(event_id));
        assert_eq!(page.items[0].request_id, Uuid::from_u128(7));
        assert_eq!(page.items[0].result_id, Uuid::from_u128(99));
        assert_eq!(page.next_cursor, (index == 0).then_some(Uuid::from_u128(8)));
        assert_eq!(observations.lock().expect("observations").len(), index + 1);
        query.cursor = page
            .next_cursor
            .or_else(|| page.items.last().map(|entry| entry.event_id));
    }
    let empty = client
        .requester_results(ReviewAuth::new(&token, "producer"), &query)
        .await
        .expect("empty terminal page")
        .value;
    assert!(empty.items.is_empty());
    assert!(empty.next_cursor.is_none());
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].1, "/v1/review-results?limit=1");
    assert_eq!(
        observations[1].1,
        "/v1/review-results?cursor=00000000-0000-0000-0000-000000000008&limit=1"
    );
    assert_eq!(
        observations[2].1,
        "/v1/review-results?cursor=00000000-0000-0000-0000-000000000009&limit=1"
    );
    assert!(responses.lock().expect("responses").is_empty());
    server.abort();
}

fn feed_entry_json(event_id: u128) -> serde_json::Value {
    json!({
        "eventId": Uuid::from_u128(event_id),
        "requestId": Uuid::from_u128(7),
        "resultId": Uuid::from_u128(99),
        "completedAt": "2026-09-19T00:00:00Z"
    })
}

async fn capture_request(
    State(observations): State<Observations>,
    Path(request_id): Path<Uuid>,
    request: Request<Body>,
) -> Response<Body> {
    capture(&observations, &request);
    json_response(
        StatusCode::OK,
        json!({
            "requestId": request_id,
            "subject": {
                "source": "registry",
                "type": "change-request",
                "id": "proposal-7",
                "version": "3",
                "digest": DIGEST
            },
            "policy": {"id": "registry-correction", "version": "1", "digest": DIGEST},
            "submissionDigest": DIGEST,
            "requesterReference": "proposal-7",
            "lifecycle": "reviewing",
            "activeStage": "legal",
            "createdAt": "2026-09-19T00:00:00Z",
            "updatedAt": "2026-09-19T00:00:01Z"
        }),
    )
}

async fn capture_feed(
    State(observations): State<Observations>,
    request: Request<Body>,
) -> Response<Body> {
    capture(&observations, &request);
    json_response(
        StatusCode::OK,
        json!({
            "items": [{
                "eventId": Uuid::from_u128(8),
                "requestId": Uuid::from_u128(7),
                "resultId": Uuid::from_u128(99),
                "completedAt": "2026-09-19T00:00:00Z"
            }],
            "nextCursor": Uuid::from_u128(8)
        }),
    )
}

async fn capture_cancel(
    State(observations): State<Observations>,
    Path(request_id): Path<Uuid>,
    request: Request<Body>,
) -> Response<Body> {
    capture(&observations, &request);
    json_response(
        StatusCode::OK,
        json!({"outcome": "cancelled", "result": {
            "resultId": Uuid::from_u128(99),
            "requestId": request_id,
            "subject": {
                "source": "registry",
                "type": "change-request",
                "id": "proposal-7",
                "version": "3",
                "digest": DIGEST
            },
            "policy": {"id": "registry-correction", "version": "1", "digest": DIGEST},
            "submissionDigest": DIGEST,
            "status": "cancelled",
            "completedAt": "2026-09-19T00:00:00Z",
            "availableUntil": "2026-10-19T00:00:00Z"
        }}),
    )
}

fn capture(observations: &Observations, request: &Request<Body>) {
    observations.lock().expect("observations").push((
        request.method().clone(),
        request.uri().to_string(),
        request.headers().clone(),
    ));
}

#[tokio::test]
async fn result_lookup_accepts_only_the_four_defined_statuses_and_shapes() {
    let app = Router::new().route("/v1/review-requests/{id}/result", get(result_by_id));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    for (id, expected) in [
        (200u128, ReviewResultLookup::Available),
        (202, ReviewResultLookup::Pending),
        (404, ReviewResultLookup::ConcealedOrUnknown),
        (410, ReviewResultLookup::Expired),
    ] {
        let response = client
            .result(
                ReviewAuth::new(&token, "producer"),
                &expected_binding(Uuid::from_u128(id)),
            )
            .await
            .expect("defined result status");
        assert_eq!(response.lookup(), expected);
        if let ReviewResultResponse::Available(complete) = response {
            assert_eq!(complete.value.request_id, Uuid::from_u128(200));
        }
    }

    let error = client
        .result(
            ReviewAuth::new(&token, "producer"),
            &expected_binding(Uuid::from_u128(201)),
        )
        .await
        .expect_err("a substituted result request ID must be refused");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::Body,
            ..
        }
    ));

    let error = client
        .result(
            ReviewAuth::new(&token, "producer"),
            &expected_binding(Uuid::from_u128(204)),
        )
        .await
        .expect_err("undefined result status");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            status: 204,
            failure: ReviewProtocolFailure::Status,
            ..
        }
    ));
    server.abort();
}

#[tokio::test]
async fn result_lookup_refuses_every_mismatched_correlation_field() {
    let app = Router::new().route("/v1/review-requests/{id}/result", get(result_by_id));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    for id in 205u128..=209 {
        let error = client
            .result(
                ReviewAuth::new(&token, "producer"),
                &expected_binding(Uuid::from_u128(id)),
            )
            .await
            .expect_err("a substituted correlation field must be refused");
        assert!(matches!(
            error,
            ReviewClientError::Protocol {
                failure: ReviewProtocolFailure::Body,
                ..
            }
        ));
    }
    server.abort();
}

#[tokio::test]
async fn result_lookup_refuses_a_non_object_payload() {
    let app = Router::new().route("/v1/review-requests/{id}/result", get(result_by_id));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let request_id = Uuid::from_u128(210);

    let error = client
        .result(
            ReviewAuth::new(&token, "producer"),
            &expected_binding(request_id),
        )
        .await
        .expect_err("a non-object result payload must be refused");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::Body,
            ..
        }
    ));
    server.abort();
}

#[tokio::test]
async fn cancellation_refuses_every_mismatched_accepted_binding_field() {
    let request_id = Uuid::from_u128(300);
    let mut wrong_policy = cancelled_json(request_id);
    wrong_policy["result"]["policy"]["version"] = json!("2");
    let mut wrong_submission = cancelled_json(request_id);
    wrong_submission["result"]["submissionDigest"] = json!(OTHER_DIGEST);
    let responses = Arc::new(Mutex::new(VecDeque::from([wrong_policy, wrong_submission])));
    let app = Router::new()
        .route(
            "/v1/review-requests/{id}/cancel",
            post(queued_cancel_response),
        )
        .with_state(responses);
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");
    let expected = expected_binding(request_id);
    let cancellation = ReviewCancelRequest {
        subject: expected.subject.clone(),
        reason: "source proposal withdrawn".to_owned(),
    };

    for _ in 0..2 {
        let error = client
            .cancel_request(
                ReviewAuth::new(&token, "producer"),
                &expected,
                "cancel-300",
                &cancellation,
            )
            .await
            .expect_err("a substituted accepted-binding field must be refused");
        assert!(matches!(
            error,
            ReviewClientError::Protocol {
                failure: ReviewProtocolFailure::Body,
                ..
            }
        ));
    }
    server.abort();
}

fn cancelled_json(request_id: Uuid) -> serde_json::Value {
    let mut result = result_json(request_id);
    result["status"] = json!("cancelled");
    json!({"outcome": "cancelled", "result": result})
}

async fn queued_cancel_response(
    State(responses): State<Arc<Mutex<VecDeque<serde_json::Value>>>>,
) -> Response<Body> {
    let value = responses
        .lock()
        .expect("responses")
        .pop_front()
        .expect("fixture response");
    json_response(StatusCode::OK, value)
}

async fn result_by_id(Path(id): Path<Uuid>) -> Response<Body> {
    match id.as_u128() {
        200 => json_response(StatusCode::OK, result_json(id)),
        201 => json_response(StatusCode::OK, result_json(Uuid::from_u128(200))),
        202 => empty_response(StatusCode::ACCEPTED),
        404 => empty_response(StatusCode::NOT_FOUND),
        410 => empty_response(StatusCode::GONE),
        205 => {
            let mut value = result_json(id);
            value["subject"]["version"] = json!("4");
            json_response(StatusCode::OK, value)
        }
        206 => {
            let mut value = result_json(id);
            value["subject"]["digest"] = json!(OTHER_DIGEST);
            json_response(StatusCode::OK, value)
        }
        207 => {
            let mut value = result_json(id);
            value["policy"]["version"] = json!("2");
            json_response(StatusCode::OK, value)
        }
        208 => {
            let mut value = result_json(id);
            value["policy"]["digest"] = json!(OTHER_DIGEST);
            json_response(StatusCode::OK, value)
        }
        209 => {
            let mut value = result_json(id);
            value["submissionDigest"] = json!(OTHER_DIGEST);
            json_response(StatusCode::OK, value)
        }
        210 => {
            let mut value = result_json(id);
            value["status"] = json!("changes-requested");
            value["outcome"] = json!("needs-correction");
            value["result"] = json!("not-an-object");
            json_response(StatusCode::OK, value)
        }
        _ => empty_response(StatusCode::NO_CONTENT),
    }
}

#[tokio::test]
async fn malformed_media_oversize_and_header_excess_are_refused() {
    let app = Router::new()
        .route("/malformed/v1/review-requests/{id}", get(malformed))
        .route("/duplicate/v1/review-requests/{id}", get(duplicate_member))
        .route("/media/v1/review-requests/{id}", get(wrong_media))
        .route("/problem/v1/review-requests/{id}", get(malformed_problem))
        .route("/unpaired/v1/review-requests/{id}", get(unpaired_problem))
        .route(
            "/provider-namespace/v1/review-requests/{id}",
            get(provider_specific_problem),
        )
        .route("/valid-problem/v1/review-requests/{id}", get(valid_problem))
        .route(
            "/invalid-uri/v1/review-requests/{id}",
            get(invalid_problem_uri),
        )
        .route(
            "/server-problem/v1/review-requests/{id}",
            get(server_problem),
        )
        .route("/oversize/v1/review-requests/{id}", get(oversize))
        .route("/headers/v1/review-requests/{id}", get(excess_headers));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    for (prefix, failure) in [
        ("malformed", ReviewProtocolFailure::Body),
        ("duplicate", ReviewProtocolFailure::Body),
        ("media", ReviewProtocolFailure::MediaType),
        ("problem", ReviewProtocolFailure::Problem),
        ("unpaired", ReviewProtocolFailure::Problem),
        ("invalid-uri", ReviewProtocolFailure::Problem),
    ] {
        let client = ReviewClient::new(ReviewClientConfig::new(
            Url::parse(&format!("http://{address}/{prefix}/")).expect("fixture URL"),
        ))
        .expect("client");
        let error = client
            .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
            .await
            .expect_err("invalid response");
        assert!(matches!(
            error,
            ReviewClientError::Protocol { failure: actual, .. } if actual == failure
        ));
    }

    let provider_client = ReviewClient::new(ReviewClientConfig::new(
        Url::parse(&format!("http://{address}/provider-namespace/")).unwrap(),
    ))
    .unwrap();
    let provider_error = provider_client
        .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
        .await
        .unwrap_err();
    assert!(matches!(
        provider_error,
        ReviewClientError::Problem { status: 400, .. }
    ));
    assert_eq!(
        provider_error.mutation_class(),
        ReviewMutationErrorClass::Deterministic
    );

    let client = ReviewClient::new(ReviewClientConfig::new(
        Url::parse(&format!("http://{address}/valid-problem/")).expect("fixture URL"),
    ))
    .expect("client");
    let error = client
        .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
        .await
        .expect_err("valid problem refusal");
    assert_eq!(
        error.mutation_class(),
        ReviewMutationErrorClass::Deterministic
    );
    assert!(matches!(
        error,
        ReviewClientError::Problem {
            status: 400,
            ref problem,
            ..
        } if problem.code.as_str() == "request.invalid"
            && problem.validation.as_ref().is_some_and(|validation|
                validation.path == "$.context.snapshot"
                    && validation.reason == ReviewValidationReason::SchemaMismatch)
    ));

    let client = ReviewClient::new(ReviewClientConfig::new(
        Url::parse(&format!("http://{address}/server-problem/")).expect("fixture URL"),
    ))
    .expect("client");
    let error = client
        .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
        .await
        .expect_err("a server problem leaves a mutation outcome ambiguous");
    assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);

    let client = ReviewClient::new(
        ReviewClientConfig::new(
            Url::parse(&format!("http://{address}/oversize/")).expect("fixture URL"),
        )
        .with_max_response_bytes(32),
    )
    .expect("client");
    let error = client
        .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
        .await
        .expect_err("oversize response");
    assert!(matches!(error, ReviewClientError::Transport { .. }));

    let client = ReviewClient::new(ReviewClientConfig::new(
        Url::parse(&format!("http://{address}/headers/")).expect("fixture URL"),
    ))
    .expect("client");
    let error = client
        .request(ReviewAuth::new(&token, "producer"), Uuid::nil())
        .await
        .expect_err("excess response headers");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::HeaderBounds,
            ..
        }
    ));
    server.abort();
}

async fn malformed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from("{"))
        .expect("fixture response")
}

async fn duplicate_member() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(
            r#"{"requestId":"00000000-0000-0000-0000-000000000007","requestId":"00000000-0000-0000-0000-000000000008"}"#,
        ))
        .expect("fixture response")
}

async fn wrong_media() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json; charset=utf-8")
        .header("traceparent", TRACEPARENT)
        .body(Body::from("{}"))
        .expect("fixture response")
}

async fn malformed_problem() -> Response<Body> {
    problem_response(true)
}

async fn invalid_problem_uri() -> Response<Body> {
    let value = json!({"type":"provider problem without a URI scheme", "title":"Refused",
        "status":400, "detail":"Refused", "code":"provider.refused",
        "traceId":"0123456789abcdef0123456789abcdef"});
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/problem+json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(value.to_string()))
        .unwrap()
}

async fn provider_specific_problem() -> Response<Body> {
    let value = json!({
        "type":"https://review-provider.example.test/problems/provider/refused",
        "title":"Invalid request", "status":400, "detail":"The request is invalid.",
        "code":"provider.refused", "traceId":"0123456789abcdef0123456789abcdef"
    });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/problem+json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(value.to_string()))
        .unwrap()
}

async fn unpaired_problem() -> Response<Body> {
    let mut response = problem_response(false);
    response.headers_mut().insert(
        "registry-review-validation-path",
        HeaderValue::from_static("$.context.snapshot"),
    );
    response
}

async fn valid_problem() -> Response<Body> {
    let mut response = problem_response(false);
    response.headers_mut().insert(
        "registry-review-validation-path",
        HeaderValue::from_static("$.context.snapshot"),
    );
    response.headers_mut().insert(
        "registry-review-validation-reason",
        HeaderValue::from_static("schema-mismatch"),
    );
    response
}

async fn server_problem() -> Response<Body> {
    let value = json!({
        "type": "https://id.registrystack.org/problems/registry-casework/runtime/failure",
        "title": "Casework runtime failure",
        "status": 503,
        "detail": "Casework could not complete the request.",
        "code": "runtime.failure",
        "traceId": "0123456789abcdef0123456789abcdef"
    });
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/problem+json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(value.to_string()))
        .expect("fixture response")
}

fn problem_response(extra_member: bool) -> Response<Body> {
    let mut value = json!({
        "type": "https://id.registrystack.org/problems/registry-casework/request/invalid",
        "title": "Invalid request",
        "status": 400,
        "detail": "The review request is invalid.",
        "code": "request.invalid",
        "traceId": "0123456789abcdef0123456789abcdef"
    });
    if extra_member {
        value["untrusted"] = json!("must be refused");
    }
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/problem+json")
        .header("traceparent", TRACEPARENT)
        .body(Body::from(value.to_string()))
        .expect("fixture response")
}

async fn oversize() -> Response<Body> {
    json_response(StatusCode::OK, json!({"padding": "x".repeat(256)}))
}

async fn excess_headers() -> Response<Body> {
    let mut response = json_response(StatusCode::OK, json!({}));
    for index in 0..65 {
        let name = HeaderName::from_bytes(format!("x-extra-{index}").as_bytes())
            .expect("fixture header name");
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static("value"));
    }
    response
}

#[tokio::test]
async fn create_refuses_each_changed_expected_policy_binding_component() {
    for field in ["id", "version", "digest"] {
        let mut body = accepted_json(Uuid::from_u128(7));
        body["policy"][field] = if field == "digest" {
            json!(OTHER_DIGEST)
        } else {
            json!("different")
        };
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || {
                let body = body.clone();
                async move { json_response(StatusCode::CREATED, body) }
            }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("one-call-secret").unwrap();
        let error = client
            .create_or_recover_request(
                ReviewAuth::new(&token, "producer"),
                "request-key",
                &create_request(),
                &expected_submission_digest(),
            )
            .await
            .expect_err("acceptance must bind every expected policy component");
        assert!(matches!(
            error,
            ReviewClientError::Protocol {
                failure: ReviewProtocolFailure::Body,
                ..
            }
        ));
        server.abort();
    }
}

#[tokio::test]
async fn explicit_producer_disagreement_is_distinct_and_never_a_safe_fresh_retry() {
    let request = create_request();
    let expected = registry_review_client::submission_digest(
        "breg-producer",
        &request.subject.source,
        &request,
    )
    .unwrap();
    let actual = registry_review_client::submission_digest(
        "casework-producer",
        &request.subject.source,
        &request,
    )
    .unwrap();
    for status in [StatusCode::CREATED, StatusCode::OK] {
        let mut body = accepted_json(Uuid::from_u128(7));
        body["submissionDigest"] = json!(actual);
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || {
                let body = body.clone();
                async move {
                    let mut response = json_response(status, body);
                    response.headers_mut().insert(
                        "registry-review-producer",
                        HeaderValue::from_static("casework-producer"),
                    );
                    response
                }
            }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("identity-token-canary").unwrap();
        let error = client
            .create_or_recover_request_for_producer(
                ReviewAuth::new(&token, "producer"),
                "identity-key",
                &request,
                &expected,
                "breg-producer",
            )
            .await
            .expect_err("explicit identity disagreement");
        assert_eq!(
            error.mutation_class(),
            ReviewMutationErrorClass::Ambiguous,
            "a successful status may have committed a review under the peer identity"
        );
        assert!(
            matches!(&error, ReviewClientError::ProducerIdentityMismatch { expected, actual, status: found, .. }
            if expected == "breg-producer" && actual == "casework-producer" && *found == status.as_u16())
        );
        assert!(!format!("{error:?}").contains("identity-token-canary"));
        server.abort();
    }
}

#[tokio::test]
async fn missing_producer_metadata_keeps_exact_digest_compatibility_and_uncertainty() {
    for digest in [DIGEST, OTHER_DIGEST] {
        let app = Router::new().route(
            "/v1/review-requests",
            post(|| async {
                json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7)))
            }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("identity-token-canary").unwrap();
        let outcome = client
            .create_or_recover_request_for_producer(
                ReviewAuth::new(&token, "producer"),
                "identity-key",
                &create_request(),
                &ContentDigest::parse(digest).unwrap(),
                "breg-producer",
            )
            .await;
        if digest == DIGEST {
            assert!(
                outcome.is_ok(),
                "older providers still require the exact original binding"
            );
        } else {
            let error = outcome.unwrap_err();
            assert!(matches!(
                error,
                ReviewClientError::Protocol {
                    failure: ReviewProtocolFailure::Body,
                    ..
                }
            ));
            assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);
        }
        server.abort();
    }
}

#[tokio::test]
async fn malformed_or_duplicate_producer_metadata_never_claims_an_identity_mismatch() {
    for values in [
        vec!["".to_owned()],
        vec!["peer identity canary".to_owned()],
        vec!["x".repeat(129)],
        vec!["peer".to_owned(), "peer".to_owned()],
    ] {
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || {
                let values = values.clone();
                async move {
                    let mut response =
                        json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7)));
                    for value in values {
                        response.headers_mut().append(
                            "registry-review-producer",
                            HeaderValue::from_str(&value).unwrap(),
                        );
                    }
                    response
                }
            }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("identity-token-canary").unwrap();
        let error = client
            .create_or_recover_request_for_producer(
                ReviewAuth::new(&token, "producer"),
                "identity-key",
                &create_request(),
                &expected_submission_digest(),
                "breg-producer",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ReviewClientError::Protocol {
                failure: ReviewProtocolFailure::ProducerIdentity,
                ..
            }
        ));
        assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);
        assert!(!format!("{error:?}").contains("peer identity canary"));
        server.abort();
    }
}

async fn mismatched_digest_is_protocol_failure(digest: &str) {
    for status in [StatusCode::CREATED, StatusCode::OK] {
        let mut body = accepted_json(Uuid::from_u128(7));
        body["submissionDigest"] = json!(digest);
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || {
                let body = body.clone();
                async move {
                    let mut response = json_response(status, body);
                    response.headers_mut().insert(
                        "registry-review-producer",
                        HeaderValue::from_static("casework-producer"),
                    );
                    response
                }
            }),
        );
        let (client, server) = serve(app).await;
        let request = create_request();
        let expected = registry_review_client::submission_digest(
            "breg-producer",
            &request.subject.source,
            &request,
        )
        .unwrap();
        let token = BearerToken::new("identity-token-canary").unwrap();
        let error = client
            .create_or_recover_request_for_producer(
                ReviewAuth::new(&token, "producer"),
                "identity-key",
                &request,
                &expected,
                "breg-producer",
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                ReviewClientError::Protocol {
                    failure: ReviewProtocolFailure::Body,
                    ..
                }
            ),
            "an unbound acceptance remains a protocol failure: {error:?}"
        );
        assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);
        assert!(!format!("{error:?}").contains("identity-token-canary"));
        server.abort();
    }
}

#[tokio::test]
async fn mismatched_producer_with_arbitrary_digest_remains_protocol_uncertain() {
    mismatched_digest_is_protocol_failure(OTHER_DIGEST).await;
}

#[tokio::test]
async fn mismatched_producer_with_stale_request_digest_remains_protocol_uncertain() {
    let mut stale = create_request();
    stale.requester_reference = "stale-requester-canary".to_owned();
    let digest = registry_review_client::submission_digest(
        "casework-producer",
        &stale.subject.source,
        &stale,
    )
    .unwrap();
    mismatched_digest_is_protocol_failure(digest.as_str()).await;
}

#[tokio::test]
async fn mismatched_producer_with_wrong_namespace_digest_remains_protocol_uncertain() {
    let digest = registry_review_client::submission_digest(
        "casework-producer",
        "producer",
        &create_request(),
    )
    .unwrap();
    mismatched_digest_is_protocol_failure(digest.as_str()).await;
}

#[tokio::test]
async fn mismatched_producer_with_malformed_digest_remains_protocol_uncertain() {
    mismatched_digest_is_protocol_failure("invalid-digest-canary").await;
}

#[tokio::test]
async fn same_producer_metadata_still_requires_the_exact_original_digest() {
    let request = create_request();
    let expected = registry_review_client::submission_digest(
        "breg-producer",
        &request.subject.source,
        &request,
    )
    .unwrap();
    for digest in [expected.as_str(), OTHER_DIGEST] {
        let mut body = accepted_json(Uuid::from_u128(7));
        body["submissionDigest"] = json!(digest);
        let app = Router::new().route(
            "/v1/review-requests",
            post(move || {
                let body = body.clone();
                async move {
                    let mut response = json_response(StatusCode::CREATED, body);
                    response.headers_mut().insert(
                        "registry-review-producer",
                        HeaderValue::from_static("breg-producer"),
                    );
                    response
                }
            }),
        );
        let (client, server) = serve(app).await;
        let token = BearerToken::new("identity-token-canary").unwrap();
        let outcome = client
            .create_or_recover_request_for_producer(
                ReviewAuth::new(&token, "producer"),
                "identity-key",
                &request,
                &expected,
                "breg-producer",
            )
            .await;
        if digest == expected.as_str() {
            assert_eq!(outcome.unwrap().value.submission_digest, expected);
        } else {
            let error = outcome.unwrap_err();
            assert!(matches!(
                error,
                ReviewClientError::Protocol {
                    failure: ReviewProtocolFailure::Body,
                    ..
                }
            ));
            assert_eq!(error.mutation_class(), ReviewMutationErrorClass::Ambiguous);
        }
        server.abort();
    }
}
