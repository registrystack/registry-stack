use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use registry_review_client::{
    BearerToken, ContentDigest, ReviewCancelRequest, ReviewClient, ReviewClientConfig,
    ReviewClientError, ReviewContext, ReviewCreateRequest, ReviewProtocolFailure,
    ReviewRequestAccepted, ReviewResultLookup, ReviewResultResponse, ReviewResultsQuery,
    SourceContextBinding, SubjectBinding, Uuid,
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
        kind: "registry-correction".to_owned(),
        subject: subject(),
        requester_reference: "proposal-7".to_owned(),
        initiator: None,
        context: ReviewContext::Source {
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
    let client = ReviewClient::new(
        ReviewClientConfig::new(Url::parse(&format!("http://{address}/")).expect("fixture URL"))
            .with_profile("producer"),
    )
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
            &token,
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
    assert_eq!(headers["registry-casework-profile"], "producer");
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
    json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7)))
}

#[tokio::test]
async fn create_refuses_a_mismatched_submission_digest() {
    let app = Router::new().route("/v1/review-requests", post(wrong_submission_digest));
    let (client, server) = serve(app).await;
    let token = BearerToken::new("one-call-secret").expect("fixture token");

    let error = client
        .create_or_recover_request(
            &token,
            "submission-7",
            &create_request(),
            &ContentDigest::parse(OTHER_DIGEST).expect("other digest fixture"),
        )
        .await
        .expect_err("the accepted binding must match the expected submission digest");
    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::Body,
            ..
        }
    ));
    server.abort();
}

async fn wrong_submission_digest() -> Response<Body> {
    json_response(StatusCode::CREATED, accepted_json(Uuid::from_u128(7)))
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
            &token,
            "submission-7",
            &create_request(),
            &expected_submission_digest(),
        )
        .await
        .expect_err("the first ambiguous response must be returned");

    assert!(matches!(
        error,
        ReviewClientError::Protocol {
            failure: ReviewProtocolFailure::Status,
            status: 503,
            ..
        }
    ));
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

    client
        .request(&token, request_id)
        .await
        .expect("request view");
    client
        .requester_results(
            &token,
            &ReviewResultsQuery {
                cursor: Some("cursor-7"),
                limit: Some(25),
            },
        )
        .await
        .expect("result feed");
    client
        .cancel_request(
            &token,
            request_id,
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
        assert_eq!(headers["registry-casework-profile"], "producer");
    }
    assert_eq!(observations[0].0, Method::GET);
    assert_eq!(
        observations[0].1,
        format!("/v1/review-requests/{request_id}")
    );
    assert_eq!(observations[1].0, Method::GET);
    assert_eq!(
        observations[1].1,
        "/v1/review-results?cursor=cursor-7&limit=25"
    );
    assert_eq!(observations[2].0, Method::POST);
    assert_eq!(
        observations[2].1,
        format!("/v1/review-requests/{request_id}/cancel")
    );
    assert_eq!(observations[2].2["idempotency-key"], "cancel-7");
    server.abort();
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
            "nextCursor": "cursor-8"
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
            .result(&token, &expected_binding(Uuid::from_u128(id)))
            .await
            .expect("defined result status");
        assert_eq!(response.lookup(), expected);
        if let ReviewResultResponse::Available(complete) = response {
            assert_eq!(complete.value.request_id, Uuid::from_u128(200));
        }
    }

    let error = client
        .result(&token, &expected_binding(Uuid::from_u128(201)))
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
        .result(&token, &expected_binding(Uuid::from_u128(204)))
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
            .result(&token, &expected_binding(Uuid::from_u128(id)))
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
        .route("/valid-problem/v1/review-requests/{id}", get(valid_problem))
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
    ] {
        let client = ReviewClient::new(
            ReviewClientConfig::new(
                Url::parse(&format!("http://{address}/{prefix}/")).expect("fixture URL"),
            )
            .with_profile("producer"),
        )
        .expect("client");
        let error = client
            .request(&token, Uuid::nil())
            .await
            .expect_err("invalid response");
        assert!(matches!(
            error,
            ReviewClientError::Protocol { failure: actual, .. } if actual == failure
        ));
    }

    let client = ReviewClient::new(
        ReviewClientConfig::new(
            Url::parse(&format!("http://{address}/valid-problem/")).expect("fixture URL"),
        )
        .with_profile("producer"),
    )
    .expect("client");
    let error = client
        .request(&token, Uuid::nil())
        .await
        .expect_err("valid problem refusal");
    assert!(matches!(
        error,
        ReviewClientError::Problem { status: 400, .. }
    ));

    let client = ReviewClient::new(
        ReviewClientConfig::new(
            Url::parse(&format!("http://{address}/oversize/")).expect("fixture URL"),
        )
        .with_profile("producer")
        .with_max_response_bytes(32),
    )
    .expect("client");
    let error = client
        .request(&token, Uuid::nil())
        .await
        .expect_err("oversize response");
    assert!(matches!(error, ReviewClientError::Transport { .. }));

    let client = ReviewClient::new(
        ReviewClientConfig::new(
            Url::parse(&format!("http://{address}/headers/")).expect("fixture URL"),
        )
        .with_profile("producer"),
    )
    .expect("client");
    let error = client
        .request(&token, Uuid::nil())
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

async fn valid_problem() -> Response<Body> {
    problem_response(false)
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
