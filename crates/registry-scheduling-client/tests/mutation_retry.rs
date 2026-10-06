// SPDX-License-Identifier: Apache-2.0

//! The bounded same-key retry of idempotency-keyed commands, against a mock
//! service that answers each request with the next scripted answer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::Router;
use chrono::{TimeZone as _, Utc};
use registry_scheduling_client::{
    type_uri, AdmissionRequest, BearerToken, CancelAppointmentRequest, CreateAppointmentRequest,
    PartyCounts, ProblemCode, RescheduleAppointmentRequest, SchedulingAuth, SchedulingClient,
    SchedulingClientConfig, SchedulingClientError, TransportKind,
};
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

const HOLD_DOCUMENT: &str = concat!(
    r#"{"holdId":"hold-7","offering":"registry-update-30","#,
    r#""start":"2026-10-05T02:00:00Z","end":"2026-10-05T02:30:00Z","#,
    r#""resource":"station-1","units":1,"expiresAt":"2026-10-05T01:45:00Z","#,
    r#""policyRevision":4,"externalReferences":[]}"#
);

const APPOINTMENT_DOCUMENT: &str = concat!(
    r#"{"appointmentId":"appt-1","offering":"registry-update-30","#,
    r#""start":"2026-10-05T02:00:00Z","end":"2026-10-05T02:30:00Z","#,
    r#""resource":"station-1","units":1,"channel":null,"revision":2,"state":"confirmed","#,
    r#""policyRevision":4,"createdAt":"2026-10-04T09:00:00Z","cancelledAt":null,"externalReferences":[]}"#
);

#[derive(Clone)]
struct Captured {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone, Copy)]
enum Answer {
    /// Holds the request past the client's timeout, so the client cannot
    /// know whether it took effect.
    Stall,
    /// An exact product problem, with an optional `Retry-After` field.
    Problem(ProblemCode, Option<&'static str>),
    /// A JSON answer with the given status.
    Json(StatusCode, &'static str),
}

#[derive(Clone)]
struct Script {
    observations: Arc<Mutex<Vec<Captured>>>,
    answers: Arc<Mutex<VecDeque<Answer>>>,
}

impl Script {
    fn observations(&self) -> Vec<Captured> {
        self.observations.lock().expect("observations").clone()
    }
}

async fn answer(
    State(script): State<Script>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    script
        .observations
        .lock()
        .expect("observations")
        .push(Captured {
            method,
            uri,
            headers,
            body,
        });
    let next = script.answers.lock().expect("answers").pop_front();
    match next {
        Some(Answer::Stall) => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Some(Answer::Problem(code, retry_after)) => {
            let document = serde_json::json!({
                "type": type_uri(code.code()),
                "title": code.title(),
                "status": code.http_status(),
                "detail": code.detail(),
                "code": code.code(),
                "traceId": TRACE_ID,
            })
            .to_string();
            let mut headers = traced("application/problem+json");
            if let Some(seconds) = retry_after {
                headers.insert("retry-after", HeaderValue::from_static(seconds));
            }
            let status = StatusCode::from_u16(code.http_status()).expect("problem status");
            (status, headers, document).into_response()
        }
        Some(Answer::Json(status, body)) => {
            (status, traced("application/json"), body.to_owned()).into_response()
        }
        None => StatusCode::IM_A_TEAPOT.into_response(),
    }
}

fn traced(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static(content_type));
    headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    headers
}

/// Serve every command route from one script, in request order.
async fn serve(answers: &[Answer]) -> (String, Script, tokio::task::JoinHandle<()>) {
    let script = Script {
        observations: Arc::new(Mutex::new(Vec::new())),
        answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
    };
    let app = Router::new()
        .route("/v1/holds", post(answer))
        .route("/v1/holds/hold-7", delete(answer))
        .route("/v1/appointments", post(answer))
        .route("/v1/appointments/appt-1/reschedule", post(answer))
        .route("/v1/appointments/appt-1/cancel", post(answer))
        .with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    (address, script, server)
}

fn config(address: &str) -> SchedulingClientConfig {
    SchedulingClientConfig::new(Url::parse(&format!("http://{address}/")).expect("fixture URL"))
}

fn client(config: SchedulingClientConfig) -> SchedulingClient {
    SchedulingClient::new(config).expect("client")
}

fn admission() -> AdmissionRequest {
    AdmissionRequest {
        offering: "registry-update-30".to_owned(),
        start: Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap(),
        party: PartyCounts {
            recipients: 1,
            attendees: 2,
        },
        channel: Some("public".to_owned()),
        duplicate_key: Some("subject:one".to_owned()),
        policy_revision: 4,
        window_revision: None,
        capabilities: Vec::new(),
        prerequisites: Vec::new(),
        external_references: Vec::new(),
    }
}

fn token() -> BearerToken {
    BearerToken::new("fixture-secret").expect("fixture token")
}

/// Every resend is the same request: method, route, every header, and every
/// body byte, so the service can only replay it under the same key.
fn assert_identical_resends(observations: &[Captured], key: &str) {
    let first = &observations[0];
    assert_eq!(first.headers["idempotency-key"], key);
    for resend in &observations[1..] {
        assert_eq!(resend.method, first.method);
        assert_eq!(resend.uri, first.uri);
        assert_eq!(resend.headers, first.headers);
        assert_eq!(resend.body, first.body);
    }
}

#[tokio::test]
async fn a_timed_out_hold_is_resent_identically_under_the_same_key() {
    let (address, script, server) = serve(&[
        Answer::Stall,
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
    ])
    .await;
    let token = token();
    let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));

    let complete = client
        .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
        .await
        .expect("the resend settles the hold");
    assert_eq!(complete.value.hold_id, "hold-7");

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_identical_resends(&observations, "hold-7");
    server.abort();
}

#[tokio::test]
async fn every_keyed_command_resends_a_5xx_answer_and_returns_the_later_success() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, None),
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
        Answer::Problem(ProblemCode::EligibilityUnavailable, None),
        Answer::Json(StatusCode::CREATED, APPOINTMENT_DOCUMENT),
        Answer::Json(StatusCode::BAD_GATEWAY, r#"{"edge":true}"#),
        Answer::Json(StatusCode::OK, APPOINTMENT_DOCUMENT),
        Answer::Problem(ProblemCode::HookUnavailable, None),
        Answer::Json(StatusCode::OK, APPOINTMENT_DOCUMENT),
    ])
    .await;
    let token = token();
    let client = client(config(&address));
    let auth = || SchedulingAuth::new(&token);

    client
        .create_hold(auth(), "hold-7", &admission())
        .await
        .expect("hold");
    client
        .create_appointment(
            auth(),
            "create-1",
            &CreateAppointmentRequest {
                hold: Some("hold-7".to_owned()),
                admission: None,
            },
        )
        .await
        .expect("appointment");
    client
        .reschedule_appointment(
            auth(),
            "appt-1",
            "move-1",
            &RescheduleAppointmentRequest {
                observed_revision: 2,
                admission: admission(),
            },
        )
        .await
        .expect("rescheduled appointment");
    client
        .cancel_appointment(
            auth(),
            "appt-1",
            "cancel-1",
            &CancelAppointmentRequest {
                observed_revision: 2,
                reason: None,
            },
        )
        .await
        .expect("cancelled appointment");

    let observations = script.observations();
    assert_eq!(observations.len(), 8);
    for (pair, key) in observations
        .chunks(2)
        .zip(["hold-7", "create-1", "move-1", "cancel-1"])
    {
        assert_identical_resends(pair, key);
    }
    server.abort();
}

#[tokio::test]
async fn a_bounded_retry_after_is_honored_before_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, Some("1")),
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
    ])
    .await;
    let token = token();
    let started = Instant::now();
    client(config(&address))
        .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
        .await
        .expect("hold");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn a_retry_after_above_the_bound_ends_the_retries() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, Some("60")),
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(config(&address))
        .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
        .await
        .expect_err("the service asked for a longer wait than the client makes");
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

/// An HTTP-date, a fraction, or any other value outside delta-seconds names a
/// wait the client cannot honor, so it ends the resends like a long wait.
#[tokio::test]
async fn an_unusable_retry_after_ends_the_retries() {
    for unusable in ["Wed, 21 Oct 2026 07:28:00 GMT", "soon", "1.5"] {
        let (address, script, server) = serve(&[
            Answer::Problem(ProblemCode::ServiceUnavailable, Some(unusable)),
            Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
        ])
        .await;
        let token = token();
        let error = client(config(&address))
            .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
            .await
            .expect_err("the service asked for a wait the client cannot read");
        assert!(
            matches!(
                error,
                SchedulingClientError::Problem {
                    code: ProblemCode::ServiceUnavailable,
                    ..
                }
            ),
            "{unusable}"
        );
        assert!(error.is_outcome_unknown(), "{unusable}");
        assert_eq!(script.observations().len(), 1, "{unusable}");
        server.abort();
    }
}

#[tokio::test]
async fn a_deterministic_refusal_is_never_resent() {
    for code in [
        ProblemCode::AuthenticationRefused,
        ProblemCode::IdempotencyKeyReused,
        ProblemCode::IdempotencyExpired,
        ProblemCode::CapacityExhausted,
    ] {
        let (address, script, server) = serve(&[
            Answer::Problem(code, None),
            Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
        ])
        .await;
        let token = token();
        let error = client(config(&address))
            .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
            .await
            .expect_err("a refusal is returned");
        assert!(
            matches!(error, SchedulingClientError::Problem { code: answered, .. } if answered == code)
        );
        assert!(!error.is_outcome_unknown(), "{code:?}");
        assert_eq!(script.observations().len(), 1, "{code:?}");
        server.abort();
    }
}

#[tokio::test]
async fn the_retry_count_is_honored() {
    for (retries, expected_attempts) in [(None, 3), (Some(2), 3), (Some(1), 2)] {
        let (address, script, server) = serve(&[
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
        ])
        .await;
        let token = token();
        let mut config = config(&address);
        if let Some(retries) = retries {
            config = config.with_max_mutation_retries(retries);
        }
        let error = client(config)
            .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
            .await
            .expect_err("every attempt was unavailable");
        assert!(matches!(
            error,
            SchedulingClientError::Problem {
                status: 503,
                code: ProblemCode::ServiceUnavailable,
                ..
            }
        ));
        assert!(error.is_outcome_unknown());
        let observations = script.observations();
        assert_eq!(observations.len(), expected_attempts, "{retries:?}");
        assert_identical_resends(&observations, "hold-7");
        server.abort();
    }
}

#[tokio::test]
async fn zero_retries_disables_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Stall,
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(
        config(&address)
            .with_request_timeout(Duration::from_millis(500))
            .with_max_mutation_retries(0),
    )
    .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
    .await
    .expect_err("the only attempt timed out");
    assert!(matches!(
        error,
        SchedulingClientError::Transport {
            kind: TransportKind::Timeout
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_unkeyed_release_is_never_resent() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, None),
        Answer::Json(StatusCode::NO_CONTENT, ""),
    ])
    .await;
    let token = token();
    let error = client(config(&address))
        .release_hold(SchedulingAuth::new(&token), "hold-7")
        .await
        .expect_err("the release was unavailable");
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, None),
        Answer::Problem(ProblemCode::AuthenticationRefused, None),
        Answer::Json(StatusCode::CREATED, HOLD_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(config(&address))
        .create_hold(SchedulingAuth::new(&token), "hold-7", &admission())
        .await
        .expect_err("the resend was refused");
    assert!(matches!(
        error,
        SchedulingClientError::Problem {
            status: 503,
            code: ProblemCode::ServiceUnavailable,
            ..
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 2);
    server.abort();
}
