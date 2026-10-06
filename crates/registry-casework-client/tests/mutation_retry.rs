//! The bounded same-key retry of idempotency-keyed mutations, against a mock
//! service that answers each request with the next scripted answer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::{TimeZone as _, Utc};
use registry_casework_client::{
    AbsenceInput, AssignmentRequest, BearerToken, CaseloadApplyRequest, CaseloadItemSelection,
    CaseloadMoveRequest, CaseworkAction, CaseworkAuth, CaseworkClient, CaseworkClientConfig,
    CaseworkClientError, CaseworkProblemCode, ClockRecomputeApplyRequest, HolidaySetDocument,
    HolidaySetRevisionInput, IssuerPrincipal, ReviewHistoryAudience, ReviewNoteRequest,
    ReviewTaskDecisionRequest, ReviewerDecisionKind, Uuid,
};
use registry_casework_core::CASEWORK_PROBLEM_TYPE_BASE;
use registry_platform_httputil::client::TransportKind;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

const ABSENCE_DOCUMENT: &str = concat!(
    r#"{"absenceId":"00000000-0000-0000-0000-000000000005","#,
    r#""person":{"issuer":"https://issuer.example","subject":"staff-1"},"#,
    r#""from":"2026-10-05T00:00:00Z","until":"2026-10-06T00:00:00Z","#,
    r#""cover":{"issuer":"https://issuer.example","subject":"staff-2"},"revision":3}"#
);

const HOLIDAY_DOCUMENT: &str = r#"{"holidaySet":"national","revision":2,"dates":["2026-12-25"]}"#;

const RECOMPUTE_DOCUMENT: &str =
    r#"{"previewId":"00000000-0000-0000-0000-000000000009","appliedOccurrences":[]}"#;

#[derive(Clone)]
struct Captured {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

/// An exact Casework problem the fixture answers with.
#[derive(Clone, Copy)]
struct Problem {
    code: &'static str,
    status: u16,
    title: &'static str,
    detail: &'static str,
}

const SERVICE_UNAVAILABLE: Problem = Problem {
    code: "service.unavailable",
    status: 503,
    title: "Casework service unavailable",
    detail: "Casework storage is unavailable. Try again after the service recovers.",
};

const RUNTIME_FAILURE: Problem = Problem {
    code: "runtime.failure",
    status: 500,
    title: "Casework runtime failure",
    detail: "Casework could not complete the request.",
};

const AUTHENTICATION_REFUSED: Problem = Problem {
    code: "authentication.refused",
    status: 401,
    title: "Authentication refused",
    detail: "The bearer credential is missing, invalid, or expired. Sign in again.",
};

const IDEMPOTENCY_EXPIRED: Problem = Problem {
    code: "idempotency.expired",
    status: 410,
    title: "Idempotency window expired",
    detail: "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key.",
};

const IDEMPOTENCY_KEY_REUSED: Problem = Problem {
    code: "idempotency.key-reused",
    status: 409,
    title: "Idempotency key reused",
    detail: "This idempotency key was used for a different request.",
};

const PRECONDITION_FAILED: Problem = Problem {
    code: "precondition.failed",
    status: 412,
    title: "Precondition failed",
    detail: "The item or directory changed since you loaded it. Reload and try again.",
};

#[derive(Clone, Copy)]
enum Answer {
    /// Holds the request past the client's timeout, so the client cannot
    /// know whether it took effect.
    Stall,
    /// An exact product problem, with an optional `Retry-After` field.
    Problem(Problem, Option<&'static str>),
    /// A JSON answer with the given status.
    Json(StatusCode, &'static str),
    /// A traced answer without a body.
    Empty(StatusCode),
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
        Some(Answer::Problem(problem, retry_after)) => {
            let document = serde_json::json!({
                "type": format!(
                    "{CASEWORK_PROBLEM_TYPE_BASE}{}",
                    problem.code.replace('.', "/")
                ),
                "title": problem.title,
                "status": problem.status,
                "detail": problem.detail,
                "code": problem.code,
                "traceId": TRACE_ID,
            })
            .to_string();
            let mut headers = traced();
            headers.insert(
                "content-type",
                HeaderValue::from_static("application/problem+json"),
            );
            if let Some(seconds) = retry_after {
                headers.insert("retry-after", HeaderValue::from_static(seconds));
            }
            let status = StatusCode::from_u16(problem.status).expect("problem status");
            (status, headers, document).into_response()
        }
        Some(Answer::Json(status, body)) => {
            let mut headers = traced();
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            (status, headers, body.to_owned()).into_response()
        }
        Some(Answer::Empty(status)) => (status, traced()).into_response(),
        None => StatusCode::IM_A_TEAPOT.into_response(),
    }
}

fn traced() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    headers
}

/// Serve every route from one script, in request order.
async fn serve(answers: &[Answer]) -> (String, Script, tokio::task::JoinHandle<()>) {
    let script = Script {
        observations: Arc::new(Mutex::new(Vec::new())),
        answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
    };
    let app = Router::new().fallback(answer).with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    (address, script, server)
}

fn config(address: &str) -> CaseworkClientConfig {
    CaseworkClientConfig::new(Url::parse(&format!("http://{address}/")).expect("fixture URL"))
}

fn client(config: CaseworkClientConfig) -> CaseworkClient {
    CaseworkClient::new(config).expect("client")
}

fn token() -> BearerToken {
    BearerToken::new("fixture-secret").expect("fixture token")
}

fn principal(subject: &str) -> IssuerPrincipal {
    IssuerPrincipal {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
    }
}

fn absence() -> AbsenceInput {
    AbsenceInput {
        person: principal("staff-1"),
        from: Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap(),
        until: Utc.with_ymd_and_hms(2026, 10, 6, 0, 0, 0).unwrap(),
        cover: principal("staff-2"),
    }
}

fn item() -> Uuid {
    Uuid::from_u128(7)
}

fn claim_action() -> CaseworkAction {
    CaseworkAction {
        operation: "claim".to_owned(),
        href: format!("/v1/work-items/{}/claim", item()),
        if_match: "\"7\"".to_owned(),
    }
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

fn assert_unavailable(error: &CaseworkClientError) {
    assert!(
        matches!(
            error,
            CaseworkClientError::Problem {
                status: 503,
                code: CaseworkProblemCode::ServiceUnavailable,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(error.is_outcome_unknown(), "{error:?}");
}

#[tokio::test]
async fn a_timed_out_absence_is_resent_identically_under_the_same_key() {
    let (address, script, server) = serve(&[
        Answer::Stall,
        Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
    ])
    .await;
    let token = token();
    let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));

    let complete = client
        .create_absence(
            CaseworkAuth::new(&token, "staff"),
            2,
            "absence-1",
            &absence(),
        )
        .await
        .expect("the resend settles the absence");
    assert_eq!(complete.value.revision, 3);

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_identical_resends(&observations, "absence-1");
    server.abort();
}

/// Each keyed send path resends a 5xx answer under the same key. A path whose
/// answer this fixture cannot satisfy ends in a refusal, which keeps the
/// earlier unknown outcome, so the identical resend is still observed.
#[tokio::test]
async fn every_keyed_mutation_resends_a_5xx_answer_under_the_same_key() {
    let unavailable = Answer::Problem(SERVICE_UNAVAILABLE, None);
    let refused = Answer::Problem(PRECONDITION_FAILED, None);
    let (address, script, server) = serve(&[
        unavailable,
        refused,
        unavailable,
        Answer::Json(StatusCode::OK, ABSENCE_DOCUMENT),
        unavailable,
        refused,
        Answer::Problem(RUNTIME_FAILURE, None),
        refused,
        unavailable,
        Answer::Empty(StatusCode::NO_CONTENT),
        unavailable,
        Answer::Empty(StatusCode::NO_CONTENT),
        unavailable,
        refused,
        unavailable,
        Answer::Empty(StatusCode::NO_CONTENT),
        unavailable,
        Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
        unavailable,
        Answer::Empty(StatusCode::NO_CONTENT),
        unavailable,
        Answer::Json(StatusCode::OK, "[]"),
        unavailable,
        Answer::Json(StatusCode::CREATED, HOLIDAY_DOCUMENT),
        unavailable,
        Answer::Json(StatusCode::OK, RECOMPUTE_DOCUMENT),
    ])
    .await;
    let token = token();
    let client = client(config(&address));
    let staff = || CaseworkAuth::new(&token, "staff");
    let source = || CaseworkAuth::new(&token, "staff").with_source_profile("reviewer");
    let task = Uuid::from_u128(11);

    let assigned = client
        .assign_work_item(
            staff(),
            item(),
            7,
            "assign-1",
            &AssignmentRequest {
                assignee: principal("staff-2"),
                reason: None,
            },
        )
        .await
        .expect_err("the resend was refused");
    assert_unavailable(&assigned);
    client
        .update_absence(staff(), Uuid::from_u128(5), 2, "absence-2", &absence())
        .await
        .expect("updated absence");
    let claimed = client
        .claim_work_item(source(), &claim_action(), "claim-1")
        .await
        .expect_err("the resend was refused");
    assert_unavailable(&claimed);
    let claimed_task = client
        .claim_review_task(staff(), task, 4, "task-claim-1")
        .await
        .expect_err("the resend was refused");
    assert!(
        matches!(
            claimed_task,
            CaseworkClientError::Problem {
                status: 500,
                code: CaseworkProblemCode::RuntimeFailure,
                ..
            }
        ),
        "{claimed_task:?}"
    );
    client
        .delete_review_task_draft(staff(), task, 4, "task-draft-1")
        .await
        .expect("deleted review task draft");
    client
        .decide_review_task(
            staff(),
            task,
            4,
            "task-decide-1",
            &ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Approve,
            },
        )
        .await
        .expect("decided review task");
    let noted = client
        .add_review_note(
            staff(),
            Uuid::from_u128(12),
            "note-1",
            &ReviewNoteRequest {
                audience: ReviewHistoryAudience::Reviewers,
                note: "Review note".to_owned(),
            },
        )
        .await
        .expect_err("the resend was refused");
    assert_unavailable(&noted);
    client
        .delete_draft(source(), item(), 7, "draft-1")
        .await
        .expect("deleted draft");
    client
        .create_absence(staff(), 2, "absence-1", &absence())
        .await
        .expect("created absence");
    client
        .delete_absence(staff(), Uuid::from_u128(5), 3, "absence-3")
        .await
        .expect("deleted absence");
    client
        .apply_caseload_move(
            staff(),
            "caseload-1",
            &CaseloadApplyRequest {
                movement: CaseloadMoveRequest {
                    from: principal("staff-1"),
                    to: principal("staff-2"),
                    queue_id: None,
                    reason: "Leave".to_owned(),
                },
                items: vec![CaseloadItemSelection {
                    item_id: item(),
                    expected_revision: 7,
                }],
            },
        )
        .await
        .expect("applied caseload move");
    client
        .create_holiday_revision(
            staff(),
            "holiday-1",
            &HolidaySetRevisionInput {
                document: HolidaySetDocument {
                    holiday_set: "national".to_owned(),
                    revision: 2,
                    dates: vec!["2026-12-25".to_owned()],
                },
            },
        )
        .await
        .expect("created holiday revision");
    client
        .apply_clock_recompute(
            staff(),
            "recompute-1",
            &ClockRecomputeApplyRequest {
                preview_id: Uuid::from_u128(9),
            },
        )
        .await
        .expect("applied clock recompute");

    let observations = script.observations();
    assert_eq!(observations.len(), 26);
    for (pair, key) in observations.chunks(2).zip([
        "assign-1",
        "absence-2",
        "claim-1",
        "task-claim-1",
        "task-draft-1",
        "task-decide-1",
        "note-1",
        "draft-1",
        "absence-1",
        "absence-3",
        "caseload-1",
        "holiday-1",
        "recompute-1",
    ]) {
        assert_eq!(pair.len(), 2, "{key}");
        assert_identical_resends(pair, key);
    }
    server.abort();
}

#[tokio::test]
async fn a_bounded_retry_after_is_honored_before_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Problem(SERVICE_UNAVAILABLE, Some("1")),
        Answer::Empty(StatusCode::NO_CONTENT),
    ])
    .await;
    let token = token();
    let started = Instant::now();
    client(config(&address))
        .delete_absence(
            CaseworkAuth::new(&token, "staff"),
            Uuid::from_u128(5),
            3,
            "absence-3",
        )
        .await
        .expect("deleted absence");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn a_retry_after_above_the_bound_ends_the_retries() {
    let (address, script, server) = serve(&[
        Answer::Problem(SERVICE_UNAVAILABLE, Some("60")),
        Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(config(&address))
        .create_absence(
            CaseworkAuth::new(&token, "staff"),
            2,
            "absence-1",
            &absence(),
        )
        .await
        .expect_err("the service asked for a longer wait than the client makes");
    assert_unavailable(&error);
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

/// An HTTP-date, a fraction, or any other value outside delta-seconds names a
/// wait the client cannot honor, so it ends the resends like a long wait.
#[tokio::test]
async fn an_unusable_retry_after_ends_the_retries() {
    for unusable in ["Wed, 21 Oct 2026 07:28:00 GMT", "soon", "1.5"] {
        let (address, script, server) = serve(&[
            Answer::Problem(SERVICE_UNAVAILABLE, Some(unusable)),
            Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
        ])
        .await;
        let token = token();
        let error = client(config(&address))
            .create_absence(
                CaseworkAuth::new(&token, "staff"),
                2,
                "absence-1",
                &absence(),
            )
            .await
            .expect_err("the service asked for a wait the client cannot read");
        assert_unavailable(&error);
        assert_eq!(script.observations().len(), 1, "{unusable}");
        server.abort();
    }
}

#[tokio::test]
async fn a_deterministic_refusal_is_never_resent() {
    for (problem, code) in [
        (
            AUTHENTICATION_REFUSED,
            CaseworkProblemCode::AuthenticationRefused,
        ),
        (
            IDEMPOTENCY_KEY_REUSED,
            CaseworkProblemCode::IdempotencyKeyReused,
        ),
        (IDEMPOTENCY_EXPIRED, CaseworkProblemCode::IdempotencyExpired),
        (PRECONDITION_FAILED, CaseworkProblemCode::PreconditionFailed),
    ] {
        let (address, script, server) = serve(&[
            Answer::Problem(problem, None),
            Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
        ])
        .await;
        let token = token();
        let error = client(config(&address))
            .create_absence(
                CaseworkAuth::new(&token, "staff"),
                2,
                "absence-1",
                &absence(),
            )
            .await
            .expect_err("a refusal is returned");
        assert!(
            matches!(&error, CaseworkClientError::Problem { code: answered, .. } if *answered == code),
            "{error:?}"
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
            Answer::Problem(SERVICE_UNAVAILABLE, None),
            Answer::Problem(SERVICE_UNAVAILABLE, None),
            Answer::Problem(SERVICE_UNAVAILABLE, None),
            Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
        ])
        .await;
        let token = token();
        let mut config = config(&address);
        if let Some(retries) = retries {
            config = config.with_max_mutation_retries(retries);
        }
        let error = client(config)
            .create_absence(
                CaseworkAuth::new(&token, "staff"),
                2,
                "absence-1",
                &absence(),
            )
            .await
            .expect_err("every attempt was unavailable");
        assert_unavailable(&error);
        let observations = script.observations();
        assert_eq!(observations.len(), expected_attempts, "{retries:?}");
        assert_identical_resends(&observations, "absence-1");
        server.abort();
    }
}

#[tokio::test]
async fn zero_retries_disables_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Stall,
        Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(
        config(&address)
            .with_request_timeout(Duration::from_millis(500))
            .with_max_mutation_retries(0),
    )
    .create_absence(
        CaseworkAuth::new(&token, "staff"),
        2,
        "absence-1",
        &absence(),
    )
    .await
    .expect_err("the only attempt timed out");
    assert!(matches!(
        error,
        CaseworkClientError::Transport {
            kind: TransportKind::Timeout
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_unkeyed_operation_is_never_resent() {
    let (address, script, server) = serve(&[
        Answer::Problem(SERVICE_UNAVAILABLE, None),
        Answer::Json(StatusCode::OK, RECOMPUTE_DOCUMENT),
    ])
    .await;
    let token = token();
    let Err(error) = client(config(&address))
        .revoke_task_grant(
            CaseworkAuth::new(&token, "staff").with_source_profile("reviewer"),
            item(),
            Uuid::from_u128(13),
        )
        .await
    else {
        panic!("the revocation was unavailable");
    };
    assert_unavailable(&error);
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
    let (address, script, server) = serve(&[
        Answer::Problem(SERVICE_UNAVAILABLE, None),
        Answer::Problem(AUTHENTICATION_REFUSED, None),
        Answer::Json(StatusCode::CREATED, ABSENCE_DOCUMENT),
    ])
    .await;
    let token = token();
    let error = client(config(&address))
        .create_absence(
            CaseworkAuth::new(&token, "staff"),
            2,
            "absence-1",
            &absence(),
        )
        .await
        .expect_err("the resend was refused");
    assert_unavailable(&error);
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

/// How a raw 409 answer ends after its status line, its headers, and the
/// first bytes of its declared body.
#[derive(Clone, Copy, Debug)]
enum Unfinished {
    /// The server holds the connection open, so the client's timeout
    /// elapses while it reads the body.
    Stall,
    /// The server closes the connection, so the body ends early.
    Close,
}

/// Serve a 409 problem answer whose body never arrives in full, counting
/// the requests it answers.
async fn serve_unfinished_conflict(
    ending: Unfinished,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let requests = Arc::new(AtomicUsize::new(0));
    let answered = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_request(&mut stream).await;
            answered.fetch_add(1, Ordering::SeqCst);
            let head = format!(
                "HTTP/1.1 409 Conflict\r\ncontent-type: application/problem+json\r\n\
                 traceparent: {TRACEPARENT}\r\ncache-control: no-store\r\n\
                 content-length: 400\r\n\r\n{{\"type\":"
            );
            stream.write_all(head.as_bytes()).await.expect("answer");
            match ending {
                Unfinished::Stall => held.push(stream),
                Unfinished::Close => drop(stream),
            }
        }
    });
    (address, requests, server)
}

/// Read one request's head and its declared body.
async fn read_request(stream: &mut tokio::net::TcpStream) {
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "the request ended early");
        received.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
    let body_length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("content length"));
    while received.len() < head_end + body_length {
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "the request body ended early");
        received.extend_from_slice(&chunk[..read]);
    }
}

/// Once the status line says 4xx, the service has answered, so the request
/// is never resent. A body that then fails to arrive leaves the refusal
/// unread, so the outcome is reported as unknown, like an unparseable 4xx.
#[tokio::test]
async fn an_unreadable_4xx_answer_is_unknown_but_never_resent() {
    for (ending, expected) in [
        (Unfinished::Stall, TransportKind::Timeout),
        (Unfinished::Close, TransportKind::Exchange),
    ] {
        let (address, requests, server) = serve_unfinished_conflict(ending).await;
        let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));
        let token = token();
        let error = client
            .create_absence(
                CaseworkAuth::new(&token, "staff"),
                2,
                "absence-1",
                &absence(),
            )
            .await
            .expect_err("the refusal body never arrives");
        assert!(
            matches!(error, CaseworkClientError::Transport { kind } if kind == expected),
            "{ending:?}: {error:?}"
        );
        assert!(error.is_outcome_unknown(), "{ending:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{ending:?}");
        server.abort();
    }
}
