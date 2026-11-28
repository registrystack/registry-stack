//! Every refusal the service answers is counted in
//! `evidence_oid4vp_request_refusals_total{check}` and written as one
//! `request refused` line that carries the check and no caller value.
//!
//! The log subscriber is process-wide (see `certificate_expiry_log.rs` for
//! why a thread-scoped one is not reliable), so this binary holds one test.

mod common;

use std::{
    future::IntoFuture,
    sync::{Arc, Mutex},
};

use axum_test::{TestResponse, TestServer};
use common::{bearer, Harness, Options};
use registry_evidence_oid4vp::service::VerifierService;
use registry_platform_authcommon::FailedCheck;
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn count(service: &VerifierService, check: FailedCheck) -> u64 {
    service
        .metrics()
        .refusal_recorder()
        .counter()
        .get(&[check.as_str()])
        .expect("every check is declared")
}

fn total(service: &VerifierService) -> u64 {
    FailedCheck::ALL
        .iter()
        .map(|check| count(service, *check))
        .sum()
}

/// What a caller sent that must never reach a log line.
struct Canaries(Vec<String>);

/// Run one request and require that exactly its member moved by one, that
/// one new log line names it, and that no canary reached the log.
async fn expect(
    service: &VerifierService,
    logs: &LogBuffer,
    canaries: &Canaries,
    check: FailedCheck,
    status: u16,
    request: impl std::future::Future<Output = TestResponse>,
) {
    let (before, lines_before, total_before) = (
        count(service, check),
        logs.text()
            .matches(&format!("failed_check=\"{}\"", check.as_str()))
            .count()
            + logs
                .text()
                .matches(&format!("failed_check={}", check.as_str()))
                .count(),
        total(service),
    );
    let response = request.await;
    assert_eq!(response.status_code().as_u16(), status, "{check:?}");
    assert_eq!(count(service, check), before + 1, "{check:?}");
    assert_eq!(
        total(service),
        total_before + 1,
        "{check:?} moved another member"
    );
    let text = logs.text();
    let lines_after = text
        .matches(&format!("failed_check=\"{}\"", check.as_str()))
        .count()
        + text
            .matches(&format!("failed_check={}", check.as_str()))
            .count();
    assert_eq!(lines_after, lines_before + 1, "{check:?}\n{text}");
    for canary in &canaries.0 {
        assert!(
            !text.contains(canary.as_str()),
            "the log carries a caller value"
        );
    }
}

#[tokio::test]
async fn each_refusal_is_counted_and_logged_under_its_check() {
    let logs = LogBuffer::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish(),
    )
    .expect("this binary installs one log subscriber");

    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    // Nothing is counted before a refusal, and every member is declared.
    for check in FailedCheck::ALL {
        assert_eq!(count(&service, check), 0);
    }
    let issuer = harness.idp.issuer().to_string();
    let creator = harness.applicant_token("portal", "user-1");
    let other = harness.applicant_token("portal", "user-2");
    let unscoped = harness.token("portal", "user-1", "something:else");
    let reader = harness.evidence_token();
    let applicant_as_reader = harness.token("portal", "user-1", "oid4vp:read-result");
    let reader_wrong_scope = harness.token("evidence", "evidence-service", "something:else");
    let canaries = Canaries(vec![
        creator.clone(),
        other.clone(),
        unscoped.clone(),
        reader.clone(),
        "user-1".to_owned(),
        "user-2".to_owned(),
        "portal".to_owned(),
        "canary-token-7f3a".to_owned(),
    ]);
    let created: Value = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&creator))
        .json(&json!({"policy": "national-id"}))
        .await
        .json();
    let reference = created["reference"].as_str().unwrap().to_owned();

    let create = |authorization: Option<String>| {
        let mut request = server.post("/v1/sessions");
        if let Some(value) = authorization {
            request = request.add_header("authorization", value);
        }
        request.json(&json!({"policy": "national-id"}))
    };
    let status = |reference: String, authorization: Option<String>| {
        let mut request = server.get(&format!("/v1/sessions/{reference}"));
        if let Some(value) = authorization {
            request = request.add_header("authorization", value);
        }
        request
    };
    let read = |authorization: Option<String>, reference: String, subject: &str| {
        let mut request = server.post("/v1/presentations/read");
        if let Some(value) = authorization {
            request = request.add_header("authorization", value);
        }
        request.json(&json!({
            "reference": reference,
            "principal": {"issuer": issuer, "subject": subject},
        }))
    };

    let (s, l, c) = (&service, &logs, &canaries);
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMissing,
        401,
        create(None).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMissing,
        401,
        create(Some("Basic dXNlcjpwYXNz".to_owned())).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMalformed,
        401,
        create(Some("Bearer canary-token-7f3a".to_owned())).into_future(),
    )
    .await;
    // A credential the server cannot read as text was sent, so it is
    // malformed rather than missing.
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMalformed,
        401,
        server
            .post("/v1/sessions")
            .add_header(
                "authorization",
                axum::http::HeaderValue::from_bytes(b"Bearer \x80\x81 canary-token-7f3a")
                    .expect("a byte above 0x7F is a legal header value"),
            )
            .json(&json!({"policy": "national-id"}))
            .into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::Scope,
        401,
        create(Some(bearer(&unscoped))).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMissing,
        401,
        status(reference.clone(), None).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::Visibility,
        404,
        status("A".repeat(43), Some(bearer(&creator))).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::Visibility,
        404,
        status(reference.clone(), Some(bearer(&other))).into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMissing,
        401,
        read(None, reference.clone(), "user-1").into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMalformed,
        401,
        read(
            Some("Bearer canary-token-7f3a".to_owned()),
            reference.clone(),
            "user-1",
        )
        .into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::TokenClient,
        401,
        read(
            Some(bearer(&applicant_as_reader)),
            reference.clone(),
            "user-1",
        )
        .into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::Scope,
        401,
        read(
            Some(bearer(&reader_wrong_scope)),
            reference.clone(),
            "user-1",
        )
        .into_future(),
    )
    .await;
    expect(
        s,
        l,
        c,
        FailedCheck::Ownership,
        404,
        read(Some(bearer(&reader)), reference.clone(), "user-2").into_future(),
    )
    .await;

    expect(
        s,
        l,
        c,
        FailedCheck::CredentialMalformed,
        401,
        create(Some("Bearer  canary-token-7f3a".to_owned())).into_future(),
    )
    .await;

    // A read of a reference nobody holds is not recorded: the consult maps
    // only another principal's session.
    let before = total(&service);
    let absent = read(Some(bearer(&reader)), "B".repeat(43), "user-1").await;
    assert_eq!(absent.status_code().as_u16(), 404);
    assert_eq!(total(&service), before);

    // An issuer key set that cannot be reached answers 503 and is counted.
    let unreachable = Harness::new(&Options {
        applicant_jwks_uri: Some("http://127.0.0.1:1/jwks"),
        ..Options::default()
    })
    .await;
    let (down, down_service) = unreachable.server().await;
    let down_token = unreachable.applicant_token("portal", "user-1");
    expect(
        &down_service,
        &logs,
        &canaries,
        FailedCheck::KeySourceUnavailable,
        503,
        down.post("/v1/sessions")
            .add_header("authorization", bearer(&down_token))
            .json(&json!({"policy": "national-id"}))
            .into_future(),
    )
    .await;

    // Spent budgets, each in a deployment whose burst is one.
    let limited = Harness::new(&Options {
        session_creation_burst: 1,
        wallet_request_burst: 1,
        wallet_response_burst: 1,
        evidence_read_burst: 1,
        ..Options::default()
    })
    .await;
    let (server, service) = limited.server().await;
    let token = limited.applicant_token("portal", "user-1");
    let reader = limited.evidence_token();
    let issuer = limited.idp.issuer().to_string();
    let create = || {
        server
            .post("/v1/sessions")
            .add_header("authorization", bearer(&token))
            .json(&json!({"policy": "national-id"}))
    };
    let first = create().await;
    assert_eq!(first.status_code().as_u16(), 201);
    let (s, l) = (&service, &logs);
    expect(s, l, c, FailedCheck::RateLimit, 429, create().into_future()).await;
    server
        .get("/v1/requests/unknown")
        .await
        .assert_status_not_found();
    expect(
        s,
        l,
        c,
        FailedCheck::RateLimit,
        429,
        server.get("/v1/requests/unknown").into_future(),
    )
    .await;
    let read = || {
        server
            .post("/v1/presentations/read")
            .add_header("authorization", bearer(&reader))
            .json(&json!({
                "reference": "C".repeat(43),
                "principal": {"issuer": issuer, "subject": "user-1"},
            }))
    };
    read().await.assert_status_not_found();
    expect(s, l, c, FailedCheck::RateLimit, 429, read().into_future()).await;
    let form = |server: &TestServer| {
        server
            .post("/v1/responses/unknown")
            .content_type("application/x-www-form-urlencoded")
            .text("response=x")
    };
    form(&server).await.assert_status_bad_request();
    expect(
        s,
        l,
        c,
        FailedCheck::RateLimit,
        429,
        form(&server).into_future(),
    )
    .await;

    // A scope refusal names the claim and the scopes the configuration
    // declares for each gate, and none of the scopes the tokens held.
    let text = logs.text();
    assert!(text.contains("scope_claim=\"scope\""), "{text}");
    assert!(
        text.contains("required_scope=\"oid4vp:read-result\""),
        "{text}"
    );
    assert!(text.contains("required_scope=\"oid4vp:session\""), "{text}");
    assert!(!text.contains("something:else"), "{text}");
}
