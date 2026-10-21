// SPDX-License-Identifier: Apache-2.0

//! The bounded same-key resend of the two idempotency-keyed mutations,
//! reserving a document and issuing a grant, and the routes that are never
//! resent, against a stand-in that answers each request with the next
//! scripted answer.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use registry_documents_client::{
    ActorKind, CustodianRef, Digest, DocumentsClientConfig, DocumentsClientError, ExternalId,
    GranteeRef, IssueGrantRequest, ProblemCode, ReservationView, ReserveDocumentRequest,
    TransportKind, UploadBody,
};
use support::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn config(url: &url::Url) -> DocumentsClientConfig {
    DocumentsClientConfig::new(url.clone())
}

fn reservation_request() -> ReserveDocumentRequest {
    ReserveDocumentRequest {
        policy_id: "birth-certificate".to_owned(),
        custodian: CustodianRef {
            subject: ExternalId::new("citizen-0001").expect("fixture subject"),
        },
        expected_digest: Digest::new(content_digest()).expect("fixture digest"),
        length: CONTENT.len() as u64,
        media_type: MEDIA_TYPE.to_owned(),
        issuing_institution: None,
        label: None,
    }
}

fn grant_request() -> IssueGrantRequest {
    IssueGrantRequest {
        version_id: VERSION_ID.to_owned(),
        grantee: GranteeRef {
            subject: ExternalId::new("clerk-0001").expect("fixture subject"),
            kind: ActorKind::Human,
        },
        expiry_hours: None,
    }
}

fn unavailable() -> Answer {
    Answer::Problem(ProblemCode::ServiceUnavailable, None)
}

fn assert_identical_resends(observations: &[Captured]) {
    let first = &observations[0];
    assert_eq!(first.headers["idempotency-key"], IDEMPOTENCY_KEY);
    for resend in &observations[1..] {
        assert_eq!(resend.method, first.method);
        assert_eq!(resend.uri, first.uri);
        assert_eq!(resend.headers, first.headers);
        assert_eq!(resend.body, first.body);
    }
}

#[tokio::test]
async fn a_timed_out_reservation_is_resent_identically_under_the_same_key() {
    let (url, script, server) = serve(vec![
        Answer::Stall,
        Answer::json(StatusCode::CREATED, reservation_json().to_string()),
    ])
    .await;
    let reserved = client(config(&url).with_request_timeout(Duration::from_millis(500)))
        .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
        .await
        .expect("the resend settles the reservation");
    assert_eq!(reserved.value.document.id, DOCUMENT_ID);
    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_identical_resends(&observations);
    server.abort();
}

#[tokio::test]
async fn a_5xx_answer_to_a_grant_is_resent_and_the_later_grant_returned() {
    let (url, script, server) = serve(vec![
        unavailable(),
        Answer::Raw(
            StatusCode::BAD_GATEWAY,
            "text/html",
            b"<p>gateway</p>".to_vec(),
        ),
        Answer::json(StatusCode::CREATED, grant_json().to_string()),
    ])
    .await;
    let issued = client(config(&url))
        .issue_grant(&token(), IDEMPOTENCY_KEY, DOCUMENT_ID, &grant_request())
        .await
        .expect("the resend settles the grant");
    assert_eq!(issued.value.id, GRANT_ID);
    let observations = script.observations();
    assert_eq!(observations.len(), 3);
    assert_identical_resends(&observations);
    server.abort();
}

#[tokio::test]
async fn a_deterministic_refusal_is_never_resent() {
    for refusal in [
        ProblemCode::IdempotencyKeyReused,
        ProblemCode::DocumentPolicyUnknown,
        ProblemCode::ProfileNotAuthorized,
        ProblemCode::AuthenticationRefused,
    ] {
        let (url, script, server) = serve(vec![Answer::Problem(refusal, None)]).await;
        let error = client(config(&url))
            .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
            .await
            .expect_err("the reservation is refused");
        assert!(
            matches!(error, DocumentsClientError::Problem { code, .. } if code == refusal),
            "{refusal:?}: {error:?}"
        );
        assert!(!error.is_outcome_unknown(), "{refusal:?}");
        assert_eq!(script.observations().len(), 1, "{refusal:?}");
        server.abort();
    }
}

#[tokio::test]
async fn the_retry_count_is_honored() {
    for (retries, expected) in [(None, 3), (Some(2), 3), (Some(1), 2), (Some(0), 1)] {
        let (url, script, server) = serve(vec![
            unavailable(),
            unavailable(),
            unavailable(),
            unavailable(),
        ])
        .await;
        let config = match retries {
            Some(value) => config(&url).with_max_mutation_retries(value),
            None => config(&url),
        };
        let error = client(config)
            .issue_grant(&token(), IDEMPOTENCY_KEY, DOCUMENT_ID, &grant_request())
            .await
            .expect_err("the service stays unavailable");
        assert!(
            matches!(
                error,
                DocumentsClientError::Problem {
                    status: 503,
                    code: ProblemCode::ServiceUnavailable,
                    ..
                }
            ),
            "{retries:?}: {error:?}"
        );
        assert!(error.is_outcome_unknown());
        let observations = script.observations();
        assert_eq!(observations.len(), expected, "{retries:?}");
        assert_identical_resends(&observations);
        server.abort();
    }
}

#[tokio::test]
async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
    let (url, script, server) = serve(vec![
        unavailable(),
        Answer::Problem(ProblemCode::ProfileNotAuthorized, None),
    ])
    .await;
    let error = client(config(&url))
        .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
        .await
        .expect_err("the resend was refused");
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 503,
                code: ProblemCode::ServiceUnavailable,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn unkeyed_mutations_are_never_resent() {
    let (url, script, server) = serve(vec![unavailable(), unavailable()]).await;
    let client = client(config(&url));
    let reservation: ReservationView =
        serde_json::from_value(reservation_json()).expect("fixture reservation");

    let upload = client
        .upload_content(&token(), &reservation, UploadBody::from(CONTENT))
        .await
        .expect_err("the upload was unavailable");
    assert!(upload.is_outcome_unknown(), "{upload:?}");
    assert_eq!(script.observations().len(), 1);

    let revoke = client
        .revoke_grant(&token(), GRANT_ID)
        .await
        .expect_err("the revocation was unavailable");
    assert!(revoke.is_outcome_unknown(), "{revoke:?}");
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn reads_are_never_resent() {
    let (url, script, server) = serve(vec![unavailable(), unavailable()]).await;
    let client = client(config(&url));
    let digest = Digest::new(content_digest()).expect("fixture digest");
    assert!(client.policies(&token()).await.is_err());
    assert!(client
        .download_content(&token(), DOCUMENT_ID, VERSION_ID, &digest)
        .await
        .is_err());
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
) -> (url::Url, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
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
    let url = url::Url::parse(&format!("http://{address}{PREFIX}/")).expect("fixture URL");
    (url, requests, server)
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
/// unread, so the outcome is reported as unknown.
#[tokio::test]
async fn an_unreadable_4xx_answer_is_unknown_but_never_resent() {
    for (ending, expected) in [
        (Unfinished::Stall, TransportKind::Timeout),
        (Unfinished::Close, TransportKind::Exchange),
    ] {
        let (url, requests, server) = serve_unfinished_conflict(ending).await;
        let error = client(config(&url).with_request_timeout(Duration::from_millis(500)))
            .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
            .await
            .expect_err("the refusal body never arrives");
        assert!(
            matches!(error, DocumentsClientError::Transport { kind } if kind == expected),
            "{ending:?}: {error:?}"
        );
        assert!(error.is_outcome_unknown(), "{ending:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{ending:?}");
        server.abort();
    }
}
