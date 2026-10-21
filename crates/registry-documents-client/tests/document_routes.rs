// SPDX-License-Identifier: Apache-2.0

//! Every Document Store route against a scripted stand-in: the request each
//! method sends, the refusals it makes before any request, the answer bounds
//! it holds, and the digest check a download must pass before any byte
//! reaches the caller.

mod support;

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::{Method, StatusCode};
use bytes::Bytes;
use registry_documents_client::{
    ActorKind, CustodianRef, Digest, DocumentLabel, DocumentStatus, DocumentsClientConfig,
    DocumentsClientError, DocumentsProtocolFailure, ExternalId, GrantState, GranteeRef,
    IssueGrantRequest, PageRequest, ProblemCode, ReservationView, ReserveDocumentRequest,
    TransportKind, UploadBody,
};
use support::*;

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
        label: Some(DocumentLabel::new("Birth certificate").expect("fixture label")),
    }
}

fn grant_request() -> IssueGrantRequest {
    IssueGrantRequest {
        version_id: VERSION_ID.to_owned(),
        grantee: GranteeRef {
            subject: ExternalId::new("clerk-0001").expect("fixture subject"),
            kind: ActorKind::Human,
        },
        expiry_hours: Some(24),
    }
}

fn reservation() -> ReservationView {
    serde_json::from_value(reservation_json()).expect("fixture reservation")
}

fn expected_digest() -> Digest {
    Digest::new(content_digest()).expect("fixture digest")
}

fn page_json(items: serde_json::Value, next: Option<&str>) -> String {
    let mut page = serde_json::json!({ "items": items });
    if let Some(cursor) = next {
        page["nextCursor"] = serde_json::Value::from(cursor);
    }
    page.to_string()
}

fn assert_bearer_json(captured: &Captured) {
    assert_eq!(captured.headers["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(captured.headers["accept"], "application/json");
}

#[tokio::test]
async fn reserve_posts_the_reservation_under_the_deployment_prefix_with_its_key() {
    let (url, script, server) = serve(vec![Answer::json(
        StatusCode::CREATED,
        reservation_json().to_string(),
    )])
    .await;
    let complete = client(config(&url))
        .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
        .await
        .expect("a reservation");
    assert_eq!(complete.trace_id, TRACE_ID);
    assert_eq!(complete.value.document.id, DOCUMENT_ID);
    assert_eq!(
        complete.value.document.version.status,
        DocumentStatus::AwaitingContent
    );

    let observations = script.observations();
    assert_eq!(observations.len(), 1);
    let sent = &observations[0];
    assert_eq!(sent.method, Method::POST);
    assert_eq!(sent.uri.path(), format!("{PREFIX}/documents"));
    assert_eq!(sent.uri.query(), None);
    assert_bearer_json(sent);
    assert_eq!(sent.headers["content-type"], "application/json");
    assert_eq!(sent.headers["idempotency-key"], IDEMPOTENCY_KEY);
    let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("a JSON body");
    assert_eq!(body["expectedDigest"], content_digest());
    assert_eq!(body["length"], CONTENT.len());
    assert_eq!(body["mediaType"], MEDIA_TYPE);
    assert_eq!(
        body,
        serde_json::to_value(reservation_request()).expect("the request as JSON")
    );
    server.abort();
}

#[tokio::test]
async fn a_malformed_idempotency_key_is_refused_before_any_request() {
    let (url, script, server) = serve(vec![]).await;
    let client = client(config(&url));
    let too_long = "k".repeat(129);
    for key in ["", "with space", "caf\u{e9}", too_long.as_str()] {
        let reserve = client
            .reserve_document(&token(), key, &reservation_request())
            .await
            .expect_err("the key is refused");
        assert!(
            matches!(reserve, DocumentsClientError::InvalidRequest { .. }),
            "{key:?}: {reserve:?}"
        );
        let grant = client
            .issue_grant(&token(), key, DOCUMENT_ID, &grant_request())
            .await
            .expect_err("the key is refused");
        assert!(
            matches!(grant, DocumentsClientError::InvalidRequest { .. }),
            "{key:?}: {grant:?}"
        );
    }
    let longest = "k".repeat(128);
    assert!(matches!(
        client
            .reserve_document(&token(), &longest, &reservation_request())
            .await,
        Err(DocumentsClientError::Protocol { status: 418, .. })
    ));
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_identifier_that_is_not_a_lowercase_uuid_is_refused_before_any_request() {
    let (url, script, server) = serve(vec![]).await;
    let client = client(config(&url));
    let upper = DOCUMENT_ID.to_ascii_uppercase();
    for id in ["", "../documents", "not-a-uuid", upper.as_str(), "6f1c2a51"] {
        let outcomes = [
            client.document(&token(), id).await.err(),
            client
                .document_grants(&token(), id, &PageRequest::default())
                .await
                .err(),
            client.revoke_grant(&token(), id).await.err(),
            client
                .issue_grant(&token(), IDEMPOTENCY_KEY, id, &grant_request())
                .await
                .err(),
            client
                .download_content(&token(), id, VERSION_ID, &expected_digest())
                .await
                .err(),
            client
                .download_content(&token(), DOCUMENT_ID, id, &expected_digest())
                .await
                .err(),
        ];
        for outcome in outcomes {
            assert!(
                matches!(outcome, Some(DocumentsClientError::InvalidRequest { .. })),
                "{id:?}: {outcome:?}"
            );
        }
    }
    assert!(script.observations().is_empty());
    server.abort();
}

#[tokio::test]
async fn list_documents_sends_the_cursor_as_given_and_reads_one_page() {
    let next = "opaque/cursor=+value";
    let (url, script, server) = serve(vec![
        Answer::json(
            StatusCode::OK,
            page_json(serde_json::json!([document_json()]), Some(next)),
        ),
        Answer::json(StatusCode::OK, page_json(serde_json::json!([]), None)),
    ])
    .await;
    let client = client(config(&url));
    let first = client
        .list_documents(&token(), &PageRequest::default())
        .await
        .expect("a first page");
    assert_eq!(first.value.items.len(), 1);
    assert_eq!(first.value.next_cursor.as_deref(), Some(next));
    // One page per call: the next cursor is the caller's to pass back.
    assert_eq!(script.observations().len(), 1);

    let second = client
        .list_documents(
            &token(),
            &PageRequest {
                cursor: first.value.next_cursor.clone(),
                limit: Some(10),
            },
        )
        .await
        .expect("a second page");
    assert!(second.value.items.is_empty());
    assert_eq!(second.value.next_cursor, None);

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    for sent in &observations {
        assert_eq!(sent.method, Method::GET);
        assert_eq!(sent.uri.path(), format!("{PREFIX}/documents"));
        assert_bearer_json(sent);
        assert!(sent.headers.get("idempotency-key").is_none());
    }
    assert_eq!(observations[0].uri.query(), None);
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(observations[1].uri.query().expect("a query").as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        pairs,
        vec![
            ("cursor".to_owned(), next.to_owned()),
            ("limit".to_owned(), "10".to_owned()),
        ]
    );
    server.abort();
}

#[tokio::test]
async fn a_page_limit_outside_the_contract_is_refused_before_any_request() {
    let (url, script, server) = serve(vec![]).await;
    let client = client(config(&url));
    for limit in [0, 101] {
        let page = PageRequest {
            cursor: None,
            limit: Some(limit),
        };
        for outcome in [
            client.list_documents(&token(), &page).await.err(),
            client.received_grants(&token(), &page).await.err(),
            client
                .document_grants(&token(), DOCUMENT_ID, &page)
                .await
                .err(),
        ] {
            assert!(
                matches!(outcome, Some(DocumentsClientError::InvalidRequest { .. })),
                "{limit}: {outcome:?}"
            );
        }
    }
    assert!(script.observations().is_empty());
    server.abort();
}

#[tokio::test]
async fn document_reads_one_document_by_its_identifier() {
    let (url, script, server) = serve(vec![Answer::json(
        StatusCode::OK,
        document_json().to_string(),
    )])
    .await;
    let complete = client(config(&url))
        .document(&token(), DOCUMENT_ID)
        .await
        .expect("a document");
    assert_eq!(complete.value.version.id, VERSION_ID);
    let sent = &script.observations()[0];
    assert_eq!(sent.method, Method::GET);
    assert_eq!(sent.uri.path(), format!("{PREFIX}/documents/{DOCUMENT_ID}"));
    assert_bearer_json(sent);
    server.abort();
}

#[tokio::test]
async fn a_typed_problem_on_a_document_route_is_its_code() {
    let (url, _script, server) =
        serve(vec![Answer::Problem(ProblemCode::ResourceNotFound, None)]).await;
    let error = client(config(&url))
        .document(&token(), DOCUMENT_ID)
        .await
        .expect_err("a refusal");
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 404,
                code: ProblemCode::ResourceNotFound,
                trace_id: Some(ref trace),
            } if trace == TRACE_ID
        ),
        "{error:?}"
    );
    assert!(!error.is_outcome_unknown());
    server.abort();
}

/// A body that yields its content in small chunks and reports no size, so
/// the client cannot buffer it into a known length before sending.
struct Chunked {
    remaining: Vec<Bytes>,
}

impl http_body::Body for Chunked {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if self.remaining.is_empty() {
            return Poll::Ready(None);
        }
        let chunk = self.remaining.remove(0);
        Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
    }
}

#[tokio::test]
async fn upload_streams_the_reserved_content_with_the_reserved_type_and_length() {
    let mut finalized = document_json();
    finalized["version"]["status"] = "pending".into();
    finalized["version"]["finalizedAt"] = "2026-10-22T08:01:00Z".into();
    let (url, script, server) =
        serve(vec![Answer::json(StatusCode::OK, finalized.to_string())]).await;
    let body = UploadBody::wrap(Chunked {
        remaining: CONTENT.chunks(5).map(Bytes::copy_from_slice).collect(),
    });
    let complete = client(config(&url))
        .upload_content(&token(), &reservation(), body)
        .await
        .expect("an uploaded version");
    assert_eq!(complete.value.version.status, DocumentStatus::Pending);

    let observations = script.observations();
    assert_eq!(observations.len(), 1);
    let sent = &observations[0];
    assert_eq!(sent.method, Method::PUT);
    assert_eq!(
        sent.uri.path(),
        format!("{PREFIX}/uploads/{UPLOAD_ID}/content")
    );
    assert_bearer_json(sent);
    assert_eq!(sent.headers["content-type"], MEDIA_TYPE);
    assert_eq!(sent.headers["content-length"], CONTENT.len().to_string());
    assert!(sent.headers.get("transfer-encoding").is_none());
    assert!(sent.headers.get("idempotency-key").is_none());
    assert_eq!(sent.body.as_ref(), CONTENT);
    server.abort();
}

#[tokio::test]
async fn an_upload_that_cannot_match_its_reservation_is_refused_before_any_request() {
    let (url, script, server) = serve(vec![]).await;
    let client = client(config(&url));

    let short = client
        .upload_content(&token(), &reservation(), UploadBody::from(&CONTENT[1..]))
        .await
        .expect_err("the in-memory length disagrees with the reservation");
    assert!(
        matches!(short, DocumentsClientError::InvalidRequest { .. }),
        "{short:?}"
    );

    for path in [
        "/uploads/not-a-uuid/content".to_owned(),
        format!("/uploads/{UPLOAD_ID}"),
        format!("/documents/{UPLOAD_ID}/content"),
        format!("https://elsewhere.example/uploads/{UPLOAD_ID}/content"),
    ] {
        let mut elsewhere = reservation();
        elsewhere.upload_path = path.clone();
        let error = client
            .upload_content(&token(), &elsewhere, UploadBody::from(CONTENT))
            .await
            .expect_err("the upload path names no upload");
        assert!(
            matches!(error, DocumentsClientError::InvalidRequest { .. }),
            "{path}: {error:?}"
        );
    }

    let mut unsendable = reservation();
    unsendable.document.version.media_type = "application/pdf\r\nx-injected: 1".to_owned();
    let error = client
        .upload_content(&token(), &unsendable, UploadBody::from(CONTENT))
        .await
        .expect_err("the media type is not a header value");
    assert!(
        matches!(error, DocumentsClientError::InvalidRequest { .. }),
        "{error:?}"
    );

    assert!(script.observations().is_empty());
    server.abort();
}

#[tokio::test]
async fn an_upload_the_service_refuses_is_its_typed_code() {
    let (url, _script, server) = serve(vec![Answer::Problem(
        ProblemCode::UploadDigestMismatch,
        None,
    )])
    .await;
    let error = client(config(&url))
        .upload_content(&token(), &reservation(), UploadBody::from(CONTENT))
        .await
        .expect_err("a refusal");
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 422,
                code: ProblemCode::UploadDigestMismatch,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn download_returns_content_only_after_its_digest_matches() {
    let (url, script, server) = serve(vec![Answer::content(CONTENT)]).await;
    let complete = client(config(&url))
        .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
        .await
        .expect("verified content");
    assert_eq!(complete.trace_id, TRACE_ID);
    assert_eq!(complete.value.media_type, MEDIA_TYPE);
    assert_eq!(complete.value.bytes, CONTENT);

    let sent = &script.observations()[0];
    assert_eq!(sent.method, Method::GET);
    assert_eq!(
        sent.uri.path(),
        format!("{PREFIX}/documents/{DOCUMENT_ID}/versions/{VERSION_ID}/content")
    );
    assert_eq!(sent.headers["authorization"], format!("Bearer {TOKEN}"));
    server.abort();
}

#[tokio::test]
async fn a_download_whose_digest_disagrees_hands_the_caller_nothing() {
    let mut tampered = CONTENT.to_vec();
    tampered[0] ^= 0x01;
    for answered in [tampered, CONTENT[..CONTENT.len() - 1].to_vec(), Vec::new()] {
        let (url, _script, server) = serve(vec![Answer::content(&answered)]).await;
        let error = client(config(&url))
            .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
            .await
            .expect_err("the content does not match the digest");
        assert!(
            matches!(
                error,
                DocumentsClientError::Protocol {
                    status: 200,
                    failure: DocumentsProtocolFailure::ContentDigest,
                    ..
                }
            ),
            "{error:?}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn a_download_over_the_configured_bound_is_refused() {
    let (url, _script, server) = serve(vec![Answer::content(CONTENT)]).await;
    let error = client(config(&url).with_max_download_bytes(8))
        .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
        .await
        .expect_err("the content exceeds the bound");
    assert!(
        matches!(
            error,
            DocumentsClientError::Transport {
                kind: TransportKind::ResponseTooLarge
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_download_refused_by_the_service_is_its_typed_code() {
    let (url, _script, server) = serve(vec![Answer::Problem(
        ProblemCode::DocumentVersionNotReleasable,
        None,
    )])
    .await;
    let error = client(config(&url))
        .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
        .await
        .expect_err("a refusal");
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 409,
                code: ProblemCode::DocumentVersionNotReleasable,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_download_refused_to_a_caller_who_sees_the_document_is_the_profile_refusal() {
    // The reserving system owns a document it holds for someone else and
    // may read it, but the runtime refuses it the content.
    let (url, script, server) = serve(vec![Answer::Problem(
        ProblemCode::ProfileNotAuthorized,
        None,
    )])
    .await;
    let error = client(config(&url))
        .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
        .await
        .expect_err("a refusal");
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 403,
                code: ProblemCode::ProfileNotAuthorized,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn issue_grant_posts_the_grant_with_its_key() {
    let (url, script, server) = serve(vec![Answer::json(
        StatusCode::CREATED,
        grant_json().to_string(),
    )])
    .await;
    let complete = client(config(&url))
        .issue_grant(&token(), IDEMPOTENCY_KEY, DOCUMENT_ID, &grant_request())
        .await
        .expect("a grant");
    assert_eq!(complete.value.id, GRANT_ID);
    assert_eq!(complete.value.state, GrantState::Active);

    let sent = &script.observations()[0];
    assert_eq!(sent.method, Method::POST);
    assert_eq!(
        sent.uri.path(),
        format!("{PREFIX}/documents/{DOCUMENT_ID}/grants")
    );
    assert_bearer_json(sent);
    assert_eq!(sent.headers["content-type"], "application/json");
    assert_eq!(sent.headers["idempotency-key"], IDEMPOTENCY_KEY);
    let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("a JSON body");
    assert_eq!(
        body["grantee"],
        serde_json::json!({ "subject": "clerk-0001", "kind": "human" })
    );
    assert_eq!(
        body,
        serde_json::to_value(grant_request()).expect("the request as JSON")
    );
    server.abort();
}

#[tokio::test]
async fn grant_lists_read_one_page_from_their_routes() {
    let page = page_json(serde_json::json!([grant_json()]), Some("next-grant-page"));
    let (url, script, server) = serve(vec![
        Answer::json(StatusCode::OK, page.clone()),
        Answer::json(StatusCode::OK, page),
    ])
    .await;
    let client = client(config(&url));
    let issued = client
        .document_grants(&token(), DOCUMENT_ID, &PageRequest::default())
        .await
        .expect("a document's grants");
    let received = client
        .received_grants(
            &token(),
            &PageRequest {
                cursor: None,
                limit: Some(100),
            },
        )
        .await
        .expect("the caller's grants");
    assert_eq!(issued.value.items[0].id, GRANT_ID);
    assert_eq!(
        received.value.next_cursor.as_deref(),
        Some("next-grant-page")
    );

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].uri.path(),
        format!("{PREFIX}/documents/{DOCUMENT_ID}/grants")
    );
    assert_eq!(observations[0].uri.query(), None);
    assert_eq!(
        observations[1].uri.path(),
        format!("{PREFIX}/document-grants")
    );
    assert_eq!(observations[1].uri.query(), Some("limit=100"));
    for sent in &observations {
        assert_eq!(sent.method, Method::GET);
        assert_bearer_json(sent);
    }
    server.abort();
}

#[tokio::test]
async fn revoke_grant_deletes_the_grant_without_a_key() {
    let mut revoked = grant_json();
    revoked["state"] = "revoked".into();
    revoked["revokedAt"] = "2026-10-22T08:10:00Z".into();
    let (url, script, server) =
        serve(vec![Answer::json(StatusCode::OK, revoked.to_string())]).await;
    let complete = client(config(&url))
        .revoke_grant(&token(), GRANT_ID)
        .await
        .expect("a revoked grant");
    assert_eq!(complete.value.state, GrantState::Revoked);

    let sent = &script.observations()[0];
    assert_eq!(sent.method, Method::DELETE);
    assert_eq!(
        sent.uri.path(),
        format!("{PREFIX}/document-grants/{GRANT_ID}")
    );
    assert_bearer_json(sent);
    assert!(sent.headers.get("idempotency-key").is_none());
    assert!(sent.body.is_empty());
    server.abort();
}

#[tokio::test]
async fn policies_reads_the_policy_list() {
    let (url, script, server) = serve(vec![Answer::json(
        StatusCode::OK,
        policies_json().to_string(),
    )])
    .await;
    let complete = client(config(&url))
        .policies(&token())
        .await
        .expect("the policies");
    assert_eq!(complete.value.items[0].id.as_str(), "birth-certificate");

    let sent = &script.observations()[0];
    assert_eq!(sent.method, Method::GET);
    assert_eq!(sent.uri.path(), format!("{PREFIX}/document-policies"));
    assert_eq!(sent.uri.query(), None);
    assert_bearer_json(sent);
    server.abort();
}

#[tokio::test]
async fn a_json_answer_that_is_not_exactly_json_is_a_protocol_failure() {
    let (url, _script, server) = serve(vec![Answer::Raw(
        StatusCode::OK,
        "application/json; charset=utf-8",
        policies_json().to_string().into_bytes(),
    )])
    .await;
    let error = client(config(&url))
        .policies(&token())
        .await
        .expect_err("the media type is not exact");
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::MediaType,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_json_answer_that_breaks_the_wire_shape_is_a_protocol_failure() {
    let mut extra = document_json();
    extra["unexpected"] = true.into();
    let (url, _script, server) = serve(vec![Answer::json(StatusCode::OK, extra.to_string())]).await;
    let error = client(config(&url))
        .document(&token(), DOCUMENT_ID)
        .await
        .expect_err("an unknown field is refused");
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                status: 200,
                failure: DocumentsProtocolFailure::Body,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_json_answer_over_the_response_bound_is_refused() {
    let (url, _script, server) = serve(vec![Answer::json(
        StatusCode::OK,
        policies_json().to_string(),
    )])
    .await;
    let error = client(config(&url).with_max_response_bytes(16))
        .policies(&token())
        .await
        .expect_err("the answer exceeds the bound");
    assert!(
        matches!(
            error,
            DocumentsClientError::Transport {
                kind: TransportKind::ResponseTooLarge
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn an_answer_without_a_trace_is_a_protocol_failure() {
    let (url, _script, server) = serve(vec![
        Answer::Untraced(
            StatusCode::OK,
            "application/json",
            policies_json().to_string().into_bytes(),
        ),
        Answer::Untraced(StatusCode::OK, MEDIA_TYPE, CONTENT.to_vec()),
    ])
    .await;
    let client = client(config(&url));
    for error in [
        client.policies(&token()).await.err(),
        client
            .download_content(&token(), DOCUMENT_ID, VERSION_ID, &expected_digest())
            .await
            .err(),
    ] {
        assert!(
            matches!(
                error,
                Some(DocumentsClientError::Protocol {
                    status: 200,
                    failure: DocumentsProtocolFailure::TraceContext,
                    ..
                })
            ),
            "{error:?}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn a_success_answer_with_the_wrong_status_is_a_protocol_failure() {
    let (url, script, server) = serve(vec![Answer::json(
        StatusCode::OK,
        reservation_json().to_string(),
    )])
    .await;
    let error = client(config(&url).with_max_mutation_retries(0))
        .reserve_document(&token(), IDEMPOTENCY_KEY, &reservation_request())
        .await
        .expect_err("a reservation answers 201");
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                status: 200,
                failure: DocumentsProtocolFailure::Status,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn a_redirect_is_never_followed() {
    let (url, script, server) = serve(vec![Answer::Headers(
        StatusCode::TEMPORARY_REDIRECT,
        vec![("location", "/elsewhere/document-policies")],
    )])
    .await;
    let error = client(config(&url))
        .policies(&token())
        .await
        .expect_err("a redirect is not an answer");
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                status: 307,
                failure: DocumentsProtocolFailure::Status,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(script.observations().len(), 1);
    server.abort();
}
