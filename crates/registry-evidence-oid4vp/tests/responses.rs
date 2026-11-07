//! The wallet response endpoint and the Evidence read endpoint, through the
//! router with a simulated wallet that encrypts with the platform's test JWE
//! encrypter.

mod common;

use std::sync::{atomic::Ordering, Arc};

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use common::{bearer, Harness, Options, HOST, READ_SCOPE};
use registry_evidence_oid4vp::{
    response::Submission,
    service::{build_app, VerifierService},
    session::{Clock, Prior},
};
use registry_platform_crypto::jwe::{encrypt_compact_ecdh_es_for_tests, JweEnc};
use registry_platform_testing::assert_json_absent_strings;
use serde_json::{json, Map, Value};

const PID_VALUE: &str = "Maria-Santos-PID-claim-value";

struct Exchange {
    reference: String,
    request_id: String,
    nonce: String,
    state: String,
    key: Map<String, Value>,
}

async fn start(
    harness: &Harness,
    server: &TestServer,
    service: &VerifierService,
    policy: &str,
    subject: &str,
) -> Exchange {
    let token = harness.applicant_token("portal", subject);
    let created: Value = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&token))
        .json(&json!({ "policy": policy }))
        .await
        .json();
    let reference = created["reference"].as_str().unwrap().to_owned();
    let request_id = created["requestUri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    // The wallet reads the secrets from the signed request object; the test
    // reads them from the session it created.
    let (nonce, state, key) = service
        .store()
        .with_by_reference(&reference, |session| {
            (
                session.nonce.clone(),
                session.state.clone(),
                session.encryption_key.public_jwk(),
            )
        })
        .expect("the session is live");
    Exchange {
        reference,
        request_id,
        nonce,
        state,
        key,
    }
}

/// The wallet's `vp_token` for the `national-id` policy.
fn national_id_payload(exchange: &Exchange) -> Value {
    json!({
        "vp_token": {"national_id": [format!("eyJhbGciOiJFUzI1NiJ9.{PID_VALUE}~eyJraWQiOiIxIn0")]},
        "state": exchange.state,
    })
}

fn seal(exchange: &Exchange, payload: &Value, enc: JweEnc, kid: Option<&str>) -> String {
    encrypt_compact_ecdh_es_for_tests(
        payload.to_string().as_bytes(),
        &exchange.key,
        enc,
        b"",
        b"",
        kid,
    )
    .expect("the simulated wallet encrypts")
}

/// Seal `plaintext` exactly as written, so a test can send JSON that no
/// `Value` could hold, such as a repeated member.
fn seal_raw(exchange: &Exchange, plaintext: &str) -> String {
    let kid = exchange.key["kid"].as_str().unwrap().to_owned();
    encrypt_compact_ecdh_es_for_tests(
        plaintext.as_bytes(),
        &exchange.key,
        JweEnc::A128Gcm,
        b"",
        b"",
        Some(&kid),
    )
    .expect("the simulated wallet encrypts")
}

fn seal_to_session(exchange: &Exchange, payload: &Value) -> String {
    let kid = exchange.key["kid"].as_str().unwrap().to_owned();
    seal(exchange, payload, JweEnc::A128Gcm, Some(&kid))
}

async fn post_response(server: &TestServer, request_id: &str, jwe: &str) -> TestResponse {
    server
        .post(&format!("/v1/responses/{request_id}"))
        .content_type("application/x-www-form-urlencoded")
        .bytes(format!("response={jwe}").into())
        .await
}

fn assert_refused(response: &TestResponse) {
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<Value>(),
        json!({"error": "invalid_request"})
    );
}

async fn read(
    server: &TestServer,
    token: &str,
    reference: &str,
    issuer: &str,
    subject: &str,
) -> TestResponse {
    server
        .post("/v1/presentations/read")
        .add_header("authorization", bearer(token))
        .json(&json!({
            "reference": reference,
            "principal": {"issuer": issuer, "subject": subject},
        }))
        .await
}

#[tokio::test]
async fn a_valid_response_is_accepted_for_each_policy_encryption() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    for enc in [JweEnc::A128Gcm, JweEnc::A256Gcm] {
        let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
        let kid = exchange.key["kid"].as_str().unwrap().to_owned();
        let jwe = seal(&exchange, &national_id_payload(&exchange), enc, Some(&kid));
        let accepted = post_response(&server, &exchange.request_id, &jwe).await;
        accepted.assert_status_ok();
        assert_eq!(accepted.header("content-type"), "application/json");
        assert_eq!(accepted.header("cache-control"), "no-store");
        assert_eq!(accepted.json::<Value>(), json!({}));
    }
}

#[tokio::test]
async fn only_the_evidence_service_credential_reads() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let jwe = seal_to_session(&exchange, &national_id_payload(&exchange));
    post_response(&server, &exchange.request_id, &jwe)
        .await
        .assert_status_ok();
    let issuer = harness.idp.issuer();

    let anonymous = server
        .post("/v1/presentations/read")
        .json(&json!({"reference": exchange.reference,
            "principal": {"issuer": issuer, "subject": "user-1"}}))
        .await;
    anonymous.assert_status_unauthorized();
    assert_eq!(anonymous.header("www-authenticate"), "Bearer");

    let applicant = harness.applicant_token("portal", "user-1");
    let wrong_client = harness.token("portal", "user-1", READ_SCOPE);
    let missing_scope = harness.token("evidence", "evidence-service", "something:else");
    for token in [&applicant, &wrong_client, &missing_scope] {
        read(&server, token, &exchange.reference, &issuer, "user-1")
            .await
            .assert_status_unauthorized();
    }

    read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await
    .assert_status_ok();
}

#[tokio::test]
async fn a_read_returns_the_presentation_and_the_session_context() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let payload = national_id_payload(&exchange);
    let presentation = payload["vp_token"].clone();
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &payload),
    )
    .await
    .assert_status_ok();
    harness.time.fetch_add(7, Ordering::SeqCst);
    let received_at = harness.time.load(Ordering::SeqCst) - 7;

    let issuer = harness.idp.issuer();
    let response = read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await;
    response.assert_status_ok();
    assert_eq!(response.header("cache-control"), "no-store");
    let body: Value = response.json();
    assert_eq!(body["presentation"], presentation);
    let context = &body["context"];
    assert_eq!(context["nonce"], exchange.nonce);
    assert_eq!(context["clientId"], format!("x509_san_dns:{HOST}"));
    assert_eq!(
        context["responseUri"],
        format!("https://{HOST}/v1/responses/{}", exchange.request_id)
    );
    assert_eq!(context["policyId"], "national-id");
    assert_eq!(
        context["createdBy"],
        json!({"issuer": issuer, "subject": "user-1"})
    );
    let thumbprint = service
        .store()
        .with_by_reference(&exchange.reference, |s| {
            s.encryption_key.thumbprint().unwrap()
        })
        .unwrap();
    assert_eq!(context["responseKeyThumbprint"], thumbprint);
    assert_eq!(
        context["receivedAt"],
        chrono::DateTime::from_timestamp(i64::try_from(received_at).unwrap(), 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    // The first successful read consumed the presentation: a later read of the
    // same reference is the 404 an unknown reference gets.
    let unknown = read(
        &server,
        &harness.evidence_token(),
        &"A".repeat(43),
        &issuer,
        "user-1",
    )
    .await;
    let again = read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await;
    again.assert_status_not_found();
    assert_eq!(again.text(), unknown.text());
    assert_eq!(again.header("content-type"), unknown.header("content-type"));
    assert!(!again.text().contains(PID_VALUE));
}

#[tokio::test]
async fn a_read_releases_the_held_bytes_and_leaves_the_status() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let jwe = seal_to_session(&exchange, &national_id_payload(&exchange));
    post_response(&server, &exchange.request_id, &jwe)
        .await
        .assert_status_ok();
    assert!(service.store().held_presentation_bytes() > 0);

    let issuer = harness.idp.issuer();
    read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await
    .assert_status_ok();
    assert_eq!(service.store().held_presentation_bytes(), 0);
    // The wallet's own retry of the identical response is still answered, and
    // the portal still sees the session as received.
    post_response(&server, &exchange.request_id, &jwe)
        .await
        .assert_status_ok();
    let status = server
        .get(&format!("/v1/sessions/{}", exchange.reference))
        .add_header(
            "authorization",
            bearer(&harness.applicant_token("portal", "user-1")),
        )
        .await;
    status.assert_status_ok();
    assert_eq!(status.json::<Value>()["status"], "received");
}

#[tokio::test]
async fn a_wallet_error_is_consumed_by_its_first_read() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    let failed = start(&harness, &server, &service, "national-id", "user-1").await;
    let error = json!({"error": "access_denied", "state": failed.state});
    post_response(
        &server,
        &failed.request_id,
        &seal_to_session(&failed, &error),
    )
    .await
    .assert_status_ok();
    read(&server, &token, &failed.reference, &issuer, "user-1")
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    read(&server, &token, &failed.reference, &issuer, "user-1")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn a_read_that_does_not_succeed_consumes_nothing() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();

    // Still pending.
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status(StatusCode::CONFLICT);
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();

    // Wrong principal, unauthenticated, unknown reference.
    read(&server, &token, &exchange.reference, &issuer, "user-2")
        .await
        .assert_status_not_found();
    server
        .post("/v1/presentations/read")
        .json(&json!({"reference": exchange.reference,
            "principal": {"issuer": issuer, "subject": "user-1"}}))
        .await
        .assert_status_unauthorized();
    read(&server, &token, &"A".repeat(43), &issuer, "user-1")
        .await
        .assert_status_not_found();

    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_rate_limited_read_consumes_nothing() {
    let harness = Harness::new(&Options {
        evidence_read_burst: 1,
        ..Options::default()
    })
    .await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    // The one-read burst goes to a pending-style miss, then the real read is
    // refused for rate.
    read(&server, &token, &"A".repeat(43), &issuer, "user-1")
        .await
        .assert_status_not_found();
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
    // Refused before the session is touched: the presentation is still held.
    assert!(service.store().held_presentation_bytes() > 0);
}

#[tokio::test]
async fn two_concurrent_reads_yield_exactly_one_result() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    for round in 0..5 {
        let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
        post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &national_id_payload(&exchange)),
        )
        .await
        .assert_status_ok();
        let (first, second) = tokio::join!(
            read(&server, &token, &exchange.reference, &issuer, "user-1"),
            read(&server, &token, &exchange.reference, &issuer, "user-1"),
        );
        let mut statuses = [first.status_code(), second.status_code()];
        statuses.sort();
        assert_eq!(
            statuses,
            [StatusCode::OK, StatusCode::NOT_FOUND],
            "round {round}"
        );
    }
}

#[tokio::test]
async fn a_delivered_read_is_journalled_as_consumed() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_ok();
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_not_found();
    let journal = harness.audit_journal();
    assert!(journal.contains("delivered_and_consumed"), "{journal}");
    assert!(journal.contains("not_found"), "{journal}");
}

#[tokio::test]
async fn a_foreign_principal_and_an_unknown_reference_read_identically() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();

    let unknown = read(&server, &token, &"A".repeat(43), &issuer, "user-1").await;
    unknown.assert_status_not_found();
    let other_subject = read(&server, &token, &exchange.reference, &issuer, "user-2").await;
    let other_issuer = read(
        &server,
        &token,
        &exchange.reference,
        "https://other.example",
        "user-1",
    )
    .await;
    for refused in [&other_subject, &other_issuer] {
        refused.assert_status_not_found();
        assert_eq!(refused.text(), unknown.text());
        assert_eq!(
            refused.header("content-type"),
            unknown.header("content-type")
        );
    }
}

#[tokio::test]
async fn a_pending_session_reads_as_not_yet_presented() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let issuer = harness.idp.issuer();
    let pending = read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await;
    pending.assert_status(StatusCode::CONFLICT);
    let body: Value = pending.json();
    assert_eq!(
        body["type"],
        "https://id.registrystack.org/problems/registry-evidence-oid4vp/not-yet-presented"
    );
    assert!(body.get("presentation").is_none());
}

#[tokio::test]
async fn only_one_response_is_accepted_per_session() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let first = seal_to_session(&exchange, &national_id_payload(&exchange));
    post_response(&server, &exchange.request_id, &first)
        .await
        .assert_status_ok();

    // Identical bytes: the same answer, nothing changes.
    let retry = post_response(&server, &exchange.request_id, &first).await;
    retry.assert_status_ok();
    assert_eq!(retry.json::<Value>(), json!({}));

    // A different, otherwise valid response is refused.
    let mut other = national_id_payload(&exchange);
    other["vp_token"]["national_id"] = json!(["a-different-presentation"]);
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &other),
        )
        .await,
    );
    // The same payload under a fresh encryption is different bytes.
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &national_id_payload(&exchange)),
        )
        .await,
    );

    let issuer = harness.idp.issuer();
    let body: Value = read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &issuer,
        "user-1",
    )
    .await
    .json();
    assert_eq!(
        body["presentation"],
        national_id_payload(&exchange)["vp_token"]
    );
}

#[tokio::test]
async fn a_response_is_refused_for_the_wrong_state_session_key_or_encryption() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;

    // Wrong state, and no state.
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let mut wrong_state = national_id_payload(&exchange);
    wrong_state["state"] = json!("not-the-state");
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &wrong_state),
        )
        .await,
    );
    let mut no_state = national_id_payload(&exchange);
    no_state.as_object_mut().unwrap().remove("state");
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &no_state),
        )
        .await,
    );

    // Wrong or missing `kid`.
    let payload = national_id_payload(&exchange);
    for kid in [Some("another-key"), None] {
        let jwe = seal(&exchange, &payload, JweEnc::A128Gcm, kid);
        assert_refused(&post_response(&server, &exchange.request_id, &jwe).await);
    }

    // Encrypted to another session's key.
    let other = start(&harness, &server, &service, "national-id", "user-1").await;
    let to_other = seal(
        &other,
        &payload,
        JweEnc::A128Gcm,
        Some(other.key["kid"].as_str().unwrap()),
    );
    assert_refused(&post_response(&server, &exchange.request_id, &to_other).await);

    // `enc` outside the policy's list: age-check accepts only A256GCM.
    let age = start(&harness, &server, &service, "age-check", "user-1").await;
    let age_payload = json!({"vp_token": {"age": ["x"]}, "state": age.state});
    let kid = age.key["kid"].as_str().unwrap().to_owned();
    assert_refused(
        &post_response(
            &server,
            &age.request_id,
            &seal(&age, &age_payload, JweEnc::A128Gcm, Some(&kid)),
        )
        .await,
    );
    post_response(
        &server,
        &age.request_id,
        &seal(&age, &age_payload, JweEnc::A256Gcm, Some(&kid)),
    )
    .await
    .assert_status_ok();

    // Garbage, an unknown request id, and the wrong content type read the
    // same as a decryption failure.
    assert_refused(&post_response(&server, &exchange.request_id, "not.a.jwe").await);
    let jwe = seal_to_session(&exchange, &payload);
    assert_refused(&post_response(&server, &"B".repeat(43), &jwe).await);
    assert_refused(
        &server
            .post(&format!("/v1/responses/{}", exchange.request_id))
            .json(&json!({"response": jwe}))
            .await,
    );
    assert_refused(
        &server
            .post(&format!("/v1/responses/{}", exchange.request_id))
            .content_type("application/x-www-form-urlencoded")
            .bytes("other=1".into())
            .await,
    );

    // None of that spent the session: the right response still lands.
    post_response(&server, &exchange.request_id, &jwe)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_payload_that_repeats_a_member_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let token = format!("eyJhbGciOiJFUzI1NiJ9.{PID_VALUE}~eyJraWQiOiIxIn0");
    let vp_token = format!(r#"{{"national_id":["{token}"]}}"#);

    // `state` repeated, the last value the right one: a parser that keeps the
    // last member would accept it.
    let repeated_state = format!(
        r#"{{"state":"not-the-state","vp_token":{vp_token},"state":"{}"}}"#,
        exchange.state
    );
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_raw(&exchange, &repeated_state),
        )
        .await,
    );

    // `vp_token` repeated, the last one the right one.
    let repeated_vp_token = format!(
        r#"{{"vp_token":{{"unknown":["x"]}},"vp_token":{vp_token},"state":"{}"}}"#,
        exchange.state
    );
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal_raw(&exchange, &repeated_vp_token),
        )
        .await,
    );

    // The same payload without a repeat lands, so the refusals above are the
    // repeat and nothing else.
    let single = format!(r#"{{"vp_token":{vp_token},"state":"{}"}}"#, exchange.state);
    post_response(&server, &exchange.request_id, &seal_raw(&exchange, &single))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn an_expired_session_refuses_a_response() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let jwe = seal_to_session(&exchange, &national_id_payload(&exchange));
    harness.time.fetch_add(300, Ordering::SeqCst);
    assert_refused(&post_response(&server, &exchange.request_id, &jwe).await);
}

#[tokio::test]
async fn a_vp_token_must_match_the_policy_query() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let presentation = "a-presentation";
    let oversize = "x".repeat(256 * 1024 + 1);
    let cases: Vec<(&str, Value)> = vec![
        (
            "unknown query id",
            json!({"national_id": [presentation], "extra": [presentation]}),
        ),
        ("missing required query", json!({})),
        ("only an unknown query", json!({"other": [presentation]})),
        ("empty array", json!({"national_id": []})),
        (
            "two presentations",
            json!({"national_id": [presentation, presentation]}),
        ),
        ("empty string", json!({"national_id": [""]})),
        ("object presentation", json!({"national_id": [{"a": 1}]})),
        ("not an array", json!({"national_id": presentation})),
        ("oversize presentation", json!({"national_id": [oversize]})),
        ("vp_token not an object", json!([presentation])),
    ];
    for (name, vp_token) in cases {
        let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
        let payload = json!({"vp_token": vp_token, "state": exchange.state});
        let refused = post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &payload),
        )
        .await;
        assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(
            refused.json::<Value>(),
            json!({"error": "invalid_request"}),
            "{name}"
        );
        // The session is still open afterwards.
        post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &national_id_payload(&exchange)),
        )
        .await
        .assert_status_ok();
    }
}

#[tokio::test]
async fn the_response_body_is_bounded_before_it_is_read() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let body = format!("response={}", "A".repeat(2 * 1024 * 1024));
    let refused = server
        .post(&format!("/v1/responses/{}", exchange.request_id))
        .content_type("application/x-www-form-urlencoded")
        .bytes(body.into())
        .await;
    refused.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_presentation_at_the_size_limit_is_accepted() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let payload = json!({
        "vp_token": {"national_id": ["x".repeat(256 * 1024)]},
        "state": exchange.state,
    });
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &payload),
    )
    .await
    .assert_status_ok();
}

/// A response whose one presentation is `length` bytes.
fn sized_payload(exchange: &Exchange, length: usize) -> Value {
    json!({
        "vp_token": {"national_id": ["x".repeat(length)]},
        "state": exchange.state,
    })
}

#[tokio::test]
async fn held_presentation_bytes_are_bounded_across_the_store() {
    const BUDGET: u64 = 1_048_576;
    let harness = Harness::new(&Options {
        maximum_held_presentation_bytes: BUDGET,
        ..Options::default()
    })
    .await;
    let (server, service) = harness.server().await;
    let max = 256 * 1024;

    // Three maximum-size presentations, then one byte short of the budget,
    // then one byte to land exactly on it.
    for length in [max, max, max, max - 1, 1] {
        let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
        post_response(
            &server,
            &exchange.request_id,
            &seal_to_session(&exchange, &sized_payload(&exchange, length)),
        )
        .await
        .assert_status_ok();
    }
    assert_eq!(service.store().held_presentation_bytes(), BUDGET);

    // One byte more is refused: 503, retryable, and the session stays pending.
    let over = start(&harness, &server, &service, "national-id", "user-1").await;
    let refused = post_response(
        &server,
        &over.request_id,
        &seal_to_session(&over, &sized_payload(&over, 1)),
    )
    .await;
    refused.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused.maybe_header("retry-after").is_some());
    assert_eq!(
        refused.json::<Value>(),
        json!({"error": "temporarily_unavailable"})
    );
    assert_eq!(service.store().held_presentation_bytes(), BUDGET);
    let token = harness.applicant_token("portal", "user-1");
    let pending = server
        .get(&format!("/v1/sessions/{}", over.reference))
        .add_header("authorization", bearer(&token))
        .await;
    assert_eq!(pending.json::<Value>()["status"], "pending");

    // The refusal is audited, without the presentation.
    let journal = harness.audit_journal();
    assert!(journal.contains("response_refusal"), "{journal}");
    assert!(journal.contains("held_presentation_budget"), "{journal}");

    // A wallet error holds no presentation, so it is not refused.
    let failed = start(&harness, &server, &service, "national-id", "user-1").await;
    let error = json!({"error": "access_denied", "state": failed.state});
    post_response(
        &server,
        &failed.request_id,
        &seal_to_session(&failed, &error),
    )
    .await
    .assert_status_ok();

    // Results that expire release their bytes without waiting for a sweep:
    // the same response lands once the earlier results are past their hold.
    harness.time.fetch_add(1_800, Ordering::SeqCst);
    let fresh = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &fresh.request_id,
        &seal_to_session(&fresh, &sized_payload(&fresh, 1)),
    )
    .await
    .assert_status_ok();
    assert_eq!(service.store().held_presentation_bytes(), 1);
}

#[tokio::test]
async fn a_discarded_session_releases_its_held_bytes() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &sized_payload(&exchange, 1_000)),
    )
    .await
    .assert_status_ok();
    assert_eq!(service.store().held_presentation_bytes(), 1_000);
    service.store().discard(&exchange.reference);
    assert_eq!(service.store().held_presentation_bytes(), 0);
}

#[tokio::test]
async fn a_wallet_error_fails_the_session_with_a_closed_category() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();

    // Encrypted, and plain (section 8.3.1 lets a wallet that cannot encrypt
    // send the error unencrypted).
    let encrypted = start(&harness, &server, &service, "national-id", "user-1").await;
    let payload = json!({
        "error": "access_denied",
        "error_description": "Maria Santos refused",
        "state": encrypted.state,
    });
    post_response(
        &server,
        &encrypted.request_id,
        &seal_to_session(&encrypted, &payload),
    )
    .await
    .assert_status_ok();
    let failed = read(&server, &token, &encrypted.reference, &issuer, "user-1").await;
    failed.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = failed.json();
    assert_eq!(
        body["type"],
        "https://id.registrystack.org/problems/registry-evidence-oid4vp/wallet-error"
    );
    assert_eq!(body["category"], "access_denied");
    assert!(!failed.text().contains("Maria"));

    let plain = start(&harness, &server, &service, "national-id", "user-1").await;
    let form = format!(
        "error=something_new&error_description=Maria%20Santos&state={}",
        plain.state
    );
    server
        .post(&format!("/v1/responses/{}", plain.request_id))
        .content_type("application/x-www-form-urlencoded")
        .bytes(form.into())
        .await
        .assert_status_ok();
    let body: Value = read(&server, &token, &plain.reference, &issuer, "user-1")
        .await
        .json();
    assert_eq!(body["category"], "other");

    // A plain error needs the session's state.
    let guessed = start(&harness, &server, &service, "national-id", "user-1").await;
    for form in ["error=access_denied", "error=access_denied&state=guess"] {
        let refused = server
            .post(&format!("/v1/responses/{}", guessed.request_id))
            .content_type("application/x-www-form-urlencoded")
            .bytes(form.to_owned().into())
            .await;
        assert_refused(&refused);
    }
    assert_eq!(
        read(&server, &token, &guessed.reference, &issuer, "user-1")
            .await
            .status_code(),
        StatusCode::CONFLICT
    );

    // A failed session accepts nothing more.
    assert_refused(
        &post_response(
            &server,
            &encrypted.request_id,
            &seal_to_session(&encrypted, &national_id_payload(&encrypted)),
        )
        .await,
    );
}

#[tokio::test]
async fn the_portal_sees_received_and_failed_without_content() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");
    let status = |reference: String| {
        let server = &server;
        let token = token.clone();
        async move {
            server
                .get(&format!("/v1/sessions/{reference}"))
                .add_header("authorization", bearer(&token))
                .await
        }
    };

    let received = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &received.request_id,
        &seal_to_session(&received, &national_id_payload(&received)),
    )
    .await
    .assert_status_ok();
    let response = status(received.reference.clone()).await;
    assert_eq!(response.json::<Value>()["status"], "received");
    assert!(!response.text().contains(PID_VALUE));

    let failed = start(&harness, &server, &service, "national-id", "user-1").await;
    let error = json!({"error": "access_denied", "state": failed.state});
    post_response(
        &server,
        &failed.request_id,
        &seal_to_session(&failed, &error),
    )
    .await
    .assert_status_ok();
    let failed_status = status(failed.reference.clone()).await;
    let failed_body: Value = failed_status.json();
    assert_eq!(failed_body["status"], "failed");
    // Only the closed category is shown; nothing else the wallet sent.
    assert_eq!(failed_body["failureCategory"], "access_denied");
    assert!(response.json::<Value>().get("failureCategory").is_none());

    let other = start(&harness, &server, &service, "national-id", "user-1").await;
    let unknown_code = json!({
        "error": "Maria Santos refused",
        "error_description": PID_VALUE,
        "state": other.state,
    });
    post_response(
        &server,
        &other.request_id,
        &seal_to_session(&other, &unknown_code),
    )
    .await
    .assert_status_ok();
    let other_status = status(other.reference.clone()).await;
    assert_eq!(other_status.json::<Value>()["failureCategory"], "other");
    assert!(!other_status.text().contains("Maria"));
    assert!(!other_status.text().contains(PID_VALUE));
}

#[tokio::test]
async fn the_result_is_dropped_when_its_hold_ends() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();

    // Past the exchange window, inside the result hold (1800 seconds).
    harness.time.fetch_add(1_000, Ordering::SeqCst);
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_ok();
    assert_eq!(service.store().cleanup(), 0);

    harness.time.fetch_add(800, Ordering::SeqCst);
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_not_found();
    assert_eq!(service.store().cleanup(), 1);
    assert!(service.store().is_empty());
}

#[tokio::test]
async fn the_audit_journal_records_the_outcomes_and_leaks_nothing() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let jwe = seal_to_session(&exchange, &national_id_payload(&exchange));
    assert_refused(
        &post_response(
            &server,
            &exchange.request_id,
            &seal(
                &exchange,
                &national_id_payload(&exchange),
                JweEnc::A128Gcm,
                Some("bad"),
            ),
        )
        .await,
    );
    post_response(&server, &exchange.request_id, &jwe)
        .await
        .assert_status_ok();
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    read(&server, &token, &exchange.reference, &issuer, "user-1")
        .await
        .assert_status_ok();
    read(&server, &token, &exchange.reference, &issuer, "user-2")
        .await
        .assert_status_not_found();

    let failed = start(&harness, &server, &service, "national-id", "user-1").await;
    let error =
        json!({"error": "access_denied", "error_description": PID_VALUE, "state": failed.state});
    post_response(
        &server,
        &failed.request_id,
        &seal_to_session(&failed, &error),
    )
    .await
    .assert_status_ok();

    let journal = harness.audit_journal();
    for operation in [
        "response_acceptance",
        "response_refusal",
        "wallet_error",
        "evidence_read",
    ] {
        assert!(journal.contains(operation), "{operation} in {journal}");
    }
    assert!(journal.contains("national-id"));
    assert!(journal.contains("sha256:"));
    assert!(journal.contains("access_denied"));
    assert!(journal.contains("principal_mismatch"));

    let presentation = national_id_payload(&exchange)["vp_token"]["national_id"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let mut forbidden = vec![
        presentation,
        PID_VALUE.to_owned(),
        exchange.nonce.clone(),
        exchange.state.clone(),
        failed.state.clone(),
        exchange.reference.clone(),
        failed.reference.clone(),
        exchange.request_id.clone(),
        jwe,
        token,
        harness.applicant_token("portal", "user-1"),
    ];
    forbidden
        .extend(["x", "y", "kid"].map(|member| exchange.key[member].as_str().unwrap().to_owned()));
    for line in journal.lines() {
        let entry: Value = serde_json::from_str(line).expect("each entry is JSON");
        assert_json_absent_strings(&entry, &forbidden).expect("no secret reaches the journal");
    }
    assert!(!journal.contains("user-1"), "principals are pseudonymized");
}

#[tokio::test]
async fn responses_are_rate_limited_per_request_and_globally() {
    let per_request = Harness::new(&Options {
        response_burst_per_request: 2,
        ..Options::default()
    })
    .await;
    let (server, service) = per_request.server().await;
    let exchange = start(&per_request, &server, &service, "national-id", "user-1").await;
    let mut wrong = national_id_payload(&exchange);
    wrong["state"] = json!("wrong");
    let jwe = seal_to_session(&exchange, &wrong);
    assert_refused(&post_response(&server, &exchange.request_id, &jwe).await);
    assert_refused(&post_response(&server, &exchange.request_id, &jwe).await);
    let limited = post_response(&server, &exchange.request_id, &jwe).await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.maybe_header("retry-after").is_some());
    assert_eq!(
        limited.json::<Value>(),
        json!({"error": "temporarily_unavailable"})
    );
    // Another session is not affected.
    let other = start(&per_request, &server, &service, "national-id", "user-1").await;
    post_response(
        &server,
        &other.request_id,
        &seal_to_session(&other, &national_id_payload(&other)),
    )
    .await
    .assert_status_ok();

    let global = Harness::new(&Options {
        wallet_response_burst: 2,
        ..Options::default()
    })
    .await;
    let (server, _service) = global.server().await;
    for _ in 0..2 {
        assert_refused(&post_response(&server, &"C".repeat(43), "x").await);
    }
    post_response(&server, &"C".repeat(43), "x")
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn reads_are_rate_limited_per_evidence_client() {
    let harness = Harness::new(&Options {
        evidence_read_burst: 2,
        ..Options::default()
    })
    .await;
    let (server, _service) = harness.server().await;
    let issuer = harness.idp.issuer();
    let token = harness.evidence_token();
    for _ in 0..2 {
        read(&server, &token, &"A".repeat(43), &issuer, "user-1")
            .await
            .assert_status_not_found();
    }
    let limited = read(&server, &token, &"A".repeat(43), &issuer, "user-1").await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.maybe_header("retry-after").is_some());
}

#[tokio::test]
async fn an_audit_failure_refuses_the_response_and_leaves_the_session_pending() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let jwe = seal_to_session(&exchange, &national_id_payload(&exchange));

    // Swapping the journal file for another makes the writer refuse entries.
    let moved = harness.audit_path.with_extension("moved");
    std::fs::rename(&harness.audit_path, &moved).unwrap();
    std::fs::write(&harness.audit_path, b"").unwrap();
    let refused = post_response(&server, &exchange.request_id, &jwe).await;
    refused.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        refused.json::<Value>(),
        json!({"error": "temporarily_unavailable"})
    );
    assert!(refused.maybe_header("retry-after").is_some());
    // The reservation was released: the session holds nothing for this
    // response and reads as pending.
    let digest = Submission::Encrypted(jwe).digest();
    let (status, prior) = service
        .store()
        .with_by_reference(&exchange.reference, |session| {
            (session.status(), session.prior(&digest))
        })
        .unwrap();
    assert_eq!(status.as_str(), "pending");
    assert_eq!(prior, Prior::None);
}

#[tokio::test]
async fn a_response_recorded_as_accepted_is_accepted_when_the_window_closes_during_the_record() {
    let harness = Harness::new(&Options::default()).await;
    // The clock passes the session window once the journal holds the
    // acceptance record, which is between the reservation and the
    // confirmation of the response.
    let time = Arc::clone(&harness.time);
    let audit_path = harness.audit_path.clone();
    let clock: Clock = Arc::new(move || {
        let base = time.load(Ordering::SeqCst);
        let journal = std::fs::read_to_string(&audit_path).unwrap_or_default();
        if journal.contains("response_acceptance") {
            base + 10_000
        } else {
            base
        }
    });
    let service = Arc::new(
        VerifierService::load_with_clock(harness.config(), clock)
            .await
            .expect("the service starts"),
    );
    let server = TestServer::new(build_app(Arc::clone(&service)));
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;

    post_response(
        &server,
        &exchange.request_id,
        &seal_to_session(&exchange, &national_id_payload(&exchange)),
    )
    .await
    .assert_status_ok();

    // The journal and the wallet agree, and Evidence can read the result.
    let journal = harness.audit_journal();
    assert!(journal.contains("\"accepted\""), "{journal}");
    assert!(!journal.contains("response_refusal"), "{journal}");
    read(
        &server,
        &harness.evidence_token(),
        &exchange.reference,
        &harness.idp.issuer(),
        "user-1",
    )
    .await
    .assert_status_ok();
}

#[tokio::test]
async fn a_reserved_session_survives_the_expiry_sweep() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let exchange = start(&harness, &server, &service, "national-id", "user-1").await;
    let digest = [5u8; 32];
    service
        .store()
        .with_by_request_id_mut(&exchange.request_id, |session| {
            session.reserve(
                digest,
                registry_evidence_oid4vp::session::Held::WalletError(
                    registry_evidence_oid4vp::session::FailureCategory::Other,
                ),
                0,
            );
        })
        .expect("the session is open");
    harness.time.fetch_add(10_000, Ordering::SeqCst);
    assert_eq!(service.store().cleanup(), 0, "a reservation is not swept");
    assert_eq!(service.store().len(), 1);
}
