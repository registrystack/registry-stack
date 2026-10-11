#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

//! Database-backed message route tests: `POST /v1/messages` renders and
//! records a submission under its idempotency key, `GET /v1/messages/{id}`
//! and `POST /v1/messages/{id}/cancel` answer only the submitter and an
//! operator, a cancellation racing the worker's claim has one winner, and
//! no contact, rendered content, template data, principal, or credential
//! reaches the journal or the operational log.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use registry_messaging::dispatch::dispatcher;
use registry_messaging::messages::{
    prepare_submission, MessageStore, MessageStoreError, OperatorAction, SettleOutcome,
};
use registry_messaging::runtime::message_reader;
use registry_messaging_core::{AccessProfiles, ActorKind, Caller, CallerIdentity, READY_PATH};
use registry_platform_audit::AuditWriter;
use registry_platform_dispatch::postgres::Claim;
use registry_platform_dispatch::{SendOutcome, Sent};
use serde_json::{json, Value};
use support::{
    email_submission, operator_token, rotated_test_audit, sender_token, sender_token_for,
    sms_submission, submit_to, test_audit, token, Harness, RefusingAuditSink, NAME,
    OTHER_SENDER_PRINCIPAL, RECIPIENT, SENDER_PRINCIPAL,
};
use tower::ServiceExt as _;
use uuid::Uuid;

fn assert_problem(answer: &(StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(answer.1["code"], code, "{}", answer.1);
}

#[tokio::test]
async fn operator_reads_and_action_previews_ignore_a_refused_audit_destination() {
    let harness = Harness::start().await;
    let message_id = harness.accepted(&email_submission()).await;
    let audit_path = harness
        .config
        .audit
        .path
        .as_ref()
        .expect("a file audit destination");
    let blocked_parent = audit_path
        .parent()
        .unwrap()
        .join("reader-audit-parent-is-a-file");
    std::fs::write(&blocked_parent, b"not a directory").unwrap();
    let mut config = harness.config.clone();
    config.audit.path = Some(blocked_parent.join("audit.jsonl"));

    let reader = message_reader(&config)
        .await
        .expect("read-only access does not open the audit destination");
    assert_eq!(reader.list(None, 10).await.unwrap().len(), 1);
    assert!(reader.read(message_id).await.unwrap().is_some());
    let preview = reader
        .operate(message_id, OperatorAction::Cancel)
        .await
        .unwrap()
        .expect("the message exists");
    assert!(preview.eligible);
    assert!(!preview.applied);
    assert_eq!(harness.state(message_id).await, "pending");
}

#[tokio::test]
async fn an_accepted_submission_records_its_rendered_parts_and_answers_a_receipt() {
    let harness = Harness::start().await;
    let (status, receipt) = harness
        .submit(&sender_token(), "submission-1", &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    let id = receipt["id"].as_str().unwrap();
    assert_eq!(
        receipt,
        json!({
            "id": id,
            "status": "queued",
            "links": {"self": format!("/v1/messages/{id}"), "cancel": format!("/v1/messages/{id}/cancel")}
        })
    );
    let message_id = Uuid::parse_str(id).unwrap();
    let row = harness
        .isolated
        .admin
        .query_one(
            "SELECT message.template_id, message.template_version, message.template_locale, \
                    message.package_digest, message.sender, message.provider, \
                    payload.recipient, payload.subject, payload.text_body, payload.erased_at IS NULL \
               FROM messaging_messages AS message \
               JOIN messaging_message_payloads AS payload USING (message_id) \
              WHERE message_id = $1",
            &[&message_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "appointment-reminder");
    assert_eq!(row.get::<_, String>(1), "1");
    assert_eq!(row.get::<_, String>(2), "en");
    assert_eq!(row.get::<_, String>(3), harness.package.digest());
    assert_eq!(row.get::<_, String>(4), "notices@example.org");
    assert_eq!(row.get::<_, String>(5), "mail-relay");
    assert_eq!(row.get::<_, String>(6), RECIPIENT);
    assert!(row.get::<_, Option<String>>(7).is_some());
    // The parts are rendered at acceptance; the data they came from is not
    // stored anywhere.
    assert!(row.get::<_, String>(8).contains(NAME));
    assert!(row.get::<_, bool>(9));
    assert_eq!(harness.state(message_id).await, "pending");
    let responses = harness.audit_responses().await;
    let accepted: Vec<&Value> = responses
        .iter()
        .filter(|record| record["event"] == "messaging.message.accepted")
        .collect();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0]["messageId"], id);
}

#[tokio::test]
async fn an_audit_request_refusal_records_no_submission() {
    let harness = Harness::start().await;
    let audit = test_audit(AuditWriter::from_line_sink(Box::new(
        RefusingAuditSink::after(0),
    )));
    let app = harness.app_with_audit(audit).await;
    let (status, _, problem) = submit_to(
        app,
        &sender_token(),
        "audit-request-refused",
        &email_submission(),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        0
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        0
    );
}

#[tokio::test]
async fn a_post_commit_audit_refusal_replays_one_committed_submission_receipt() {
    let harness = Harness::start().await;
    let audit = test_audit(AuditWriter::from_line_sink(Box::new(
        RefusingAuditSink::after(1),
    )));
    let app = harness.app_with_audit(audit).await;
    let key = "audit-response-refused";
    let (status, _, problem) = submit_to(app, &sender_token(), key, &email_submission()).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        1
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        1
    );

    let (status, receipt) = harness
        .submit(&sender_token(), key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    let committed_id: Uuid = harness
        .isolated
        .admin
        .query_one(
            "SELECT message_id FROM messaging_idempotency WHERE idempotency_key = $1",
            &[&key],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(receipt["id"], committed_id.to_string());
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        1
    );
}

#[tokio::test]
async fn readiness_fails_when_the_audit_writer_loses_its_destination() {
    let harness = Harness::start().await;
    let audit = test_audit(AuditWriter::from_line_sink(Box::new(
        RefusingAuditSink::after(0),
    )));
    assert!(audit
        .append_background(json!({"event": "messaging.test.probe"}))
        .await
        .is_err());
    let app = harness.app_with_audit(audit).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri(READY_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn an_idempotency_key_replays_one_request_and_refuses_another() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let first = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let replay = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(replay, first);

    let mut different = email_submission();
    different["correlationId"] = json!("case-43");
    assert_problem(
        &harness.submit(&sender, "key-1", &different).await,
        StatusCode::CONFLICT,
        "idempotency.key-reused",
    );
    // The key belongs to the principal: another sender's same key is its own.
    let other = harness
        .submit(
            &sender_token_for(OTHER_SENDER_PRINCIPAL),
            "key-1",
            &different,
        )
        .await;
    assert_eq!(other.0, StatusCode::ACCEPTED);
    assert_ne!(other.1["id"], first.1["id"]);

    harness
        .execute(
            "UPDATE messaging_idempotency SET expires_at = now() - interval '1 second' \
              WHERE message_id = $1",
            &[&Uuid::parse_str(first.1["id"].as_str().unwrap()).unwrap()],
        )
        .await;
    // Past its receipt horizon the exact request answers expired, and a
    // different request under the key is still a reuse, as it was inside
    // the horizon.
    assert_problem(
        &harness.submit(&sender, "key-1", &email_submission()).await,
        StatusCode::GONE,
        "idempotency.expired",
    );
    assert_problem(
        &harness.submit(&sender, "key-1", &different).await,
        StatusCode::CONFLICT,
        "idempotency.key-reused",
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", format!("Bearer {sender}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&email_submission()).unwrap(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(harness.app.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );
}

#[tokio::test]
async fn an_exact_retry_across_an_audit_key_rotation_replays_and_never_sends_again() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let first = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(first.0, StatusCode::ACCEPTED, "{}", first.1);

    // A runtime restarted after an `audit.hashKeyRef` rotation computes
    // another pseudonym for the same caller. The spent key belongs to the
    // caller's issuer and subject, so the rotation does not free it.
    let journal = RefusingAuditSink::after(usize::MAX);
    let rotated = harness
        .app_with_audit(rotated_test_audit(AuditWriter::from_line_sink(Box::new(
            journal.clone(),
        ))))
        .await;
    let (status, _, replay) =
        submit_to(rotated.clone(), &sender, "key-1", &email_submission()).await;
    assert_eq!((status, replay), first);

    let mut different = email_submission();
    different["correlationId"] = json!("case-43");
    let (status, _, problem) = submit_to(rotated.clone(), &sender, "key-1", &different).await;
    assert_problem(
        &(status, problem),
        StatusCode::CONFLICT,
        "idempotency.key-reused",
    );
    // The key is still the caller's own: another sender's same key, under
    // the rotated key, records its own message.
    let (status, _, other) = submit_to(
        rotated.clone(),
        &sender_token_for(OTHER_SENDER_PRINCIPAL),
        "key-1",
        &email_submission(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{other}");
    assert_ne!(other["id"], first.1["id"]);

    harness
        .execute(
            "UPDATE messaging_idempotency SET expires_at = now() - interval '1 second' \
              WHERE message_id = $1",
            &[&Uuid::parse_str(first.1["id"].as_str().unwrap()).unwrap()],
        )
        .await;
    for (body, status_code, code) in [
        (email_submission(), StatusCode::GONE, "idempotency.expired"),
        (different, StatusCode::CONFLICT, "idempotency.key-reused"),
    ] {
        let (status, _, problem) = submit_to(rotated.clone(), &sender, "key-1", &body).await;
        assert_problem(&(status, problem), status_code, code);
    }

    // One message and one dispatch job for the first caller's key, and one
    // for the other sender's.
    for table in ["messaging_messages", "messaging_dispatch_jobs"] {
        assert_eq!(
            harness
                .count(&format!("SELECT count(*) FROM {table}"))
                .await,
            2,
            "{table}"
        );
    }
    // The journal still names callers only by their pseudonyms.
    let entries = journal.entries();
    assert!(
        entries
            .iter()
            .any(|entry| entry["record"]["event"] == "messaging.message.replayed"),
        "{entries:?}"
    );
    support::assert_absent("the rotated journal", &Value::Array(entries));
}

#[tokio::test]
async fn an_idempotency_key_is_scoped_to_the_issuer_as_well_as_the_subject() {
    let harness = Harness::start().await;
    let first = harness
        .submit(&sender_token(), "key-1", &email_submission())
        .await;
    assert_eq!(first.0, StatusCode::ACCEPTED, "{}", first.1);

    // The same subject under another issuer is another caller, and its key
    // is its own.
    let caller = Caller {
        identity: CallerIdentity {
            issuer: "https://another-identity.example.test".to_owned(),
            subject: SENDER_PRINCIPAL.to_owned(),
        },
        actor_kind: Some(ActorKind::Service),
        profile: harness
            .package
            .access_profiles()
            .get("case-notices")
            .expect("the starter sender profile")
            .clone(),
    };
    let submission = prepare_submission(
        &harness.package,
        &caller,
        &serde_json::to_vec(&email_submission()).unwrap(),
    )
    .expect("the prepared submission");
    let answer = harness
        .service
        .submit(&caller, "key-1", &submission)
        .await
        .expect("the other issuer's submission");
    assert!(!answer.replayed);
    assert_ne!(answer.message_id.to_string(), first.1["id"]);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );
}

#[tokio::test]
async fn an_exact_retry_the_caller_may_no_longer_send_is_refused_while_the_first_attempt_stands() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let first = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(first.0, StatusCode::ACCEPTED, "{}", first.1);
    let message_id = Uuid::parse_str(first.1["id"].as_str().unwrap()).unwrap();

    // An activation removes the template from the caller's access profile.
    // A retry is authorized again before its key is looked up, so the exact
    // retry is refused although the first attempt was accepted and is
    // queued to send.
    let narrowed = AccessProfiles::new(
        harness
            .package
            .access_profiles()
            .iter()
            .cloned()
            .map(|mut profile| {
                profile
                    .templates
                    .retain(|template| template != "appointment-reminder");
                profile
            })
            .collect(),
    )
    .expect("the narrowed access profiles");
    let narrowed_app = harness.app_with_access_profiles(narrowed).await;
    let (status, _, problem) = submit_to(narrowed_app, &sender, "key-1", &email_submission()).await;
    assert_problem(
        &(status, problem),
        StatusCode::FORBIDDEN,
        "profile.not-authorized",
    );
    assert_eq!(harness.state(message_id).await, "pending");
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        1
    );

    // Under a profile that allows it again, the same retry answers the first
    // attempt's receipt: the refusal said nothing about that attempt.
    let replay = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(replay, first);
}

#[tokio::test]
async fn concurrent_submissions_under_one_key_record_one_message() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let mut submissions = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = harness.app.clone();
        let sender = sender.clone();
        submissions.spawn(async move {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("authorization", format!("Bearer {sender}"))
                .header("idempotency-key", "shared-key")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&email_submission()).unwrap(),
                ))
                .unwrap();
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        });
    }
    let answers = submissions.join_all().await;
    for answer in &answers {
        assert_eq!(answer.0, StatusCode::ACCEPTED, "{}", answer.1);
        assert_eq!(answer.1["id"], answers[0].1["id"]);
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        1
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_dispatch_jobs")
            .await,
        1
    );
}

/// SEC-01: only a sender submits, and only through what its profile lists.
#[tokio::test]
async fn a_submission_outside_the_callers_role_or_profile_is_refused_before_the_store() {
    let harness = Harness::start().await;
    assert_problem(
        &harness
            .submit(&operator_token(), "key-1", &email_submission())
            .await,
        StatusCode::FORBIDDEN,
        "operation.not-authorized",
    );
    let mut unlisted_profile = email_submission();
    unlisted_profile["senderProfile"] = json!("another-program");
    let mut unlisted_template = email_submission();
    unlisted_template["template"] = json!({"id": "unshipped", "version": "1"});
    let direct = json!({
        "senderProfile": "transactional",
        "to": {"email": RECIPIENT},
        "content": {"subject": "Hello", "text": NAME}
    });
    for body in [unlisted_profile, unlisted_template, direct] {
        assert_problem(
            &harness.submit(&sender_token(), "key-1", &body).await,
            StatusCode::FORBIDDEN,
            "profile.not-authorized",
        );
    }
    let unscoped = token(json!({
        "sub": support::SENDER_PRINCIPAL,
        "azp": "case-system",
        "registry_scopes": "messaging:read",
        "registry_actor_kind": "service",
    }));
    assert_problem(
        &harness
            .submit(&unscoped, "key-1", &email_submission())
            .await,
        StatusCode::FORBIDDEN,
        "profile.not-authorized",
    );
    let (status, _) = harness.call("POST", "/v1/messages", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        0
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        0
    );
}

/// SEC-02: the body is closed; a member the contract does not name, such
/// as a provider or a credential reference, is refused and nothing is kept.
#[tokio::test]
async fn a_submission_naming_an_unknown_member_is_refused_and_records_nothing() {
    let harness = Harness::start().await;
    let mut provider_chosen = email_submission();
    provider_chosen["provider"] = json!("https://attacker.example");
    let mut credential_chosen = email_submission();
    credential_chosen["to"]["passwordRef"] = json!("secret:env/SMTP");
    let mut wrong_channel = email_submission();
    wrong_channel["to"] = json!({"phone": "+15551234567"});
    for body in [provider_chosen, credential_chosen, wrong_channel] {
        assert_problem(
            &harness.submit(&sender_token(), "key-1", &body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.unprocessable",
        );
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        0
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        0
    );
}

/// SEC-04: a message is visible to its submitter and to an operator only,
/// and one the caller may not see answers exactly like one that does not
/// exist.
#[tokio::test]
async fn a_message_is_visible_to_its_submitter_and_an_operator_only() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    let uri = format!("/v1/messages/{id}");

    let (status, view) = harness.call("GET", &uri, Some(&sender_token())).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["id"], id.to_string());
    assert_eq!(view["status"], "queued");
    assert_eq!(view["dispatch"], "queued");
    // The email goes through an SMTP provider, which records no receipts.
    assert_eq!(view["report"], "unavailable");
    assert!(view.get("reportedAt").is_none(), "{view}");
    assert_eq!(view["to"], json!({"email": "redacted"}));
    assert_eq!(
        view["template"],
        json!({"id": "appointment-reminder", "version": "1"})
    );
    assert_eq!(view["correlationId"], "case-42");
    for absent in [
        "data", "content", "parts", "subject", "text", "html", "provider",
    ] {
        assert!(view.get(absent).is_none(), "{absent} in {view}");
    }
    support::assert_absent("the message view", &view);

    // The SMS goes through an HTTP provider that declares receipts, so no
    // report has arrived yet.
    let sms = harness.accepted(&sms_submission()).await;
    let (status, sms_view) = harness
        .call("GET", &format!("/v1/messages/{sms}"), Some(&sender_token()))
        .await;
    assert_eq!(status, StatusCode::OK, "{sms_view}");
    assert_eq!(
        (
            &sms_view["status"],
            &sms_view["dispatch"],
            &sms_view["report"]
        ),
        (&json!("queued"), &json!("queued"), &json!("none"))
    );

    let (status, operator_view) = harness.call("GET", &uri, Some(&operator_token())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(operator_view["id"], view["id"]);

    let other = sender_token_for(OTHER_SENDER_PRINCIPAL);
    let hidden = harness.call("GET", &uri, Some(&other)).await;
    assert_problem(&hidden, StatusCode::NOT_FOUND, "message.not-visible");
    let absent = harness
        .call(
            "GET",
            &format!("/v1/messages/{}", Uuid::new_v4()),
            Some(&other),
        )
        .await;
    assert_problem(&absent, StatusCode::NOT_FOUND, "message.not-visible");
    assert_eq!(hidden.1["title"], absent.1["title"]);
    assert_eq!(hidden.1["detail"], absent.1["detail"]);
    let hidden_cancel = harness
        .call("POST", &format!("{uri}/cancel"), Some(&other))
        .await;
    assert_problem(&hidden_cancel, StatusCode::NOT_FOUND, "message.not-visible");
    assert_eq!(harness.state(id).await, "pending");
    let (status, _) = harness.call("GET", &uri, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// MESSAGING-DEC-15: a status read is answered from the store and writes
/// no audit record, whether the caller sees the message or not.
#[tokio::test]
async fn a_status_read_writes_no_audit_record() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    harness.publish().await;
    let audit_responses = harness.audit_responses().await.len();
    let journal = harness.journal().len();
    let uri = format!("/v1/messages/{id}");

    let (status, _) = harness.call("GET", &uri, Some(&sender_token())).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = harness.call("GET", &uri, Some(&operator_token())).await;
    assert_eq!(status, StatusCode::OK);
    let other = sender_token_for(OTHER_SENDER_PRINCIPAL);
    let (status, _) = harness.call("GET", &uri, Some(&other)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    harness.publish().await;

    assert_eq!(harness.audit_responses().await.len(), audit_responses);
    assert_eq!(harness.journal().len(), journal);
}

#[tokio::test]
async fn a_queued_message_cancels_once_and_a_claimed_one_does_not() {
    let harness = Harness::start().await;
    let queued = harness.accepted(&email_submission()).await;
    let cancel = format!("/v1/messages/{queued}/cancel");
    let (status, view) = harness.call("POST", &cancel, Some(&sender_token())).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["status"], "cancelled");
    assert_eq!(view["to"], json!({"email": "redacted"}));
    assert_problem(
        &harness.call("POST", &cancel, Some(&operator_token())).await,
        StatusCode::CONFLICT,
        "message.terminal",
    );

    let claimed = harness.accepted(&sms_submission()).await;
    let leased = harness
        .service
        .messages()
        .dispatcher()
        .claim()
        .await
        .unwrap()
        .leased()
        .expect("the queued message is leased");
    assert_eq!(leased.key.id(), claimed);
    assert_problem(
        &harness
            .call(
                "POST",
                &format!("/v1/messages/{claimed}/cancel"),
                Some(&operator_token()),
            )
            .await,
        StatusCode::CONFLICT,
        "message.dispatch-started",
    );
    assert_eq!(harness.state(claimed).await, "leased");

    harness.publish().await;
    let cancelled: Vec<Value> = harness
        .journal()
        .into_iter()
        .filter(|entry| entry["record"]["event"] == "messaging.dispatch.transition")
        .filter(|entry| entry["record"]["disposition"] == "cancelled")
        .collect();
    assert_eq!(cancelled.len(), 2, "{cancelled:?}");
    assert_eq!(cancelled[0]["phase"], "request");
    assert_eq!(cancelled[1]["phase"], "response");
    assert_eq!(cancelled[0]["correlation"], cancelled[1]["correlation"]);
    assert_eq!(cancelled[1]["record"]["actor"]["kind"], "caller");
    assert_eq!(
        cancelled[1]["record"]["actor"]["accessProfile"],
        "case-notices"
    );
}

/// Start with the SMS sender profile set to `onUncertain: retry`.
async fn retrying_harness() -> Harness {
    Harness::start_with(Value::Null, |package| {
        let path = package.join("messaging.yaml");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut manifest: Value = serde_norway::from_str(&source).unwrap();
        manifest["senderProfiles"][1]["onUncertain"] = Value::String("retry".to_owned());
        std::fs::write(path, serde_norway::to_string(&manifest).unwrap()).unwrap();
    })
    .await
}

/// Lease the message and finish its attempt with `outcome`.
async fn attempt(harness: &Harness, id: Uuid, outcome: SendOutcome) {
    let dispatcher = harness.service.messages().dispatcher();
    let leased = dispatcher
        .claim()
        .await
        .unwrap()
        .leased()
        .expect("the queued message is leased");
    assert_eq!(leased.key.id(), id);
    dispatcher
        .finish(
            &leased,
            Sent {
                outcome,
                detail: (),
            },
        )
        .await
        .unwrap();
    assert_eq!(harness.state(id).await, "pending");
}

/// MESSAGING-DEC-09: a message waiting to retry after attempts that were
/// definitely not sent is still withdrawn by a cancel.
#[tokio::test]
async fn a_message_retrying_after_transient_failures_cancels() {
    let harness = retrying_harness().await;
    let id = harness.accepted(&sms_submission()).await;
    attempt(&harness, id, SendOutcome::Transient { retry_after: None }).await;
    let preview = harness
        .service
        .messages()
        .operate(id, OperatorAction::Cancel, false)
        .await
        .unwrap()
        .expect("the message exists");
    assert!(preview.eligible, "the operator preview agrees");
    let (status, view) = harness
        .call(
            "POST",
            &format!("/v1/messages/{id}/cancel"),
            Some(&sender_token()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["status"], "cancelled");
    assert_eq!(harness.state(id).await, "cancelled");
}

/// MESSAGING-DEC-09: a message waiting to retry after an attempt that may
/// have reached its provider, whether the provider answered maybe-sent or
/// the lease lapsed mid-attempt, is refused as started and keeps its retry.
#[tokio::test]
async fn a_message_retrying_after_an_attempt_that_may_have_been_sent_does_not_cancel() {
    let harness = retrying_harness().await;
    let maybe_sent = harness.accepted(&sms_submission()).await;
    attempt(&harness, maybe_sent, SendOutcome::MaybeSent).await;

    let lapsed = harness.accepted(&sms_submission()).await;
    let dispatcher = harness.service.messages().dispatcher();
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(leased.key.id(), lapsed);
    assert_eq!(
        harness
            .execute(
                "UPDATE messaging_dispatch_jobs \
                    SET attempt_started_at = now() - interval '2 minutes', \
                        lease_expires_at = now() - interval '1 minute' \
                  WHERE message_id = $1 AND state = 'leased'",
                &[&lapsed],
            )
            .await,
        1
    );
    assert!(dispatcher.claim().await.unwrap().leased().is_none());
    assert_eq!(harness.state(lapsed).await, "pending");

    for id in [maybe_sent, lapsed] {
        assert_problem(
            &harness
                .call(
                    "POST",
                    &format!("/v1/messages/{id}/cancel"),
                    Some(&operator_token()),
                )
                .await,
            StatusCode::CONFLICT,
            "message.dispatch-started",
        );
        assert_eq!(harness.state(id).await, "pending");
        for apply in [false, true] {
            let report = harness
                .service
                .messages()
                .operate(id, OperatorAction::Cancel, apply)
                .await
                .unwrap()
                .expect("the message exists");
            assert!(
                !report.eligible && !report.applied,
                "the operator preview agrees with the cancel: {report:?}"
            );
            assert_eq!(report.next_status, None);
        }
        assert_eq!(harness.state(id).await, "pending");
    }
}

/// A cancellation racing the worker's claim has exactly one winner: the
/// message is cancelled and never leased, or leased and the cancellation is
/// refused as started. The two run on separate worker threads and the claim
/// starts a little later on some rounds, so which one wins a round is left
/// to the database; the test holds that exactly one does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancellation_racing_a_claim_has_one_winner() {
    const ROUNDS: u64 = 40;
    let harness = Harness::start().await;
    let dispatcher = harness.service.messages().dispatcher().clone();
    let mut claims = 0_i64;
    for round in 0..ROUNDS {
        let id = harness.accepted(&email_submission()).await;
        let uri = format!("/v1/messages/{id}/cancel");
        let token = sender_token();
        let stagger = Duration::from_micros((round % 8) * 400);
        let claim = {
            let dispatcher = dispatcher.clone();
            tokio::spawn(async move {
                if !stagger.is_zero() {
                    tokio::time::sleep(stagger).await;
                }
                dispatcher.claim().await
            })
        };
        let cancel = harness.call("POST", &uri, Some(&token)).await;
        match (claim.await.unwrap().unwrap(), cancel.0) {
            (Claim::Idle, StatusCode::OK) => {
                assert_eq!(harness.state(id).await, "cancelled");
            }
            (Claim::Leased(job), StatusCode::CONFLICT) => {
                assert_eq!(job.key.id(), id);
                assert_eq!(cancel.1["code"], "message.dispatch-started");
                assert_eq!(harness.state(id).await, "leased");
                claims += 1;
            }
            (claim, status) => panic!("both or neither won: {claim:?} and {status}"),
        }
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_attempts")
            .await,
        claims
    );
}

/// A cancelled message is never leased.
#[tokio::test]
async fn a_cancelled_message_is_never_claimed() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    let (status, _) = harness
        .call(
            "POST",
            &format!("/v1/messages/{id}/cancel"),
            Some(&sender_token()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let claim = harness
        .service
        .messages()
        .dispatcher()
        .claim()
        .await
        .unwrap();
    assert_eq!(claim, Claim::Idle);
    assert_eq!(harness.state(id).await, "cancelled");
}

/// Submissions, replays, refusals, reads, and cancellations journal their
/// references and outcomes only.
#[tokio::test]
async fn no_contact_content_data_principal_or_credential_reaches_the_journal_or_the_log() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let first = harness.submit(&sender, "key-1", &email_submission()).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let _ = harness.submit(&sender, "key-1", &email_submission()).await;
    let mut different = email_submission();
    different["locale"] = json!("fr");
    let _ = harness.submit(&sender, "key-1", &different).await;
    let _ = harness
        .submit(&operator_token(), "key-2", &email_submission())
        .await;
    let sms = harness.accepted(&sms_submission()).await;
    let id = first.1["id"].as_str().unwrap();
    let _ = harness
        .call("GET", &format!("/v1/messages/{id}"), Some(&sender))
        .await;
    let _ = harness
        .call("POST", &format!("/v1/messages/{sms}/cancel"), Some(&sender))
        .await;
    harness.publish().await;

    let journal = harness.journal();
    let events: Vec<&str> = journal
        .iter()
        .filter_map(|entry| entry["record"]["event"].as_str())
        .collect();
    for expected in [
        "messaging.message.accepted",
        "messaging.message.replayed",
        "messaging.message.refused",
        "messaging.dispatch.transition",
    ] {
        assert!(
            events.contains(&expected),
            "{expected} missing from {events:?}"
        );
    }
    let accepted = journal
        .iter()
        .find(|entry| entry["record"]["event"] == "messaging.message.accepted")
        .unwrap();
    assert!(
        accepted["record"]["recipientReference"].is_string(),
        "{accepted}"
    );
    support::assert_absent("the journal", &Value::Array(journal));
    support::assert_absent(
        "the audit responses",
        &Value::Array(harness.audit_responses().await),
    );
    support::assert_logs_clean();
}

/// A subject past the stored bound fails the idempotency insert on its
/// CHECK, and PostgreSQL's account of that failure repeats the failing row:
/// the caller's issuer, subject, and key. The operational log names the
/// failure and none of the row: a store error displays the driver's kind of
/// failure, and the database's message and detail stay its source.
#[tokio::test]
async fn a_refused_store_write_logs_no_part_of_the_refused_row() {
    let harness = Harness::start().await;
    let subject = format!("over-long-subject-{}", "s".repeat(1024));
    let key = "a-key-the-log-never-names";
    let (status, problem) = harness
        .submit(&sender_token_for(&subject), key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");

    let logs = support::captured_logs();
    assert!(
        logs.contains("the Messaging store could not record a submission"),
        "{logs}"
    );
    for value in ["over-long-subject", key, "Failing row"] {
        assert!(!logs.contains(value), "the log names {value}: {logs}");
    }
    support::assert_logs_clean();
}

/// Give the starter's sender profile a daily limit of `limit`.
fn with_daily_limit(limit: u32) -> impl FnOnce(&std::path::Path) {
    move |package: &std::path::Path| {
        let manifest = package.join("messaging.yaml");
        let text = std::fs::read_to_string(&manifest).unwrap();
        let limited = text.replacen(
            "    burst: 10\n",
            &format!("    burst: 10\n    maximumMessagesPerDay: {limit}\n"),
            1,
        );
        assert_ne!(limited, text, "the starter's sender profile moved");
        std::fs::write(&manifest, limited).unwrap();
    }
}

#[tokio::test]
async fn a_profile_past_its_daily_limit_is_refused_across_a_restart() {
    let harness = Harness::start_with(Value::Null, with_daily_limit(3)).await;
    let sender = sender_token();
    for key in ["daily-1", "daily-2", "daily-3"] {
        let (status, receipt) = harness.submit(&sender, key, &email_submission()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    }
    // A replay answers its stored receipt and is not counted again.
    assert_eq!(
        harness
            .submit(&sender, "daily-1", &email_submission())
            .await
            .0,
        StatusCode::ACCEPTED
    );
    // The limit belongs to the profile, not the principal.
    let (status, headers, problem) = submit_to(
        harness.restarted_app().await,
        &sender_token_for(OTHER_SENDER_PRINCIPAL),
        "daily-4",
        &email_submission(),
    )
    .await;
    assert_problem(
        &(status, problem),
        StatusCode::TOO_MANY_REQUESTS,
        "quota.exceeded",
    );
    // The oldest counted acceptance leaves the window a day after it was
    // accepted, which is at most a day from now.
    let retry_after: u64 = headers
        .get("retry-after")
        .expect("a Retry-After")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((86_300..=86_400).contains(&retry_after), "{retry_after}");
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        3
    );

    // Once the oldest acceptance is a day old, one more is admitted.
    harness
        .execute(
            "UPDATE messaging_messages SET accepted_at = accepted_at - interval '1 day' \
              WHERE accepted_at = (SELECT min(accepted_at) FROM messaging_messages)",
            &[],
        )
        .await;
    assert_eq!(
        harness
            .submit(&sender, "daily-5", &email_submission())
            .await
            .0,
        StatusCode::ACCEPTED
    );
    assert_problem(
        &harness
            .submit(&sender, "daily-6", &email_submission())
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "quota.exceeded",
    );
    harness.publish().await;
    let refused: Vec<Value> = harness
        .journal()
        .into_iter()
        .filter(|entry| entry["record"]["problem"] == "quota.exceeded")
        .collect();
    assert_eq!(refused.len(), 2);
    assert!(refused
        .iter()
        .all(|entry| entry["record"]["event"] == "messaging.message.refused"));
    // Each process counts its own refusals: the restarted runtime counted
    // the first, this one the second.
    assert_eq!(
        harness
            .sample("messaging_limit_refusals_total{limit=\"daily\"}")
            .await,
        Some(1)
    );
    assert_eq!(
        harness
            .sample("messaging_limit_refusals_total{limit=\"rate\"}")
            .await,
        Some(0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_submissions_never_take_more_than_the_daily_limit() {
    let harness = Harness::start_with(Value::Null, with_daily_limit(5)).await;
    let sender = sender_token();
    let submissions = (0..12).map(|index| {
        let app = harness.app.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            submit_to(app, &sender, &format!("race-{index}"), &email_submission())
                .await
                .0
        })
    });
    let mut accepted = 0;
    let mut refused = 0;
    for submission in submissions.collect::<Vec<_>>() {
        match submission.await.unwrap() {
            StatusCode::ACCEPTED => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => refused += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!((accepted, refused), (5, 7));
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        5
    );
}

/// The advisory-lock name a profile's daily count is taken under.
const CASE_NOTICES_DAILY_LOCK: &str = "registry-messaging.daily-limit:case-notices";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_key_submissions_racing_for_the_last_daily_place_answer_one_receipt() {
    let harness = Harness::start_with(Value::Null, with_daily_limit(2)).await;
    let sender = sender_token();
    let (status, receipt) = harness.submit(&sender, "first", &email_submission()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    // Hold the profile's daily-limit lock so both submissions find no
    // record under their key before either reaches the count.
    let admin = &harness.isolated.admin;
    admin.batch_execute("BEGIN").await.unwrap();
    admin
        .execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&CASE_NOTICES_DAILY_LOCK],
        )
        .await
        .unwrap();
    let submissions: Vec<_> = (0..2)
        .map(|_| {
            let app = harness.app.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let (status, _, body) =
                    submit_to(app, &sender, "shared", &email_submission()).await;
                (status, body)
            })
        })
        .collect();
    let mut waiting = 0;
    for _ in 0..500 {
        waiting = admin
            .query_one(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        if waiting >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        waiting >= 2,
        "both submissions wait on the daily-limit lock"
    );
    admin.batch_execute("COMMIT").await.unwrap();
    let mut answers = Vec::new();
    for submission in submissions {
        answers.push(submission.await.unwrap());
    }
    for answer in &answers {
        assert_eq!(answer.0, StatusCode::ACCEPTED, "{}", answer.1);
        assert_eq!(answer.1["id"], answers[0].1["id"]);
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );
}

#[tokio::test]
async fn a_daily_limit_wait_never_exceeds_the_window() {
    let harness = Harness::start_with(Value::Null, with_daily_limit(1)).await;
    let sender = sender_token();
    let (status, receipt) = harness.submit(&sender, "first", &email_submission()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    // An acceptance committed by a transaction that started after this
    // submission's own carries a later instant than the submission's now.
    harness
        .execute(
            "UPDATE messaging_messages SET accepted_at = now() + interval '1 hour'",
            &[],
        )
        .await;
    let (status, headers, problem) =
        submit_to(harness.app.clone(), &sender, "second", &email_submission()).await;
    assert_problem(
        &(status, problem),
        StatusCode::TOO_MANY_REQUESTS,
        "quota.exceeded",
    );
    assert_eq!(headers.get("retry-after").unwrap(), "86400");
}

#[tokio::test]
async fn a_window_narrower_than_the_stored_precision_is_unprocessable() {
    let harness = Harness::start().await;
    // PostgreSQL keeps microseconds: these instants differ only below that.
    let second = (chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%S");
    let mut body = email_submission();
    body["notBefore"] = json!(format!("{second}.0000001Z"));
    body["expiresAt"] = json!(format!("{second}.0000009Z"));
    assert_problem(
        &harness.submit(&sender_token(), "narrow", &body).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "request.unprocessable",
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        0
    );
}

#[tokio::test]
async fn the_runtime_is_ready_only_while_the_ledger_names_its_package_active() {
    let harness = Harness::start().await;
    assert_eq!(harness.call("GET", "/ready", None).await.0, StatusCode::OK);

    // An operator applies another package; this runtime still serves the
    // one it loaded, so it stops answering ready until it is restarted.
    let other = format!("sha256:{}", "0".repeat(64));
    harness
        .execute(
            "INSERT INTO messaging_activations \
               (activation_id, apply_order, package_digest, predecessor_package_digest, \
                database_id, plan_kind, applied_at, role_mode) \
             SELECT gen_random_uuid(), apply_order + 1, $1, package_digest, \
                    database_id, 'successor', now(), role_mode \
               FROM messaging_activations ORDER BY apply_order DESC LIMIT 1",
            &[&other],
        )
        .await;
    let (status, problem) = harness.call("GET", "/ready", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(harness.call("GET", "/health", None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn readiness_rechecks_the_database_identity_recorded_after_startup() {
    let harness = Harness::start().await;
    assert_eq!(harness.call("GET", "/ready", None).await.0, StatusCode::OK);

    let digest = harness.package.digest().to_owned();
    harness
        .execute(
            "INSERT INTO messaging_activations \
               (activation_id, apply_order, package_digest, predecessor_package_digest, \
                database_id, plan_kind, applied_at, role_mode) \
             SELECT gen_random_uuid(), apply_order + 1, $1, package_digest, \
                    'another-deployment', 'successor', now(), role_mode \
               FROM messaging_activations ORDER BY apply_order DESC LIMIT 1",
            &[&digest],
        )
        .await;
    let (status, problem) = harness.call("GET", "/ready", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
}

/// Put one message's dispatch job in the unknown outcome an operator
/// settles.
async fn make_unknown(harness: &Harness, message_id: Uuid) {
    let changed = harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET state = 'unknown', attempt = 1, next_attempt_at = NULL \
              WHERE message_id = $1",
            &[&message_id],
        )
        .await;
    assert_eq!(changed, 1);
}

/// Make every later write to a dispatch job change nothing, as a write
/// that lost a race with another transaction does.
async fn skip_job_writes(harness: &Harness) {
    harness
        .execute(
            "CREATE FUNCTION skip_job_write() RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RETURN NULL; END $$",
            &[],
        )
        .await;
    harness
        .execute(
            "CREATE TRIGGER skip_job_write BEFORE UPDATE ON messaging_dispatch_jobs \
             FOR EACH ROW EXECUTE FUNCTION skip_job_write()",
            &[],
        )
        .await;
}

fn settlement_responses(journal: &[Value]) -> Vec<Value> {
    journal
        .iter()
        .filter(|entry| {
            entry["phase"] == "response"
                && entry["record"]["messageId"].is_string()
                && entry["record"]["event"]
                    .as_str()
                    .is_some_and(|event| event.contains("settle"))
        })
        .map(|entry| entry["record"].clone())
        .collect()
}

#[tokio::test]
async fn a_settlement_the_store_refuses_is_reported_changed_and_journaled_refused() {
    let harness = Harness::start().await;
    let message_id = harness.accepted(&email_submission()).await;
    make_unknown(&harness, message_id).await;
    skip_job_writes(&harness).await;

    let refused = harness
        .service
        .messages()
        .operate(
            message_id,
            OperatorAction::Settle(SettleOutcome::Sent),
            true,
        )
        .await
        .expect_err("a settlement that changed no row is refused");
    assert!(matches!(refused, MessageStoreError::Refused), "{refused}");
    assert_eq!(harness.state(message_id).await, "unknown");
    let responses = settlement_responses(&harness.journal());
    assert_eq!(responses.len(), 1, "{responses:?}");
    assert_eq!(responses[0]["outcome"], "refused");
}

#[tokio::test]
async fn a_dispatch_core_refusal_is_reported_as_an_outcome_that_may_have_applied() {
    let harness = Harness::start().await;
    let message_id = harness.accepted(&email_submission()).await;
    skip_job_writes(&harness).await;

    let unknown = harness
        .service
        .messages()
        .operate(message_id, OperatorAction::Cancel, true)
        .await
        .expect_err("the dispatch core refuses a cancellation that changed no row");
    assert!(
        matches!(unknown, MessageStoreError::OutcomeUnknown),
        "{unknown}"
    );
}

/// A message store over the harness's schema whose audit writer accepts
/// only its first `accepted_writes` records.
async fn store_with_audit(harness: &Harness, accepted_writes: usize) -> MessageStore {
    let audit = test_audit(AuditWriter::from_line_sink(Box::new(
        RefusingAuditSink::after(accepted_writes),
    )));
    let schema = harness.store.current_schema().await.unwrap();
    MessageStore::new(
        harness.store.clone(),
        dispatcher(
            harness.store.clone(),
            &schema,
            Arc::clone(&harness.transports),
            Arc::clone(&audit),
        )
        .unwrap(),
        audit,
    )
}

#[tokio::test]
async fn a_settlement_whose_request_record_is_refused_changes_nothing() {
    let harness = Harness::start().await;
    let message_id = harness.accepted(&email_submission()).await;
    make_unknown(&harness, message_id).await;

    let refused = store_with_audit(&harness, 0)
        .await
        .operate(
            message_id,
            OperatorAction::Settle(SettleOutcome::Sent),
            true,
        )
        .await
        .expect_err("a settlement requires its request record");
    assert!(
        matches!(refused, MessageStoreError::AuditUnavailable),
        "{refused}"
    );
    assert_eq!(harness.state(message_id).await, "unknown");
}

#[tokio::test]
async fn a_settlement_whose_outcome_record_is_refused_is_applied_and_unconfirmed() {
    let harness = Harness::start().await;
    let message_id = harness.accepted(&email_submission()).await;
    make_unknown(&harness, message_id).await;

    let unconfirmed = store_with_audit(&harness, 1)
        .await
        .operate(
            message_id,
            OperatorAction::Settle(SettleOutcome::Sent),
            true,
        )
        .await
        .expect_err("the outcome record is written after the commit");
    assert!(
        matches!(unconfirmed, MessageStoreError::AuditUnconfirmed),
        "{unconfirmed}"
    );
    assert_eq!(harness.state(message_id).await, "delivered");
}

#[tokio::test]
async fn original_receipt_reads_preserve_ownership_request_expiry_and_product_state() {
    let harness = Harness::start().await;
    let body = email_submission();
    let key = "original-receipt-canary-key";
    let (status, original) = harness.submit(&sender_token(), key, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = Uuid::parse_str(original["id"].as_str().unwrap()).unwrap();
    let before = harness
        .count("SELECT count(*) FROM messaging_messages")
        .await;
    async fn lookup(h: &Harness, bearer: &str, key: &str, body: &Value) -> (StatusCode, Value) {
        h.send(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/receipt")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
    }
    let answer = lookup(&harness, &sender_token(), key, &body).await;
    assert_eq!(answer, (StatusCode::OK, original));
    let mut changed = body.clone();
    changed["data"]["name"] = json!("receipt-sensitive-canary");
    for (bearer, command_key, request) in [
        (sender_token_for(OTHER_SENDER_PRINCIPAL), key, body.clone()),
        (sender_token(), "unseen-receipt-key", body.clone()),
        (sender_token(), key, changed),
    ] {
        assert_problem(
            &lookup(&harness, &bearer, command_key, &request).await,
            StatusCode::CONFLICT,
            "receipt.unresolved",
        );
    }
    harness.isolated.admin.execute("UPDATE messaging_idempotency SET expires_at=transaction_timestamp()-interval '1 second' WHERE message_id=$1", &[&id]).await.unwrap();
    assert_problem(
        &lookup(&harness, &sender_token(), key, &body).await,
        StatusCode::CONFLICT,
        "receipt.unresolved",
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        before
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        1
    );
    assert_eq!(harness.state(id).await, "pending");
    let audit = serde_json::to_string(&harness.audit_responses().await).unwrap();
    assert!(!audit.contains("receipt-sensitive-canary"));
    assert!(!audit.contains(key));
}

#[tokio::test]
async fn original_receipt_reads_neither_spend_nor_require_submission_budget() {
    let harness = Harness::start().await;
    let body = email_submission();
    let sender = sender_token();
    let key = "receipt-before-rate-limit";
    let (status, original) = harness.submit(&sender, key, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let profiles = AccessProfiles::new(
        harness
            .package
            .access_profiles()
            .iter()
            .cloned()
            .map(|mut profile| {
                profile.requests_per_minute = 1;
                profile.burst = 1;
                profile
            })
            .collect(),
    )
    .unwrap();
    let app = harness
        .app_with_caller_limits(registry_messaging::limits::CallerLimits::new(&profiles).unwrap())
        .await;
    for after_submission in [false, true] {
        if after_submission {
            let (status, _, _) = submit_to(app.clone(), &sender, "one-budgeted-send", &body).await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }
        for _ in 0..3 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/messages/receipt")
                        .header("authorization", format!("Bearer {sender}"))
                        .header("content-type", "application/json")
                        .header("idempotency-key", key)
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), original);
        }
    }
    let (status, _, problem) = submit_to(app, &sender, "send-over-budget", &body).await;
    assert_problem(
        &(status, problem),
        StatusCode::TOO_MANY_REQUESTS,
        "rate-limit.exceeded",
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        2
    );
}

#[tokio::test]
async fn original_receipt_disclosure_requires_both_audit_entries() {
    let harness = Harness::start().await;
    let body = email_submission();
    let key = "audit-gated-original-receipt";
    assert_eq!(
        harness.submit(&sender_token(), key, &body).await.0,
        StatusCode::ACCEPTED
    );
    for accepted_writes in [0, 1] {
        let audit = test_audit(AuditWriter::from_line_sink(Box::new(
            RefusingAuditSink::after(accepted_writes),
        )));
        let app = harness.app_with_audit(audit).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/receipt")
                    .header("authorization", format!("Bearer {}", sender_token()))
                    .header("content-type", "application/json")
                    .header("idempotency-key", key)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let problem: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["code"], "service.unavailable");
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        1
    );
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        1
    );
}
