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

use std::time::Duration;

use axum::http::StatusCode;
use registry_platform_dispatch::postgres::Claim;
use serde_json::{json, Value};
use support::{
    email_submission, operator_token, sender_token, sender_token_for, sms_submission, submit_to,
    token, Harness, NAME, OTHER_SENDER_PRINCIPAL, RECIPIENT,
};
use uuid::Uuid;

fn assert_problem(answer: &(StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(answer.1["code"], code, "{}", answer.1);
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
    let outbox = harness.outbox().await;
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0]["event"], "messaging.message.accepted");
    assert_eq!(outbox[0]["messageId"], id);
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
              WHERE idempotency_key = 'key-1' AND subject = $1",
            &[&support::SENDER_PRINCIPAL],
        )
        .await;
    // An expired key answers expired whether or not the body matches.
    for body in [email_submission(), different] {
        assert_problem(
            &harness.submit(&sender, "key-1", &body).await,
            StatusCode::GONE,
            "idempotency.expired",
        );
    }
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
    let outbox = harness.outbox().await.len();
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

    assert_eq!(harness.outbox().await.len(), outbox);
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
    assert_eq!(cancelled.len(), 1, "{cancelled:?}");
    assert_eq!(cancelled[0]["record"]["actor"]["kind"], "caller");
    assert_eq!(
        cancelled[0]["record"]["actor"]["accessProfile"],
        "case-notices"
    );
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
    support::assert_absent("the outbox", &Value::Array(harness.outbox().await));
    support::assert_logs_clean();
}

/// Give the starter's sender profile a daily limit of `limit`.
fn with_daily_limit(limit: u32) -> impl FnOnce(&std::path::Path) {
    move |package: &std::path::Path| {
        let manifest = package.join("messaging.yaml");
        let text = std::fs::read_to_string(&manifest).unwrap();
        let limited = text.replacen(
            "    burst: 10\n",
            &format!("    burst: 10\n    dailyLimit: {limit}\n"),
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

#[tokio::test]
async fn the_runtime_is_ready_only_while_the_ledger_names_its_package_active() {
    let harness = Harness::start().await;
    assert_eq!(harness.call("GET", "/ready", None).await.0, StatusCode::OK);

    // An operator applies another package; this runtime still serves the
    // one it loaded, so it stops answering ready until it is restarted.
    let other = format!("sha256:{}", "0".repeat(64));
    harness
        .execute(
            "INSERT INTO messaging_package_ledger (package_digest, runtime_version, activated_at) \
             VALUES ($1, 'test', now())",
            &[&other],
        )
        .await;
    let (status, problem) = harness.call("GET", "/ready", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");
    assert_eq!(harness.call("GET", "/health", None).await.0, StatusCode::OK);
}
