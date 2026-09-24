// SPDX-License-Identifier: Apache-2.0

//! Database-backed provider callback tests (spec 7.4): a callback the
//! provider's configured verifier accepts is read by the package's receipt
//! script and applied to the message whose attempt carries the reference, in
//! one transaction with its audit record; one it refuses changes nothing.
//!
//! Each message is sent through the starter's `sms-gateway` HTTP provider,
//! activated as the runtime activates it, against a loopback gateway that
//! answers every send with a reference derived from the message id. The
//! callbacks then go through the public router, as a provider's would.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::hmac;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use registry_messaging::dispatch::{dispatcher, MessageDispatcher, MessageSender};
use registry_messaging::receipts::{MAXIMUM_STORED_RECEIPTS, RECEIPT_RECORDED_EVENT};
use registry_messaging_core::MessageStatus;
use registry_platform_dispatch::postgres::DispatchOutcome;
use serde_json::{json, Value};
use support::{
    assert_absent, assert_logs_clean, captured_logs, sender_token, sms_submission, Harness,
};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request as GatewayRequest, ResponseTemplate};

const CALLBACK_ROUTE: &str = "/v1/provider-callbacks/sms-gateway";
/// The external URL an `hmac-sha1-url-form` provider is given and signs.
const EXTERNAL_CALLBACK_URL: &str =
    "https://messaging.example.org/v1/provider-callbacks/sms-gateway";
const BODY_SECRET: &str = "a-body-signing-secret-for-callbacks";
const FORM_SECRET: &str = "a-form-signing-secret-for-callbacks";
const PATH_TOKEN: &str = "a-path-token-for-callbacks-6c02e1";
const SIGNATURE_HEADER: &str = "x-gateway-signature";
const FORM_SIGNATURE_HEADER: &str = "x-form-signature";

/// Which verifier the deployment configures for `sms-gateway`.
#[derive(Clone, Copy, Debug)]
enum Verifier {
    Body,
    Form,
    PathToken,
}

/// A deployment whose `sms-gateway` sends to a loopback gateway and
/// receives callbacks under `verifier`, with the worker that sends through it.
struct Deployment {
    harness: Harness,
    _gateway: MockServer,
    dispatcher: MessageDispatcher,
    sender: MessageSender,
    verifier: Verifier,
}

/// An environment variable holding `value`, as the secret reference that
/// resolves it.
fn secret(value: &str) -> String {
    let name = format!("MESSAGING_CALLBACK_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&name, value);
    format!("secret:env/{name}")
}

fn verifier_config(verifier: Verifier) -> Value {
    match verifier {
        Verifier::Body => json!({
            "kind": "hmac-sha256-body",
            "header": SIGNATURE_HEADER,
            "encoding": "hex",
            "secretRef": secret(BODY_SECRET)
        }),
        Verifier::Form => json!({
            "kind": "hmac-sha1-url-form",
            "url": EXTERNAL_CALLBACK_URL,
            "header": FORM_SIGNATURE_HEADER,
            "secretRef": secret(FORM_SECRET)
        }),
        Verifier::PathToken => json!({"kind": "path-token", "tokenRef": secret(PATH_TOKEN)}),
    }
}

/// The reference the gateway answers for the message whose id it was sent.
fn reference_for(message_id: Uuid) -> String {
    format!("gw-{message_id}")
}

async fn deployment(verifier: Verifier) -> Deployment {
    let gateway = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(|request: &GatewayRequest| {
            let message_id = request
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .expect("the prepare script names the message");
            ResponseTemplate::new(200).set_body_json(json!({"id": format!("gw-{message_id}")}))
        })
        .mount(&gateway)
        .await;
    let providers = json!({"sms-gateway": {
        "kind": "http",
        "baseUrl": format!("{}/v1/", gateway.uri()),
        "timeoutMilliseconds": 5000,
        "maximumResponseBytes": 65536,
        "concurrencyLimit": 4,
        "redirects": "deny",
        "authentication": {"kind": "none"},
        "callbackVerifier": verifier_config(verifier)
    }});
    let harness = Harness::start_with(providers, |package: &Path| {
        if matches!(verifier, Verifier::Form) {
            let form = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/messaging/examples/providers/form-sms-gateway/scripts");
            std::fs::copy(
                form.join("receipt.rhai"),
                package.join("providers/sms-gateway/scripts/receipt.rhai"),
            )
            .expect("the form receipt script");
        }
    })
    .await;
    let dispatcher = dispatcher(
        harness.store.clone(),
        &harness.isolated.schema,
        Arc::clone(&harness.transports),
    )
    .unwrap();
    let sender = MessageSender::new(dispatcher.clone(), Arc::clone(&harness.transports));
    Deployment {
        harness,
        _gateway: gateway,
        dispatcher,
        sender,
        verifier,
    }
}

impl Deployment {
    /// Accept one SMS and send it, so its attempt carries the gateway's
    /// reference.
    async fn sent(&self) -> Uuid {
        let id = self.harness.accepted(&sms_submission()).await;
        assert_eq!(
            self.dispatcher.dispatch_once(&self.sender).await.unwrap(),
            DispatchOutcome::Delivered
        );
        let stored: Option<String> = self
            .harness
            .isolated
            .admin
            .query_one(
                "SELECT provider_reference FROM messaging_attempts WHERE message_id = $1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored, Some(reference_for(id)));
        id
    }

    /// A callback reporting `status` for `reference`, signed or carrying the
    /// token as the verifier requires, or forged when `forged`.
    fn callback(
        &self,
        reference: &str,
        status: &str,
        code: Option<&str>,
        forged: bool,
    ) -> Request<Body> {
        match self.verifier {
            Verifier::Body => {
                let mut report = json!({"id": reference, "status": status});
                if let Some(code) = code {
                    report["code"] = json!(code);
                }
                let body = serde_json::to_vec(&report).unwrap();
                let secret = if forged {
                    "not-the-secret"
                } else {
                    BODY_SECRET
                };
                let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()), &body);
                Request::builder()
                    .method("POST")
                    .uri(CALLBACK_ROUTE)
                    .header(CONTENT_TYPE, "application/json")
                    .header(SIGNATURE_HEADER, hex::encode(tag.as_ref()))
                    .body(Body::from(body))
                    .unwrap()
            }
            Verifier::Form => {
                let mut parameters = vec![
                    ("MessageSid", reference.to_owned()),
                    ("MessageStatus", status.to_owned()),
                    ("To", "+15550009999".to_owned()),
                ];
                if let Some(code) = code {
                    parameters.push(("ErrorCode", code.to_owned()));
                }
                let mut signed = EXTERNAL_CALLBACK_URL.to_owned();
                let mut sorted = parameters.clone();
                sorted.sort_by(|left, right| left.0.cmp(right.0));
                for (name, value) in &sorted {
                    signed.push_str(name);
                    signed.push_str(value);
                }
                let secret = if forged {
                    "not-the-secret"
                } else {
                    FORM_SECRET
                };
                let tag = hmac::sign(
                    &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes()),
                    signed.as_bytes(),
                );
                let body = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(
                        parameters
                            .iter()
                            .map(|(name, value)| (*name, value.as_str())),
                    )
                    .finish();
                Request::builder()
                    .method("POST")
                    .uri(CALLBACK_ROUTE)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(FORM_SIGNATURE_HEADER, STANDARD.encode(tag.as_ref()))
                    .body(Body::from(body))
                    .unwrap()
            }
            Verifier::PathToken => {
                let mut report = json!({"id": reference, "status": status});
                if let Some(code) = code {
                    report["code"] = json!(code);
                }
                let token = if forged {
                    "not-the-path-token"
                } else {
                    PATH_TOKEN
                };
                Request::builder()
                    .method("POST")
                    .uri(format!("{CALLBACK_ROUTE}/{token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&report).unwrap()))
                    .unwrap()
            }
        }
    }

    async fn report(
        &self,
        reference: &str,
        status: &str,
        code: Option<&str>,
    ) -> (StatusCode, Value) {
        self.harness
            .send(self.callback(reference, status, code, false))
            .await
    }

    /// The stored report of one message and whether its time is set with it.
    async fn stored_report(&self, message_id: Uuid) -> Option<String> {
        let row = self
            .harness
            .isolated
            .admin
            .query_one(
                "SELECT report, report_at IS NOT NULL FROM messaging_messages \
                  WHERE message_id = $1",
                &[&message_id],
            )
            .await
            .unwrap();
        let report: Option<String> = row.get(0);
        let timed: bool = row.get(1);
        assert_eq!(report.is_some(), timed);
        report
    }

    /// The stored receipts of one message, in order: report, code, applied.
    async fn receipts(&self, message_id: Uuid) -> Vec<(String, Option<String>, bool)> {
        self.harness
            .isolated
            .admin
            .query(
                "SELECT report, code, applied FROM messaging_receipts \
                  WHERE message_id = $1 ORDER BY sequence",
                &[&message_id],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    /// The message as its submitter reads it over the public route.
    async fn view(&self, message_id: Uuid) -> Value {
        let (status, view) = self
            .harness
            .call(
                "GET",
                &format!("/v1/messages/{message_id}"),
                Some(&sender_token()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        view
    }

    /// The ids the operator listing names for `status`.
    async fn listed(&self, status: MessageStatus) -> Vec<String> {
        self.harness
            .service
            .messages()
            .list(Some(status), 100)
            .await
            .unwrap()
            .into_iter()
            .map(|summary| summary.id)
            .collect()
    }

    /// The receipt records in the outbox.
    async fn receipt_records(&self) -> Vec<Value> {
        self.harness
            .outbox()
            .await
            .into_iter()
            .filter(|record| record["event"] == RECEIPT_RECORDED_EVENT)
            .collect()
    }

    fn counted(&self, outcome: &str) -> u64 {
        let rendered = self.harness.metrics.render();
        let prefix = format!("messaging_provider_callbacks_total{{outcome=\"{outcome}\"}} ");
        rendered
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("no {outcome} counter in {rendered}"))
            .parse()
            .unwrap()
    }
}

/// Neither a log line nor a journal record carries the provider reference,
/// a callback secret, or the path token, beside the suite's forbidden values.
fn assert_nothing_leaked(deployment: &Deployment, references: &[String]) {
    assert_logs_clean();
    let logs = captured_logs();
    for secret in [BODY_SECRET, FORM_SECRET, PATH_TOKEN] {
        assert!(
            !logs.contains(secret),
            "a log line carries a callback secret"
        );
    }
    for reference in references {
        assert!(
            !logs.contains(reference.as_str()),
            "a log line carries a provider reference"
        );
    }
    let journal = Value::Array(deployment.harness.journal());
    assert_absent("the journal", &journal);
    let text = journal.to_string();
    for value in references
        .iter()
        .map(String::as_str)
        .chain([BODY_SECRET, FORM_SECRET, PATH_TOKEN])
    {
        assert!(!text.contains(value), "the journal carries {value:?}");
    }
}

async fn a_verified_callback_is_applied_and_a_forged_one_changes_nothing(verifier: Verifier) {
    let deployment = deployment(verifier).await;
    let id = deployment.sent().await;
    let reference = reference_for(id);
    let view = deployment.view(id).await;
    assert_eq!(
        (&view["status"], &view["dispatch"], &view["report"]),
        (&json!("submitted"), &json!("submitted"), &json!("none"))
    );
    assert!(view.get("reportedAt").is_none(), "{view}");
    let (status, body) = deployment
        .harness
        .send(deployment.callback(&reference, "delivered", None, true))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "callback.unverified");
    assert_eq!(deployment.stored_report(id).await, None);
    assert!(deployment.receipts(id).await.is_empty());
    assert!(deployment.receipt_records().await.is_empty());
    assert_eq!(deployment.counted("unverified"), 1);

    let (status, body) = deployment.report(&reference, "delivered", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(body, Value::Null);
    assert_eq!(
        deployment.stored_report(id).await.as_deref(),
        Some("delivered")
    );
    assert_eq!(
        deployment.receipts(id).await,
        vec![("delivered".to_owned(), None, true)]
    );
    let records = deployment.receipt_records().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["messageId"], id.to_string());
    assert_eq!(records[0]["provider"], "sms-gateway");
    assert_eq!(records[0]["report"], "delivered");
    assert_eq!(records[0]["applied"], true);
    assert_eq!(records[0]["from"], Value::Null);
    assert_eq!(records[0]["disposition"], "delivered");
    assert_eq!(deployment.counted("applied"), 1);

    // The submitter now reads the message as delivered, and the operator
    // listing files it there and no longer under submitted.
    let view = deployment.view(id).await;
    assert_eq!(
        (&view["status"], &view["dispatch"], &view["report"]),
        (
            &json!("delivered"),
            &json!("submitted"),
            &json!("delivered")
        )
    );
    assert!(view["reportedAt"].is_string(), "{view}");
    assert_eq!(
        deployment.listed(MessageStatus::Delivered).await,
        vec![id.to_string()]
    );
    assert!(deployment.listed(MessageStatus::Submitted).await.is_empty());

    deployment.harness.publish().await;
    assert!(deployment
        .harness
        .journal()
        .iter()
        .any(|record| record.to_string().contains(RECEIPT_RECORDED_EVENT)));
    assert_nothing_leaked(&deployment, &[reference]);
}

#[tokio::test]
async fn an_hmac_sha256_body_callback_is_applied_and_a_forged_one_is_unverified() {
    a_verified_callback_is_applied_and_a_forged_one_changes_nothing(Verifier::Body).await;
}

#[tokio::test]
async fn an_hmac_sha1_url_form_callback_is_applied_and_a_forged_one_is_unverified() {
    a_verified_callback_is_applied_and_a_forged_one_changes_nothing(Verifier::Form).await;
}

#[tokio::test]
async fn a_path_token_callback_is_applied_and_a_wrong_token_is_unverified() {
    a_verified_callback_is_applied_and_a_forged_one_changes_nothing(Verifier::PathToken).await;
}

#[tokio::test]
async fn duplicate_and_out_of_order_receipts_never_regress_the_report() {
    let deployment = deployment(Verifier::Body).await;
    let id = deployment.sent().await;
    let reference = reference_for(id);
    let steps = [
        ("sent", None, Some("sent")),
        ("sent", None, Some("sent")),
        ("delivered", None, Some("delivered")),
        ("sent", None, Some("delivered")),
        ("failed", Some("gateway.expired"), Some("delivered")),
        ("delivered", None, Some("delivered")),
    ];
    for (status, code, expected) in steps {
        let (answer, body) = deployment.report(&reference, status, code).await;
        assert_eq!(answer, StatusCode::NO_CONTENT, "{status}: {body}");
        assert_eq!(deployment.stored_report(id).await.as_deref(), expected);
    }
    assert_eq!(
        deployment.receipts(id).await,
        vec![
            ("sent".to_owned(), None, true),
            ("delivered".to_owned(), None, true),
            (
                "undelivered".to_owned(),
                Some("gateway.expired".to_owned()),
                false
            ),
        ]
    );
    // One record for each receipt that joined the history or moved the
    // report; the exact duplicates wrote none.
    let records = deployment.receipt_records().await;
    let summary: Vec<(Value, Value, Value)> = records
        .iter()
        .map(|record| {
            (
                record["report"].clone(),
                record["applied"].clone(),
                record["disposition"].clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (json!("sent"), json!(true), json!("sent")),
            (json!("delivered"), json!(true), json!("delivered")),
            (json!("undelivered"), json!(false), json!("delivered")),
        ]
    );
    assert_eq!(records[2]["code"], "gateway.expired");
    assert_eq!(records[2]["from"], "delivered");
    assert_eq!(deployment.counted("applied"), 2);
    assert_eq!(deployment.counted("unchanged"), 4);

    deployment.harness.publish().await;
    assert_nothing_leaked(&deployment, &[reference]);
}

#[tokio::test]
async fn a_final_undelivered_report_is_not_replaced_by_a_late_delivered_one() {
    let deployment = deployment(Verifier::PathToken).await;
    let id = deployment.sent().await;
    let reference = reference_for(id);
    for status in ["failed", "delivered", "sent"] {
        let (answer, body) = deployment.report(&reference, status, None).await;
        assert_eq!(answer, StatusCode::NO_CONTENT, "{body}");
    }
    assert_eq!(
        deployment.stored_report(id).await.as_deref(),
        Some("undelivered")
    );
    assert_eq!(
        deployment.receipts(id).await,
        vec![
            ("undelivered".to_owned(), None, true),
            ("delivered".to_owned(), None, false),
            ("sent".to_owned(), None, false),
        ]
    );
    // A submitted message the provider could not deliver has failed.
    let view = deployment.view(id).await;
    assert_eq!(
        (&view["status"], &view["dispatch"], &view["report"]),
        (&json!("failed"), &json!("submitted"), &json!("undelivered"))
    );
    assert_eq!(
        deployment.listed(MessageStatus::Failed).await,
        vec![id.to_string()]
    );
    assert!(deployment.listed(MessageStatus::Delivered).await.is_empty());
    assert!(deployment.listed(MessageStatus::Submitted).await.is_empty());
}

#[tokio::test]
async fn a_message_keeps_a_bounded_history_of_distinct_receipts() {
    let deployment = deployment(Verifier::Body).await;
    let id = deployment.sent().await;
    let reference = reference_for(id);
    let (answer, _) = deployment.report(&reference, "delivered", None).await;
    assert_eq!(answer, StatusCode::NO_CONTENT);
    for index in 0..MAXIMUM_STORED_RECEIPTS + 4 {
        let code = format!("gateway.late-{index}");
        let (answer, body) = deployment.report(&reference, "failed", Some(&code)).await;
        assert_eq!(answer, StatusCode::NO_CONTENT, "{body}");
    }
    let receipts = deployment.receipts(id).await;
    assert_eq!(
        receipts.len(),
        usize::try_from(MAXIMUM_STORED_RECEIPTS).unwrap()
    );
    assert_eq!(receipts[0], ("delivered".to_owned(), None, true));
    assert_eq!(
        deployment.stored_report(id).await.as_deref(),
        Some("delivered")
    );
    // A receipt past the bound neither joins the history nor is audited.
    assert_eq!(
        deployment.receipt_records().await.len(),
        usize::try_from(MAXIMUM_STORED_RECEIPTS).unwrap()
    );
}

#[tokio::test]
async fn a_verified_receipt_naming_no_message_is_received_and_counted() {
    let deployment = deployment(Verifier::Body).await;
    let id = deployment.sent().await;
    for reference in ["gw-no-such-message", &"r".repeat(129)] {
        let (answer, body) = deployment.report(reference, "delivered", None).await;
        assert_eq!(answer, StatusCode::NO_CONTENT, "{body}");
    }
    assert_eq!(deployment.counted("unmatched"), 2);
    assert_eq!(deployment.stored_report(id).await, None);
    assert_eq!(
        deployment
            .harness
            .count("SELECT count(*) FROM messaging_receipts")
            .await,
        0
    );
    assert!(deployment.receipt_records().await.is_empty());
}

#[tokio::test]
async fn a_reference_scoped_to_another_provider_names_nothing() {
    let deployment = deployment(Verifier::Body).await;
    let id = deployment.sent().await;
    let reference = reference_for(id);
    deployment
        .harness
        .execute(
            "UPDATE messaging_messages SET provider = 'mail-relay' WHERE message_id = $1",
            &[&id],
        )
        .await;
    let (answer, _) = deployment.report(&reference, "delivered", None).await;
    assert_eq!(answer, StatusCode::NO_CONTENT);
    assert_eq!(deployment.counted("unmatched"), 1);
    assert_eq!(deployment.stored_report(id).await, None);
}

#[tokio::test]
async fn a_reference_two_messages_carry_is_received_and_applied_to_neither() {
    let deployment = deployment(Verifier::Body).await;
    let first = deployment.sent().await;
    let second = deployment.sent().await;
    let reference = reference_for(first);
    deployment
        .harness
        .execute(
            "UPDATE messaging_attempts SET provider_reference = $2 WHERE message_id = $1",
            &[&second, &reference],
        )
        .await;
    let (answer, _) = deployment.report(&reference, "delivered", None).await;
    assert_eq!(answer, StatusCode::NO_CONTENT);
    assert_eq!(deployment.counted("ambiguous"), 1);
    assert_eq!(deployment.stored_report(first).await, None);
    assert_eq!(deployment.stored_report(second).await, None);
    assert!(deployment.receipt_records().await.is_empty());
}

#[tokio::test]
async fn a_verified_callback_the_script_cannot_read_or_does_not_record() {
    let deployment = deployment(Verifier::Body).await;
    let id = deployment.sent().await;
    let body = br#"{"unexpected": true}"#.to_vec();
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, BODY_SECRET.as_bytes()),
        &body,
    );
    let request = Request::builder()
        .method("POST")
        .uri(CALLBACK_ROUTE)
        .header(CONTENT_TYPE, "application/json")
        .header(SIGNATURE_HEADER, hex::encode(tag.as_ref()))
        .body(Body::from(body))
        .unwrap();
    let (answer, problem) = deployment.harness.send(request).await;
    assert_eq!(answer, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(problem["code"], "callback.unreadable");
    assert_eq!(deployment.counted("unreadable"), 1);

    // An intermediate state the script reports as nothing is received.
    let (answer, _) = deployment.report(&reference_for(id), "queued", None).await;
    assert_eq!(answer, StatusCode::NO_CONTENT);
    assert_eq!(deployment.counted("ignored"), 1);
    assert_eq!(deployment.stored_report(id).await, None);
    assert!(deployment.receipts(id).await.is_empty());
}
