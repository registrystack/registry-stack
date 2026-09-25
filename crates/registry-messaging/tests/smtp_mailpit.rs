// SPDX-License-Identifier: Apache-2.0

//! The SMTP provider against a real relay: a Mailpit container reached over
//! development loopback plaintext. Each test sends one message and reads it
//! back through Mailpit's HTTP API.
//!
//! The relay is named by `MESSAGING_SMTP_TEST_MAILPIT_SMTP` (such as
//! `127.0.0.1:1025`) and its API by `MESSAGING_SMTP_TEST_MAILPIT_API` (such as
//! `http://127.0.0.1:8025`). A suite that passes because its relay is absent
//! is not relay verification, so both are required: without them every test
//! in this file fails on the spot.

use std::net::SocketAddr;
use std::time::Duration;

use registry_messaging::smtp::{
    SmtpMessage, SmtpProvider, SmtpProviderSettings, SmtpStage, SmtpTlsMode,
};
use registry_messaging_core::RenderedParts;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_dispatch::SendOutcome;
use serde_json::Value;
use uuid::Uuid;

const SENDER: &str = "notices@agency.example";
const RECIPIENT: &str = "resident.4471@citizen.example";

fn relay() -> SocketAddr {
    std::env::var("MESSAGING_SMTP_TEST_MAILPIT_SMTP")
        .expect("MESSAGING_SMTP_TEST_MAILPIT_SMTP names a Mailpit SMTP listener")
        .parse()
        .expect("MESSAGING_SMTP_TEST_MAILPIT_SMTP is an IP address and port")
}

fn api() -> String {
    std::env::var("MESSAGING_SMTP_TEST_MAILPIT_API")
        .expect("MESSAGING_SMTP_TEST_MAILPIT_API names the Mailpit HTTP API")
        .trim_end_matches('/')
        .to_owned()
}

fn provider() -> SmtpProvider {
    let relay = relay();
    let settings = SmtpProviderSettings {
        host: relay.ip().to_string(),
        port: Some(relay.port()),
        tls: SmtpTlsMode::DevelopmentLoopback,
        trusted_root_certificate_ref: None,
        authentication: None,
        attempt_timeout_seconds: 10,
        allowed_private_cidrs: Vec::new(),
    };
    let secrets = SecretResolver::new([SecretProvider::Environment], "/").expect("resolver");
    settings.activate(&secrets, false).expect("activation")
}

/// Send one message and return Mailpit's full view of it.
async fn send_and_read(parts: &RenderedParts) -> (String, Value) {
    let message_id = Uuid::new_v4().simple().to_string();
    let sent = provider()
        .send(&SmtpMessage {
            message_id: &message_id,
            from: SENDER,
            to: RECIPIENT,
            parts,
        })
        .await;
    assert!(
        matches!(sent.outcome, SendOutcome::Accepted { .. }),
        "{sent:?}"
    );
    assert_eq!(sent.detail.stage, SmtpStage::EndOfData);
    assert_eq!(sent.detail.reply_code, Some(250));

    let header = format!("{message_id}@agency.example");
    let client = reqwest::Client::new();
    let summary = client
        .get(format!("{}/api/v1/search", api()))
        .query(&[("query", format!("message-id:\"{header}\""))])
        .send()
        .await
        .expect("Mailpit search")
        .error_for_status()
        .expect("Mailpit search status")
        .json::<Value>()
        .await
        .expect("Mailpit search body");
    let messages = summary["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1, "{summary}");
    let id = messages[0]["ID"].as_str().expect("Mailpit id");
    let message = client
        .get(format!("{}/api/v1/message/{id}", api()))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("Mailpit message")
        .error_for_status()
        .expect("Mailpit message status")
        .json::<Value>()
        .await
        .expect("Mailpit message body");
    (header, message)
}

/// A part as the recipient reads it: SMTP carries CRLF line endings, so the
/// part's own LF endings come back as CRLF.
fn body(part: &Value) -> Option<String> {
    part.as_str()
        .map(|text| text.replace("\r\n", "\n").trim_end().to_owned())
}

fn assert_envelope(message: &Value, header: &str, subject: &str) {
    assert_eq!(message["MessageID"], header, "{message}");
    assert_eq!(message["From"]["Address"], SENDER);
    let to = message["To"].as_array().expect("To array");
    assert_eq!(to.len(), 1, "{message}");
    assert_eq!(to[0]["Address"], RECIPIENT);
    assert!(message["Cc"].as_array().is_none_or(Vec::is_empty));
    assert!(message["Bcc"].as_array().is_none_or(Vec::is_empty));
    assert_eq!(message["Subject"], subject);
}

#[tokio::test]
async fn a_message_with_text_and_html_arrives_whole() {
    let parts = RenderedParts {
        subject: Some("Votre rendez-vous de mardi à Riverside".to_owned()),
        text: "Apportez le formulaire 12-B au bureau de Riverside.\n\n.Une ligne qui commence par un point."
            .to_owned(),
        html: Some(
            "<p>Apportez le <strong>formulaire 12-B</strong> au bureau de Riverside.</p>"
                .to_owned(),
        ),
    };
    let (header, message) = send_and_read(&parts).await;
    assert_envelope(&message, &header, "Votre rendez-vous de mardi à Riverside");
    assert_eq!(body(&message["Text"]), Some(parts.text.clone()));
    assert_eq!(body(&message["HTML"]), parts.html.clone());
}

#[tokio::test]
async fn a_text_only_message_arrives_without_html() {
    let parts = RenderedParts {
        subject: Some("Reminder".to_owned()),
        text: "Your appointment is on Tuesday.".to_owned(),
        html: None,
    };
    let (header, message) = send_and_read(&parts).await;
    assert_envelope(&message, &header, "Reminder");
    assert_eq!(body(&message["Text"]), Some(parts.text.clone()));
    assert_eq!(message["HTML"], "");
}
