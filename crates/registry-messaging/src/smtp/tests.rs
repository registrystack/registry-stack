// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use registry_messaging_core::RenderedParts;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_dispatch::SendOutcome;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

use super::settings::tests::{development, write_secret};
use super::stub::{Act, Script, Stub};
use super::*;

const MESSAGE_ID: &str = "0192f1d6-7c1a-7b4e-9a51-3f0c2e8d4b10";
const SENDER: &str = "notices@agency.example";
const RECIPIENT: &str = "resident.4471@citizen.example";
const SUBJECT: &str = "Your appointment on Tuesday";
const TEXT: &str = "Bring form 12-B to the Riverside office.";
const HTML: &str = "<p>Bring <strong>form 12-B</strong> to the Riverside office.</p>";
const TLS_HOST: &str = "smtp.relay.example";

fn parts(html: bool) -> RenderedParts {
    RenderedParts {
        subject: Some(SUBJECT.to_owned()),
        text: TEXT.to_owned(),
        html: html.then(|| HTML.to_owned()),
    }
}

fn message(parts: &RenderedParts) -> SmtpMessage<'_> {
    SmtpMessage {
        message_id: MESSAGE_ID,
        from: SENDER,
        to: RECIPIENT,
        parts,
    }
}

fn no_secrets() -> SecretResolver {
    SecretResolver::new([SecretProvider::Environment], "/").expect("resolver")
}

/// A plaintext provider for a loopback stub.
fn loopback(stub: &Stub) -> SmtpProvider {
    loopback_with(stub, |_| {})
}

fn loopback_with(stub: &Stub, adjust: impl FnOnce(&mut SmtpProviderSettings)) -> SmtpProvider {
    let mut settings = development("127.0.0.1");
    settings.port = Some(stub.address.port());
    adjust(&mut settings);
    settings.activate(&no_secrets()).expect("activation")
}

/// A TLS provider for the public host [`TLS_HOST`], whose checked answers are
/// redirected to the stub.
fn scripted(
    settings: &SmtpProviderSettings,
    secrets: &SecretResolver,
    answers: &[IpAddr],
    stub: SocketAddr,
) -> SmtpProvider {
    let mut provider = settings.activate(secrets).expect("activation");
    provider.network = Network::Scripted {
        answers: answers.to_vec(),
        connect_to: stub,
    };
    provider
}

fn public_answer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
}

async fn send(provider: &SmtpProvider) -> Sent<SmtpAttemptDetail> {
    let parts = parts(true);
    provider.send(&message(&parts)).await
}

fn transient() -> SendOutcome {
    SendOutcome::Transient { retry_after: None }
}

fn permanent_code(code: &str) -> SendOutcome {
    SendOutcome::Permanent {
        code: FailureCode::new(code).expect("code"),
    }
}

#[tokio::test]
async fn an_accepted_message_carries_the_relays_queue_id_and_the_derived_message_id() {
    let stub = Stub::start(Script::default()).await;
    let sent = send(&loopback(&stub)).await;
    assert_eq!(
        sent.outcome,
        SendOutcome::Accepted {
            provider_reference: Some(ProviderReference::new("4BCD12345").expect("reference")),
        }
    );
    assert_eq!(
        sent.detail,
        SmtpAttemptDetail {
            stage: SmtpStage::EndOfData,
            reply_code: Some(250),
            failure: None,
        }
    );
    let recorded = stub.recorded();
    let verbs: Vec<&str> = recorded
        .commands
        .iter()
        .map(|command| command.split([' ', ':']).next().unwrap_or_default())
        .collect();
    assert_eq!(verbs, ["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]);
    assert_eq!(recorded.commands[1], format!("MAIL FROM:<{SENDER}>"));
    assert_eq!(recorded.commands[2], format!("RCPT TO:<{RECIPIENT}>"));
    let content = recorded.content.expect("content");
    assert!(
        content.contains(&format!("Message-ID: <{MESSAGE_ID}@agency.example>\r\n")),
        "{content}"
    );
    assert!(content.contains(&format!("Subject: {SUBJECT}\r\n")));
    assert!(content.contains("multipart/alternative"));
    assert!(content.contains(TEXT));
    assert!(content.contains("<strong>form 12-B</strong>"));
}

#[tokio::test]
async fn a_text_only_message_is_a_single_plain_part() {
    let stub = Stub::start(Script::default()).await;
    let parts = parts(false);
    let sent = loopback(&stub).send(&message(&parts)).await;
    assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
    let content = stub.recorded().content.expect("content");
    assert!(!content.contains("multipart"), "{content}");
    assert!(content.contains("Content-Type: text/plain"));
}

#[tokio::test]
async fn an_acceptance_without_a_usable_queue_id_has_no_reference() {
    for reply in [
        "250 2.0.0 Ok",
        "250 Ok: queued as ",
        "250 queued as \u{7f}bad",
    ] {
        let stub = Stub::start(Script {
            end_of_data: Act::Reply(reply),
            ..Script::default()
        })
        .await;
        assert_eq!(
            send(&loopback(&stub)).await.outcome,
            SendOutcome::Accepted {
                provider_reference: None
            },
            "{reply}"
        );
    }
}

#[tokio::test]
async fn a_4xx_reply_at_any_transaction_stage_is_transient() {
    for (stage, script) in transaction_scripts("451 4.3.0 Try again later") {
        let stub = Stub::start(script).await;
        let sent = send(&loopback(&stub)).await;
        assert_eq!(sent.outcome, transient(), "{stage:?}");
        assert_eq!(
            sent.detail,
            SmtpAttemptDetail {
                stage,
                reply_code: Some(451),
                failure: Some(SmtpFailure::Reply),
            }
        );
    }
}

#[tokio::test]
async fn a_5xx_reply_at_any_transaction_stage_is_permanent_with_a_bounded_code() {
    for (stage, script) in transaction_scripts("550 5.1.1 Mailbox unavailable") {
        let stub = Stub::start(script).await;
        let sent = send(&loopback(&stub)).await;
        assert_eq!(sent.outcome, permanent_code("smtp-550"), "{stage:?}");
        assert_eq!(sent.detail.stage, stage);
        assert_eq!(sent.detail.reply_code, Some(550));
    }
}

fn transaction_scripts(reply: &'static str) -> Vec<(SmtpStage, Script)> {
    vec![
        (
            SmtpStage::MailFrom,
            Script {
                mail: Act::Reply(reply),
                ..Script::default()
            },
        ),
        (
            SmtpStage::RcptTo,
            Script {
                rcpt: Act::Reply(reply),
                ..Script::default()
            },
        ),
        (
            SmtpStage::Data,
            Script {
                data: Act::Reply(reply),
                ..Script::default()
            },
        ),
        (
            SmtpStage::EndOfData,
            Script {
                end_of_data: Act::Reply(reply),
                ..Script::default()
            },
        ),
    ]
}

#[tokio::test]
async fn a_drop_after_the_end_of_data_marker_is_maybe_sent() {
    let stub = Stub::start(Script {
        end_of_data: Act::Drop,
        ..Script::default()
    })
    .await;
    let sent = send(&loopback(&stub)).await;
    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
    assert_eq!(
        sent.detail,
        SmtpAttemptDetail {
            stage: SmtpStage::EndOfData,
            reply_code: None,
            failure: Some(SmtpFailure::Connection),
        }
    );
    assert!(stub.recorded().content.is_some(), "the marker was sent");
}

#[tokio::test]
async fn a_timeout_after_the_end_of_data_marker_is_maybe_sent() {
    let stub = Stub::start(Script {
        end_of_data: Act::Stall,
        ..Script::default()
    })
    .await;
    let provider = loopback_with(&stub, |settings| settings.attempt_timeout_seconds = 1);
    let sent = send(&provider).await;
    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
    assert_eq!(sent.detail.failure, Some(SmtpFailure::TimedOut));
}

#[tokio::test]
async fn a_failure_before_data_is_transient() {
    let cases = [
        (
            SmtpStage::Connect,
            Script {
                greeting: Act::Drop,
                ..Script::default()
            },
        ),
        (
            SmtpStage::MailFrom,
            Script {
                mail: Act::Drop,
                ..Script::default()
            },
        ),
        (
            SmtpStage::RcptTo,
            Script {
                rcpt: Act::Drop,
                ..Script::default()
            },
        ),
        (
            SmtpStage::Data,
            Script {
                data: Act::Drop,
                ..Script::default()
            },
        ),
    ];
    for (stage, script) in cases {
        let stub = Stub::start(script).await;
        let sent = send(&loopback(&stub)).await;
        assert_eq!(sent.outcome, transient(), "{stage:?}");
        assert_eq!(sent.detail.stage, stage);
        assert_eq!(sent.detail.failure, Some(SmtpFailure::Connection));
        assert!(stub.recorded().content.is_none());
    }
}

#[tokio::test]
async fn a_refused_connection_is_transient() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let mut settings = development("127.0.0.1");
    settings.port = Some(port);
    let sent = send(&settings.activate(&no_secrets()).expect("activation")).await;
    assert_eq!(sent.outcome, transient());
    assert_eq!(sent.detail.stage, SmtpStage::Connect);
    assert_eq!(sent.detail.failure, Some(SmtpFailure::Connection));
}

#[tokio::test]
async fn a_5xx_before_mail_from_concerns_the_relay_and_is_transient() {
    let stub = Stub::start(Script {
        greeting: Act::Reply("554 5.3.2 No service"),
        ..Script::default()
    })
    .await;
    let sent = send(&loopback(&stub)).await;
    assert_eq!(sent.outcome, transient());
    assert_eq!(sent.detail.stage, SmtpStage::Connect);
    assert_eq!(sent.detail.reply_code, Some(554));
}

#[tokio::test]
async fn the_attempt_timeout_bounds_a_stalled_relay() {
    let stub = Stub::start(Script {
        greeting: Act::Stall,
        ..Script::default()
    })
    .await;
    let provider = loopback_with(&stub, |settings| settings.attempt_timeout_seconds = 1);
    let started = std::time::Instant::now();
    let sent = send(&provider).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
    assert_eq!(sent.outcome, transient());
    assert_eq!(sent.detail.stage, SmtpStage::Connect);
    assert_eq!(sent.detail.failure, Some(SmtpFailure::TimedOut));
}

#[tokio::test]
async fn invalid_addresses_and_message_ids_are_refused_before_connecting() {
    let stub = Stub::start(Script::default()).await;
    let provider = loopback(&stub);
    let parts = parts(false);
    for (message, code) in [
        (
            SmtpMessage {
                to: "not an address",
                ..message(&parts)
            },
            "smtp-recipient-invalid",
        ),
        (
            SmtpMessage {
                to: "a@b.example>\r\nRCPT TO:<c@d.example",
                ..message(&parts)
            },
            "smtp-recipient-invalid",
        ),
        (
            SmtpMessage {
                from: "notices",
                ..message(&parts)
            },
            "smtp-sender-invalid",
        ),
        (
            SmtpMessage {
                message_id: "id@elsewhere",
                ..message(&parts)
            },
            "smtp-message-id-invalid",
        ),
        (
            SmtpMessage {
                message_id: "",
                ..message(&parts)
            },
            "smtp-message-id-invalid",
        ),
    ] {
        let sent = provider.send(&message).await;
        assert_eq!(sent.outcome, permanent_code(code));
        assert_eq!(sent.detail.stage, SmtpStage::Prepare);
    }
    assert_eq!(stub.recorded().connections, 0);
}

#[tokio::test]
async fn a_subject_cannot_inject_a_header() {
    let stub = Stub::start(Script::default()).await;
    let parts = RenderedParts {
        subject: Some("Hello\r\nBcc: attacker@evil.example".to_owned()),
        text: TEXT.to_owned(),
        html: None,
    };
    let sent = loopback(&stub).send(&message(&parts)).await;
    assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
    let recorded = stub.recorded();
    let content = recorded.content.expect("content");
    assert!(
        !content.lines().any(|line| line.starts_with("Bcc:")),
        "{content}"
    );
    assert_eq!(
        recorded
            .commands
            .iter()
            .filter(|command| command.starts_with("RCPT"))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_private_answer_is_refused_before_connecting() {
    let stub = Stub::start(Script::default()).await;
    let settings = tls_settings(None, false);
    for answers in [
        vec![IpAddr::from([10, 0, 0, 5])],
        vec![IpAddr::from([127, 0, 0, 1])],
        vec![IpAddr::from([169, 254, 169, 254])],
        vec![IpAddr::from([100, 64, 0, 1])],
        "fd00::1".parse().map(|ip| vec![ip]).expect("ula"),
        "::ffff:10.0.0.5"
            .parse()
            .map(|ip| vec![ip])
            .expect("mapped"),
        // One bad answer refuses the whole set, so a rebinding resolver
        // cannot slip a private address behind a public one.
        vec![public_answer(), IpAddr::from([192, 168, 1, 10])],
    ] {
        let provider = scripted(&settings, &no_secrets(), &answers, stub.address);
        let sent = send(&provider).await;
        assert_eq!(sent.outcome, transient(), "{answers:?}");
        assert_eq!(
            sent.detail,
            SmtpAttemptDetail {
                stage: SmtpStage::Resolve,
                reply_code: None,
                failure: Some(SmtpFailure::DestinationRefused),
            }
        );
    }
    assert_eq!(stub.recorded().connections, 0);
}

#[tokio::test]
async fn a_private_literal_host_is_refused_before_connecting() {
    let mut settings = tls_settings(None, false);
    settings.host = "10.0.0.5".to_owned();
    let provider = settings.activate(&no_secrets()).expect("activation");
    let sent = send(&provider).await;
    assert_eq!(sent.detail.failure, Some(SmtpFailure::DestinationRefused));
}

#[tokio::test]
async fn loopback_is_refused_in_a_tls_mode_with_real_resolution() {
    let stub = Stub::start(Script::default()).await;
    let mut settings = tls_settings(None, false);
    settings.host = "localhost".to_owned();
    settings.port = Some(stub.address.port());
    let sent = send(&settings.activate(&no_secrets()).expect("activation")).await;
    assert_eq!(sent.detail.failure, Some(SmtpFailure::DestinationRefused));
    assert_eq!(stub.recorded().connections, 0);
}

#[tokio::test]
async fn an_allowlisted_private_answer_connects() {
    let stub = Stub::start(Script::default()).await;
    let mut settings = tls_settings(None, false);
    settings.allowed_private_cidrs = vec!["10.20.0.0/16".to_owned()];
    let provider = scripted(
        &settings,
        &no_secrets(),
        &[IpAddr::from([10, 20, 3, 4])],
        stub.address,
    );
    let sent = send(&provider).await;
    // The stub offers no STARTTLS, which proves the connection was made.
    assert_eq!(sent.detail.failure, Some(SmtpFailure::StartTlsUnavailable));
    assert_eq!(stub.recorded().connections, 1);
}

#[tokio::test]
async fn development_plaintext_refuses_an_answer_that_is_not_loopback() {
    let stub = Stub::start(Script::default()).await;
    let mut settings = development("localhost");
    settings.port = Some(stub.address.port());
    let mut provider = settings.activate(&no_secrets()).expect("activation");
    provider.network = Network::Scripted {
        answers: vec![IpAddr::from([127, 0, 0, 1]), public_answer()],
        connect_to: stub.address,
    };
    let sent = send(&provider).await;
    assert_eq!(sent.detail.failure, Some(SmtpFailure::DestinationRefused));
    assert_eq!(stub.recorded().connections, 0);
}

#[tokio::test]
async fn starttls_verifies_the_configured_host_and_protects_the_whole_transaction() {
    let authority = Authority::new();
    let stub = Stub::start(Script {
        starttls: Some(authority.server(TLS_HOST)),
        advertise_auth: true,
        ..Script::default()
    })
    .await;
    let (secrets, _directory) = secrets(&authority);
    let settings = tls_settings(credentials(), true);
    let provider = scripted(&settings, &secrets, &[public_answer()], stub.address);
    let sent = send(&provider).await;
    assert!(
        matches!(sent.outcome, SendOutcome::Accepted { .. }),
        "{sent:?}"
    );
    let recorded = stub.recorded();
    assert_eq!(recorded.mail_encrypted, Some(true));
    // STARTTLS is the only command before the upgrade; the credential goes
    // over TLS only.
    assert_eq!(recorded.commands[1], "STARTTLS");
    assert!(recorded.commands[3].starts_with("AUTH PLAIN"));
}

#[tokio::test]
async fn starttls_refuses_a_certificate_for_another_name() {
    let authority = Authority::new();
    let stub = Stub::start(Script {
        starttls: Some(authority.server("other.relay.example")),
        ..Script::default()
    })
    .await;
    let (secrets, _directory) = secrets(&authority);
    let provider = scripted(
        &tls_settings(None, true),
        &secrets,
        &[public_answer()],
        stub.address,
    );
    let sent = send(&provider).await;
    assert_eq!(sent.outcome, transient());
    assert_eq!(sent.detail.stage, SmtpStage::StartTls);
    assert_eq!(sent.detail.failure, Some(SmtpFailure::Connection));
    assert!(stub.recorded().mail_encrypted.is_none());
}

#[tokio::test]
async fn starttls_refuses_an_untrusted_certificate() {
    let stub = Stub::start(Script {
        starttls: Some(Authority::new().server(TLS_HOST)),
        ..Script::default()
    })
    .await;
    let provider = scripted(
        &tls_settings(None, false),
        &no_secrets(),
        &[public_answer()],
        stub.address,
    );
    let sent = send(&provider).await;
    assert_eq!(sent.detail.stage, SmtpStage::StartTls);
    assert!(stub.recorded().mail_encrypted.is_none());
}

#[tokio::test]
async fn a_relay_without_starttls_gets_no_credential_and_no_message() {
    let authority = Authority::new();
    let stub = Stub::start(Script {
        advertise_auth: true,
        ..Script::default()
    })
    .await;
    let (secrets, _directory) = secrets(&authority);
    let settings = tls_settings(credentials(), true);
    let provider = scripted(&settings, &secrets, &[public_answer()], stub.address);
    let sent = send(&provider).await;
    assert_eq!(sent.outcome, transient());
    assert_eq!(sent.detail.failure, Some(SmtpFailure::StartTlsUnavailable));
    let commands = stub.recorded().commands;
    assert!(
        commands
            .iter()
            .all(|command| !command.starts_with("AUTH") && !command.starts_with("MAIL")),
        "{commands:?}"
    );
}

#[tokio::test]
async fn implicit_tls_verifies_the_configured_host() {
    let authority = Authority::new();
    let stub = Stub::start(Script {
        implicit_tls: Some(authority.server(TLS_HOST)),
        ..Script::default()
    })
    .await;
    let (secrets, _directory) = secrets(&authority);
    let mut settings = tls_settings(None, true);
    settings.tls = SmtpTlsMode::Implicit;
    let provider = scripted(&settings, &secrets, &[public_answer()], stub.address);
    let sent = send(&provider).await;
    assert!(
        matches!(sent.outcome, SendOutcome::Accepted { .. }),
        "{sent:?}"
    );
    assert_eq!(stub.recorded().mail_encrypted, Some(true));
}

#[tokio::test]
async fn no_log_line_carries_an_address_content_or_credential() {
    let captured = Captured::install();

    let authority = Authority::new();
    let (secrets, _directory) = secrets(&authority);
    let accepting = Stub::start(Script {
        starttls: Some(authority.server(TLS_HOST)),
        advertise_auth: true,
        ..Script::default()
    })
    .await;
    let settings = tls_settings(credentials(), true);
    let provider = scripted(&settings, &secrets, &[public_answer()], accepting.address);
    assert!(matches!(
        send(&provider).await.outcome,
        SendOutcome::Accepted { .. }
    ));
    for script in [
        Script {
            rcpt: Act::Reply("550 5.1.1 <resident.4471@citizen.example> unknown"),
            ..Script::default()
        },
        Script {
            end_of_data: Act::Drop,
            ..Script::default()
        },
    ] {
        let stub = Stub::start(script).await;
        send(&loopback(&stub)).await;
    }
    tracing::debug!(provider = ?provider, "provider debug form");

    let logs = captured.finish();
    assert_eq!(
        logs.matches("smtp attempt finished").count(),
        3,
        "every attempt is logged:\n{logs}"
    );
    assert!(logs.contains("provider debug form"), "{logs}");
    for needle in [
        RECIPIENT,
        "resident.4471",
        SENDER,
        SUBJECT,
        TEXT,
        "form 12-B",
        USERNAME,
        PASSWORD,
        "relay-user",
        "relay-password",
    ] {
        assert!(!logs.contains(needle), "logs carry {needle:?}:\n{logs}");
    }
}

const USERNAME: &str = "mailer-account";
const PASSWORD: &str = "correct horse battery staple";

thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Arc<Mutex<Vec<u8>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Every record emitted on this thread while the capture is open.
///
/// Tests running concurrently can register a callsite while no subscriber is
/// installed, which caches it as uninteresting, and a thread-local subscriber
/// does not reliably undo that. So one subscriber is installed process-wide on
/// first use and routes each record to the buffer of the thread that emitted
/// it; records from threads without a buffer are dropped. The attempt and the
/// stub run on this test's current-thread runtime, so its records land here.
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn install() -> Self {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::TRACE)
                    .with_ansi(false)
                    .with_writer(|| ThreadBuffer)
                    .finish(),
            )
            .expect("this test binary installs no other global subscriber");
        });
        let buffer = Arc::new(Mutex::new(Vec::new()));
        CAPTURE.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&buffer)));
        Self(buffer)
    }

    fn finish(self) -> String {
        CAPTURE.with(|slot| *slot.borrow_mut() = None);
        String::from_utf8(self.0.lock().expect("captured lock").clone()).expect("utf-8 logs")
    }
}

struct ThreadBuffer;

impl std::io::Write for ThreadBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        CAPTURE.with(|slot| {
            if let Some(buffer) = slot.borrow().as_ref() {
                buffer
                    .lock()
                    .expect("captured lock")
                    .extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Settings for the public host [`TLS_HOST`]. With `trusted`, the relay's
/// root is the test authority from [`secrets`]; without it, only the public
/// roots are trusted.
fn tls_settings(authentication: Option<SmtpAuthentication>, trusted: bool) -> SmtpProviderSettings {
    SmtpProviderSettings {
        host: TLS_HOST.to_owned(),
        port: None,
        tls: SmtpTlsMode::Starttls,
        trusted_root_certificate_ref: trusted.then(|| "secret:file/relay-root".to_owned()),
        authentication,
        attempt_timeout_seconds: 5,
        allowed_private_cidrs: Vec::new(),
    }
}

fn credentials() -> Option<SmtpAuthentication> {
    Some(SmtpAuthentication {
        username_ref: "secret:file/relay-user".to_owned(),
        password_ref: "secret:file/relay-password".to_owned(),
    })
}

/// A private certificate authority that signs the stub's certificates.
struct Authority {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Authority {
    fn new() -> Self {
        let mut parameters =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("authority parameters");
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("authority key");
        let certificate = parameters.self_signed(&key).expect("authority certificate");
        Self { certificate, key }
    }

    fn server(&self, name: &str) -> Arc<ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("server key");
        let certificate = rcgen::CertificateParams::new(vec![name.to_owned()])
            .expect("server parameters")
            .signed_by(&key, &self.certificate, &self.key)
            .expect("server certificate");
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");
        Arc::new(config)
    }
}

/// A file secret root holding the credential pair and the authority's root.
fn secrets(authority: &Authority) -> (SecretResolver, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("secret directory");
    let root = directory.path().canonicalize().expect("canonical root");
    write_secret(&root, "relay-user", USERNAME.as_bytes());
    write_secret(&root, "relay-password", PASSWORD.as_bytes());
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            authority.certificate.der().as_ref()
        )
    );
    write_secret(&root, "relay-root", pem.as_bytes());
    let resolver = SecretResolver::new([SecretProvider::File], &root).expect("resolver");
    (resolver, directory)
}

#[test]
fn queue_references_are_read_from_the_acceptance_reply() {
    use lettre::transport::smtp::response::{Category, Code, Detail, Severity};
    let code = Code::new(
        Severity::PositiveCompletion,
        Category::MailSystem,
        Detail::Zero,
    );
    let reference = |lines: &[&str]| {
        queue_reference(&Response::new(
            code,
            lines.iter().map(|line| (*line).to_owned()).collect(),
        ))
        .map(|reference| reference.as_str().to_owned())
    };
    assert_eq!(
        reference(&["2.0.0 Ok: queued as 4BCD12345"]),
        Some("4BCD12345".to_owned())
    );
    assert_eq!(
        reference(&["Ok", "QUEUED AS abc-1 extra"]),
        Some("abc-1".to_owned())
    );
    assert_eq!(reference(&["2.0.0 Ok"]), None);
    assert_eq!(
        reference(&[&format!("queued as {}", "x".repeat(129))]),
        None
    );
}

#[test]
fn provider_debug_output_names_no_credential() {
    let authority = Authority::new();
    let (secrets, _directory) = secrets(&authority);
    let settings = tls_settings(credentials(), true);
    let provider = settings.activate(&secrets).expect("activation");
    let debug = format!("{provider:?}");
    assert!(
        !debug.contains(USERNAME) && !debug.contains(PASSWORD),
        "{debug}"
    );
    let parts = parts(true);
    let debug = format!("{:?}", message(&parts));
    assert!(
        !debug.contains(RECIPIENT) && !debug.contains(SUBJECT),
        "{debug}"
    );
}

#[test]
fn smtp_failure_codes_fit_the_dispatch_bound() {
    for code in [
        "smtp-message-id-invalid",
        "smtp-sender-invalid",
        "smtp-recipient-invalid",
        "smtp-message-invalid",
        "smtp-smtputf8-unsupported",
        "smtp-8bitmime-unsupported",
        "smtp-550",
        "smtp-599",
    ] {
        assert!(FailureCode::new(code).is_ok(), "{code}");
    }
}
