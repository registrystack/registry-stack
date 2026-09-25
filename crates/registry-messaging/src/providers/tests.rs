// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use registry_messaging_core::{verify_callback, CallbackRequest, Channel, RenderedParts};
use registry_platform_testing::MockHttpUpstream;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use uuid::Uuid;

use super::*;
use crate::config::tests::{package_value, runtime_value, write_project};
use crate::smtp::stub::{Act, Script, Stub};

const MESSAGE_ID: &str = "0192f1d6-7c1a-7b4e-9a51-3f0c2e8d4b10";
const RECIPIENT_EMAIL: &str = "resident.4471@citizen.example";
const RECIPIENT_PHONE: &str = "+15550104471";
const IDEMPOTENCY_KEY: &str = "idempotency-7c1a";
const CALLBACK_TOKEN: &[u8] = b"callback-token-9d2e61";

struct Project {
    _root: TempDir,
    config: RuntimeConfig,
    loaded: LoadedPackage,
    secrets: SecretResolver,
}

fn project(
    providers: Value,
    adjust_package: impl FnOnce(&mut Value),
    secrets: &[(&str, &[u8])],
) -> Project {
    let root = tempfile::tempdir().expect("project root");
    let path = root.path().canonicalize().expect("canonical project root");
    let secret_root = path.join("secrets");
    std::fs::create_dir(&secret_root).expect("secret root");
    for (name, value) in secrets {
        write_secret(&secret_root, name, value);
    }
    let mut runtime = runtime_value(&path);
    runtime["providers"] = providers;
    let mut package = package_value();
    adjust_package(&mut package);
    let file = write_project(&path, &runtime, &package);
    let config = RuntimeConfig::load_with_environment(&file, &|_| None).expect("runtime config");
    let loaded = config.load_package().expect("package");
    let secrets = config.secret_resolver().expect("secret resolver");
    Project {
        _root: root,
        config,
        loaded,
        secrets,
    }
}

fn write_secret(root: &Path, name: &str, value: &[u8]) {
    let path = root.join(name);
    std::fs::write(&path, value).expect("write secret");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("secret mode");
}

fn smtp_connection(stub: &Stub) -> Value {
    json!({
        "kind": "smtp",
        "host": "127.0.0.1",
        "port": stub.address.port(),
        "tls": "development-loopback"
    })
}

fn http_connection(upstream: &MockHttpUpstream, authentication: Value) -> Value {
    http_connection_to(
        &format!("{}/v1/", upstream.url().trim_end_matches('/')),
        authentication,
    )
}

fn http_connection_to(base_url: &str, authentication: Value) -> Value {
    json!({
        "kind": "http",
        "baseUrl": base_url,
        "timeoutMilliseconds": 3000,
        "maximumResponseBytes": 65536,
        "concurrencyLimit": 4,
        "redirects": "deny",
        "authentication": authentication,
        "callbackVerifier": {"kind": "path-token", "tokenRef": "secret:file/callback-token"}
    })
}

/// The callback receivers of a starter project whose `sms-gateway` names
/// `verifier`, reading `secrets`.
pub(crate) fn callback_receivers(verifier: Value, secrets: &[(&str, &[u8])]) -> CallbackReceivers {
    let mut connection = http_connection_to("http://127.0.0.1:9/v1/", json!({"kind": "none"}));
    connection["callbackVerifier"] = verifier;
    let project = project(json!({"sms-gateway": connection}), |_| {}, secrets);
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut Transports::new(),
    )
    .expect("providers activate")
}

fn outbound(
    channel: Channel,
    provider: &str,
    profile: &str,
    sender: &str,
    to: &str,
) -> OutboundMessage {
    OutboundMessage {
        message_id: Uuid::parse_str(MESSAGE_ID).expect("message id"),
        generation: 1,
        attempt: 1,
        channel,
        provider: provider.to_owned(),
        sender_profile: profile.to_owned(),
        sender: sender.to_owned(),
        recipient: to.to_owned(),
        parts: RenderedParts {
            subject: (channel == Channel::Email).then(|| "Your appointment".to_owned()),
            text: "Bring form 12-B to the Riverside office.".to_owned(),
            html: None,
        },
        idempotency_key: IDEMPOTENCY_KEY.to_owned(),
        provider_idempotent_submit: true,
        budget: Duration::from_secs(5),
    }
}

fn email() -> OutboundMessage {
    outbound(
        Channel::Email,
        "mail-relay",
        "transactional",
        "notices@example.org",
        RECIPIENT_EMAIL,
    )
}

fn sms() -> OutboundMessage {
    outbound(
        Channel::Sms,
        "sms-gateway",
        "reminders-sms",
        "Registry",
        RECIPIENT_PHONE,
    )
}

async fn received(upstream: &MockHttpUpstream) -> Vec<wiremock::Request> {
    upstream
        .wiremock_server()
        .received_requests()
        .await
        .expect("request recording is on")
}

#[tokio::test]
async fn configured_providers_become_transports_that_send_what_was_accepted() {
    let stub = Stub::start(Script::default()).await;
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_json(200, json!({"id": "gw-7731"}))
        .await;
    let project = project(
        json!({
            "mail-relay": smtp_connection(&stub),
            "sms-gateway": http_connection(&upstream, json!({"kind": "none"}))
        }),
        |_| {},
        &[("callback-token", CALLBACK_TOKEN)],
    );
    let mut transports = Transports::new();
    let receivers = activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("providers activate");

    let relay = transports.get("mail-relay").expect("smtp transport");
    assert_eq!(relay.attempt_timeout(), Duration::from_secs(30));
    assert!(matches!(
        relay.send(&email()).await,
        SendOutcome::Accepted { .. }
    ));
    let recorded = stub.recorded();
    assert!(recorded
        .commands
        .contains(&"MAIL FROM:<notices@example.org>".to_owned()));
    assert!(recorded
        .commands
        .contains(&format!("RCPT TO:<{RECIPIENT_EMAIL}>")));
    assert!(recorded
        .content
        .expect("content")
        .contains(&format!("Message-ID: <{MESSAGE_ID}@example.org>")));

    let gateway = transports.get("sms-gateway").expect("http transport");
    // The provider's three-second timeout rounds up to the seam's minimum
    // of one second only when shorter.
    assert_eq!(gateway.attempt_timeout(), Duration::from_secs(3));
    let outcome = gateway.send(&sms()).await;
    assert!(
        matches!(&outcome, SendOutcome::Accepted { receiver_reference: Some(reference) } if reference.as_str() == "gw-7731"),
        "{outcome:?}"
    );
    let requests = received(&upstream).await;
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["to"], RECIPIENT_PHONE);
    assert_eq!(body["from"], "Registry");
    assert_eq!(body["channel"], "sms");
    assert_eq!(
        requests[0]
            .headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some(IDEMPOTENCY_KEY)
    );
    assert_eq!(
        requests[0]
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(MESSAGE_ID)
    );

    let receiver = receivers.get("sms-gateway").expect("callback receiver");
    assert_eq!(receivers.len(), 1);
    let token = std::str::from_utf8(CALLBACK_TOKEN).expect("ascii token");
    let request = CallbackRequest {
        method: "POST",
        url: "https://messaging.example.org/v1/provider-callbacks/sms-gateway",
        form_parameters: &[],
        body: b"",
        headers: &[],
        path_token: Some(token),
    };
    assert_eq!(verify_callback(&receiver.verifier(), &request), Ok(()));
    let rendered = format!("{receiver:?}");
    assert!(!rendered.contains(token), "{rendered}");
}

#[tokio::test]
async fn the_idempotency_key_follows_the_capability_persisted_at_acceptance() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_json(200, json!({"id": "gw-7732"}))
        .await;
    let project = project(
        json!({"sms-gateway": http_connection(&upstream, json!({"kind": "none"}))}),
        |package| {
            package["providers"][1]
                .as_object_mut()
                .expect("provider")
                .remove("idempotentSubmit");
        },
        &[("callback-token", CALLBACK_TOKEN)],
    );
    let mut transports = Transports::new();
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("providers activate");
    let gateway = transports.get("sms-gateway").expect("http transport");
    let mut accepted_without_deduplication = sms();
    accepted_without_deduplication.provider_idempotent_submit = false;
    gateway.send(&accepted_without_deduplication).await;
    // The active package no longer declares the capability, but a message
    // accepted while it did still carries its key after a restart.
    gateway.send(&sms()).await;
    let requests = received(&upstream).await;
    assert!(requests[0].headers.get("idempotency-key").is_none());
    assert_eq!(
        requests[1]
            .headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some(IDEMPOTENCY_KEY)
    );
}

#[test]
fn a_path_token_must_be_bounded_utf8_before_callback_activation() {
    for token in [
        vec![0xff],
        vec![b'a'; MAXIMUM_CALLBACK_PATH_TOKEN_BYTES + 1],
    ] {
        let project = project(
            json!({
                "sms-gateway": http_connection_to(
                    "http://127.0.0.1:9/v1/",
                    json!({"kind": "none"})
                )
            }),
            |_| {},
            &[("callback-token", &token)],
        );
        let error = activate_providers(
            &project.config,
            &project.loaded,
            &project.secrets,
            &mut Transports::new(),
        )
        .expect_err("an unusable path token");
        let text = error.to_string();
        assert!(text.contains("callbackVerifier.tokenRef"), "{text}");
        assert!(text.contains("UTF-8"), "{text}");
    }
}

#[tokio::test]
async fn an_unconfigured_package_provider_gets_no_transport() {
    let upstream = MockHttpUpstream::start().await;
    let project = project(
        json!({"sms-gateway": http_connection(&upstream, json!({"kind": "none"}))}),
        |_| {},
        &[("callback-token", CALLBACK_TOKEN)],
    );
    let mut transports = Transports::new();
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("providers activate");
    assert!(transports.get("mail-relay").is_none());
}

#[tokio::test]
async fn a_provider_that_cannot_be_activated_names_itself_and_never_a_secret() {
    let upstream = MockHttpUpstream::start().await;

    // The callback verifier's secret is resolved at startup.
    let missing = project(
        json!({"sms-gateway": http_connection(&upstream, json!({"kind": "none"}))}),
        |_| {},
        &[],
    );
    let error = activate_providers(
        &missing.config,
        &missing.loaded,
        &missing.secrets,
        &mut Transports::new(),
    )
    .expect_err("missing callback token");
    assert_eq!(error.provider, "sms-gateway");
    assert!(error.to_string().contains("sms-gateway"), "{error}");
    assert!(error.to_string().contains("callbackVerifier"), "{error}");

    // A resolved credential that cannot be used is refused without its value.
    let mut connection = http_connection(
        &upstream,
        json!({
            "kind": "basic",
            "usernameRef": "secret:file/gateway-user",
            "passwordRef": "secret:file/gateway-password"
        }),
    );
    connection["baseUrl"] = json!("https://gateway.example.org/v1/");
    let unusable = project(
        json!({"sms-gateway": connection}),
        |_| {},
        &[
            ("callback-token", CALLBACK_TOKEN),
            ("gateway-user", b"account:with-colon-4417"),
            ("gateway-password", b"password-value-51be"),
        ],
    );
    let error = activate_providers(
        &unusable.config,
        &unusable.loaded,
        &unusable.secrets,
        &mut Transports::new(),
    )
    .expect_err("unusable username");
    assert_eq!(error.provider, "sms-gateway");
    let text = error.to_string();
    assert!(text.contains("authentication.usernameRef"), "{text}");
    for value in [
        "with-colon-4417",
        "password-value-51be",
        "callback-token-9d2e61",
    ] {
        assert!(!text.contains(value), "{text}");
    }

    // An SMTP credential that does not resolve names the provider.
    let stub = Stub::start(Script::default()).await;
    let mut connection = smtp_connection(&stub);
    connection["authentication"] = json!({
        "usernameRef": "secret:file/smtp-user",
        "passwordRef": "secret:file/smtp-password"
    });
    let smtp = project(json!({"mail-relay": connection}), |_| {}, &[]);
    let error = activate_providers(
        &smtp.config,
        &smtp.loaded,
        &smtp.secrets,
        &mut Transports::new(),
    )
    .expect_err("missing smtp credential");
    assert_eq!(error.provider, "mail-relay");
    assert!(error.to_string().contains("smtp-user"), "{error}");
}

#[tokio::test]
async fn a_provider_with_a_registered_transport_is_refused() {
    let stub = Stub::start(Script::default()).await;
    let project = project(json!({"mail-relay": smtp_connection(&stub)}), |_| {}, &[]);
    let mut transports = Transports::new();
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("first activation");
    let error = activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect_err("second activation");
    assert_eq!(error.provider, "mail-relay");
    assert!(error.to_string().contains("already registered"), "{error}");
}

/// A listener that counts connections and closes each one after reading what
/// the client first writes, so a request that reached it has no answer.
async fn silent_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0_u8; 4096];
            let _read = stream.read(&mut buffer).await;
            drop(stream);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn an_activated_provider_resolving_to_loopback_is_refused_before_connecting() {
    let stub = Stub::start(Script::default()).await;
    let (port, accepted) = silent_listener().await;
    let mut relay = smtp_connection(&stub);
    relay["host"] = json!("localhost");
    relay["tls"] = json!("starttls");
    let gateway = http_connection_to(
        &format!("https://localhost:{port}/v1/"),
        json!({"kind": "static-authorization", "tokenRef": "secret:file/gateway-token"}),
    );
    let project = project(
        json!({"mail-relay": relay, "sms-gateway": gateway}),
        |_| {},
        &[
            ("callback-token", CALLBACK_TOKEN),
            ("gateway-token", b"gateway-token-value"),
        ],
    );
    let mut transports = Transports::new();
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("providers activate");

    // Both kinds refuse the resolved loopback address before any byte
    // leaves, and the attempt is not sent, so the worker may retry it.
    let not_sent = SendOutcome::Transient { retry_after: None };
    let relay = transports.get("mail-relay").expect("smtp transport");
    assert_eq!(relay.send(&email()).await, not_sent);
    assert_eq!(stub.recorded().connections, 0);
    let gateway = transports.get("sms-gateway").expect("http transport");
    assert_eq!(gateway.send(&sms()).await, not_sent);
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no connection was made");
}

#[tokio::test]
async fn an_activated_provider_cut_off_after_the_message_left_is_maybe_sent() {
    let stub = Stub::start(Script {
        end_of_data: Act::Drop,
        ..Script::default()
    })
    .await;
    let (port, accepted) = silent_listener().await;
    let project = project(
        json!({
            "mail-relay": smtp_connection(&stub),
            "sms-gateway": http_connection_to(
                &format!("http://127.0.0.1:{port}/v1/"),
                json!({"kind": "none"}),
            )
        }),
        |_| {},
        &[("callback-token", CALLBACK_TOKEN)],
    );
    let mut transports = Transports::new();
    activate_providers(
        &project.config,
        &project.loaded,
        &project.secrets,
        &mut transports,
    )
    .expect("providers activate");

    // Each kind reports a send that may have reached the provider as
    // maybe-sent, which the dispatcher holds as unknown.
    let relay = transports.get("mail-relay").expect("smtp transport");
    assert_eq!(relay.send(&email()).await, SendOutcome::MaybeSent);
    assert!(stub.recorded().content.is_some(), "the message was written");
    let gateway = transports.get("sms-gateway").expect("http transport");
    assert_eq!(gateway.send(&sms()).await, SendOutcome::MaybeSent);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}
