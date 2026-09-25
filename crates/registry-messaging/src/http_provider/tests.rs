// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use registry_messaging_core::{
    CallbackRequest, CallbackVerifierConfig, Channel, DeliveryReport, Receipt, RenderedParts,
    SenderProfile, UncertainPolicy,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_dispatch::{FailureCode, ReceiverReference, SendOutcome};
use registry_platform_testing::MockHttpUpstream;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use wiremock::ResponseTemplate;

use super::*;

const TOKEN: &[u8] = b"token-value-7f3a9c";
const PASSWORD: &[u8] = b"password-value-51be";

const JSON_PREPARE: &str = r#"
fn prepare(message, profile) {
    #{
        target: "messages",
        headers: #{ "x-request-id": message.messageId },
        bodyFormat: "json",
        body: #{ to: message.recipient, from: profile.sender, text: message.parts.text },
    }
}
"#;

const ERROR_BODY_INTERPRET: &str = r#"
fn interpret(response) {
    let body = response.body;
    if response.status == 200 && type_of(body) == "map" && body.error != () {
        return #{ outcome: "permanent", code: "gateway.rejected" };
    }
    if response.status == 200 && type_of(body) == "map" && type_of(body.id) == "string" {
        return #{ outcome: "accepted", providerReference: body.id };
    }
    if response.status == 503 {
        return #{ outcome: "transient", retryAfter: 7 };
    }
    if response.status == 429 {
        return #{ outcome: "transient" };
    }
    #{ outcome: "permanent", code: "gateway.other" }
}
"#;

struct Secrets {
    _root: TempDir,
    resolver: SecretResolver,
}

fn secrets(values: &[(&str, &[u8])]) -> Secrets {
    let root = tempfile::tempdir().expect("secret root");
    let path = root.path().canonicalize().expect("canonical secret root");
    for (name, value) in values {
        let file = path.join(name);
        std::fs::write(&file, value).expect("write secret");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only secret");
    }
    let resolver = SecretResolver::new([SecretProvider::File], path).expect("resolver");
    Secrets {
        _root: root,
        resolver,
    }
}

fn no_secrets() -> Secrets {
    secrets(&[])
}

fn package(yaml: &str) -> HttpProviderPackage {
    serde_norway::from_str(yaml).expect("package parses")
}

fn plain_package(interpret: bool) -> HttpProviderPackage {
    let mut package = package(
        r"
prepareScript: prepare.rhai
request:
  method: post
  headers: [x-request-id]
responseHeaders: [x-request-id]
capabilities:
  receipts: none
  concurrencyLimit: 4
",
    );
    if interpret {
        package.interpret_script = Some("interpret.rhai".to_owned());
    }
    package
}

fn settings(base_url: &str, authentication: &str) -> HttpProviderSettings {
    serde_norway::from_str(&format!(
        "baseUrl: {base_url}\ntimeoutMilliseconds: 3000\nmaximumResponseBytes: 65536\n\
         concurrencyLimit: 4\nredirects: deny\nauthentication:\n{authentication}"
    ))
    .expect("settings parse")
}

const NONE: &str = "  kind: none\n";

fn base(upstream: &MockHttpUpstream) -> String {
    format!("{}/v1/", upstream.url().trim_end_matches('/'))
}

fn scripts<'a>(prepare: &'a str, interpret: Option<&'a str>) -> HttpProviderScripts<'a> {
    HttpProviderScripts {
        prepare,
        interpret,
        receipt: None,
    }
}

fn activate(
    settings: &HttpProviderSettings,
    package: &HttpProviderPackage,
    scripts: HttpProviderScripts<'_>,
    secrets: &Secrets,
) -> HttpProvider {
    settings
        .activate("gateway", package, scripts, None, &secrets.resolver)
        .expect("provider activates")
}

struct Content {
    profile: SenderProfile,
    parts: RenderedParts,
}

fn content() -> Content {
    Content {
        profile: SenderProfile {
            id: "reminders-sms".to_owned(),
            channel: Channel::Sms,
            provider: "gateway".to_owned(),
            sender: "Registry".to_owned(),
            maximum_segments: Some(2),
            retry: None,
            on_uncertain: UncertainPolicy::Hold,
            accept_duplicates: false,
            default_expiry_seconds: None,
        },
        parts: RenderedParts {
            subject: None,
            text: "Your appointment is at 10:00.".to_owned(),
            html: None,
        },
    }
}

fn message(content: &Content) -> HttpProviderMessage<'_> {
    HttpProviderMessage {
        message_id: "msg-0001",
        attempt: 1,
        generation: 3,
        channel: Channel::Sms,
        profile: &content.profile,
        recipient: "+15005550010",
        parts: &content.parts,
        idempotency_key: Some("msg-0001"),
    }
}

async fn received(upstream: &MockHttpUpstream) -> Vec<wiremock::Request> {
    upstream
        .wiremock_server()
        .received_requests()
        .await
        .expect("request recording is on")
}

fn header(request: &wiremock::Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().expect("ascii header").to_owned())
}

fn permanent_code(code: &str) -> SendOutcome {
    SendOutcome::Permanent {
        code: FailureCode::new(code).expect("valid code"),
    }
}

fn accepted(reference: Option<&str>) -> SendOutcome {
    SendOutcome::Accepted {
        receiver_reference: reference
            .map(|reference| ReceiverReference::new(reference).expect("valid reference")),
    }
}

// ---------------------------------------------------------------------------
// Authentication: where each kind places its credential.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn basic_authentication_sends_the_encoded_pair_in_the_authorization_header() {
    use base64::Engine as _;
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(201)
        .await;
    let secrets = secrets(&[("user", b"account-1"), ("password", PASSWORD)]);
    let settings = settings(
        &base(&upstream),
        "  kind: basic\n  usernameRef: secret:file/user\n  passwordRef: secret:file/password\n",
    );
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, accepted(None));
    let requests = received(&upstream).await;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(b"account-1:password-value-51be")
    );
    assert_eq!(header(&requests[0], "authorization"), Some(expected));
}

#[tokio::test]
async fn static_authorization_sends_a_bearer_token() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(202)
        .await;
    let secrets = secrets(&[("token", TOKEN)]);
    let settings = settings(
        &base(&upstream),
        "  kind: static-authorization\n  tokenRef: secret:file/token\n",
    );
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, accepted(None));
    let requests = received(&upstream).await;
    assert_eq!(
        header(&requests[0], "authorization").as_deref(),
        Some("Bearer token-value-7f3a9c")
    );
}

#[tokio::test]
async fn static_api_key_sends_the_value_in_the_declared_header_only() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(200)
        .await;
    let secrets = secrets(&[("key", TOKEN)]);
    let settings = settings(
        &base(&upstream),
        "  kind: static-api-key\n  headerName: X-Api-Key\n  valueRef: secret:file/key\n",
    );
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    provider.send(&message(&content)).await;

    let requests = received(&upstream).await;
    assert_eq!(
        header(&requests[0], "x-api-key").as_deref(),
        Some("token-value-7f3a9c")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
    assert_eq!(requests[0].url.query(), None);
}

#[tokio::test]
async fn static_api_key_query_appends_the_parameter_after_the_script_target() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(200)
        .await;
    let secrets = secrets(&[("key", TOKEN)]);
    let settings = settings(
        &base(&upstream),
        "  kind: static-api-key-query\n  parameterName: api_key\n  valueRef: secret:file/key\n",
    );
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    provider.send(&message(&content)).await;

    let requests = received(&upstream).await;
    assert_eq!(requests[0].url.query(), Some("api_key=token-value-7f3a9c"));
    assert_eq!(header(&requests[0], "authorization"), None);
}

#[tokio::test]
async fn oauth2_client_credentials_fetches_caches_and_drops_a_refused_token() {
    let upstream = MockHttpUpstream::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "issued-token-1",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(upstream.wiremock_server())
        .await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/messages"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(upstream.wiremock_server())
        .await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(201)
        .await;
    let secrets = secrets(&[("client-id", b"client-1"), ("client-secret", PASSWORD)]);
    let settings = settings(
        &base(&upstream),
        &format!(
            "  kind: oauth2-client-credentials\n  tokenEndpoint: {}/oauth/token\n  \
             clientIdRef: secret:file/client-id\n  clientSecretRef: secret:file/client-secret\n  \
             scope: messages.send\n  maximumCacheSeconds: 600\n",
            upstream.url().trim_end_matches('/')
        ),
    );
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    let refused = provider.send(&message(&content)).await;
    let first = provider.send(&message(&content)).await;
    let second = provider.send(&message(&content)).await;

    assert_eq!(
        refused.outcome,
        SendOutcome::Transient { retry_after: None }
    );
    assert_eq!(refused.detail.status, Some(401));
    assert_eq!(first.outcome, accepted(None));
    assert_eq!(second.outcome, accepted(None));
    let requests = received(&upstream).await;
    let token_requests = requests
        .iter()
        .filter(|request| request.url.path() == "/oauth/token")
        .collect::<Vec<_>>();
    assert_eq!(
        token_requests.len(),
        2,
        "the refused token is dropped once, then the new one is cached"
    );
    let form = url::form_urlencoded::parse(&token_requests[0].body)
        .into_owned()
        .collect::<Vec<_>>();
    assert!(form.contains(&("grant_type".to_owned(), "client_credentials".to_owned())));
    assert!(form.contains(&("client_id".to_owned(), "client-1".to_owned())));
    assert!(form.contains(&("client_secret".to_owned(), "password-value-51be".to_owned())));
    assert!(form.contains(&("scope".to_owned(), "messages.send".to_owned())));
    for request in requests
        .iter()
        .filter(|request| request.url.path() == "/v1/messages")
    {
        assert_eq!(
            header(request, "authorization").as_deref(),
            Some("Bearer issued-token-1")
        );
    }
}

#[tokio::test]
async fn oauth2_accepts_a_token_response_with_scope_and_a_lowercase_type() {
    for (token, expiry) in [
        (
            json!({
                "access_token": "issued-token-2",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "messages.send"
            }),
            "",
        ),
        (
            json!({
                "access_token": "issued-token-2",
                "token_type": "BEARER",
                "scope": "messages.send"
            }),
            "  assumedLifetimeSeconds: 300\n",
        ),
    ] {
        let upstream = MockHttpUpstream::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token))
            .mount(upstream.wiremock_server())
            .await;
        upstream
            .expect("POST", "/v1/messages")
            .respond_status(201)
            .await;
        let secrets = secrets(&[("client-id", b"client-1"), ("client-secret", PASSWORD)]);
        let settings = settings(
            &base(&upstream),
            &format!(
                "  kind: oauth2-client-credentials\n  tokenEndpoint: {}/oauth/token\n  \
                 clientIdRef: secret:file/client-id\n  clientSecretRef: secret:file/client-secret\n  \
                 maximumCacheSeconds: 600\n{expiry}",
                upstream.url().trim_end_matches('/')
            ),
        );
        let provider = activate(
            &settings,
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            &secrets,
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, accepted(None), "{expiry}");
        let requests = received(&upstream).await;
        let send = requests
            .iter()
            .find(|request| request.url.path() == "/v1/messages")
            .expect("the message was sent");
        assert_eq!(
            header(send, "authorization").as_deref(),
            Some("Bearer issued-token-2")
        );
    }
}

#[test]
fn no_authentication_is_refused_for_an_https_provider() {
    let settings = settings("https://gateway.example.org/v1/", NONE);
    let error = settings
        .activate(
            "gateway",
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            None,
            &no_secrets().resolver,
        )
        .expect_err("none is loopback only");
    assert!(error.to_string().starts_with("authentication:"), "{error}");
}

#[test]
fn a_credential_must_be_a_secret_reference() {
    let secrets = secrets(&[("token", TOKEN)]);
    for reference in [
        "${GATEWAY_TOKEN}",
        "token-value-7f3a9c",
        "secret:vault/token",
    ] {
        let settings = settings(
            "https://gateway.example.org/v1/",
            &format!("  kind: static-authorization\n  tokenRef: '{reference}'\n"),
        );
        let error = settings
            .activate(
                "gateway",
                &plain_package(false),
                scripts(JSON_PREPARE, None),
                None,
                &secrets.resolver,
            )
            .expect_err("only secret references resolve");
        assert!(matches!(error, HttpProviderError::Secret(_)), "{error}");
        assert!(!error.to_string().contains("token-value-7f3a9c"));
    }
}

// ---------------------------------------------------------------------------
// Request bodies: Rust serializes what the script returns.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_json_body_is_serialized_by_rust() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(201)
        .await;
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let content = content();

    provider.send(&message(&content)).await;

    let requests = received(&upstream).await;
    assert_eq!(
        header(&requests[0], "content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        header(&requests[0], "x-request-id").as_deref(),
        Some("msg-0001")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body,
        json!({"to": "+15005550010", "from": "Registry", "text": "Your appointment is at 10:00."})
    );
}

#[tokio::test]
async fn a_form_body_is_serialized_by_rust() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(201)
        .await;
    let prepare = r#"
fn prepare(message, profile) {
    #{
        target: "messages",
        bodyFormat: "form",
        body: #{ To: message.recipient, Body: "a&b=c " + message.parts.text, Segments: 2, Flash: false },
    }
}
"#;
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(false),
        scripts(prepare, None),
        &no_secrets(),
    );
    let content = content();

    provider.send(&message(&content)).await;

    let requests = received(&upstream).await;
    assert_eq!(
        header(&requests[0], "content-type").as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    let form = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(form["To"], "+15005550010");
    assert_eq!(form["Body"], "a&b=c Your appointment is at 10:00.");
    assert_eq!(form["Segments"], "2");
    assert_eq!(form["Flash"], "false");
}

#[tokio::test]
async fn a_nested_form_value_is_refused_before_sending() {
    let upstream = MockHttpUpstream::start().await;
    let prepare = r#"
fn prepare(message, profile) {
    #{ target: "messages", bodyFormat: "form", body: #{ to: [message.recipient] } }
}
"#;
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(false),
        scripts(prepare, None),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, permanent_code("provider.prepare-failed"));
    assert!(received(&upstream).await.is_empty());
}

#[tokio::test]
async fn a_get_provider_sends_no_body_and_needs_the_query_string_acknowledgement() {
    let upstream = MockHttpUpstream::start().await;
    upstream.expect("GET", "/v1/send").respond_status(200).await;
    let mut package = plain_package(false);
    package.request.method = HttpSendMethod::Get;
    let prepare = r#"
fn prepare(message, profile) {
    #{ target: "send?to=" + message.recipient.sub_string(1) + "&from=" + profile.sender }
}
"#;
    let mut settings = settings(&base(&upstream), NONE);
    let refused = settings
        .activate(
            "gateway",
            &package,
            scripts(prepare, None),
            None,
            &no_secrets().resolver,
        )
        .expect_err("get needs the acknowledgement");
    assert!(
        refused
            .to_string()
            .starts_with("acknowledgeQueryStringContent:"),
        "{refused}"
    );
    settings.acknowledge_query_string_content = true;
    let provider = activate(&settings, &package, scripts(prepare, None), &no_secrets());
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, accepted(None));
    let requests = received(&upstream).await;
    assert!(requests[0].body.is_empty());
    assert_eq!(
        requests[0].url.query(),
        Some("to=15005550010&from=Registry")
    );
}

// ---------------------------------------------------------------------------
// Classification.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn without_an_interpret_script_the_status_classifies_the_response() {
    let cases = [
        (200, accepted(None)),
        (201, accepted(None)),
        (202, accepted(None)),
        (302, permanent_code("http.302")),
        (400, permanent_code("http.400")),
        (401, permanent_code("http.401")),
        (404, permanent_code("http.404")),
        (422, permanent_code("http.422")),
        (408, SendOutcome::Transient { retry_after: None }),
        (429, SendOutcome::Transient { retry_after: None }),
        (500, SendOutcome::Transient { retry_after: None }),
        (503, SendOutcome::Transient { retry_after: None }),
    ];
    for (status, expected) in cases {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/v1/messages")
            .respond_status(status)
            .await;
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected, "status {status}");
        assert_eq!(sent.detail.status, Some(status));
        assert_eq!(
            received(&upstream).await.len(),
            1,
            "no redirect is followed"
        );
    }
}

#[tokio::test]
async fn retry_after_is_honoured_in_delta_seconds_and_capped() {
    let cases = [
        (429, "30", Some(Duration::from_secs(30))),
        (
            503,
            "999999",
            Some(Duration::from_secs(MAXIMUM_RETRY_AFTER_SECONDS)),
        ),
        (503, "Wed, 21 Oct 2026 07:28:00 GMT", None),
        (429, "0", None),
        (408, "5", Some(Duration::from_secs(5))),
    ];
    for (status, value, expected) in cases {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/v1/messages")
            .respond(ResponseTemplate::new(status).insert_header("retry-after", value))
            .await;
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(
            sent.outcome,
            SendOutcome::Transient {
                retry_after: expected
            },
            "{status} with Retry-After {value}"
        );
    }
}

async fn interpret_once(template: ResponseTemplate) -> Sent<HttpAttemptDetail> {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond(template)
        .await;
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(true),
        scripts(JSON_PREPARE, Some(ERROR_BODY_INTERPRET)),
        &no_secrets(),
    );
    let content = content();
    provider.send(&message(&content)).await
}

#[tokio::test]
async fn the_interpret_script_classifies_a_success_status_carrying_an_error_body() {
    let error = interpret_once(
        ResponseTemplate::new(200).set_body_json(json!({"error": {"reason": "blocked"}})),
    )
    .await;
    let success =
        interpret_once(ResponseTemplate::new(200).set_body_json(json!({"id": "gw-42"}))).await;

    assert_eq!(error.outcome, permanent_code("gateway.rejected"));
    assert_eq!(error.detail.failure, None);
    assert_eq!(success.outcome, accepted(Some("gw-42")));
}

#[tokio::test]
async fn the_interpret_script_retry_after_wins_and_the_header_fills_in() {
    let own = interpret_once(ResponseTemplate::new(503).insert_header("retry-after", "60")).await;
    let header =
        interpret_once(ResponseTemplate::new(429).insert_header("retry-after", "12")).await;

    assert_eq!(
        own.outcome,
        SendOutcome::Transient {
            retry_after: Some(Duration::from_secs(7))
        }
    );
    assert_eq!(
        header.outcome,
        SendOutcome::Transient {
            retry_after: Some(Duration::from_secs(12))
        }
    );
}

#[tokio::test]
async fn a_success_the_script_cannot_classify_is_maybe_sent_and_a_failure_falls_back_to_the_status()
{
    let throwing = "fn interpret(response) { if response.body == () { throw \"unreadable\"; } #{ outcome: \"accepted\" } }";
    for (status, expected) in [
        (200, SendOutcome::MaybeSent),
        (500, SendOutcome::Transient { retry_after: None }),
        (404, permanent_code("http.404")),
    ] {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/v1/messages")
            .respond(ResponseTemplate::new(status).set_body_string("not json"))
            .await;
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(true),
            scripts(JSON_PREPARE, Some(throwing)),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected, "status {status}");
        assert_eq!(
            sent.detail.failure,
            Some(HttpFailure::Script(ScriptFailure::Failed)),
            "status {status}"
        );
    }
}

#[tokio::test]
async fn a_success_whose_body_exceeds_the_response_bound_is_maybe_sent() {
    let upstream = MockHttpUpstream::start().await;
    let padding = "x".repeat(2_048);
    upstream
        .expect("POST", "/v1/messages")
        .respond(
            ResponseTemplate::new(200).set_body_json(json!({"id": "gw-1", "padding": padding})),
        )
        .await;
    let mut settings = settings(&base(&upstream), NONE);
    settings.maximum_response_bytes = 1_024;
    let provider = activate(
        &settings,
        &plain_package(true),
        scripts(JSON_PREPARE, Some(ERROR_BODY_INTERPRET)),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
    assert_eq!(sent.detail.failure, Some(HttpFailure::ResponseUnreadable));
}

#[tokio::test]
async fn an_interpret_output_that_mixes_outcome_members_is_refused() {
    for output in [
        r#"#{ outcome: "accepted", code: "x" }"#,
        r#"#{ outcome: "permanent" }"#,
        r#"#{ outcome: "permanent", code: "Not A Code" }"#,
        r#"#{ outcome: "transient", retryAfter: 0 }"#,
        r#"#{ outcome: "maybe-sent", providerReference: "x" }"#,
        r#"#{ outcome: "accepted", providerReference: "has space" }"#,
        r#"#{ outcome: "delivered" }"#,
        r#"#{ outcome: "accepted", extra: true }"#,
    ] {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/v1/messages")
            .respond_status(200)
            .await;
        let interpret = format!("fn interpret(response) {{ {output} }}");
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(true),
            scripts(JSON_PREPARE, Some(&interpret)),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, SendOutcome::MaybeSent, "{output}");
        assert_eq!(
            sent.detail.failure,
            Some(HttpFailure::Script(ScriptFailure::OutputInvalid)),
            "{output}"
        );
    }
}

#[tokio::test]
async fn an_interpret_output_over_its_bound_is_refused() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(200)
        .await;
    let interpret = r#"
fn interpret(response) {
    let padding = "x";
    for i in 0..17 { padding += padding; }
    #{ outcome: "accepted", providerReference: padding }
}
"#;
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(true),
        scripts(JSON_PREPARE, Some(interpret)),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
    assert_eq!(
        sent.detail.failure,
        Some(HttpFailure::Script(ScriptFailure::OutputTooLarge))
    );
}

#[tokio::test]
async fn a_runaway_prepare_script_exhausts_its_budget_and_nothing_is_sent() {
    let upstream = MockHttpUpstream::start().await;
    let prepare = "fn prepare(message, profile) { loop { } }";
    let provider = activate(
        &settings(&base(&upstream), NONE),
        &plain_package(false),
        scripts(prepare, None),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, permanent_code("provider.prepare-failed"));
    assert_eq!(
        sent.detail.failure,
        Some(HttpFailure::Script(ScriptFailure::ResourceExhausted))
    );
    assert!(received(&upstream).await.is_empty());
}

// ---------------------------------------------------------------------------
// Delivery certainty of transport failures.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_connection_is_not_sent_and_transient() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("address").port()
    };
    let provider = activate(
        &settings(&format!("http://127.0.0.1:{port}/v1/"), NONE),
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: None });
    let Some(HttpFailure::Destination(error)) = sent.detail.failure else {
        panic!("expected a destination failure, got {:?}", sent.detail);
    };
    assert_eq!(
        error.delivery_certainty(),
        DestinationDeliveryCertainty::NotSent
    );
}

#[tokio::test]
async fn a_connection_dropped_after_the_request_is_maybe_sent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0_u8; 4096];
            let _read = stream.read(&mut buffer).await;
            drop(stream);
        }
    });
    let provider = activate(
        &settings(&format!("http://127.0.0.1:{port}/v1/"), NONE),
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
    let Some(HttpFailure::Destination(error)) = sent.detail.failure else {
        panic!("expected a destination failure, got {:?}", sent.detail);
    };
    assert_eq!(
        error.delivery_certainty(),
        DestinationDeliveryCertainty::MaybeSent
    );
}

#[tokio::test]
async fn a_response_slower_than_the_timeout_is_maybe_sent() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond(ResponseTemplate::new(201).set_delay(Duration::from_millis(1_500)))
        .await;
    let mut settings = settings(&base(&upstream), NONE);
    settings.timeout_milliseconds = 300;
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::MaybeSent);
}

#[tokio::test]
async fn a_send_waiting_past_its_deadline_for_a_slot_is_transient() {
    let upstream = MockHttpUpstream::start().await;
    let mut settings = settings(&base(&upstream), NONE);
    settings.timeout_milliseconds = 200;
    settings.concurrency_limit = 1;
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let held = Arc::clone(&provider.slots)
        .acquire_owned()
        .await
        .expect("the only slot");
    let content = content();

    let sent = provider.send(&message(&content)).await;
    drop(held);

    assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: None });
    assert_eq!(sent.detail.stage, HttpStage::Queue);
    assert_eq!(sent.detail.failure, Some(HttpFailure::Deadline));
    assert!(received(&upstream).await.is_empty());
}

// ---------------------------------------------------------------------------
// MESSAGING-SEC-03: provider egress stays on public addresses.
// ---------------------------------------------------------------------------

/// A loopback listener that counts the connections it accepts.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

fn production(base_url: &str) -> HttpProviderSettings {
    settings(
        base_url,
        "  kind: static-authorization\n  tokenRef: secret:file/token\n",
    )
}

#[tokio::test]
async fn a_production_provider_name_resolving_to_loopback_is_refused_before_connecting() {
    let (port, accepted) = counting_listener().await;
    let secrets = secrets(&[("token", TOKEN)]);
    let provider = activate(
        &production(&format!("https://localhost:{port}/v1/")),
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &secrets,
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: None });
    let Some(HttpFailure::Destination(error)) = sent.detail.failure else {
        panic!("expected a destination refusal, got {:?}", sent.detail);
    };
    assert_eq!(
        error.delivery_certainty(),
        DestinationDeliveryCertainty::NotSent
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no connection was made");
}

#[tokio::test]
async fn metadata_private_and_loopback_provider_addresses_are_refused_without_an_allowlist() {
    let (port, accepted) = counting_listener().await;
    let secrets = secrets(&[("token", TOKEN)]);
    for base_url in [
        format!("https://127.0.0.1:{port}/v1/"),
        "https://169.254.169.254/latest/".to_owned(),
        "https://10.0.0.5/v1/".to_owned(),
        "https://[fd00::5]/v1/".to_owned(),
        "https://100.64.0.1/v1/".to_owned(),
    ] {
        let outcome = match production(&base_url).activate(
            "gateway",
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            None,
            &secrets.resolver,
        ) {
            Ok(provider) => {
                let content = content();
                let sent = provider.send(&message(&content)).await;
                assert!(
                    matches!(
                        sent.detail.failure,
                        Some(HttpFailure::Destination(error))
                            if error.delivery_certainty() == DestinationDeliveryCertainty::NotSent
                    ),
                    "{base_url}: {:?}",
                    sent.detail
                );
                sent.outcome
            }
            Err(error) => panic!("{base_url} should activate and be refused per send: {error}"),
        };
        assert_eq!(
            outcome,
            SendOutcome::Transient { retry_after: None },
            "{base_url}"
        );
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no connection was made");
}

#[test]
fn a_private_network_allowance_must_be_an_exact_cidr_for_an_https_provider() {
    let secrets = secrets(&[("token", TOKEN)]);
    let mut development = settings("http://127.0.0.1:9/v1/", NONE);
    development.allowed_private_cidrs = vec!["10.0.0.0/8".to_owned()];
    let error = development
        .activate(
            "gateway",
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            None,
            &secrets.resolver,
        )
        .expect_err("development providers take no allowance");
    assert!(
        error.to_string().starts_with("allowedPrivateCidrs:"),
        "{error}"
    );
    let mut production = production("https://gateway.internal.example/v1/");
    production.allowed_private_cidrs = vec!["not-a-network".to_owned()];
    let error = production
        .activate(
            "gateway",
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            None,
            &secrets.resolver,
        )
        .expect_err("a malformed allowance is refused");
    assert!(
        error.to_string().starts_with("allowedPrivateCidrs:"),
        "{error}"
    );
}

#[test]
fn a_provider_url_with_credentials_a_query_or_plain_http_to_a_remote_host_is_refused() {
    let secrets = secrets(&[("token", TOKEN)]);
    for base_url in [
        "https://user:pass@gateway.example.org/v1/",
        "https://gateway.example.org/v1/?key=x",
        "https://gateway.example.org/v1/#x",
        "http://gateway.example.org/v1/",
        "https://gateway.example.org/v1",
        "https://gateway.example.org/v1/%2e%2e/",
        "ftp://gateway.example.org/v1/",
    ] {
        let error = production(base_url)
            .activate(
                "gateway",
                &plain_package(false),
                scripts(JSON_PREPARE, None),
                None,
                &secrets.resolver,
            )
            .expect_err(base_url);
        assert!(
            error.to_string().starts_with("baseUrl:"),
            "{base_url}: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// MESSAGING-SEC-02 at the provider: a script cannot choose the endpoint, a
// header the runtime owns, or a credential.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_script_target_outside_the_base_path_or_origin_is_refused() {
    let upstream = MockHttpUpstream::start().await;
    upstream.expect("POST", "/admin").respond_status(200).await;
    for target in [
        "../admin",
        "messages/../../admin",
        "/admin",
        "//evil.example/admin",
        "https://evil.example/admin",
        "messages#fragment",
        "messages\\..\\admin",
        "",
        "%2e%2e/admin",
    ] {
        let prepare = format!(
            "fn prepare(message, profile) {{ #{{ target: {target:?}, bodyFormat: \"json\", body: #{{ a: 1 }} }} }}"
        );
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(false),
            scripts(&prepare, None),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(
            sent.outcome,
            permanent_code("provider.request-refused"),
            "{target}"
        );
        assert_eq!(
            sent.detail.failure,
            Some(HttpFailure::RequestRefused),
            "{target}"
        );
    }
    assert!(
        received(&upstream).await.is_empty(),
        "nothing left the process"
    );
}

#[tokio::test]
async fn a_script_header_outside_the_declared_allowlist_is_refused() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(200)
        .await;
    for header in [
        "x-undeclared",
        "authorization",
        "host",
        "content-type",
        "cookie",
    ] {
        let prepare = format!(
            "fn prepare(message, profile) {{ #{{ target: \"messages\", headers: #{{ {header:?}: \"v\" }}, bodyFormat: \"json\", body: #{{ a: 1 }} }} }}"
        );
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(false),
            scripts(&prepare, None),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(
            sent.outcome,
            permanent_code("provider.request-refused"),
            "{header}"
        );
    }
    assert!(
        received(&upstream).await.is_empty(),
        "nothing left the process"
    );
}

#[test]
fn a_package_may_not_declare_a_runtime_owned_request_header() {
    for header in [
        "authorization",
        "host",
        "content-type",
        "content-length",
        "cookie",
    ] {
        let mut package = plain_package(false);
        package.request.headers = vec![header.to_owned()];
        let error = package.validate().expect_err(header);
        assert!(
            error.to_string().starts_with("request.headers:"),
            "{header}: {error}"
        );
    }
}

#[test]
fn an_api_key_header_may_not_also_be_script_writable() {
    let secrets = secrets(&[("key", TOKEN)]);
    let settings = settings(
        "https://gateway.example.org/v1/",
        "  kind: static-api-key\n  headerName: x-request-id\n  valueRef: secret:file/key\n",
    );
    let error = settings
        .activate(
            "gateway",
            &plain_package(false),
            scripts(JSON_PREPARE, None),
            None,
            &secrets.resolver,
        )
        .expect_err("the script could overwrite the key");
    assert!(
        error.to_string().starts_with("authentication.headerName:"),
        "{error}"
    );
}

#[tokio::test]
async fn secrets_are_absent_from_script_scope() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/v1/messages")
        .respond_status(201)
        .await;
    let secrets = secrets(&[("user", b"account-1"), ("password", PASSWORD)]);
    let settings = settings(
        &base(&upstream),
        "  kind: basic\n  usernameRef: secret:file/user\n  passwordRef: secret:file/password\n",
    );
    let prepare = r#"
fn prepare(message, profile) {
    #{
        target: "messages",
        bodyFormat: "json",
        body: #{
            messageKeys: message.keys(),
            profileKeys: profile.keys(),
            partKeys: message.parts.keys(),
            message: message,
            profile: profile,
        },
    }
}
"#;
    let provider = activate(
        &settings,
        &plain_package(false),
        scripts(prepare, None),
        &secrets,
    );
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(sent.outcome, accepted(None));
    let requests = received(&upstream).await;
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    let mut message_keys = body["messageKeys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key.as_str().expect("key").to_owned())
        .collect::<Vec<_>>();
    message_keys.sort();
    assert_eq!(
        message_keys,
        [
            "attempt",
            "channel",
            "generation",
            "idempotencyKey",
            "messageId",
            "parts",
            "recipient"
        ]
    );
    let mut profile_keys = body["profileKeys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key.as_str().expect("key").to_owned())
        .collect::<Vec<_>>();
    profile_keys.sort();
    assert_eq!(profile_keys, ["channel", "id", "maximumSegments", "sender"]);
    let raw = String::from_utf8(requests[0].body.clone()).expect("utf-8 body");
    assert!(!raw.contains("password-value-51be"));
    assert!(!raw.contains("secret:"));
    assert!(
        header(&requests[0], "authorization").is_some(),
        "Rust placed the credential"
    );
}

#[tokio::test]
async fn a_script_referring_to_anything_outside_its_arguments_fails() {
    let upstream = MockHttpUpstream::start().await;
    for expression in ["token", "env", "secrets", "authorization"] {
        let prepare = format!(
            "fn prepare(message, profile) {{ #{{ target: \"messages\", bodyFormat: \"json\", body: #{{ leaked: {expression} }} }} }}"
        );
        let provider = activate(
            &settings(&base(&upstream), NONE),
            &plain_package(false),
            scripts(&prepare, None),
            &no_secrets(),
        );
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(
            sent.detail.failure,
            Some(HttpFailure::Script(ScriptFailure::Failed)),
            "{expression}"
        );
    }
    assert!(received(&upstream).await.is_empty());
}

// ---------------------------------------------------------------------------
// Startup checks and strict configuration.
// ---------------------------------------------------------------------------

#[test]
fn idempotent_submission_is_declared_in_the_manifest_not_in_capabilities() {
    let declared_here = serde_norway::from_str::<HttpProviderPackage>(
        "prepareScript: p.rhai\nrequest: {method: post}\n\
         capabilities: {receipts: none, idempotentSubmit: true, concurrencyLimit: 1}\n",
    );
    assert!(declared_here.is_err());
}

#[test]
fn unknown_configuration_members_are_refused() {
    let unknown_setting = serde_norway::from_str::<HttpProviderSettings>(
        "baseUrl: https://gateway.example.org/v1/\ntimeoutMilliseconds: 1000\n\
         maximumResponseBytes: 1024\nconcurrencyLimit: 1\nredirects: deny\n\
         authentication: {kind: none}\nfollowRedirects: true\n",
    );
    assert!(unknown_setting.is_err());
    let unknown_authentication_member = serde_norway::from_str::<HttpProviderSettings>(
        "baseUrl: https://gateway.example.org/v1/\ntimeoutMilliseconds: 1000\n\
         maximumResponseBytes: 1024\nconcurrencyLimit: 1\nredirects: deny\n\
         authentication: {kind: static-authorization, tokenRef: secret:file/t, token: inline}\n",
    );
    assert!(unknown_authentication_member.is_err());
    let unknown_kind = serde_norway::from_str::<HttpProviderSettings>(
        "baseUrl: https://gateway.example.org/v1/\ntimeoutMilliseconds: 1000\n\
         maximumResponseBytes: 1024\nconcurrencyLimit: 1\nredirects: deny\n\
         authentication: {kind: digest}\n",
    );
    assert!(unknown_kind.is_err());
    let follow_redirects = serde_norway::from_str::<HttpProviderSettings>(
        "baseUrl: https://gateway.example.org/v1/\ntimeoutMilliseconds: 1000\n\
         maximumResponseBytes: 1024\nconcurrencyLimit: 1\nredirects: follow\n\
         authentication: {kind: none}\n",
    );
    assert!(follow_redirects.is_err());
    let unknown_package_member = serde_norway::from_str::<HttpProviderPackage>(
        "prepareScript: p.rhai\nrequest: {method: post}\n\
         capabilities: {receipts: none, concurrencyLimit: 1}\n\
         endpoint: https://gateway.example.org/\n",
    );
    assert!(unknown_package_member.is_err());
    let unknown_capability = serde_norway::from_str::<HttpProviderPackage>(
        "prepareScript: p.rhai\nrequest: {method: post}\n\
         capabilities: {receipts: none, concurrencyLimit: 1, burst: 3}\n",
    );
    assert!(unknown_capability.is_err());
}

type PackageChange = fn(&mut HttpProviderPackage);
type SettingsChange = fn(&mut HttpProviderSettings);

#[test]
fn package_capabilities_and_script_paths_are_bounded() {
    let cases: [(&str, PackageChange); 7] = [
        ("capabilities.concurrencyLimit", |package| {
            package.capabilities.concurrency_limit = 0;
        }),
        ("capabilities.concurrencyLimit", |package| {
            package.capabilities.concurrency_limit = MAXIMUM_CONCURRENCY_LIMIT + 1;
        }),
        ("capabilities.ratePerSecond", |package| {
            package.capabilities.rate_per_second = Some(0);
        }),
        ("capabilities.ratePerSecond", |package| {
            package.capabilities.rate_per_second = Some(MAXIMUM_RATE_PER_SECOND + 1);
        }),
        ("prepareScript", |package| {
            package.prepare_script = "../outside.rhai".to_owned();
        }),
        ("receiptScript", |package| {
            package.capabilities.receipts = ReceiptCapability::Callback;
        }),
        ("receiptScript", |package| {
            package.receipt_script = Some("receipt.rhai".to_owned());
        }),
    ];
    for (field, change) in cases {
        let mut package = plain_package(false);
        change(&mut package);
        let error = package.validate().expect_err(field);
        assert!(
            error.to_string().starts_with(&format!("{field}:")),
            "{error}"
        );
    }
}

#[test]
fn connection_bounds_are_checked_at_activation() {
    let secrets = no_secrets();
    let cases: [(&str, SettingsChange); 5] = [
        ("timeoutMilliseconds", |settings| {
            settings.timeout_milliseconds = 10_001;
        }),
        ("maximumResponseBytes", |settings| {
            settings.maximum_response_bytes = MAXIMUM_RESPONSE_BYTES + 1;
        }),
        ("concurrencyLimit", |settings| {
            settings.concurrency_limit = 5
        }),
        ("tlsTrustProfile", |settings| {
            settings.tls_trust_profile = Some("gateway-ca".to_owned());
        }),
        ("callbackVerifier", |settings| {
            settings.callback_verifier = Some(CallbackVerifierConfig::PathToken {
                token_ref: "secret:file/path-token".to_owned(),
            });
        }),
    ];
    for (field, change) in cases {
        let mut settings = settings("http://127.0.0.1:9/v1/", NONE);
        change(&mut settings);
        let error = settings
            .activate(
                "gateway",
                &plain_package(false),
                scripts(JSON_PREPARE, None),
                None,
                &secrets.resolver,
            )
            .expect_err(field);
        assert!(
            error.to_string().starts_with(&format!("{field}:")),
            "{error}"
        );
    }
}

#[test]
fn scripts_are_compiled_at_activation_against_their_entry_points() {
    let secrets = no_secrets();
    let settings = settings("http://127.0.0.1:9/v1/", NONE);
    let cases = [
        ("fn prepare(message) { #{} }", None, "prepareScript"),
        ("fn prepare(message, profile) {", None, "prepareScript"),
        (
            JSON_PREPARE,
            Some("fn classify(response) { #{} }"),
            "interpretScript",
        ),
    ];
    for (prepare, interpret, field) in cases {
        let error = settings
            .activate(
                "gateway",
                &plain_package(true),
                scripts(prepare, interpret.or(Some(ERROR_BODY_INTERPRET))),
                None,
                &secrets.resolver,
            )
            .expect_err(field);
        assert!(
            error.to_string().starts_with(&format!("{field}:")),
            "{error}"
        );
    }
    let missing = settings
        .activate(
            "gateway",
            &plain_package(true),
            scripts(JSON_PREPARE, None),
            None,
            &secrets.resolver,
        )
        .expect_err("the declared interpret script is missing");
    assert!(
        missing.to_string().starts_with("interpretScript:"),
        "{missing}"
    );
}

#[test]
fn a_debug_rendering_never_shows_a_credential_reference() {
    let settings = settings(
        "https://gateway.example.org/v1/",
        "  kind: basic\n  usernameRef: secret:file/user-name-ref\n  passwordRef: secret:file/password-ref\n",
    );
    let rendered = format!("{settings:?}");
    assert!(!rendered.contains("user-name-ref"));
    assert!(!rendered.contains("password-ref"));
    assert!(rendered.contains("basic"));
}

// ---------------------------------------------------------------------------
// Example packages.
// ---------------------------------------------------------------------------

const FORM_SMS_PACKAGE: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/provider.yaml"
);
const FORM_SMS_CONNECTION: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/connection.example.yaml"
);
const FORM_SMS_PREPARE: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/scripts/prepare.rhai"
);
const FORM_SMS_INTERPRET: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/scripts/interpret.rhai"
);
const FORM_SMS_RECEIPT: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/scripts/receipt.rhai"
);
const FORM_SMS_ACCEPTED: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/accepted.json"
);
const FORM_SMS_INVALID_RECIPIENT: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/invalid-recipient.json"
);
const FORM_SMS_RATE_LIMITED: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/rate-limited.json"
);
const FORM_SMS_CALLBACK_DELIVERED: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/callback-delivered.form"
);
const FORM_SMS_CALLBACK_UNDELIVERED: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/callback-undelivered.form"
);
const FORM_SMS_CALLBACK_SENDING: &str = include_str!(
    "../../../../products/messaging/examples/providers/form-sms-gateway/fixtures/callback-sending.form"
);

const MOCK_PACKAGE: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/provider.yaml");
const MOCK_CONNECTION: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/connection.example.yaml");
const MOCK_PREPARE: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/scripts/prepare.rhai");
const MOCK_INTERPRET: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/scripts/interpret.rhai");
const MOCK_RECEIPT: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/scripts/receipt.rhai");
const MOCK_ACCEPTED: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/fixtures/accepted.json");
const MOCK_ERROR_BODY: &str =
    include_str!("../../../../products/messaging/examples/providers/mock/fixtures/error-body.json");
const MOCK_CALLBACK_FAILED: &str = include_str!(
    "../../../../products/messaging/examples/providers/mock/fixtures/callback-failed.json"
);

const FORM_SMS_ACCOUNT_PATH: &str = "/2010-04-01/Accounts/AC00000000000000000000000000000000/";

fn json_response(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.trim().as_bytes().to_vec(), "application/json")
}

async fn form_sms_gateway(upstream: &MockHttpUpstream, secrets: &Secrets) -> HttpProvider {
    let package = package(FORM_SMS_PACKAGE);
    let mut settings: HttpProviderSettings =
        serde_norway::from_str(FORM_SMS_CONNECTION).expect("example connection parses");
    settings.base_url = format!(
        "{}{FORM_SMS_ACCOUNT_PATH}",
        upstream.url().trim_end_matches('/')
    );
    settings
        .activate(
            "sms-gateway",
            &package,
            HttpProviderScripts {
                prepare: FORM_SMS_PREPARE,
                interpret: Some(FORM_SMS_INTERPRET),
                receipt: Some(FORM_SMS_RECEIPT),
            },
            None,
            &secrets.resolver,
        )
        .expect("the example activates")
}

fn form_sms_secrets() -> Secrets {
    secrets(&[
        ("sms-account-sid", b"AC00000000000000000000000000000000"),
        ("sms-auth-token", PASSWORD),
    ])
}

#[tokio::test]
async fn the_form_sms_example_sends_a_form_and_reads_recorded_shape_responses() {
    use base64::Engine as _;
    let secrets = form_sms_secrets();
    let content = content();
    let cases = [
        (
            json_response(201, FORM_SMS_ACCEPTED),
            accepted(Some("SM00000000000000000000000000000001")),
        ),
        (
            json_response(400, FORM_SMS_INVALID_RECIPIENT),
            permanent_code("gateway.21211"),
        ),
        (
            json_response(429, FORM_SMS_RATE_LIMITED).insert_header("retry-after", "2"),
            SendOutcome::Transient {
                retry_after: Some(Duration::from_secs(2)),
            },
        ),
        (
            json_response(201, r#"{"sid":"SM1","error_code":30007}"#),
            SendOutcome::MaybeSent,
        ),
    ];
    for (response, expected) in cases {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", &format!("{FORM_SMS_ACCOUNT_PATH}Messages.json"))
            .respond(response)
            .await;
        let provider = form_sms_gateway(&upstream, &secrets).await;

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected);
        let requests = received(&upstream).await;
        let form = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect::<Vec<_>>();
        assert_eq!(
            form,
            [
                (
                    "Body".to_owned(),
                    "Your appointment is at 10:00.".to_owned()
                ),
                ("From".to_owned(), "Registry".to_owned()),
                ("To".to_owned(), "+15005550010".to_owned()),
            ]
        );
        let expected_authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(b"AC00000000000000000000000000000000:password-value-51be")
        );
        assert_eq!(
            header(&requests[0], "authorization"),
            Some(expected_authorization)
        );
    }
}

#[tokio::test]
async fn the_form_sms_example_refuses_an_email_before_sending() {
    let secrets = form_sms_secrets();
    let upstream = MockHttpUpstream::start().await;
    let provider = form_sms_gateway(&upstream, &secrets).await;
    let mut content = content();
    content.profile.channel = Channel::Email;
    let mut email = message(&content);
    email.channel = Channel::Email;

    let sent = provider.send(&email).await;

    assert_eq!(sent.outcome, permanent_code("provider.prepare-failed"));
    assert!(received(&upstream).await.is_empty());
}

fn form_callback(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.trim().as_bytes())
        .into_owned()
        .collect()
}

#[tokio::test]
async fn the_form_sms_example_reads_recorded_shape_status_callbacks() {
    let secrets = form_sms_secrets();
    let upstream = MockHttpUpstream::start().await;
    let provider = form_sms_gateway(&upstream, &secrets).await;
    let read = |raw: &str| {
        let fields = form_callback(raw);
        let pairs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        provider.receipt(&CallbackRequest {
            method: "POST",
            url: "https://messaging.example.org/v1/callbacks/sms-gateway",
            form_parameters: &pairs,
            body: raw.trim().as_bytes(),
            headers: &[("x-callback-signature", "not-read-by-the-script")],
            path_token: None,
        })
    };

    assert_eq!(
        read(FORM_SMS_CALLBACK_DELIVERED),
        Ok(Some(Receipt {
            provider_reference: "SM00000000000000000000000000000001".to_owned(),
            report: DeliveryReport::Delivered,
            code: None,
        }))
    );
    assert_eq!(
        read(FORM_SMS_CALLBACK_UNDELIVERED),
        Ok(Some(Receipt {
            provider_reference: "SM00000000000000000000000000000001".to_owned(),
            report: DeliveryReport::Undelivered,
            code: Some("gateway.30003".to_owned()),
        }))
    );
    assert_eq!(read(FORM_SMS_CALLBACK_SENDING), Ok(None));
    assert_eq!(
        read("MessageSid=SM1&MessageSid=SM2&MessageStatus=sent"),
        Err(ReceiptScriptError::DuplicateField)
    );
    assert_eq!(
        read("Unrelated=1"),
        Err(ReceiptScriptError::Script(ScriptFailure::Failed))
    );
}

async fn mock_gateway(upstream: &MockHttpUpstream, secrets: &Secrets) -> HttpProvider {
    let package = package(MOCK_PACKAGE);
    let mut settings: HttpProviderSettings =
        serde_norway::from_str(MOCK_CONNECTION).expect("example connection parses");
    settings.base_url = base(upstream);
    settings
        .activate(
            "mail-and-sms",
            &package,
            HttpProviderScripts {
                prepare: MOCK_PREPARE,
                interpret: Some(MOCK_INTERPRET),
                receipt: Some(MOCK_RECEIPT),
            },
            None,
            &secrets.resolver,
        )
        .expect("the example activates")
}

#[tokio::test]
async fn the_mock_example_sends_json_with_an_idempotency_key_and_reads_its_answers() {
    let secrets = secrets(&[("gateway-token", TOKEN)]);
    let mut content = content();
    content.parts.subject = Some("Appointment".to_owned());
    for (response, expected) in [
        (
            json_response(202, MOCK_ACCEPTED),
            accepted(Some("msg-0001")),
        ),
        (
            json_response(200, MOCK_ERROR_BODY),
            permanent_code("gateway.rejected"),
        ),
        (
            json_response(502, "{}"),
            SendOutcome::Transient { retry_after: None },
        ),
    ] {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/v1/messages")
            .respond(response)
            .await;
        let provider = mock_gateway(&upstream, &secrets).await;

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected);
        let requests = received(&upstream).await;
        assert_eq!(
            header(&requests[0], "idempotency-key").as_deref(),
            Some("msg-0001")
        );
        assert_eq!(
            header(&requests[0], "authorization").as_deref(),
            Some("Bearer token-value-7f3a9c")
        );
        let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
        assert_eq!(body["subject"], "Appointment");
        assert_eq!(body["channel"], "sms");
        assert!(body.get("html").is_none());
    }
}

#[tokio::test]
async fn the_mock_example_reads_a_json_delivery_report() {
    let secrets = secrets(&[("gateway-token", TOKEN)]);
    let upstream = MockHttpUpstream::start().await;
    let provider = mock_gateway(&upstream, &secrets).await;

    let receipt = provider.receipt(&CallbackRequest {
        method: "POST",
        url: "https://messaging.example.org/v1/callbacks/mail-and-sms",
        form_parameters: &[],
        body: MOCK_CALLBACK_FAILED.trim().as_bytes(),
        headers: &[],
        path_token: None,
    });

    assert_eq!(
        receipt,
        Ok(Some(Receipt {
            provider_reference: "msg-0001".to_owned(),
            report: DeliveryReport::Undelivered,
            code: Some("gateway.unreachable".to_owned()),
        }))
    );
}

#[test]
fn a_receipt_is_refused_by_a_provider_without_a_receipt_script() {
    let provider = activate(
        &settings("http://127.0.0.1:9/v1/", NONE),
        &plain_package(false),
        scripts(JSON_PREPARE, None),
        &no_secrets(),
    );
    let receipt = provider.receipt(&CallbackRequest {
        method: "POST",
        url: "https://messaging.example.org/v1/callbacks/gateway",
        form_parameters: &[],
        body: b"{}",
        headers: &[],
        path_token: None,
    });
    assert_eq!(receipt, Err(ReceiptScriptError::NotDeclared));
}
