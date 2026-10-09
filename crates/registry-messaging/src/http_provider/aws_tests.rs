#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

//! The AWS End User Messaging SMS example against the HTTP provider boundary.

use std::os::unix::fs::PermissionsExt as _;

use registry_messaging_core::{Channel, RenderedParts, SenderProfile, UncertainPolicy};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_dispatch::{FailureCode, ReceiverReference, SendOutcome};
use registry_platform_testing::MockHttpUpstream;
use registry_platform_yaml::Reader;
use serde_json::Value;
use tempfile::TempDir;
use wiremock::ResponseTemplate;

use super::*;

const AWS_PACKAGE: &str =
    include_str!("../../../../products/messaging/examples/providers/aws-sms/provider.yaml");
const AWS_CONNECTION: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/connection.example.yaml"
);
const AWS_PREPARE: &str =
    include_str!("../../../../products/messaging/examples/providers/aws-sms/scripts/prepare.rhai");
const AWS_INTERPRET: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/scripts/interpret.rhai"
);
const AWS_ACCEPTED: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/accepted.json"
);
const AWS_MALFORMED_SUCCESS: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/malformed-success.json"
);
const AWS_THROTTLED: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/throttled.json"
);
const AWS_VALIDATION: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/validation.json"
);
const AWS_INTERNAL_SERVER: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/internal-server.json"
);
const AWS_THROTTLED_NAMESPACED: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/throttled-namespaced.json"
);
const AWS_EXPIRED_TOKEN: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/expired-token.json"
);
const AWS_UNRECOGNIZED_CLIENT: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/unrecognized-client.json"
);
const AWS_INVALID_SIGNATURE: &str = include_str!(
    "../../../../products/messaging/examples/providers/aws-sms/fixtures/invalid-signature.json"
);

const ACCESS_KEY_ID: &[u8] = b"AKIDEXAMPLE";
const SECRET_ACCESS_KEY: &[u8] = b"test-secret-access-key-51be";
const SESSION_TOKEN: &[u8] = b"test-session-token-7f3a9c";
const ORIGINATION_IDENTITY: &str = "REGISTRY";

struct Secrets {
    _root: TempDir,
    resolver: SecretResolver,
}

fn aws_secrets() -> Secrets {
    let root = tempfile::tempdir().expect("secret root");
    let path = root.path().canonicalize().expect("canonical secret root");
    for (name, value) in [
        ("aws-access-key-id", ACCESS_KEY_ID),
        ("aws-secret-access-key", SECRET_ACCESS_KEY),
        ("aws-session-token", SESSION_TOKEN),
    ] {
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

fn aws_package() -> HttpProviderPackage {
    HttpProviderPackage::decode(Reader::new("provider.yaml"), AWS_PACKAGE.as_bytes())
        .expect("AWS example package parses")
        .value
}

fn aws_settings(base_url: Option<&str>, session_token: bool) -> HttpProviderSettings {
    let mut settings: HttpProviderSettings =
        serde_norway::from_str(AWS_CONNECTION).expect("AWS example connection parses");
    if let Some(base_url) = base_url {
        settings.base_url = base_url.to_owned();
    }
    if session_token {
        let HttpProviderAuthentication::AwsSigv4 {
            session_token_ref, ..
        } = &mut settings.authentication
        else {
            panic!("the example uses aws-sigv4");
        };
        *session_token_ref = Some("secret:file/aws-session-token".to_owned());
    }
    settings
}

fn aws_provider(upstream: &MockHttpUpstream, secrets: &Secrets, prepare: &str) -> HttpProvider {
    let base_url = format!("{}/", upstream.url().trim_end_matches('/'));
    aws_settings(Some(&base_url), true)
        .activate(
            "aws-sms",
            &aws_package(),
            HttpProviderScripts {
                prepare,
                interpret: Some(AWS_INTERPRET),
                receipt: None,
            },
            None,
            &secrets.resolver,
        )
        .expect("AWS example activates")
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
            provider: "aws-sms".to_owned(),
            sender: ORIGINATION_IDENTITY.to_owned(),
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
        idempotency_key: None,
    }
}

fn json_response(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(
        body.trim().as_bytes().to_vec(),
        "application/x-amz-json-1.0",
    )
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
        .map(|value| value.to_str().expect("ASCII header").to_owned())
}

fn accepted(reference: &str) -> SendOutcome {
    SendOutcome::Accepted {
        receiver_reference: Some(ReceiverReference::new(reference).expect("valid reference")),
    }
}

fn permanent(code: &str) -> SendOutcome {
    SendOutcome::Permanent {
        code: FailureCode::new(code).expect("valid failure code"),
    }
}

#[test]
fn the_aws_example_builds_and_checks_as_an_installed_package() {
    let project = tempfile::tempdir().expect("project root");
    crate::package::tests::copy_starter(project.path());
    let manifest = project.path().join("messaging.yaml");
    let manifest_text = std::fs::read_to_string(&manifest)
        .expect("read starter manifest")
        .replace("  - id: sms-gateway\n", "  - id: aws-sms\n")
        .replace("    idempotentSubmit: true\n", "")
        .replace("    provider: sms-gateway\n", "    provider: aws-sms\n")
        .replace(
            "    sender: Registry\n    maximumSegments: 2\n",
            concat!(
                "    sender: REGISTRY\n",
                "    maximumSegments: 2\n",
                "    onUncertain: hold\n",
            ),
        );
    std::fs::write(&manifest, manifest_text).expect("write AWS manifest");
    let mock = project.path().join("providers/sms-gateway");
    let provider = project.path().join("providers/aws-sms");
    std::fs::rename(mock, &provider).expect("replace starter provider id");
    std::fs::write(provider.join("provider.yaml"), AWS_PACKAGE).expect("write provider package");
    std::fs::write(provider.join("scripts/prepare.rhai"), AWS_PREPARE)
        .expect("write prepare script");
    std::fs::write(provider.join("scripts/interpret.rhai"), AWS_INTERPRET)
        .expect("write interpret script");
    std::fs::remove_file(provider.join("scripts/receipt.rhai")).expect("remove receipt script");

    let inputs = crate::package::package_inputs(project.path()).expect("authoring project checks");
    let output = tempfile::tempdir().expect("installed package parent");
    let installed = output.path().join("package");
    crate::package::write_package_inputs(&installed, &inputs, Some("aws-example-test"))
        .expect("package installs");
    let loaded = crate::package::load_package(&installed).expect("installed package checks");

    let provider = &loaded.providers["aws-sms"];
    assert_eq!(
        provider.package.capabilities.receipts,
        ReceiptCapability::None
    );
    assert!(provider.scripts().interpret.is_some());
    assert!(provider.scripts().receipt.is_none());
    assert!(loaded
        .files
        .iter()
        .any(|file| file.path == "providers/aws-sms/scripts/interpret.rhai"));
}

#[test]
fn the_aws_example_package_and_connection_activate_together() {
    let package = aws_package();
    package.validate().expect("the provider package is valid");
    assert_eq!(package.capabilities.receipts, ReceiptCapability::None);
    assert!(package.interpret_script.is_some());
    assert!(package.receipt_script.is_none());

    let secrets = aws_secrets();
    let provider = aws_settings(None, false)
        .activate(
            "aws-sms",
            &package,
            HttpProviderScripts {
                prepare: AWS_PREPARE,
                interpret: Some(AWS_INTERPRET),
                receipt: None,
            },
            None,
            &secrets.resolver,
        )
        .expect("the example connection and scripts activate");
    assert_eq!(provider.capabilities().receipts, ReceiptCapability::None);
}

#[tokio::test]
async fn the_aws_example_sends_the_official_json_1_0_shape_with_a_session_token() {
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/")
        .respond(json_response(200, AWS_ACCEPTED))
        .await;
    let secrets = aws_secrets();
    let provider = aws_provider(&upstream, &secrets, AWS_PREPARE);
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(
        sent.outcome,
        accepted("00000000-1111-2222-3333-444444444444")
    );
    let requests = received(&upstream).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        header(&requests[0], "content-type").as_deref(),
        Some("application/x-amz-json-1.0")
    );
    assert_eq!(
        header(&requests[0], "x-amz-target").as_deref(),
        Some("PinpointSMSVoiceV2.SendTextMessage")
    );
    assert_eq!(
        header(&requests[0], "x-amz-security-token").as_deref(),
        Some("test-session-token-7f3a9c")
    );
    assert!(header(&requests[0], "x-amz-content-sha256").is_some());
    assert!(header(&requests[0], "x-amz-date").is_some());
    let authorization = header(&requests[0], "authorization").expect("authorization");
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    assert!(authorization.contains("/af-south-1/sms-voice/aws4_request"));
    assert!(authorization.contains(
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target"
    ));

    let body: Value = serde_json::from_slice(&requests[0].body).expect("AWS JSON body");
    assert_eq!(body["DestinationPhoneNumber"], "+15005550010");
    assert_eq!(body["OriginationIdentity"], ORIGINATION_IDENTITY);
    assert_eq!(body["MessageBody"], "Your appointment is at 10:00.");
    assert_eq!(body["MessageType"], "TRANSACTIONAL");
    assert_eq!(body.as_object().expect("object").len(), 4);
    let raw_body = String::from_utf8(requests[0].body.clone()).expect("UTF-8 body");
    assert!(!raw_body.contains("AKIDEXAMPLE"));
    assert!(!raw_body.contains("test-secret-access-key-51be"));
    assert!(!raw_body.contains("test-session-token-7f3a9c"));
}

#[tokio::test]
async fn the_aws_example_classifies_recorded_shape_answers_without_exposing_error_text() {
    let secrets = aws_secrets();
    let cases = [
        (
            200,
            AWS_ACCEPTED,
            accepted("00000000-1111-2222-3333-444444444444"),
        ),
        (200, AWS_MALFORMED_SUCCESS, SendOutcome::MaybeSent),
        (
            400,
            AWS_THROTTLED,
            SendOutcome::Transient { retry_after: None },
        ),
        (400, AWS_VALIDATION, permanent("aws.validation")),
        (500, AWS_INTERNAL_SERVER, SendOutcome::MaybeSent),
        (
            400,
            r#"{"__type":"UnexpectedException","Message":"body-canary-unknown"}"#,
            SendOutcome::MaybeSent,
        ),
    ];
    for (status, body, expected) in cases {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/")
            .respond(json_response(status, body))
            .await;
        let provider = aws_provider(&upstream, &secrets, AWS_PREPARE);
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected, "status {status}, body {body}");
        assert!(!format!("{sent:?}").contains("body-canary"));
    }
}

#[tokio::test]
async fn aws_credentials_are_not_in_the_prepare_script_views() {
    const SCOPE_PROBE: &str = r#"
fn prepare(message, profile) {
    #{
        target: "",
        headers: #{ "x-amz-target": "PinpointSMSVoiceV2.SendTextMessage" },
        bodyFormat: "json",
        body: #{
            MessageKeys: message.keys(),
            ProfileKeys: profile.keys(),
            PartsKeys: message.parts.keys(),
        },
    }
}
"#;
    let upstream = MockHttpUpstream::start().await;
    upstream
        .expect("POST", "/")
        .respond(json_response(200, AWS_ACCEPTED))
        .await;
    let secrets = aws_secrets();
    let provider = aws_provider(&upstream, &secrets, SCOPE_PROBE);
    let content = content();

    let sent = provider.send(&message(&content)).await;

    assert_eq!(
        sent.outcome,
        accepted("00000000-1111-2222-3333-444444444444")
    );
    let requests = received(&upstream).await;
    let body: Value = serde_json::from_slice(&requests[0].body).expect("probe body");
    let sorted_strings = |field: &Value| {
        let mut values = field
            .as_array()
            .expect("array")
            .iter()
            .map(|value| value.as_str().expect("string").to_owned())
            .collect::<Vec<_>>();
        values.sort();
        values
    };
    assert_eq!(
        sorted_strings(&body["MessageKeys"]),
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
    assert_eq!(
        sorted_strings(&body["ProfileKeys"]),
        ["channel", "id", "maximumSegments", "sender"]
    );
    assert_eq!(sorted_strings(&body["PartsKeys"]), ["text"]);
    let raw_body = String::from_utf8(requests[0].body.clone()).expect("UTF-8 body");
    for absent in [
        "accessKeyId",
        "secretAccessKey",
        "sessionToken",
        "AKIDEXAMPLE",
        "test-secret-access-key-51be",
        "test-session-token-7f3a9c",
    ] {
        assert!(!raw_body.contains(absent), "script saw {absent}");
    }
}

#[tokio::test]
async fn aws_non_root_non_json_or_missing_action_requests_are_refused_before_connecting() {
    let secrets = aws_secrets();
    let upstream = MockHttpUpstream::start().await;
    let cases = [
        r#"fn prepare(message, profile) {
            #{ target: "messages", headers: #{ "x-amz-target": "PinpointSMSVoiceV2.SendTextMessage" }, bodyFormat: "json", body: #{ a: 1 } }
        }"#,
        r#"fn prepare(message, profile) {
            #{ target: "", headers: #{}, bodyFormat: "json", body: #{ a: 1 } }
        }"#,
        r#"fn prepare(message, profile) {
            #{ target: "", headers: #{ "x-amz-target": "PinpointSMSVoiceV2.SendTextMessage" }, bodyFormat: "form", body: #{ a: 1 } }
        }"#,
    ];
    for prepare in cases {
        let provider = aws_provider(&upstream, &secrets, prepare);
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, permanent("provider.request-refused"));
        assert_eq!(sent.detail.stage, HttpStage::Prepare);
    }
    assert!(received(&upstream).await.is_empty());
}

fn activate_with(secrets: &Secrets) -> Result<HttpProvider, HttpProviderError> {
    aws_settings(None, true).activate(
        "aws-sms",
        &aws_package(),
        HttpProviderScripts {
            prepare: AWS_PREPARE,
            interpret: Some(AWS_INTERPRET),
            receipt: None,
        },
        None,
        &secrets.resolver,
    )
}

#[test]
fn aws_credential_files_written_with_a_trailing_newline_are_refused_by_reference() {
    for (name, field, value) in [
        (
            "aws-secret-access-key",
            "authentication.secretAccessKeyRef",
            &b"test-secret-access-key-51be\n"[..],
        ),
        (
            "aws-secret-access-key",
            "authentication.secretAccessKeyRef",
            b"test-secret-access-key-51be\r\n",
        ),
        (
            "aws-session-token",
            "authentication.sessionTokenRef",
            b"test-session-token-7f3a9c\n",
        ),
        (
            "aws-access-key-id",
            "authentication.accessKeyIdRef",
            b"AKIDEXAMPLE\n",
        ),
    ] {
        let secrets = aws_secrets();
        std::fs::write(secrets._root.path().join(name), value).expect("rewrite secret");

        let Err(error) = activate_with(&secrets) else {
            panic!("a credential with a trailing newline is refused");
        };
        let error = error.to_string();

        assert!(error.contains(field), "{error}");
        assert!(error.contains(&format!("secret:file/{name}")), "{error}");
        assert!(error.contains("trailing newline"), "{error}");
        for secret in [
            "AKIDEXAMPLE",
            "test-secret-access-key-51be",
            "test-session-token-7f3a9c",
        ] {
            assert!(!error.contains(secret), "{error}");
        }
    }
}

#[test]
fn aws_secret_access_keys_with_inner_whitespace_or_non_ascii_are_refused() {
    for value in [
        "test secret".as_bytes(),
        b"test\tsecret",
        "test-secr\u{e9}t".as_bytes(),
    ] {
        let secrets = aws_secrets();
        std::fs::write(secrets._root.path().join("aws-secret-access-key"), value)
            .expect("rewrite secret");

        let Err(error) = activate_with(&secrets) else {
            panic!("a non-printable secret access key is refused");
        };
        let error = error.to_string();

        assert!(
            error.contains("authentication.secretAccessKeyRef"),
            "{error}"
        );
        assert!(
            error.contains("secret:file/aws-secret-access-key"),
            "{error}"
        );
        assert!(!error.contains("secret\t") && !error.contains("test secret"));
    }
}

#[tokio::test]
async fn the_aws_example_reads_namespaced_and_bare_error_types() {
    let secrets = aws_secrets();
    let transient = SendOutcome::Transient { retry_after: None };
    let cases = [
        (400, AWS_THROTTLED_NAMESPACED, transient.clone()),
        (
            400,
            r#"{"__type":"ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/","message":"body-canary"}"#,
            transient,
        ),
        (400, AWS_EXPIRED_TOKEN, permanent("aws.expired-token")),
        (
            400,
            r#"{"__type":"ExpiredTokenException","message":"body-canary"}"#,
            permanent("aws.expired-token"),
        ),
        (
            400,
            AWS_UNRECOGNIZED_CLIENT,
            permanent("aws.unrecognized-client"),
        ),
        (
            403,
            AWS_INVALID_SIGNATURE,
            permanent("aws.invalid-signature"),
        ),
        (
            403,
            r#"{"__type":"com.amazon.coral.service#IncompleteSignatureException","message":"body-canary"}"#,
            permanent("aws.incomplete-signature"),
        ),
        (
            403,
            r#"{"__type":"MissingAuthenticationTokenException","message":"body-canary"}"#,
            permanent("aws.missing-authentication-token"),
        ),
        (
            400,
            r#"{"__type":"com.amazon.coral.service#AccessDeniedException:http://internal.amazon.com/coral/com.amazon.coral.service/","message":"body-canary"}"#,
            permanent("aws.access-denied"),
        ),
        (
            400,
            r#"{"__type":"com.amazonaws.pinpointsmsvoicev2#ValidationException","message":"body-canary"}"#,
            permanent("aws.validation"),
        ),
        (
            500,
            r#"{"__type":"com.amazon.coral.service#ExpiredTokenException","message":"body-canary"}"#,
            SendOutcome::MaybeSent,
        ),
        (
            400,
            r#"{"__type":"com.amazon.coral.service#UnexpectedException","message":"body-canary"}"#,
            SendOutcome::MaybeSent,
        ),
        (
            403,
            r#"{"message":"body-canary-no-type"}"#,
            SendOutcome::MaybeSent,
        ),
        (
            400,
            r##"{"__type":"#","message":"body-canary"}"##,
            SendOutcome::MaybeSent,
        ),
    ];
    for (status, body, expected) in cases {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/")
            .respond(json_response(status, body))
            .await;
        let provider = aws_provider(&upstream, &secrets, AWS_PREPARE);
        let content = content();

        let sent = provider.send(&message(&content)).await;

        assert_eq!(sent.outcome, expected, "status {status}, body {body}");
        assert!(!format!("{sent:?}").contains("body-canary"));
    }
}

#[test]
fn packages_naming_response_headers_scripts_cannot_read_are_refused() {
    for name in ["x-amzn-errortype", "server", "cf-ray"] {
        let mut package = aws_package();
        package.response_headers = vec![name.to_owned()];

        let error = package
            .validate()
            .expect_err("a withheld response header is refused")
            .to_string();

        assert!(error.contains("responseHeaders"), "{error}");
        assert!(!error.contains(name), "{error}");
        assert!(error.contains("scripts cannot read it"), "{error}");

        let refused = format!("{AWS_PACKAGE}responseHeaders: [{name}]\n");
        let report = HttpProviderPackage::decode(Reader::new("provider.yaml"), refused.as_bytes())
            .expect_err("a withheld response header is refused at read");
        let refusals: Vec<_> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(refusals, [("config.invalid-value", "/responseHeaders/0")]);
        assert!(report
            .diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.message.contains(name)));
    }
    let mut package = aws_package();
    package.response_headers = vec!["x-request-id".to_owned()];
    package
        .validate()
        .expect("a readable response header is accepted");
}
