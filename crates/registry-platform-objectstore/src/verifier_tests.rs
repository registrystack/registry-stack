use super::*;
use axum::{body::to_bytes, extract::Request, routing::any, Router};
use registry_platform_config::SecretProvider;
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const CONTENT: &[u8] = b"synthetic attachment for verification";
const TOKEN: &str = "verification-token-canary";
const POLICY: &str = "scanner-rules-2026-09";
const NAMESPACE: VerifierNamespace = VerifierNamespace {
    binding_domain: "breg-attachment-verification-http-v1",
    max_content_bytes: 1024 * 1024,
};

struct SecretFile(tempfile::TempDir);

impl SecretFile {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("token");
        std::fs::write(&file, TOKEN).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(root)
    }

    fn resolver(&self) -> SecretResolver {
        SecretResolver::new([SecretProvider::File], self.0.path()).unwrap()
    }
}

/// One request as the verifier received it.
#[derive(Clone, Debug)]
struct Received {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Hook {
    url: String,
    count: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Received>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Hook {
    async fn new(status: StatusCode, body: String, delay: Duration) -> Self {
        let count = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let calls = count.clone();
        let log = received.clone();
        let app = Router::new().fallback(any(move |request: Request| {
            let calls = calls.clone();
            let log = log.clone();
            let body = body.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let query = request.uri().query().map(str::to_owned);
                let headers = request
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            value.to_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect();
                let bytes = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                log.lock().unwrap().push(Received {
                    method,
                    path,
                    query,
                    headers,
                    body: bytes.to_vec(),
                });
                tokio::time::sleep(delay).await;
                (status, body)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/verify", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url,
            count,
            received,
            server,
        }
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn raw(url: &str) -> serde_json::Value {
    json!({"url":url, "authorizationRef":"secret:file/token", "policyId":POLICY})
}

fn settings(input: serde_json::Value) -> Result<HttpVerifierSettings> {
    HttpVerifierSettings::from_config(
        &serde_json::from_value::<AttachmentVerifierConfig>(input).unwrap(),
    )
}

fn activate(input: serde_json::Value, files: &SecretFile) -> HttpVerifier {
    settings(input)
        .unwrap()
        .activate(NAMESPACE, &files.resolver())
        .unwrap()
}

fn content_digest() -> String {
    hex::encode(Sha256::digest(CONTENT))
}

#[test]
fn verifier_config_is_strict_and_redacted() {
    for url in [
        "http://public.example/verify",
        "http://10.0.0.1/verify",
        "https://example/verify#fragment",
    ] {
        assert_eq!(
            settings(raw(url)).unwrap_err(),
            VerifierError::InvalidConfiguration,
            "{url}"
        );
    }
    // The shared block's `Url` already refuses these at decode.
    for url in [
        "https://user:secret@example/verify",
        "file:///verify",
        " https://example/verify",
    ] {
        assert!(serde_json::from_value::<AttachmentVerifierConfig>(raw(url)).is_err());
    }
    let mut input = raw("https://verification-canary.example/verify");
    input["authorizationRef"] = json!("inline-token-canary");
    let error = serde_json::from_value::<AttachmentVerifierConfig>(input)
        .expect_err("an inline token is not a secret reference");
    assert!(!error.to_string().contains("inline-token-canary"));
    for value in [
        json!(""),
        json!("contains whitespace"),
        json!("x".repeat(129)),
    ] {
        let mut input = raw("https://verification-canary.example/verify");
        input["policyId"] = value;
        assert_eq!(
            settings(input).unwrap_err(),
            VerifierError::InvalidConfiguration
        );
    }
    for timeout in [0, 99, 60_001] {
        let mut input = raw("https://verification-canary.example/verify");
        input["attemptTimeoutMilliseconds"] = json!(timeout);
        assert!(serde_json::from_value::<AttachmentVerifierConfig>(input).is_err());
    }
    let mut missing = raw("https://example/verify");
    missing.as_object_mut().unwrap().remove("policyId");
    assert!(serde_json::from_value::<AttachmentVerifierConfig>(missing).is_err());
    let mut endpoint = raw("https://example/verify");
    endpoint["endpoint"] = endpoint["url"].clone();
    assert!(serde_json::from_value::<AttachmentVerifierConfig>(endpoint).is_err());
    let files = SecretFile::new();
    let settings = settings(raw("https://verification-canary.example/verify")).unwrap();
    let verifier = settings.activate(NAMESPACE, &files.resolver()).unwrap();
    let debug = format!("{settings:?} {verifier:?}");
    assert!(!debug.contains("canary"), "{debug}");
}

#[test]
fn attempt_and_connect_timeouts_follow_the_configured_attempt() {
    let defaults = settings(raw("https://example/verify")).unwrap();
    assert_eq!(defaults.timeout, Duration::from_millis(10_000));
    assert_eq!(connect_timeout(defaults.timeout), Duration::from_secs(5));
    let mut input = raw("https://example/verify");
    input["attemptTimeoutMilliseconds"] = json!(100);
    let short = settings(input).unwrap();
    assert_eq!(short.timeout, Duration::from_millis(100));
    assert_eq!(connect_timeout(short.timeout), Duration::from_millis(100));
}

#[test]
fn activation_refuses_a_bad_namespace_or_credential() {
    let files = SecretFile::new();
    let settings = settings(raw("https://example/verify")).unwrap();
    for namespace in [
        VerifierNamespace {
            binding_domain: "",
            ..NAMESPACE
        },
        VerifierNamespace {
            binding_domain: "with space",
            ..NAMESPACE
        },
        VerifierNamespace {
            max_content_bytes: 0,
            ..NAMESPACE
        },
    ] {
        assert_eq!(
            settings.activate(namespace, &files.resolver()).unwrap_err(),
            VerifierError::InvalidConfiguration
        );
    }
    for token in ["", "with space", &"t".repeat(MAXIMUM_SECRET_BYTES + 1)] {
        std::fs::write(files.0.path().join("token"), token).unwrap();
        assert_eq!(
            settings.activate(NAMESPACE, &files.resolver()).unwrap_err(),
            VerifierError::Secret
        );
    }
    std::fs::remove_file(files.0.path().join("token")).unwrap();
    assert_eq!(
        settings.activate(NAMESPACE, &files.resolver()).unwrap_err(),
        VerifierError::Secret
    );
}

#[tokio::test]
async fn a_verification_posts_exactly_the_bytes_and_four_headers_and_never_the_policy() {
    let files = SecretFile::new();
    for (wire, expected) in [
        ("approved", Verdict::Approved),
        ("rejected", Verdict::Rejected),
    ] {
        let hook = Hook::new(
            StatusCode::OK,
            format!("{{\"verdict\":\"{wire}\"}}"),
            Duration::ZERO,
        )
        .await;
        let verifier = activate(raw(&hook.url), &files);
        assert_eq!(
            verifier
                .verify(&content_digest(), "application/pdf", CONTENT.to_vec())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(hook.count.load(Ordering::SeqCst), 1);
        let received = hook.received.lock().unwrap()[0].clone();
        assert_eq!(received.method, "POST");
        assert_eq!(received.path, "/verify");
        assert_eq!(received.query, None);
        assert_eq!(received.body, CONTENT);
        let header = |name: &str| {
            received
                .headers
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(header("authorization"), [format!("Bearer {TOKEN}")]);
        assert_eq!(header("content-type"), ["application/pdf"]);
        assert_eq!(header("accept"), ["application/json"]);
        assert_eq!(header("x-content-sha256"), [content_digest()]);
        // The policy identifies the binding only; it never reaches the wire.
        let everything = format!("{received:?}");
        assert!(!everything.contains(POLICY), "{everything}");
        assert!(!everything.to_ascii_lowercase().contains("policy"));
    }
}

#[test]
fn request_headers_are_the_fixed_set_with_a_sensitive_credential() {
    let files = SecretFile::new();
    let verifier = activate(raw("https://example/verify"), &files);
    let headers = verifier
        .request_headers(&content_digest(), "application/pdf", CONTENT)
        .unwrap();
    let mut names = headers.keys().map(|name| name.as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "accept",
            "authorization",
            "content-type",
            "x-content-sha256"
        ]
    );
    assert!(headers["authorization"].is_sensitive());
    assert!(!format!("{headers:?}").contains(TOKEN));
}

#[tokio::test]
async fn malformed_oversized_and_failed_verdicts_remain_unavailable() {
    let files = SecretFile::new();
    for (status, body) in [
        (StatusCode::OK, "{}".to_string()),
        (StatusCode::OK, "[]".to_string()),
        (StatusCode::OK, "{\"verdict\":\"unknown\"}".to_string()),
        (StatusCode::OK, "{\"verdict\":\"Approved\"}".to_string()),
        (
            StatusCode::OK,
            "{\"verdict\":\"approved\",\"secret\":\"response-canary\"}".to_string(),
        ),
        (
            StatusCode::OK,
            "{\"verdict\":\"approved\",\"verdict\":\"rejected\"}".to_string(),
        ),
        (
            StatusCode::OK,
            "{\"verdict\":\"approved\"} trailing".to_string(),
        ),
        (
            StatusCode::OK,
            " ".repeat(MAXIMUM_VERDICT_BYTES as usize + 1),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "response-canary".to_string(),
        ),
        (
            StatusCode::ACCEPTED,
            "{\"verdict\":\"approved\"}".to_string(),
        ),
        (StatusCode::NO_CONTENT, String::new()),
    ] {
        let hook = Hook::new(status, body, Duration::ZERO).await;
        let verifier = activate(raw(&hook.url), &files);
        let error = verifier
            .verify(&content_digest(), "application/pdf", CONTENT.to_vec())
            .await
            .unwrap_err();
        assert_eq!(error, VerifierError::Unavailable);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert_eq!(hook.count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn verification_timeout_and_invalid_input_cannot_approve() {
    let hook = Hook::new(
        StatusCode::OK,
        "{\"verdict\":\"approved\"}".to_string(),
        Duration::from_secs(1),
    )
    .await;
    let files = SecretFile::new();
    let mut input = raw(&hook.url);
    input["attemptTimeoutMilliseconds"] = json!(100);
    let verifier = activate(input, &files);
    let hash = content_digest();
    for (sha256, content_type, bytes) in [
        (
            hash.as_str(),
            "application/pdf\r\nx-canary: value",
            CONTENT.to_vec(),
        ),
        (hash.as_str(), "", CONTENT.to_vec()),
        (hash.as_str(), "application/pdfé", CONTENT.to_vec()),
        (
            hash.as_str(),
            &"a".repeat(MAXIMUM_CONTENT_TYPE_BYTES + 1),
            CONTENT.to_vec(),
        ),
        (&"a".repeat(64), "application/pdf", CONTENT.to_vec()),
        (&hash[..63], "application/pdf", CONTENT.to_vec()),
        (
            &hash.to_ascii_uppercase(),
            "application/pdf",
            CONTENT.to_vec(),
        ),
    ] {
        assert_eq!(
            verifier.verify(sha256, content_type, bytes).await,
            Err(VerifierError::Integrity)
        );
    }
    assert_eq!(hook.count.load(Ordering::SeqCst), 0);
    assert_eq!(
        verifier
            .verify(&hash, "application/pdf", CONTENT.to_vec())
            .await,
        Err(VerifierError::Unavailable)
    );
    assert_eq!(hook.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn content_over_the_namespace_bound_is_refused_before_sending() {
    let hook = Hook::new(
        StatusCode::OK,
        "{\"verdict\":\"approved\"}".to_string(),
        Duration::ZERO,
    )
    .await;
    let files = SecretFile::new();
    let verifier = settings(raw(&hook.url))
        .unwrap()
        .activate(
            VerifierNamespace {
                max_content_bytes: CONTENT.len() as u64 - 1,
                ..NAMESPACE
            },
            &files.resolver(),
        )
        .unwrap();
    assert_eq!(
        verifier
            .verify(&content_digest(), "application/pdf", CONTENT.to_vec())
            .await,
        Err(VerifierError::Integrity)
    );
    assert_eq!(hook.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn verification_never_follows_a_redirect() {
    let destination = Hook::new(
        StatusCode::OK,
        "{\"verdict\":\"approved\"}".to_string(),
        Duration::ZERO,
    )
    .await;
    let location = destination.url.clone();
    let app = Router::new().fallback(any(move || {
        let location = location.clone();
        async move {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(reqwest::header::LOCATION, location)],
            )
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/verify", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let files = SecretFile::new();
    let verifier = activate(raw(&url), &files);
    assert_eq!(
        verifier
            .verify(&content_digest(), "application/pdf", CONTENT.to_vec())
            .await,
        Err(VerifierError::Unavailable)
    );
    assert_eq!(destination.count.load(Ordering::SeqCst), 0);
    server.abort();
}

#[test]
fn the_binding_commits_to_domain_url_and_policy_but_not_the_credential_or_timeout() {
    // The hex SHA-256 of
    // ["breg-attachment-verification-http-v1","https://example/verify","scanner-rules-2026-09"],
    // generated independently with Python.
    let pinned = "66b0045c64f63582f96d0c35cd7a2944f30834f236400fb0045f390be4e7b647";
    let files = SecretFile::new();
    let input = raw("https://example/verify");
    assert_eq!(activate(input.clone(), &files).binding_digest(), pinned);
    std::fs::write(files.0.path().join("token"), "rotated-token-canary").unwrap();
    let mut tuning = input.clone();
    tuning["attemptTimeoutMilliseconds"] = json!(5000);
    assert_eq!(activate(tuning, &files).binding_digest(), pinned);
    let mut policy = input.clone();
    policy["policyId"] = json!("scanner-rules-next");
    assert_ne!(activate(policy, &files).binding_digest(), pinned);
    let mut moved = input.clone();
    moved["url"] = json!("https://other.example/verify");
    assert_ne!(activate(moved, &files).binding_digest(), pinned);
    let other_domain = settings(input)
        .unwrap()
        .activate(
            VerifierNamespace {
                binding_domain: "documents-verification-http-v1",
                ..NAMESPACE
            },
            &files.resolver(),
        )
        .unwrap();
    assert_ne!(other_domain.binding_digest(), pinned);
}
