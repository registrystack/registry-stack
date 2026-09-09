// SPDX-License-Identifier: Apache-2.0
//! A bounded external verdict transport. Durable quarantine, retries and release
//! authority remain in the Registry worker and PostgreSQL transaction boundary.

use std::{fmt, net::IpAddr, sync::Arc, time::Duration};

use registry_platform_config::{ProtectedSecret, SecretReference, SecretResolver};
use registry_platform_httputil::{read_bounded, validate_response_headers, OutboundClientBuilder};
use reqwest::{header::HeaderValue, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAXIMUM_VERDICT_BYTES: u64 = 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttachmentVerificationError {
    #[error("attachment verification configuration is invalid")]
    InvalidConfiguration,
    #[error("attachment verification secret resolution failed")]
    Secret,
    #[error("attachment verification is unavailable")]
    Unavailable,
    #[error("attachment verification input failed integrity validation")]
    Integrity,
}

type Result<T> = std::result::Result<T, AttachmentVerificationError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentVerificationVerdict {
    Approved,
    Rejected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictResponse {
    verdict: AttachmentVerificationVerdict,
}

/// No verifier preserves the ordinary attachment availability behavior. A
/// configured verifier keeps uploads quarantined until its worker releases them.
#[derive(Clone, Default)]
pub enum AttachmentVerification {
    #[default]
    Disabled,
    Http(Arc<HttpAttachmentVerifier>),
}

impl AttachmentVerification {
    pub fn binding_digest(&self) -> String {
        match self {
            Self::Disabled => "disabled".to_string(),
            Self::Http(verifier) => verifier.binding_digest.clone(),
        }
    }
}

impl fmt::Debug for AttachmentVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "AttachmentVerification::Disabled",
            Self::Http(_) => "AttachmentVerification::Http(<redacted>)",
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum RawAttachmentVerificationConfig {
    Disabled {},
    Http {
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 2048)))]
        endpoint: String,
        authorization_ref: String,
        /// Non-secret identity of the external scanner and rules generation.
        #[cfg_attr(
            feature = "schema",
            schemars(length(min = 1, max = 128), regex(pattern = r"^[\x21-\x7E]+$"))
        )]
        policy_id: String,
        #[serde(default = "default_timeout_milliseconds")]
        #[cfg_attr(feature = "schema", schemars(range(min = 100, max = 60_000)))]
        timeout_milliseconds: u64,
    },
}

impl Default for RawAttachmentVerificationConfig {
    fn default() -> Self {
        Self::Disabled {}
    }
}

fn default_timeout_milliseconds() -> u64 {
    10_000
}

#[derive(Clone, Default)]
pub(crate) struct AttachmentVerificationConfig(Option<HttpVerifierConfig>);

#[derive(Clone)]
struct HttpVerifierConfig {
    endpoint: Url,
    authorization_ref: SecretReference,
    policy_id: String,
    timeout: Duration,
}

impl AttachmentVerificationConfig {
    pub(crate) fn from_raw(raw: RawAttachmentVerificationConfig) -> Result<Self> {
        let RawAttachmentVerificationConfig::Http {
            endpoint,
            authorization_ref,
            policy_id,
            timeout_milliseconds,
        } = raw
        else {
            return Ok(Self::default());
        };
        let url =
            Url::parse(&endpoint).map_err(|_| AttachmentVerificationError::InvalidConfiguration)?;
        let loopback = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if endpoint.len() > 2048
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || policy_id.is_empty()
            || policy_id.len() > 128
            || !policy_id.bytes().all(|b| b.is_ascii_graphic())
            || !(100..=60_000).contains(&timeout_milliseconds)
        {
            return Err(AttachmentVerificationError::InvalidConfiguration);
        }
        Ok(Self(Some(HttpVerifierConfig {
            endpoint: url,
            authorization_ref: SecretReference::parse(authorization_ref)
                .map_err(|_| AttachmentVerificationError::InvalidConfiguration)?,
            policy_id,
            timeout: Duration::from_millis(timeout_milliseconds),
        })))
    }

    pub(crate) fn activate(&self, resolver: &SecretResolver) -> Result<AttachmentVerification> {
        let Some(config) = &self.0 else {
            return Ok(AttachmentVerification::Disabled);
        };
        let authorization = resolver
            .resolve_reference(&config.authorization_ref)
            .map_err(|_| AttachmentVerificationError::Secret)?;
        if authorization.is_empty()
            || authorization.len() > 4096
            || !authorization
                .expose_secret()
                .iter()
                .all(u8::is_ascii_graphic)
        {
            return Err(AttachmentVerificationError::Secret);
        }
        let identity = serde_json::to_vec(&(
            "breg-attachment-verification-http-v1",
            config.endpoint.as_str(),
            &config.policy_id,
        ))
        .map_err(|_| AttachmentVerificationError::InvalidConfiguration)?;
        Ok(AttachmentVerification::Http(Arc::new(
            HttpAttachmentVerifier {
                client: OutboundClientBuilder::new()
                    .timeout(config.timeout)
                    .connect_timeout(config.timeout.min(Duration::from_secs(5)))
                    .try_build()
                    .map_err(|_| AttachmentVerificationError::InvalidConfiguration)?,
                endpoint: config.endpoint.clone(),
                authorization,
                binding_digest: hex::encode(Sha256::digest(identity)),
            },
        )))
    }
}

impl fmt::Debug for AttachmentVerificationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.0.is_some() {
            "AttachmentVerificationConfig::Http(<redacted>)"
        } else {
            "AttachmentVerificationConfig::Disabled"
        })
    }
}

pub struct HttpAttachmentVerifier {
    client: reqwest::Client,
    endpoint: Url,
    authorization: ProtectedSecret,
    binding_digest: String,
}

impl fmt::Debug for HttpAttachmentVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpAttachmentVerifier(<redacted>)")
    }
}

impl HttpAttachmentVerifier {
    /// The worker must bind this verdict to the exact retained digest and policy
    /// generation. Transport errors leave quarantine intact and are retryable.
    pub async fn verify(
        &self,
        sha256: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<AttachmentVerificationVerdict> {
        if bytes.len() as u64 > crate::contract::MAX_ATTACHMENT_BYTES as u64
            || sha256.len() != 64
            || hex::encode(Sha256::digest(&bytes)) != sha256
            || content_type.is_empty()
            || content_type.len() > 255
            || !content_type.is_ascii()
        {
            return Err(AttachmentVerificationError::Integrity);
        }
        let content_type = HeaderValue::from_str(content_type)
            .map_err(|_| AttachmentVerificationError::Integrity)?;
        let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
        bearer.extend_from_slice(self.authorization.expose_secret());
        let mut authorization =
            HeaderValue::from_bytes(&bearer).map_err(|_| AttachmentVerificationError::Secret)?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("x-content-sha256", sha256)
            .body(bytes)
            .send()
            .await
            .map_err(|_| AttachmentVerificationError::Unavailable)?;
        validate_response_headers(response.headers())
            .map_err(|_| AttachmentVerificationError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(AttachmentVerificationError::Unavailable);
        }
        let bytes = read_bounded(response, MAXIMUM_VERDICT_BYTES)
            .await
            .map_err(|_| AttachmentVerificationError::Unavailable)?;
        let result: VerdictResponse =
            serde_json::from_slice(&bytes).map_err(|_| AttachmentVerificationError::Unavailable)?;
        Ok(result.verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, extract::Request, routing::any, Router};
    use registry_platform_config::SecretProvider;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const CONTENT: &[u8] = b"synthetic attachment for verification";
    const TOKEN: &str = "verification-token-canary";

    struct SecretFile(std::path::PathBuf);
    impl SecretFile {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("breg-verifier-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let file = root.join("token");
            std::fs::write(&file, TOKEN).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self(root)
        }
        fn resolver(&self) -> SecretResolver {
            SecretResolver::new([SecretProvider::File], &self.0).unwrap()
        }
    }
    impl Drop for SecretFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Hook {
        endpoint: String,
        count: Arc<AtomicUsize>,
        exact: Arc<AtomicBool>,
        server: tokio::task::JoinHandle<()>,
    }
    impl Hook {
        async fn new(status: StatusCode, body: String, delay: Duration) -> Self {
            let count = Arc::new(AtomicUsize::new(0));
            let exact = Arc::new(AtomicBool::new(false));
            let calls = count.clone();
            let matched = exact.clone();
            let app = Router::new().fallback(any(move |request: Request| {
                let calls = calls.clone();
                let matched = matched.clone();
                let body = body.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let digest = hex::encode(Sha256::digest(CONTENT));
                    let headers = request.headers();
                    let exact_headers = request.method() == reqwest::Method::POST
                        && request.uri().path() == "/verify"
                        && headers
                            .get("authorization")
                            .is_some_and(|value| value == format!("Bearer {TOKEN}").as_str())
                        && headers
                            .get("content-type")
                            .is_some_and(|value| value == "application/pdf")
                        && headers
                            .get("x-content-sha256")
                            .is_some_and(|value| value == digest.as_str());
                    let bytes = to_bytes(
                        request.into_body(),
                        crate::contract::MAX_ATTACHMENT_BYTES as usize,
                    )
                    .await
                    .unwrap();
                    matched.store(exact_headers && bytes.as_ref() == CONTENT, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    (status, body)
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/verify", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                endpoint,
                count,
                exact,
                server,
            }
        }
    }
    impl Drop for Hook {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn raw(endpoint: &str) -> serde_json::Value {
        json!({"kind":"http", "endpoint":endpoint, "authorizationRef":"secret:file/token", "policyId":"scanner-rules-2026-09"})
    }
    fn activate(input: serde_json::Value, files: &SecretFile) -> AttachmentVerification {
        AttachmentVerificationConfig::from_raw(serde_json::from_value(input).unwrap())
            .unwrap()
            .activate(&files.resolver())
            .unwrap()
    }
    fn http(value: AttachmentVerification) -> Arc<HttpAttachmentVerifier> {
        let AttachmentVerification::Http(value) = value else {
            panic!("HTTP verifier expected");
        };
        value
    }

    #[test]
    fn verification_config_is_strict_and_redacted() {
        for endpoint in [
            "http://public.example/verify",
            "http://10.0.0.1/verify",
            "https://user:secret@example/verify",
            "https://example/verify#fragment",
            "file:///verify",
            " https://example/verify",
        ] {
            assert_eq!(
                AttachmentVerificationConfig::from_raw(
                    serde_json::from_value(raw(endpoint)).unwrap()
                )
                .unwrap_err(),
                AttachmentVerificationError::InvalidConfiguration
            );
        }
        for (key, value) in [
            ("authorizationRef", json!("inline-token-canary")),
            ("policyId", json!("")),
            ("policyId", json!("contains whitespace")),
            ("timeoutMilliseconds", json!(0)),
            ("timeoutMilliseconds", json!(60001)),
        ] {
            let mut input = raw("https://verification-canary.example/verify");
            input[key] = value;
            assert!(
                AttachmentVerificationConfig::from_raw(serde_json::from_value(input).unwrap())
                    .is_err()
            );
        }
        assert!(serde_json::from_value::<RawAttachmentVerificationConfig>(
            json!({"kind":"disabled", "endpoint":"https://ignored.example"})
        )
        .is_err());
        let mut missing = raw("https://example/verify");
        missing.as_object_mut().unwrap().remove("policyId");
        assert!(serde_json::from_value::<RawAttachmentVerificationConfig>(missing).is_err());
        let files = SecretFile::new();
        let verifier = activate(raw("https://verification-canary.example/verify"), &files);
        let debug = format!("{verifier:?} {:?}", http(verifier.clone()));
        assert!(!debug.contains("canary"));
        let config = AttachmentVerificationConfig::default();
        assert!(matches!(
            config.activate(&files.resolver()).unwrap(),
            AttachmentVerification::Disabled
        ));
    }

    #[tokio::test]
    async fn verification_posts_exact_authenticated_bytes_and_returns_terminal_verdicts() {
        let files = SecretFile::new();
        for (wire, expected) in [
            ("approved", AttachmentVerificationVerdict::Approved),
            ("rejected", AttachmentVerificationVerdict::Rejected),
        ] {
            let hook = Hook::new(
                StatusCode::OK,
                format!("{{\"verdict\":\"{wire}\"}}"),
                Duration::ZERO,
            )
            .await;
            let verifier = http(activate(raw(&hook.endpoint), &files));
            assert_eq!(
                verifier
                    .verify(
                        &hex::encode(Sha256::digest(CONTENT)),
                        "application/pdf",
                        CONTENT.to_vec()
                    )
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(hook.count.load(Ordering::SeqCst), 1);
            assert!(hook.exact.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_failed_verdicts_remain_unavailable() {
        let files = SecretFile::new();
        for (status, body) in [
            (StatusCode::OK, "{}".to_string()),
            (StatusCode::OK, "[]".to_string()),
            (StatusCode::OK, "{\"verdict\":\"unknown\"}".to_string()),
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
        ] {
            let hook = Hook::new(status, body, Duration::ZERO).await;
            let verifier = http(activate(raw(&hook.endpoint), &files));
            let error = verifier
                .verify(
                    &hex::encode(Sha256::digest(CONTENT)),
                    "application/pdf",
                    CONTENT.to_vec(),
                )
                .await
                .unwrap_err();
            assert_eq!(error, AttachmentVerificationError::Unavailable);
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
        let mut input = raw(&hook.endpoint);
        input["timeoutMilliseconds"] = json!(100);
        let verifier = http(activate(input, &files));
        let hash = hex::encode(Sha256::digest(CONTENT));
        assert_eq!(
            verifier
                .verify(
                    &hash,
                    "application/pdf\r\nx-canary: value",
                    CONTENT.to_vec()
                )
                .await,
            Err(AttachmentVerificationError::Integrity)
        );
        assert_eq!(
            verifier
                .verify(&"a".repeat(64), "application/pdf", CONTENT.to_vec())
                .await,
            Err(AttachmentVerificationError::Integrity)
        );
        assert_eq!(hook.count.load(Ordering::SeqCst), 0);
        assert_eq!(
            verifier
                .verify(&hash, "application/pdf", CONTENT.to_vec())
                .await,
            Err(AttachmentVerificationError::Unavailable)
        );
        assert_eq!(hook.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn verification_never_follows_a_redirect() {
        let destination = Hook::new(
            StatusCode::OK,
            "{\"verdict\":\"approved\"}".to_string(),
            Duration::ZERO,
        )
        .await;
        let location = destination.endpoint.clone();
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
        let endpoint = format!("http://{}/verify", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let files = SecretFile::new();
        let verifier = http(activate(raw(&endpoint), &files));
        assert_eq!(
            verifier
                .verify(
                    &hex::encode(Sha256::digest(CONTENT)),
                    "application/pdf",
                    CONTENT.to_vec()
                )
                .await,
            Err(AttachmentVerificationError::Unavailable)
        );
        assert_eq!(destination.count.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[test]
    fn policy_binding_changes_with_endpoint_or_generation_but_not_secret_rotation() {
        let files = SecretFile::new();
        let input = raw("https://example/verify");
        let original = activate(input.clone(), &files).binding_digest();
        std::fs::write(files.0.join("token"), "rotated-token-canary").unwrap();
        let mut tuning = input.clone();
        tuning["timeoutMilliseconds"] = json!(5000);
        assert_eq!(original, activate(tuning, &files).binding_digest());
        let mut policy = input.clone();
        policy["policyId"] = json!("scanner-rules-next");
        assert_ne!(original, activate(policy, &files).binding_digest());
        let mut endpoint = input;
        endpoint["endpoint"] = json!("https://other.example/verify");
        assert_ne!(original, activate(endpoint, &files).binding_digest());
    }

    #[test]
    #[cfg(feature = "schema")]
    fn verification_schema_requires_policy_and_secret_reference() {
        let schema = crate::runtime_config::runtime_config_schema().unwrap();
        let schema = schema
            .pointer("/$defs/RawAttachmentVerificationConfig")
            .unwrap();
        let validator = jsonschema::JSONSchema::compile(schema).unwrap();
        let mut input = raw("https://example/verify");
        assert!(validator.is_valid(&input));
        input["authorizationRef"] = json!("inline-token-canary");
        assert!(!validator.is_valid(&input));
        let mut input = raw("https://example/verify");
        input.as_object_mut().unwrap().remove("policyId");
        assert!(!validator.is_valid(&input));
        assert!(
            !validator.is_valid(&json!({"kind":"disabled", "endpoint":"https://ignored.example"}))
        );
    }
}
