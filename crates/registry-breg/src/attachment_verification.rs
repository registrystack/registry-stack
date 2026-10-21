// SPDX-License-Identifier: Apache-2.0
//! A bounded external verdict transport. Durable quarantine, retries and release
//! authority remain in the Registry worker and PostgreSQL transaction boundary.
//!
//! The transport is `registry-platform-objectstore`; this module binds it to
//! the Registry's binding domain `breg-attachment-verification-http-v1` and
//! the attachment size bound, and keeps verification off by default.

use std::{fmt, sync::Arc};

use registry_platform_config::{AttachmentVerifierConfig, SecretResolver};
use registry_platform_objectstore::{HttpVerifierSettings, VerifierNamespace};
use serde::Deserialize;

pub use registry_platform_objectstore::{
    HttpVerifier as HttpAttachmentVerifier, Verdict as AttachmentVerificationVerdict,
    VerifierError as AttachmentVerificationError,
};

/// The Registry's verifier binding. Changing it changes the policy digest
/// recorded beside every quarantined attachment.
const NAMESPACE: VerifierNamespace = VerifierNamespace {
    binding_domain: "breg-attachment-verification-http-v1",
    max_content_bytes: crate::contract::MAX_ATTACHMENT_BYTES as u64,
};

type Result<T> = std::result::Result<T, AttachmentVerificationError>;

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
            Self::Http(verifier) => verifier.binding_digest().to_string(),
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
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum RawAttachmentVerificationConfig {
    Disabled {},
    Http(AttachmentVerifierConfig),
}
registry_platform_yaml::tagged_union!(RawAttachmentVerificationConfig);

#[cfg(feature = "schema")]
impl serde::Serialize for RawAttachmentVerificationConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        crate::contract::serialize_tagged_union(
            Self::serialize(self, serde_json::value::Serializer),
            "type",
            serializer,
        )
    }
}

impl Default for RawAttachmentVerificationConfig {
    fn default() -> Self {
        Self::Disabled {}
    }
}

#[derive(Clone, Default)]
pub(crate) struct AttachmentVerificationConfig(Option<HttpVerifierSettings>);

impl AttachmentVerificationConfig {
    pub(crate) fn from_raw(raw: RawAttachmentVerificationConfig) -> Result<Self> {
        match raw {
            RawAttachmentVerificationConfig::Disabled {} => Ok(Self::default()),
            RawAttachmentVerificationConfig::Http(config) => {
                HttpVerifierSettings::from_config(&config).map(|settings| Self(Some(settings)))
            }
        }
    }

    pub(crate) fn activate(&self, resolver: &SecretResolver) -> Result<AttachmentVerification> {
        let Some(settings) = &self.0 else {
            return Ok(AttachmentVerification::Disabled);
        };
        let verifier = settings.activate(NAMESPACE, resolver)?;
        Ok(AttachmentVerification::Http(Arc::new(verifier)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, extract::Request, routing::any, Router};
    use registry_platform_config::SecretProvider;
    use reqwest::StatusCode;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// The verdict body bound the transport enforces.
    const MAXIMUM_VERDICT_BYTES: u64 = 1024;

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
        json!({"type":"http", "url":endpoint, "authorizationRef":"secret:file/token", "policyId":"scanner-rules-2026-09"})
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
            "https://example/verify#fragment",
        ] {
            assert_eq!(
                AttachmentVerificationConfig::from_raw(
                    serde_json::from_value(raw(endpoint)).unwrap()
                )
                .unwrap_err(),
                AttachmentVerificationError::InvalidConfiguration
            );
        }
        // Userinfo, another scheme, or surrounding space is refused at decode.
        for endpoint in [
            "https://user:secret@example/verify",
            "file:///verify",
            " https://example/verify",
        ] {
            assert!(
                serde_json::from_value::<RawAttachmentVerificationConfig>(raw(endpoint)).is_err()
            );
        }
        let mut renamed = raw("https://example/verify");
        renamed["endpoint"] = renamed["url"].take();
        renamed.as_object_mut().unwrap().remove("url");
        assert!(serde_json::from_value::<RawAttachmentVerificationConfig>(renamed).is_err());
        let mut input = raw("https://verification-canary.example/verify");
        input["authorizationRef"] = json!("inline-token-canary");
        let error = serde_json::from_value::<RawAttachmentVerificationConfig>(input)
            .err()
            .expect("an inline token is not a secret reference");
        assert!(!error.to_string().contains("inline-token-canary"));
        for (key, value) in [
            ("policyId", json!("")),
            ("policyId", json!("contains whitespace")),
        ] {
            let mut input = raw("https://verification-canary.example/verify");
            input[key] = value;
            assert!(
                AttachmentVerificationConfig::from_raw(serde_json::from_value(input).unwrap())
                    .is_err()
            );
        }
        // The timeout is bounded at decode.
        for timeout in [0, 60_001] {
            let mut input = raw("https://verification-canary.example/verify");
            input["attemptTimeoutMilliseconds"] = json!(timeout);
            assert!(serde_json::from_value::<RawAttachmentVerificationConfig>(input).is_err());
        }
        assert!(serde_json::from_value::<RawAttachmentVerificationConfig>(
            json!({"type":"disabled", "url":"https://ignored.example"})
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
        input["attemptTimeoutMilliseconds"] = json!(100);
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
        tuning["attemptTimeoutMilliseconds"] = json!(5000);
        assert_eq!(original, activate(tuning, &files).binding_digest());
        let mut policy = input.clone();
        policy["policyId"] = json!("scanner-rules-next");
        assert_ne!(original, activate(policy, &files).binding_digest());
        let mut endpoint = input;
        endpoint["url"] = json!("https://other.example/verify");
        assert_ne!(original, activate(endpoint, &files).binding_digest());
    }

    #[test]
    #[cfg(feature = "schema")]
    fn verification_schema_requires_policy_and_secret_reference() {
        let root = crate::runtime_config::runtime_config_schema().unwrap();
        let mut schema = root
            .pointer("/$defs/RawAttachmentVerificationConfig")
            .unwrap()
            .clone();
        schema["$defs"] = root["$defs"].clone();
        let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
        let mut input = raw("https://example/verify");
        assert!(validator.is_valid(&input));
        input["authorizationRef"] = json!("inline-token-canary");
        assert!(!validator.is_valid(&input));
        let mut input = raw("https://example/verify");
        input.as_object_mut().unwrap().remove("policyId");
        assert!(!validator.is_valid(&input));
        assert!(!validator.is_valid(&json!({"type":"disabled", "url":"https://ignored.example"})));
    }
}
