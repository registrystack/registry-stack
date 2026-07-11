// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary assembly, auth, audit, and HTTP source connectors.

#[path = "sidecar_assurance.rs"]
mod sidecar_assurance;
#[path = "signing/mod.rs"]
mod signing;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Mutex, OnceCell, Semaphore};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::Algorithm;
use registry_notary_core::deployment::{
    evaluate_gates, EvaluatedFinding, EvaluatedWaiver, GateEvaluation,
};
use registry_notary_core::sd_jwt::EvidenceIssuer;
use registry_notary_core::{
    AccessMode, BoundedCorrelationId, BoundedVerifiedClaims, BulkMode, ConfigAuditEvent,
    DciSourceConnectionConfig, EvidenceAuditEvent, EvidenceAuthMode, EvidenceAuthorizationDetails,
    EvidenceConfig, EvidenceCredentialConfig, EvidenceEntity, EvidenceError, EvidencePrincipal,
    EvidenceRequestContext, ExpectedSidecarConfig, Hashed, Oauth2ClientCredentialsSourceAuthConfig,
    PrincipalIdentifier, RateLimitBucket, RegistryNotaryAdminListenerMode, RequestIdentifier,
    SelfAttestationAssuranceClaimSource, SelfAttestationClaimSource, SelfAttestationDenialCode,
    SigningKeyConfig, SigningKeyProviderConfig, SourceAuthConfig, SourceBindingConfig,
    SourceConnectionConfig, SourceConnectorKind, SourceRuntimeAssurance, SourceRuntimeSummary,
    StandaloneRegistryNotaryConfig, SubjectRequest, VerifiedClaimName, VerifiedClaimValue,
    SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR,
};
use registry_platform_audit::{
    AuditError, AuditKeyHasher, AuditProfile, AuditSink as PlatformAuditSink, ChainState,
    JsonlFileSink, JsonlStdoutSink, SyslogSink,
};
use registry_platform_authcommon::{
    parse_bearer_token, verify_api_key, CredentialFingerprintRefError, FingerprintFormatError,
};
use registry_platform_crypto::{
    sign, verify, KeyReadiness, LocalJwkSigner, PrivateJwk, PublicJwk, SigningProvider,
};
use registry_platform_httputil::{
    read_bounded, url as httputil_url, FetchUrlError, FetchUrlPolicy, ValidatedFetchUrl,
};
use registry_platform_oidc::{
    fetch_userinfo_jwt_with_policy, Audience, JwksFetcher, JwksFetcherConfig, OidcError,
    TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use registry_platform_ops::{AckObservation, ConfigProvenance, ConfigSource};
use registry_platform_replay::{ReplayKey, ReplayScope};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use ulid::Ulid;
use zeroize::Zeroizing;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::{CelWorker, CelWorkerConfig};
#[cfg(feature = "registry-notary-cel")]
use crate::runtime::validate_cel_claims_for_startup;
use crate::{
    api::METRICS_SCOPE,
    config_governed::ConfigGovernanceContext,
    credential_status::{CredentialStatusBuildError, CredentialStatusStore},
    metrics::{metrics_handler, metrics_middleware, AppMetrics},
    posture::PostureContext,
    replay::{require_replay_insert, ReplayBuildError, ReplayStores},
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver, EvidenceStore,
    RegistryNotaryApiState, SelfAttestationRateLimitKeys, SelfAttestationRateLimiter, SourceReader,
};

#[path = "assembly.rs"]
mod assembly;
#[path = "auth/mod.rs"]
mod auth;
#[path = "compat.rs"]
mod compat;
#[path = "connectors/mod.rs"]
mod connectors;
#[path = "cors.rs"]
mod cors;
#[path = "deployment.rs"]
mod deployment;
#[path = "preauth.rs"]
mod preauth;
#[path = "sources/mod.rs"]
mod sources;
#[path = "transport/mod.rs"]
mod transport;

pub use assembly::*;
use auth::*;
pub use auth::{find_credential, ResolvedCredential};
pub(crate) use auth::{AuditPipeline, AuthAuditState};
pub(crate) use compat::*;
use connectors::*;
use cors::*;
pub(crate) use deployment::*;
use preauth::*;
pub(crate) use preauth::{
    constant_time_eq, generate_numeric_tx_code, generate_opaque_token, pkce_s256_challenge,
    pre_auth_audit_event, PreAuthAuditFields, PreAuthRuntime,
};
use sidecar_assurance::*;
pub use signing::providers::EvidenceIssuerRegistry;
use signing::providers::*;
pub(crate) use signing::providers::{signing_key_public_jwk_from_config, SignerReadiness};
pub use sources::HttpEvidenceSources;
use sources::*;
pub(crate) use transport::audit_error_response;
use transport::*;

const SOURCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const FILE_WATCH_METADATA_CHECK_INTERVAL: Duration = Duration::from_millis(250);
const MAX_REQUEST_URI_BYTES: usize = 8 * 1024;
const MAX_SOURCE_JSON_BYTES: usize = 1024 * 1024;
const MAX_INBOUND_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const PREAUTH_LOGIN_STATE_MAX_ENTRIES: usize = 4096;
const SELF_ATTESTATION_CORS_METHODS: &str = "GET,POST,OPTIONS";
const OIDC_ID_TOKEN_HEADER: &str = "x-registry-notary-oidc-id-token";
const SELF_ATTESTATION_CORS_DEFAULT_HEADERS: &str =
    "authorization,content-type,x-registry-notary-oidc-id-token";
const DEPLOYMENT_PROFILE_REQUIRED_ACTION: &str =
    "set deployment.profile: local for development, or production/evidence_grade for deployment";
#[cfg(test)]
#[path = "route_security_characterization.rs"]
mod route_security_characterization;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use axum::body::Body;
    use axum::extract::Query;
    use axum::response::Redirect;
    use axum::routing::{get, post};
    use axum_test::TestServer;
    #[cfg(feature = "pkcs11")]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(feature = "pkcs11")]
    use base64::Engine;
    use registry_notary_core::{
        tokens::{
            mint_access_token, AccessTokenClaims, BoundSubject,
            NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION, NOTARY_AUTHORIZATION_DETAILS_TYPE,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        },
        EvaluateRequest, SelfAttestationDenialCode, SelfAttestationRateLimitsConfig,
        SourceConnectionConfig, SourceLookupConfig, SourceQueryFieldConfig,
        FORMAT_CLAIM_RESULT_JSON,
    };
    #[cfg(feature = "pkcs11")]
    use registry_notary_core::{ClaimProvenance, ClaimResultView, TargetRefView};
    use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};

    const SOURCE_ADAPTER_SIDECAR_TOKEN_ENV: &str = "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN";
    const SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV: &str = "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN_HASH";
    const SOURCE_ADAPTER_SIDECAR_TOKEN: &str = "source-adapter-sidecar-token";
    const SOURCE_ADAPTER_SIDECAR_TOKEN_HASH: &str =
        "sha256:95daed38ef01a80fd7273dd22da0bd6553958630af3f87eae1bc02056ad9f828";
    const SOURCE_ADAPTER_SPIKE_PURPOSE: &str = "https://purpose.example.test/eligibility";
    const SOURCE_ADAPTER_PRODUCT: &str = "registry-notary-source-adapter-sidecar";
    const SOURCE_ADAPTER_INSTANCE_ID: &str = "demo";
    const SOURCE_ADAPTER_ENVIRONMENT: &str = "staging";
    const SOURCE_ADAPTER_STREAM_ID: &str = "source-adapter-sidecar-runtime";
    const HTTP_JSON_CREDENTIAL_ENV: &str = "TEST_HTTP_JSON_READER_CREDENTIAL_JSON";
    const TEST_AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_NOTARY_TEST_AUDIT_HASH_SECRET";
    static HTTP_JSON_SIDECAR_ENV_LOCK: Mutex<()> = Mutex::const_new(());
    const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
    const TEST_ISSUER_JWK_WITH_KID: &str = r##"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#file-watch","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"##;
    const TEST_ROTATED_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
    const TEST_OLD_ISSUER_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#old"}"##;
    const TEST_OLD_HSM_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm-old"}"##;
    #[cfg(feature = "pkcs11")]
    static SOFTHSM_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Debug)]
    struct TestReadinessProvider {
        signer: LocalJwkSigner,
        readiness: Arc<AtomicU8>,
    }

    #[async_trait]
    impl SigningProvider for TestReadinessProvider {
        fn algorithm(&self) -> registry_platform_crypto::SigningAlgorithm {
            self.signer.algorithm()
        }

        fn key_id(&self) -> &str {
            self.signer.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.signer.public_jwk()
        }

        fn readiness(&self) -> KeyReadiness {
            key_readiness_from_u8(self.readiness.load(Ordering::SeqCst))
        }

        async fn sign(
            &self,
            payload: &[u8],
        ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
            self.signer.sign(payload).await
        }
    }

    #[test]
    fn signer_readiness_tracks_status_by_kid_and_counts_required_keys() {
        let provider_readiness =
            Arc::new(AtomicU8::new(key_readiness_to_u8(KeyReadiness::NotReady)));
        let provider: Arc<dyn SigningProvider> = Arc::new(TestReadinessProvider {
            signer: LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("jwk"))
                .expect("local signer builds"),
            readiness: Arc::clone(&provider_readiness),
        });
        let readiness = SignerReadiness::from_entries(vec![
            static_key_readiness(
                "did:web:notary.example#local".to_string(),
                SigningKeyProviderConfig::LocalJwkEnv,
                true,
                KeyReadiness::Ready,
            ),
            provider_key_readiness(
                "did:web:notary.example#hsm".to_string(),
                SigningKeyProviderConfig::Pkcs11,
                true,
                Arc::clone(&provider),
            ),
            static_key_readiness(
                "did:web:notary.example#publish-only".to_string(),
                SigningKeyProviderConfig::LocalJwkEnv,
                false,
                KeyReadiness::Ready,
            ),
        ]);

        assert_eq!(readiness.total(), 2);
        assert_eq!(readiness.ready_count(), 1);
        assert_eq!(readiness.failed_count(), 1);
        assert_eq!(
            readiness.provider_counts(),
            BTreeMap::from([("local_jwk_env".to_string(), 1), ("pkcs11".to_string(), 1)])
        );
        let by_kid = readiness
            .by_kid()
            .into_iter()
            .map(|entry| (entry.kid, entry.readiness))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_kid["did:web:notary.example#local"], KeyReadiness::Ready);
        assert_eq!(by_kid["did:web:notary.example#hsm"], KeyReadiness::NotReady);
        assert_eq!(
            by_kid["did:web:notary.example#publish-only"],
            KeyReadiness::Ready
        );

        provider_readiness.store(key_readiness_to_u8(KeyReadiness::Ready), Ordering::SeqCst);
        assert!(readiness.is_ready());
        assert_eq!(readiness.ready_count(), 2);
    }

    #[test]
    fn access_token_verification_key_enforces_publish_until_boundary() {
        let public_jwk = PublicJwk::parse(TEST_OLD_ISSUER_PUBLIC_JWK).expect("public jwk parses");
        let active_key = AccessTokenVerificationKey {
            public_jwk: public_jwk.clone(),
            publish_until_unix_seconds: None,
        };
        assert!(active_key.may_verify_at(i64::MAX));

        let expiring_key = AccessTokenVerificationKey {
            public_jwk,
            publish_until_unix_seconds: Some(1_000),
        };
        assert!(expiring_key.may_verify_at(999));
        assert!(expiring_key.may_verify_at(1_000));
        assert!(!expiring_key.may_verify_at(1_001));
        assert!(!expiring_key.may_verify_at(-1));
    }

    #[tokio::test]
    async fn notary_token_auth_rejects_expired_verification_key() {
        let signer =
            LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("private jwk"))
                .expect("local signer builds");
        let public_jwk = PublicJwk::parse(TEST_OLD_ISSUER_PUBLIC_JWK).expect("public jwk parses");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = mint_access_token(
            &signer,
            "registry-notary-access+jwt",
            &AccessTokenClaims {
                issuer: "https://notary.example".to_string(),
                jti: None,
                audiences: vec!["registry-notary".to_string()],
                token_type: "Bearer".to_string(),
                credential_configuration_id: "identity_credential".to_string(),
                subject: BoundSubject {
                    subject: "subject-1".to_string(),
                    subject_binding_claim: "civil_id".to_string(),
                    subject_binding_value: "civil-1".to_string(),
                    client_id: "wallet-demo".to_string(),
                    scopes: vec!["openid".to_string()],
                    acr: None,
                    auth_time: None,
                },
                authorization_details: Vec::new(),
                confirmation: None,
                actor: None,
                iat: now - 1,
                exp: now + 300,
            },
        )
        .await
        .expect("token mints");

        let mut anchor = NotaryTokenAnchor {
            verification_keys: vec![AccessTokenVerificationKey {
                public_jwk: public_jwk.clone(),
                publish_until_unix_seconds: Some(1),
            }],
            issuer: "https://notary.example".to_string(),
            token_typ: "registry-notary-access+jwt".to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        assert!(matches!(
            authenticate_notary_token(&token.compact, &anchor, &ReplayStores::memory()).await,
            Err(EvidenceError::MissingCredential)
        ));

        anchor.verification_keys[0] = AccessTokenVerificationKey {
            public_jwk,
            publish_until_unix_seconds: Some(u64::try_from(now + 300).expect("future is positive")),
        };
        assert!(
            authenticate_notary_token(&token.compact, &anchor, &ReplayStores::memory())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn notary_transaction_token_auth_consumes_jti_once() {
        let signer =
            LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("private jwk"))
                .expect("local signer builds");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &AccessTokenClaims {
                issuer: "https://notary.example".to_string(),
                jti: Some("txn-jti-1".to_string()),
                audiences: vec!["registry-notary".to_string()],
                token_type: "Bearer".to_string(),
                credential_configuration_id: "identity_credential".to_string(),
                subject: BoundSubject {
                    subject: "subject-1".to_string(),
                    subject_binding_claim: "civil_id".to_string(),
                    subject_binding_value: "civil-1".to_string(),
                    client_id: "assisted-access".to_string(),
                    scopes: vec!["registry_notary:self_attestation".to_string()],
                    acr: None,
                    auth_time: None,
                },
                authorization_details: vec![json!({
                    "type": NOTARY_AUTHORIZATION_DETAILS_TYPE,
                    "schema_version": NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                    "actions": ["evaluate"],
                    "locations": ["registry-notary"],
                })],
                confirmation: None,
                actor: Some(json!({"actor_id_hash": "hmac-sha256:actor"})),
                iat: now - 1,
                exp: now + 300,
            },
        )
        .await
        .expect("transaction token mints");
        let anchor = NotaryTokenAnchor {
            verification_keys: vec![AccessTokenVerificationKey {
                public_jwk: signer.public_jwk(),
                publish_until_unix_seconds: None,
            }],
            issuer: "https://notary.example".to_string(),
            token_typ: NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        let replay = ReplayStores::memory();

        authenticate_notary_token(&token.compact, &anchor, &replay)
            .await
            .expect("first token use succeeds");
        let replay_error = authenticate_notary_token(&token.compact, &anchor, &replay)
            .await
            .expect_err("second token use is replay");

        assert!(matches!(replay_error, EvidenceError::MissingCredential));
    }

    #[tokio::test]
    async fn consume_notary_token_jti_rejects_missing_jti_for_transaction_typ() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let payload = json!({
            "iss": "https://notary.example",
            "exp": now + 300,
        });
        let anchor = NotaryTokenAnchor {
            verification_keys: Vec::new(),
            issuer: "https://notary.example".to_string(),
            token_typ: NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        let replay = ReplayStores::memory();

        // A single-use transaction-typ token without `jti` must fail closed
        // rather than silently skip replay protection.
        let error = consume_notary_token_jti(&payload, &anchor, &replay)
            .await
            .expect_err("missing jti for single-use typ fails closed");
        assert!(matches!(error, EvidenceError::MissingCredential));

        // A non-single-use typ legitimately has no `jti` and is accepted.
        let other_anchor = NotaryTokenAnchor {
            token_typ: "registry-notary-access+jwt".to_string(),
            ..anchor
        };
        consume_notary_token_jti(&payload, &other_anchor, &replay)
            .await
            .expect("missing jti for non-single-use typ is accepted");
    }

    fn file_watch_key(path: &std::path::Path) -> SigningKeyConfig {
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::FileWatch,
            alg: "EdDSA".to_string(),
            kid: "did:web:issuer.example#file-watch".to_string(),
            status: registry_notary_core::SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: String::new(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: path.to_string_lossy().into_owned(),
            password_env: String::new(),
        }
    }

    fn test_file_modified(path: &std::path::Path) -> SystemTime {
        std::fs::metadata(path)
            .expect("test key metadata reads")
            .modified()
            .expect("test key modified time reads")
    }

    fn set_test_file_modified(path: &std::path::Path, modified: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("test key opens")
            .set_modified(modified)
            .expect("test key modified time sets");
        assert_eq!(
            test_file_modified(path),
            modified,
            "test filesystem preserved the requested modified time"
        );
    }

    fn bump_test_file_modified(path: &std::path::Path, previous: SystemTime) -> SystemTime {
        let modified = previous + Duration::from_secs(2);
        set_test_file_modified(path, modified);
        modified
    }

    async fn wait_for_file_watch_metadata_check() {
        tokio::time::sleep(FILE_WATCH_METADATA_CHECK_INTERVAL + Duration::from_millis(25)).await;
    }

    fn mark_file_watch_checked_now(provider: &FileWatchSigningProvider) {
        provider
            .file_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last_checked = Instant::now();
    }

    #[tokio::test]
    async fn file_watch_signing_key_reloads_valid_same_key_replacement_without_restart() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch signer test";

        let old_public = provider.public_jwk();
        let old_signature = provider.sign(payload).await.expect("old signer signs");
        verify(payload, &old_signature, &old_public).expect("old signature verifies");

        std::fs::write(&key_path, TEST_ISSUER_JWK_WITH_KID).expect("replacement key writes");
        wait_for_file_watch_metadata_check().await;
        let replacement_signature = provider
            .sign(payload)
            .await
            .expect("replacement signer signs");
        let replacement_public = provider.public_jwk();

        assert_eq!(old_signature, replacement_signature);
        assert_eq!(old_public, replacement_public);
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        verify(payload, &replacement_signature, &replacement_public)
            .expect("replacement signature verifies");
    }

    #[tokio::test]
    async fn file_watch_signing_key_debounces_metadata_checks_between_signatures() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch debounce";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        wait_for_file_watch_metadata_check().await;
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        mark_file_watch_checked_now(&provider);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        let immediate_signature = provider
            .sign(payload)
            .await
            .expect("debounced signer still signs");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Ready,
            "metadata is not checked again during the debounce interval"
        );
        verify(payload, &immediate_signature, &old_public)
            .expect("debounced signature still verifies with the last good key");

        wait_for_file_watch_metadata_check().await;
        let delayed_signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after refresh failure");
        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        verify(payload, &delayed_signature, &old_public)
            .expect("last good signature verifies after refresh failure");
    }

    #[test]
    fn file_watch_signing_key_missing_initial_file_fails_closed_without_path_leak() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("missing-issuer.jwk");
        let key = file_watch_key(&key_path);

        let err = FileWatchSigningProvider::from_config("file-watch", &key)
            .expect_err("missing watched key file fails startup");
        let err = err.to_string();

        assert!(err.contains("signing key 'file-watch' is invalid"));
        assert!(err.contains("file_watch key file could not be read"));
        let key_path_text = key_path.to_string_lossy();
        assert!(!err.contains(key_path_text.as_ref() as &str));
    }

    #[tokio::test]
    async fn file_watch_signing_key_keeps_last_good_signer_when_replacement_is_malformed() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch malformed replacement";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        set_test_file_modified(&key_path, initial_modified);
        let signature = provider
            .sign(payload)
            .await
            .expect("unchanged mtime keeps last good signer ready");
        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public)
            .expect("unchanged-mtime malformed replacement was not reloaded");

        let malformed_modified = bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs");

        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public).expect("last good signature verifies");
        let debug = format!("{provider:?}");
        assert!(debug.contains("FileWatchSigningProvider"));
        let key_path_text = key_path.to_string_lossy();
        assert!(!debug.contains(key_path_text.as_ref() as &str));
        assert!(!debug.contains("2oPoxdKu"));

        std::fs::write(&key_path, TEST_ROTATED_ISSUER_JWK)
            .expect("wrong public-key replacement writes");
        bump_test_file_modified(&key_path, malformed_modified);
        wait_for_file_watch_metadata_check().await;
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after wrong-key replacement");
        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
        assert_eq!(provider.public_jwk(), old_public);
        verify(payload, &signature, &old_public).expect("wrong-key replacement was not swapped in");
    }

    #[tokio::test]
    async fn file_watch_signing_provider_reports_readiness_through_shared_trait() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let provider: Arc<dyn SigningProvider> = Arc::new(provider);

        assert_eq!(provider.readiness(), KeyReadiness::Ready);
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        provider
            .sign(b"registry-notary shared readiness")
            .await
            .expect("last good signer still signs");

        assert_eq!(provider.readiness(), KeyReadiness::Degraded);
    }

    #[tokio::test]
    async fn file_watch_signing_key_readiness_is_reported_by_kid() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key_path_text = key_path.to_string_lossy();
        let evidence: EvidenceConfig = serde_norway::from_str(&format!(
            r#"
signing_keys:
  active-key:
    provider: file_watch
    path: "{key_path_text}"
    alg: EdDSA
    kid: did:web:issuer.example#file-watch
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#
        ))
        .expect("evidence config parses");
        let reuse_scoped_key_ids: HashSet<&str> = evidence
            .credential_profiles
            .values()
            .map(|profile| profile.signing_key.as_str())
            .collect();
        let registry = SigningKeyRegistry::from_config(&evidence, &reuse_scoped_key_ids)
            .expect("registry builds");
        let readiness = registry.signer_readiness();
        assert_eq!(
            readiness.by_kid()[0].readiness,
            KeyReadiness::Ready,
            "initial file-watch key is ready"
        );
        let initial_modified = test_file_modified(&key_path);

        std::fs::write(&key_path, "{ not valid jwk").expect("malformed replacement writes");
        bump_test_file_modified(&key_path, initial_modified);
        wait_for_file_watch_metadata_check().await;
        let provider = registry
            .signing_provider("active-key")
            .expect("active provider exists");
        provider
            .sign(b"registry-notary readiness refresh")
            .await
            .expect("last good signer still signs");

        let by_kid = readiness
            .by_kid()
            .into_iter()
            .map(|entry| (entry.kid, entry.readiness))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_kid["did:web:issuer.example#file-watch"],
            KeyReadiness::Degraded
        );
    }

    #[tokio::test]
    async fn file_watch_signing_key_detects_same_mtime_content_change_after_debounce() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch same-mtime content detection";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        // Replace the file with same-key content but a different byte representation,
        // then restore mtime so it is identical to what was recorded at provider creation.
        std::fs::write(&key_path, TEST_ISSUER_JWK_WITH_KID).expect("same-key replacement writes");
        set_test_file_modified(&key_path, initial_modified);

        wait_for_file_watch_metadata_check().await;

        // After the debounce window, the content digest reveals the change even though
        // mtime is identical. The replacement is a valid same-public-key file, so
        // the provider should remain Ready with the refreshed signer.
        let signature = provider
            .sign(payload)
            .await
            .expect("provider signs after same-mtime reload");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Ready,
            "valid same-key same-mtime replacement keeps provider Ready"
        );
        assert_eq!(
            provider.public_jwk(),
            old_public,
            "public key is unchanged after same-key reload"
        );
        verify(payload, &signature, &old_public)
            .expect("signature from same-mtime refreshed signer verifies");
    }

    #[tokio::test]
    async fn file_watch_signing_key_detects_same_mtime_malformed_replacement_after_debounce() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key_path = tmp.path().join("issuer.jwk");
        std::fs::write(&key_path, TEST_ISSUER_JWK).expect("initial key writes");
        let key = file_watch_key(&key_path);
        let provider =
            FileWatchSigningProvider::from_config("file-watch", &key).expect("provider builds");
        let payload = b"registry-notary file-watch same-mtime malformed detection";
        let old_public = provider.public_jwk();
        let initial_modified = test_file_modified(&key_path);

        // Replace with malformed content but restore mtime to the original value.
        std::fs::write(&key_path, "{ not valid jwk }").expect("malformed replacement writes");
        set_test_file_modified(&key_path, initial_modified);

        wait_for_file_watch_metadata_check().await;

        // After the debounce window the digest reveals the malformed replacement.
        // The provider must degrade but keep the last good signer.
        let signature = provider
            .sign(payload)
            .await
            .expect("last good signer still signs after same-mtime malformed replacement");
        assert_eq!(
            provider.readiness(),
            KeyReadiness::Degraded,
            "malformed same-mtime replacement degrades readiness after debounce"
        );
        assert_eq!(
            provider.public_jwk(),
            old_public,
            "last good public key is kept"
        );
        verify(payload, &signature, &old_public)
            .expect("last good signer signature verifies after same-mtime malformed replacement");
    }

    #[test]
    fn cached_source_token_debug_redacts_access_token() {
        let token = CachedSourceToken {
            access_token: "source-access-token-secret".to_string(),
            refresh_after: Instant::now(),
        };

        let debug = format!("{token:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("source-access-token-secret"));
    }

    #[test]
    fn request_identifier_hashes_are_deterministic_and_non_raw() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let first = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-1"));
        let again = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-1"));
        let other = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-2"));

        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_ne!(first.as_str(), "request-jti-1");
    }

    #[test]
    fn esignet_verifier_config_does_not_require_userinfo_exp() {
        // MOSIP eSignet signs its userinfo JWS without an `exp` claim, which the
        // OpenID Connect Core spec permits for UserInfo responses. The RP verifier
        // must therefore not require one, or every userinfo-sourced binding fails.
        let config = esignet_token_verifier_config("https://esignet.example", "rp-client");

        assert!(!config.userinfo_requires_exp);
        assert_eq!(config.issuer, "https://esignet.example");
        assert_eq!(config.audiences, vec!["rp-client".to_string()]);
        assert_eq!(config.allowed_userinfo_typ, vec!["JWT".to_string()]);
    }

    #[tokio::test]
    async fn pinned_request_builder_sends_get_and_post_to_validated_target() {
        let app = Router::new()
            .route("/get", get(|| async { "pinned-get" }))
            .route("/post", post(|| async { "pinned-post" }));
        let server = TestServer::builder().http_transport().build(app);
        let base_url = server.server_address().expect("server address").to_string();
        let base_url = base_url.trim_end_matches('/');
        let get_url = format!("{base_url}/get").parse().expect("GET URL parses");
        let post_url = format!("{base_url}/post").parse().expect("POST URL parses");
        let policy = FetchUrlPolicy::dev();

        let validated_get = policy
            .validate_for_immediate_fetch_with_timeout(&get_url, Duration::from_secs(2))
            .await
            .expect("GET URL validates");
        let get_response =
            pinned_request_builder(&validated_get, reqwest::Method::GET, Duration::from_secs(2))
                .expect("GET request builds from validated URL")
                .send()
                .await
                .expect("GET request sends");
        assert_eq!(get_response.status(), reqwest::StatusCode::OK);
        let get_body = get_response.text().await.expect("GET response body reads");

        let validated_post = policy
            .validate_for_immediate_fetch_with_timeout(&post_url, Duration::from_secs(2))
            .await
            .expect("POST URL validates");
        let post_response = pinned_request_builder(
            &validated_post,
            reqwest::Method::POST,
            Duration::from_secs(2),
        )
        .expect("POST request builds from validated URL")
        .body("ignored")
        .send()
        .await
        .expect("POST request sends");
        assert_eq!(post_response.status(), reqwest::StatusCode::OK);
        let post_body = post_response
            .text()
            .await
            .expect("POST response body reads");

        assert_eq!(get_body, "pinned-get");
        assert_eq!(post_body, "pinned-post");
        assert!(!validated_get.resolved_ips().is_empty());
        assert!(!validated_post.resolved_ips().is_empty());
    }

    fn audit_event() -> EvidenceAuditEvent {
        EvidenceAuditEvent {
            event_id: "01HX0000000000000000000000".to_string(),
            occurred_at: "2026-05-22T00:00:00Z".to_string(),
            principal_id_hash: Some(Hashed::from_hash("sha256:caseworker")),
            scopes_used: vec!["registry_notary:admin".to_string()],
            decision: "allowed".to_string(),
            method: "GET".to_string(),
            path: "/v1/claims".to_string(),
            status: 200,
            verification_id: None,
            claim_hash: None,
            purposes: None,
            row_count: None,
            source_read_count: None,
            forwarded: None,
            error_code: None,
            access_mode: Some(AccessMode::MachineClient),
            federation_peer_id_hash: None,
            federation_issuer: None,
            federation_profile: None,
            federation_purpose: None,
            federation_request_jti_hash: None,
            federation_subject_ref_hash: None,
            denial_code: None,
            token_claim_name: None,
            correlation_id_hash: None,
            credential_profile: None,
            protocol: None,
            credential_configuration_id: None,
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_version: None,
            policy_hash: None,
            target_type: None,
            target_ref_hash: None,
            requester_type: None,
            requester_ref_hash: None,
            matching_policy_id: None,
            matching_policy_hash: None,
            matching_evaluated_rule_ids: None,
            ecosystem_binding_id: None,
            ecosystem_binding_version: None,
            pack_id: None,
            pack_version: None,
            matching_method: None,
            matching_outcome: None,
            matching_error_code: None,
            redacted_fields: None,
            batch_items: None,
            source_sidecar_config_hashes: None,
            config: None,
        }
    }

    fn auth_state(audit: AuditPipeline) -> Arc<AuthAuditState> {
        Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator::Static {
                api_keys: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: Vec::new(),
                    authorization_details: None,
                }],
                bearer_tokens: Vec::new(),
            })),
            audit,
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            self_attestation_invalid_token_limiter: None,
            self_attestation_rate_keys: None,
        })
    }

    #[test]
    fn evidence_service_discovery_is_not_auth_exempt() {
        let protected_openapi = AuthExemptionPolicy {
            openapi_requires_auth: true,
        };
        assert!(
            !is_auth_exempt_path("/.well-known/evidence-service", protected_openapi),
            "service discovery exposes configured capability metadata and must stay authenticated"
        );
        assert!(is_auth_exempt_path("/healthz", protected_openapi));
        assert!(is_auth_exempt_path(
            "/.well-known/evidence/jwks.json",
            protected_openapi
        ));
        assert!(!is_auth_exempt_path("/openapi.json", protected_openapi));

        let public_openapi = AuthExemptionPolicy {
            openapi_requires_auth: false,
        };
        assert!(is_auth_exempt_path("/openapi.json", public_openapi));
        assert!(
            !is_auth_exempt_path("/.well-known/evidence-service", public_openapi),
            "server.openapi_requires_auth only affects /openapi.json"
        );
    }

    fn public_jwk_with_kid(public_jwk: &str, kid: &str) -> String {
        let mut value: Value = serde_json::from_str(public_jwk).expect("public JWK parses");
        value["kid"] = json!(kid);
        serde_json::to_string(&value).expect("public JWK serializes")
    }

    #[test]
    fn issuer_registry_uses_active_key_and_publishes_rotated_keys_once() {
        unsafe {
            std::env::set_var("TEST_ACTIVE_SIGNING_JWK", TEST_ISSUER_JWK);
            std::env::set_var("TEST_OLD_SIGNING_PUBLIC_JWK", TEST_OLD_ISSUER_PUBLIC_JWK);
            std::env::set_var(
                "TEST_EXPIRED_OLD_SIGNING_PUBLIC_JWK",
                public_jwk_with_kid(
                    TEST_OLD_ISSUER_PUBLIC_JWK,
                    "did:web:issuer.example#expired-old",
                ),
            );
            std::env::set_var("TEST_OLD_HSM_PUBLIC_JWK", TEST_OLD_HSM_PUBLIC_JWK);
            std::env::set_var("TEST_DISABLED_SIGNING_JWK", TEST_ISSUER_JWK);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_ACTIVE_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
  old-key:
    provider: local_jwk_env
    public_jwk_env: TEST_OLD_SIGNING_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#old
    status: publish_only
  old-hsm-key:
    provider: pkcs11
    public_jwk_env: TEST_OLD_HSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm-old
    status: publish_only
  expired-old-key:
    provider: local_jwk_env
    public_jwk_env: TEST_EXPIRED_OLD_SIGNING_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#expired-old
    status: publish_only
    publish_until_unix_seconds: 1
  disabled-key:
    provider: local_jwk_env
    private_jwk_env: TEST_DISABLED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#disabled
    status: disabled
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
"#,
        )
        .expect("evidence config parses");
        let registry = EvidenceIssuerRegistry::from_config(&evidence).expect("registry builds");

        assert!(registry.issuer("profile-a").is_ok());
        assert!(registry.issuer("profile-b").is_ok());
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 3);
        assert!(jwks.iter().all(|jwk| jwk.get("d").is_none()));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#active"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#old"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#hsm-old"));
        assert!(!jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#expired-old"));
        assert!(!jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#disabled"));
    }

    #[test]
    fn local_jwk_signing_key_rejects_mismatched_embedded_kid() {
        let jwk = r#"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#wrong","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
        unsafe {
            std::env::set_var("TEST_MISMATCHED_SIGNING_JWK", jwk);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_MISMATCHED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("mismatched key id must fail startup");
        assert!(
            err.to_string().contains("kid does not match"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn pkcs11_signing_key_fails_closed_when_feature_is_disabled() {
        unsafe {
            std::env::set_var(
                "TEST_PKCS11_PUBLIC_JWK",
                r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
            );
            std::env::set_var("TEST_PKCS11_PIN", "1234");
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: registry-notary
    pin_env: TEST_PKCS11_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_PKCS11_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("PKCS#11 must fail closed without feature");
        assert!(
            err.to_string().contains("provider 'pkcs11' is not enabled"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "pkcs11")]
    #[tokio::test]
    async fn pkcs11_signing_key_signs_with_softhsm_when_available() {
        let _guard = SOFTHSM_ENV_LOCK.lock().await;
        let Some(module_path) = softhsm_module_path() else {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but softhsm2-util is not available"
            );
            eprintln!("skipping SoftHSM signing test: softhsm2-util is not available");
            return;
        };
        if command_output(std::process::Command::new("openssl").arg("version")).is_none() {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but openssl is not available"
            );
            eprintln!("skipping SoftHSM signing test: openssl is not available");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let token_dir = tmp.path().join("tokens");
        std::fs::create_dir(&token_dir).expect("token dir is created");
        let softhsm_conf = tmp.path().join("softhsm2.conf");
        std::fs::write(
            &softhsm_conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                token_dir.display()
            ),
        )
        .expect("SoftHSM config is written");

        let token_label = format!("registry-notary-test-{}", std::process::id());
        let pin = "1234";
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", &softhsm_conf);
        }
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--init-token")
                .arg("--free")
                .arg("--label")
                .arg(&token_label)
                .arg("--so-pin")
                .arg("123456")
                .arg("--pin")
                .arg(pin),
        );

        let key_path = tmp.path().join("issuer-ed25519.pem");
        let secondary_key_path = tmp.path().join("issuer-ed25519-secondary.pem");
        run_command(
            std::process::Command::new("openssl")
                .arg("genpkey")
                .arg("-algorithm")
                .arg("ED25519")
                .arg("-out")
                .arg(&key_path),
        );
        run_command(
            std::process::Command::new("openssl")
                .arg("genpkey")
                .arg("-algorithm")
                .arg("ED25519")
                .arg("-out")
                .arg(&secondary_key_path),
        );
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--import")
                .arg(&key_path)
                .arg("--token")
                .arg(&token_label)
                .arg("--pin")
                .arg(pin)
                .arg("--label")
                .arg("issuer-signing-key")
                .arg("--id")
                .arg("01ab23cd")
                .arg("--force"),
        );
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--import")
                .arg(&secondary_key_path)
                .arg("--token")
                .arg(&token_label)
                .arg("--pin")
                .arg(pin)
                .arg("--label")
                .arg("issuer-signing-key-secondary")
                .arg("--id")
                .arg("02ab23cd")
                .arg("--force"),
        );

        let public_der = command_output(
            std::process::Command::new("openssl")
                .arg("pkey")
                .arg("-in")
                .arg(&key_path)
                .arg("-pubout")
                .arg("-outform")
                .arg("DER"),
        )
        .expect("openssl exports public key");
        assert!(
            public_der.len() >= 32,
            "Ed25519 SubjectPublicKeyInfo has key bytes"
        );
        let x = URL_SAFE_NO_PAD.encode(&public_der[public_der.len() - 32..]);
        let secondary_public_der = command_output(
            std::process::Command::new("openssl")
                .arg("pkey")
                .arg("-in")
                .arg(&secondary_key_path)
                .arg("-pubout")
                .arg("-outform")
                .arg("DER"),
        )
        .expect("openssl exports secondary public key");
        assert!(
            secondary_public_der.len() >= 32,
            "secondary Ed25519 SubjectPublicKeyInfo has key bytes"
        );
        let secondary_x =
            URL_SAFE_NO_PAD.encode(&secondary_public_der[secondary_public_der.len() - 32..]);
        let public_jwk_primary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm"
        })
        .to_string();
        let public_jwk_secondary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": secondary_x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm-secondary"
        })
        .to_string();
        unsafe {
            std::env::set_var("TEST_SOFTHSM_PIN", pin);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK", public_jwk_primary);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK_SECONDARY", public_jwk_secondary);
        }

        let evidence: EvidenceConfig = serde_norway::from_str(&format!(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#softhsm
    status: active
  hsm-key-secondary:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key-secondary
    key_id_hex: 02ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK_SECONDARY
    alg: EdDSA
    kid: did:web:issuer.example#softhsm-secondary
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key-secondary
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
"#,
        ))
        .expect("evidence config parses");

        let registry =
            EvidenceIssuerRegistry::from_config(&evidence).expect("SoftHSM signer builds");
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 2);
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm-secondary"));
        let issuer = registry
            .issuer("profile-a")
            .expect("profile-a issuer resolves");
        assert!(registry.issuer("profile-b").is_ok());
        let profile = evidence
            .credential_profiles
            .get("profile-a")
            .expect("profile-a exists");
        let results = vec![ClaimResultView {
            evaluation_id: "eval-softhsm".to_string(),
            claim_id: "claim-a".to_string(),
            claim_version: "1.0.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "person".to_string(),
                handle: "subject-ref".to_string(),
                identifier_schemes: vec!["registry-subject-ref".to_string()],
                profile: None,
            },
            matching: None,
            value: Some(serde_json::json!({ "verified": true })),
            satisfied: Some(true),
            disclosure: "value".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CLAIM_RESULT_JSON.to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "softhsm-test".to_string(),
                "eval-test".to_string(),
                "claim".to_string(),
                "1".to_string(),
                registry_notary_core::ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        }];
        let signed = registry_notary_core::sd_jwt::issue(
            profile,
            &issuer,
            &results,
            "subject-ref",
            None,
            time::OffsetDateTime::now_utc(),
            registry_notary_core::sd_jwt::IssueOptions::default(),
        )
        .await
        .expect("SoftHSM-backed credential issues");
        assert!(
            signed.compact.contains('~'),
            "issued credential includes SD-JWT disclosure separators"
        );
    }

    #[cfg(feature = "pkcs11")]
    fn softhsm_module_path() -> Option<String> {
        if let Some(path) = command_output(
            std::process::Command::new("softhsm2-util")
                .arg("--show-config")
                .arg("default-pkcs11-lib"),
        )
        .and_then(|output| String::from_utf8(output).ok())
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty() && std::path::Path::new(path).is_absolute())
        {
            return Some(path);
        }

        [
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
            "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .map(str::to_string)
    }

    #[cfg(feature = "pkcs11")]
    fn require_softhsm() -> bool {
        std::env::var("REGISTRY_NOTARY_REQUIRE_SOFTHSM")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    #[cfg(feature = "pkcs11")]
    fn command_output(command: &mut std::process::Command) -> Option<Vec<u8>> {
        let output = command.output().ok()?;
        output.status.success().then_some(output.stdout)
    }

    #[cfg(feature = "pkcs11")]
    fn run_command(command: &mut std::process::Command) {
        let output = command.output().expect("command starts");
        assert!(
            output.status.success(),
            "command failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn test_audit_config(sink: &str) -> registry_notary_core::EvidenceAuditConfig {
        std::env::set_var(
            TEST_AUDIT_HASH_SECRET_ENV,
            "0123456789abcdef0123456789abcdef",
        );
        registry_notary_core::EvidenceAuditConfig {
            sink: sink.to_string(),
            hash_secret_env: Some(TEST_AUDIT_HASH_SECRET_ENV.to_string()),
            ..registry_notary_core::EvidenceAuditConfig::default()
        }
    }

    #[test]
    fn audit_event_carries_self_attestation_context_fields() {
        let principal = EvidencePrincipal {
            principal_id: "citizen".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };
        let mut response = StatusCode::FORBIDDEN.into_response();
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_id: None,
            verification_decision: Some("evaluate_denied".to_string()),
            claim_hash: Some("sha256:claim-hash".to_string()),
            purposes: None,
            row_count: None,
            source_read_count: None,
            forwarded: None,
            access_mode: Some(AccessMode::SelfAttestation),
            denial_code: Some(SelfAttestationDenialCode::SubjectMismatch),
            token_claim_name: Some(
                registry_notary_core::ConfigMetadata::new("national_id").expect("bounded"),
            ),
            credential_profile: None,
            protocol: Some(
                registry_notary_core::ConfigMetadata::new("openid4vci").expect("bounded"),
            ),
            credential_configuration_id: Some(
                registry_notary_core::ConfigMetadata::new("person_is_alive_sd_jwt")
                    .expect("bounded"),
            ),
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_hash: None,
            target_type: Some("person".to_string()),
            target_ref_hash: Some(Hashed::from_hash("sha256:target")),
            requester_type: Some("person".to_string()),
            requester_ref_hash: Some(Hashed::from_hash("sha256:requester")),
            matching_policy_id: Some("civil-registry-v1".to_string()),
            matching_policy_hash: Some(Hashed::from_hash("sha256:matching-policy")),
            matching_evaluated_rule_ids: Some(vec!["source-binding-policy:person".to_string()]),
            ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
            ecosystem_binding_version: Some("2026-06-19".to_string()),
            matching_method: Some("configured_lookup".to_string()),
            matching_outcome: Some("matched".to_string()),
            matching_error_code: None,
            batch_items: None,
            ..EvidenceAuditContext::default()
        });

        let event = build_audit_event(
            Some(&principal),
            &AuditKeyHasher::unkeyed_dev_only(),
            "POST",
            "/v1/evaluations",
            BoundedCorrelationId::new("req-123").expect("test correlation id is bounded"),
            &response,
        );

        assert_eq!(event.decision, "evaluate_denied");
        assert_eq!(event.claim_hash.as_deref(), Some("sha256:claim-hash"));
        assert_eq!(event.access_mode, Some(AccessMode::SelfAttestation));
        assert!(event.principal_id_hash.is_some());
        let expected_correlation_hash = AuditKeyHasher::unkeyed_dev_only().hash("req-123");
        assert_eq!(
            event.correlation_id_hash.as_ref().map(Hashed::as_str),
            Some(expected_correlation_hash.as_str())
        );
        assert_eq!(
            event.denial_code,
            Some(SelfAttestationDenialCode::SubjectMismatch)
        );
        assert_eq!(
            event.protocol.as_ref().map(|value| value.as_str()),
            Some("openid4vci")
        );
        assert_eq!(
            event
                .credential_configuration_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("person_is_alive_sd_jwt")
        );
        assert_eq!(event.target_type.as_deref(), Some("person"));
        assert_eq!(
            event.target_ref_hash.as_ref().map(Hashed::as_str),
            Some("sha256:target")
        );
        assert_eq!(event.requester_type.as_deref(), Some("person"));
        assert_eq!(
            event.requester_ref_hash.as_ref().map(Hashed::as_str),
            Some("sha256:requester")
        );
        assert_eq!(
            event.matching_policy_id.as_deref(),
            Some("civil-registry-v1")
        );
        assert_eq!(
            event.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(
            event.ecosystem_binding_version.as_deref(),
            Some("2026-06-19")
        );
        assert_eq!(event.matching_method.as_deref(), Some("configured_lookup"));
        assert_eq!(event.matching_outcome.as_deref(), Some("matched"));
    }

    fn test_binding(dataset: &str, entity: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: Some("registry".to_string()),
            required_scope: None,
            dataset: dataset.to_string(),
            entity: entity.to_string(),
            lookup: SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::new(),
            matching: registry_notary_core::SourceMatchingConfig::default(),
        }
    }

    fn test_source_config(base_url: &str, allow_insecure_localhost: bool) -> EvidenceConfig {
        EvidenceConfig {
            allowed_purposes: vec![SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()],
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: base_url.to_string(),
                    allow_insecure_localhost,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_POLICY_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        }
    }

    fn source_adapter_sidecar_spike_config(base_url: &str) -> EvidenceConfig {
        let raw = format!(
            r#"
enabled: true
service_id: spike.registry-notary
allowed_purposes:
  - {SOURCE_ADAPTER_SPIKE_PURPOSE}
source_connections:
  source_adapter_crvs:
    base_url: "{base_url}"
    allow_insecure_localhost: true
    retry_on_5xx: false
    token_env: {SOURCE_ADAPTER_SIDECAR_TOKEN_ENV}
claims:
  - id: date-of-birth
    title: Date of birth
    version: 2026-05
    subject_type: person
    value:
      type: date
    inputs:
      - name: subject_id
        type: string
    source_bindings:
      crvs:
        connector: source_adapter_sidecar
        connection: source_adapter_crvs
        required_scope: civil_registry:evidence_verification
        dataset: civil_registry
        entity: civil_person
        lookup:
          input: target.id
          field: national_id
          op: eq
          cardinality: one
        fields:
          birth_date:
            field: birth_date
            type: date
            required: true
        matching:
          allowed_purposes:
            - "{SOURCE_ADAPTER_SPIKE_PURPOSE}"
    rule:
      type: extract
      source: crvs
      field: birth_date
    disclosure:
      default: value
      allowed:
        - value
        - redacted
    formats:
      - "{FORMAT_CLAIM_RESULT_JSON}"
"#
        );
        serde_norway::from_str(&raw).expect("spike config parses")
    }

    fn http_json_sidecar_test_manifest(upstream_url: &str) -> String {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH,
        );
        std::env::set_var(
            HTTP_JSON_CREDENTIAL_ENV,
            json!({
                "baseUrl": upstream_url,
                "clientId": "notary-test",
                "apiToken": "http-json-target-token"
            })
            .to_string(),
        );
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: "{SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV}"
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
sources:
  source_adapter_crvs:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: "{HTTP_JSON_CREDENTIAL_ENV}"
    credential_public_fields:
      - baseUrl
      - clientId
    allowed_base_urls:
      - "{upstream_url}"
    allow_insecure_localhost: true
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/people"
      query:
        id:
          cel: lookup.value
      headers:
        x-client-id:
          cel: credential_public.clientId
      auth:
        type: bearer
        token:
          secret: apiToken
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#
        )
    }

    async fn fixed_source_adapter_batch_response_handler(
        State(response): State<Value>,
        Json(_request): Json<Value>,
    ) -> Response {
        Json(response).into_response()
    }

    async fn http_json_people_handler(
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> Response {
        let authorized = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            == Some("Bearer http-json-target-token");
        let client_id = headers
            .get("x-client-id")
            .and_then(|value| value.to_str().ok());
        if !authorized || client_id != Some("notary-test") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let id = query.get("id").cloned().unwrap_or_default();
        let results = match id.as_str() {
            "person-123" | "smoke-person" => json!([
                {
                    "national_id": id,
                    "birth_date": "1990-01-01",
                    "ignored_extra": "notary must not depend on this"
                }
            ]),
            _ => json!([]),
        };
        Json(json!({ "results": results })).into_response()
    }

    fn http_json_sidecar_test_config(upstream_url: &str) -> SidecarConfig {
        serde_norway::from_str(&http_json_sidecar_test_manifest(upstream_url))
            .expect("http_json sidecar test config parses")
    }

    async fn read_source_adapter_batch_from_fixed_response(
        response: Value,
    ) -> Vec<Result<Value, EvidenceError>> {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                    post(fixed_source_adapter_batch_response_handler),
                )
                .with_state(response),
        );
        let evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let bindings = ["person-0", "person-1"]
            .into_iter()
            .map(|id| {
                (
                    binding.clone(),
                    EvidenceRequestContext {
                        requester: None,
                        target: registry_notary_core::EvidenceEntity::from_subject_request(
                            "Person",
                            SubjectRequest {
                                id: id.to_string(),
                                id_type: None,
                            },
                        ),
                        relationship: None,
                        on_behalf_of: None,
                    },
                )
            })
            .collect::<Vec<_>>();

        read_remote_source_adapter_sidecar_many_context(
            &source,
            connection,
            &bindings,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
    }

    #[derive(Clone)]
    struct SourceAdapterAssuranceFixture {
        assurance_count: Arc<AtomicUsize>,
        records_count: Arc<AtomicUsize>,
        config_hash: String,
    }

    async fn fixed_source_adapter_assurance_handler(
        State(fixture): State<SourceAdapterAssuranceFixture>,
    ) -> Response {
        fixture.assurance_count.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "status": "ready",
            "product": "registry-notary-source-adapter-sidecar",
            "instance_id": "demo",
            "environment": "staging",
            "stream_id": "source-adapter-sidecar-runtime",
            "bundle_id": "opencrvs-sidecar-test",
            "sequence": 12,
            "config_hash": fixture.config_hash,
            "signer_kids": ["kid"],
            "expression_hashes_verified": true,
            "runtime_verified": true,
            "smoke_verified": true
        }))
        .into_response()
    }

    async fn fixed_source_adapter_records_handler(
        State(fixture): State<SourceAdapterAssuranceFixture>,
    ) -> Response {
        fixture.records_count.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "data": [{
                "national_id": "person-123",
                "birth_date": "1990-01-01"
            }]
        }))
        .into_response()
    }

    fn expected_source_adapter_sidecar(config_hash: &str) -> ExpectedSidecarConfig {
        ExpectedSidecarConfig {
            product: SOURCE_ADAPTER_PRODUCT.to_string(),
            instance_id: SOURCE_ADAPTER_INSTANCE_ID.to_string(),
            environment: SOURCE_ADAPTER_ENVIRONMENT.to_string(),
            stream_id: SOURCE_ADAPTER_STREAM_ID.to_string(),
            config_hash: config_hash.to_string(),
            require_expression_hashes_verified: true,
            require_runtime_verified: true,
            require_smoke_verified: true,
            assurance_ttl_ms: 60_000,
        }
    }

    #[test]
    fn source_adapter_sidecar_assurance_url_preserves_base_path_prefix() {
        let url =
            source_adapter_sidecar_assurance_url("https://sidecar.example/api/source-adapter")
                .expect("assurance URL builds");

        assert_eq!(
            url.as_str(),
            "https://sidecar.example/api/source-adapter/v1/assurance"
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_expected_assurance_is_cached_across_source_reads() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let config_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: config_hash.clone(),
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/v1/assurance", get(fixed_source_adapter_assurance_handler))
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&config_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(source.has_readiness_check());
        assert!(source.check_ready().await);
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect("first source read succeeds");
        read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect("second source read succeeds");

        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            source
                .observed_sidecar_config_hashes(&evidence, &["date-of-birth".to_string()])
                .await,
            vec![config_hash]
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_expected_assurance_mismatch_fails_before_source_read() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let observed_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let expected_hash =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: observed_hash,
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/v1/assurance", get(fixed_source_adapter_assurance_handler))
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&expected_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(!source.check_ready().await);
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
        let error = read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect_err("mismatched assurance must fail");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn source_adapter_sidecar_missing_assurance_endpoint_fails_before_source_read() {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let expected_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let fixture = SourceAdapterAssuranceFixture {
            assurance_count: Arc::new(AtomicUsize::new(0)),
            records_count: Arc::new(AtomicUsize::new(0)),
            config_hash: expected_hash.clone(),
        };
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route(
                    "/v1/datasets/civil_registry/entities/civil_person/records",
                    get(fixed_source_adapter_records_handler),
                )
                .with_state(fixture.clone()),
        );
        let mut evidence = source_adapter_sidecar_spike_config(
            upstream
                .server_address()
                .expect("HTTP transport exposes upstream address")
                .as_str(),
        );
        evidence
            .source_connections
            .get_mut("source_adapter_crvs")
            .expect("connection exists")
            .expected_sidecar = Some(expected_source_adapter_sidecar(&expected_hash));
        let source = HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let binding = evidence.claims[0].source_bindings["crvs"].clone();
        let connection = source
            .source_connection(&binding)
            .expect("source connection exists");
        let subject = SubjectRequest {
            id: "person-123".to_string(),
            id_type: None,
        };

        assert!(!source.check_ready().await);
        let error = read_remote_registry_data_api_one(
            &source,
            connection,
            &binding,
            &subject,
            SOURCE_ADAPTER_SPIKE_PURPOSE,
        )
        .await
        .expect_err("missing assurance endpoint must fail");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
        assert_eq!(fixture.assurance_count.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.records_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn source_fetch_url_policy_private_network_escape_hatch_keeps_metadata_denial() {
        let config = test_source_config("http://registry-relay:8080", false);
        let mut connection = config
            .source_connections
            .get("registry")
            .expect("source connection")
            .clone();
        connection.allow_insecure_private_network = true;

        let policy = source_fetch_url_policy(&connection);

        assert_eq!(policy.allowed_schemes, ["http", "https"]);
        assert!(policy.allow_localhost);
        assert!(policy.allow_http_private_network);
        assert!(!policy.deny_private_ranges);
        assert!(policy.deny_cloud_metadata);
    }

    #[test]
    fn source_fetch_url_policy_defaults_to_strict() {
        let config = test_source_config("https://registry.example.test", false);
        let connection = config
            .source_connections
            .get("registry")
            .expect("source connection");

        assert_eq!(
            source_fetch_url_policy(connection),
            FetchUrlPolicy::strict()
        );
    }

    #[tokio::test]
    async fn audit_pipeline_emits_chained_jsonl() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let output = std::fs::read_to_string(path).expect("audit output is readable");
        assert!(output.ends_with('\n'));
        assert_eq!(output.lines().count(), 1);

        let line: Value = serde_json::from_str(output.trim_end()).expect("audit line is JSON");
        assert!(line["envelope_id"].as_str().is_some());
        assert_eq!(
            line["record"]["event_id"],
            json!("01HX0000000000000000000000")
        );
        assert!(line["record"]["principal_id_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(line["record"].get("principal_id").is_none());
        assert!(line["record"].get("fields").is_none());
        assert!(line["record"].get("audit").is_none());
    }

    #[tokio::test]
    async fn audit_pipeline_file_sink_uses_configured_rotation() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let mut config = test_audit_config("file");
        config.path = Some(path.display().to_string());
        config.max_size_mb = Some(1);
        config.max_files = Some(2);
        let audit = AuditPipeline::from_config(&config).expect("audit config builds");

        for _ in 0..2_500 {
            audit
                .emit(&audit_event())
                .await
                .expect("audit write succeeds");
        }

        assert!(path.exists(), "active audit file should exist");
        assert!(
            tmp.path().join("audit.jsonl.1").exists(),
            "rotated audit file should exist"
        );
        assert!(
            !tmp.path().join("audit.jsonl.2").exists(),
            "rotation should retain only the configured number of files"
        );
    }

    #[test]
    fn audit_pipeline_file_sink_is_single_writer() {
        // #211: a second notary audit pipeline over the same file path must fail
        // loudly at construction (the single-writer advisory lock) rather than
        // silently forking the audit chain.
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let mut config = test_audit_config("file");
        config.path = Some(path.display().to_string());

        let _first = AuditPipeline::from_config(&config).expect("first audit pipeline builds");
        let second = AuditPipeline::from_config(&config);
        assert!(
            matches!(
                second,
                Err(StandaloneServerError::Audit(AuditError::SinkLocked { .. }))
            ),
            "second writer must be rejected, got {second:?}"
        );
    }

    #[test]
    fn audit_pipeline_accepts_syslog_sink_config() {
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some("/tmp/registry-notary-test-syslog.sock".to_string());

        AuditPipeline::from_config(&config).expect("syslog audit config builds");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn audit_pipeline_syslog_sink_writes_to_configured_socket() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let socket_path = tmp.path().join("audit.sock");
        let socket = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some(socket_path.display().to_string());
        let audit = AuditPipeline::from_config(&config).expect("syslog audit config builds");

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let mut buffer = vec![0; 8192];
        let bytes = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("syslog datagram is received")
            .expect("syslog socket receives datagram");
        let frame = std::str::from_utf8(&buffer[..bytes]).expect("syslog frame is UTF-8");
        assert!(frame.starts_with("<134>1 "));
        assert!(frame.contains("registry-platform-audit"));
        assert!(frame.contains(r#""event_id":"01HX0000000000000000000000""#));
    }

    #[test]
    fn audit_pipeline_rejects_zero_file_retention() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut config = test_audit_config("file");
        config.path = Some(tmp.path().join("audit.jsonl").display().to_string());
        config.max_files = Some(0);

        let error = AuditPipeline::from_config(&config).expect_err("zero retention is rejected");

        assert!(matches!(
            error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
        assert!(
            error.to_string().contains("max_files"),
            "error should name the invalid field"
        );
    }

    #[test]
    fn audit_pipeline_rejects_sink_specific_fields_on_wrong_sink() {
        let mut stdout_config = test_audit_config("stdout");
        stdout_config.max_size_mb = Some(1);
        let stdout_error = AuditPipeline::from_config(&stdout_config)
            .expect_err("stdout cannot accept file rotation");
        assert!(matches!(
            stdout_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));

        let mut file_config = test_audit_config("file");
        file_config.path = Some("/tmp/audit.jsonl".to_string());
        file_config.syslog_socket_path = Some("/tmp/syslog.sock".to_string());
        let file_error =
            AuditPipeline::from_config(&file_config).expect_err("file cannot accept syslog path");
        assert!(matches!(
            file_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
    }

    #[tokio::test]
    async fn http_json_sidecar_rda_facade_can_source_single_item_attestation() {
        let _env_guard = HTTP_JSON_SIDECAR_ENV_LOCK.lock().await;
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/people", get(http_json_people_handler)));
        let upstream_url = upstream
            .server_address()
            .expect("HTTP transport exposes upstream address")
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let sidecar = sidecar_router(http_json_sidecar_test_config(&upstream_url))
            .await
            .expect("http_json sidecar router builds");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(source_adapter_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await
            .expect("http_json sidecar facade sources the claim");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "date-of-birth");
        assert_eq!(results[0].value, Some(json!("1990-01-01")));
        assert_eq!(results[0].provenance.used.source_count, 1);
        assert!(
            results[0].provenance.used.source_runtimes.is_empty(),
            "unsigned local sidecar has no pinned runtime summary"
        );
    }

    /// Mock upstream for the `script_rhai` sidecar. Returns a bare JSON array
    /// record (the script forwards `source.get(...).body` verbatim and the
    /// sidecar wraps it as `{ "data": [...] }`). Answers both the notary's lookup
    /// value (`person-123`) and the startup-smoke value (`smoke-person`); any
    /// other id yields an empty array. No auth is enforced (the target omits
    /// auth), so the script needs no credential.
    async fn rhai_lookup_handler(Query(query): Query<HashMap<String, String>>) -> Response {
        let id = query.get("id").cloned().unwrap_or_default();
        let records = match id.as_str() {
            "person-123" | "smoke-person" => json!([
                {
                    "national_id": id,
                    "birth_date": "1990-01-01",
                    "ignored_extra": "notary must not depend on this"
                }
            ]),
            _ => json!([]),
        };
        Json(records).into_response()
    }

    fn script_rhai_sidecar_test_manifest(upstream_url: &str) -> String {
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN_HASH,
        );
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: "{SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV}"
limits:
  max_workers: 2
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  source_adapter_crvs:
    engine: script_rhai
    dataset: civil_registry
    entity: civil_person
    allowed_base_urls:
      - "{upstream_url}"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {{
          source.get("primary", "/lookup", #{{ id: ctx.lookup.value }}).body
        }}
      targets:
        primary:
          base_url: "{upstream_url}"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#
        )
    }

    fn script_rhai_sidecar_test_config(upstream_url: &str) -> SidecarConfig {
        serde_norway::from_str(&script_rhai_sidecar_test_manifest(upstream_url))
            .expect("script_rhai sidecar test config parses")
    }

    /// End-to-end twin of `http_json_sidecar_rda_facade_can_source_single_item_attestation`,
    /// swapping only the sidecar engine to `script_rhai`. The notary connector
    /// (`source_adapter_sidecar`) and its spike config are identical: the
    /// protocol between notary and sidecar is engine-agnostic.
    #[tokio::test]
    async fn script_rhai_sidecar_rda_facade_can_source_single_item_attestation() {
        let _env_guard = HTTP_JSON_SIDECAR_ENV_LOCK.lock().await;
        std::env::set_var(
            SOURCE_ADAPTER_SIDECAR_TOKEN_ENV,
            SOURCE_ADAPTER_SIDECAR_TOKEN,
        );
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/lookup", get(rhai_lookup_handler)));
        let upstream_url = upstream
            .server_address()
            .expect("HTTP transport exposes upstream address")
            .to_string()
            .trim_end_matches('/')
            .to_string();
        let sidecar = sidecar_router(script_rhai_sidecar_test_config(&upstream_url))
            .await
            .expect("script_rhai sidecar router builds and passes startup smoke");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(source_adapter_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(SOURCE_ADAPTER_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await
            .expect("script_rhai sidecar facade sources the claim");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "date-of-birth");
        assert_eq!(results[0].value, Some(json!("1990-01-01")));
        assert_eq!(results[0].provenance.used.source_count, 1);
        assert!(
            results[0].provenance.used.source_runtimes.is_empty(),
            "unsigned local sidecar has no pinned runtime summary"
        );
    }

    #[tokio::test]
    async fn source_adapter_sidecar_batch_client_rejects_malformed_response_item_ids() {
        let cases = [
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "id": "1", "data": [{ "national_id": "person-1", "birth_date": "1991-01-01" }] },
                    { "id": "unexpected", "data": [] }
                ]
            }),
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "id": "0", "data": [] }
                ]
            }),
            json!({
                "items": [
                    { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                    { "data": [] }
                ]
            }),
        ];

        for response in cases {
            let results = read_source_adapter_batch_from_fixed_response(response).await;

            assert_eq!(results.len(), 2);
            assert!(
                results
                    .iter()
                    .all(|result| matches!(result, Err(EvidenceError::SourceUnavailable))),
                "malformed batch response ids must reject the whole batch result: {results:?}"
            );
        }
    }

    #[tokio::test]
    async fn source_adapter_sidecar_batch_client_maps_missing_response_item_per_subject() {
        let results = read_source_adapter_batch_from_fixed_response(json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] }
            ]
        }))
        .await;

        assert_eq!(results.len(), 2);
        assert!(results[0]
            .as_ref()
            .is_ok_and(|row| row.get("birth_date") == Some(&json!("1990-01-01"))));
        assert!(matches!(results[1], Err(EvidenceError::SourceUnavailable)));
    }

    #[tokio::test]
    async fn audit_sink_emit_surfaces_file_write_errors() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));

        let error = audit
            .emit(&audit_event())
            .await
            .expect_err("file write error is returned");

        assert!(matches!(error, AuditError::Io(_)));
    }

    #[tokio::test]
    async fn audit_write_failure_replaces_authorized_response_with_request_error() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(auth_state(audit), auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let response = server.get("/ok").add_header("x-api-key", "api-token").await;

        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("audit.write_failed"));
    }

    #[tokio::test]
    async fn invalid_bearer_tokens_are_rate_limited_when_self_attestation_is_enabled() {
        let rate_limits = SelfAttestationRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 1,
            per_principal_per_minute: 1,
            subject_mismatch_per_principal_per_hour: 1,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 1,
            ..SelfAttestationRateLimitsConfig::default()
        };
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new()));
        let state = Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator::Static {
                api_keys: Vec::new(),
                bearer_tokens: Vec::new(),
            })),
            audit: audit.clone(),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            self_attestation_invalid_token_limiter: Some(Arc::new(
                SelfAttestationRateLimiter::new(rate_limits),
            )),
            self_attestation_rate_keys: Some(Arc::new(SelfAttestationRateLimitKeys::new(
                audit.profile.key_hasher(),
            ))),
        });
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state, auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let first = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        first.assert_status(StatusCode::UNAUTHORIZED);

        let second = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        second.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: Value = second.json();
        assert_eq!(body["code"], json!("self_attestation.rate_limited"));
    }

    #[tokio::test]
    async fn missing_credentials_are_rate_limited_when_self_attestation_is_enabled() {
        let rate_limits = SelfAttestationRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 1,
            per_principal_per_minute: 1,
            subject_mismatch_per_principal_per_hour: 1,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 1,
            ..SelfAttestationRateLimitsConfig::default()
        };
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new()));
        let state = Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator::Static {
                api_keys: Vec::new(),
                bearer_tokens: Vec::new(),
            })),
            audit: audit.clone(),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            self_attestation_invalid_token_limiter: Some(Arc::new(
                SelfAttestationRateLimiter::new(rate_limits),
            )),
            self_attestation_rate_keys: Some(Arc::new(SelfAttestationRateLimitKeys::new(
                audit.profile.key_hasher(),
            ))),
        });
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state, auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let first = server.get("/ok").await;
        first.assert_status(StatusCode::UNAUTHORIZED);

        let second = server.get("/ok").await;
        second.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: Value = second.json();
        assert_eq!(body["code"], json!("self_attestation.rate_limited"));
    }

    #[tokio::test]
    async fn auth_state_accepts_case_insensitive_bearer_scheme() {
        let state = AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator::Static {
                api_keys: Vec::new(),
                bearer_tokens: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: vec!["farmer_registry:evidence_verification".to_string()],
                    authorization_details: None,
                }],
            })),
            audit: AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new())),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            self_attestation_invalid_token_limiter: None,
            self_attestation_rate_keys: None,
        };
        let request = Request::builder()
            .uri("/v1/claims")
            .header(header::AUTHORIZATION, "BEARER api-token")
            .body(Body::empty())
            .expect("request builds");

        let principal = state
            .authenticate(request_credentials(&request))
            .await
            .expect("bearer auth succeeds");

        assert_eq!(principal.principal_id, "caseworker");
    }

    #[tokio::test]
    async fn static_auth_rejects_multiple_credential_headers() {
        let authenticator = Authenticator::Static {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            bearer_tokens: vec![ResolvedCredential {
                id: "bearer-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("bearer-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };

        let err = authenticator
            .authenticate(request, &ReplayStores::memory())
            .await
            .expect_err("multiple credentials must fail");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[tokio::test]
    async fn static_auth_rejects_api_key_with_malformed_authorization_header() {
        let authenticator = Authenticator::Static {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            bearer_tokens: Vec::new(),
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        let err = authenticator
            .authenticate(request, &ReplayStores::memory())
            .await
            .expect_err("ambiguous credentials must not fall back to api key");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[test]
    fn oidc_id_token_is_supplemental_not_a_separate_auth_mode() {
        let oidc_request = RequestCredentials {
            api_key: None,
            authorization_present: true,
            bearer_token: Some("access-token".to_string()),
            id_token: Some("id-token".to_string()),
        };
        let api_key_and_bearer = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };
        let api_key_and_malformed_authorization = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        assert_eq!(oidc_request.credential_type_count(), 1);
        assert_eq!(api_key_and_bearer.credential_type_count(), 2);
        assert_eq!(
            api_key_and_malformed_authorization.credential_type_count(),
            2
        );
    }

    #[test]
    fn static_credentials_have_machine_access_and_no_verified_claims() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: None,
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };

        let authenticated =
            authenticate_static(&request, &[credential], &[]).expect("static auth succeeds");

        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "caseworker");
        assert_eq!(
            authenticated.scopes,
            vec!["farmer_registry:evidence_verification".to_string()]
        );
        assert!(authenticated.verified_claims.is_none());
        assert!(authenticated.authorization_details.is_none());
    }

    #[test]
    fn static_credentials_can_carry_configured_authorization_details() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: Some(EvidenceAuthorizationDetails {
                detail_type: "registry-notary/evidence-authorization/v1".to_string(),
                schema_version: "v1".to_string(),
                legal_basis_ref: Some("demo:casework".to_string()),
                consent_ref: Some("demo:consent".to_string()),
                jurisdiction: Some("ZZ".to_string()),
                assurance_level: Some("substantial".to_string()),
                ..EvidenceAuthorizationDetails::default()
            }),
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };

        let authenticated =
            authenticate_static(&request, &[credential], &[]).expect("static auth succeeds");
        let details = authenticated
            .authorization_details
            .expect("configured authorization details are trusted context");

        assert_eq!(details.legal_basis_ref.as_deref(), Some("demo:casework"));
        assert_eq!(details.consent_ref.as_deref(), Some("demo:consent"));
        assert_eq!(details.jurisdiction.as_deref(), Some("ZZ"));
        assert_eq!(details.assurance_level.as_deref(), Some("substantial"));
    }

    fn verified_token_with_extra(extra: Map<String, Value>) -> VerifiedToken {
        VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("registry-notary".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: Some("fallback-client".to_string()),
                extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "evidence:self_attest".to_string()],
        }
    }

    #[test]
    fn oidc_principal_carries_bounded_verified_claims() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let mut extra = Map::new();
        extra.insert("scope".to_string(), json!("openid evidence:self_attest"));
        extra.insert(subject_binding_claim.to_string(), json!("NAT-123"));
        extra.insert("acr".to_string(), json!("loa3"));
        extra.insert("auth_time".to_string(), json!(1_700_000_000_i64));
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::Many(vec![
                    "registry-notary".to_string(),
                    "citizen-portal".to_string(),
                ])),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: Some("fallback-client".to_string()),
                extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "evidence:self_attest".to_string()],
        };

        let authenticated = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            subject_binding_claim,
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "NAT-123");
        assert_eq!(
            verified_claims.issuer.as_str(),
            "https://issuer.example.test"
        );
        assert_eq!(
            verified_claims
                .audiences
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["registry-notary", "citizen-portal"]
        );
        assert_eq!(
            verified_claims
                .client_id
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("azp:citizen-client")
        );
        assert_eq!(
            verified_claims
                .token_type
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("JWT")
        );
        assert_eq!(
            verified_claims
                .scopes
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["openid", "evidence:self_attest"]
        );
        assert_eq!(
            verified_claims
                .subject
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("login-subject-123")
        );
        assert_eq!(
            verified_claims
                .subject_binding_claim
                .as_ref()
                .map(VerifiedClaimName::as_str),
            Some(subject_binding_claim)
        );
        assert_eq!(
            verified_claims
                .subject_binding_value
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("NAT-123")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("loa3")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_000));
        assert_eq!(verified_claims.exp, Some(1_700_003_600));
        assert_eq!(verified_claims.iat, Some(1_700_000_000));
        assert_eq!(verified_claims.nbf, Some(1_699_999_900));
    }

    #[test]
    fn oidc_principal_requires_configured_principal_claim() {
        let verified = verified_token_with_extra(Map::new());

        let error = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "national_id",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect_err("missing configured principal claim must not fall back to matched client");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_matched_client_id_when_default_sub_is_missing() {
        let mut verified = verified_token_with_extra(Map::new());
        verified.claims.sub = None;
        verified.claims.azp = None;
        verified.claims.client_id = Some("service-client".to_string());
        verified.matched_client = Some("client_id:service-client".to_string());

        let error = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect_err("matched client_id must not replace a missing sub principal");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_matched_azp_when_default_sub_is_missing() {
        let mut verified = verified_token_with_extra(Map::new());
        verified.claims.sub = None;
        verified.claims.azp = Some("service-client".to_string());
        verified.claims.client_id = None;
        verified.matched_client = Some("azp:service-client".to_string());

        let error = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect_err("matched azp alone is not a client-credentials principal");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_malformed_matching_authorization_details() {
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([{
                "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
                "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                "actions": "evaluate"
            }]),
        );
        let verified = verified_token_with_extra(extra);

        let error = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect_err("malformed matching authorization_details must fail auth");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_duplicate_matching_authorization_details() {
        let detail = json!({
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["registry-notary"]
        });
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([detail.clone(), detail]),
        );
        let verified = verified_token_with_extra(extra);

        let error = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect_err("duplicate matching authorization_details must fail auth");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_ignores_context_only_matching_authorization_details() {
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([{
                "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
                "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                "legal_basis_ref": "demo:casework",
                "consent_ref": "demo:consent",
                "jurisdiction": "ZZ",
                "assurance_level": "substantial"
            }]),
        );
        let verified = verified_token_with_extra(extra);

        let principal = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect("context-only OIDC authorization_details fall back to scope checks");

        assert!(principal.authorization_details.is_none());
    }

    #[test]
    fn oidc_principal_can_bind_userinfo_claims_and_id_token_assurance() {
        let mut access_extra = Map::new();
        access_extra.insert("scope".to_string(), json!("openid self_attestation"));
        let access_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: None,
                azp: Some("citizen-client".to_string()),
                client_id: Some("citizen-client".to_string()),
                extra: access_extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "self_attestation".to_string()],
        };
        let mut userinfo_extra = Map::new();
        userinfo_extra.insert("individual_id".to_string(), json!("NID-1001"));
        let userinfo = registry_platform_oidc::Claims {
            sub: Some("pairwise-subject".to_string()),
            iss: Some("https://issuer.example.test".to_string()),
            aud: None,
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra: userinfo_extra,
        };
        let mut id_token_extra = Map::new();
        id_token_extra.insert("acr".to_string(), json!("mosip:idp:acr:generated-code"));
        id_token_extra.insert("auth_time".to_string(), json!(1_700_000_010_i64));
        let id_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_010),
                nbf: None,
                azp: None,
                client_id: None,
                extra: id_token_extra,
            },
            matched_client: None,
            scopes: Vec::new(),
        };

        let authenticated = principal_from_oidc(
            &access_token,
            Some(&userinfo),
            Some(&id_token),
            verified_claim_value("JWT"),
            "sub",
            Some("individual_id"),
            SelfAttestationClaimSource::Userinfo,
            SelfAttestationAssuranceClaimSource::IdToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(authenticated.principal_id, "pairwise-subject");
        assert_eq!(
            verified_claims.subject_binding_value("individual_id"),
            Some("NID-1001")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("mosip:idp:acr:generated-code")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_010));
    }

    #[test]
    fn oidc_verified_claims_fail_closed_without_string_subject_binding_claim() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("registry-notary".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: None,
                extra: Map::new(),
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["evidence:self_attest".to_string()],
        };

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .is_none());

        let mut verified = verified;
        verified
            .claims
            .extra
            .insert(subject_binding_claim.to_string(), json!(12345));

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .is_none());
    }

    #[test]
    fn oidc_validation_errors_are_internal_invalid_token_auth_failures() {
        assert_eq!(
            oidc_internal_error_code(&OidcError::TokenExpired),
            "auth.invalid_token"
        );
        assert!(matches!(
            oidc_auth_error(OidcError::TokenExpired),
            EvidenceError::MissingCredential
        ));
    }

    #[test]
    fn resolved_credential_debug_output_is_redacted() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: Some(EvidenceAuthorizationDetails {
                detail_type: "registry-notary/evidence-authorization/v1".to_string(),
                schema_version: "v1".to_string(),
                legal_basis_ref: Some("demo:casework".to_string()),
                consent_ref: Some("demo:consent".to_string()),
                jurisdiction: Some("ZZ".to_string()),
                assurance_level: Some("substantial".to_string()),
                ..EvidenceAuthorizationDetails::default()
            }),
        };
        let connection = ResolvedEvidenceSourceConnection {
            id: "registry".to_string(),
            base_url: "https://registry.example.test".to_string(),
            auth: SourceAuthRuntime::StaticBearer(Arc::from("source-token")),
            fetch_url_policy: FetchUrlPolicy::strict(),
            dci: DciSourceConnectionConfig::default(),
            semaphore: Arc::new(Semaphore::new(8)),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_timeout_max: Duration::from_secs(30),
            expected_sidecar: None,
        };

        let debug = format!("{credential:?} {connection:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("api-token"));
        assert!(!debug.contains("source-token"));
    }

    #[test]
    fn registry_data_api_url_percent_encodes_dataset_and_entity_segments() {
        let binding = test_binding("farmer/registry", "farmer?active");

        let url = registry_data_api_url("https://registry.example.test/api", &binding)
            .expect("url builds");

        assert_eq!(
            url.as_str(),
            "https://registry.example.test/api/v1/datasets/farmer%2Fregistry/entities/farmer%3Factive/records"
        );
    }

    #[test]
    fn context_lookup_value_supports_requester_and_relationship_paths() {
        let mut binding = test_binding("people", "person");
        let mut requester =
            registry_notary_core::EvidenceEntity::with_identifier("Person", "national_id", "REQ-1");
        requester
            .attributes
            .insert("birthdate".to_string(), json!("1984-02-10"));
        let mut relationship = registry_notary_core::EvidenceRelationship {
            relationship_type: "guardian".to_string(),
            attributes: BTreeMap::new(),
        };
        relationship
            .attributes
            .insert("case_id".to_string(), json!("CASE-9"));
        let context = EvidenceRequestContext {
            requester: Some(requester),
            target: registry_notary_core::EvidenceEntity::with_identifier(
                "Person",
                "national_id",
                "NID-1",
            ),
            relationship: Some(relationship),
            on_behalf_of: None,
        };

        binding.lookup.input = "requester.identifiers.national_id".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("requester id resolves"),
            json!("REQ-1")
        );
        binding.lookup.input = "requester.attributes.birthdate".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("requester attr resolves"),
            json!("1984-02-10")
        );
        binding.lookup.input = "relationship.attributes.case_id".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context).expect("relationship attr resolves"),
            json!("CASE-9")
        );
        binding.lookup.input = "requester.identifiers.missing".to_string();
        assert_eq!(
            lookup_value_for_context(&binding, &context)
                .expect_err("missing requester identifier is specific")
                .code(),
            "requester.identifier_missing"
        );
    }

    #[test]
    fn dci_query_fields_build_opencrvs_expression_query_from_target_attributes() {
        let mut binding = test_binding("civil_registry", "birth_registration");
        binding.query_fields = vec![
            SourceQueryFieldConfig {
                input: "target.attributes.given_name".to_string(),
                field: "given_name".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.family_name".to_string(),
                field: "surname".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.birthdate".to_string(),
                field: "birth_date".to_string(),
                op: "eq".to_string(),
            },
        ];
        let dci = DciSourceConnectionConfig {
            query_type: "expression".to_string(),
            registry_type: Some("ns:org:RegistryType:Civil".to_string()),
            registry_event_type: Some("birth".to_string()),
            ..DciSourceConnectionConfig::default()
        };
        let mut target = registry_notary_core::EvidenceEntity::new("Person");
        target
            .attributes
            .insert("given_name".to_string(), json!("Amina"));
        target
            .attributes
            .insert("family_name".to_string(), json!("Diallo"));
        target
            .attributes
            .insert("birthdate".to_string(), json!("2020-01-02"));
        let context = EvidenceRequestContext {
            requester: None,
            target,
            relationship: None,
            on_behalf_of: None,
        };

        let values = source_query_values_for_context(&binding, &context)
            .expect("query values resolve from target attributes");
        let criteria =
            dci_search_criteria_for_values(&dci, &binding, &values, 2).expect("criteria builds");

        assert_eq!(criteria["query_type"], json!("expression"));
        assert_eq!(
            criteria["query"],
            json!({
                "type": "ns:org:QueryType:expression",
                "value": {
                    "expression": {
                        "query": {
                            "given_name": { "type": "exact", "term": "Amina" },
                            "surname": { "type": "exact", "term": "Diallo" },
                            "birth_date": { "type": "exact", "term": "2020-01-02" }
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn rda_query_fields_build_registry_relay_query_params_from_target_attributes() {
        let mut binding = test_binding("civil_registry", "civil_person");
        binding.query_fields = vec![
            SourceQueryFieldConfig {
                input: "target.attributes.given_name".to_string(),
                field: "given_name".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.family_name".to_string(),
                field: "surname".to_string(),
                op: "eq".to_string(),
            },
            SourceQueryFieldConfig {
                input: "target.attributes.birthdate".to_string(),
                field: "birth_date".to_string(),
                op: "eq".to_string(),
            },
        ];
        let mut target = registry_notary_core::EvidenceEntity::new("Person");
        target
            .attributes
            .insert("given_name".to_string(), json!("Amina"));
        target
            .attributes
            .insert("family_name".to_string(), json!("Diallo"));
        target
            .attributes
            .insert("birthdate".to_string(), json!("2020-01-02"));
        let context = EvidenceRequestContext {
            requester: None,
            target,
            relationship: None,
            on_behalf_of: None,
        };

        let values = source_query_values_for_context(&binding, &context)
            .expect("query values resolve from target attributes");
        let pairs = values
            .iter()
            .map(registry_data_api_query_pair)
            .collect::<Result<Vec<_>, _>>()
            .expect("RDA query pairs build");

        assert_eq!(
            pairs,
            vec![
                ("given_name".to_string(), "Amina".to_string()),
                ("surname".to_string(), "Diallo".to_string()),
                ("birth_date".to_string(), "2020-01-02".to_string()),
            ]
        );
        assert_eq!(
            projected_source_fields_with_query_values(&binding, &values),
            vec![
                "birth_date".to_string(),
                "given_name".to_string(),
                "surname".to_string()
            ]
        );
        binding.matching.source_observed_at_field = Some("observed_at".to_string());
        assert_eq!(
            projected_source_fields_with_query_values(&binding, &values),
            vec![
                "birth_date".to_string(),
                "given_name".to_string(),
                "observed_at".to_string(),
                "surname".to_string()
            ]
        );
        assert_eq!(
            projected_source_fields_with_lookup(&binding, "national_id"),
            vec!["national_id".to_string(), "observed_at".to_string()]
        );
    }

    #[test]
    fn dci_expression_filter_accepts_gte_lte_aliases() {
        let gte = dci_expression_filter(&SourceQueryValue {
            field: "birth_date".to_string(),
            op: "gte".to_string(),
            value: json!("2020-01-01"),
        })
        .expect("gte maps to range filter");
        let lte = dci_expression_filter(&SourceQueryValue {
            field: "birth_date".to_string(),
            op: "lte".to_string(),
            value: json!("2020-12-31"),
        })
        .expect("lte maps to range filter");

        assert_eq!(gte, json!({ "type": "range", "gte": "2020-01-01" }));
        assert_eq!(lte, json!({ "type": "range", "lte": "2020-12-31" }));
    }

    #[test]
    fn parse_source_observed_at_trims_timestamp_before_parse() {
        let mut binding = test_binding("people", "person");
        binding.matching.source_observed_at_field = Some("observed_at".to_string());

        let observed_at =
            parse_source_observed_at(&binding, &json!({"observed_at": "\t2026-05-24T12:00:00Z "}))
                .expect("trimmed observed_at parses")
                .expect("observed_at is present");

        assert_eq!(
            observed_at
                .format(&Rfc3339)
                .expect("observed_at formats as RFC3339"),
            "2026-05-24T12:00:00Z"
        );
    }

    #[test]
    fn dci_source_url_rejects_absolute_search_paths() {
        assert!(source_url(
            "https://registry.example.test",
            "https://attacker.example.test/dci/search"
        )
        .is_err());
        assert!(source_url("https://registry.example.test", "file:///tmp/search").is_err());
        assert_eq!(
            source_url("https://registry.example.test/base", "/dci/search")
                .expect("relative path is accepted")
                .as_str(),
            "https://registry.example.test/base/dci/search"
        );
    }

    #[tokio::test]
    async fn source_json_reader_rejects_oversized_body() {
        let app = Router::new().route(
            "/too-large",
            get(|| async { "x".repeat(MAX_SOURCE_JSON_BYTES + 1) }),
        );
        let server = TestServer::builder().http_transport().build(app);
        let url = format!(
            "{}too-large",
            server
                .server_address()
                .expect("HTTP transport exposes upstream address")
        );
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client builds")
            .get(url)
            .send()
            .await
            .expect("request succeeds");

        let error = read_source_json(response)
            .await
            .expect_err("oversized body is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_do_not_follow_upstream_redirects() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN", "source-token");
        let app = Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(|| async { Redirect::temporary("/redirect-target") }),
            )
            .route(
                "/redirect-target",
                get(|| async {
                    Json(json!({
                        "data": [{
                            "id": "person-1",
                            "total_farmed_area": 3.5
                        }]
                    }))
                }),
            );
        let server = TestServer::builder().http_transport().build(app);
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: server
                        .server_address()
                        .expect("HTTP transport exposes upstream address")
                        .to_string(),
                    allow_insecure_localhost: true,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };
        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let mut binding = test_binding("farmer_registry", "farmer");
        binding.fields.insert(
            "total_farmed_area".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "total_farmed_area".to_string(),
                field_type: Some("number".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("redirect response is not followed");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_private_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("https://10.0.0.1", false),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("private source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_cloud_metadata_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("http://169.254.169.254", true),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("metadata source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[test]
    fn http_sources_from_config_sets_finite_request_timeout() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN", "source-token");
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                registry_notary_core::SourceConnectionConfig {
                    base_url: "https://registry.example.test".to_string(),
                    allow_insecure_localhost: false,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN".to_string(),
                    source_auth: None,
                    expected_sidecar: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };

        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");

        assert_eq!(sources.request_timeout, SOURCE_REQUEST_TIMEOUT);
        assert!(sources.request_timeout > Duration::ZERO);
    }
}
