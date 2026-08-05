// SPDX-License-Identifier: Apache-2.0
//! Test fixtures and assertions for Registry Platform consumers.

#[cfg(not(feature = "test-utils"))]
compile_error!(
    "registry-platform-testing is a test-only crate; enable feature \"test-utils\" from dev-dependencies"
);

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::Algorithm;
use registry_platform_audit::{verify_chain, AuditChainHasher, AuditEnvelope};
use registry_platform_crypto::{sign, LocalJwkSigner, PrivateJwk, PublicJwk, SigningProvider};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use wiremock::{
    matchers::{method, path},
    Match, Mock, MockServer, Request, ResponseTemplate,
};

const TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub struct MockIdp {
    issuer: String,
    state: Arc<RwLock<MockIdpState>>,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct MockIdpState {
    keys: Vec<SigningKeyFixture>,
    current: usize,
}

#[derive(Debug, Clone)]
struct SigningKeyFixture {
    private: PrivateJwk,
    public: PublicJwk,
}

impl MockIdp {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock IdP binds to a random local port");
        let addr = listener
            .local_addr()
            .expect("mock IdP local address is available");
        let issuer = format!("http://{addr}");
        let state = Arc::new(RwLock::new(MockIdpState {
            keys: vec![
                SigningKeyFixture::from_jwk(fixtures::ED25519_PRIVATE_JWK),
                SigningKeyFixture::from_jwk(fixtures::ED25519_ROTATED_PRIVATE_JWK),
            ],
            current: 0,
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks.json", get(jwks))
            .with_state(MockIdpAppState {
                issuer: issuer.clone(),
                state: Arc::clone(&state),
            });
        let (tx, rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await;
        });

        Self {
            issuer,
            state,
            shutdown: Some(tx),
            server: Some(server),
        }
    }

    #[must_use]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    #[must_use]
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }

    #[must_use]
    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks.json", self.issuer)
    }

    #[must_use]
    pub fn mint_token(&self, claims: Value) -> String {
        let key = {
            let state = self.state.read().expect("mock IdP state lock is healthy");
            state.keys[state.current].clone()
        };
        mint_ed25519_jwt(&self.issuer, claims, &key.private)
    }

    /// Mint a token whose JOSE header omits the optional `typ` member, modelling
    /// IdPs (such as eSignet) that sign ID Tokens with only `alg` + `kid`.
    #[must_use]
    pub fn mint_token_without_typ(&self, claims: Value) -> String {
        let key = {
            let state = self.state.read().expect("mock IdP state lock is healthy");
            state.keys[state.current].clone()
        };
        mint_ed25519_jwt_without_typ(&self.issuer, claims, &key.private)
    }

    pub fn rotate_key(&self) {
        let mut state = self.state.write().expect("mock IdP state lock is healthy");
        state.current = (state.current + 1) % state.keys.len();
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
    }
}

impl Drop for MockIdp {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

impl SigningKeyFixture {
    fn from_jwk(jwk: &str) -> Self {
        let private = PrivateJwk::parse(jwk).expect("fixture private JWK parses");
        let public = private.public();
        Self { private, public }
    }
}

#[derive(Clone)]
struct MockIdpAppState {
    issuer: String,
    state: Arc<RwLock<MockIdpState>>,
}

async fn discovery(State(state): State<MockIdpAppState>) -> impl IntoResponse {
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/jwks.json", state.issuer),
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }))
}

async fn jwks(State(state): State<MockIdpAppState>) -> impl IntoResponse {
    let key = {
        let state = state.state.read().expect("mock IdP state lock is healthy");
        state.keys[state.current].public.clone()
    };
    Json(json!({ "keys": [key] }))
}

fn mint_ed25519_jwt(issuer: &str, claims: Value, private: &PrivateJwk) -> String {
    let kid = private
        .kid
        .clone()
        .unwrap_or_else(|| "registry-platform-testing-ed25519-1".to_string());
    let claims = normalize_claims(issuer, claims);
    sign_ed25519_compact_jwt_with_key(private, "JWT", &kid, claims)
}

fn mint_ed25519_jwt_without_typ(issuer: &str, claims: Value, private: &PrivateJwk) -> String {
    let kid = private
        .kid
        .clone()
        .unwrap_or_else(|| "registry-platform-testing-ed25519-1".to_string());
    let claims = normalize_claims(issuer, claims);
    let header = json!({ "alg": "EdDSA", "kid": kid });
    let signing_input = format!("{}.{}", encode_json(&header), encode_json(&claims));
    let signature = sign(signing_input.as_bytes(), private).expect("fixture key signs JWT");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

#[must_use]
pub fn sign_ed25519_compact_jwt(private_jwk: &str, typ: &str, kid: &str, claims: Value) -> String {
    let private = PrivateJwk::parse(private_jwk).expect("fixture private JWK parses");
    sign_ed25519_compact_jwt_with_key(&private, typ, kid, claims)
}

#[must_use]
pub fn sign_ed25519_compact_jwt_with_key(
    private: &PrivateJwk,
    typ: &str,
    kid: &str,
    claims: Value,
) -> String {
    let header = json!({
        "alg": "EdDSA",
        "typ": typ,
        "kid": kid,
    });
    let signing_input = format!("{}.{}", encode_json(&header), encode_json(&claims));
    let signature = sign(signing_input.as_bytes(), private).expect("fixture key signs JWT");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

pub async fn sign_ed25519_compact_jwt_with_provider(
    signer: &dyn SigningProvider,
    typ: &str,
    claims: Value,
) -> String {
    let header = json!({
        "alg": "EdDSA",
        "typ": typ,
        "kid": signer.key_id(),
    });
    let signing_input = format!("{}.{}", encode_json(&header), encode_json(&claims));
    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .expect("fixture provider signs JWT");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

#[must_use]
pub fn jwks_from_private_jwk(private: &PrivateJwk) -> Value {
    json!({ "keys": [private.public()] })
}

#[must_use]
pub fn jwks_from_signing_provider(signer: &dyn SigningProvider) -> Value {
    json!({ "keys": [signer.public_jwk()] })
}

fn normalize_claims(issuer: &str, claims: Value) -> Value {
    let now = now_unix_seconds();
    let mut claims = match claims {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    claims
        .entry("iss")
        .or_insert_with(|| Value::String(issuer.to_string()));
    claims.entry("iat").or_insert_with(|| json!(now));
    claims.entry("nbf").or_insert_with(|| json!(now));
    claims
        .entry("exp")
        .or_insert_with(|| json!(now + TOKEN_LIFETIME.as_secs() as i64));
    Value::Object(claims)
}

fn encode_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JWT JSON serializes"))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs() as i64
}

#[derive(Debug)]
pub struct MockHttpUpstream {
    server: MockServer,
    max_request_bytes: Arc<AtomicU64>,
}

impl MockHttpUpstream {
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
            max_request_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    #[must_use]
    pub fn url(&self) -> String {
        self.server.uri()
    }

    #[must_use]
    pub fn expect<'a>(&'a self, method_name: &str, request_path: &str) -> MockExpectation<'a> {
        MockExpectation {
            server: &self.server,
            method: method_name.to_string(),
            path: request_path.to_string(),
            max_request_bytes: Arc::clone(&self.max_request_bytes),
        }
    }

    pub fn assert_max_request_bytes(&self, n: u64) {
        let observed = self.max_request_bytes.load(Ordering::SeqCst);
        assert!(
            observed <= n,
            "expected max request body to be <= {n} bytes, observed {observed} bytes"
        );
    }

    #[must_use]
    pub fn wiremock_server(&self) -> &MockServer {
        &self.server
    }
}

#[derive(Debug)]
pub struct MockExpectation<'a> {
    server: &'a MockServer,
    method: String,
    path: String,
    max_request_bytes: Arc<AtomicU64>,
}

impl MockExpectation<'_> {
    pub async fn respond(self, response: ResponseTemplate) {
        Mock::given(method(self.method.as_str()))
            .and(path(self.path.as_str()))
            .and(BodySizeTracker {
                max_request_bytes: self.max_request_bytes,
            })
            .respond_with(response)
            .mount(self.server)
            .await;
    }

    pub async fn respond_status(self, status: u16) {
        self.respond(ResponseTemplate::new(status)).await;
    }

    pub async fn respond_json(self, status: u16, body: Value) {
        self.respond(ResponseTemplate::new(status).set_body_json(body))
            .await;
    }

    pub async fn respond_body(self, status: u16, body: impl Into<Vec<u8>>) {
        self.respond(ResponseTemplate::new(status).set_body_bytes(body))
            .await;
    }
}

#[derive(Debug)]
struct BodySizeTracker {
    max_request_bytes: Arc<AtomicU64>,
}

impl Match for BodySizeTracker {
    fn matches(&self, request: &Request) -> bool {
        let len = request.body.len() as u64;
        let mut current = self.max_request_bytes.load(Ordering::Relaxed);
        while len > current {
            match self.max_request_bytes.compare_exchange_weak(
                current,
                len,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        true
    }
}

pub mod fixtures {
    use super::*;

    pub const ED25519_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registry-platform-testing-ed25519-1"}"#;
    pub const ED25519_ROTATED_PRIVATE_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"registry-platform-testing-ed25519-2"}"#;

    pub fn ed25519_pair() -> (PrivateJwk, PublicJwk) {
        pair(ED25519_PRIVATE_JWK)
    }

    pub fn ed25519_signer() -> LocalJwkSigner {
        let private = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("fixture private JWK parses");
        LocalJwkSigner::new(private).expect("fixture signer builds")
    }

    fn pair(jwk: &str) -> (PrivateJwk, PublicJwk) {
        let private = PrivateJwk::parse(jwk).expect("fixture private JWK parses");
        let public = private.public();
        (private, public)
    }
}

pub type ChainAssertionError = registry_platform_audit::ChainVerificationError;

pub fn assert_chain_integrity(envelopes: &[AuditEnvelope]) -> Result<(), ChainAssertionError> {
    verify_chain(envelopes, &AuditChainHasher::unkeyed_dev_only()).map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("audit JSON contains forbidden raw value: {needle}")]
pub struct AuditJsonLeakError {
    needle: String,
}

impl AuditJsonLeakError {
    #[must_use]
    pub fn needle(&self) -> &str {
        &self.needle
    }
}

pub fn assert_json_absent_strings<I, S>(
    value: &Value,
    forbidden: I,
) -> Result<(), AuditJsonLeakError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for needle in forbidden {
        let needle = needle.as_ref();
        if !needle.is_empty() && json_value_contains(value, needle) {
            return Err(AuditJsonLeakError {
                needle: needle.to_string(),
            });
        }
    }
    Ok(())
}

fn json_value_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => (if *value { "true" } else { "false" }).contains(needle),
        Value::Number(value) => value.to_string().contains(needle),
        Value::String(value) => value.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| json_value_contains(value, needle)),
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key.contains(needle) || json_value_contains(value, needle)),
    }
}

#[must_use]
pub fn oidc_verifier_config(
    issuer: String,
    audiences: Vec<String>,
) -> registry_platform_oidc::TokenVerifierConfig {
    registry_platform_oidc::TokenVerifierConfig {
        issuer,
        audiences,
        allowed_algorithms: vec![Algorithm::EdDSA],
        allowed_typ: vec!["JWT".to_string()],
        allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
        allowed_userinfo_typ: vec!["JWT".to_string()],
        userinfo_requires_exp: true,
        scope_claim: "scope".to_string(),
        scope_separator: ' ',
        scope_map: None,
        allowed_clients: Vec::new(),
        leeway: Duration::from_secs(60),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use async_trait::async_trait;
    use jsonwebtoken::decode_header;
    use registry_platform_audit::{AuditError, AuditSink, ChainState};
    use registry_platform_crypto::verify;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{
        fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
        TokenVerifier,
    };

    #[test]
    fn ed25519_fixture_signs_and_verifies() {
        let (private, public) = fixtures::ed25519_pair();
        let payload = b"registry-platform-testing";
        let signature = sign(payload, &private).expect("fixture signs");
        verify(payload, &signature, &public).expect("fixture verifies");
    }

    #[test]
    fn rotated_ed25519_fixture_uses_distinct_key_material() {
        let first: Value =
            serde_json::from_str(fixtures::ED25519_PRIVATE_JWK).expect("primary fixture parses");
        let rotated: Value = serde_json::from_str(fixtures::ED25519_ROTATED_PRIVATE_JWK)
            .expect("rotated fixture parses");
        assert_ne!(first["d"], rotated["d"]);
        assert_ne!(first["x"], rotated["x"]);
    }

    #[tokio::test]
    async fn provider_backed_jwt_fixture_signs_with_provider_kid_and_jwks() {
        let signer = fixtures::ed25519_signer();
        let typ = "registry-platform-testing+jwt";
        let token = sign_ed25519_compact_jwt_with_provider(
            &signer,
            typ,
            json!({ "sub": "fixture-subject" }),
        )
        .await;

        let header = decode_header(&token).expect("header decodes");
        assert_eq!(header.kid.as_deref(), Some(signer.key_id()));
        assert_eq!(header.typ.as_deref(), Some(typ));

        let jwks = jwks_from_signing_provider(&signer);
        let keys = jwks["keys"].as_array().expect("jwks keys");
        assert_eq!(keys[0]["kid"], signer.key_id());
        assert!(keys[0].get("d").is_none());
    }

    #[tokio::test]
    async fn mock_idp_serves_discovery_jwks_and_mints_verifiable_tokens() {
        let idp = MockIdp::start().await;
        let discovery = fetch_discovery_with_policy(
            &OidcDiscoveryConfig {
                issuer: idp.issuer(),
                jwks_uri_override: None,
                discovery_timeout: Duration::from_secs(5),
                max_doc_bytes: 16 * 1024,
            },
            &FetchUrlPolicy::dev(),
        )
        .await
        .expect("discovery fetch succeeds");
        assert_eq!(discovery.jwks_uri, idp.jwks_uri());

        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            discovery.jwks_uri,
            JwksFetcherConfig {
                cache_ttl: Duration::from_secs(60),
                negative_cache_ttl: Duration::from_millis(1),
                refresh_cooldown: Duration::from_millis(1),
                max_doc_bytes: 16 * 1024,
                request_timeout: Duration::from_secs(5),
                outage_tolerance: Duration::from_secs(900),
            },
            FetchUrlPolicy::dev(),
        ));
        let mut config = oidc_verifier_config(idp.issuer(), vec!["registry-api".to_string()]);
        config.allowed_clients = vec!["client-a".to_string()];
        let verifier = TokenVerifier::new(config, fetcher);

        let token = idp.mint_token(json!({
            "aud": "registry-api",
            "sub": "subject-1",
            "client_id": "client-a",
            "scope": "claims:read claims:write",
        }));
        let verified = verifier.verify(&token).await.expect("token verifies");
        assert_eq!(
            verified.matched_client.as_deref(),
            Some("client_id:client-a")
        );
        assert_eq!(verified.scopes, vec!["claims:read", "claims:write"]);

        idp.stop().await;
    }

    #[tokio::test]
    async fn mock_idp_rotation_serves_new_kid() {
        let idp = MockIdp::start().await;
        let before = reqwest::get(idp.jwks_uri())
            .await
            .expect("jwks response")
            .json::<Value>()
            .await
            .expect("jwks json");
        idp.rotate_key();
        let after = reqwest::get(idp.jwks_uri())
            .await
            .expect("jwks response")
            .json::<Value>()
            .await
            .expect("jwks json");
        assert_ne!(before, after);
        idp.stop().await;
    }

    #[tokio::test]
    async fn mock_http_upstream_mounts_expectations_and_tracks_request_size() {
        let upstream = MockHttpUpstream::start().await;
        upstream
            .expect("POST", "/claims")
            .respond_json(200, json!({ "ok": true }))
            .await;

        let response = reqwest::Client::new()
            .post(format!("{}/claims", upstream.url()))
            .body("abc")
            .send()
            .await
            .expect("request succeeds");
        assert!(response.status().is_success());
        upstream.assert_max_request_bytes(3);
    }

    #[tokio::test]
    async fn chain_integrity_assertion_delegates_to_audit_verifier() {
        let sink = MemorySink::default();
        let chain = ChainState::unkeyed_dev_only();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let mut second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert_chain_integrity(&[first.clone(), second.clone()]).expect("chain is valid");
        second.record["event"] = json!("changed");
        assert!(assert_chain_integrity(&[first, second]).is_err());
    }

    #[test]
    fn audit_json_leak_assertion_reports_raw_values() {
        let record = json!({
            "event": "evaluation",
            "target_ref_hash": "hmac-sha256:abc",
            "safe": ["no raw subject here"],
        });

        assert_json_absent_strings(&record, ["Amina", "1984-02-10"]).expect("no leak");
        let err = assert_json_absent_strings(&record, ["raw subject"])
            .expect_err("raw substring is reported");
        assert_eq!(err.needle(), "raw subject");

        let escaped = json!({
            "A\nB": "safe wrapper",
            "nested": { "value": "subject \"quoted\" value" },
        });
        let err = assert_json_absent_strings(&escaped, ["A\nB"])
            .expect_err("escaped object-key leak is reported");
        assert_eq!(err.needle(), "A\nB");
        let err = assert_json_absent_strings(&escaped, ["subject \"quoted\""])
            .expect_err("escaped string-value leak is reported");
        assert_eq!(err.needle(), "subject \"quoted\"");

        let boolean = json!({
            "contains_bool": true,
        });
        let err =
            assert_json_absent_strings(&boolean, ["true"]).expect_err("boolean leak is reported");
        assert_eq!(err.needle(), "true");
    }

    #[tokio::test]
    async fn chain_integrity_assertion_accepts_retained_suffix() {
        let sink = MemorySink::default();
        let chain = ChainState::unkeyed_dev_only();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert_chain_integrity(std::slice::from_ref(&second))
            .expect("retained suffix is internally consistent");
        let verification = verify_chain(
            std::slice::from_ref(&second),
            &AuditChainHasher::unkeyed_dev_only(),
        )
        .expect("retained suffix verifies");
        assert_eq!(verification.start_prev_hash, Some(first.record_hash));
        assert_eq!(verification.last_hash, Some(second.record_hash));
    }

    #[derive(Default)]
    struct MemorySink {
        envelopes: Mutex<Vec<AuditEnvelope>>,
    }

    #[async_trait]
    impl AuditSink for MemorySink {
        async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
            self.envelopes
                .lock()
                .expect("memory sink lock is healthy")
                .push(envelope.clone());
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(self
                .envelopes
                .lock()
                .expect("memory sink lock is healthy")
                .last()
                .map(|envelope| envelope.record_hash))
        }

        async fn tail_hash_with_hasher(
            &self,
            hasher: &AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            let _ = hasher;
            Ok(self
                .envelopes
                .lock()
                .expect("memory sink lock is healthy")
                .last()
                .map(|envelope| envelope.record_hash))
        }
    }
}
