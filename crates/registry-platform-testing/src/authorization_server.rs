// SPDX-License-Identifier: Apache-2.0
//! An in-process OAuth 2.0 authorization server for tests.
//!
//! [`TestAuthorizationServer`] serves, over loopback HTTP, the parts of an
//! authorization server a registry service meets: OIDC discovery and RFC 8414
//! metadata, a JWKS, the authorization-code grant with PKCE S256, the
//! `client_credentials` grant authenticated by `private_key_jwt`, and RFC 8693
//! token exchange. Its access tokens are RFC 9068 `at+jwt` tokens signed with
//! the crate's Ed25519 fixture key, so [`TestAuthorizationServer::verifier_config`]
//! gives a `registry-platform-oidc` verifier that accepts them.
//!
//! It is test-only. Nobody signs in: `/authorize` takes the subject from the
//! `login_hint` parameter, or from the subject the test declared logged in, and
//! issues a code for it without asking anyone anything. Codes, assertion
//! identifiers, and everything else it remembers live in memory for the life of
//! the server.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{verify, PrivateJwk, PublicJwk};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

use crate::{fixtures, oidc_verifier_config, sign_ed25519_compact_jwt_with_key};

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ACCESS_TOKEN_TYP: &str = "at+jwt";
const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
/// How long an authorization code stays redeemable.
const CODE_LIFETIME_SECONDS: i64 = 60;
/// The longest client assertion lifetime this server accepts.
const MAXIMUM_ASSERTION_LIFETIME_SECONDS: i64 = 300;
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(300);

/// The `registry_actor_kind` claim a client's tokens carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TestActorKind {
    #[default]
    Human,
    Agent,
    Service,
}

impl TestActorKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

/// The shape of the claims a token exchange issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExchangeProfile {
    /// `act` is exactly `{"sub": <actor subject>}`, and `registry_actor_kind`
    /// is the kind registered for the exchanging client.
    #[default]
    Conformant,
    /// `act` is `{"sub": <actor subject>, "iss": <this issuer>}`, and
    /// `registry_actor_kind` is copied unchanged from the subject token. Some
    /// deployed authorization servers issue this shape; select it to test a
    /// resource server against it.
    IssuerQualifiedActor,
}

/// One registered client.
#[derive(Debug, Clone)]
pub struct TestClient {
    id: String,
    public_jwk: Option<PublicJwk>,
    redirect_uris: Vec<String>,
    resources: Vec<String>,
    actor_kind: TestActorKind,
    token_lifetime: Duration,
    service_subject: String,
}

impl TestClient {
    /// A public client (no key) with no redirect URI, no resource, the human
    /// actor kind, a 300 second token lifetime, and a random service subject.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            public_jwk: None,
            redirect_uris: Vec::new(),
            resources: Vec::new(),
            actor_kind: TestActorKind::default(),
            token_lifetime: DEFAULT_TOKEN_LIFETIME,
            service_subject: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Make the client confidential: it authenticates with a `private_key_jwt`
    /// assertion signed by the private half of `jwk`, which must carry a `kid`.
    #[must_use]
    pub fn with_public_jwk(mut self, jwk: PublicJwk) -> Self {
        self.public_jwk = Some(jwk);
        self
    }

    /// Register a redirect URI. `/authorize` compares redirect URIs exactly.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }

    /// Allow the client to request tokens for this RFC 8707 resource.
    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    #[must_use]
    pub fn with_actor_kind(mut self, kind: TestActorKind) -> Self {
        self.actor_kind = kind;
        self
    }

    /// The lifetime of every token issued to this client. An exchanged token
    /// never outlives its subject token, whatever this says.
    #[must_use]
    pub fn with_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;
        self
    }

    /// The `sub` of the client's own `client_credentials` tokens.
    #[must_use]
    pub fn with_service_subject(mut self, subject: impl Into<String>) -> Self {
        self.service_subject = subject.into();
        self
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn service_subject(&self) -> &str {
        &self.service_subject
    }

    fn lifetime_seconds(&self) -> i64 {
        i64::try_from(self.token_lifetime.as_secs()).expect("the token lifetime fits in i64")
    }
}

/// Configures a [`TestAuthorizationServer`] before it starts.
#[derive(Debug, Default)]
pub struct TestAuthorizationServerBuilder {
    clients: Vec<TestClient>,
    profile: ExchangeProfile,
    logged_in_subject: Option<String>,
}

impl TestAuthorizationServerBuilder {
    #[must_use]
    pub fn client(mut self, client: TestClient) -> Self {
        self.clients.push(client);
        self
    }

    #[must_use]
    pub fn exchange_profile(mut self, profile: ExchangeProfile) -> Self {
        self.profile = profile;
        self
    }

    /// The subject `/authorize` issues a code for when the request carries no
    /// `login_hint`. Without one, such a request ends with `login_required`.
    #[must_use]
    pub fn logged_in_subject(mut self, subject: impl Into<String>) -> Self {
        self.logged_in_subject = Some(subject.into());
        self
    }

    /// Bind a random loopback port and serve.
    ///
    /// # Panics
    ///
    /// Panics when two clients share an identifier, a confidential client's
    /// key carries no `kid`, or the port cannot be bound.
    pub async fn start(self) -> TestAuthorizationServer {
        let mut clients = BTreeMap::new();
        for client in self.clients {
            if let Some(jwk) = &client.public_jwk {
                assert!(
                    jwk.kid.is_some(),
                    "a confidential test client key needs a kid"
                );
            }
            let id = client.id.clone();
            assert!(
                clients.insert(id, client).is_none(),
                "test client identifiers are unique"
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the test authorization server binds to a random local port");
        let addr = listener
            .local_addr()
            .expect("the test authorization server local address is available");
        let issuer = format!("http://{addr}");
        let (signing_key, public_key) = fixtures::ed25519_pair();
        let state = Arc::new(ServerState {
            issuer: issuer.clone(),
            signing_key,
            public_key,
            clients,
            profile: self.profile,
            logged_in_subject: self.logged_in_subject,
            codes: Mutex::new(HashMap::new()),
            used_assertions: Mutex::new(HashSet::new()),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(metadata))
            .route("/.well-known/oauth-authorization-server", get(metadata))
            .route("/jwks.json", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(Arc::clone(&state));
        let (tx, rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await;
        });
        TestAuthorizationServer {
            state,
            shutdown: Some(tx),
            server: Some(server),
        }
    }
}

/// An in-process authorization server. See the module documentation.
pub struct TestAuthorizationServer {
    state: Arc<ServerState>,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for TestAuthorizationServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthorizationServer")
            .field("issuer", &self.state.issuer)
            .field("profile", &self.state.profile)
            .finish_non_exhaustive()
    }
}

impl TestAuthorizationServer {
    #[must_use]
    pub fn builder() -> TestAuthorizationServerBuilder {
        TestAuthorizationServerBuilder::default()
    }

    #[must_use]
    pub fn issuer(&self) -> String {
        self.state.issuer.clone()
    }

    #[must_use]
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.state.issuer)
    }

    #[must_use]
    pub fn jwks_uri(&self) -> String {
        self.state.jwks_uri()
    }

    #[must_use]
    pub fn authorization_endpoint(&self) -> String {
        self.state.authorization_endpoint()
    }

    #[must_use]
    pub fn token_endpoint(&self) -> String {
        self.state.token_endpoint()
    }

    /// A `registry-platform-oidc` verifier configuration that accepts this
    /// server's access tokens for `audiences`. Set `allowed_clients` on it to
    /// the clients the resource server admits.
    #[must_use]
    pub fn verifier_config(
        &self,
        audiences: Vec<String>,
    ) -> registry_platform_oidc::TokenVerifierConfig {
        let mut config = oidc_verifier_config(self.state.issuer.clone(), audiences);
        config.allowed_typ = registry_platform_oidc::access_token_typ_set(ACCESS_TOKEN_TYP);
        config
    }

    /// Sign an access token as this server would issue it to `client_id`
    /// through the authorization-code grant, without running the grant. The
    /// expiry is the caller's, so a test can mint one already expired.
    ///
    /// # Panics
    ///
    /// Panics when `client_id` is not registered.
    #[must_use]
    pub fn issue_access_token(
        &self,
        client_id: &str,
        subject: &str,
        resource: &str,
        scope: &str,
        expires_at: i64,
    ) -> String {
        let client = self
            .state
            .clients
            .get(client_id)
            .expect("the token is issued to a registered test client");
        let mut claims = self
            .state
            .access_claims(client, subject, resource, expires_at);
        claims.insert("scope".to_owned(), json!(scope));
        claims.insert(
            "registry_actor_kind".to_owned(),
            json!(client.actor_kind.as_str()),
        );
        self.state.sign(ACCESS_TOKEN_TYP, claims)
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

impl Drop for TestAuthorizationServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

struct ServerState {
    issuer: String,
    signing_key: PrivateJwk,
    public_key: PublicJwk,
    clients: BTreeMap<String, TestClient>,
    profile: ExchangeProfile,
    logged_in_subject: Option<String>,
    codes: Mutex<HashMap<String, PendingCode>>,
    /// `client_id` and `jti` of every client assertion accepted so far.
    used_assertions: Mutex<HashSet<(String, String)>>,
}

struct PendingCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    subject: String,
    scope: Option<String>,
    resource: Option<String>,
    nonce: Option<String>,
    expires_at: i64,
}

impl ServerState {
    fn jwks_uri(&self) -> String {
        format!("{}/jwks.json", self.issuer)
    }

    fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.issuer)
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer)
    }

    fn kid(&self) -> &str {
        self.signing_key
            .kid
            .as_deref()
            .expect("the fixture signing key carries a kid")
    }

    fn sign(&self, typ: &str, claims: Map<String, Value>) -> String {
        sign_ed25519_compact_jwt_with_key(&self.signing_key, typ, self.kid(), Value::Object(claims))
    }

    /// The claims every access token carries.
    fn access_claims(
        &self,
        client: &TestClient,
        subject: &str,
        audience: &str,
        expires_at: i64,
    ) -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("iss".to_owned(), json!(self.issuer));
        claims.insert("sub".to_owned(), json!(subject));
        claims.insert("aud".to_owned(), json!(audience));
        claims.insert("exp".to_owned(), json!(expires_at));
        claims.insert("iat".to_owned(), json!(now()));
        claims.insert("jti".to_owned(), json!(uuid::Uuid::new_v4().to_string()));
        claims.insert("client_id".to_owned(), json!(client.id));
        claims.insert("azp".to_owned(), json!(client.id));
        claims
    }

    /// The claims of an unexpired access token this server signed.
    fn verified_access_token(&self, token: &str) -> Option<Map<String, Value>> {
        let claims = verified_compact(token, |header| {
            let typ = header.get("typ")?.as_str()?;
            let access = typ.eq_ignore_ascii_case(ACCESS_TOKEN_TYP)
                || typ.eq_ignore_ascii_case("application/at+jwt");
            (access
                && header.get("alg")?.as_str()? == "EdDSA"
                && header.get("kid")?.as_str()? == self.kid())
            .then(|| self.public_key.clone())
        })?;
        let unexpired = claims.get("exp")?.as_i64()? > now();
        (claims.get("iss")?.as_str()? == self.issuer && unexpired).then_some(claims)
    }
}

/// Split and verify a compact JWS, returning its claims. `key_for` inspects
/// the protected header and names the key to check the signature against, or
/// refuses.
fn verified_compact(
    token: &str,
    key_for: impl FnOnce(&Map<String, Value>) -> Option<PublicJwk>,
) -> Option<Map<String, Value>> {
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header = decode_object(header)?;
    let key = key_for(&header)?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let signing_input = &token[..token.rfind('.')?];
    verify(signing_input.as_bytes(), &signature, &key).ok()?;
    decode_object(payload)
}

fn decode_object(segment: &str) -> Option<Map<String, Value>> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

fn now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs();
    i64::try_from(seconds).expect("the clock fits in i64")
}

/// Parse a query or form body, refusing a parameter that appears twice (RFC
/// 6749 section 3.1 and 3.2).
fn single_valued(input: &[u8]) -> Option<HashMap<String, String>> {
    let mut parameters = HashMap::new();
    for (name, value) in url::form_urlencoded::parse(input) {
        if parameters
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(parameters)
}

fn scopes(scope: &str) -> Vec<&str> {
    scope.split(' ').filter(|scope| !scope.is_empty()).collect()
}

async fn metadata(State(state): State<Arc<ServerState>>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": state.authorization_endpoint(),
        "token_endpoint": state.token_endpoint(),
        "jwks_uri": state.jwks_uri(),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials", TOKEN_EXCHANGE_GRANT_TYPE],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["EdDSA", "ES256", "ES384", "RS256", "RS384"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

async fn jwks(State(state): State<Arc<ServerState>>) -> Json<Value> {
    Json(json!({ "keys": [state.public_key] }))
}

/// An authorization request the server cannot answer by redirecting, because
/// the client or its redirect URI is not established (RFC 6749 section
/// 4.1.2.1).
fn unredirectable() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_request" })),
    )
        .into_response()
}

fn redirect_to(redirect_uri: &str, parameters: &[(&str, &str)]) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in parameters {
        query.append_pair(name, value);
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!("{redirect_uri}{separator}{}", query.finish());
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).expect("the redirect location is a valid header"),
    );
    response
}

async fn authorize(State(state): State<Arc<ServerState>>, RawQuery(query): RawQuery) -> Response {
    let Some(parameters) = single_valued(query.unwrap_or_default().as_bytes()) else {
        return unredirectable();
    };
    let Some(client) = parameters
        .get("client_id")
        .and_then(|id| state.clients.get(id))
    else {
        return unredirectable();
    };
    let Some(redirect_uri) = parameters
        .get("redirect_uri")
        .filter(|uri| client.redirect_uris.contains(uri))
    else {
        return unredirectable();
    };
    let state_parameter = parameters.get("state").map(String::as_str);
    let refuse = |error: &str| {
        let mut response = vec![("error", error)];
        if let Some(value) = state_parameter {
            response.push(("state", value));
        }
        response.push(("iss", state.issuer.as_str()));
        redirect_to(redirect_uri, &response)
    };
    if parameters.get("response_type").map(String::as_str) != Some("code") {
        return refuse("unsupported_response_type");
    }
    // An S256 challenge is the base64url encoding of 32 bytes, 43 characters.
    let challenge = parameters.get("code_challenge").filter(|challenge| {
        URL_SAFE_NO_PAD
            .decode(challenge.as_bytes())
            .is_ok_and(|bytes| bytes.len() == 32)
    });
    let (Some(challenge), Some("S256")) = (
        challenge,
        parameters.get("code_challenge_method").map(String::as_str),
    ) else {
        return refuse("invalid_request");
    };
    let resource = parameters.get("resource");
    if resource.is_some_and(|resource| !client.resources.contains(resource)) {
        return refuse("invalid_target");
    }
    let Some(subject) = parameters
        .get("login_hint")
        .or(state.logged_in_subject.as_ref())
    else {
        return refuse("login_required");
    };
    let code = uuid::Uuid::new_v4().simple().to_string();
    state
        .codes
        .lock()
        .expect("the code store lock is healthy")
        .insert(
            code.clone(),
            PendingCode {
                client_id: client.id.clone(),
                redirect_uri: redirect_uri.clone(),
                code_challenge: challenge.clone(),
                subject: subject.clone(),
                scope: parameters.get("scope").cloned(),
                resource: resource.cloned(),
                nonce: parameters.get("nonce").cloned(),
                expires_at: now() + CODE_LIFETIME_SECONDS,
            },
        );
    let mut response = vec![("code", code.as_str())];
    if let Some(value) = state_parameter {
        response.push(("state", value));
    }
    response.push(("iss", state.issuer.as_str()));
    redirect_to(redirect_uri, &response)
}

/// A token endpoint refusal (RFC 6749 section 5.2). It carries only the
/// registered code, never a description that could quote a request value.
struct Refusal {
    status: StatusCode,
    code: &'static str,
}

impl Refusal {
    fn bad(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }

    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_client",
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        uncacheable(self.status, json!({ "error": self.code }))
    }
}

fn uncacheable(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn token(State(state): State<Arc<ServerState>>, headers: HeaderMap, body: Bytes) -> Response {
    match issue(&state, &headers, &body) {
        Ok(issued) => uncacheable(StatusCode::OK, issued),
        Err(refusal) => refusal.into_response(),
    }
}

fn issue(state: &ServerState, headers: &HeaderMap, body: &[u8]) -> Result<Value, Refusal> {
    let form_media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(FORM_MEDIA_TYPE));
    if !form_media_type {
        return Err(Refusal::bad("invalid_request"));
    }
    let form = single_valued(body).ok_or(Refusal::bad("invalid_request"))?;
    let client = authenticate(state, &form)?;
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => authorization_code(state, client, &form),
        Some("client_credentials") => client_credentials(state, client, &form),
        Some(TOKEN_EXCHANGE_GRANT_TYPE) => token_exchange(state, client, &form),
        Some(_) => Err(Refusal::bad("unsupported_grant_type")),
        None => Err(Refusal::bad("invalid_request")),
    }
}

/// Authenticate the client: by `private_key_jwt` when it registered a key, by
/// its identifier alone when it is public.
fn authenticate<'a>(
    state: &'a ServerState,
    form: &HashMap<String, String>,
) -> Result<&'a TestClient, Refusal> {
    let assertion = form.get("client_assertion");
    let assertion_type = form.get("client_assertion_type");
    let Some(assertion) = assertion else {
        if assertion_type.is_some() {
            return Err(Refusal::invalid_client());
        }
        let client = form
            .get("client_id")
            .and_then(|id| state.clients.get(id))
            .ok_or_else(Refusal::invalid_client)?;
        return if client.public_jwk.is_none() {
            Ok(client)
        } else {
            Err(Refusal::invalid_client())
        };
    };
    if assertion_type.map(String::as_str) != Some(CLIENT_ASSERTION_TYPE) {
        return Err(Refusal::invalid_client());
    }
    let claims = verified_compact(assertion, |header| {
        let issuer = decode_object(assertion.split('.').nth(1)?)?
            .get("iss")?
            .as_str()?
            .to_owned();
        let jwk = state.clients.get(&issuer)?.public_jwk.clone()?;
        let expected_alg = jwk.algorithm().ok()?.jwa_name();
        (header.get("alg")?.as_str()? == expected_alg
            && header.get("kid")?.as_str()? == jwk.kid.as_deref()?)
        .then_some(jwk)
    })
    .ok_or_else(Refusal::invalid_client)?;
    let client_id = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(Refusal::invalid_client)?;
    let client = state
        .clients
        .get(client_id)
        .ok_or_else(Refusal::invalid_client)?;
    let token_endpoint = state.token_endpoint();
    let audience_accepted = match claims.get("aud") {
        Some(Value::String(audience)) => *audience == token_endpoint || *audience == state.issuer,
        Some(Value::Array(audiences)) => audiences.iter().any(|audience| {
            audience.as_str() == Some(&token_endpoint) || audience.as_str() == Some(&state.issuer)
        }),
        _ => false,
    };
    let now = now();
    let timely = claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_some_and(|exp| exp > now && exp <= now + MAXIMUM_ASSERTION_LIFETIME_SECONDS);
    let jti = claims.get("jti").and_then(Value::as_str);
    if claims.get("sub").and_then(Value::as_str) != Some(client_id)
        || form.get("client_id").is_some_and(|id| id != client_id)
        || !audience_accepted
        || !timely
        || jti.is_none_or(str::is_empty)
    {
        return Err(Refusal::invalid_client());
    }
    let first_use = state
        .used_assertions
        .lock()
        .expect("the assertion store lock is healthy")
        .insert((client_id.to_owned(), jti.unwrap_or_default().to_owned()));
    if first_use {
        Ok(client)
    } else {
        Err(Refusal::invalid_client())
    }
}

/// The audience of a token for `client`: the requested resource, which the
/// client must be allowed, or else `default`.
fn audience(
    client: &TestClient,
    requested: Option<&String>,
    default: Option<String>,
) -> Result<String, Refusal> {
    match requested {
        Some(resource) if client.resources.contains(resource) => Ok(resource.clone()),
        Some(_) => Err(Refusal::bad("invalid_target")),
        None => default.ok_or(Refusal::bad("invalid_target")),
    }
}

fn issued(access_token: String, expires_at: Option<i64>, scope: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
    });
    if let Some(expires_at) = expires_at {
        body["expires_in"] = json!(expires_at - now());
    }
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

fn authorization_code(
    state: &ServerState,
    client: &TestClient,
    form: &HashMap<String, String>,
) -> Result<Value, Refusal> {
    let (Some(code), Some(redirect_uri), Some(verifier)) = (
        form.get("code"),
        form.get("redirect_uri"),
        form.get("code_verifier"),
    ) else {
        return Err(Refusal::bad("invalid_request"));
    };
    // A code is spent by its first presentation, whatever the outcome.
    let pending = state
        .codes
        .lock()
        .expect("the code store lock is healthy")
        .remove(code)
        .ok_or(Refusal::bad("invalid_grant"))?;
    let verifier_well_formed = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if pending.client_id != client.id
        || pending.expires_at <= now()
        || pending.redirect_uri != *redirect_uri
        || !verifier_well_formed
        || challenge != pending.code_challenge
    {
        return Err(Refusal::bad("invalid_grant"));
    }
    let single_resource = match client.resources.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    };
    let audience = match (form.get("resource"), &pending.resource) {
        (Some(requested), Some(authorized)) if requested != authorized => {
            return Err(Refusal::bad("invalid_target"));
        }
        (requested, authorized) => {
            audience(client, requested.or(authorized.as_ref()), single_resource)?
        }
    };
    let expires_at = now() + client.lifetime_seconds();
    let mut claims = state.access_claims(client, &pending.subject, &audience, expires_at);
    if let Some(scope) = &pending.scope {
        claims.insert("scope".to_owned(), json!(scope));
    }
    claims.insert(
        "registry_actor_kind".to_owned(),
        json!(client.actor_kind.as_str()),
    );
    let mut body = issued(
        state.sign(ACCESS_TOKEN_TYP, claims),
        Some(expires_at),
        pending.scope.as_deref(),
    );
    if pending
        .scope
        .as_deref()
        .is_some_and(|scope| scopes(scope).contains(&"openid"))
    {
        let mut id_claims = Map::new();
        id_claims.insert("iss".to_owned(), json!(state.issuer));
        id_claims.insert("sub".to_owned(), json!(pending.subject));
        id_claims.insert("aud".to_owned(), json!(client.id));
        id_claims.insert("azp".to_owned(), json!(client.id));
        id_claims.insert("exp".to_owned(), json!(expires_at));
        id_claims.insert("iat".to_owned(), json!(now()));
        if let Some(nonce) = &pending.nonce {
            id_claims.insert("nonce".to_owned(), json!(nonce));
        }
        body["id_token"] = json!(state.sign("JWT", id_claims));
    }
    Ok(body)
}

fn client_credentials(
    state: &ServerState,
    client: &TestClient,
    form: &HashMap<String, String>,
) -> Result<Value, Refusal> {
    if client.public_jwk.is_none() {
        return Err(Refusal::bad("unauthorized_client"));
    }
    let audience = audience(client, form.get("resource"), Some(state.issuer.clone()))?;
    let expires_at = now() + client.lifetime_seconds();
    let mut claims = state.access_claims(client, &client.service_subject, &audience, expires_at);
    let scope = form.get("scope").filter(|scope| !scopes(scope).is_empty());
    if let Some(scope) = scope {
        claims.insert("scope".to_owned(), json!(scope));
    }
    claims.insert(
        "registry_actor_kind".to_owned(),
        json!(client.actor_kind.as_str()),
    );
    Ok(issued(
        state.sign(ACCESS_TOKEN_TYP, claims),
        Some(expires_at),
        scope.map(String::as_str),
    ))
}

fn token_exchange(
    state: &ServerState,
    client: &TestClient,
    form: &HashMap<String, String>,
) -> Result<Value, Refusal> {
    if client.public_jwk.is_none() {
        return Err(Refusal::bad("unauthorized_client"));
    }
    let (Some(subject_token), Some(ACCESS_TOKEN_TYPE)) = (
        form.get("subject_token"),
        form.get("subject_token_type").map(String::as_str),
    ) else {
        return Err(Refusal::bad("invalid_request"));
    };
    if form
        .get("requested_token_type")
        .is_some_and(|requested| requested != ACCESS_TOKEN_TYPE)
    {
        return Err(Refusal::bad("invalid_request"));
    }
    // RFC 8693 section 2.1: `actor_token_type` is present exactly when
    // `actor_token` is.
    let actor = match (
        form.get("actor_token"),
        form.get("actor_token_type").map(String::as_str),
    ) {
        (None, None) => None,
        (Some(actor), Some(ACCESS_TOKEN_TYPE)) => Some(actor),
        _ => return Err(Refusal::bad("invalid_request")),
    };
    let resource = form
        .get("resource")
        .ok_or(Refusal::bad("invalid_request"))?;
    let subject = state
        .verified_access_token(subject_token)
        .ok_or(Refusal::bad("invalid_grant"))?;
    // The actor token must be the exchanging client's own `client_credentials`
    // token: issued to it, naming its service subject.
    let actor_subject = match actor {
        None => None,
        Some(actor) => {
            let actor = state
                .verified_access_token(actor)
                .ok_or(Refusal::bad("invalid_grant"))?;
            let own = actor.get("client_id").and_then(Value::as_str) == Some(client.id.as_str())
                && actor.get("sub").and_then(Value::as_str)
                    == Some(client.service_subject.as_str());
            if !own {
                return Err(Refusal::bad("invalid_grant"));
            }
            Some(client.service_subject.clone())
        }
    };
    let audience = audience(client, Some(resource), None)?;
    let subject_scope = subject
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope = match form.get("scope") {
        Some(requested) => {
            let granted = scopes(subject_scope);
            if !scopes(requested)
                .iter()
                .all(|scope| granted.contains(scope))
            {
                return Err(Refusal::bad("invalid_scope"));
            }
            requested.as_str()
        }
        None => subject_scope,
    };
    let scope = (!scopes(scope).is_empty()).then_some(scope);
    let subject_expiry = subject
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Refusal::bad("invalid_grant"))?;
    let expires_at = subject_expiry.min(now() + client.lifetime_seconds());
    let subject_sub = subject
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(Refusal::bad("invalid_grant"))?;
    let mut claims = state.access_claims(client, subject_sub, &audience, expires_at);
    if let Some(scope) = scope {
        claims.insert("scope".to_owned(), json!(scope));
    }
    match state.profile {
        ExchangeProfile::Conformant => {
            claims.insert(
                "registry_actor_kind".to_owned(),
                json!(client.actor_kind.as_str()),
            );
            if let Some(actor) = actor_subject {
                claims.insert("act".to_owned(), json!({ "sub": actor }));
            }
        }
        ExchangeProfile::IssuerQualifiedActor => {
            if let Some(kind) = subject.get("registry_actor_kind") {
                claims.insert("registry_actor_kind".to_owned(), kind.clone());
            }
            if let Some(actor) = actor_subject {
                claims.insert(
                    "act".to_owned(),
                    json!({ "sub": actor, "iss": state.issuer }),
                );
            }
        }
    }
    let mut body = issued(
        state.sign(ACCESS_TOKEN_TYP, claims),
        Some(expires_at),
        scope,
    );
    body["issued_token_type"] = json!(ACCESS_TOKEN_TYPE);
    Ok(body)
}
