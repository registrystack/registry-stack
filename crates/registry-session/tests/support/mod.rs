// SPDX-License-Identifier: Apache-2.0
//! A session service wired to an in-process OpenID provider, driven over
//! loopback HTTP the way a browser and a gateway would drive it.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_crypto::PrivateJwk;
use registry_platform_testing::fixtures;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

pub const PERSON_AUDIENCE: &str = "https://api.example/person";
pub const CASEWORK_AUDIENCE: &str = "https://casework.example/api";
pub const DOCUMENTS_AUDIENCE: &str = "https://documents.example/api";
pub const CITIZEN_CLIENT: &str = "citizen-app";
pub const STAFF_CLIENT: &str = "staff-app";

/// A random value for a test to use as a secret, never printed.
pub fn random(bytes: usize) -> String {
    registry_platform_crypto::random_base64url(bytes).expect("random")
}

fn unix_now() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    i64::try_from(seconds).expect("fits")
}

fn form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn oauth_error(code: &str) -> Response {
    json_response(StatusCode::BAD_REQUEST, &json!({ "error": code }))
}

struct Code {
    client: String,
    subject: String,
    nonce: String,
    challenge: String,
    resource: String,
    redirect_uri: String,
}

struct RefreshRecord {
    family: u64,
    client: String,
    resource: String,
    subject: String,
    used: bool,
}

#[derive(Default)]
struct Inner {
    codes: HashMap<String, Code>,
    refresh: HashMap<String, RefreshRecord>,
    revoked_families: HashSet<u64>,
    /// Every refresh token issued, in order, with its client.
    issued: Vec<(String, String)>,
    next_family: u64,
    authorize_log: Vec<HashMap<String, String>>,
    end_session_visits: Vec<Vec<String>>,
}

struct Shared {
    origin: String,
    redirect_uri: String,
    key: PrivateJwk,
    client_secrets: HashMap<String, String>,
    inner: Mutex<Inner>,
    authorize_calls: AtomicU64,
    token_calls: AtomicU64,
    refresh_calls: AtomicU64,
    revoke_calls: AtomicU64,
    /// The lifetime in seconds of the next access tokens.
    access_lifetime: AtomicU64,
    omit_refresh_token: AtomicBool,
}

/// An OpenID provider that behaves like the real one where it matters:
/// single-use codes, PKCE, one audience per access token chosen by
/// `resource`, rotating refresh tokens whose reuse revokes the family.
#[derive(Clone)]
pub struct FakeIssuer {
    shared: Arc<Shared>,
}

impl FakeIssuer {
    pub async fn start(redirect_uri: &str, client_secrets: &[(&str, &str)]) -> Self {
        let (key, _) = fixtures::ed25519_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let shared = Arc::new(Shared {
            origin,
            redirect_uri: redirect_uri.to_owned(),
            key,
            client_secrets: client_secrets
                .iter()
                .map(|(id, secret)| ((*id).to_owned(), (*secret).to_owned()))
                .collect(),
            inner: Mutex::new(Inner::default()),
            authorize_calls: AtomicU64::new(0),
            token_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            revoke_calls: AtomicU64::new(0),
            access_lifetime: AtomicU64::new(600),
            omit_refresh_token: AtomicBool::new(false),
        });
        let app = Router::new()
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/jwks", get(jwks))
            .route("/logout", get(logout))
            .with_state(shared.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("issuer serves");
        });
        Self { shared }
    }

    pub fn origin(&self) -> &str {
        &self.shared.origin
    }

    pub fn authorize_calls(&self) -> u64 {
        self.shared.authorize_calls.load(Ordering::Acquire)
    }

    pub fn token_calls(&self) -> u64 {
        self.shared.token_calls.load(Ordering::Acquire)
    }

    pub fn refresh_calls(&self) -> u64 {
        self.shared.refresh_calls.load(Ordering::Acquire)
    }

    pub fn revoke_calls(&self) -> u64 {
        self.shared.revoke_calls.load(Ordering::Acquire)
    }

    pub fn set_access_lifetime(&self, seconds: u64) {
        self.shared
            .access_lifetime
            .store(seconds, Ordering::Release);
    }

    pub fn omit_refresh_tokens(&self, omit: bool) {
        self.shared
            .omit_refresh_token
            .store(omit, Ordering::Release);
    }

    /// The query parameters of each authorization request, in order.
    pub fn authorize_log(&self) -> Vec<HashMap<String, String>> {
        self.shared
            .inner
            .lock()
            .expect("lock")
            .authorize_log
            .clone()
    }

    /// The query parameter names of each visit to the end-session endpoint.
    pub fn end_session_visits(&self) -> Vec<Vec<String>> {
        self.shared
            .inner
            .lock()
            .expect("lock")
            .end_session_visits
            .clone()
    }

    /// How many refresh token families are live.
    pub fn live_families(&self) -> usize {
        let inner = self.shared.inner.lock().expect("lock");
        let families: HashSet<u64> = inner.refresh.values().map(|record| record.family).collect();
        families.difference(&inner.revoked_families).count()
    }

    /// Every refresh token issued so far, oldest first, with its client.
    pub fn issued_refresh_tokens(&self) -> Vec<(String, String)> {
        self.shared.inner.lock().expect("lock").issued.clone()
    }

    /// The status a refresh request with `token` for `client` gets, as a copy
    /// of the token in another hand would see it.
    pub async fn try_refresh(&self, client: &str, token: &str) -> StatusCode {
        let secret = self.shared.client_secrets.get(client).expect("client");
        let response = reqwest::Client::new()
            .post(format!("{}/token", self.shared.origin))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", client),
                ("client_secret", secret),
            ])
            .send()
            .await
            .expect("token request");
        StatusCode::from_u16(response.status().as_u16()).expect("status")
    }
}

fn issuer_error_redirect(shared: &Shared, redirect_uri: &str, state: &str, code: &str) -> Response {
    let mut location = url::Url::parse(redirect_uri).expect("redirect uri");
    location
        .query_pairs_mut()
        .append_pair("error", code)
        .append_pair("state", state)
        .append_pair("iss", &shared.origin);
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, location.to_string())],
    )
        .into_response()
}

async fn authorize(State(shared): State<Arc<Shared>>, RawQuery(query): RawQuery) -> Response {
    shared.authorize_calls.fetch_add(1, Ordering::AcqRel);
    let pairs: HashMap<String, String> = query
        .as_deref()
        .map(|query| form(query.as_bytes()))
        .unwrap_or_default();
    shared
        .inner
        .lock()
        .expect("lock")
        .authorize_log
        .push(pairs.clone());
    let get = |name: &str| pairs.get(name).map(String::as_str).unwrap_or_default();
    let client = get("client_id");
    let valid = shared.client_secrets.contains_key(client)
        && get("response_type") == "code"
        && get("redirect_uri") == shared.redirect_uri
        && get("code_challenge_method") == "S256"
        && !get("code_challenge").is_empty()
        && !get("state").is_empty()
        && !get("nonce").is_empty()
        && get("scope").split(' ').any(|scope| scope == "openid")
        && !pairs.contains_key("prompt");
    if !valid {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    let resource = get("resource");
    if url::Url::parse(resource).is_err() {
        return issuer_error_redirect(&shared, get("redirect_uri"), get("state"), "invalid_target");
    }
    let code = random(24);
    let subject = pairs
        .get("login_hint")
        .cloned()
        .unwrap_or_else(|| "citizen-a".to_owned());
    shared.inner.lock().expect("lock").codes.insert(
        code.clone(),
        Code {
            client: client.to_owned(),
            subject,
            nonce: get("nonce").to_owned(),
            challenge: get("code_challenge").to_owned(),
            resource: resource.to_owned(),
            redirect_uri: get("redirect_uri").to_owned(),
        },
    );
    let mut location = url::Url::parse(get("redirect_uri")).expect("redirect uri");
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", get("state"))
        .append_pair("iss", &shared.origin);
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, location.to_string())],
    )
        .into_response()
}

fn access_token(shared: &Shared, client: &str, subject: &str, resource: &str) -> String {
    let now = unix_now();
    let lifetime = i64::try_from(shared.access_lifetime.load(Ordering::Acquire)).expect("fits");
    registry_platform_testing::sign_ed25519_compact_jwt_with_key(
        &shared.key,
        "at+jwt",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": shared.origin,
            "sub": subject,
            "aud": resource,
            "client_id": client,
            "iat": now,
            "exp": now + lifetime,
            "jti": random(16),
        }),
    )
}

fn id_token(shared: &Shared, client: &str, subject: &str, nonce: &str) -> String {
    let now = unix_now();
    registry_platform_testing::sign_ed25519_compact_jwt_with_key(
        &shared.key,
        "JWT",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": shared.origin,
            "sub": subject,
            "aud": client,
            "azp": client,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "name": format!("Name of {subject}"),
            "email": format!("{subject}@example.org"),
            "email_verified": true,
        }),
    )
}

fn authenticated(shared: &Shared, form: &HashMap<String, String>) -> Option<String> {
    let client = form.get("client_id")?;
    let secret = shared.client_secrets.get(client)?;
    (form.get("client_secret") == Some(secret)).then(|| client.clone())
}

fn issue_refresh(
    shared: &Shared,
    inner: &mut Inner,
    family: u64,
    client: &str,
    resource: &str,
    subject: &str,
) -> Option<String> {
    if shared.omit_refresh_token.load(Ordering::Acquire) {
        return None;
    }
    let token = random(32);
    inner.refresh.insert(
        token.clone(),
        RefreshRecord {
            family,
            client: client.to_owned(),
            resource: resource.to_owned(),
            subject: subject.to_owned(),
            used: false,
        },
    );
    inner.issued.push((client.to_owned(), token.clone()));
    Some(token)
}

async fn token(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    shared.token_calls.fetch_add(1, Ordering::AcqRel);
    let form = form(&body);
    let Some(client) = authenticated(&shared, &form) else {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "invalid_client" }),
        );
    };
    let lifetime = shared.access_lifetime.load(Ordering::Acquire);
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let mut inner = shared.inner.lock().expect("lock");
            let Some(code) = form.get("code").and_then(|code| inner.codes.remove(code)) else {
                return oauth_error("invalid_grant");
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let resource = form.get("resource").cloned().unwrap_or_default();
            if code.client != client
                || challenge != code.challenge
                || form.get("redirect_uri") != Some(&code.redirect_uri)
                || resource != code.resource
            {
                return oauth_error("invalid_grant");
            }
            let family = inner.next_family;
            inner.next_family += 1;
            let refresh = issue_refresh(
                &shared,
                &mut inner,
                family,
                &client,
                &resource,
                &code.subject,
            );
            let mut answer = json!({
                "access_token": access_token(&shared, &client, &code.subject, &resource),
                "token_type": "Bearer",
                "expires_in": lifetime,
                "id_token": id_token(&shared, &client, &code.subject, &code.nonce),
            });
            if let Some(refresh) = refresh {
                answer["refresh_token"] = json!(refresh);
            }
            json_response(StatusCode::OK, &answer)
        }
        Some("refresh_token") => {
            shared.refresh_calls.fetch_add(1, Ordering::AcqRel);
            let mut inner = shared.inner.lock().expect("lock");
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            let Some(record) = inner.refresh.get_mut(&presented) else {
                return oauth_error("invalid_grant");
            };
            let (family, reused) = (record.family, record.used);
            if record.client != client || inner.revoked_families.contains(&family) {
                return oauth_error("invalid_grant");
            }
            if reused {
                inner.revoked_families.insert(family);
                return oauth_error("invalid_grant");
            }
            let record = inner.refresh.get_mut(&presented).expect("present");
            record.used = true;
            let resource = form
                .get("resource")
                .cloned()
                .unwrap_or_else(|| record.resource.clone());
            let subject = record.subject.clone();
            let refresh = issue_refresh(&shared, &mut inner, family, &client, &resource, &subject);
            let mut answer = json!({
                "access_token": access_token(&shared, &client, &subject, &resource),
                "token_type": "Bearer",
                "expires_in": lifetime,
            });
            if let Some(refresh) = refresh {
                answer["refresh_token"] = json!(refresh);
            }
            json_response(StatusCode::OK, &answer)
        }
        _ => oauth_error("unsupported_grant_type"),
    }
}

async fn revoke(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    shared.revoke_calls.fetch_add(1, Ordering::AcqRel);
    let form = form(&body);
    if authenticated(&shared, &form).is_none() {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "invalid_client" }),
        );
    }
    let mut inner = shared.inner.lock().expect("lock");
    let family = form
        .get("token")
        .and_then(|token| inner.refresh.get(token))
        .map(|record| record.family);
    if let Some(family) = family {
        inner.revoked_families.insert(family);
    }
    StatusCode::OK.into_response()
}

async fn jwks(State(shared): State<Arc<Shared>>) -> Response {
    json_response(
        StatusCode::OK,
        &registry_platform_testing::jwks_from_private_jwk(&shared.key),
    )
}

async fn logout(State(shared): State<Arc<Shared>>, RawQuery(query): RawQuery) -> Response {
    let names = query
        .as_deref()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, _)| name.into_owned())
                .collect()
        })
        .unwrap_or_default();
    shared
        .inner
        .lock()
        .expect("lock")
        .end_session_visits
        .push(names);
    (StatusCode::OK, "signed out at the issuer").into_response()
}

/// The `aud` of a compact JWT, without verifying it.
pub fn audience_of(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("a JWT payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["aud"].as_str().expect("aud").to_owned()
}

/// Write a secret file the way the runtime requires: owner-only.
pub fn write_secret(directory: &Path, name: &str, value: &[u8]) {
    let path = directory.join(name);
    std::fs::write(&path, value).expect("write secret");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("permissions");
}

/// An audit destination a test controls: it keeps every line the service
/// writes and refuses every write once its budget of accepted writes is spent.
#[derive(Clone, Default)]
pub struct AuditSink {
    lines: Arc<Mutex<Vec<u8>>>,
    budget: Arc<Mutex<Option<u64>>>,
}

impl AuditSink {
    /// Accept `writes` more writes, then refuse every later one.
    pub fn fail_after(&self, writes: u64) {
        *self.budget.lock().expect("lock") = Some(writes);
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.lines.lock().expect("lock").clone()).expect("utf-8")
    }
}

impl std::io::Write for AuditSink {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut budget = self.budget.lock().expect("lock");
        match budget.as_mut() {
            Some(0) => return Err(std::io::Error::other("the test audit sink refuses")),
            Some(remaining) => *remaining -= 1,
            None => {}
        }
        self.lines.lock().expect("lock").extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Options {
    /// Rewrites the runtime document before it is written.
    pub edit: Box<dyn Fn(String) -> String>,
    pub audit_sink: Option<AuditSink>,
    /// Appended to the runtime document, such as a `rateLimits` block.
    pub extra_document: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            edit: Box::new(|document| document),
            audit_sink: None,
            extra_document: String::new(),
        }
    }
}

/// A response as a browser or the gateway sees it.
pub struct Page {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Page {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub fn location(&self) -> &str {
        self.header("location").expect("a location header")
    }

    /// The `name=value` pair of the cookie this response sets under `name`.
    pub fn cookie_pair(&self, name: &str) -> Option<String> {
        self.set_cookie(name)
            .map(|value| value.split(';').next().expect("pair").to_owned())
    }

    /// The whole `Set-Cookie` value for the cookie `name`.
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(str::to_owned)
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("a JSON body")
    }

    /// The path the continue page moves the browser to.
    pub fn continue_path(&self) -> Option<String> {
        let marker = "url=";
        let start = self.body.find(marker)? + marker.len();
        let end = self.body[start..].find('"')? + start;
        Some(self.body[start..end].replace("&amp;", "&"))
    }

    /// The session's own answer marker.
    pub fn marked(&self) -> bool {
        self.header("registry-session-answer") == Some("1")
    }
}

pub fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

pub async fn page(response: reqwest::Response) -> Page {
    let status = StatusCode::from_u16(response.status().as_u16()).expect("status");
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers() {
        headers.append(
            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()).expect("name"),
            axum::http::HeaderValue::from_bytes(value.as_bytes()).expect("value"),
        );
    }
    let body = response.text().await.expect("body");
    Page {
        status,
        headers,
        body,
    }
}

pub const SESSION_COOKIE: &str = registry_session::config::DEVELOPMENT_SESSION_COOKIE;
pub const FLOW_COOKIE: &str = registry_session::config::DEVELOPMENT_FLOW_COOKIE;

/// How a sign-in ended.
pub struct SignedIn {
    /// The `name=value` pair of the session cookie.
    pub cookie: String,
    /// The final response, the continue page.
    pub page: Page,
    /// How many times the browser visited the authorization endpoint.
    pub hops: usize,
}

/// A running service and the browser that drives it.
pub struct Harness {
    pub issuer: FakeIssuer,
    pub public: String,
    pub check: String,
    pub http: reqwest::Client,
    pub directory: TempDir,
    pub audit_path: PathBuf,
    pub citizen_secret: String,
    pub staff_secret: String,
}

fn document(
    public: std::net::SocketAddr,
    check: std::net::SocketAddr,
    issuer: &str,
    secrets: &Path,
    audit: &Path,
) -> String {
    format!(
        "apiVersion: id.registrystack.org/formats/platform/session-runtime/v1alpha1\n\
kind: PlatformSessionRuntimeConfig\n\
listener:\n  bind: \"{public}\"\n  tlsTermination: development-loopback\n\
checkListener: \"{check}\"\n\
publicOrigin: http://{public}\n\
secretProviders:\n  file:\n    root: {secrets}\n\
issuer:\n  id: {issuer}\n  authorization: {issuer}/authorize\n  endSession: {issuer}/logout\n  token: {issuer}/token\n  revocation: {issuer}/revoke\n  jwks: {issuer}/jwks\n\
personAudience: {PERSON_AUDIENCE}\n\
modules:\n\
\x20 - id: breg\n    prefix: /api/registry/\n    audience: person\n\
\x20 - id: documents\n    prefix: /api/documents/\n    audience: person\n\
\x20 - id: casework\n    prefix: /api/casework/\n    audience: {CASEWORK_AUDIENCE}\n    signIns: [staff]\n\
pages:\n  - prefix: /apply/\n    signIn: citizen\n  - prefix: /staff/\n    signIn: staff\n\
signIns:\n\
\x20 citizen:\n    clientId: {CITIZEN_CLIENT}\n    clientSecretRef: secret:file/citizen-secret\n    scopes: [registry:read]\n\
\x20 staff:\n    clientId: {STAFF_CLIENT}\n    clientSecretRef: secret:file/staff-secret\n    scopes: [registry:read, casework:work]\n\
audit:\n  hashKeyRef: secret:file/audit-key\n  path: {audit}\n",
        secrets = secrets.display(),
        audit = audit.display(),
    )
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Self {
        let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let check_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let public_address = public_listener.local_addr().expect("address");
        let check_address = check_listener.local_addr().expect("address");
        let public = format!("http://{public_address}");
        let citizen_secret = random(24);
        let staff_secret = random(24);
        let issuer = FakeIssuer::start(
            &format!("{public}/session/callback"),
            &[
                (CITIZEN_CLIENT, &citizen_secret),
                (STAFF_CLIENT, &staff_secret),
            ],
        )
        .await;

        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().canonicalize().expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let secrets = root.join("secrets");
        std::fs::create_dir(&secrets).expect("secrets directory");
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).expect("mode");
        write_secret(&secrets, "citizen-secret", citizen_secret.as_bytes());
        write_secret(&secrets, "staff-secret", staff_secret.as_bytes());
        write_secret(&secrets, "audit-key", &[0x5a; 32]);
        let audit_directory = root.join("audit");
        std::fs::create_dir(&audit_directory).expect("audit directory");
        std::fs::set_permissions(&audit_directory, std::fs::Permissions::from_mode(0o700))
            .expect("mode");
        let audit_path = audit_directory.join("audit.jsonl");
        let text = document(
            public_address,
            check_address,
            issuer.origin(),
            &secrets,
            &audit_path,
        );
        let text = format!("{}{}", (options.edit)(text), options.extra_document);
        let config_path = root.join("runtime.yaml");
        std::fs::write(&config_path, text).expect("write document");

        let config =
            registry_session::config::RuntimeConfig::load(&config_path).expect("document loads");
        let writer = options.audit_sink.map(|sink| {
            registry_platform_audit::AuditWriter::from_line_sink_without_posture(Box::new(sink))
        });
        let service = registry_session::runtime::Service::build(config, writer)
            .await
            .expect("service starts");
        tokio::spawn(registry_session::runtime::serve_until(
            public_listener,
            service.public,
            std::future::pending(),
        ));
        tokio::spawn(registry_session::runtime::serve_until(
            check_listener,
            service.check,
            std::future::pending(),
        ));
        Self {
            issuer,
            public,
            check: format!("http://{check_address}"),
            http: browser(),
            directory,
            audit_path,
            citizen_secret,
            staff_secret,
        }
    }

    pub async fn get(&self, path: &str, cookie: Option<&str>) -> Page {
        let mut request = self.http.get(format!("{}{path}", self.public));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        page(request.send().await.expect("response")).await
    }

    /// A sign-out request with the headers of `extra`.
    pub async fn sign_out(&self, cookie: Option<&str>, extra: &[(&str, &str)]) -> Page {
        let mut request = self.http.post(format!("{}/session/sign-out", self.public));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        page(request.send().await.expect("response")).await
    }

    /// What the gateway's call to the check listener gets back for a request
    /// to `path` with the browser's `cookie`.
    pub async fn check(&self, method: &str, path: &str, cookie: Option<&str>) -> Page {
        let mut request = self.http.request(
            reqwest::Method::from_bytes(method.as_bytes()).expect("method"),
            format!("{}/check{path}", self.check),
        );
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        page(request.send().await.expect("response")).await
    }

    /// Start a sign-in for `return_to` and return the response.
    pub async fn start_sign_in(&self, return_to: &str) -> Page {
        self.get(
            &format!(
                "/session/sign-in?return={}",
                url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
            ),
            None,
        )
        .await
    }

    /// Follow one authorization redirect as the person `subject`: visit the
    /// authorization endpoint and return its redirect back to the service.
    pub async fn authorize_as(&self, location: &str, subject: &str) -> String {
        let response = self
            .http
            .get(format!("{location}&login_hint={subject}"))
            .send()
            .await
            .expect("authorization response");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        response
            .headers()
            .get("location")
            .expect("location")
            .to_str()
            .expect("ascii")
            .to_owned()
    }

    pub async fn callback(&self, callback_url: &str, flow_cookie: Option<&str>) -> Page {
        let mut request = self.http.get(callback_url);
        if let Some(cookie) = flow_cookie {
            request = request.header("cookie", cookie);
        }
        page(request.send().await.expect("response")).await
    }

    /// Sign `subject` in for `return_to` through every redirect the service
    /// asks for.
    pub async fn sign_in(&self, return_to: &str, subject: &str) -> SignedIn {
        self.sign_in_as(return_to, &[subject]).await
    }

    /// Sign in with a different subject at each hop, in order; the last
    /// subject repeats for any further hop.
    pub async fn sign_in_as(&self, return_to: &str, subjects: &[&str]) -> SignedIn {
        let mut response = self.start_sign_in(return_to).await;
        let mut hops = 0;
        loop {
            assert_eq!(response.status, StatusCode::FOUND, "{}", response.body);
            let flow = response.cookie_pair(FLOW_COOKIE).expect("a flow cookie");
            let subject = subjects[hops.min(subjects.len() - 1)];
            hops += 1;
            let callback = self.authorize_as(response.location(), subject).await;
            response = self.callback(&callback, Some(&flow)).await;
            if response.status == StatusCode::OK {
                let cookie = response
                    .cookie_pair(SESSION_COOKIE)
                    .expect("the callback sets a session cookie");
                return SignedIn {
                    cookie,
                    page: response,
                    hops,
                };
            }
            assert!(hops < 8, "too many hops: {}", response.status);
        }
    }

    /// One sign-in attempt through the first hop only, returning the
    /// callback's response, which is the final one when the first hop is also
    /// the last or when it fails.
    pub async fn sign_in_attempt(&self, return_to: &str, subject: &str) -> Page {
        let start = self.start_sign_in(return_to).await;
        assert_eq!(start.status, StatusCode::FOUND, "{}", start.body);
        let flow = start.cookie_pair(FLOW_COOKIE).expect("a flow cookie");
        let callback = self.authorize_as(start.location(), subject).await;
        self.callback(&callback, Some(&flow)).await
    }

    pub fn audit_text(&self) -> String {
        let directory = self.audit_path.parent().expect("directory");
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .expect("read directory")
            .map(|entry| entry.expect("entry").path())
            .collect();
        entries.sort();
        entries
            .into_iter()
            .filter(|path| path.is_file())
            .map(|path| std::fs::read_to_string(path).expect("read audit"))
            .collect()
    }
}
