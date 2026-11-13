// SPDX-License-Identifier: Apache-2.0
//! Browser authorization for one synthetic development run.

use anyhow::{ensure, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, Weak,
    },
    thread,
    time::Duration,
};
use url::{form_urlencoded, Url};
use zeroize::Zeroizing;

use super::{
    clock,
    issuer::{Issuer, BROWSER_TOKEN_LIFETIME_SECONDS},
    plan::Product,
    RunInput,
};

const FORM_LIMIT: usize = 16 * 1024;
const MAXIMUM_PENDING: usize = 256;
const REQUEST_LIFETIME: u64 = 300;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

pub(super) struct BrowserClient {
    pub(super) id: String,
    pub(super) secret: Zeroizing<String>,
    pub(super) redirect_uri: String,
}

struct Session {
    person: String,
    expires: u64,
}

struct Pending {
    authorization: Authorization,
    expires: u64,
}

struct Code {
    authorization: Authorization,
    person: String,
    expires: u64,
}

struct BrowserState {
    input: Arc<RunInput>,
    issuer: Weak<Issuer>,
    origin: String,
    cookie_name: String,
    client: BrowserClient,
    audiences: BTreeMap<String, Product>,
    jwks: Value,
    expires: Arc<AtomicU64>,
    sessions: Mutex<BTreeMap<String, Session>>,
    pending: Mutex<BTreeMap<String, Pending>>,
    codes: Mutex<BTreeMap<String, Code>>,
}

pub(super) struct BrowserServer {
    pub(super) origin: String,
    alive: Arc<AtomicBool>,
    expires: Arc<AtomicU64>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    _issuer: Arc<Issuer>,
}

struct MarkStopped(Arc<AtomicBool>);

impl Drop for MarkStopped {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for BrowserServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl BrowserServer {
    pub(super) fn alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Permit browser grants only after the application has become ready.
    pub(super) fn activate(&self, expires_at: u64) {
        self.expires.store(expires_at, Ordering::Release);
    }

    pub(super) fn start(
        listener: TcpListener,
        input: Arc<RunInput>,
        issuer: Arc<Issuer>,
        client: BrowserClient,
    ) -> Result<Self> {
        listener.set_nonblocking(true)?;
        ensure!(
            listener.local_addr()?.ip().is_loopback() && listener.local_addr()?.is_ipv4(),
            "browser issuer must bind IPv4 loopback"
        );
        let origin = format!("http://{}", listener.local_addr()?);
        ensure!(
            origin == input.plan.issuer,
            "run issuer URL does not match the bound listener"
        );
        ensure!(
            input.run_id.len() == 32 && input.run_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid development run ID"
        );
        validate_client(&client.id, &client.secret, &client.redirect_uri)?;
        let audiences = input
            .plan
            .products
            .iter()
            .map(|entry| (entry.audience.clone(), entry.product))
            .collect();
        let expires = Arc::new(AtomicU64::new(0));
        let state = Arc::new(BrowserState {
            cookie_name: cookie_name(&input.run_id),
            input,
            issuer: Arc::downgrade(&issuer),
            origin: origin.clone(),
            client,
            audiences,
            jwks: issuer.public_jwks(),
            expires: expires.clone(),
            sessions: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            codes: Mutex::new(BTreeMap::new()),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize).post(select_person))
            .route("/token", axum::routing::post(token))
            .route("/logout", get(logout))
            .layer(DefaultBodyLimit::max(FORM_LIMIT))
            .with_state(state);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let alive = Arc::new(AtomicBool::new(true));
        let thread_alive = alive.clone();
        let thread = thread::Builder::new()
            .name("rstack-dev-browser-issuer".to_owned())
            .spawn(move || {
                let _stopped = MarkStopped(thread_alive);
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match tokio::net::TcpListener::from_std(listener) {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(())).is_err() {
                        return;
                    }
                    let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
                    let server = async move {
                        if let Err(error) = axum::serve(listener, app)
                            .with_graceful_shutdown(async move {
                                let _ = drain_rx.await;
                            })
                            .await
                        {
                            eprintln!("development browser issuer stopped: {error}");
                        }
                    };
                    tokio::pin!(server);
                    tokio::select! {
                        () = &mut server => return,
                        _ = shutdown_rx => {}
                    }
                    let _ = drain_tx.send(());
                    let _ = tokio::time::timeout(SHUTDOWN_GRACE, server).await;
                });
                runtime.shutdown_timeout(SHUTDOWN_GRACE);
            })?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = thread.join();
                anyhow::bail!("cannot start development browser issuer: {error}");
            }
            Err(error) => {
                let _ = shutdown_tx.send(());
                let _ = thread.join();
                anyhow::bail!("development browser issuer did not initialize: {error}");
            }
        }
        Ok(Self {
            origin,
            alive,
            expires,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            _issuer: issuer,
        })
    }
}

fn validate_client(id: &str, secret: &str, redirect_uri: &str) -> Result<()> {
    ensure!(
        (1..=256).contains(&id.len())
            && !id.chars().any(char::is_whitespace)
            && !id.chars().any(char::is_control),
        "invalid browser client ID"
    );
    ensure!(
        (32..=4096).contains(&secret.len()) && !secret.chars().any(char::is_control),
        "invalid browser client credential"
    );
    let redirect = Url::parse(redirect_uri)?;
    ensure!(
        redirect.scheme() == "http"
            && redirect.host_str() == Some("127.0.0.1")
            && redirect.port().is_some()
            && redirect.username().is_empty()
            && redirect.password().is_none()
            && redirect.path().starts_with('/')
            && redirect.path().len() <= 256
            && redirect.query().is_none()
            && redirect.fragment().is_none(),
        "browser callback must be an exact loopback URI"
    );
    Ok(())
}

async fn discovery(State(state): State<Arc<BrowserState>>) -> impl IntoResponse {
    let origin = &state.origin;
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "issuer": origin,
            "authorization_endpoint": format!("{origin}/authorize"),
            "token_endpoint": format!("{origin}/token"),
            "jwks_uri": format!("{origin}/jwks"),
            "end_session_endpoint": format!("{origin}/logout"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
        })),
    )
}

async fn jwks(State(state): State<Arc<BrowserState>>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(state.jwks.clone()),
    )
}

async fn authorize(
    State(state): State<Arc<BrowserState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(query) = query else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(authorization) = parse_authorization(
        &query,
        &state.client.id,
        &state.client.redirect_uri,
        &state.audiences,
    ) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(now) = clock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    if now >= state.expires.load(Ordering::Acquire) {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    if !authorization.fresh {
        if let Some(session_id) = session_cookie(&headers, &state.cookie_name) {
            let person = match state.sessions.lock() {
                Ok(sessions) => sessions
                    .get(&session_id)
                    .filter(|session| session.expires > now)
                    .map(|session| session.person.clone()),
                Err(_) => {
                    return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
                }
            };
            if let Some(person) = person {
                if person_can_use(&state, &person, &authorization) {
                    return issue_code(&state, authorization, person, now, None);
                }
            }
        }
    }
    let choices = state.input.plan.people.iter()
        .filter(|(name, _)| person_can_use(&state, name, &authorization))
        .map(|(name, person)| format!("<label><input type=\"radio\" name=\"identity\" value=\"{}\" required> {}</label><br>", escape_html(name), escape_html(person.display_name.as_deref().unwrap_or(name))))
        .collect::<String>();
    if choices.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "access_denied");
    }
    let Ok(transaction) = random_id() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Ok(mut pending) = state.pending.lock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    pending.retain(|_, item| item.expires > now);
    if pending.len() >= MAXIMUM_PENDING {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    pending.insert(
        transaction.clone(),
        Pending {
            authorization: authorization.clone(),
            expires: now + REQUEST_LIFETIME,
        },
    );
    drop(pending);
    let page = format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Choose a test person</title><h1>Choose a test person</h1><p>Synthetic development identities only.</p><form method=\"post\" action=\"/authorize\"><input type=\"hidden\" name=\"transaction\" value=\"{}\">{}<button type=\"submit\">Sign in</button></form></html>", escape_html(&transaction), choices);
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(page),
    )
        .into_response()
}

async fn select_person(
    State(state): State<Arc<BrowserState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(form) = parse_form(text) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if form.len() != 2 {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let (Some(transaction), Some(person)) = (form.get("transaction"), form.get("identity")) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(now) = clock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let pending = match state.pending.lock() {
        Ok(mut pending) => pending.remove(transaction),
        Err(_) => return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    let expires = state.expires.load(Ordering::Acquire);
    let Some(pending) = pending.filter(|pending| pending.expires > now && expires > now) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !person_can_use(&state, person, &pending.authorization) {
        return oauth_error(StatusCode::FORBIDDEN, "access_denied");
    }
    let Ok(session_id) = random_id() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Ok(mut sessions) = state.sessions.lock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    sessions.retain(|_, session| session.expires > now);
    if let Some(previous) = session_cookie(&headers, &state.cookie_name) {
        sessions.remove(&previous);
    }
    if sessions.len() >= MAXIMUM_PENDING {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    sessions.insert(
        session_id.clone(),
        Session {
            person: person.clone(),
            expires,
        },
    );
    drop(sessions);
    issue_code(
        &state,
        pending.authorization,
        person.clone(),
        now,
        Some(&session_id),
    )
}

fn person_can_use(state: &BrowserState, alias: &str, authorization: &Authorization) -> bool {
    granted_scopes(state, alias, authorization).is_some()
}

fn granted_scopes(
    state: &BrowserState,
    alias: &str,
    authorization: &Authorization,
) -> Option<Vec<String>> {
    state
        .input
        .plan
        .people
        .get(alias)
        .and_then(|person| person.grants.get(&authorization.product))
        .and_then(|grant| {
            let scopes: Vec<_> = authorization
                .scopes
                .iter()
                .filter(|scope| grant.scopes.contains(scope))
                .cloned()
                .collect();
            (authorization.scopes.is_empty() || !scopes.is_empty()).then_some(scopes)
        })
}

fn issue_code(
    state: &BrowserState,
    authorization: Authorization,
    person: String,
    now: u64,
    session_id: Option<&str>,
) -> Response {
    let Ok(code) = random_id() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let mut redirect = authorization.redirect.clone();
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &authorization.state);
    let Ok(mut codes) = state.codes.lock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    codes.retain(|_, item| item.expires > now);
    if codes.len() >= MAXIMUM_PENDING {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    codes.insert(
        code,
        Code {
            authorization,
            person,
            expires: now + REQUEST_LIFETIME,
        },
    );
    drop(codes);
    let mut response = (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, redirect.as_str()),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response();
    if let Some(session_id) = session_id {
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "{}={session_id}; HttpOnly; SameSite=Lax; Path=/",
            state.cookie_name
        )) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
    response
}

async fn token(
    State(state): State<Arc<BrowserState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(form) = parse_form(text) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if form.get("client_id") != Some(&state.client.id)
        || !form.get("client_secret").is_some_and(|secret| {
            constant_time_equal(secret.as_bytes(), state.client.secret.as_bytes())
        })
    {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let Some(code) = form.get("code") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(now) = clock() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let issued = match state.codes.lock() {
        Ok(mut codes) => codes.remove(code),
        Err(_) => return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    let expires = state.expires.load(Ordering::Acquire);
    let Some(issued) = issued.filter(|issued| issued.expires > now && expires > now) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    if form.get("redirect_uri").map(String::as_str) != Some(issued.authorization.redirect.as_str())
        || !form
            .get("code_verifier")
            .is_some_and(|verifier| verify_pkce(verifier, &issued.authorization.challenge))
        || !form.get("resource").is_some_and(|resource| {
            state.audiences.get(resource) == Some(&issued.authorization.product)
        })
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let Some(person) = state.input.plan.people.get(&issued.person) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let Some(scopes) = granted_scopes(&state, &issued.person, &issued.authorization) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let Some(issuer) = state.issuer.upgrade() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let access = issuer
        .sign_browser_access(
            &state.input,
            &issued.person,
            issued.authorization.product,
            &state.client.id,
            &scopes,
            expires,
        )
        .await;
    let identity = issuer
        .sign_id_token(
            &state.origin,
            &state.client.id,
            &person.subject,
            &issued.authorization.nonce,
            expires,
        )
        .await;
    let (Ok(access), Ok(identity)) = (access, identity) else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let lifetime = BROWSER_TOKEN_LIFETIME_SECONDS.min(expires.saturating_sub(now));
    let response = json!({
        "access_token": &*access, "id_token": &*identity, "token_type": "Bearer",
        "expires_in": lifetime,
        "scope": format!("openid {}", scopes.join(" ")).trim().to_owned(),
    });
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(response),
    )
        .into_response()
}

async fn logout(
    State(state): State<Arc<BrowserState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Ok(values) = parse_form(query.as_deref().unwrap_or_default()) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(redirect) = Url::parse(&state.client.redirect_uri) else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let origin = redirect.origin().ascii_serialization();
    let state_value = values.get("state");
    if values.len() != 2 + usize::from(state_value.is_some())
        || values.get("client_id") != Some(&state.client.id)
        || values.get("post_logout_redirect_uri").map(String::as_str) != Some(origin.as_str())
        || state_value.is_some_and(|value| {
            !(1..=512).contains(&value.len()) || value.chars().any(char::is_control)
        })
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut return_to) = Url::parse(&origin) else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    if let Some(value) = state_value {
        return_to.query_pairs_mut().append_pair("state", value);
    }
    if let Some(session_id) = session_cookie(&headers, &state.cookie_name) {
        let Ok(mut sessions) = state.sessions.lock() else {
            return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        };
        sessions.remove(&session_id);
    }
    let mut response = (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, return_to.to_string()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response();
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "{}=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/",
        state.cookie_name
    )) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": code})),
    )
        .into_response()
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let mut parts = value.split(';').map(str::trim);
            parts.next().is_some_and(|type_| {
                type_.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            }) && parts
                .next()
                .is_none_or(|parameter| parameter.eq_ignore_ascii_case("charset=utf-8"))
                && parts.next().is_none()
        })
}

fn cookie_name(run_id: &str) -> String {
    format!("rstack_dev_session_{run_id}")
}

fn session_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for pair in value.to_str().ok()?.split(';') {
            let Some((cookie_name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if cookie_name != name {
                continue;
            }
            if found.is_some()
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).context("cannot create development authorization state")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()).min(4096) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Clone)]
struct Authorization {
    redirect: Url,
    product: Product,
    scopes: Vec<String>,
    state: String,
    nonce: String,
    challenge: String,
    fresh: bool,
}

fn parse_form(raw: &str) -> Result<BTreeMap<String, String>> {
    ensure!(raw.len() <= FORM_LIMIT, "authorization form is too large");
    let mut values = BTreeMap::new();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        ensure!(
            !key.is_empty() && !values.contains_key(key.as_ref()),
            "duplicate or empty authorization parameter"
        );
        values.insert(key.into_owned(), value.into_owned());
    }
    Ok(values)
}

fn parse_authorization(
    query: &str,
    client_id: &str,
    redirect_uri: &str,
    audiences: &BTreeMap<String, Product>,
) -> Result<Authorization> {
    let values = parse_form(query)?;
    let required = |key: &str| -> Result<&str> {
        values
            .get(key)
            .map(String::as_str)
            .context("missing authorization parameter")
    };
    ensure!(required("client_id")? == client_id, "unregistered client");
    ensure!(
        required("redirect_uri")? == redirect_uri,
        "unregistered redirect URI"
    );
    ensure!(
        required("response_type")? == "code",
        "unsupported response type"
    );
    ensure!(
        required("code_challenge_method")? == "S256",
        "PKCE S256 is required"
    );
    let challenge = required("code_challenge")?;
    ensure!(
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "invalid PKCE challenge"
    );
    let state = required("state")?;
    let nonce = required("nonce")?;
    ensure!(
        (1..=512).contains(&state.len()) && (1..=512).contains(&nonce.len()),
        "invalid state or nonce"
    );
    let resource = required("resource")?;
    let product = *audiences.get(resource).context("unknown resource")?;
    let scopes: Vec<_> = required("scope")?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    ensure!(
        (1..=32).contains(&scopes.len()) && scopes.iter().any(|scope| scope == "openid"),
        "openid scope is required"
    );
    ensure!(
        scopes
            .iter()
            .all(|scope| !scope.chars().any(char::is_whitespace) && scope.len() <= 256),
        "invalid scope"
    );
    ensure!(
        scopes.iter().collect::<BTreeSet<_>>().len() == scopes.len(),
        "duplicate scope"
    );
    if let Some(claims) = values.get("claims") {
        let parsed: serde_json::Value =
            serde_json::from_str(claims).context("invalid claims parameter")?;
        ensure!(parsed.is_object(), "claims parameter must be an object");
    }
    let prompt = values.get("prompt").map(String::as_str);
    ensure!(
        prompt.is_none_or(|value| value == "login"),
        "unsupported prompt"
    );
    for key in values.keys() {
        ensure!(
            matches!(
                key.as_str(),
                "client_id"
                    | "redirect_uri"
                    | "response_type"
                    | "code_challenge"
                    | "code_challenge_method"
                    | "state"
                    | "nonce"
                    | "scope"
                    | "resource"
                    | "claims"
                    | "prompt"
            ),
            "unsupported authorization parameter"
        );
    }
    Ok(Authorization {
        redirect: Url::parse(redirect_uri)?,
        product,
        scopes: scopes
            .into_iter()
            .filter(|scope| scope != "openid" && scope != "profile")
            .collect(),
        state: state.to_owned(),
        nonce: nonce.to_owned(),
        challenge: challenge.to_owned(),
        fresh: prompt == Some("login"),
    })
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let actual = pkce_challenge(verifier);
    actual.len() == challenge.len()
        && actual
            .bytes()
            .zip(challenge.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn authorization_rejects_foreign_redirect_and_weak_pkce() {
        let valid = "client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256&state=state-1&nonce=nonce-1&scope=openid%20registry.read&resource=registry-service";
        let audiences = [(
            "registry-service".to_owned(),
            super::super::plan::Product::Breg,
        )]
        .into_iter()
        .collect();
        assert!(
            parse_authorization(valid, "app", "http://127.0.0.1:4000/callback", &audiences).is_ok()
        );
        assert!(parse_authorization(
            &valid.replace("4000", "4001"),
            "app",
            "http://127.0.0.1:4000/callback",
            &audiences
        )
        .is_err());
        assert!(parse_authorization(
            &valid.replace("S256", "plain"),
            "app",
            "http://127.0.0.1:4000/callback",
            &audiences
        )
        .is_err());
        assert!(parse_authorization(
            &format!("{valid}&state=duplicate"),
            "app",
            "http://127.0.0.1:4000/callback",
            &audiences
        )
        .is_err());
    }

    #[test]
    fn pkce_verifier_must_match_the_challenge() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let challenge = pkce_challenge(verifier);
        assert!(verify_pkce(verifier, &challenge));
        assert!(!verify_pkce(
            "different-verifier-with-valid-length-01234567890123456789",
            &challenge
        ));
    }

    #[test]
    fn form_content_type_allows_utf8_charset_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        assert!(is_form(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_form(&headers));
    }

    #[test]
    fn concurrent_runs_have_distinct_browser_cookie_names() {
        assert_ne!(
            cookie_name("0123456789abcdef0123456789abcdef"),
            cookie_name("fedcba9876543210fedcba9876543210")
        );
    }

    #[test]
    fn browser_client_registration_refuses_credentials_in_callback_url() {
        assert!(validate_client(
            "app",
            "a-secret-longer-than-thirty-two-bytes",
            "http://127.0.0.1:4000/callback"
        )
        .is_ok());
        assert!(validate_client(
            "app",
            "a-secret-longer-than-thirty-two-bytes",
            "http://name@127.0.0.1:4000/callback"
        )
        .is_err());
        assert!(validate_client(
            "",
            "a-secret-longer-than-thirty-two-bytes",
            "http://127.0.0.1:4000/callback"
        )
        .is_err());
    }

    #[test]
    fn browser_code_exchange_is_one_use_and_binds_the_selected_person() {
        let scratch = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let input: RunInput = serde_json::from_value(json!({
            "run_id": "0123456789abcdef0123456789abcdef", "project": "/project",
            "ttl_seconds": 1800,
            "plan": {"issuer": origin,
                "products": [
                    {"product": "breg", "project": ".", "audience": "registry-service"},
                    {"product": "casework", "project": ".", "audience": "casework-service"}
                ],
                "people": {"person": {"subject": "subject-1", "client": "cli-client",
                    "displayName": "Test <Person>",
                    "grants": {"breg": {"profile": "viewer", "scopes": ["registry.read"],
                        "claims": {"registry_actor_kind": "human", "role": "viewer"}},
                        "casework": {"profile": "viewer", "scopes": ["casework.read"],
                        "claims": {"registry_actor_kind": "human", "role": "viewer"}}}},
                    "other": {"subject": "subject-2", "client": "cli-client",
                    "displayName": "Other Person",
                    "grants": {"breg": {"profile": "viewer", "scopes": ["registry.read"],
                        "claims": {"registry_actor_kind": "human", "role": "viewer"}}}}},
                "journey": {"id": "smoke", "steps": [{"id": "read", "product": "breg",
                    "as": "person", "method": "GET", "path": "/v1/records",
                    "expect": {"status": 200}}]}},
            "schema_people": [],
            "breg_authority": {"principal": "registry_principal", "purpose": false,
                "requires_postgis": false, "encrypts_fields": false, "named_clients": []},
            "casework_principals": {"viewer": "sub"}, "binaries": {}
        }))
        .unwrap();
        let issuer = Arc::new(Issuer::create(scratch.path()).unwrap());
        let server = BrowserServer::start(
            listener,
            Arc::new(input),
            issuer,
            BrowserClient {
                id: "app".to_owned(),
                secret: Zeroizing::new("a-secret-longer-than-thirty-two-bytes".to_owned()),
                redirect_uri: "http://127.0.0.1:4000/callback".to_owned(),
            },
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let http = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap();
            let metadata: Value = http.get(format!("{}/.well-known/openid-configuration", server.origin))
                .send().await.unwrap().json().await.unwrap();
            assert!(server.alive());
            assert_eq!(metadata["issuer"], server.origin);
            let public_keys: Value = http.get(format!("{}/jwks", server.origin))
                .send().await.unwrap().json().await.unwrap();
            assert!(public_keys["keys"][0].get("d").is_none());
            let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            let before_ready = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-before-ready&nonce=nonce-before-ready&scope=openid%20registry.read&resource=registry-service", server.origin, pkce_challenge(verifier));
            let refused = http.get(before_ready).send().await.unwrap();
            assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
            server.activate(clock().unwrap() + 1800);
            let ineligible_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-denied&nonce=nonce-denied&scope=openid%20casework.write&resource=casework-service", server.origin, pkce_challenge(verifier));
            for _ in 0..=MAXIMUM_PENDING {
                let denied = http.get(&ineligible_url).send().await.unwrap();
                assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
                assert_eq!(denied.json::<Value>().await.unwrap()["error"], "access_denied");
            }
            let auth_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-1&nonce=nonce-1&scope=openid%20registry.read%20registry.other&resource=registry-service", server.origin, pkce_challenge(verifier));
            let page = http.get(auth_url).send().await.unwrap();
            assert_eq!(page.status(), StatusCode::OK);
            let page = page.text().await.unwrap();
            assert!(page.contains("Test &lt;Person&gt;"));
            assert!(!page.contains("Test <Person>"));
            let transaction = page.split("name=\"transaction\" value=\"").nth(1).unwrap().split('"').next().unwrap();
            let selected = http.post(format!("{}/authorize", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("transaction={transaction}&identity=person"))
                .send().await.unwrap();
            assert_eq!(selected.status(), StatusCode::SEE_OTHER);
            let cookie = selected.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap()
                .split(';').next().unwrap().to_owned();
            let callback = Url::parse(selected.headers().get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
            assert_eq!(callback.query_pairs().find(|(name, _)| name == "state").unwrap().1, "state-1");
            let code = callback.query_pairs().find(|(name, _)| name == "code").unwrap().1.to_string();
            let form = format!("grant_type=authorization_code&client_id=app&client_secret=a-secret-longer-than-thirty-two-bytes&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&code_verifier={verifier}&resource=registry-service");
            let wrong_client = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form.replace("client_id=app", "client_id=other"))
                .send().await.unwrap();
            assert_eq!(wrong_client.status(), StatusCode::UNAUTHORIZED);
            let exchanged = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form.clone()).send().await.unwrap();
            assert_eq!(exchanged.status(), StatusCode::OK);
            let tokens: Value = exchanged.json().await.unwrap();
            assert_eq!(tokens["token_type"], "Bearer");
            assert_eq!(tokens["scope"], "openid registry.read");
            let encoded = tokens["access_token"].as_str().unwrap().split('.').nth(1).unwrap();
            let access: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
            assert_eq!(access["sub"], "subject-1");
            assert_eq!(access["client_id"], "app");
            assert_eq!(access["aud"], "registry-service");
            assert_eq!(access["name"], "Test <Person>");
            assert_eq!(access["scope"], "registry.read");
            assert_eq!(access["registry_scopes"], "registry.read");
            let replay = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form).send().await.unwrap();
            assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

            let mismatch_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-mismatch&nonce=nonce-mismatch&scope=openid%20registry.read&resource=registry-service", server.origin, pkce_challenge(verifier));
            let mismatch = http.get(mismatch_url).header(header::COOKIE, &cookie).send().await.unwrap();
            assert_eq!(mismatch.status(), StatusCode::SEE_OTHER);
            let mismatch_callback = Url::parse(mismatch.headers().get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
            let mismatch_code = mismatch_callback.query_pairs().find(|(name, _)| name == "code").unwrap().1.to_string();
            let wrong_resource = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("grant_type=authorization_code&client_id=app&client_secret=a-secret-longer-than-thirty-two-bytes&code={mismatch_code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&code_verifier={verifier}&resource=casework-service"))
                .send().await.unwrap();
            assert_eq!(wrong_resource.status(), StatusCode::BAD_REQUEST);
            assert_eq!(wrong_resource.json::<Value>().await.unwrap()["error"], "invalid_grant");

            let second_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-2&nonce=nonce-2&scope=openid%20casework.read&resource=casework-service", server.origin, pkce_challenge(verifier));
            let second = http.get(second_url).header(header::COOKIE, &cookie).send().await.unwrap();
            assert_eq!(second.status(), StatusCode::SEE_OTHER);
            let second_callback = Url::parse(second.headers().get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
            let second_code = second_callback.query_pairs().find(|(name, _)| name == "code").unwrap().1.to_string();
            let second_form = format!("grant_type=authorization_code&client_id=app&client_secret=a-secret-longer-than-thirty-two-bytes&code={second_code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&code_verifier={verifier}&resource=casework-service");
            let second_tokens: Value = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(second_form).send().await.unwrap().json().await.unwrap();
            let encoded = second_tokens["access_token"].as_str().unwrap().split('.').nth(1).unwrap();
            let second_access: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
            assert_eq!(second_access["aud"], "casework-service");
            assert_eq!(second_access["sub"], "subject-1");
            assert_eq!(second_access["registry_principal"], "subject-1");

            let casework_picker_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-person&nonce=nonce-person&scope=openid%20casework.read&resource=casework-service&prompt=login", server.origin, pkce_challenge(verifier));
            let casework_picker = http.get(casework_picker_url).header(header::COOKIE, &cookie).send().await.unwrap();
            assert_eq!(casework_picker.status(), StatusCode::OK);
            let casework_page = casework_picker.text().await.unwrap();
            assert!(!casework_page.contains("Other Person"));
            let casework_transaction = casework_page.split("name=\"transaction\" value=\"").nth(1).unwrap().split('"').next().unwrap();
            let ungranted_person = http.post(format!("{}/authorize", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("transaction={casework_transaction}&identity=other"))
                .send().await.unwrap();
            assert_eq!(ungranted_person.status(), StatusCode::FORBIDDEN);

            let fresh_url = format!("{}/authorize?client_id=app&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&response_type=code&code_challenge={}&code_challenge_method=S256&state=state-3&nonce=nonce-3&scope=openid%20registry.read&resource=registry-service&prompt=login", server.origin, pkce_challenge(verifier));
            let fresh = http.get(fresh_url).header(header::COOKIE, &cookie).send().await.unwrap();
            assert_eq!(fresh.status(), StatusCode::OK);
            let fresh_page = fresh.text().await.unwrap();
            assert!(fresh_page.contains("Other Person"));
            let fresh_transaction = fresh_page.split("name=\"transaction\" value=\"").nth(1).unwrap().split('"').next().unwrap();
            let switched = http.post(format!("{}/authorize", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("transaction={fresh_transaction}&identity=other"))
                .send().await.unwrap();
            assert_eq!(switched.status(), StatusCode::SEE_OTHER);
            let switched_cookie = switched.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap()
                .split(';').next().unwrap().to_owned();
            let switched_callback = Url::parse(switched.headers().get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
            let switched_code = switched_callback.query_pairs().find(|(name, _)| name == "code").unwrap().1.to_string();
            let switched_form = format!("grant_type=authorization_code&client_id=app&client_secret=a-secret-longer-than-thirty-two-bytes&code={switched_code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&code_verifier={verifier}&resource=registry-service");
            let switched_tokens: Value = http.post(format!("{}/token", server.origin))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(switched_form).send().await.unwrap().json().await.unwrap();
            let encoded = switched_tokens["access_token"].as_str().unwrap().split('.').nth(1).unwrap();
            let switched_access: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
            assert_eq!(switched_access["sub"], "subject-2");

            let bad_logout = http.get(format!("{}/logout?client_id=app&post_logout_redirect_uri=http%3A%2F%2Fevil.invalid", server.origin))
                .header(header::COOKIE, &switched_cookie).send().await.unwrap();
            assert_eq!(bad_logout.status(), StatusCode::BAD_REQUEST);
            let extra_logout = http.get(format!("{}/logout?client_id=app&post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A4000&next=http%3A%2F%2Fevil.invalid", server.origin))
                .header(header::COOKIE, &switched_cookie).send().await.unwrap();
            assert_eq!(extra_logout.status(), StatusCode::BAD_REQUEST);
            let logout = http.get(format!("{}/logout?client_id=app&post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A4000&state=appkit-switch.abc", server.origin))
                .header(header::COOKIE, &switched_cookie).send().await.unwrap();
            assert_eq!(logout.status(), StatusCode::SEE_OTHER);
            assert_eq!(logout.headers().get(header::LOCATION).unwrap(), "http://127.0.0.1:4000/?state=appkit-switch.abc");
        });
        drop(server);
        runtime.block_on(async {
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("{origin}/.well-known/openid-configuration"))
                .send()
                .await;
            assert!(response.is_err(), "stopped issuer must refuse old clients");
        });
        drop(runtime);
    }
}
