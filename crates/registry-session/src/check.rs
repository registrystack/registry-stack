// SPDX-License-Identifier: Apache-2.0

//! The gateway's authorization check.
//!
//! The gateway forwards the original method, path with query, and a few
//! headers to the check listener under [`CHECK_PREFIX`]. The check answers 200
//! to allow, with the headers to add upstream, or a denial the gateway returns
//! to the browser unchanged. The service checks; it never proxies.
//!
//! The router here is served on the check listener only. The router for the
//! public listener must not carry a `/check` route: its tests assert that with
//! the helper in [`testing`].

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use registry_platform_httputil::BearerToken;
use tokio::sync::{OwnedMutexGuard, Semaphore};
use zeroize::Zeroizing;

use crate::config::{ModuleConfig, Route, RuntimeConfig};
use crate::grants::{GrantError, Grants};
use crate::journal::{Action, Journal, Outcome};
use crate::store::{well_formed_token, Store};
use crate::wire::{
    problem, ProblemKind, ANSWER_MARKER_HEADER, ANSWER_MARKER_VALUE, CLIENT_HEADER,
    FETCH_SITE_HEADER, ORIGIN_HEADER,
};

/// The path prefix the gateway adds to the original path.
pub const CHECK_PREFIX: &str = "/check";

/// The sign-in route a page request without a session is sent to.
pub const SIGN_IN_PATH: &str = "/session/sign-in";

/// What the check decided for one request.
#[derive(Debug)]
pub enum Decision {
    /// Let the call through. `authorization` is the bearer token to attach to
    /// a module call; a page call carries none.
    Allow { authorization: Option<BearerToken> },
    /// Send the browser to sign in. Holds the `Location` value.
    SignIn(String),
    /// 403 `session.refused`.
    Refused,
    /// 401 `session.expired`.
    Expired,
    /// 503 `session.unavailable`.
    Unavailable,
}

impl Decision {
    /// The response the gateway receives.
    #[must_use]
    pub fn into_response(self) -> Response {
        match self {
            Self::Allow { authorization } => {
                let mut response = Response::new(Body::empty());
                let headers = response.headers_mut();
                // A page call carries no bearer token, so the gateway also
                // removes any `Authorization` the browser sent. A module call
                // gets the service's own, which the gateway sets after the
                // removals.
                let removed = if authorization.is_some() {
                    "cookie"
                } else {
                    "cookie,authorization"
                };
                headers.insert(
                    HeaderName::from_static("x-envoy-auth-headers-to-remove"),
                    HeaderValue::from_static(removed),
                );
                if let Some(token) = authorization {
                    headers.insert(header::AUTHORIZATION, token.authorization_header_value());
                }
                response
            }
            Self::SignIn(location) => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::FOUND;
                let headers = response.headers_mut();
                headers.insert(
                    header::LOCATION,
                    HeaderValue::from_str(&location)
                        .expect("a percent-encoded return path is header-safe"),
                );
                headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                headers.insert(
                    HeaderName::from_static(ANSWER_MARKER_HEADER),
                    HeaderValue::from_static(ANSWER_MARKER_VALUE),
                );
                response
            }
            Self::Refused => problem(ProblemKind::Refused, StatusCode::FORBIDDEN),
            Self::Expired => problem(ProblemKind::Expired, StatusCode::UNAUTHORIZED),
            Self::Unavailable => problem(ProblemKind::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    /// The outcome word logs carry.
    fn outcome(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::SignIn(_) => "sign-in",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What a spawned renewal reports back to the check that started it.
enum Renewal {
    Token(BearerToken),
    Expired,
    Unavailable,
}

/// How many renewals may be in flight at the issuer at once, across all
/// sessions. A check that finds none free allows with its unexpired token.
const MAXIMUM_CONCURRENT_REFRESHES: usize = 32;

struct Inner<G> {
    config: Arc<RuntimeConfig>,
    store: Arc<Store>,
    grants: G,
    /// Where a session ended by a refused renewal is recorded.
    journal: Option<Arc<Journal>>,
    refresh_permits: Semaphore,
    /// How many renewals have reached the session's renewal lock.
    #[cfg(test)]
    lock_requests: std::sync::atomic::AtomicUsize,
}

/// Decides each request the gateway forwards.
pub struct Checker<G: Grants> {
    inner: Arc<Inner<G>>,
}

impl<G: Grants> Clone for Checker<G> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<G: Grants> Checker<G> {
    #[must_use]
    pub fn new(config: Arc<RuntimeConfig>, store: Arc<Store>, grants: G) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                store,
                grants,
                journal: None,
                refresh_permits: Semaphore::new(MAXIMUM_CONCURRENT_REFRESHES),
                #[cfg(test)]
                lock_requests: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Allow at most `limit` renewals in flight at the issuer at once. Only
    /// call this before the checker is cloned.
    #[must_use]
    pub fn with_refresh_limit(mut self, limit: usize) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("a checker is configured before it is cloned")
            .refresh_permits = Semaphore::new(limit);
        self
    }

    /// Record sessions that end because the issuer refused their renewal.
    /// Only call this before the checker is cloned.
    #[must_use]
    pub fn with_journal(mut self, journal: Arc<Journal>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("a checker is configured before it is cloned")
            .journal = Some(journal);
        self
    }

    /// Decide the request the gateway forwarded: `target` is the path with
    /// query as the gateway sent it, `/check` prefix included.
    pub async fn decide(&self, method: &Method, target: &str, headers: &HeaderMap) -> Decision {
        let Some(stripped) = strip_check_prefix(target) else {
            return Decision::Refused;
        };
        let path = stripped.split_once('?').map_or(stripped, |(path, _)| path);
        if !clean_path(path) {
            return Decision::Refused;
        }
        let config = &self.inner.config;
        let Some(route) = config.route(path) else {
            return Decision::Refused;
        };
        let label = match route {
            Route::Module(module) => module.id.as_str(),
            Route::Page(_) => "page",
        };
        let decision = self.decide_route(route, method, stripped, headers).await;
        tracing::info!(
            outcome = decision.outcome(),
            module = label,
            "session check"
        );
        decision
    }

    async fn decide_route(
        &self,
        route: Route<'_>,
        method: &Method,
        original: &str,
        headers: &HeaderMap,
    ) -> Decision {
        let config = &self.inner.config;
        let read = method == Method::GET || method == Method::HEAD;
        // A request another site started never carries a token to a module,
        // whatever its method: it could trigger a read with side effects.
        if matches!(route, Route::Module(_))
            && matches!(
                single_header(headers, FETCH_SITE_HEADER),
                Ok(Some("cross-site")) | Err(())
            )
        {
            return Decision::Refused;
        }
        let allowed = match route {
            Route::Page(_) => read,
            Route::Module(_) => read || same_origin_page_call(headers, &config.origin()),
        };
        if !allowed {
            return Decision::Refused;
        }
        let cookie = session_cookie(headers, config.session_cookie());
        let live =
            cookie.and_then(|cookie| self.inner.store.live(cookie).map(|live| (cookie, live)));
        let Some((cookie, live)) = live else {
            return match route {
                Route::Module(_) => Decision::Expired,
                Route::Page(_) => sign_in(original),
            };
        };
        match route {
            Route::Page(page) if live.kind == page.sign_in.as_str() => Decision::Allow {
                authorization: None,
            },
            Route::Page(_) => sign_in(original),
            Route::Module(module) => self.module_call(module, cookie, &live).await,
        }
    }

    async fn module_call(
        &self,
        module: &ModuleConfig,
        cookie: &str,
        live: &crate::store::Live,
    ) -> Decision {
        let inner = &self.inner;
        if !module.admits(&live.kind) {
            return Decision::Refused;
        }
        let Some(audience) = inner.config.module_audience(module) else {
            return Decision::Refused;
        };
        let Some(access) = inner.store.access(cookie, audience) else {
            if inner.store.live(cookie).is_none() {
                // The session ended between the two reads.
                return Decision::Expired;
            }
            tracing::warn!(
                module = module.id.as_str(),
                "a session holds no token for the module audience"
            );
            return Decision::Refused;
        };
        let now = inner.store.now();
        if now < access.renew_at(renew_before(&inner.config)) {
            return Decision::Allow {
                authorization: Some(access.token),
            };
        }
        // A check never waits on the issuer while its token is still valid:
        // it allows with that token while the issuer is being avoided after a
        // failure, or another check is already renewing this session.
        let valid = access.expires_at > now;
        let held = if valid && access.retry_after.is_some_and(|after| after > now) {
            return Decision::Allow {
                authorization: Some(access.token),
            };
        } else {
            match live.renewal.clone().try_lock_owned() {
                Ok(guard) => Some(guard),
                Err(_) if valid => {
                    return Decision::Allow {
                        authorization: Some(access.token),
                    };
                }
                Err(_) => None,
            }
        };
        // The renewal runs in its own task: if the gateway times the check out
        // and this handler is dropped, the rotated refresh token is still
        // stored.
        let task = tokio::spawn(renew(
            inner.clone(),
            Zeroizing::new(cookie.to_owned()),
            audience.to_owned(),
            live.kind.clone(),
            live.renewal.clone(),
            held,
        ));
        match task.await {
            Ok(Renewal::Token(token)) => Decision::Allow {
                authorization: Some(token),
            },
            Ok(Renewal::Expired) => Decision::Expired,
            Ok(Renewal::Unavailable) => Decision::Unavailable,
            Err(error) => {
                tracing::error!(panicked = error.is_panic(), "a session renewal task failed");
                Decision::Unavailable
            }
        }
    }
}

fn renew_before(config: &RuntimeConfig) -> Duration {
    Duration::from_secs(config.session.renew_before_seconds.get())
}

/// Hold the session's renewal lock (taking it when `held` is empty), then use
/// the token another caller already renewed, or renew it.
async fn renew<G: Grants>(
    inner: Arc<Inner<G>>,
    cookie: Zeroizing<String>,
    audience: String,
    kind: String,
    renewal: Arc<tokio::sync::Mutex<()>>,
    held: Option<OwnedMutexGuard<()>>,
) -> Renewal {
    let _held = match held {
        Some(guard) => guard,
        None => {
            #[cfg(test)]
            inner
                .lock_requests
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            renewal.lock_owned().await
        }
    };
    let store = &inner.store;
    // The session may have ended while this waited for the lock, or crossed
    // its absolute deadline.
    if store.live(&cookie).is_none() {
        return Renewal::Expired;
    }
    let Some(access) = store.access(&cookie, &audience) else {
        return Renewal::Expired;
    };
    let now = store.now();
    if now < access.renew_at(renew_before(&inner.config)) {
        return Renewal::Token(access.token);
    }
    // Without a renewal, an unexpired token still serves and an expired one
    // cannot.
    let valid = access.expires_at > now;
    let without_renewal = |token: BearerToken| {
        if valid {
            Renewal::Token(token)
        } else {
            Renewal::Unavailable
        }
    };
    if access.retry_after.is_some_and(|after| after > now) {
        return without_renewal(access.token);
    }
    let Some(refresh_token) = store.refresh_token(&cookie, &audience) else {
        if valid {
            return Renewal::Token(access.token);
        }
        if let Some(session) = store.remove(&cookie) {
            store.release(&session);
        }
        return Renewal::Expired;
    };
    let Ok(_permit) = inner.refresh_permits.try_acquire() else {
        return without_renewal(access.token);
    };
    match inner.grants.refresh(&kind, &refresh_token, &audience).await {
        Ok(renewed) => {
            let token = renewed.access_token.clone();
            match store.apply_renewed(&cookie, &audience, renewed) {
                Ok(()) => Renewal::Token(token),
                Err(gone) => {
                    // The session ended during the renewal. The rotated
                    // refresh token would stay live at the issuer, so it is
                    // revoked here.
                    if let Some(rotated) = gone.refresh_token {
                        if inner.grants.revoke(&kind, &rotated).await.is_err() {
                            tracing::warn!(
                                "a rotated refresh token could not be revoked at the issuer"
                            );
                        }
                    }
                    Renewal::Expired
                }
            }
        }
        Err(GrantError::Refused) => {
            if let Some(session) = store.remove(&cookie) {
                store.release(&session);
                record_ended(&inner, &session).await;
            }
            Renewal::Expired
        }
        Err(GrantError::Unavailable) => {
            store.note_unavailable(&cookie);
            without_renewal(access.token)
        }
    }
}

/// Audit a session the issuer ended. The session is already gone, so a
/// failure to record it is logged, never hidden behind an answer.
async fn record_ended<G>(inner: &Inner<G>, session: &crate::store::Session) {
    let Some(journal) = &inner.journal else {
        return;
    };
    let Ok(person) = journal.person_at(session.issuer(), session.subject()) else {
        tracing::error!("a person pseudonym could not be derived");
        return;
    };
    if let Err(error) = journal
        .record(
            Action::SessionEnded,
            session.kind(),
            Some(&person),
            Outcome::Refused,
        )
        .await
    {
        tracing::error!(%error, "a session end could not be audited");
    }
}

fn sign_in(original: &str) -> Decision {
    Decision::SignIn(format!(
        "{SIGN_IN_PATH}?return={}",
        percent_encode(original)
    ))
}

/// The one value of the named header, or `None` when it is absent. A repeated
/// or non-text header is `Err`.
pub(crate) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// Whether a write to a module comes from the service's own page: the page
/// header exactly, an `Origin` equal to the public origin, and a
/// `Sec-Fetch-Site` of `same-origin` when present. A browser sends `Origin` on
/// every request that is not a GET or HEAD, so a write without one was
/// stripped on the way or did not come from a browser.
fn same_origin_page_call(headers: &HeaderMap, origin: &str) -> bool {
    single_header(headers, CLIENT_HEADER) == Ok(Some("page"))
        && single_header(headers, ORIGIN_HEADER) == Ok(Some(origin))
        && single_header(headers, FETCH_SITE_HEADER)
            .is_ok_and(|value| value.is_none_or(|v| v == "same-origin"))
}

/// The one value of cookie `name` a request presents, when it presents
/// exactly one value of the shape this service issues.
pub(crate) fn session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((candidate, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if candidate == name {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found.filter(|value| well_formed_token(value))
}

/// `target` without [`CHECK_PREFIX`], or `None` when it does not start with
/// `/check/`.
fn strip_check_prefix(target: &str) -> Option<&str> {
    let rest = target.strip_prefix(CHECK_PREFIX)?;
    rest.starts_with('/').then_some(rest)
}

/// Whether `path` (no query) is safe to match: no dot segment, empty segment,
/// backslash, semicolon, or percent-encoded `/`, `\`, `.`, `%` or NUL.
pub(crate) fn clean_path(path: &str) -> bool {
    let Some(segments) = path.strip_prefix('/') else {
        return false;
    };
    if path.contains('\\') {
        return false;
    }
    // `;` starts a path parameter some upstreams strip, and `%25` and `%00`
    // are double encoding and a NUL.
    if path.contains(';') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if ["%2f", "%5c", "%2e", "%25", "%00"]
        .iter()
        .any(|encoded| lower.contains(encoded))
    {
        return false;
    }
    let segments: Vec<&str> = segments.split('/').collect();
    segments.iter().enumerate().all(|(index, segment)| {
        *segment != "." && *segment != ".." && (!segment.is_empty() || index + 1 == segments.len())
    })
}

/// Percent-encode everything but the RFC 3986 unreserved characters.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The router for the check listener: the check itself, `/healthz`, `/readyz`.
pub fn check_router<G: Grants>(checker: Checker<G>) -> Router {
    Router::new()
        .route("/healthz", get(healthy))
        .route("/readyz", get(healthy))
        .fallback(check_handler::<G>)
        .with_state(checker)
}

async fn healthy() -> Response {
    let mut response = Response::new(Body::empty());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn check_handler<G: Grants>(State(checker): State<Checker<G>>, request: Request) -> Response {
    let target = request
        .uri()
        .path_and_query()
        .map_or("", |target| target.as_str());
    checker
        .decide(request.method(), target, request.headers())
        .await
        .into_response()
}

/// Helpers for the tests of the router served on the public listener.
#[cfg(test)]
pub(crate) mod testing {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    /// Whether `router` answers 404 for a `/check/...` request, as the public
    /// router must.
    pub(crate) async fn answers_404_for_check(router: Router) -> bool {
        let request = Request::builder()
            .uri("/check/api/registry/records")
            .body(Body::empty())
            .expect("request");
        router.oneshot(request).await.expect("response").status() == StatusCode::NOT_FOUND
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{header, HeaderValue, Request, StatusCode};
    use serde_json::{Map, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::clock::{Clock, ManualClock};
    use crate::grants::fake::FakeIssuer;
    use crate::store::{random_token, Access, AudienceGrant, Session};

    const PERSON: &str = "https://api.example/person";
    const CASEWORK: &str = "https://casework.example/api";

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .get(name)
                .map(|value| value.to_str().expect("ascii"))
        }

        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).expect("json body")
        }

        fn authorization(&self) -> Option<HeaderValue> {
            self.headers.get(header::AUTHORIZATION).cloned()
        }
    }

    struct Harness {
        clock: Arc<ManualClock>,
        issuer: Arc<FakeIssuer>,
        store: Arc<Store>,
        config: Arc<RuntimeConfig>,
        checker: Checker<Arc<FakeIssuer>>,
        router: Router,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_document(&crate::config::tests::document())
        }

        fn with_document(text: &str) -> Self {
            Self::build(text, None)
        }

        /// A harness whose service allows `limit` renewals in flight at once.
        fn with_refresh_limit(limit: usize) -> Self {
            Self::build(&crate::config::tests::document(), Some(limit))
        }

        fn build(text: &str, refresh_limit: Option<usize>) -> Self {
            let config = Arc::new(crate::config::tests::load(text).expect("config"));
            let clock = Arc::new(ManualClock::new());
            let issuer = FakeIssuer::new(clock.clone());
            let (ended, revoker) = crate::revoker::channel(16);
            tokio::spawn(revoker.run(issuer.clone()));
            let store = Arc::new(
                Store::new(clock.clone(), 100, 100)
                    .with_idle_lifetime(Duration::from_secs(config.session.idle_lifetime_seconds()))
                    .with_ended_sessions(ended),
            );
            let mut checker = Checker::new(config.clone(), store.clone(), issuer.clone());
            if let Some(limit) = refresh_limit {
                checker = checker.with_refresh_limit(limit);
            }
            Self {
                clock,
                issuer,
                store,
                config,
                router: check_router(checker.clone()),
                checker,
            }
        }

        /// A signed-in session of `kind` with a token for each audience of
        /// the kind, returning its cookie value.
        fn sign_in(&self, kind: &str) -> String {
            self.sign_in_with(kind, true)
        }

        fn sign_in_with(&self, kind: &str, refreshable: bool) -> String {
            self.sign_in_for(kind, refreshable, None)
        }

        /// A session whose tokens last `lifetime` instead of the issuer's.
        fn sign_in_short(&self, kind: &str, lifetime: Duration) -> String {
            self.sign_in_for(kind, true, Some(lifetime))
        }

        fn sign_in_for(&self, kind: &str, refreshable: bool, lifetime: Option<Duration>) -> String {
            let cookie = random_token().expect("random");
            let audiences = self
                .config
                .audience_set(kind)
                .into_iter()
                .map(|audience| {
                    let (access_token, expires_at, refresh) = self.issuer.sign_in(audience);
                    AudienceGrant {
                        audience: audience.to_owned(),
                        access_token,
                        expires_at: lifetime
                            .map_or(expires_at, |lifetime| self.clock.now() + lifetime),
                        issued_at: self.clock.now(),
                        refresh_token: refreshable.then_some(refresh),
                    }
                })
                .collect();
            let lifetime = self.config.session.absolute_lifetime_seconds.get();
            let session = Session::new(
                kind.to_owned(),
                "https://id.example".to_owned(),
                format!("subject-{cookie}"),
                Map::new(),
                audiences,
                self.clock.now() + Duration::from_secs(lifetime),
            );
            let _ = self.store.insert(&cookie, session).expect("room");
            cookie
        }

        fn cookie_header(&self, cookie: &str) -> String {
            format!("{}={cookie}", self.config.session_cookie())
        }

        /// The `Authorization` value the session holds for `audience`.
        fn bearer(&self, cookie: &str, audience: &str) -> HeaderValue {
            self.store
                .access(cookie, audience)
                .expect("a token")
                .token
                .authorization_header_value()
        }

        async fn call(&self, method: &str, target: &str, headers: &[(&str, &str)]) -> Reply {
            let mut request = Request::builder().method(method).uri(target);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let request = request.body(Body::empty()).expect("request");
            reply(
                self.router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("response"),
            )
            .await
        }

        /// A request with the session cookie of `cookie`.
        async fn get(&self, cookie: &str, target: &str) -> Reply {
            let header = self.cookie_header(cookie);
            self.call("GET", target, &[("cookie", &header)]).await
        }
    }

    async fn reply(response: Response) -> Reply {
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: axum::body::to_bytes(body, 64 * 1024)
                .await
                .expect("body")
                .to_vec(),
        }
    }

    /// A module route is called by scripts that cannot follow a sign-in
    /// redirect, so it answers a problem, never a 3xx.
    #[tokio::test]
    async fn a_module_route_never_redirects() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let header = harness.cookie_header(&cookie);
        for method in ["GET", "POST", "PUT", "DELETE"] {
            for path in ["/check/api/registry/x", "/check/api/casework/x"] {
                let anonymous = harness.call(method, path, &[]).await;
                let signed_in = harness.call(method, path, &[("cookie", &header)]).await;
                for reply in [anonymous, signed_in] {
                    assert!(!reply.status.is_redirection(), "{method} {path}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_page_redirect_carries_the_answer_marker_and_an_allow_does_not() {
        let harness = Harness::new();
        let redirect = harness.call("GET", "/check/apply/", &[]).await;
        assert_eq!(redirect.status, StatusCode::FOUND);
        assert_eq!(
            redirect.header(ANSWER_MARKER_HEADER),
            Some(ANSWER_MARKER_VALUE)
        );
        let cookie = harness.sign_in("citizen");
        let header = harness.cookie_header(&cookie);
        let allowed = harness
            .call("GET", "/check/api/registry/x", &[("cookie", &header)])
            .await;
        assert_eq!(allowed.status, StatusCode::OK);
        assert!(allowed.header(ANSWER_MARKER_HEADER).is_none());
    }

    fn assert_problem(reply: &Reply, status: StatusCode, code: &str) {
        assert_eq!(reply.status, status);
        assert_eq!(
            reply.header("content-type"),
            Some("application/problem+json")
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        assert!(reply.header("location").is_none());
        assert!(reply.authorization().is_none());
        let body = reply.json();
        assert_eq!(body["code"], code);
        assert_eq!(body["status"], status.as_u16());
        let suffix = code.strip_prefix("session.").expect("a session code");
        assert_eq!(
            body["type"],
            format!("https://id.registrystack.org/problems/registry-platform/session/{suffix}")
        );
        assert_eq!(
            reply.header(ANSWER_MARKER_HEADER),
            Some(ANSWER_MARKER_VALUE)
        );
        assert!(body["title"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    /// A module call is allowed with a bearer token and loses its cookie; a
    /// page call carries no token and loses its cookie and any `Authorization`.
    fn assert_allowed(reply: &Reply) {
        assert_eq!(reply.status, StatusCode::OK);
        let removed = if reply.authorization().is_some() {
            "cookie"
        } else {
            "cookie,authorization"
        };
        assert_eq!(
            reply.header("x-envoy-auth-headers-to-remove"),
            Some(removed)
        );
    }

    // Step 1: the path is clean before anything is matched.

    #[test]
    fn the_check_prefix_is_stripped_only_at_a_segment_boundary() {
        assert_eq!(strip_check_prefix("/check/api/x?a=1"), Some("/api/x?a=1"));
        assert_eq!(strip_check_prefix("/check/"), Some("/"));
        assert_eq!(strip_check_prefix("/check"), None);
        assert_eq!(strip_check_prefix("/checkout/api/"), None);
        assert_eq!(strip_check_prefix("/api/registry/"), None);
        assert_eq!(strip_check_prefix(""), None);
    }

    #[test]
    fn a_path_with_a_dot_segment_or_an_encoded_separator_is_not_clean() {
        for clean in [
            "/api/registry/records/1",
            "/api/.hidden/x",
            "/api/v1.2/x",
            "/",
        ] {
            assert!(clean_path(clean), "{clean}");
        }
        for unclean in [
            "/api/./x",
            "/api/../x",
            "/api/x/..",
            "/api/x/.",
            "/api//x",
            "//api/x",
            "/api\\x",
            "/api/%2f/x",
            "/api/%2F/x",
            "/api/a%2Fb",
            "/api/%5c/x",
            "/api/%5C/x",
            "/api/%2e/x",
            "/api/%2E%2e/x",
            "/api/.%2e/x",
            "/api/..;/x",
            "/api/a;b/x",
            "/api/%00/x",
            "/api/a%00",
            "/api/%252e/x",
            "/api/%25/x",
        ] {
            assert!(!clean_path(unclean), "{unclean}");
        }
    }

    #[test]
    fn percent_encoding_keeps_only_unreserved_characters() {
        assert_eq!(percent_encode("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(
            percent_encode("/apply/form?a=1&b=%C3%A9"),
            "%2Fapply%2Fform%3Fa%3D1%26b%3D%25C3%25A9"
        );
        assert_eq!(percent_encode("é "), "%C3%A9%20");
    }

    #[tokio::test]
    async fn an_unclean_path_is_refused_before_any_matching() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        for target in [
            "/check/api/registry/../casework/x",
            "/check/api/registry/./x",
            "/check/api/registry//x",
            "/check/api/registry/%2f/x",
            "/check/api/registry/%2F/x",
            "/check/api/registry/%5c/x",
            "/check/api/registry/%5C/x",
            "/check/api/registry/%2e%2e/x",
            "/check/api/registry/%2E/x",
            "/check/apply/../staff/",
            "/check/api/registry/..;/casework/x",
            "/check/api/registry/%00",
            "/check/api/registry/%252e%252e/x",
        ] {
            let reply = harness.get(&cookie, target).await;
            assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        }
    }

    #[tokio::test]
    async fn a_target_without_the_check_prefix_is_refused() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        for target in [
            "/api/registry/records",
            "/check",
            "/checkout/api/registry/x",
        ] {
            let reply = harness.get(&cookie, target).await;
            assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        }
    }

    // Step 2: longest prefix over modules and pages.

    #[tokio::test]
    async fn a_path_that_matches_no_prefix_is_refused() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        for target in [
            "/check/unknown/x",
            "/check/api/registry",
            "/check/session/sign-in",
            "/check/",
        ] {
            let reply = harness.get(&cookie, target).await;
            assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        }
        let reply = harness.call("GET", "/check/unknown/x", &[]).await;
        assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
    }

    #[tokio::test]
    async fn the_longest_prefix_decides_between_a_module_and_a_page() {
        let text = crate::config::tests::document().replace(
            "pages:\n",
            "pages:\n  - prefix: /api/casework/docs/\n    signIn: staff\n",
        );
        let harness = Harness::with_document(&text);
        let cookie = harness.sign_in("staff");
        let module = harness.get(&cookie, "/check/api/casework/tasks").await;
        assert_allowed(&module);
        assert!(module.authorization().is_some());
        let page = harness
            .get(&cookie, "/check/api/casework/docs/a.html")
            .await;
        assert_allowed(&page);
        assert!(page.authorization().is_none());
    }

    // Step 3: cross-site defence.

    #[tokio::test]
    async fn a_write_to_a_module_needs_the_page_header_and_a_same_origin_request() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let session = harness.cookie_header(&cookie);
        let post = |extra: Vec<(&'static str, &'static str)>| {
            let session = session.clone();
            let harness = &harness;
            async move {
                let mut headers = vec![("cookie", session.as_str())];
                headers.extend(extra);
                harness
                    .call("POST", "/check/api/registry/records", &headers)
                    .await
            }
        };
        assert_problem(
            &post(vec![]).await,
            StatusCode::FORBIDDEN,
            "session.refused",
        );
        for wrong in ["Page", "page ", "other", ""] {
            assert_problem(
                &post(vec![("registry-client", wrong)]).await,
                StatusCode::FORBIDDEN,
                "session.refused",
            );
        }
        assert_problem(
            &post(vec![
                ("registry-client", "page"),
                ("origin", "https://evil.example"),
            ])
            .await,
            StatusCode::FORBIDDEN,
            "session.refused",
        );
        assert_problem(
            &post(vec![("registry-client", "page"), ("origin", "null")]).await,
            StatusCode::FORBIDDEN,
            "session.refused",
        );
        for site in ["cross-site", "same-site", "none", "Same-Origin"] {
            assert_problem(
                &post(vec![("registry-client", "page"), ("sec-fetch-site", site)]).await,
                StatusCode::FORBIDDEN,
                "session.refused",
            );
        }
        // A browser sends Origin on every write, so a write without one was
        // stripped by the gateway or did not come from a browser.
        assert_problem(
            &post(vec![("registry-client", "page")]).await,
            StatusCode::FORBIDDEN,
            "session.refused",
        );
        assert_problem(
            &post(vec![
                ("registry-client", "page"),
                ("sec-fetch-site", "same-origin"),
            ])
            .await,
            StatusCode::FORBIDDEN,
            "session.refused",
        );
        let allowed = post(vec![
            ("registry-client", "page"),
            ("origin", "https://app.example"),
            ("sec-fetch-site", "same-origin"),
        ])
        .await;
        assert_allowed(&allowed);
        assert_eq!(
            allowed.authorization(),
            Some(harness.bearer(&cookie, PERSON))
        );
    }

    #[tokio::test]
    async fn a_repeated_cross_site_header_is_refused() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let session = harness.cookie_header(&cookie);
        let reply = harness
            .call(
                "DELETE",
                "/check/api/registry/records/1",
                &[
                    ("cookie", &session),
                    ("registry-client", "page"),
                    ("origin", "https://app.example"),
                    ("origin", "https://app.example"),
                ],
            )
            .await;
        assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
    }

    #[tokio::test]
    async fn a_read_of_a_module_needs_no_cross_site_headers() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        for method in ["GET", "HEAD"] {
            let session = harness.cookie_header(&cookie);
            let reply = harness
                .call(
                    method,
                    "/check/api/registry/records",
                    &[("cookie", &session)],
                )
                .await;
            assert_allowed(&reply);
        }
    }

    #[tokio::test]
    async fn pages_accept_only_get_and_head() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let session = harness.cookie_header(&cookie);
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let reply = harness
                .call(
                    method,
                    "/check/apply/form",
                    &[("cookie", &session), ("registry-client", "page")],
                )
                .await;
            assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        }
        for method in ["GET", "HEAD"] {
            let reply = harness
                .call(method, "/check/apply/form", &[("cookie", &session)])
                .await;
            assert_allowed(&reply);
        }
    }

    // Step 4: the session cookie.

    #[tokio::test]
    async fn a_module_call_without_a_session_is_401_with_no_location() {
        let harness = Harness::new();
        let reply = harness
            .call("GET", "/check/api/registry/records", &[])
            .await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
    }

    #[tokio::test]
    async fn a_page_without_a_session_is_sent_to_sign_in_with_its_return_path() {
        let harness = Harness::new();
        let reply = harness
            .call("GET", "/check/apply/form?a=1&b=%C3%A9", &[])
            .await;
        assert_eq!(reply.status, StatusCode::FOUND);
        assert_eq!(
            reply.header("location"),
            Some("/session/sign-in?return=%2Fapply%2Fform%3Fa%3D1%26b%3D%25C3%25A9")
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        assert!(reply.authorization().is_none());
    }

    #[tokio::test]
    async fn an_unknown_repeated_or_malformed_cookie_is_no_session() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let name = harness.config.session_cookie();
        let good = format!("{name}={cookie}");
        let unknown = format!("{name}={}", random_token().expect("random"));
        let malformed = format!("{name}=<script>");
        let short = format!("{name}={}", &cookie[..42]);
        let repeated = format!("{good}; {good}");
        let wrong_name = format!("registry-session={cookie}");
        for header in [&unknown, &malformed, &short, &repeated, &wrong_name] {
            let reply = harness
                .call("GET", "/check/api/registry/records", &[("cookie", header)])
                .await;
            assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        }
        let two_headers = harness
            .call(
                "GET",
                "/check/api/registry/records",
                &[("cookie", &good), ("cookie", &good)],
            )
            .await;
        assert_problem(&two_headers, StatusCode::UNAUTHORIZED, "session.expired");
        let among_others = format!("a=1; {good}; b=2");
        let reply = harness
            .call(
                "GET",
                "/check/api/registry/records",
                &[("cookie", &among_others)],
            )
            .await;
        assert_allowed(&reply);
    }

    #[tokio::test]
    async fn a_session_past_its_absolute_deadline_is_over_and_removed() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let lifetime = harness.config.session.absolute_lifetime_seconds.get();
        harness.clock.advance(Duration::from_secs(lifetime));
        let module = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(&module, StatusCode::UNAUTHORIZED, "session.expired");
        assert!(harness.store.live(&cookie).is_none());
        let page = harness.get(&cookie, "/check/apply/form").await;
        assert_eq!(page.status, StatusCode::FOUND);
    }

    #[tokio::test]
    async fn development_cookies_use_the_development_name() {
        let harness = Harness::with_document(&crate::config::tests::development());
        let cookie = harness.sign_in("citizen");
        let reply = harness
            .call(
                "GET",
                "/check/api/registry/records",
                &[("cookie", &format!("registry-session={cookie}"))],
            )
            .await;
        assert_allowed(&reply);
        let reply = harness
            .call(
                "GET",
                "/check/api/registry/records",
                &[("cookie", &format!("__Host-registry-session={cookie}"))],
            )
            .await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
    }

    // Step 5: pages.

    #[tokio::test]
    async fn a_page_wants_a_session_of_its_own_kind() {
        let harness = Harness::new();
        let citizen = harness.sign_in("citizen");
        let staff = harness.sign_in("staff");
        let own = harness.get(&citizen, "/check/apply/form").await;
        assert_allowed(&own);
        assert!(own.authorization().is_none());
        let other = harness.get(&staff, "/check/apply/form?x=1").await;
        assert_eq!(other.status, StatusCode::FOUND);
        assert_eq!(
            other.header("location"),
            Some("/session/sign-in?return=%2Fapply%2Fform%3Fx%3D1")
        );
        let other = harness.get(&citizen, "/check/staff/").await;
        assert_eq!(other.status, StatusCode::FOUND);
        assert_allowed(&harness.get(&staff, "/check/staff/").await);
    }

    // Step 6: modules.

    #[tokio::test]
    async fn a_module_call_carries_the_token_of_its_audience() {
        let harness = Harness::new();
        let staff = harness.sign_in("staff");
        let registry = harness.get(&staff, "/check/api/registry/records").await;
        let documents = harness.get(&staff, "/check/api/documents/slots").await;
        let casework = harness.get(&staff, "/check/api/casework/tasks").await;
        for reply in [&registry, &documents, &casework] {
            assert_allowed(reply);
        }
        // Two modules in the person audience share one token.
        assert_eq!(
            registry.authorization(),
            Some(harness.bearer(&staff, PERSON))
        );
        assert_eq!(registry.authorization(), documents.authorization());
        assert_eq!(
            casework.authorization(),
            Some(harness.bearer(&staff, CASEWORK))
        );
        assert_ne!(registry.authorization(), casework.authorization());
        assert_eq!(harness.issuer.refresh_calls(), 0);
    }

    #[tokio::test]
    async fn a_kind_that_may_not_call_a_module_is_refused() {
        let harness = Harness::new();
        let citizen = harness.sign_in("citizen");
        let reply = harness.get(&citizen, "/check/api/casework/tasks").await;
        assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        assert_eq!(harness.issuer.refresh_calls(), 0);
    }

    #[tokio::test]
    async fn a_token_with_more_than_the_renewal_span_left_is_used_as_it_is() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        // 300 second tokens and a 60 second span: 61 seconds left.
        harness.clock.advance(Duration::from_secs(239));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(harness.issuer.refresh_calls(), 0);
        // Exactly the span left: renew.
        harness.clock.advance(Duration::from_secs(1));
        let old = harness.bearer(&cookie, PERSON);
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(harness.issuer.refresh_calls(), 1);
        assert_ne!(reply.authorization(), Some(old));
        assert_eq!(reply.authorization(), Some(harness.bearer(&cookie, PERSON)));
    }

    #[tokio::test]
    async fn a_page_never_renews() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        harness.clock.advance(Duration::from_secs(250));
        assert_allowed(&harness.get(&cookie, "/check/apply/form").await);
        assert_eq!(harness.issuer.refresh_calls(), 0);
    }

    /// Spawn a GET of `target` with the session cookie, answered on its own
    /// task so the caller can hold the issuer's gate meanwhile.
    fn spawn_get(
        harness: &Harness,
        cookie: &str,
        target: &str,
    ) -> tokio::task::JoinHandle<Response> {
        let router = harness.router.clone();
        let request = Request::builder()
            .uri(target)
            .header("cookie", harness.cookie_header(cookie))
            .body(Body::empty())
            .expect("request");
        tokio::spawn(async move { router.oneshot(request).await.expect("response") })
    }

    /// Wait until `count` renewals have reached the session's renewal lock, so
    /// a test opens the issuer's gate only when every waiter is queued.
    async fn until_waiting(harness: &Harness, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while harness
                .checker
                .inner
                .lock_requests
                .load(std::sync::atomic::Ordering::SeqCst)
                < count
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the waiters reached the renewal lock");
    }

    #[tokio::test]
    async fn five_concurrent_checks_with_an_expired_token_make_one_refresh_and_all_get_the_new_token(
    ) {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let old = harness.bearer(&cookie, PERSON);
        harness.clock.advance(Duration::from_secs(301));
        harness.issuer.close_gate();
        let handles: Vec<_> = (0..5)
            .map(|_| spawn_get(&harness, &cookie, "/check/api/registry/records"))
            .collect();
        harness.issuer.refresh_started().await;
        // One check holds the lock at the issuer's gate, and the other four are
        // queued on it.
        until_waiting(&harness, 4).await;
        harness.issuer.open_gate();
        let mut tokens = Vec::new();
        for handle in handles {
            let reply = reply(handle.await.expect("task")).await;
            assert_allowed(&reply);
            tokens.push(reply.authorization().expect("token"));
        }
        assert_eq!(harness.issuer.refresh_calls(), 1);
        assert!(tokens.iter().all(|token| *token == tokens[0]));
        assert_ne!(tokens[0], old);
        assert_eq!(tokens[0], harness.bearer(&cookie, PERSON));
    }

    #[tokio::test]
    async fn a_valid_token_is_allowed_at_once_while_a_renewal_hangs() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let old = harness.bearer(&cookie, PERSON);
        harness.clock.advance(Duration::from_secs(250));
        harness.issuer.close_gate();
        let first = spawn_get(&harness, &cookie, "/check/api/registry/records");
        harness.issuer.refresh_started().await;
        for _ in 0..10 {
            let reply = tokio::time::timeout(
                Duration::from_secs(2),
                harness.get(&cookie, "/check/api/registry/records"),
            )
            .await
            .expect("a valid token is not held up by the renewal");
            assert_allowed(&reply);
            assert_eq!(reply.authorization(), Some(old.clone()));
        }
        // No task piled up behind the hung renewal.
        assert_eq!(harness.issuer.refresh_calls(), 1);
        harness.issuer.open_gate();
        let reply = reply(first.await.expect("task")).await;
        assert_allowed(&reply);
        assert_ne!(reply.authorization(), Some(old));
    }

    #[tokio::test]
    async fn renewal_backs_off_after_the_issuer_is_unreachable_and_doubles_to_a_minute() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        harness.issuer.set_unavailable(true);
        harness.clock.advance(Duration::from_secs(250));
        let old = harness.bearer(&cookie, PERSON);
        let check = || harness.get(&cookie, "/check/api/registry/records");
        for _ in 0..4 {
            let reply = check().await;
            assert_allowed(&reply);
            assert_eq!(reply.authorization(), Some(old.clone()));
        }
        assert_eq!(harness.issuer.refresh_calls(), 1);
        // 5 seconds, then 10, then 20.
        for (waited, calls) in [(4, 1), (1, 2), (9, 2), (1, 3), (19, 3), (1, 4)] {
            harness.clock.advance(Duration::from_secs(waited));
            assert_allowed(&check().await);
            assert_eq!(harness.issuer.refresh_calls(), calls, "after {waited} s");
        }
        // The last failure, at 285 s, set a 40 s backoff. Past the token's
        // expiry at 300 s the backoff still holds: 503 at once, with no call to
        // the issuer, until it ends at 325 s.
        for (waited, calls) in [(20, 4), (10, 4), (10, 5)] {
            harness.clock.advance(Duration::from_secs(waited));
            assert_problem(
                &check().await,
                StatusCode::SERVICE_UNAVAILABLE,
                "session.unavailable",
            );
            assert_eq!(harness.issuer.refresh_calls(), calls, "after {waited} s");
        }
    }

    #[test]
    fn the_backoff_doubles_from_five_seconds_to_at_most_sixty_and_a_renewal_clears_it() {
        let harness_clock = Arc::new(ManualClock::new());
        let store = Store::new(harness_clock.clone(), 4, 4);
        let issuer = FakeIssuer::new(harness_clock.clone());
        let (access_token, expires_at, refresh) = issuer.sign_in(PERSON);
        let session = Session::new(
            "citizen".to_owned(),
            "https://id.example".to_owned(),
            "p".to_owned(),
            Map::new(),
            vec![AudienceGrant {
                audience: PERSON.to_owned(),
                access_token,
                expires_at,
                issued_at: harness_clock.now(),
                refresh_token: Some(refresh),
            }],
            harness_clock.now() + Duration::from_secs(3600),
        );
        let _ = store.insert("c", session).expect("room");
        assert!(store
            .access("c", PERSON)
            .expect("access")
            .retry_after
            .is_none());
        for seconds in [5, 10, 20, 40, 60, 60, 60] {
            store.note_unavailable("c");
            let retry_after = store.access("c", PERSON).expect("access").retry_after;
            assert_eq!(
                retry_after,
                Some(harness_clock.now() + Duration::from_secs(seconds))
            );
        }
        let renewed = crate::grants::Renewed {
            access_token: BearerToken::new("renewed-token").expect("token"),
            expires_at: harness_clock.now() + Duration::from_secs(300),
            refresh_token: None,
        };
        store.apply_renewed("c", PERSON, renewed).expect("stored");
        assert!(store
            .access("c", PERSON)
            .expect("access")
            .retry_after
            .is_none());
    }

    #[tokio::test]
    async fn no_more_than_the_refresh_limit_renew_at_once_and_the_rest_use_their_valid_token() {
        let harness = Harness::with_refresh_limit(1);
        let first = harness.sign_in("citizen");
        let second = harness.sign_in("citizen");
        let old = harness.bearer(&second, PERSON);
        harness.clock.advance(Duration::from_secs(250));
        harness.issuer.close_gate();
        let held = spawn_get(&harness, &first, "/check/api/registry/records");
        harness.issuer.refresh_started().await;
        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            harness.get(&second, "/check/api/registry/records"),
        )
        .await
        .expect("answered without the issuer");
        assert_allowed(&reply);
        assert_eq!(reply.authorization(), Some(old));
        assert_eq!(harness.issuer.refresh_calls(), 1);
        harness.issuer.open_gate();
        assert_allowed(&reply_of(held).await);
    }

    async fn reply_of(handle: tokio::task::JoinHandle<Response>) -> Reply {
        reply(handle.await.expect("task")).await
    }

    #[tokio::test]
    async fn a_session_past_its_deadline_while_waiting_for_the_renewal_lock_is_expired() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        harness.clock.advance(Duration::from_secs(301));
        harness.issuer.close_gate();
        let holder = spawn_get(&harness, &cookie, "/check/api/registry/records");
        harness.issuer.refresh_started().await;
        let waiter = spawn_get(&harness, &cookie, "/check/api/registry/records");
        until_waiting(&harness, 1).await;
        let lifetime = harness.config.session.absolute_lifetime_seconds.get();
        harness.clock.advance(Duration::from_secs(lifetime));
        harness.issuer.open_gate();
        assert_problem(
            &reply_of(waiter).await,
            StatusCode::UNAUTHORIZED,
            "session.expired",
        );
        let _ = holder.await;
    }

    #[test]
    fn a_token_is_due_at_the_smaller_of_the_span_and_half_its_lifetime() {
        let clock = ManualClock::new();
        let issued_at = clock.now();
        let access = |lifetime: u64| Access {
            token: BearerToken::new("token-value").expect("token"),
            expires_at: issued_at + Duration::from_secs(lifetime),
            issued_at,
            retry_after: None,
        };
        let span = Duration::from_secs(60);
        assert_eq!(
            access(300).renew_at(span),
            issued_at + Duration::from_secs(240)
        );
        assert_eq!(
            access(120).renew_at(span),
            issued_at + Duration::from_secs(60)
        );
        assert_eq!(
            access(60).renew_at(span),
            issued_at + Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn a_short_lived_token_is_renewed_at_half_its_lifetime_not_on_every_call() {
        let harness = Harness::new();
        let cookie = harness.sign_in_short("citizen", Duration::from_secs(60));
        harness.clock.advance(Duration::from_secs(29));
        assert_allowed(&harness.get(&cookie, "/check/api/registry/records").await);
        assert_eq!(harness.issuer.refresh_calls(), 0);
        harness.clock.advance(Duration::from_secs(1));
        assert_allowed(&harness.get(&cookie, "/check/api/registry/records").await);
        assert_eq!(harness.issuer.refresh_calls(), 1);
    }

    /// Wait until the issuer has been asked `count` times to revoke.
    async fn until_revoked(harness: &Harness, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while harness.issuer.revoke_calls() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the revocations reached the issuer");
    }

    #[tokio::test]
    async fn sessions_that_expire_without_a_sign_out_have_their_refresh_tokens_revoked() {
        let harness = Harness::new();
        let absolute = harness.sign_in("citizen");
        let idle = harness.sign_in("citizen");
        let absolute_token = harness
            .store
            .refresh_token(&absolute, PERSON)
            .expect("refresh");
        let idle_token = harness.store.refresh_token(&idle, PERSON).expect("refresh");
        // One session is used once and then left idle. The other keeps being
        // used until its absolute deadline.
        let idle_lifetime = harness.config.session.idle_lifetime_seconds();
        harness.clock.advance(Duration::from_secs(1000));
        assert!(harness.store.live(&absolute).is_some());
        harness
            .clock
            .advance(Duration::from_secs(idle_lifetime - 1000));
        assert!(harness.store.live(&idle).is_none(), "idle for its lifetime");
        until_revoked(&harness, 1).await;
        assert!(harness.issuer.family_revoked(&idle_token));
        assert!(!harness.issuer.family_revoked(&absolute_token));
        while harness.store.live(&absolute).is_some() {
            harness.clock.advance(Duration::from_secs(1000));
        }
        until_revoked(&harness, 2).await;
        assert!(harness.issuer.family_revoked(&absolute_token));
    }

    #[tokio::test]
    async fn a_refused_renewal_revokes_the_refresh_tokens_of_the_other_audiences() {
        let harness = Harness::new();
        let cookie = harness.sign_in("staff");
        let person = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        let casework = harness
            .store
            .refresh_token(&cookie, CASEWORK)
            .expect("refresh");
        harness
            .issuer
            .revoke("staff", &person)
            .await
            .expect("revoked");
        harness.clock.advance(Duration::from_secs(250));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !harness.issuer.family_revoked(&casework) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the other audience's family was revoked");
    }

    #[tokio::test]
    async fn a_page_allow_removes_the_browsers_authorization_and_cookie_headers() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let page = harness.get(&cookie, "/check/apply/form").await;
        assert_eq!(
            page.header("x-envoy-auth-headers-to-remove"),
            Some("cookie,authorization")
        );
        assert!(page.authorization().is_none());
        let module = harness.get(&cookie, "/check/api/registry/records").await;
        assert_eq!(
            module.header("x-envoy-auth-headers-to-remove"),
            Some("cookie")
        );
        assert!(module.authorization().is_some());
    }

    #[tokio::test]
    async fn a_cross_site_request_to_a_module_is_refused_for_every_method() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let session = harness.cookie_header(&cookie);
        for method in ["GET", "POST", "DELETE"] {
            let reply = harness
                .call(
                    method,
                    "/check/api/registry/records",
                    &[
                        ("cookie", &session),
                        ("registry-client", "page"),
                        ("sec-fetch-site", "cross-site"),
                    ],
                )
                .await;
            assert_problem(&reply, StatusCode::FORBIDDEN, "session.refused");
        }
        let repeated = harness
            .call(
                "GET",
                "/check/api/registry/records",
                &[
                    ("cookie", &session),
                    ("sec-fetch-site", "same-origin"),
                    ("sec-fetch-site", "cross-site"),
                ],
            )
            .await;
        assert_problem(&repeated, StatusCode::FORBIDDEN, "session.refused");
        for site in ["same-origin", "same-site", "none"] {
            let reply = harness
                .call(
                    "GET",
                    "/check/api/registry/records",
                    &[("cookie", &session), ("sec-fetch-site", site)],
                )
                .await;
            assert_allowed(&reply);
        }
    }

    /// The process-wide log buffer. A subscriber installed for the whole process
    /// keeps every callsite enabled, so what a test asserts on does not depend on
    /// which tests ran beside it. The values a test asserts the logs lack are
    /// random per test, so other tests' lines cannot match them.
    fn captured_logs() -> String {
        static BUFFER: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<u8>>>> =
            std::sync::OnceLock::new();
        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("sink").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = BUFFER.get_or_init(|| {
            let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = Sink(buffer.clone());
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(move || sink.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
            buffer
        });
        String::from_utf8(buffer.lock().expect("logs").clone()).expect("utf8")
    }

    #[tokio::test]
    async fn no_log_line_carries_a_cookie_a_token_or_a_path() {
        captured_logs();
        let harness = Harness::new();
        let cookie = harness.sign_in("staff");
        let person = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        let access = harness.bearer(&cookie, PERSON);
        let session = harness.cookie_header(&cookie);
        harness.get(&cookie, "/check/api/registry/records").await;
        harness.get(&cookie, "/check/apply/path-canary").await;
        harness.get(&cookie, "/check/api/nowhere/path-canary").await;
        harness
            .call(
                "POST",
                "/check/api/registry/records",
                &[("cookie", &session)],
            )
            .await;
        // An unreachable issuer, then a refused renewal.
        harness.issuer.set_unavailable(true);
        harness.clock.advance(Duration::from_secs(250));
        harness.get(&cookie, "/check/api/registry/records").await;
        harness.issuer.set_unavailable(false);
        harness.clock.advance(Duration::from_secs(60));
        harness
            .issuer
            .revoke("staff", &person)
            .await
            .expect("revoked");
        harness.get(&cookie, "/check/api/registry/records").await;
        let text = captured_logs();
        assert!(text.contains("session check"), "the check logs its outcome");
        for secret in [
            cookie.as_str(),
            person.expose(),
            "refresh-",
            "access-",
            "canary",
            access.to_str().expect("ascii"),
        ] {
            assert!(!text.contains(secret), "a log line carries a secret value");
        }
    }

    #[tokio::test]
    async fn a_session_ended_during_a_renewal_has_its_rotated_token_revoked() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let original = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        harness.clock.advance(Duration::from_secs(250));
        harness.issuer.close_gate();
        let request = Request::builder()
            .uri("/check/api/registry/records")
            .header("cookie", harness.cookie_header(&cookie))
            .body(Body::empty())
            .expect("request");
        let router = harness.router.clone();
        let call = tokio::spawn(async move { router.oneshot(request).await.expect("response") });
        harness.issuer.refresh_started().await;
        assert!(harness.store.remove(&cookie).is_some());
        harness.issuer.open_gate();
        let reply = reply(call.await.expect("task")).await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        assert_eq!(harness.issuer.refresh_calls(), 1);
        assert_eq!(harness.issuer.revoke_calls(), 1);
        assert!(harness.issuer.family_revoked(&original));
    }

    #[tokio::test]
    async fn a_session_removed_between_the_two_store_reads_is_expired_not_forbidden() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let checker = Checker::new(
            harness.config.clone(),
            harness.store.clone(),
            harness.issuer.clone(),
        );
        let live = harness.store.live(&cookie).expect("live");
        harness.store.remove(&cookie);
        let module = &harness.config.modules[0];
        let decision = checker.module_call(module, &cookie, &live).await;
        assert!(matches!(decision, Decision::Expired), "{decision:?}");
    }

    #[tokio::test]
    async fn renewal_keeps_working_across_rotations() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let mut seen = vec![harness.bearer(&cookie, PERSON)];
        for round in 1..=4 {
            harness.clock.advance(Duration::from_secs(250));
            let reply = harness.get(&cookie, "/check/api/registry/records").await;
            assert_allowed(&reply);
            let token = reply.authorization().expect("token");
            assert!(!seen.contains(&token), "round {round} reuses a token");
            seen.push(token);
            assert_eq!(harness.issuer.refresh_calls(), round);
        }
        let refresh = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        assert!(!harness.issuer.family_revoked(&refresh));
    }

    #[tokio::test]
    async fn a_check_dropped_during_a_refresh_still_stores_the_rotated_token() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let old = harness.bearer(&cookie, PERSON);
        let first_refresh = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        harness.clock.advance(Duration::from_secs(250));
        harness.issuer.close_gate();
        let router = harness.router.clone();
        let request = Request::builder()
            .uri("/check/api/registry/records")
            .header("cookie", harness.cookie_header(&cookie))
            .body(Body::empty())
            .expect("request");
        let task = tokio::spawn(async move { router.oneshot(request).await });
        harness.issuer.refresh_started().await;
        // The gateway gives up: the handler is dropped mid-renewal.
        task.abort();
        assert!(task.await.expect_err("aborted").is_cancelled());
        harness.issuer.open_gate();
        tokio::time::timeout(Duration::from_secs(5), async {
            while harness.bearer(&cookie, PERSON) == old {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the renewal finished and was stored");
        let rotated = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        assert_ne!(rotated.expose(), first_refresh.expose());
        // The next renewal presents the rotated token, not the used one.
        harness.clock.advance(Duration::from_secs(250));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(harness.issuer.refresh_calls(), 2);
        assert!(!harness.issuer.family_revoked(&rotated));
    }

    #[tokio::test]
    async fn invalid_grant_ends_the_session() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let refresh = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        harness
            .issuer
            .revoke("citizen", &refresh)
            .await
            .expect("revoked");
        harness.clock.advance(Duration::from_secs(250));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        assert!(harness.store.live(&cookie).is_none());
        let page = harness.get(&cookie, "/check/apply/form").await;
        assert_eq!(page.status, StatusCode::FOUND);
    }

    #[tokio::test]
    async fn a_reused_refresh_token_ends_the_session() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let refresh = harness
            .store
            .refresh_token(&cookie, PERSON)
            .expect("refresh");
        // Someone else spends the token first.
        harness
            .issuer
            .refresh("citizen", &refresh, PERSON)
            .await
            .expect("spent elsewhere");
        harness.clock.advance(Duration::from_secs(250));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        assert!(harness.store.live(&cookie).is_none());
    }

    #[tokio::test]
    async fn a_transport_failure_allows_an_unexpired_token_and_refuses_an_expired_one() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        harness.issuer.set_unavailable(true);
        harness.clock.advance(Duration::from_secs(250));
        let old = harness.bearer(&cookie, PERSON);
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(reply.authorization(), Some(old));
        assert_eq!(harness.issuer.refresh_calls(), 1);
        harness.clock.advance(Duration::from_secs(60));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(
            &reply,
            StatusCode::SERVICE_UNAVAILABLE,
            "session.unavailable",
        );
        assert!(harness.store.live(&cookie).is_some(), "the session is kept");
        // The refresh token was never spent, so the issuer coming back recovers
        // once the backoff has passed.
        harness.issuer.set_unavailable(false);
        harness.clock.advance(Duration::from_secs(10));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(reply.authorization(), Some(harness.bearer(&cookie, PERSON)));
    }

    #[tokio::test]
    async fn a_session_without_a_refresh_token_lasts_as_long_as_its_token() {
        let harness = Harness::new();
        let cookie = harness.sign_in_with("citizen", false);
        let old = harness.bearer(&cookie, PERSON);
        harness.clock.advance(Duration::from_secs(250));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_allowed(&reply);
        assert_eq!(reply.authorization(), Some(old));
        harness.clock.advance(Duration::from_secs(60));
        let reply = harness.get(&cookie, "/check/api/registry/records").await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "session.expired");
        assert!(harness.store.live(&cookie).is_none());
        assert_eq!(harness.issuer.refresh_calls(), 0);
    }

    // Step 7 and the listener.

    #[tokio::test]
    async fn every_allow_removes_the_cookie_and_every_denial_is_no_store() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        assert_allowed(&harness.get(&cookie, "/check/apply/").await);
        assert_allowed(&harness.get(&cookie, "/check/api/registry/x").await);
        for (target, status, code) in [
            (
                "/check/api/casework/x",
                StatusCode::FORBIDDEN,
                "session.refused",
            ),
            ("/check/nowhere/", StatusCode::FORBIDDEN, "session.refused"),
        ] {
            assert_problem(&harness.get(&cookie, target).await, status, code);
        }
    }

    #[tokio::test]
    async fn a_denial_carries_no_value_from_the_request() {
        let harness = Harness::new();
        let cookie = harness.sign_in("citizen");
        let reply = harness
            .get(&cookie, "/check/api/casework/secret-path-canary")
            .await;
        let text = String::from_utf8(reply.body.clone()).expect("utf8");
        assert!(!text.contains("canary"), "{text}");
        assert!(!text.contains(&cookie), "{text}");
    }

    #[tokio::test]
    async fn health_routes_answer_without_a_session() {
        let harness = Harness::new();
        for target in ["/healthz", "/readyz"] {
            let reply = harness.call("GET", target, &[]).await;
            assert_eq!(reply.status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn the_public_router_helper_tells_a_check_route_from_none() {
        assert!(testing::answers_404_for_check(Router::new()).await);
        let harness = Harness::new();
        assert!(!testing::answers_404_for_check(harness.router.clone()).await);
    }
}
