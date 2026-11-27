// SPDX-License-Identifier: Apache-2.0

//! The public listener: the routes the gateway sends under `/session/` and
//! nothing else. Every answer is `no-store`, `nosniff` and `no-referrer`, and
//! HTML answers carry a content security policy that allows nothing.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};
use axum::Router;
use registry_platform_ratelimit::token_bucket::{TokenBucketError, TokenBucketLimiter};
use serde_json::{json, Value};

use crate::check::{session_cookie, single_header};
use crate::config::RuntimeConfig;
use crate::grants::{Grants, Redeemer};
use crate::journal::{Action, Journal, Outcome};
use crate::pages;
use crate::signin;
use crate::store::Store;
use crate::wire::{problem, ProblemKind};

/// The one key of the global sign-in limit.
const GLOBAL_SIGN_IN_KEY: &str = "global";

/// Everything a public handler shares.
pub(crate) struct App<G> {
    pub config: Arc<RuntimeConfig>,
    pub store: Arc<Store>,
    pub grants: G,
    pub journal: Arc<Journal>,
    /// One bucket for everyone on the unauthenticated sign-in routes.
    pub global_sign_in: TokenBucketLimiter,
    /// Keyed by the person a session names.
    pub per_person: TokenBucketLimiter,
}

impl<G> App<G> {
    pub(crate) fn redirect_uri(&self) -> String {
        format!("{}/session/callback", self.config.origin())
    }

    /// A `Set-Cookie` value for `name`: HttpOnly, `SameSite=Lax`, host-only,
    /// and `Secure` except under development loopback.
    pub(crate) fn cookie(&self, name: &str, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.config.development() {
            ""
        } else {
            "; Secure"
        };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
        ))
        .expect("cookie names, tokens and attributes are header-safe")
    }

    pub(crate) fn clear_cookie(&self, name: &str) -> HeaderValue {
        self.cookie(name, "", 0)
    }

    /// Admit one request against `limiter`, or the time to wait.
    pub(crate) async fn admit(limiter: &TokenBucketLimiter, key: &str) -> Result<(), Duration> {
        match limiter.check(key, 1).await {
            Ok(()) => Ok(()),
            Err(TokenBucketError::Exceeded { retry_after }) => {
                Err(retry_after.max(Duration::from_secs(1)))
            }
            Err(error) => {
                tracing::warn!(%error, "a rate limit refused a request");
                Err(Duration::from_secs(1))
            }
        }
    }

    pub(crate) async fn admit_sign_in(&self) -> Result<(), Duration> {
        Self::admit(&self.global_sign_in, GLOBAL_SIGN_IN_KEY).await
    }
}

pub(crate) fn rate_limited(retry_after: Duration) -> Response {
    let mut response = problem(ProblemKind::RateLimited, StatusCode::TOO_MANY_REQUESTS);
    let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    response
}

/// The router for the public listener.
pub(crate) fn router<G: Grants + Redeemer>(app: Arc<App<G>>) -> Router {
    Router::new()
        .route("/session/sign-in", guarded(get(signin::start::<G>)))
        .route("/session/callback", guarded(get(signin::callback::<G>)))
        .route("/session/me", guarded(get(me::<G>)))
        .route("/session/sign-out", guarded(post(sign_out::<G>)))
        .route("/session/signed-out", guarded(get(signed_out)))
        .fallback(not_found)
        .with_state(app)
        .layer(middleware::map_response(harden))
}

fn guarded<S: Clone + Send + Sync + 'static>(route: MethodRouter<S>) -> MethodRouter<S> {
    route.fallback(method_not_allowed)
}

async fn not_found() -> Response {
    problem(ProblemKind::NotFound, StatusCode::NOT_FOUND)
}

async fn method_not_allowed() -> Response {
    problem(
        ProblemKind::MethodNotAllowed,
        StatusCode::METHOD_NOT_ALLOWED,
    )
}

/// The headers every public answer carries.
async fn harden(mut response: Response) -> Response {
    let html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if html {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    response
}

pub(crate) fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// `GET /session/me`: the session behind the cookie, without renewing it.
async fn me<G: Grants + Redeemer>(State(app): State<Arc<App<G>>>, headers: HeaderMap) -> Response {
    let cookie = session_cookie(&headers, app.config.session_cookie());
    let found = cookie.and_then(|cookie| {
        let live = app.store.live(cookie)?;
        let claims = app.store.claims(cookie)?;
        let person = app.store.person(cookie)?;
        Some((live.kind, claims, person))
    });
    let Some((kind, claims, (issuer, subject))) = found else {
        return problem(ProblemKind::Expired, StatusCode::UNAUTHORIZED);
    };
    if let Ok(person) = app.journal.person_at(&issuer, &subject) {
        if let Err(wait) = App::<G>::admit(&app.per_person, &person).await {
            return rate_limited(wait);
        }
    }
    (
        StatusCode::OK,
        axum::Json(json!({ "signIn": kind, "claims": Value::Object(claims) })),
    )
        .into_response()
}

/// Whether a sign-out request comes from the service's own page: an `Origin`
/// equal to the public origin, or the page header with no `Origin`, and a
/// `Sec-Fetch-Site` of `same-origin` when present.
fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    let from_origin = match single_header(headers, "origin") {
        Ok(Some(value)) => value == origin,
        Ok(None) => single_header(headers, "registry-client") == Ok(Some("page")),
        Err(()) => false,
    };
    from_origin
        && single_header(headers, "sec-fetch-site")
            .is_ok_and(|value| value.is_none_or(|v| v == "same-origin"))
}

fn redirect(status: StatusCode, location: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).expect("a validated location is header-safe"),
    );
    response
}

/// `POST /session/sign-out`: end the session here at once and at the issuer.
/// The session is removed, audited and its cookie cleared before any issuer
/// call: the refresh tokens go to the revocation queue, so a slow issuer
/// cannot hold the sign-out or leave the session alive. Sign-out is never
/// rate limited.
async fn sign_out<G: Grants + Redeemer>(
    State(app): State<Arc<App<G>>>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers, &app.config.origin()) {
        return problem(ProblemKind::Refused, StatusCode::FORBIDDEN);
    }
    let name = app.config.session_cookie();
    let ended = session_cookie(&headers, name).and_then(|cookie| app.store.remove(cookie));
    let mut response = match ended {
        Some(session) => {
            let person = app
                .journal
                .person_at(session.issuer(), session.subject())
                .ok();
            let queued = app
                .store
                .revoke_later(session.kind(), session.refresh_tokens());
            let outcome = if queued {
                Outcome::Ok
            } else {
                Outcome::RevocationFailed
            };
            if let Err(error) = app
                .journal
                .record(Action::SignOut, session.kind(), person.as_deref(), outcome)
                .await
            {
                tracing::error!(%error, "a sign-out could not be audited");
            }
            match end_session_location(&app, session.kind()) {
                Some(location) => redirect(StatusCode::SEE_OTHER, &location),
                None => redirect(StatusCode::SEE_OTHER, "/session/signed-out"),
            }
        }
        None => redirect(StatusCode::SEE_OTHER, "/session/signed-out"),
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, app.clear_cookie(name));
    response
}

/// The issuer's end-session endpoint with the kind's client and the page to
/// return to. No `id_token_hint`: the service keeps no ID token. A kind the
/// configuration does not know has no client to name, so the person lands on
/// the signed-out page instead.
fn end_session_location<G>(app: &App<G>, kind: &str) -> Option<String> {
    let Some(sign_in) = app.config.sign_in(kind) else {
        tracing::error!("a session names a kind of sign-in the configuration lacks");
        return None;
    };
    let mut location = url::Url::parse(app.config.issuer.end_session.as_str())
        .expect("the configuration validated the end-session endpoint");
    location
        .query_pairs_mut()
        .append_pair("client_id", sign_in.client_id.as_str())
        .append_pair(
            "post_logout_redirect_uri",
            &format!("{}/session/signed-out", app.config.origin()),
        );
    Some(location.to_string())
}

async fn signed_out() -> Response {
    html(StatusCode::OK, pages::signed_out())
}
