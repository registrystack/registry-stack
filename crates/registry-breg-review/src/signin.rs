// SPDX-License-Identifier: Apache-2.0

//! Sign-in: the OpenID Connect authorization code flow with PKCE, a state,
//! a nonce, and an RFC 8707 resource, redeemed by a `private_key_jwt`
//! confidential client. The access token stays in the server-side session;
//! the browser holds only a random session identifier.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_httputil::client::TokenError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::journal::{Action, Operation, Outcome};
use crate::session::{random_token, tokens_match, PendingSignIn, Session, Store};
use crate::{canonical_uuid, cookie, App, Problem};

/// The only path a sign-in may return to is a request page.
const RETURN_PREFIX: &str = "/requests/";

/// Removes a newly inserted session if the callback is cancelled or terminal
/// audit fails before the browser receives its cookie.
struct SessionRollback<'a> {
    sessions: &'a Store,
    cookie: &'a str,
    armed: bool,
}

impl<'a> SessionRollback<'a> {
    fn armed(sessions: &'a Store, cookie: &'a str) -> Self {
        Self {
            sessions,
            cookie,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for SessionRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.sessions.remove(self.cookie);
        }
    }
}

/// The query parameters of `query`, refusing any repeated name.
pub(crate) fn single_valued(query: &str) -> Option<Vec<(String, String)>> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if pairs.iter().any(|(seen, _)| *seen == name) {
            return None;
        }
        pairs.push((name.into_owned(), value.into_owned()));
    }
    Some(pairs)
}

fn parameter<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

/// The request identifier named by the one `return` parameter, which must be
/// exactly `/requests/{canonical uuid}` and nothing else.
fn return_request(query: Option<&str>) -> Option<String> {
    let pairs = single_valued(query?)?;
    let [(name, value)] = pairs.as_slice() else {
        return None;
    };
    if name != "return" {
        return None;
    }
    let request_id = value.strip_prefix(RETURN_PREFIX)?;
    canonical_uuid(request_id).then(|| request_id.to_owned())
}

fn fresh(app: &App) -> Result<String, Response> {
    random_token().map_err(|error| {
        tracing::error!(%error, "the operating system random source failed");
        app.problem(Problem::Internal)
    })
}

/// `GET /signin?return=/requests/{id}`: start a sign-in and send the browser
/// to the provider.
pub(crate) async fn start(State(app): State<Arc<App>>, RawQuery(query): RawQuery) -> Response {
    match begin(&app, query.as_deref()).await {
        Ok(response) | Err(response) => response,
    }
}

async fn begin(app: &App, query: Option<&str>) -> Result<Response, Response> {
    app.admit_sign_in().await?;
    let request_id =
        return_request(query).ok_or_else(|| app.problem(Problem::ReturnPathRefused))?;
    let state = fresh(app)?;
    let nonce = fresh(app)?;
    let verifier = Zeroizing::new(fresh(app)?);
    let cookie_value = fresh(app)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let mut location = app.authorization_endpoint.clone();
    location
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &app.client_id)
        .append_pair("redirect_uri", app.redirect_uri.as_str())
        .append_pair("scope", &format!("openid {}", app.scopes.join(" ")))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", &app.resource);
    let location = HeaderValue::from_str(location.as_str()).map_err(|_| {
        tracing::error!("the authorization request is not a valid header value");
        app.problem(Problem::Internal)
    })?;

    app.sessions
        .begin_sign_in(
            &cookie_value,
            PendingSignIn::new(
                request_id,
                state,
                nonce,
                verifier.to_string(),
                app.sign_in_lifetime,
            ),
        )
        .map_err(|_| app.problem(Problem::SignInsExhausted))?;
    // The provider returns the browser with a cross-site top-level GET, which
    // carries a Lax cookie and not a Strict one.
    let sign_in = app.cookies.set(
        app.cookies.sign_in,
        &cookie_value,
        app.sign_in_lifetime.as_secs(),
        "Lax",
    );
    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location), (header::SET_COOKIE, sign_in)],
    )
        .into_response())
}

/// `GET /signin/callback`: redeem the code, verify the ID token, and open a
/// session. The sign-in cookie is cleared whatever the outcome.
pub(crate) async fn callback(
    State(app): State<Arc<App>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut response = match complete(&app, query.as_deref(), &headers).await {
        Ok(response) | Err(response) => response,
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        app.cookies.clear(app.cookies.sign_in, "Lax"),
    );
    response
}

async fn complete(
    app: &App,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    app.admit_sign_in().await?;
    let refused = || app.problem(Problem::SignInRefused);
    // Taking the pending sign-in consumes it, so a replayed callback finds
    // nothing, whatever it carries.
    let pending = cookie(headers, app.cookies.sign_in)
        .and_then(|value| app.sessions.finish_sign_in(value))
        .ok_or_else(refused)?;
    let pairs = query.and_then(single_valued).ok_or_else(refused)?;
    let state = parameter(&pairs, "state").ok_or_else(refused)?;
    if !tokens_match(state, &pending.state) {
        tracing::info!("a sign-in callback carried the wrong state");
        return Err(refused());
    }
    match parameter(&pairs, "iss") {
        Some(iss) if iss != app.issuer => {
            tracing::info!("a sign-in callback named another issuer");
            return Err(refused());
        }
        None if app.requires_iss => {
            tracing::info!("a sign-in callback omitted the issuer the provider promises");
            return Err(refused());
        }
        _ => {}
    }
    // State and issuer admission happen before the audit boundary: malformed
    // or untrusted callbacks do not create an operation in another person's
    // name. Every terminal outcome for a valid pending flow is audited.
    let operation = app
        .journal
        .begin(Action::SignIn, None, None)
        .await
        .map_err(|error| {
            tracing::error!(%error, "a sign-in request could not be audited");
            app.problem(Problem::AuditUnavailable)
        })?;
    if parameter(&pairs, "error").is_some() {
        tracing::info!("the provider returned an error instead of a code");
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    }
    let Some(code) = parameter(&pairs, "code").filter(|code| !code.is_empty()) else {
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    };

    let redeemed = match app
        .sign_in_client
        .redeem_authorization_code(code, &app.redirect_uri, &pending.verifier)
        .await
    {
        Ok(redeemed) => redeemed,
        Err(error) => {
            tracing::warn!(%error, "the authorization code could not be redeemed");
            let (outcome, problem) = match error {
                TokenError::Transport { .. } | TokenError::Unavailable => {
                    (Outcome::Failed, Problem::SignInUnavailable)
                }
                _ => (Outcome::Refused, Problem::SignInRefused),
            };
            return Err(finish_problem(app, operation, outcome, problem).await);
        }
    };
    let Some(id_token) = redeemed.id_token() else {
        tracing::warn!("the token response carried no ID token");
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    };
    let verified = match app.verifier.verify_related_token(id_token).await {
        Ok(verified) => verified,
        Err(error) => {
            tracing::warn!(%error, "the ID token was refused");
            return Err(
                finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await,
            );
        }
    };
    let nonce = verified
        .claims
        .extra
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !tokens_match(nonce, &pending.nonce) {
        tracing::warn!("the ID token carried the wrong nonce");
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    }
    let Some(subject) = verified
        .claims
        .sub
        .as_deref()
        .filter(|subject| !subject.is_empty())
    else {
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    };
    // A session never outlives its access token, so a token without a
    // stated lifetime opens none.
    let Some(token_expiry) = redeemed.expires_at() else {
        tracing::warn!("the access token has no stated lifetime");
        return Err(finish_problem(app, operation, Outcome::Refused, Problem::SignInRefused).await);
    };
    let expires_at = token_expiry.min(Instant::now() + app.maximum_session);

    let citizen = match app.journal.citizen(&app.issuer, subject) {
        Ok(citizen) => citizen,
        Err(_) => {
            tracing::error!("a citizen pseudonym could not be derived");
            return Err(finish_problem(app, operation, Outcome::Failed, Problem::Internal).await);
        }
    };
    let session_cookie = match fresh(app) {
        Ok(value) => value,
        Err(_) => {
            return Err(finish_problem(app, operation, Outcome::Failed, Problem::Internal).await)
        }
    };
    let csrf = match fresh(app) {
        Ok(value) => value,
        Err(_) => {
            return Err(finish_problem(app, operation, Outcome::Failed, Problem::Internal).await)
        }
    };
    // The session is opened before the sign-in is audited: it is cheap,
    // in-memory, and reversible, so a browser that never receives it never
    // has a "succeeded" audit record made in its name. An audit failure
    // after this point removes the session again rather than leave it
    // behind unconfirmed.
    let registry = Arc::new(app.registry.with_bearer_token(redeemed.into_access_token()));
    if app
        .sessions
        .insert(
            &session_cookie,
            Session::new(citizen.clone(), registry, csrf, expires_at),
        )
        .is_err()
    {
        return Err(
            finish_problem(app, operation, Outcome::Refused, Problem::SessionsExhausted).await,
        );
    }
    let rollback = SessionRollback::armed(&app.sessions, &session_cookie);
    if let Err(error) = operation.finish(Outcome::Succeeded, Some(&citizen)).await {
        tracing::error!(%error, "the sign-in could not be audited");
        return Err(app.problem(Problem::AuditUnavailable));
    }
    rollback.disarm();

    let max_age = expires_at
        .saturating_duration_since(Instant::now())
        .as_secs();
    let set_session = app
        .cookies
        .set(app.cookies.session, &session_cookie, max_age, "Strict");
    // The session cookie is Strict, so it would not accompany a redirect
    // that began on the provider's site. A same-origin page continues
    // instead.
    let mut response = app.rendered(
        StatusCode::OK,
        app.templates.continue_to(&pending.request_id),
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, set_session);
    Ok(response)
}

/// Record a known sign-in outcome, with audit unavailability taking priority
/// over the product refusal because no unaudited terminal answer is released.
async fn finish_problem(
    app: &App,
    operation: Operation,
    outcome: Outcome,
    problem: Problem,
) -> Response {
    if let Err(error) = operation.finish(outcome, None).await {
        tracing::error!(%error, "a sign-in response could not be audited");
        return app.problem(Problem::AuditUnavailable);
    }
    app.problem(problem)
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::time::Duration;

    use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};

    use super::*;

    const ID: &str = "3f6c8a3e-0b8e-4c52-9d0e-6a4f1c2b7d10";

    #[test]
    fn only_one_canonical_request_path_is_a_return_path() {
        assert_eq!(
            return_request(Some(&format!("return=%2Frequests%2F{ID}"))).as_deref(),
            Some(ID)
        );
        for query in [
            String::new(),
            "return=".to_owned(),
            format!("return=%2Frequests%2F{ID}&other=1"),
            format!("return=%2Frequests%2F{ID}&return=%2Frequests%2F{ID}"),
            format!("next=%2Frequests%2F{ID}"),
            format!("return=%2Frequests%2F{ID}%2F"),
            format!("return=https%3A%2F%2Fevil.example%2Frequests%2F{ID}"),
        ] {
            assert_eq!(return_request(Some(&query)), None, "{query}");
        }
        assert_eq!(return_request(None), None);
    }

    #[tokio::test]
    async fn cancelling_terminal_audit_rolls_back_the_unreleased_session() {
        let store = Store::new(1, 1);
        let cookie = random_token().unwrap();
        let registry = BaseRegistryClient::new(BaseRegistryClientConfig::new(
            url::Url::parse("https://registry.example").unwrap(),
        ))
        .unwrap();
        store
            .insert(
                &cookie,
                Session::new(
                    "citizen".to_owned(),
                    Arc::new(registry),
                    "csrf".to_owned(),
                    std::time::Instant::now() + Duration::from_secs(60),
                ),
            )
            .unwrap();

        let mut cancelled = Box::pin(async {
            let _rollback = SessionRollback::armed(&store, &cookie);
            pending::<()>().await;
        });
        tokio::select! {
            biased;
            () = &mut cancelled => unreachable!("the terminal audit model never completes"),
            () = tokio::task::yield_now() => {}
        }
        drop(cancelled);

        assert!(store.current(&cookie).is_none());
    }
}
