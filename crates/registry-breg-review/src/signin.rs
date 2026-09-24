// SPDX-License-Identifier: Apache-2.0

//! Sign-in: the OpenID Connect authorization code flow with PKCE, a state,
//! a nonce, and an RFC 8707 resource, redeemed by a `private_key_jwt`
//! confidential client. The access token stays in the server-side session;
//! the browser holds only a random session identifier.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_httputil::client::TokenError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::journal::{Action, Outcome};
use crate::session::{random_token, tokens_match, PendingSignIn, Session};
use crate::{canonical_uuid, cookie, App, Problem};

/// The only path a sign-in may return to is a request page.
const RETURN_PREFIX: &str = "/requests/";

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
pub(crate) async fn start(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
) -> Response {
    match begin(&app, peer, query.as_deref()).await {
        Ok(response) | Err(response) => response,
    }
}

async fn begin(app: &App, peer: SocketAddr, query: Option<&str>) -> Result<Response, Response> {
    let address = app.address(peer)?;
    app.admit_address(&address).await?;
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
        .map_err(|_| app.problem(Problem::SessionsExhausted))?;
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut response = match complete(&app, peer, query.as_deref(), &headers).await {
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
    peer: SocketAddr,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let address = app.address(peer)?;
    app.admit_address(&address).await?;
    let refused = || app.problem(Problem::SignInRefused);
    // Taking the pending sign-in consumes it, so a replayed callback finds
    // nothing, whatever it carries.
    let pending = cookie(headers, app.cookies.sign_in)
        .and_then(|value| app.sessions.finish_sign_in(value))
        .ok_or_else(refused)?;
    let pairs = query.and_then(single_valued).ok_or_else(refused)?;
    if parameter(&pairs, "error").is_some() {
        tracing::info!("the provider returned an error instead of a code");
        return Err(refused());
    }
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
    let code = parameter(&pairs, "code")
        .filter(|code| !code.is_empty())
        .ok_or_else(refused)?;

    let redeemed = app
        .sign_in_client
        .redeem_authorization_code(code, &app.redirect_uri, &pending.verifier)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "the authorization code could not be redeemed");
            match error {
                TokenError::Transport { .. } | TokenError::Unavailable => {
                    app.problem(Problem::SignInUnavailable)
                }
                _ => refused(),
            }
        })?;
    let id_token = redeemed.id_token().ok_or_else(|| {
        tracing::warn!("the token response carried no ID token");
        refused()
    })?;
    let verified = app
        .verifier
        .verify_related_token(id_token)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "the ID token was refused");
            refused()
        })?;
    let nonce = verified
        .claims
        .extra
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !tokens_match(nonce, &pending.nonce) {
        tracing::warn!("the ID token carried the wrong nonce");
        return Err(refused());
    }
    let subject = verified
        .claims
        .sub
        .as_deref()
        .filter(|subject| !subject.is_empty())
        .ok_or_else(refused)?;
    // A session never outlives its access token, so a token without a
    // stated lifetime opens none.
    let token_expiry = redeemed.expires_at().ok_or_else(|| {
        tracing::warn!("the access token has no stated lifetime");
        refused()
    })?;
    let expires_at = token_expiry.min(Instant::now() + app.maximum_session);

    let citizen = app.journal.citizen(&app.issuer, subject).map_err(|_| {
        tracing::error!("a citizen pseudonym could not be derived");
        app.problem(Problem::Internal)
    })?;
    let session_cookie = fresh(app)?;
    let csrf = fresh(app)?;
    if let Err(error) = app
        .journal
        .record(
            Action::SignIn,
            Outcome::Succeeded,
            Some(&citizen),
            &address,
            None,
        )
        .await
    {
        tracing::error!(%error, "the sign-in could not be audited");
        return Err(app.problem(Problem::AuditUnavailable));
    }
    let registry = Arc::new(app.registry.with_bearer_token(redeemed.into_access_token()));
    app.sessions
        .insert(
            &session_cookie,
            Session::new(citizen, registry, csrf, expires_at),
        )
        .map_err(|_| app.problem(Problem::SessionsExhausted))?;

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

#[cfg(test)]
mod tests {
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
}
