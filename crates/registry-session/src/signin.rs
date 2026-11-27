// SPDX-License-Identifier: Apache-2.0

//! Sign-in: the OpenID Connect authorization code flow with PKCE, a state, a
//! nonce and an RFC 8707 resource, once per audience of the kind of sign-in.
//! Every hop is one top-level redirect. All hops complete or no session
//! opens, and the refresh tokens already obtained are revoked.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::check::{clean_path, session_cookie};
use crate::config::Route;
use crate::grants::{GrantError, Grants, Redeemer, Redemption, RefreshToken};
use crate::journal::{Action, Outcome};
use crate::pages::{self, Failure};
use crate::public::{html, rate_limited, App};
use crate::store::{random_token, tokens_match, AudienceGrant, PendingSignIn, Person, Session};
use crate::wire::{problem, ProblemKind, ANSWER_MARKER_HEADER, ANSWER_MARKER_VALUE};

/// The longest return path, in bytes.
const MAXIMUM_RETURN_BYTES: usize = 2048;

/// The query parameters of `query`, refusing any repeated name.
fn single_valued(query: &str) -> Option<Vec<(String, String)>> {
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

/// The return path and the kind of sign-in it needs: the one `return`
/// parameter, a path the configured pages cover, normalized as the check
/// normalizes, with an optional query.
fn return_target<G>(app: &App<G>, query: Option<&str>) -> Option<(String, String)> {
    let pairs = single_valued(query?)?;
    let [(name, value)] = pairs.as_slice() else {
        return None;
    };
    if name != "return"
        || value.len() > MAXIMUM_RETURN_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    let path = value
        .split_once('?')
        .map_or(value.as_str(), |(path, _)| path);
    if !clean_path(path) {
        return None;
    }
    match app.config.route(path)? {
        Route::Page(page) => Some((value.clone(), page.sign_in.as_str().to_owned())),
        Route::Module(_) => None,
    }
}

fn fresh() -> Option<String> {
    random_token()
        .inspect_err(|error| tracing::error!(%error, "the operating system random source failed"))
        .ok()
}

/// The secrets of one hop and the cookie value its pending sign-in lives under.
struct HopSecrets {
    state: String,
    nonce: String,
    verifier: Zeroizing<String>,
    cookie: String,
}

impl HopSecrets {
    fn new() -> Option<Self> {
        Some(Self {
            state: fresh()?,
            nonce: fresh()?,
            verifier: Zeroizing::new(fresh()?),
            cookie: fresh()?,
        })
    }
}

/// The issuer's authorization endpoint with this hop's request.
fn authorization_location<G>(
    app: &App<G>,
    kind: &str,
    audience: &str,
    secrets: &HopSecrets,
) -> Option<String> {
    let sign_in = app.config.sign_in(kind)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(secrets.verifier.as_bytes()));
    let mut scopes = vec!["openid".to_owned()];
    scopes.extend(sign_in.scopes.iter().map(|scope| scope.as_str().to_owned()));
    let mut location = url::Url::parse(app.config.issuer.authorization.as_str()).ok()?;
    location
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", sign_in.client_id.as_str())
        .append_pair("redirect_uri", &app.redirect_uri())
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", &secrets.state)
        .append_pair("nonce", &secrets.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", audience);
    Some(location.to_string())
}

fn lifetime<G>(app: &App<G>) -> Duration {
    Duration::from_secs(app.config.session.sign_in_lifetime_seconds.get())
}

fn authorize_redirect<G>(app: &App<G>, location: &str, flow_cookie: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        header::HeaderValue::from_str(location).expect("a built URL is header-safe"),
    );
    headers.append(
        header::SET_COOKIE,
        app.cookie(
            app.config.flow_cookie(),
            flow_cookie,
            lifetime(app).as_secs(),
        ),
    );
    response
}

/// `GET /session/sign-in?return=<path>`: start a sign-in and send the browser
/// to the issuer.
pub(crate) async fn start<G: Grants + Redeemer>(
    State(app): State<Arc<App<G>>>,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(wait) = app.admit_sign_in().await {
        return rate_limited(wait);
    }
    let Some((return_to, kind)) = return_target(&app, query.as_deref()) else {
        return problem(ProblemKind::ReturnRefused, StatusCode::BAD_REQUEST);
    };
    let audiences: Vec<String> = app
        .config
        .audience_set(&kind)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let (Some(first), Some(secrets)) = (audiences.first().cloned(), HopSecrets::new()) else {
        return problem(ProblemKind::Internal, StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(location) = authorization_location(&app, &kind, &first, &secrets) else {
        return problem(ProblemKind::Internal, StatusCode::INTERNAL_SERVER_ERROR);
    };
    let pending = PendingSignIn::new(
        kind,
        return_to,
        audiences,
        secrets.state.clone(),
        secrets.nonce.clone(),
        secrets.verifier.to_string(),
    );
    if app
        .store
        .begin_sign_in(&secrets.cookie, pending, lifetime(&app))
        .is_err()
    {
        return problem(ProblemKind::Busy, StatusCode::SERVICE_UNAVAILABLE);
    }
    authorize_redirect(&app, &location, &secrets.cookie)
}

/// What a callback decided.
enum Step {
    /// More audiences remain: send the browser to the issuer again.
    Next {
        location: String,
        flow_cookie: String,
    },
    /// The session is open.
    Done {
        session_cookie: String,
        return_to: String,
        max_age: u64,
    },
    Failed {
        failure: Failure,
        return_to: Option<String>,
    },
}

/// `GET /session/callback`: redeem the code, verify the ID token, and either
/// ask for the next audience or open the session. The flow cookie is cleared
/// whatever the outcome, unless a further hop refreshes it.
pub(crate) async fn callback<G: Grants + Redeemer>(
    State(app): State<Arc<App<G>>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let flow_name = app.config.flow_cookie();
    let step = complete(&app, query.as_deref(), &headers).await;
    let mut response = match step {
        Step::Next {
            location,
            flow_cookie,
        } => return authorize_redirect(&app, &location, &flow_cookie),
        Step::Done {
            session_cookie,
            return_to,
            max_age,
        } => {
            let mut response = html(StatusCode::OK, pages::continue_to(&return_to));
            response.headers_mut().append(
                header::SET_COOKIE,
                app.cookie(app.config.session_cookie(), &session_cookie, max_age),
            );
            response
        }
        Step::Failed { failure, return_to } => {
            let status = match failure {
                Failure::Refused => StatusCode::BAD_REQUEST,
                Failure::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                Failure::Unavailable | Failure::AuditUnavailable | Failure::Busy => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            };
            let mut response = html(status, pages::failed(failure, return_to.as_deref()));
            response.headers_mut().insert(
                header::HeaderName::from_static(ANSWER_MARKER_HEADER),
                header::HeaderValue::from_static(ANSWER_MARKER_VALUE),
            );
            response
        }
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, app.clear_cookie(flow_name));
    response
}

/// End a sign-in that cannot finish: revoke every refresh token it holds,
/// including `extra`, and audit the refusal.
async fn abandon<G: Grants>(
    app: &App<G>,
    pending: PendingSignIn,
    extra: Vec<RefreshToken>,
    failure: Failure,
) -> Step {
    let mut tokens: Vec<RefreshToken> = pending
        .grants
        .iter()
        .filter_map(|grant| grant.refresh_token.clone())
        .collect();
    tokens.extend(extra);
    app.revoke_all(&pending.kind, &tokens).await;
    let person = pending
        .person
        .as_ref()
        .and_then(|person| app.journal.person(&person.subject).ok());
    if let Err(error) = app
        .journal
        .record(
            Action::SignIn,
            &pending.kind,
            person.as_deref(),
            Outcome::Refused,
        )
        .await
    {
        tracing::error!(%error, "a refused sign-in could not be audited");
    }
    Step::Failed {
        failure,
        return_to: Some(pending.return_to),
    }
}

/// The claims `whoAmI.claims` allows, from the verified ID token's claims.
fn allowed_claims<G>(app: &App<G>, claims: &Map<String, Value>) -> Map<String, Value> {
    app.config
        .who_am_i
        .claim_names()
        .into_iter()
        .filter_map(|name| claims.get(&name).cloned().map(|value| (name, value)))
        .collect()
}

async fn complete<G: Grants + Redeemer>(
    app: &App<G>,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Step {
    // Taking the pending sign-in consumes it, so a replayed callback finds
    // nothing, whatever it carries. It is taken before the limit admits the
    // callback, so a throttled callback ends its flow too.
    let pending = session_cookie(headers, app.config.flow_cookie())
        .and_then(|cookie| app.store.finish_sign_in(cookie));
    if let Err(_wait) = app.admit_sign_in().await {
        if let Some(pending) = pending {
            let tokens: Vec<RefreshToken> = pending
                .grants
                .iter()
                .filter_map(|grant| grant.refresh_token.clone())
                .collect();
            app.revoke_all(&pending.kind, &tokens).await;
        }
        return Step::Failed {
            failure: Failure::RateLimited,
            return_to: None,
        };
    }
    let Some(mut pending) = pending else {
        return Step::Failed {
            failure: Failure::Refused,
            return_to: None,
        };
    };
    let Some(pairs) = query.and_then(single_valued) else {
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let state_matches =
        parameter(&pairs, "state").is_some_and(|state| tokens_match(state, &pending.state));
    if !state_matches {
        tracing::info!("a sign-in callback carried the wrong state");
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    }
    // RFC 9207: the issuer always names itself, so its absence is a refusal.
    if parameter(&pairs, "iss") != Some(app.config.issuer.id.as_str()) {
        tracing::info!("a sign-in callback named no issuer or another one");
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    }
    if parameter(&pairs, "error").is_some() {
        tracing::info!("the issuer returned an error instead of a code");
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    }
    let Some(code) = parameter(&pairs, "code").filter(|code| !code.is_empty()) else {
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let Some(audience) = pending.audience().map(str::to_owned) else {
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };

    let redirect_uri = app.redirect_uri();
    let redeemed = app
        .grants
        .redeem(&Redemption {
            kind: &pending.kind,
            code,
            verifier: &pending.verifier,
            redirect_uri: &redirect_uri,
            resource: &audience,
            nonce: &pending.nonce,
        })
        .await;
    let redeemed = match redeemed {
        Ok(redeemed) => redeemed,
        Err(GrantError::Unavailable) => {
            tracing::warn!("the authorization code could not be redeemed");
            return abandon(app, pending, Vec::new(), Failure::Unavailable).await;
        }
        Err(GrantError::Refused) => {
            tracing::warn!("the authorization code or the ID token was refused");
            return abandon(app, pending, Vec::new(), Failure::Refused).await;
        }
    };

    if let Some(person) = &pending.person {
        if redeemed.subject != person.subject {
            tracing::warn!("a later sign-in hop named another person");
            let extra = redeemed.refresh_token.into_iter().collect();
            return abandon(app, pending, extra, Failure::Refused).await;
        }
    } else if redeemed.subject.is_empty() {
        let extra = redeemed.refresh_token.into_iter().collect();
        return abandon(app, pending, extra, Failure::Refused).await;
    } else {
        // The per-person limit applies to every request that names a person,
        // sign-in included.
        let admitted = match app.journal.person(&redeemed.subject) {
            Ok(person) => App::<G>::admit(&app.per_person, &person).await.is_ok(),
            Err(_) => false,
        };
        if !admitted {
            let extra = redeemed.refresh_token.into_iter().collect();
            return abandon(app, pending, extra, Failure::RateLimited).await;
        }
        pending.person = Some(Person {
            subject: redeemed.subject.clone(),
            claims: allowed_claims(app, &redeemed.claims),
        });
    }
    let Some(refresh_token) = redeemed.refresh_token else {
        tracing::error!(
            "the issuer returned no refresh token: the sign-in client needs the refresh grant"
        );
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let grant = AudienceGrant {
        audience,
        access_token: redeemed.access_token,
        expires_at: redeemed.expires_at,
        refresh_token: Some(refresh_token),
    };

    if !pending.is_last_hop() {
        return next_hop(app, pending, grant).await;
    }
    open_session(app, pending, grant).await
}

/// Put the pending sign-in back for the next audience under a fresh flow
/// cookie, and point the browser at the issuer again.
async fn next_hop<G: Grants + Redeemer>(
    app: &App<G>,
    mut pending: PendingSignIn,
    grant: AudienceGrant,
) -> Step {
    let Some(secrets) = HopSecrets::new() else {
        pending.grants.push(grant);
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    pending.advance(
        grant,
        secrets.state.clone(),
        secrets.nonce.clone(),
        secrets.verifier.to_string(),
    );
    let location = pending
        .audience()
        .and_then(|audience| authorization_location(app, &pending.kind, audience, &secrets));
    let Some(location) = location else {
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let (kind, return_to) = (pending.kind.clone(), pending.return_to.clone());
    let tokens: Vec<RefreshToken> = pending
        .grants
        .iter()
        .filter_map(|grant| grant.refresh_token.clone())
        .collect();
    if app
        .store
        .begin_sign_in(&secrets.cookie, pending, lifetime(app))
        .is_err()
    {
        app.revoke_all(&kind, &tokens).await;
        return Step::Failed {
            failure: Failure::Busy,
            return_to: Some(return_to),
        };
    }
    Step::Next {
        location,
        flow_cookie: secrets.cookie,
    }
}

/// Audit the sign-in, open the session, and release the cookie.
async fn open_session<G: Grants + Redeemer>(
    app: &App<G>,
    mut pending: PendingSignIn,
    last: AudienceGrant,
) -> Step {
    pending.grants.push(last);
    let Some(person) = pending.person.take() else {
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let (Some(cookie), Ok(pseudonym)) = (fresh(), app.journal.person(&person.subject)) else {
        tracing::error!("a session identifier or a person pseudonym could not be derived");
        return abandon(app, pending, Vec::new(), Failure::Refused).await;
    };
    let absolute = Duration::from_secs(app.config.session.absolute_lifetime_seconds.get());
    let kind = pending.kind.clone();
    let return_to = pending.return_to.clone();
    let session = Session::new(
        kind.clone(),
        app.config.issuer.id.as_str().to_owned(),
        person.subject.clone(),
        person.claims,
        pending.grants,
        app.store.now() + absolute,
    );
    let tokens = session.refresh_tokens();
    // Every fallible step comes before the insert, because nothing brings an
    // ended session back: the audit confirms the sign-in, then the store takes
    // the session. A store that is full after the audit is audited as refused.
    if let Err(error) = app
        .journal
        .record(Action::SignIn, &kind, Some(&pseudonym), Outcome::Ok)
        .await
    {
        tracing::error!(%error, "the sign-in could not be audited");
        app.revoke_all(&kind, &tokens).await;
        return Step::Failed {
            failure: Failure::AuditUnavailable,
            return_to: Some(return_to),
        };
    }
    let Ok(replaced) = app.store.insert(&cookie, session) else {
        app.revoke_all(&kind, &tokens).await;
        if let Err(error) = app
            .journal
            .record(Action::SignIn, &kind, Some(&pseudonym), Outcome::Refused)
            .await
        {
            tracing::error!(%error, "a refused sign-in could not be audited");
        }
        return Step::Failed {
            failure: Failure::Busy,
            return_to: Some(return_to),
        };
    };
    // The person's oldest sessions ended to make room: their tokens go too.
    for ended in replaced.sessions() {
        app.revoke_all(ended.kind(), &ended.refresh_tokens()).await;
    }
    Step::Done {
        session_cookie: cookie,
        return_to,
        max_age: absolute.as_secs(),
    }
}
