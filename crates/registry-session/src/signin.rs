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
    headers: HeaderMap,
) -> Response {
    // The shared sign-in limit is charged only for a start that names a page
    // the service can send the person back to, so requests that are refused
    // anyway do not drain it. Callbacks are not charged: a callback needs the
    // pending sign-in a charged start created.
    let Some((return_to, kind)) = return_target(&app, query.as_deref()) else {
        return problem(ProblemKind::ReturnRefused, StatusCode::BAD_REQUEST);
    };
    if let Err(wait) = app.admit_sign_in().await {
        return rate_limited(wait);
    }
    // A flow cookie the browser already presents belongs to a sign-in it
    // walked away from: that sign-in ends here, and the refresh tokens of the
    // hops it finished are revoked.
    if let Some(abandoned) = session_cookie(&headers, app.config.flow_cookie()) {
        app.store.abandon_sign_in(abandoned);
    }
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
///
/// The work runs in its own task, so a request the gateway or the browser
/// gives up on cannot stop it halfway and drop refresh tokens the issuer
/// already issued. When nobody is left to receive the answer, a session it
/// opened is ended and its tokens revoked.
pub(crate) async fn callback<G: Grants + Redeemer>(
    State(app): State<Arc<App<G>>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let flow_name = app.config.flow_cookie();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = app.clone();
    tokio::spawn(async move {
        let step = complete(&worker, query.as_deref(), &headers).await;
        if let Err(unheard) = sender.send(step) {
            discard(&worker, unheard).await;
        }
    });
    let Ok(step) = receiver.await else {
        tracing::error!("a sign-in callback task ended without an answer");
        return problem(ProblemKind::Internal, StatusCode::INTERNAL_SERVER_ERROR);
    };
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

/// What to do with a step nobody will read: a session it opened never reaches
/// the browser, so it ends and its tokens are revoked. A further hop's pending
/// sign-in stays in the store until it expires and is reaped.
async fn discard<G: Grants>(app: &App<G>, step: Step) {
    if let Step::Done { session_cookie, .. } = step {
        tracing::warn!("a sign-in finished after its request was given up on");
        if let Some(session) = app.store.remove(&session_cookie) {
            end_audited(app, &session).await;
        }
    }
}

/// Queue the refresh tokens of a session that ended without a sign-out and
/// audit its end.
async fn end_audited<G>(app: &App<G>, session: &Session) {
    app.store.release(session);
    let Ok(person) = app.journal.person_at(session.issuer(), session.subject()) else {
        tracing::error!("a person pseudonym could not be derived");
        return;
    };
    if let Err(error) = app
        .journal
        .record(
            Action::SessionEnded,
            session.kind(),
            Some(&person),
            Outcome::Ok,
        )
        .await
    {
        tracing::error!(%error, "a session end could not be audited");
    }
}

/// Audit a sign-in the service refused after it had a valid pending sign-in.
async fn audit_refusal<G>(app: &App<G>, kind: &str, subject: Option<&str>) {
    let person = subject.and_then(|subject| app.journal.person(subject).ok());
    if let Err(error) = app
        .journal
        .record(Action::SignIn, kind, person.as_deref(), Outcome::Refused)
        .await
    {
        tracing::error!(%error, "a refused sign-in could not be audited");
    }
}

/// End a sign-in that cannot finish: queue every refresh token it holds,
/// including `extra`, for revocation, and audit the refusal.
async fn abandon<G: Grants>(
    app: &App<G>,
    pending: PendingSignIn,
    extra: Vec<RefreshToken>,
    failure: Failure,
) -> Step {
    let mut tokens = pending.refresh_tokens();
    tokens.extend(extra);
    app.store.revoke_later(&pending.kind, tokens);
    audit_refusal(
        app,
        &pending.kind,
        pending
            .person
            .as_ref()
            .map(|person| person.subject.as_str()),
    )
    .await;
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
    // nothing, whatever it carries.
    let pending = session_cookie(headers, app.config.flow_cookie())
        .and_then(|cookie| app.store.finish_sign_in(cookie));
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
        issued_at: app.store.now(),
        refresh_token: Some(refresh_token),
    };

    if !pending.is_last_hop() {
        return next_hop(app, pending, grant).await;
    }
    let previous = session_cookie(headers, app.config.session_cookie());
    open_session(app, pending, grant, previous).await
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
    let subject = pending.person.as_ref().map(|person| person.subject.clone());
    let tokens = pending.refresh_tokens();
    if app
        .store
        .begin_sign_in(&secrets.cookie, pending, lifetime(app))
        .is_err()
    {
        app.store.revoke_later(&kind, tokens);
        audit_refusal(app, &kind, subject.as_deref()).await;
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

/// Audit the sign-in, open the session, and release the cookie. A session the
/// browser already presents (`previous`) ends: whoever signs in through a
/// browser replaces whoever was signed in there.
async fn open_session<G: Grants + Redeemer>(
    app: &App<G>,
    mut pending: PendingSignIn,
    last: AudienceGrant,
    previous: Option<&str>,
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
        app.store.revoke_later(&kind, tokens);
        return Step::Failed {
            failure: Failure::AuditUnavailable,
            return_to: Some(return_to),
        };
    }
    let Ok(replaced) = app.store.insert(&cookie, session) else {
        app.store.revoke_later(&kind, tokens);
        audit_refusal(app, &kind, Some(&person.subject)).await;
        return Step::Failed {
            failure: Failure::Busy,
            return_to: Some(return_to),
        };
    };
    // The person's oldest sessions ended to make room, and the session this
    // browser held: their tokens go too.
    for ended in replaced.sessions() {
        end_audited(app, ended).await;
    }
    if let Some(held) = previous.and_then(|held| app.store.remove(held)) {
        end_audited(app, &held).await;
    }
    Step::Done {
        session_cookie: cookie,
        return_to,
        max_age: absolute.as_secs(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use registry_platform_audit::{AuditProfile, AuditWriter};
    use registry_platform_httputil::BearerToken;
    use registry_platform_ratelimit::token_bucket::{TokenBucketConfig, TokenBucketLimiter};
    use tower::ServiceExt;

    use super::*;
    use crate::clock::SystemClock;
    use crate::grants::{GrantError, Redeemed, Renewed};
    use crate::journal::Journal;
    use crate::public::router;
    use crate::store::Store;

    /// An issuer double for the production posture, whose plain-HTTP token
    /// endpoint the real client could not reach.
    struct Issuer {
        redemptions: AtomicUsize,
        /// Fills the pending store while a redemption is in flight, so the
        /// next hop finds it full.
        crowd: Option<Arc<Store>>,
    }

    impl Redeemer for Issuer {
        async fn redeem(&self, _redemption: &Redemption<'_>) -> Result<Redeemed, GrantError> {
            let count = self.redemptions.fetch_add(1, Ordering::SeqCst);
            if let Some(store) = &self.crowd {
                let crowded = PendingSignIn::new(
                    "citizen".to_owned(),
                    "/apply/".to_owned(),
                    vec!["urn:x".to_owned()],
                    "s".to_owned(),
                    "n".to_owned(),
                    "v".to_owned(),
                );
                store
                    .begin_sign_in("crowd", crowded, Duration::from_secs(60))
                    .expect("room for the crowd");
            }
            Ok(Redeemed {
                access_token: BearerToken::new(format!("access-{count}")).expect("token"),
                expires_at: Instant::now() + Duration::from_secs(300),
                refresh_token: Some(RefreshToken::new(format!("refresh-{count}")).expect("token")),
                subject: "person-1".to_owned(),
                claims: Map::new(),
            })
        }
    }

    impl Grants for Issuer {
        async fn refresh(
            &self,
            _kind: &str,
            _refresh_token: &RefreshToken,
            _resource: &str,
        ) -> Result<Renewed, GrantError> {
            Err(GrantError::Refused)
        }

        async fn revoke(&self, _kind: &str, _token: &RefreshToken) -> Result<(), GrantError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The production runtime file served over a double issuer.
    fn production(crowd_the_store: bool) -> (Router, Arc<Store>, Sink) {
        let config = Arc::new(
            crate::config::tests::load(&crate::config::tests::document())
                .expect("the production document loads"),
        );
        let store = Arc::new(Store::new(
            Arc::new(SystemClock),
            config.session.sessions(),
            if crowd_the_store {
                1
            } else {
                config.session.pending_sign_ins()
            },
        ));
        let sink = Sink::default();
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![7; 32]))
            .expect("audit profile");
        let journal = Arc::new(
            Journal::new(
                AuditWriter::from_line_sink_without_posture(Box::new(sink.clone())),
                profile.key_hasher(),
                config.issuer.id.as_str(),
                config
                    .sign_ins
                    .iter()
                    .map(|sign_in| (sign_in.id.as_str(), sign_in.client_id.as_str())),
            )
            .expect("journal"),
        );
        let limiter = |requests_per_minute, burst| {
            TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute,
                burst,
            })
            .expect("limiter")
        };
        let issuer = Issuer {
            redemptions: AtomicUsize::new(0),
            crowd: crowd_the_store.then(|| store.clone()),
        };
        let app = Arc::new(App {
            config,
            store: store.clone(),
            grants: issuer,
            journal,
            global_sign_in: limiter(6000, 600),
            per_person: limiter(6000, 600),
        });
        (router(app), store, sink)
    }

    async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
        router.clone().oneshot(request).await.expect("a response")
    }

    fn set_cookies(response: &axum::response::Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("ascii").to_owned())
            .collect()
    }

    fn cookie_named(response: &axum::response::Response, name: &str) -> String {
        set_cookies(response)
            .into_iter()
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("a {name} cookie"))
    }

    fn pair(cookie: &str) -> String {
        cookie.split(';').next().expect("a pair").to_owned()
    }

    fn state_of(response: &axum::response::Response) -> String {
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("a location")
            .to_str()
            .expect("ascii");
        url::Url::parse(location)
            .expect("url")
            .query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.into_owned())
            .expect("a state")
    }

    fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request.body(Body::empty()).expect("request")
    }

    fn callback_path(state: &str) -> String {
        format!("/session/callback?code=c&state={state}&iss=https%3A%2F%2Fid.example")
    }

    /// Every attribute of the cookies a production service sets, end to end:
    /// the `__Host-` names, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` and
    /// no `Domain`, at sign-in, at the callback and at sign-out.
    #[tokio::test]
    async fn production_cookies_are_host_prefixed_secure_host_only_and_small() {
        let (router, _store, _sink) = production(false);
        let started = send(&router, get("/session/sign-in?return=%2Fapply%2F", None)).await;
        assert_eq!(started.status(), StatusCode::FOUND);
        let flow = cookie_named(&started, crate::config::FLOW_COOKIE);
        let state = state_of(&started);

        let done = send(&router, get(&callback_path(&state), Some(&pair(&flow)))).await;
        assert_eq!(done.status(), StatusCode::OK);
        let session = cookie_named(&done, crate::config::SESSION_COOKIE);
        let cleared_flow = cookie_named(&done, crate::config::FLOW_COOKIE);
        let sign_out = Request::post("/session/sign-out")
            .header(header::COOKIE, pair(&session))
            .header("origin", "https://app.example")
            .body(Body::empty())
            .expect("request");
        let out = send(&router, sign_out).await;
        assert_eq!(out.status(), StatusCode::SEE_OTHER);
        let cleared_session = cookie_named(&out, crate::config::SESSION_COOKIE);

        for cookie in [&flow, &session, &cleared_flow, &cleared_session] {
            for attribute in ["; Path=/", "; HttpOnly", "; SameSite=Lax", "; Secure"] {
                assert!(cookie.contains(attribute), "{attribute} is missing");
            }
            assert!(cookie.starts_with("__Host-"), "the name is host-prefixed");
            assert!(!cookie.contains("Domain"), "the cookie is host-only");
        }
        assert!(session.contains("Max-Age=28800"));
        assert!(cleared_flow.contains("Max-Age=0"));
        assert!(cleared_session.contains("Max-Age=0"));

        // The browser sends both names back on every call: the whole header
        // stays well inside the limits proxies and servers apply.
        let header = format!("{}; {}", pair(&session), pair(&flow));
        assert!(header.len() <= 150, "{} bytes", header.len());
    }

    #[tokio::test]
    async fn a_refusal_between_hops_is_audited_and_revokes_the_first_hops_token() {
        let (router, store, sink) = production(true);
        let started = send(&router, get("/session/sign-in?return=%2Fstaff%2F", None)).await;
        assert_eq!(started.status(), StatusCode::FOUND);
        let flow = cookie_named(&started, crate::config::FLOW_COOKIE);
        let state = state_of(&started);

        // The first hop returns while another sign-in took the only slot.
        let refused = send(&router, get(&callback_path(&state), Some(&pair(&flow)))).await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        let audit = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8");
        assert!(audit.contains("\"action\":\"sign-in\""), "{audit}");
        assert!(audit.contains("refused"), "{audit}");
        assert_eq!(store.session_count(), 0);
    }
}
