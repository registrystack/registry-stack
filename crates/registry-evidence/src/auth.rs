//! Strict OIDC access-token authentication and configured claim extraction.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    actor_kind, grant_claims, ActorKind, Audience, ClaimError, ClaimNames, GrantClaims,
    GrantContextError, JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier,
    TokenVerifierConfig, VerifiedToken,
};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::config::{
    AccessTokenAlgorithm, AccessTokenType, AssuranceProfile, AuthenticationConfig,
};

const MAX_PRINCIPAL_BYTES: usize = 512;
const MAX_TAGS: usize = 32;

/// How long an unreachable issuer key set stays quiet after it has been named
/// once.
///
/// A deployment that cannot reach the key set rejects every request, so the
/// unthrottled report is one log line per request: the fault would bury the
/// traffic that revealed it, and a caller could provoke the writing. One line a
/// minute names it and keeps naming it while it lasts.
const KEY_SOURCE_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// How long a failed readiness probe is trusted before another is attempted.
///
/// Readiness is polled on a schedule the service does not choose. Without this,
/// a probe every second against an issuer that is down is an outbound request
/// every second, from every replica. A successful probe needs no equivalent:
/// the verifier's own cache answers it without a request.
const KEY_SOURCE_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Stands in for the key-set location in the log when there is none to name.
///
/// Only an in-memory key set reaches this, which no deployment configures.
const STATIC_KEY_SOURCE: &str = "<static key set>";

/// How many causes below the reported error are rendered.
///
/// `reqwest` reports a transport failure as "error sending request" and keeps
/// the reason underneath it: the connection that was refused, the certificate
/// that did not verify. That reason is the whole diagnosis, and it is two or
/// three levels down.
const REPORTED_CAUSES: usize = 3;

/// The bound on the rendered cause, which is remote text in part.
const MAX_CAUSE_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct AuthenticationClaimsConfig {
    pub principal_claim: String,
    pub requester_tags_claim: String,
    pub evidence_audience_claim: String,
    pub contextual_claims: ClaimNames,
    pub actor_claim: Option<String>,
}

#[derive(Clone)]
pub struct Authenticator {
    verifier: Arc<TokenVerifier>,
    claims: AuthenticationClaimsConfig,
    /// Scopes every token must carry, checked after verification and before
    /// any authority claim is read. Empty keeps the no-scope-gate behavior.
    /// Client admission is not held here: it is configured on the platform
    /// verifier, in its documented `client_id`/`azp` semantics.
    required_scopes: Vec<String>,
    /// Resource identifiers accepted by the verifier. A task grant must name
    /// the one member that actually matched the token audience.
    resources: Vec<String>,
    key_source: Arc<Mutex<KeySourceState>>,
}

/// What is known about the issuer key set, and when it was last said aloud.
///
/// Shared rather than copied when the authenticator is cloned, so the two
/// intervals bound the process and not each handle.
#[derive(Debug, Default)]
struct KeySourceState {
    /// When the failure was last written to the log.
    last_reported: Option<Instant>,
    /// When a readiness probe last failed, and so has not been retried since.
    last_failed_probe: Option<Instant>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AuthenticatedContext {
    principal: String,
    actor: Option<String>,
    actor_kind: ActorKind,
    client: Option<String>,
    requester_tags: Vec<String>,
    evidence_audience: String,
    task_grant: Result<Option<GrantClaims>, TaskGrantError>,
    verified_claims: Value,
}

/// A redacted reason a present task-grant context cannot be trusted.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TaskGrantError {
    #[error("task-grant claims are invalid")]
    Claims,
    #[error("task-grant principal does not match the authenticated principal")]
    PrincipalMismatch,
    #[error("task-grant client context is invalid")]
    Client,
    #[error("task-grant resource context is invalid")]
    Resource,
}

impl AuthenticatedContext {
    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    pub const fn actor_kind(&self) -> ActorKind {
        self.actor_kind
    }

    pub fn client(&self) -> Option<&str> {
        self.client.as_deref()
    }

    pub fn requester_tags(&self) -> &[String] {
        &self.requester_tags
    }

    pub fn evidence_audience(&self) -> &str {
        &self.evidence_audience
    }

    pub fn grant_id(&self) -> Option<&str> {
        self.grant().ok().flatten().map(GrantClaims::id)
    }

    pub fn grant_authority(&self) -> Option<&str> {
        self.grant().ok().flatten().map(GrantClaims::authority)
    }

    pub fn grant(&self) -> Result<Option<&GrantClaims>, TaskGrantError> {
        self.task_grant
            .as_ref()
            .map(Option::as_ref)
            .map_err(|error| *error)
    }

    pub fn claim_path(&self, path: &str) -> Option<&Value> {
        resolve_claim_path(&self.verified_claims, path)
    }

    /// Construct a context for the bundle-owned, offline fixture command.
    ///
    /// This is crate-private so no production caller can bypass token
    /// verification. The public fixture harness still runs the normal
    /// authorization and selector-resolution functions over this context.
    pub(crate) fn offline_fixture_context(
        requester_tags: Vec<String>,
        evidence_audience: &str,
        actor_kind: ActorKind,
        client: Option<&str>,
        task_grant: Result<Option<GrantClaims>, TaskGrantError>,
        verified_claims: Value,
    ) -> Self {
        Self {
            principal: "offline-fixture-principal".to_owned(),
            actor: None,
            actor_kind,
            client: client.map(ToOwned::to_owned),
            requester_tags,
            evidence_audience: evidence_audience.to_owned(),
            task_grant,
            verified_claims,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_context(
        principal: &str,
        requester_tags: Vec<String>,
        evidence_audience: &str,
        task_grant: Result<Option<GrantClaims>, TaskGrantError>,
        verified_claims: Value,
    ) -> Self {
        let mut context = Self::offline_fixture_context(
            requester_tags,
            evidence_audience,
            ActorKind::Service,
            None,
            task_grant,
            verified_claims,
        );
        context.principal = principal.to_owned();
        context
    }
}

impl std::fmt::Debug for AuthenticatedContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedContext")
            .field("principal", &"<redacted>")
            .field("actor", &self.actor.as_ref().map(|_| "<redacted>"))
            .field("actor_kind", &self.actor_kind)
            .field("client", &self.client.as_ref().map(|_| "<redacted>"))
            .field("requester_tags", &"<redacted>")
            .field("evidence_audience", &self.evidence_audience)
            .field(
                "task_grant",
                &self.task_grant.as_ref().map(|_| "<redacted>"),
            )
            .field("verified_claims", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("access token is malformed")]
    Malformed,
    #[error("access token verification failed")]
    Verification,
    #[error("required authenticated context is missing or invalid")]
    Context,
    #[error("access token is bound to a sender proof this profile cannot validate")]
    SenderConstrained,
}

/// RFC 7800 confirmation claim. Its presence means the authorization server
/// issued a token that is only valid when presented with a matching proof of
/// possession, such as DPoP or mutual TLS.
const CONFIRMATION_CLAIM: &str = "cnf";

impl Authenticator {
    /// Build the one strict resource-server profile from the loaded bundle.
    pub fn from_config(config: &AuthenticationConfig, assurance_profile: AssuranceProfile) -> Self {
        let algorithms = config
            .algorithms
            .iter()
            .map(|algorithm| match algorithm {
                AccessTokenAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
                AccessTokenAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
                AccessTokenAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            })
            .collect();
        let token_types = config
            .token_types
            .iter()
            .map(|token_type| match token_type {
                AccessTokenType::AtJwt => "at+jwt".to_owned(),
                AccessTokenType::ApplicationAtJwt => "application/at+jwt".to_owned(),
            })
            .collect();
        let verifier_config = TokenVerifierConfig::access_token_profile(
            config.issuer.clone(),
            config.audiences.clone(),
            algorithms,
            token_types,
        )
        .with_denied_kids(config.revoked_key_ids.iter().cloned().collect())
        .with_max_token_lifetime(Some(Duration::from_secs(
            config.maximum_token_lifetime_seconds,
        )))
        .with_allowed_clients(config.allowed_clients.clone().unwrap_or_default());
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            config.jwks_uri.clone(),
            JwksFetcherConfig::defaults(),
            jwks_fetch_policy(config, assurance_profile),
        ));
        let verifier = Arc::new(TokenVerifier::new(verifier_config, fetcher));
        let claims = AuthenticationClaimsConfig {
            principal_claim: config.principal_claim.clone(),
            requester_tags_claim: config.requester_tags_claim.clone(),
            evidence_audience_claim: config.evidence_audience_claim.clone(),
            contextual_claims: config.claims.clone(),
            actor_claim: config.actor_claim.clone(),
        };
        Self::new(verifier, claims)
            .with_required_scopes(config.required_scopes.clone().unwrap_or_default())
            .with_resources(config.audiences.clone())
    }

    pub fn new(verifier: Arc<TokenVerifier>, claims: AuthenticationClaimsConfig) -> Self {
        Self {
            verifier,
            claims,
            required_scopes: Vec::new(),
            resources: Vec::new(),
            key_source: Arc::new(Mutex::new(KeySourceState::default())),
        }
    }

    /// State the scopes every token must carry. An empty list keeps the
    /// permissive default, which is the behavior a configuration that states
    /// no `requiredScopes` means.
    #[must_use]
    pub fn with_required_scopes(mut self, required_scopes: Vec<String>) -> Self {
        self.required_scopes = required_scopes;
        self
    }

    #[must_use]
    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources;
        self
    }

    pub async fn authenticate(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        strict_jwt_preflight(access_token)?;
        let verified = match self.verifier.verify(access_token).await {
            Ok(verified) => verified,
            Err(error) => {
                if is_key_source_failure(&error) {
                    self.report_key_source_failure(&error);
                }
                return Err(AuthenticationError::Verification);
            }
        };
        // The scope gate reads only the verified token's scope set. It runs
        // after signature verification and before any authority claim is
        // read, so a token that lacks a required scope reaches no protected
        // source operation and no authority interpretation. A missing scope
        // is never inferred from tags, principal, roles, `sub`, or request
        // fields, and the refusal is the same closed authentication failure a
        // refused client admission gets.
        if !self.required_scopes.is_empty() {
            let present: std::collections::HashSet<&str> =
                verified.scopes.iter().map(String::as_str).collect();
            if !self
                .required_scopes
                .iter()
                .all(|scope| present.contains(scope.as_str()))
            {
                return Err(AuthenticationError::Verification);
            }
        }
        self.extract_context(verified)
    }

    /// Ask the issuer for its key set on a readiness check, and name what comes
    /// back, without letting the answer decide readiness.
    ///
    /// Readiness answers whether this deployment should be sent traffic, and
    /// the honest answer during an issuer outage is yes: the verifier keeps
    /// serving a key set it cannot recheck for a bounded while, so requests
    /// carrying tokens signed by keys already held still succeed. Withholding
    /// readiness would take every replica out of rotation at once for a
    /// dependency none of them owns, which is the shape of a cascading failure
    /// rather than a diagnosis. So the probe reports and the report is the
    /// point: an operator watching this deployment is told the issuer has gone
    /// quiet while requests still work, and told again when the allowance is
    /// what stands between them and rejecting everything.
    ///
    /// A failed probe is remembered for a short interval, so an orchestrator's
    /// polling schedule cannot become this deployment's retry schedule against
    /// an issuer that is down.
    pub async fn probe_key_source(&self) {
        if self.probe_is_suppressed(Instant::now()) {
            return;
        }
        match self.verifier.key_source().ensure_key_set().await {
            Ok(()) => {
                self.lock_key_source().last_failed_probe = None;
                self.report_key_source_outage().await;
            }
            Err(error) => {
                self.report_key_source_failure(&error);
                self.lock_key_source().last_failed_probe = Some(Instant::now());
            }
        }
    }

    /// Require the configured JWKS endpoint to provide a usable key set now.
    ///
    /// Serving readiness deliberately tolerates a bounded issuer outage. A
    /// deployment preflight has different semantics: before first traffic, an
    /// operator needs a fail-closed answer that the configured key transport
    /// is reachable and usable.
    pub async fn key_source_ready(&self) -> bool {
        self.verifier.key_source().ensure_key_set().await.is_ok()
    }

    /// Attempt the issuer's key set once at startup, and name it if it cannot
    /// be had.
    ///
    /// A misspelled or unreachable `jwksUri` is otherwise discovered one
    /// rejected request at a time, and the rejection an operator sees is the
    /// same closed `401` a bad token gets. Startup is where an operator is
    /// looking, so startup is where it should be said.
    ///
    /// It reports rather than refuses, for the same reason readiness does:
    /// refusing would tie this deployment's start to the issuer's, so a restart
    /// during an issuer outage could not come back, and an issuer that starts
    /// alongside this service would race it.
    pub async fn announce_key_source(&self) {
        if let Err(error) = self.verifier.key_source().ensure_key_set().await {
            self.report_key_source_failure(&error);
        }
    }

    /// Whether the last probe failed recently enough to stand for this one.
    fn probe_is_suppressed(&self, now: Instant) -> bool {
        self.lock_key_source()
            .last_failed_probe
            .is_some_and(|failed| now.duration_since(failed) < KEY_SOURCE_PROBE_INTERVAL)
    }

    /// Name an unreachable issuer key set, at most once per interval.
    ///
    /// The caller learns nothing from this. Their rejection is the same closed
    /// `401` whether the token was bad or this deployment could not check it,
    /// which is the right answer to give a caller and the reason the operator
    /// has nothing else to go on. The distinction exists only here.
    fn report_key_source_failure(&self, error: &OidcError) {
        if !self.claim_report_interval(Instant::now()) {
            return;
        }
        tracing::warn!(
            target: "registry_evidence::authentication",
            jwks_uri = self
                .verifier
                .key_source()
                .jwks_uri()
                .unwrap_or(STATIC_KEY_SOURCE),
            cause = describe_causes(error),
            "the access-token issuer key set could not be retrieved; every request is rejected until it can be"
        );
    }

    /// Name a key set that is being served without being confirmed, at most
    /// once per interval.
    ///
    /// Nothing else would say so. The verifier keeps serving a key set it
    /// cannot recheck, so requests succeed, readiness holds, and the only
    /// thing that has changed is that the issuer has stopped answering. That
    /// is worth an operator's attention before the allowance runs out and the
    /// deployment starts rejecting everything.
    async fn report_key_source_outage(&self) {
        let Some(outage) = self.verifier.key_source().outage_duration().await else {
            return;
        };
        if !self.claim_report_interval(Instant::now()) {
            return;
        }
        tracing::warn!(
            target: "registry_evidence::authentication",
            jwks_uri = self
                .verifier
                .key_source()
                .jwks_uri()
                .unwrap_or(STATIC_KEY_SOURCE),
            outage_seconds = outage.as_secs(),
            "the access-token issuer key set has not been retrievable; the key set already held is still being accepted, and requests will be rejected once its allowance runs out"
        );
    }

    /// Take the reporting interval if it is free, so exactly one caller logs.
    fn claim_report_interval(&self, now: Instant) -> bool {
        let mut state = self.lock_key_source();
        if state
            .last_reported
            .is_some_and(|reported| now.duration_since(reported) < KEY_SOURCE_REPORT_INTERVAL)
        {
            return false;
        }
        state.last_reported = Some(now);
        true
    }

    /// Recover the guard even from a poisoned lock: the state behind it is two
    /// timestamps, which a panicking holder cannot leave inconsistent, and
    /// readiness must not panic because a report once did.
    fn lock_key_source(&self) -> MutexGuard<'_, KeySourceState> {
        self.key_source
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn extract_context(
        &self,
        verified: VerifiedToken,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        let actor_kind = actor_kind(&verified.claims, &self.claims.contextual_claims)
            .map_err(|_| AuthenticationError::Context)?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthenticationError::Context)?
            .as_secs();
        let mut task_grant =
            grant_claims(&verified.claims, &self.claims.contextual_claims, now_unix)
                .map_err(|_: ClaimError| TaskGrantError::Claims);
        let claims =
            serde_json::to_value(&verified.claims).map_err(|_| AuthenticationError::Context)?;
        let claims_object = claims.as_object().ok_or(AuthenticationError::Context)?;

        // Version one validates no proof of possession. Treating a
        // sender-constrained token as an ordinary bearer would silently discard
        // the constraint the authorization server issued it under and make a
        // stolen token replayable for its whole lifetime, so the profile denies
        // rather than downgrades.
        if claims_object.contains_key(CONFIRMATION_CLAIM) {
            return Err(AuthenticationError::SenderConstrained);
        }

        let principal = required_direct_string(
            claims_object,
            &self.claims.principal_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        let evidence_audience = required_direct_string(
            claims_object,
            &self.claims.evidence_audience_claim,
            MAX_PRINCIPAL_BYTES,
        )?;
        url::Url::parse(&evidence_audience).map_err(|_| AuthenticationError::Context)?;
        let requester_tags =
            required_string_array(claims_object, &self.claims.requester_tags_claim, MAX_TAGS)?;
        let actor = self
            .claims
            .actor_claim
            .as_deref()
            .map(|claim| optional_direct_string(claims_object, claim, MAX_PRINCIPAL_BYTES))
            .transpose()?
            .flatten();
        if let Ok(Some(grant)) = &task_grant {
            if grant.principal() != principal {
                task_grant = Err(TaskGrantError::PrincipalMismatch);
            } else {
                match exactly_matched_resource(verified.claims.aud.as_ref(), &self.resources) {
                    Some(resource) => {
                        if let Err(error) = grant.verify_context(&verified, resource) {
                            task_grant = Err(match error {
                                GrantContextError::MissingVerifiedClient
                                | GrantContextError::InvalidVerifiedClient
                                | GrantContextError::ClientMismatch => TaskGrantError::Client,
                                GrantContextError::ResourceMismatch => TaskGrantError::Resource,
                                _ => TaskGrantError::Claims,
                            });
                        }
                    }
                    None => task_grant = Err(TaskGrantError::Resource),
                }
            }
        }
        let client = verified
            .matched_client_id()
            .ok()
            .flatten()
            .or(verified.claims.azp.as_deref())
            .or(verified.claims.client_id.as_deref())
            .map(ToOwned::to_owned);

        Ok(AuthenticatedContext {
            principal,
            actor,
            actor_kind,
            client,
            requester_tags,
            evidence_audience,
            task_grant,
            verified_claims: claims,
        })
    }
}

fn exactly_matched_resource<'a>(
    audience: Option<&'a Audience>,
    resources: &[String],
) -> Option<&'a str> {
    let matched = match audience? {
        Audience::One(value) => resources
            .contains(value)
            .then_some(value.as_str())
            .into_iter()
            .collect(),
        Audience::Many(values) => values
            .iter()
            .filter(|value| resources.contains(*value))
            .map(String::as_str)
            .collect::<Vec<_>>(),
    };
    match matched.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn jwks_fetch_policy(
    config: &AuthenticationConfig,
    assurance_profile: AssuranceProfile,
) -> FetchUrlPolicy {
    if config.uses_local_issuer_http(assurance_profile) {
        return FetchUrlPolicy {
            allowed_schemes: vec!["http".to_owned()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: true,
            deny_cloud_metadata: true,
        };
    }
    FetchUrlPolicy {
        allowed_schemes: vec!["https".to_owned()],
        allow_localhost: true,
        allow_http_private_network: false,
        deny_private_ranges: false,
        deny_cloud_metadata: true,
    }
}

/// Whether a verification failure was this deployment's key source rather than
/// the caller's token.
///
/// Every known failure is listed rather than folded into the wildcard, which
/// covers only variants added to the shared verifier after this was written.
/// Those default to the caller's side: a failure this code has never seen is
/// one it cannot honestly describe as an unreachable key set, and an operator
/// misdirected by a confident wrong message is worse off than one who reads
/// the same `auth.invalid_credential` twice.
fn is_key_source_failure(error: &OidcError) -> bool {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk
        | OidcError::EmptyKeySet
        | OidcError::MissingIssuer => true,
        OidcError::IssuerMismatch { .. }
        | OidcError::MalformedToken
        | OidcError::AlgorithmNotAllowed
        | OidcError::TokenTypeNotAllowed
        | OidcError::MissingKid
        | OidcError::KidTooLong
        | OidcError::UnknownKid
        | OidcError::TokenExpired
        | OidcError::TokenNotYetValid
        | OidcError::AudienceMismatch
        | OidcError::SignatureInvalid
        | OidcError::InvalidToken
        | OidcError::ClientNotAllowed => false,
        _ => false,
    }
}

/// Render an error together with the causes beneath it, bounded.
///
/// Separated from the logging call so what reaches the log can be asserted
/// directly. Every part of it is either this crate's own text or the transport
/// library's account of a connection to an address the bundle configured;
/// nothing the caller supplied passes through here.
fn describe_causes(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut cause = error.source();
    let mut remaining = REPORTED_CAUSES;
    while let (Some(current), 1..) = (cause, remaining) {
        rendered.push_str(": ");
        rendered.push_str(&current.to_string());
        cause = current.source();
        remaining -= 1;
    }
    if rendered.len() > MAX_CAUSE_BYTES {
        let mut end = MAX_CAUSE_BYTES;
        while !rendered.is_char_boundary(end) {
            end -= 1;
        }
        rendered.truncate(end);
        rendered.push_str("...");
    }
    rendered
}

pub fn strict_jwt_preflight(token: &str) -> Result<(), AuthenticationError> {
    validate_compact_access_token(token).map_err(|_| AuthenticationError::Malformed)
}

fn required_direct_string(
    claims: &Map<String, Value>,
    name: &str,
    maximum_bytes: usize,
) -> Result<String, AuthenticationError> {
    optional_direct_string(claims, name, maximum_bytes)?.ok_or(AuthenticationError::Context)
}

fn optional_direct_string(
    claims: &Map<String, Value>,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<String>, AuthenticationError> {
    let Some(value) = claims.get(name) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(AuthenticationError::Context)?;
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(AuthenticationError::Context);
    }
    Ok(Some(value.to_owned()))
}

fn required_string_array(
    claims: &Map<String, Value>,
    name: &str,
    maximum_items: usize,
) -> Result<Vec<String>, AuthenticationError> {
    let values = claims
        .get(name)
        .and_then(Value::as_array)
        .ok_or(AuthenticationError::Context)?;
    if values.is_empty() || values.len() > maximum_items {
        return Err(AuthenticationError::Context);
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(AuthenticationError::Context)?;
        if value.is_empty() || value.len() > MAX_PRINCIPAL_BYTES {
            return Err(AuthenticationError::Context);
        }
        output.push(value.to_owned());
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn resolve_claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() || path.len() > 512 {
        return None;
    }
    let mut current = claims;
    for segment in path.split('.') {
        if !valid_claim_path_segment(segment) {
            return None;
        }
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn valid_claim_path_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authentication_config() -> AuthenticationConfig {
        crate::config::EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("acceptance configuration parses")
        .authentication
    }

    #[test]
    fn jwks_fetch_policy_opens_http_only_for_the_supervised_local_issuer() {
        let mut exact = authentication_config();
        exact.issuer = "http://127.0.0.1:8081".to_owned();
        exact.jwks_uri = "http://127.0.0.1:8081/.well-known/jwks.json".to_owned();
        let local = jwks_fetch_policy(&exact, AssuranceProfile::Local);
        assert_eq!(local.allowed_schemes, ["http"]);
        assert!(local.allow_localhost);
        assert!(local.deny_private_ranges);

        // The JWKS path is the issuer's to choose; what stays fixed is the
        // exact same numeric loopback origin.
        let mut other_path = exact.clone();
        other_path.jwks_uri = "http://127.0.0.1:8081/oauth2/jwks".to_owned();
        assert_eq!(
            jwks_fetch_policy(&other_path, AssuranceProfile::Local).allowed_schemes,
            ["http"]
        );

        for (profile, issuer, jwks_uri) in [
            (
                AssuranceProfile::Production,
                "http://127.0.0.1:8081",
                "http://127.0.0.1:8081/.well-known/jwks.json",
            ),
            (
                AssuranceProfile::EvidenceGrade,
                "http://127.0.0.1:8081",
                "http://127.0.0.1:8081/.well-known/jwks.json",
            ),
            (
                AssuranceProfile::Local,
                "http://localhost:8081",
                "http://localhost:8081/.well-known/jwks.json",
            ),
            (
                AssuranceProfile::Local,
                "http://127.0.0.2:8081",
                "http://127.0.0.2:8081/.well-known/jwks.json",
            ),
            (
                AssuranceProfile::Local,
                "http://127.0.0.1:8081",
                "http://127.0.0.1:8082/.well-known/jwks.json",
            ),
        ] {
            let mut candidate = authentication_config();
            candidate.issuer = issuer.to_owned();
            candidate.jwks_uri = jwks_uri.to_owned();
            let policy = jwks_fetch_policy(&candidate, profile);
            assert_eq!(
                policy.allowed_schemes,
                ["https"],
                "{profile:?} opened HTTP for {jwks_uri}"
            );
        }
    }

    fn segment(input: &str) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    #[test]
    fn strict_preflight_accepts_three_strict_json_segments() {
        let token = format!(
            "{}.{}.{}",
            segment(r#"{"alg":"EdDSA","kid":"key","typ":"at+jwt"}"#),
            segment(r#"{"iss":"https://issuer.invalid","aud":"evidence","exp":2000000000}"#),
            URL_SAFE_NO_PAD.encode([1_u8; 64])
        );
        strict_jwt_preflight(&token).expect("token structure is valid");
    }

    #[test]
    fn strict_preflight_rejects_duplicate_members_and_bad_compact_shape() {
        let duplicate_header = format!(
            "{}.{}.{}",
            segment(r#"{"alg":"EdDSA","alg":"RS256"}"#),
            segment(r#"{"iss":"https://issuer.invalid"}"#),
            URL_SAFE_NO_PAD.encode([1_u8; 64])
        );
        assert!(strict_jwt_preflight(&duplicate_header).is_err());
        for token in ["", "a.b", "a.b.c.d", "a..c", " a.b.c"] {
            assert!(strict_jwt_preflight(token).is_err());
        }
    }

    #[test]
    fn claim_paths_are_exact_and_do_not_fallback() {
        let claims = serde_json::json!({"grant": {"subject-id": "value"}, "sub": "principal"});
        assert_eq!(
            resolve_claim_path(&claims, "grant.subject-id"),
            Some(&Value::String("value".to_string()))
        );
        assert!(resolve_claim_path(&claims, "grant.missing").is_none());
        assert!(resolve_claim_path(&claims, "grant..subject-id").is_none());
    }

    #[test]
    fn key_source_failures_are_separated_from_token_failures() {
        // The operator's half: nothing here is anything the caller did, and
        // each one leaves the deployment unable to verify any token at all.
        for error in [
            OidcError::HttpStatus(503),
            OidcError::InvalidUrl,
            OidcError::Parse,
            OidcError::InvalidJwk,
            OidcError::EmptyKeySet,
            OidcError::MissingIssuer,
        ] {
            assert!(
                is_key_source_failure(&error),
                "{error} is a fault in this deployment's key source"
            );
        }

        // The caller's half: reporting these would let a caller write to the
        // operator log by presenting bad tokens, and none of them says
        // anything about the deployment.
        for error in [
            OidcError::MalformedToken,
            OidcError::AlgorithmNotAllowed,
            OidcError::TokenTypeNotAllowed,
            OidcError::MissingKid,
            OidcError::KidTooLong,
            OidcError::UnknownKid,
            OidcError::TokenExpired,
            OidcError::TokenNotYetValid,
            OidcError::AudienceMismatch,
            OidcError::SignatureInvalid,
            OidcError::InvalidToken,
            OidcError::ClientNotAllowed,
            OidcError::IssuerMismatch {
                expected: "https://issuer.invalid".to_owned(),
                actual: "https://other.invalid".to_owned(),
            },
        ] {
            assert!(
                !is_key_source_failure(&error),
                "{error} is a fault in the presented token"
            );
        }
    }

    #[derive(Debug)]
    struct Layered {
        message: &'static str,
        below: Option<Box<Layered>>,
    }

    impl std::fmt::Display for Layered {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.message)
        }
    }

    impl std::error::Error for Layered {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.below
                .as_deref()
                .map(|below| below as &(dyn std::error::Error + 'static))
        }
    }

    fn layered(messages: &[&'static str]) -> Layered {
        let mut layers = messages.iter().rev();
        let mut error = Layered {
            message: layers.next().expect("at least one layer"),
            below: None,
        };
        for message in layers {
            error = Layered {
                message,
                below: Some(Box::new(error)),
            };
        }
        error
    }

    #[test]
    fn the_reported_cause_reaches_past_the_summary_to_the_reason() {
        // The shape a refused TLS handshake arrives in: the top layer says
        // only that a request failed, and the layer an operator needs is
        // underneath it.
        let described = describe_causes(&layered(&[
            "error sending request",
            "connection error",
            "invalid peer certificate: UnknownIssuer",
        ]));
        assert_eq!(
            described,
            "error sending request: connection error: invalid peer certificate: UnknownIssuer"
        );
    }

    #[test]
    fn the_reported_cause_is_bounded_in_depth_and_length() {
        let deep = describe_causes(&layered(&["first", "second", "third", "fourth", "fifth"]));
        assert_eq!(deep, "first: second: third: fourth");

        let long = describe_causes(&layered(&["x".repeat(4096).leak()]));
        assert!(
            long.len() <= MAX_CAUSE_BYTES + 3,
            "an unbounded remote message reached the log: {} bytes",
            long.len()
        );
        assert!(long.ends_with("..."), "truncation is not marked: {long}");
    }

    #[test]
    fn a_failing_key_source_is_named_once_per_interval() {
        let authenticator = Authenticator::new(
            Arc::new(TokenVerifier::new(
                TokenVerifierConfig::access_token_profile(
                    "https://issuer.invalid".to_owned(),
                    vec!["urn:example:audience".to_owned()],
                    vec![jsonwebtoken::Algorithm::EdDSA],
                    vec!["at+jwt".to_owned()],
                ),
                Arc::new(JwksFetcher::new(
                    "https://issuer.invalid/jwks".to_owned(),
                    JwksFetcherConfig::defaults(),
                )),
            )),
            AuthenticationClaimsConfig {
                principal_claim: "sub".to_owned(),
                requester_tags_claim: "evidence_tags".to_owned(),
                evidence_audience_claim: "evidence_audience".to_owned(),
                contextual_claims: ClaimNames::default(),
                actor_claim: None,
            },
        );

        let now = Instant::now();
        assert!(
            authenticator.claim_report_interval(now),
            "the first failure is always named"
        );
        assert!(
            !authenticator.claim_report_interval(now + KEY_SOURCE_REPORT_INTERVAL / 2),
            "a deployment rejecting every request must not log every request"
        );
        assert!(
            authenticator.claim_report_interval(now + KEY_SOURCE_REPORT_INTERVAL),
            "a fault that lasts keeps being named"
        );
    }

    #[test]
    fn a_failed_readiness_probe_stands_in_for_the_next_one() {
        let authenticator = Authenticator::new(
            Arc::new(TokenVerifier::new(
                TokenVerifierConfig::access_token_profile(
                    "https://issuer.invalid".to_owned(),
                    vec!["urn:example:audience".to_owned()],
                    vec![jsonwebtoken::Algorithm::EdDSA],
                    vec!["at+jwt".to_owned()],
                ),
                Arc::new(JwksFetcher::new(
                    "https://issuer.invalid/jwks".to_owned(),
                    JwksFetcherConfig::defaults(),
                )),
            )),
            AuthenticationClaimsConfig {
                principal_claim: "sub".to_owned(),
                requester_tags_claim: "evidence_tags".to_owned(),
                evidence_audience_claim: "evidence_audience".to_owned(),
                contextual_claims: ClaimNames::default(),
                actor_claim: None,
            },
        );

        let now = Instant::now();
        assert!(
            !authenticator.probe_is_suppressed(now),
            "nothing is known yet, so the first probe must run"
        );
        authenticator.lock_key_source().last_failed_probe = Some(now);
        assert!(
            authenticator.probe_is_suppressed(now + KEY_SOURCE_PROBE_INTERVAL / 2),
            "an orchestrator's polling rate must not become the retry rate"
        );
        assert!(
            !authenticator.probe_is_suppressed(now + KEY_SOURCE_PROBE_INTERVAL),
            "an issuer that comes back must be found"
        );
    }

    #[test]
    fn authenticated_context_debug_redacts_claim_material() {
        let mut context = AuthenticatedContext::test_context(
            "principal-canary",
            vec!["tag-canary".to_string()],
            "urn:example:audience",
            Err(TaskGrantError::Claims),
            serde_json::json!({"protected": "claim-canary"}),
        );
        context.actor = Some("actor-canary".to_string());
        let debug = format!("{context:?}");
        for canary in [
            "principal-canary",
            "actor-canary",
            "tag-canary",
            "claim-canary",
        ] {
            assert!(!debug.contains(canary));
        }
    }

    fn context_extraction_authenticator(principal_claim: &str) -> Authenticator {
        Authenticator::new(
            Arc::new(TokenVerifier::new(
                TokenVerifierConfig::access_token_profile(
                    "https://issuer.invalid".to_owned(),
                    vec!["evidence-resource".to_owned()],
                    vec![jsonwebtoken::Algorithm::EdDSA],
                    vec!["at+jwt".to_owned()],
                )
                .with_allowed_clients(vec!["evidence-agent".to_owned()]),
                Arc::new(JwksFetcher::new(
                    "https://issuer.invalid/jwks".to_owned(),
                    JwksFetcherConfig::defaults(),
                )),
            )),
            AuthenticationClaimsConfig {
                principal_claim: principal_claim.to_owned(),
                requester_tags_claim: "evidence_tags".to_owned(),
                evidence_audience_claim: "evidence_audience".to_owned(),
                contextual_claims: ClaimNames::default(),
                actor_claim: None,
            },
        )
        .with_resources(vec!["evidence-resource".to_owned()])
    }

    #[test]
    fn evidence_principal_must_equal_the_grant_subject() {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::from_value(serde_json::json!({
            "iss": "https://issuer.invalid",
            "aud": "evidence-resource",
            "sub": "institutional-agent",
            "evidence_principal": "different-principal",
            "exp": now + 300,
            "registry_actor_kind": "agent",
            "registry_purpose": "eligibility-check",
            "registry_grant_id": "grant-1",
            "registry_grant_authority": "authority-1",
            "registry_grant_source_issuer": "https://casework.invalid",
            "registry_grant_client": "evidence-agent",
            "registry_grant_resource": "evidence-resource",
            "registry_grant_exp": now + 300,
            "registry_grant_bounds": {"type":"evidence", "requirement":"urn:example:requirement"},
            "evidence_tags": ["caseworker"],
            "evidence_audience": "https://relying-party.invalid"
        }))
        .expect("claims parse");
        let context = context_extraction_authenticator("evidence_principal")
            .extract_context(VerifiedToken {
                claims,
                matched_client: Some("client_id:evidence-agent".to_owned()),
                scopes: Vec::new(),
            })
            .expect("verified product context extracts");
        assert_eq!(context.grant(), Err(TaskGrantError::PrincipalMismatch));
    }

    #[test]
    fn purpose_only_service_token_is_not_a_task_grant() {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::from_value(serde_json::json!({
            "iss": "https://issuer.invalid",
            "aud": "evidence-resource",
            "sub": "service-principal",
            "exp": now + 300,
            "registry_actor_kind": "service",
            "registry_purpose": "standing-service",
            "evidence_tags": ["service"],
            "evidence_audience": "https://relying-party.invalid"
        }))
        .expect("claims parse");
        let context = context_extraction_authenticator("sub")
            .extract_context(VerifiedToken {
                claims,
                matched_client: Some("client_id:evidence-agent".to_owned()),
                scopes: Vec::new(),
            })
            .expect("standing token extracts");
        assert_eq!(context.actor_kind(), ActorKind::Service);
        assert!(matches!(context.grant(), Ok(None)));
    }
}
