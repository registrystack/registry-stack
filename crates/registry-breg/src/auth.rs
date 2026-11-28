// SPDX-License-Identifier: Apache-2.0
//! Production bearer admission and OIDC claim mapping for Registry HTTP routes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use registry_platform_authcommon::{
    parse_bearer_token, validate_compact_access_token, BearerParseError, FailedCheck, RefusalNote,
};
use registry_platform_oidc::{
    grant_claims, is_access_token_typ_pair, Audience, ClaimError, ClaimNames, DeclaredKinds,
    GrantContextError, IssuerEntry, IssuerSet, IssuerSetError, JwksFetcher, OidcError,
    TokenVerifier, TokenVerifierConfig,
};
use serde_json::Value;
use thiserror::Error;

use crate::api::{VerifiedClaimValue, VerifiedRequestClaims};
#[cfg(feature = "tooling")]
pub(crate) use crate::authority::compiled_authority_field_type;
use crate::authority::{authority_inventory, AuthorityInventoryError, DirectClaimExpectation};
use crate::contract::FieldTypeSource;
use crate::model::{CompiledRecipients, CompiledRegistry};

const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_SCOPE_VALUES: usize = 128;
const MAX_SCOPE_VALUE_BYTES: usize = 512;
const REFUSAL_WARNING_INTERVAL: Duration = Duration::from_secs(60);
/// Reads check no live task-grant status, so a revoked grant keeps reading
/// until its token expires. This bound on the issued lifetime, not the time
/// left, keeps that window short whatever the ordinary token ceiling allows.
const MAX_TASK_GRANT_TOKEN_LIFETIME_SECONDS: i64 = 900;

const REGISTERED_CLAIMS: &[&str] = &[
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "sub",
    "client_id",
    "azp",
    "jti",
    "cnf",
];

/// Direct claims that may become Registry authority after OIDC verification.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityClaimConfig {
    principal_claim: String,
    purpose_claim: Option<String>,
    contextual_claims: ClaimNames,
    trusted_actors: BTreeMap<String, String>,
}

impl AuthorityClaimConfig {
    #[must_use]
    pub fn new(principal_claim: impl Into<String>, purpose_claim: Option<String>) -> Self {
        Self {
            principal_claim: principal_claim.into(),
            purpose_claim,
            contextual_claims: ClaimNames::default(),
            trusted_actors: BTreeMap::new(),
        }
    }

    /// The claim the caller's principal is read from.
    #[must_use]
    pub fn principal_claim(&self) -> &str {
        &self.principal_claim
    }

    /// The claim the caller's purpose is read from, when one is configured.
    #[must_use]
    pub fn purpose_claim(&self) -> Option<&str> {
        self.purpose_claim.as_deref()
    }

    /// The claim the caller's actor kind is read from.
    #[must_use]
    pub fn actor_kind_claim(&self) -> &str {
        &self.contextual_claims.actor_kind
    }

    #[must_use]
    pub fn with_contextual_claims(
        mut self,
        contextual_claims: ClaimNames,
        trusted_actors: BTreeMap<String, String>,
    ) -> Self {
        self.contextual_claims = contextual_claims;
        self.trusted_actors = trusted_actors;
        self
    }
}

impl fmt::Debug for AuthorityClaimConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityClaimConfig")
            .field("principal_claim", &self.principal_claim)
            .field("purpose_claim", &self.purpose_claim)
            .field("contextual_claims", &self.contextual_claims)
            .field("trusted_actor_clients", &self.trusted_actors.keys())
            .finish()
    }
}

/// A closed construction failure. Each variant names the check that refused
/// the deployment, and deliberately carries no configured URL, claim name, or
/// claim value that an operator could accidentally copy into a log.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationConfigError {
    #[error("the OIDC access-token verification profile is invalid")]
    InvalidVerifierProfile,
    #[error("an authority claim mapping is invalid")]
    InvalidClaimMapping,
    #[error(
        "the project names clients in requesterClients, trusted actors, or consent recipients \
         that no authentication.oidc.issuers entry lists in allowedClients; list each of them \
         in the allowedClients of the entry whose issuer signs its tokens, because the keyword \
         unrestricted lists none"
    )]
    NamedClientNotListed,
    #[error("a contextual authority claim overlaps another configured claim role")]
    ConflictingClaimMapping,
    #[error("the configured principal claim is not the principal claim a compiled access profile requires")]
    PrincipalClaimMismatch,
    #[error("a compiled row boundary selects a field the compiled entity does not declare")]
    BoundaryFieldNotCompiled,
    #[error("a compiled authority target entity does not exist")]
    TargetEntityNotCompiled,
    #[error("a compiled verified-claim lookup names a selector profile the compiled entity does not declare")]
    LookupSelectorNotCompiled,
    #[error("a compiled verified-claim lookup leaves a selector field without a claim mapping")]
    LookupClaimMappingIncomplete,
    #[error("a compiled verified-claim lookup maps a field the compiled entity does not declare")]
    LookupFieldNotCompiled,
    #[error("a purpose claim must be configured exactly when a compiled access profile requires a purpose")]
    PurposeClaimMismatch,
    #[error("two compiled authority mappings expect different value shapes for one claim")]
    ConflictingClaimExpectation,
}

/// A closed request failure. Platform verifier details and the bearer value
/// are intentionally erased at this boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential is malformed")]
    MalformedCredential,
    #[error("the bearer credential was refused")]
    VerificationRefused,
    #[error("the verified credential has invalid authority claims")]
    InvalidClaims,
}

impl AuthenticationError {
    /// Pair the failure with the check that produced it. The check is
    /// operator-side only: it reaches the refusal counter and log line, never
    /// the response.
    fn because(self, check: FailedCheck) -> Refusal {
        Refusal {
            error: self,
            check,
            remedy: None,
            development_assertion: false,
        }
    }
}

/// A closed request failure and the check that failed. Every refusal built in
/// this module names its check, so none reaches the recording layer without
/// one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Refusal {
    error: AuthenticationError,
    check: FailedCheck,
    /// The setting an operator changes to admit such a token, for the
    /// refusal log line. It is fixed text, never a caller value, and never
    /// reaches the response.
    remedy: Option<&'static str>,
    development_assertion: bool,
}

impl Refusal {
    /// The note the recording layer counts and logs for this refusal.
    fn note(self) -> RefusalNote {
        let note = RefusalNote::new(self.check);
        match self.remedy {
            Some(remedy) => note.with_remedy(remedy),
            None => note,
        }
    }
}

fn invalid_claims(check: FailedCheck) -> Refusal {
    AuthenticationError::InvalidClaims.because(check)
}

/// One issuer the authenticator accepts tokens from: its id, the access-token
/// profile it verifies, where its signing keys come from, and the actor kinds
/// the operator declared for it.
pub struct AuthenticatorIssuer {
    id: String,
    verifier: TokenVerifierConfig,
    key_source: Arc<JwksFetcher>,
    declared: DeclaredKinds,
}

impl AuthenticatorIssuer {
    /// An issuer that declares no actor kind.
    pub fn new(
        id: impl Into<String>,
        verifier: TokenVerifierConfig,
        key_source: Arc<JwksFetcher>,
    ) -> Self {
        Self {
            id: id.into(),
            verifier,
            key_source,
            declared: DeclaredKinds::None,
        }
    }

    /// This issuer with the actor kinds its entry declares.
    #[must_use]
    pub fn with_declared_kinds(self, declared: DeclaredKinds) -> Self {
        Self { declared, ..self }
    }

    /// The issuer id the operator gave the entry.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Where this issuer's signing keys come from.
    pub fn key_source(&self) -> &Arc<JwksFetcher> {
        &self.key_source
    }
}

impl fmt::Debug for AuthenticatorIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatorIssuer")
            .field("id", &self.id)
            .field("issuer", &"<redacted>")
            .finish()
    }
}

/// The rules of one issuer entry that apply after its verifier accepted a
/// token.
struct IssuerRules {
    issuer: String,
    audience: String,
    scope_claim: String,
    /// The clock leeway the verifier applies to `exp` and `nbf`, reused as
    /// the allowance for a task-grant token's `iat` ahead of this clock.
    leeway: Duration,
}

/// Production OIDC verifiers plus the only claim mapping allowed to construct
/// [`VerifiedRequestClaims`].
pub struct RegistryAuthenticator {
    peer_policy: registry_platform_httputil::PeerPolicy,
    issuers: IssuerSet,
    rules: BTreeMap<String, IssuerRules>,
    last_key_refusal_warning: Mutex<Option<Instant>>,
    principal_claim: String,
    purpose_claim: Option<String>,
    direct_claims: BTreeMap<String, DirectClaimExpectation>,
    contextual_claims: ClaimNames,
    trusted_actors: BTreeMap<String, String>,
    recipients: CompiledRecipients,
    consent_decisions: BTreeMap<String, BTreeSet<String>>,
}

/// The issuer id [`RegistryAuthenticator::new`] gives its one issuer.
const SINGLE_ISSUER_ID: &str = "issuer";

impl RegistryAuthenticator {
    /// Bind one exact platform verifier profile and one exact authority mapping
    /// to the immutable compiled Registry served by this process.
    pub fn new(
        registry: &CompiledRegistry,
        verifier_config: TokenVerifierConfig,
        key_source: Arc<JwksFetcher>,
        claims: AuthorityClaimConfig,
    ) -> Result<Self, AuthenticationConfigError> {
        Self::with_issuers(
            registry,
            vec![AuthenticatorIssuer::new(
                SINGLE_ISSUER_ID,
                verifier_config,
                key_source,
            )],
            claims,
        )
    }

    /// Bind the issuers a token may come from, each with its own exact
    /// verifier profile, and one exact authority mapping to the immutable
    /// compiled Registry served by this process. A token is verified only by
    /// the issuer its `iss` names.
    pub fn with_issuers(
        registry: &CompiledRegistry,
        issuers: Vec<AuthenticatorIssuer>,
        claims: AuthorityClaimConfig,
    ) -> Result<Self, AuthenticationConfigError> {
        for issuer in &issuers {
            validate_verifier_profile(&issuer.verifier)?;
        }
        let profiles = issuers
            .iter()
            .map(|issuer| &issuer.verifier)
            .collect::<Vec<_>>();
        let direct_claims = validate_claim_mapping(registry, &profiles, &claims)?;
        let mut rules = BTreeMap::new();
        let mut entries = Vec::with_capacity(issuers.len());
        for issuer in issuers {
            let AuthenticatorIssuer {
                id,
                verifier,
                key_source,
                declared,
            } = issuer;
            rules.insert(
                id.clone(),
                IssuerRules {
                    issuer: verifier.issuer.clone(),
                    audience: verifier.audiences[0].clone(),
                    scope_claim: verifier.scope_claim.clone(),
                    leeway: verifier.leeway,
                },
            );
            entries.push(IssuerEntry::new(
                id,
                TokenVerifier::new(verifier, key_source),
                declared,
            ));
        }
        let issuers = IssuerSet::new(entries, claims.contextual_claims.clone()).map_err(
            |error| match error {
                IssuerSetError::InvalidClaimNames => AuthenticationConfigError::InvalidClaimMapping,
                IssuerSetError::Empty | IssuerSetError::DuplicateIss { .. } => {
                    AuthenticationConfigError::InvalidVerifierProfile
                }
            },
        )?;
        let consent_decisions = crate::consent::feed_decisions(registry.entities());
        Ok(Self {
            peer_policy: registry_platform_httputil::PeerPolicy::RefuseDevelopmentPeer,
            issuers,
            rules,
            last_key_refusal_warning: Mutex::new(None),
            principal_claim: claims.principal_claim,
            purpose_claim: claims.purpose_claim,
            direct_claims,
            contextual_claims: claims.contextual_claims,
            trusted_actors: claims.trusted_actors,
            recipients: registry.recipients().clone(),
            consent_decisions,
        })
    }

    pub(crate) fn with_peer_policy(
        mut self,
        policy: registry_platform_httputil::PeerPolicy,
    ) -> Self {
        self.peer_policy = policy;
        self
    }

    /// Verify and map one already-admitted compact bearer token.
    pub async fn authenticate(
        &self,
        token: &str,
    ) -> Result<VerifiedRequestClaims, AuthenticationError> {
        self.authenticate_checked(token)
            .await
            .map(|(claims, _)| claims)
            .map_err(|refusal| refusal.error)
    }

    /// Verify `token` with the issuer its `iss` names, without mapping its
    /// claims. A schema test compares the scopes it carries with the mapped
    /// claims.
    #[cfg(feature = "tooling")]
    pub(crate) async fn verify_token(
        &self,
        token: &str,
    ) -> Result<registry_platform_oidc::VerifiedToken, OidcError> {
        self.issuers
            .verify(token)
            .await
            .map(|caller| caller.token)
            .map_err(|refusal| refusal.error)
    }

    /// [`Self::authenticate`], with the check that refused the token. A
    /// verified token comes with the scope claim of the issuer that verified
    /// it.
    pub(crate) async fn authenticate_checked(
        &self,
        token: &str,
    ) -> Result<(VerifiedRequestClaims, &str), Refusal> {
        validate_compact_access_token(token).map_err(|_| {
            AuthenticationError::MalformedCredential.because(FailedCheck::CredentialMalformed)
        })?;
        let caller = self.issuers.verify(token).await.map_err(|refusal| {
            // UnknownKid precedes signature verification and also covers denied
            // keys. It cannot establish rotation, regardless of the key source.
            if matches!(refusal.error, OidcError::UnknownKid)
                && admit_refusal_warning(&self.last_key_refusal_warning, Instant::now())
            {
                tracing::warn!(
                    target: "registry_breg::auth",
                    message = "refused an access token with an unknown or disallowed key \
                               identifier; this does not establish provider key rotation; \
                               check issuer key configuration and key policy before changing trust"
                );
            }
            Refusal {
                remedy: refusal.remedy,
                ..AuthenticationError::VerificationRefused.because(refusal.failed_check())
            }
        })?;
        let rules = self
            .rules
            .get(&*caller.issuer_id)
            .ok_or_else(|| invalid_claims(FailedCheck::TokenIssuer))?;
        let verified = &caller.token;
        if registry_platform_oidc::refuses_development_assertion(verified, self.peer_policy) {
            return Err(grant_context_check(GrantContextError::DevelopmentAssertion));
        }
        if !accepted_audience(verified.claims.aud.as_ref(), &rules.audience) {
            return Err(invalid_claims(FailedCheck::TokenAudience));
        }

        let claims = &verified.claims.extra;
        let subject = verified
            .claims
            .sub
            .as_ref()
            .map(|value| Value::String(value.clone()));
        let principal = required_direct_string(if self.principal_claim == "sub" {
            subject.as_ref()
        } else {
            claims.get(&self.principal_claim)
        })
        .map_err(|error| error.because(FailedCheck::TokenClaims))?;
        let purpose = self
            .purpose_claim
            .as_deref()
            .map(|name| optional_direct_string(claims.get(name)))
            .transpose()
            .map_err(|error| error.because(FailedCheck::TokenClaims))?
            .flatten();
        if verified.scopes.len() > MAX_SCOPE_VALUES {
            return Err(invalid_claims(FailedCheck::TokenClaims));
        }
        let scopes = verified
            .scopes
            .iter()
            .cloned()
            .map(validate_scope)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|error| error.because(FailedCheck::TokenClaims))?;
        let direct_claims = self
            .direct_claims
            .iter()
            .filter_map(|(name, expectation)| {
                let value = if name == "sub" {
                    subject.as_ref()
                } else {
                    claims.get(name)
                };
                value.map(|value| {
                    mapped_claim(value, expectation).map(|value| (name.clone(), value))
                })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|error| error.because(FailedCheck::TokenClaims))?;

        let requester_client = verified
            .matched_client_id()
            .map_err(|_| invalid_claims(FailedCheck::TokenClient))?
            .map(str::to_owned);
        let actor_subject = optional_actor_subject(claims.get("act"), &rules.issuer)
            .map_err(|error| error.because(FailedCheck::Delegation))?;
        if let Some(actor) = actor_subject.as_deref() {
            let client = requester_client
                .as_deref()
                .ok_or_else(|| invalid_claims(FailedCheck::TokenClient))?;
            if self.trusted_actors.get(client).map(String::as_str) != Some(actor) {
                return Err(invalid_claims(FailedCheck::Delegation));
            }
        }
        // A token exchange copies the subject's claims, so a kind claim on a
        // delegated token describes the person, not the caller. The trusted
        // actor verified above is the caller, and it is always an agent.
        // Otherwise the kind is the one the issuer set settled, and a token
        // that states none and has none declared is an unspecified caller: a
        // profile that pins a kind refuses it.
        let actor_kind = if actor_subject.is_some() {
            Some(registry_platform_oidc::ActorKind::Agent)
        } else {
            caller.kind.kind()
        };
        // The person is named by the configured principal claim, the same
        // claim every access profile reads. A review authority compares this
        // identity with its own caller principals, so it must not fall back
        // to `sub` when the deployment's principal lives in another claim.
        let human_identity = if actor_kind == Some(registry_platform_oidc::ActorKind::Human) {
            Some(registry_review_client::HumanIdentity {
                issuer: rules.issuer.clone(),
                subject: principal.clone(),
            })
        } else {
            None
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_claims(FailedCheck::TokenTime))?
            .as_secs();
        let grant =
            grant_claims(&verified.claims, &self.contextual_claims, now).map_err(|error| {
                invalid_claims(match error {
                    ClaimError::Expired => FailedCheck::TaskGrantExpired,
                    _ => FailedCheck::TaskGrantClaims,
                })
            })?;
        if let Some(grant) = &grant {
            grant
                .verify_context(verified, &rules.audience, self.peer_policy)
                .map_err(grant_context_check)?;
            task_grant_token_lifetime(verified.claims.iat, verified.claims.exp, now, rules.leeway)
                .map_err(invalid_claims)?;
        }
        let grant_subjects = if grant.is_some() {
            bounded_identity(claims.get("identity"))
                .map_err(|error| error.because(FailedCheck::TaskGrantClaims))?
        } else {
            BTreeMap::new()
        };
        let direct_claims = if grant.is_some() {
            self.direct_claims
                .iter()
                .filter_map(|(name, expectation)| {
                    let value = if name == "sub" {
                        subject.as_ref()
                    } else {
                        grant_subjects.get(name)
                    };
                    value.map(|value| {
                        mapped_claim(value, expectation).map(|value| (name.clone(), value))
                    })
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|error| error.because(FailedCheck::TaskGrantClaims))?
        } else {
            direct_claims
        };
        // The recipient set comes from the same verified matched client that
        // `requesterClients` checks, never from a token claim or a header.
        let recipients = requester_client
            .as_deref()
            .map(|client| self.recipients.recipient_set(client))
            .unwrap_or_default();

        VerifiedRequestClaims::authenticated(
            self.principal_claim.clone(),
            principal,
            scopes,
            purpose,
            direct_claims,
        )
        .and_then(|claims| {
            claims.with_contextual_authority(
                actor_kind,
                requester_client,
                actor_subject,
                grant,
                grant_subjects,
            )
        })
        .and_then(|claims| claims.with_human_identity(human_identity))
        .and_then(|claims| claims.with_consent_claims(recipients, &self.consent_decisions))
        .map(|claims| (claims, rules.scope_claim.as_str()))
        .map_err(|_| invalid_claims(FailedCheck::TokenClaims))
    }
}

/// A task-grant token must carry `iat` and `exp`, with `exp` after `iat` and
/// `iat` no later than `now` plus the verifier's clock leeway. A token that
/// fails any of those is a malformed grant token (`TaskGrantClaims`). One that
/// is well formed but issued for more than
/// [`MAX_TASK_GRANT_TOKEN_LIFETIME_SECONDS`] is refused as `TaskGrantLifetime`,
/// so its issued lifetime also bounds the time it is honoured from this clock.
fn task_grant_token_lifetime(
    issued_at: Option<i64>,
    expires_at: Option<i64>,
    now: u64,
    leeway: Duration,
) -> Result<(), FailedCheck> {
    let latest_issued_at = now
        .checked_add(leeway.as_secs())
        .and_then(|latest| i64::try_from(latest).ok());
    let (Some(issued_at), Some(expires_at), Some(latest_issued_at)) =
        (issued_at, expires_at, latest_issued_at)
    else {
        return Err(FailedCheck::TaskGrantClaims);
    };
    let lifetime = expires_at.saturating_sub(issued_at);
    if issued_at > latest_issued_at || lifetime < 1 {
        return Err(FailedCheck::TaskGrantClaims);
    }
    if lifetime > MAX_TASK_GRANT_TOKEN_LIFETIME_SECONDS {
        return Err(FailedCheck::TaskGrantLifetime);
    }
    Ok(())
}

fn admit_refusal_warning(last_warning: &Mutex<Option<Instant>>, now: Instant) -> bool {
    // One timestamp per authenticator bounds both memory and warning volume,
    // including concurrent requests with distinct caller-controlled key IDs.
    // A timestamp contains no partial authorization state. Recover it after a
    // panic so poisoning cannot permanently silence refusal diagnostics.
    let mut last = last_warning
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if last
        .is_some_and(|previous| now.saturating_duration_since(previous) < REFUSAL_WARNING_INTERVAL)
    {
        return false;
    }
    *last = Some(now);
    true
}

impl fmt::Debug for RegistryAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryAuthenticator")
            .field("issuers", &self.rules.keys())
            .field("principal_claim", &self.principal_claim)
            .field("purpose_claim", &self.purpose_claim)
            .field("direct_claims", &self.direct_claims.keys())
            .field("contextual_claims", &self.contextual_claims)
            .field("trusted_actor_clients", &self.trusted_actors.keys())
            .finish()
    }
}

/// Authenticate a presented bearer before any Registry route authorization.
/// A missing credential and every invalid presented credential fail closed:
/// the registry serves authenticated callers only. Any caller-supplied
/// authority extension is removed first.
pub(crate) async fn authenticate_request(
    State(authenticator): State<Arc<RegistryAuthenticator>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.extensions_mut().remove::<VerifiedRequestClaims>();
    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(check) => return authentication_refused(RefusalNote::new(check)),
    };
    let (claims, scope_claim) = match authenticator.authenticate_checked(token).await {
        Ok(verified) => verified,
        Err(refusal) => {
            return refusal.response();
        }
    };
    let claims = match request
        .extensions()
        .get::<crate::correlation::RequestCorrelation>()
    {
        Some(correlation) => {
            claims.with_scope_declaration(scope_claim, correlation.declared_scope_slot())
        }
        None => claims,
    };
    request.extensions_mut().insert(claims);
    next.run(request).await
}

/// The one bearer credential on a request, or the check it failed. A request
/// with no credential, or one in another scheme, names the missing
/// credential. A repeated or unreadable header, or a bearer that is not one
/// well-formed token, names the malformed credential.
pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, FailedCheck> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(FailedCheck::CredentialMissing);
    };
    if values.next().is_some() {
        return Err(FailedCheck::CredentialMalformed);
    }
    let value = value
        .to_str()
        .map_err(|_| FailedCheck::CredentialMalformed)?;
    parse_bearer_token(value).map_err(|error| match error {
        BearerParseError::InvalidScheme => FailedCheck::CredentialMissing,
        _ => FailedCheck::CredentialMalformed,
    })
}

fn validate_verifier_profile(
    config: &TokenVerifierConfig,
) -> Result<(), AuthenticationConfigError> {
    if !valid_config_value(&config.issuer)
        || config.audiences.len() != 1
        || !valid_config_value(&config.audiences[0])
        || config.allowed_algorithms.len() != 1
        || !admits_one_access_token_type(&config.allowed_typ)
        || !valid_claim_name(&config.scope_claim)
        || REGISTERED_CLAIMS.contains(&config.scope_claim.as_str())
        || config.scope_separator.is_control()
        || config.scope_separator.is_alphanumeric()
    {
        return Err(AuthenticationConfigError::InvalidVerifierProfile);
    }
    if let Some(scope_map) = &config.scope_map {
        for (source, mapped) in scope_map {
            if !valid_scope_value(source)
                || mapped.is_empty()
                || mapped.len() > MAX_SCOPE_VALUES
                || mapped.iter().any(|scope| !valid_scope_value(scope))
                || mapped.iter().collect::<BTreeSet<_>>().len() != mapped.len()
            {
                return Err(AuthenticationConfigError::InvalidVerifierProfile);
            }
        }
    }
    Ok(())
}

/// Exactly one admitted access-token type semantics: a single valid
/// `typ` value, or the two RFC 9068 spellings of the access-token media
/// type, which name the same type and must be accepted together
/// (RFC 9068 §4). This profile rejects every other list shape.
fn admits_one_access_token_type(allowed_typ: &[String]) -> bool {
    (allowed_typ.len() == 1 && valid_config_value(&allowed_typ[0]))
        || is_access_token_typ_pair(allowed_typ)
}

/// Hold a claim mapping to the compiled access profiles without building an
/// authenticator, so an offline check refuses what startup refuses.
pub(crate) fn check_claim_mapping(
    registry: &CompiledRegistry,
    verifiers: &[&TokenVerifierConfig],
    claims: &AuthorityClaimConfig,
) -> Result<(), AuthenticationConfigError> {
    validate_claim_mapping(registry, verifiers, claims).map(|_| ())
}

/// Hold one authority mapping to the compiled access profiles and to every
/// issuer profile a token may be verified by. A claim the mapping reads may
/// not be any issuer's scope claim, and a client the project names must be
/// listed by an issuer.
fn validate_claim_mapping(
    registry: &CompiledRegistry,
    verifiers: &[&TokenVerifierConfig],
    claims: &AuthorityClaimConfig,
) -> Result<BTreeMap<String, DirectClaimExpectation>, AuthenticationConfigError> {
    let scope_claims = verifiers
        .iter()
        .map(|verifier| verifier.scope_claim.as_str())
        .collect::<BTreeSet<_>>();
    let listed = |client: &str| {
        verifiers.iter().any(|verifier| {
            verifier
                .allowed_clients
                .iter()
                .any(|allowed| allowed == client)
        })
    };
    claims
        .contextual_claims
        .validate()
        .map_err(|_| AuthenticationConfigError::InvalidClaimMapping)?;
    let ClaimNames {
        actor_kind,
        purpose: contextual_purpose,
        grant_id,
        grant_source_issuer,
        grant_client,
        grant_resource,
        grant_exp,
        grant_bounds,
        approver,
    } = &claims.contextual_claims;
    let contextual_claims_with_distinct_roles = [
        actor_kind,
        grant_id,
        grant_source_issuer,
        grant_client,
        grant_resource,
        grant_exp,
        grant_bounds,
        approver,
    ];
    if contextual_claims_with_distinct_roles.iter().any(|name| {
        *name == &claims.principal_claim
            || scope_claims.contains(name.as_str())
            || claims.purpose_claim.as_ref() == Some(*name)
    }) || contextual_purpose == &claims.principal_claim
        || scope_claims.contains(contextual_purpose.as_str())
    {
        return Err(AuthenticationConfigError::ConflictingClaimMapping);
    }
    if claims.trusted_actors.len() > 128
        || claims.trusted_actors.iter().any(|(client, actor)| {
            !valid_config_value(client)
                || client.chars().any(char::is_whitespace)
                || !valid_config_value(actor)
                || actor.chars().any(char::is_whitespace)
                || uuid::Uuid::parse_str(actor).is_err()
        })
    {
        return Err(AuthenticationConfigError::InvalidClaimMapping);
    }
    if claims.trusted_actors.keys().any(|client| !listed(client)) {
        return Err(AuthenticationConfigError::NamedClientNotListed);
    }
    if !(valid_authority_claim_name(&claims.principal_claim) || claims.principal_claim == "sub")
        || scope_claims.contains(claims.principal_claim.as_str())
    {
        return Err(AuthenticationConfigError::InvalidClaimMapping);
    }
    if let Some(purpose) = &claims.purpose_claim {
        if !valid_authority_claim_name(purpose)
            || purpose == &claims.principal_claim
            || scope_claims.contains(purpose.as_str())
        {
            return Err(AuthenticationConfigError::InvalidClaimMapping);
        }
    }
    let inventory = authority_inventory(registry).map_err(|error| match error {
        AuthorityInventoryError::PrincipalClaimMissing => {
            AuthenticationConfigError::PrincipalClaimMismatch
        }
        AuthorityInventoryError::TargetEntityNotCompiled => {
            AuthenticationConfigError::TargetEntityNotCompiled
        }
        AuthorityInventoryError::BoundaryFieldNotCompiled => {
            AuthenticationConfigError::BoundaryFieldNotCompiled
        }
        AuthorityInventoryError::LookupSelectorNotCompiled => {
            AuthenticationConfigError::LookupSelectorNotCompiled
        }
        AuthorityInventoryError::LookupClaimMappingIncomplete => {
            AuthenticationConfigError::LookupClaimMappingIncomplete
        }
        AuthorityInventoryError::LookupFieldNotCompiled => {
            AuthenticationConfigError::LookupFieldNotCompiled
        }
        AuthorityInventoryError::ConflictingClaimExpectation => {
            AuthenticationConfigError::ConflictingClaimExpectation
        }
    })?;
    for profile in registry
        .entities()
        .values()
        .flat_map(|entity| entity.access_profiles.values())
        .chain(
            registry
                .statistical_datasets()
                .values()
                .flat_map(|dataset| dataset.access_profiles.values()),
        )
    {
        if profile
            .requester_clients
            .iter()
            .any(|client| !listed(client))
        {
            return Err(AuthenticationConfigError::NamedClientNotListed);
        }
        if profile.actor_kind == Some(crate::contract::ActorKindSource::Agent)
            && profile.task_grant.is_none()
            && profile
                .requester_clients
                .iter()
                .any(|client| !claims.trusted_actors.contains_key(client))
        {
            return Err(AuthenticationConfigError::InvalidClaimMapping);
        }
    }
    if registry.actions().actions.iter().any(|action| {
        action.permissions.iter().any(|profile| {
            profile
                .requester_clients
                .iter()
                .any(|client| !listed(client))
        }) || match &action.execution {
            crate::model::CompiledActionExecution::Immediate => false,
            crate::model::CompiledActionExecution::Proposal { proposal } => {
                proposal.permissions.iter().any(|profile| {
                    profile
                        .requester_clients
                        .iter()
                        .any(|client| !listed(client))
                })
            }
        }
    }) {
        return Err(AuthenticationConfigError::NamedClientNotListed);
    }
    if registry.actions().actions.iter().any(|action| {
        let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return false;
        };
        proposal.permissions.iter().any(|profile| {
            profile.actor_kind == Some(crate::contract::ActorKindSource::Agent)
                && profile.task_grant.is_none()
                && profile
                    .operations
                    .contains(&crate::contract::ProposalOperation::GetReviewContext)
                && profile
                    .requester_clients
                    .iter()
                    .any(|client| !claims.trusted_actors.contains_key(client))
        })
    }) {
        return Err(AuthenticationConfigError::InvalidClaimMapping);
    }
    // A recipient's client that the verifier would refuse can never read under
    // consent, so a mismatch is a configuration error, not a silent denial.
    if registry
        .recipients()
        .clients()
        .any(|client| !listed(client))
    {
        return Err(AuthenticationConfigError::NamedClientNotListed);
    }
    if inventory
        .principal_claims
        .iter()
        .any(|name| name != &claims.principal_claim)
    {
        return Err(AuthenticationConfigError::PrincipalClaimMismatch);
    }
    for (name, expectation) in &inventory.direct_claims {
        if name == &claims.principal_claim {
            // Ownership reuses the explicitly selected principal, never a fallback.
            // The field still applies its ordinary scalar type validation.
            if expectation.multi_value
                || matches!(
                    expectation.field_type,
                    FieldTypeSource::Boolean
                        | FieldTypeSource::Int64
                        | FieldTypeSource::Crs84Point { .. }
                        | FieldTypeSource::Crs84Polygon { .. }
                        | FieldTypeSource::Structured { .. }
                )
            {
                return Err(AuthenticationConfigError::ConflictingClaimExpectation);
            }
        } else if !valid_authority_claim_name(name)
            || scope_claims.contains(name.as_str())
            || claims.purpose_claim.as_ref() == Some(name)
        {
            return Err(AuthenticationConfigError::InvalidClaimMapping);
        }
    }
    if inventory.purpose_required != claims.purpose_claim.is_some() {
        return Err(AuthenticationConfigError::PurposeClaimMismatch);
    }
    Ok(inventory.direct_claims)
}

fn accepted_audience(audience: Option<&Audience>, expected: &str) -> bool {
    const MAX_AUDIENCES: usize = 16;
    match audience {
        Some(Audience::One(value)) => valid_config_value(value) && value == expected,
        Some(Audience::Many(values)) => {
            !values.is_empty()
                && values.len() <= MAX_AUDIENCES
                && values.iter().all(|value| valid_config_value(value))
                && values.iter().collect::<BTreeSet<_>>().len() == values.len()
                && values.iter().any(|value| value == expected)
        }
        None => false,
    }
}

fn valid_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLAIM_NAME_BYTES
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

/// Whether a direct authority claim name is valid and does not shadow a registered JWT claim.
/// Authoring preflight shares the same rule as runtime authority configuration.
pub fn valid_authority_claim_name(value: &str) -> bool {
    valid_claim_name(value) && !REGISTERED_CLAIMS.contains(&value)
}

fn valid_config_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= 2048
        && !value.chars().any(char::is_control)
}

fn valid_scope_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_VALUE_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn validate_scope(value: String) -> Result<String, AuthenticationError> {
    valid_scope_value(&value)
        .then_some(value)
        .ok_or(AuthenticationError::InvalidClaims)
}

fn required_direct_string(value: Option<&Value>) -> Result<String, AuthenticationError> {
    optional_direct_string(value)?.ok_or(AuthenticationError::InvalidClaims)
}

fn optional_direct_string(value: Option<&Value>) -> Result<Option<String>, AuthenticationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(AuthenticationError::InvalidClaims)?;
    let value = VerifiedClaimValue::direct_string(value.to_owned())
        .map_err(|_| AuthenticationError::InvalidClaims)?;
    match value {
        VerifiedClaimValue::DirectString(value) => Ok(Some(value)),
        VerifiedClaimValue::DirectStringSet(_) => unreachable!("direct constructor returns string"),
    }
}

/// Reads `act` as exactly `{sub}` or `{sub, iss}`. An issuer may only repeat
/// the verified token issuer; any other member, including a nested `act`, is
/// refused.
fn optional_actor_subject(
    value: Option<&Value>,
    token_issuer: &str,
) -> Result<Option<String>, AuthenticationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(AuthenticationError::InvalidClaims)?;
    match object.len() {
        1 => {}
        2 if object.get("iss").and_then(Value::as_str) == Some(token_issuer) => {}
        _ => return Err(AuthenticationError::InvalidClaims),
    }
    required_direct_string(object.get("sub")).map(Some)
}

fn bounded_identity(value: Option<&Value>) -> Result<BTreeMap<String, Value>, AuthenticationError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(AuthenticationError::InvalidClaims)?;
    if object.is_empty() || object.len() > 32 {
        return Err(AuthenticationError::InvalidClaims);
    }
    object
        .iter()
        .map(|(name, value)| {
            if name.is_empty()
                || name.len() > MAX_CLAIM_NAME_BYTES
                || name.chars().any(char::is_control)
                || !match value {
                    Value::String(value) => {
                        !value.is_empty()
                            && value.len() <= MAX_SCOPE_VALUE_BYTES
                            && !value.chars().any(char::is_control)
                    }
                    Value::Bool(_) => true,
                    Value::Number(value) => value.as_i64().is_some() || value.as_u64().is_some(),
                    _ => false,
                }
            {
                return Err(AuthenticationError::InvalidClaims);
            }
            Ok((name.clone(), value.clone()))
        })
        .collect()
}

fn mapped_claim(
    value: &Value,
    expectation: &DirectClaimExpectation,
) -> Result<VerifiedClaimValue, AuthenticationError> {
    map_authority_claim(value, &expectation.field_type, expectation.multi_value)
}

/// Map a typed authority value identically for verified tokens and synthetic previews.
pub(crate) fn map_authority_claim(
    value: &Value,
    field_type: &FieldTypeSource,
    multi_value: bool,
) -> Result<VerifiedClaimValue, AuthenticationError> {
    if multi_value {
        let values = value.as_array().ok_or(AuthenticationError::InvalidClaims)?;
        // A value repeated in a multi-valued claim asserts the same authority
        // once, so identical mapped values collapse. Every entry is still
        // mapped and validated, and the bound on distinct values still applies.
        let values = values
            .iter()
            .map(|value| mapped_scalar_claim(value, field_type))
            .collect::<Result<BTreeSet<_>, _>>()?;
        VerifiedClaimValue::direct_string_set(values)
            .map_err(|_| AuthenticationError::InvalidClaims)
    } else {
        VerifiedClaimValue::direct_string(mapped_scalar_claim(value, field_type)?)
            .map_err(|_| AuthenticationError::InvalidClaims)
    }
}

/// Validate the shape and field bounds of one direct scalar row claim.
/// This authoring preflight grants no authority and performs no authentication.
pub fn valid_direct_scalar_claim(value: &Value, field_type: &FieldTypeSource) -> bool {
    mapped_scalar_claim(value, field_type).is_ok()
}

fn mapped_scalar_claim(
    value: &Value,
    field_type: &FieldTypeSource,
) -> Result<String, AuthenticationError> {
    let value = match field_type {
        FieldTypeSource::Boolean => value
            .as_bool()
            .map(|value| value.to_string())
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::Int64 => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. }
        | FieldTypeSource::VocabularyCode { .. } => value
            .as_str()
            .map(str::to_owned)
            .ok_or(AuthenticationError::InvalidClaims)?,
        FieldTypeSource::Crs84Point { .. }
        | FieldTypeSource::Crs84Polygon { .. }
        | FieldTypeSource::Structured { .. } => {
            return Err(AuthenticationError::InvalidClaims);
        }
    };
    crate::postgres::validate_field_value(&value, field_type)
        .map_err(|_| AuthenticationError::InvalidClaims)?;
    Ok(value)
}

/// The check a task grant refused by its token context failed. A token with
/// no usable verified client fails the client check, and a grant bound to
/// another client or resource fails its binding.
fn grant_context_check(error: GrantContextError) -> Refusal {
    let check = match error {
        GrantContextError::MissingVerifiedClient | GrantContextError::InvalidVerifiedClient => {
            FailedCheck::TokenClient
        }
        GrantContextError::ClientMismatch | GrantContextError::ResourceMismatch => {
            FailedCheck::TaskGrantBinding
        }
        GrantContextError::DevelopmentAssertion => {
            return Refusal {
                development_assertion: true,
                ..invalid_claims(FailedCheck::TaskGrantClaims)
            };
        }
        _ => FailedCheck::TaskGrantClaims,
    };
    invalid_claims(check)
}

impl Refusal {
    /// The 401 for this refusal: its own code for a task grant issued in
    /// development, the uniform authentication refusal otherwise. Both name
    /// the `Bearer` scheme in `WWW-Authenticate`.
    fn response(self) -> Response {
        if self.development_assertion {
            let mut response = crate::correlation::problem_response(
                StatusCode::UNAUTHORIZED,
                "Development task assertion",
                "A production registry refuses task assertions issued in development.",
                registry_platform_oidc::DEVELOPMENT_ASSERTION_CODE,
            );
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                registry_platform_httpsec::bearer_challenge(),
            );
            return crate::correlation::attach_refusal_note(response, self.note());
        }
        authentication_refused(self.note())
    }
}

/// The uniform 401 for a missing credential or a general authentication
/// refusal. The answer is the same for every check, so a caller learns
/// nothing about which one failed: it names the `Bearer` scheme in
/// `WWW-Authenticate` and nothing about why. The note, with its remedy,
/// reaches only the recording layer.
pub(crate) fn authentication_refused(note: RefusalNote) -> Response {
    let mut response = crate::api::refusal_problem_with_note(
        crate::problem::ProblemCode::AuthenticationRefused,
        note,
    );
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        registry_platform_httpsec::bearer_challenge(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_context_refusal_names_the_check_it_failed() {
        for (error, check) in [
            (
                GrantContextError::MissingVerifiedClient,
                FailedCheck::TokenClient,
            ),
            (
                GrantContextError::InvalidVerifiedClient,
                FailedCheck::TokenClient,
            ),
            (
                GrantContextError::ClientMismatch,
                FailedCheck::TaskGrantBinding,
            ),
            (
                GrantContextError::ResourceMismatch,
                FailedCheck::TaskGrantBinding,
            ),
        ] {
            assert_eq!(
                grant_context_check(error),
                invalid_claims(check),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_development_assertion_preserves_the_task_grant_claims_metric_label() {
        let refusal = grant_context_check(GrantContextError::DevelopmentAssertion);
        assert_eq!(refusal.check, FailedCheck::TaskGrantClaims);
        assert_eq!(refusal.response().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_bearer_names_the_check_its_header_failed() {
        let headers = |values: &[&'static str]| {
            let mut headers = axum::http::HeaderMap::new();
            for value in values {
                headers.append(AUTHORIZATION, axum::http::HeaderValue::from_static(value));
            }
            headers
        };
        assert_eq!(bearer_token(&headers(&["Bearer a.b.c"])), Ok("a.b.c"));
        for (values, check) in [
            (&[][..], FailedCheck::CredentialMissing),
            (&["Basic abc"][..], FailedCheck::CredentialMissing),
            (
                &["Bearer a", "Bearer b"][..],
                FailedCheck::CredentialMalformed,
            ),
            (&["Bearer  a"][..], FailedCheck::CredentialMalformed),
            (&["Bearer"][..], FailedCheck::CredentialMalformed),
            (&["Bearer a b"][..], FailedCheck::CredentialMalformed),
        ] {
            assert_eq!(bearer_token(&headers(values)), Err(check), "{values:?}");
        }
        let mut unreadable = axum::http::HeaderMap::new();
        unreadable.insert(
            AUTHORIZATION,
            axum::http::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert_eq!(
            bearer_token(&unreadable),
            Err(FailedCheck::CredentialMalformed)
        );
    }

    #[test]
    fn refusal_warnings_recover_poisoned_timestamps_and_preserve_rate_limits() {
        let last_warning = Mutex::new(None);
        let now = Instant::now();
        std::thread::scope(|scope| {
            let poisoned = scope.spawn(|| {
                let _guard = last_warning.lock().expect("initial warning state");
                panic!("canary warning-state poison");
            });
            assert!(poisoned.join().is_err());
        });
        assert!(last_warning.is_poisoned());
        assert!(admit_refusal_warning(&last_warning, now));
        assert!(!admit_refusal_warning(
            &last_warning,
            now + REFUSAL_WARNING_INTERVAL - Duration::from_nanos(1)
        ));
        assert!(admit_refusal_warning(
            &last_warning,
            now + REFUSAL_WARNING_INTERVAL
        ));
    }

    #[test]
    fn key_refusal_warnings_are_bounded_across_concurrent_misses_and_resume_after_interval() {
        let last_warning = Mutex::new(None);
        let now = Instant::now();
        std::thread::scope(|scope| {
            let handles = (0..16)
                .map(|_| scope.spawn(|| admit_refusal_warning(&last_warning, now)))
                .collect::<Vec<_>>();
            let admitted = handles
                .into_iter()
                .map(|handle| handle.join().expect("warning worker"))
                .filter(|admitted| *admitted)
                .count();
            assert_eq!(admitted, 1);
        });
        assert!(!admit_refusal_warning(
            &last_warning,
            now + REFUSAL_WARNING_INTERVAL - Duration::from_nanos(1)
        ));
        assert!(admit_refusal_warning(
            &last_warning,
            now + REFUSAL_WARNING_INTERVAL
        ));
    }

    /// Every 401 the service answers carries the failed check. Only the two
    /// runtime constructors and the generated OpenAPI example can name the
    /// refusal. Adding another call site requires updating this list.
    #[test]
    fn only_the_noting_constructors_build_a_401() {
        fn visit(root: &std::path::Path, dir: &std::path::Path, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("source directory is readable") {
                let path = entry.expect("directory entry is readable").path();
                if path.is_dir() {
                    visit(root, &path, found);
                    continue;
                }
                // Judge the path below `src`, so where the checkout lives
                // cannot exclude the files.
                let name = path
                    .strip_prefix(root)
                    .expect("the file is below the source directory")
                    .to_string_lossy()
                    .into_owned();
                if !name.ends_with(".rs")
                    || name.contains("tests")
                    || name == "problem.rs"
                    || name == "compiler.rs"
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("source file is readable");
                let production = text
                    .split("#[cfg(test)]\nmod tests {")
                    .next()
                    .unwrap_or_default();
                for needle in [
                    "StatusCode::UNAUTHORIZED",
                    "ProblemCode::AuthenticationRefused",
                ] {
                    for _ in production.matches(needle) {
                        found.push(format!(
                            "{needle} in {}",
                            path.file_name().expect("file name").to_string_lossy()
                        ));
                    }
                }
            }
        }
        let mut found = Vec::new();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        visit(&root, &root, &mut found);
        found.sort();
        assert_eq!(
            found,
            [
                "ProblemCode::AuthenticationRefused in artifacts.rs",
                "ProblemCode::AuthenticationRefused in auth.rs",
                "ProblemCode::AuthenticationRefused in mod.rs",
                "StatusCode::UNAUTHORIZED in auth.rs",
            ]
        );
    }

    #[test]
    fn task_grant_tokens_must_be_issued_for_at_most_fifteen_minutes() {
        let issued = 1_800_000_000;
        let now = 1_800_000_000;
        let leeway = Duration::from_secs(60);
        assert_eq!(
            task_grant_token_lifetime(Some(issued), Some(issued + 900), now, leeway),
            Ok(())
        );
        assert_eq!(
            task_grant_token_lifetime(Some(issued), Some(issued + 1), now, leeway),
            Ok(())
        );
        for (issued_at, expires_at) in [
            (Some(issued), Some(issued + 901)),
            (Some(issued - 604_200), Some(issued + 600)),
            (Some(i64::MIN), Some(i64::MAX)),
        ] {
            assert_eq!(
                task_grant_token_lifetime(issued_at, expires_at, now, leeway),
                Err(FailedCheck::TaskGrantLifetime),
                "iat {issued_at:?} and exp {expires_at:?} are too long"
            );
        }
        for (issued_at, expires_at) in [
            (None, Some(issued + 600)),
            (Some(issued), None),
            (Some(issued), Some(issued)),
            (Some(issued + 1), Some(issued)),
        ] {
            assert_eq!(
                task_grant_token_lifetime(issued_at, expires_at, now, leeway),
                Err(FailedCheck::TaskGrantClaims),
                "iat {issued_at:?} and exp {expires_at:?} are malformed"
            );
        }
    }

    #[test]
    fn task_grant_tokens_must_not_be_issued_later_than_now_plus_leeway() {
        let now: u64 = 1_800_000_000;
        let leeway = Duration::from_secs(60);
        let at = |offset: i64| i64::try_from(now).expect("test clock fits i64") + offset;
        for issued_at in [at(86_400), at(61)] {
            assert_eq!(
                task_grant_token_lifetime(Some(issued_at), Some(issued_at + 900), now, leeway),
                Err(FailedCheck::TaskGrantClaims),
                "iat {issued_at} later than now plus leeway is refused"
            );
        }
        for issued_at in [at(59), at(60)] {
            assert_eq!(
                task_grant_token_lifetime(Some(issued_at), Some(issued_at + 900), now, leeway),
                Ok(()),
                "iat {issued_at} within the leeway is accepted"
            );
        }
        assert_eq!(
            task_grant_token_lifetime(Some(at(0)), Some(at(900)), u64::MAX, leeway),
            Err(FailedCheck::TaskGrantClaims),
            "a clock that cannot bound iat refuses the token"
        );
    }
}
