// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the Scheduling HTTP surface.
//!
//! There is no unauthenticated mode: every `/v1` route resolves its caller
//! here first. Authentication answers three questions in order. Is the
//! credential a verifiable access token from the configured issuer, for this
//! deployment's audience, signed by a key the issuer published? Which actor
//! kind does it claim, and does it carry a complete task grant? And does the
//! caller hold the scope the route's authentication profile demands?
//!
//! The profiles mirror the route families. Catalogue, availability and
//! ordinary owner reads take callers holding the reads scope. One appointment
//! detail also accepts an explicit `appointment.read` task action so a
//! source-bound manager does not need catalogue authority; the service then
//! checks its exact retained service, location, manager and current status.
//! A current grant for the appointment's service and location can also read a
//! self-booked appointment by id, an accepted residual risk: grant the action
//! only to services whose workflow already selects the appointment (accepted
//! residual SCHEDULING-RES-01, see
//! https://docs.registrystack.org/security/scheduling/#scheduling-res-01-a-self-booked-appointment-is-readable-by-id-within-the-granted-service-and-location).
//! The explain path takes its own scope; cross-owner operational reads take
//! exactly one configured profile scope; mutating routes demand no extra
//! product scope because their authority is the task grant, whose scheduling
//! permissions the service checks per offering.
//!
//! The task grant is extracted with the platform's contextual-authorization
//! claim profile. A token with no grant claims is an ordinary standing
//! caller: it may read, and the service refuses its mutations. A token with
//! partial grant claims is a malformed credential, refused here rather than
//! half-trusted later.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use registry_platform_authcommon::{
    validate_compact_access_token, DeclaredScope, FailedCheck, RefusalRecorder,
};
use registry_platform_oidc::{
    grant_claims, refuses_development_assertion, ClaimError, ClaimNames, DeclaredKinds,
    IssuerEntry, IssuerSet, IssuerSetError, JwksFetcher, OidcError, TokenVerifier,
    TokenVerifierConfig, VerifiedCaller, ASSERTION_ISSUER_CLAIM,
};
use serde_json::Value;
use thiserror::Error;

use crate::config::OidcConfig;
use crate::operational::{
    authorize_operational_read, AuthorizedOperationalRead, OperationalIdentity,
    OperationalReadFilter, OperationalReadProfileConfig,
};
use crate::service::{Caller, DetailAdmission, APPOINTMENT_READ_ACTION};
use crate::source_busy::{
    authorize_busy_source, AuthorizedBusySource, BusyImportProfileConfig, BusySourceIdentity,
};

/// The actor kind recorded for a caller that neither the operator nor the
/// token gave a kind.
pub const UNSPECIFIED_ACTOR_KIND: &str = "unspecified";

/// Why [`SchedulingAuthenticator::new`] refused its sources.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorBuildError {
    /// Two sources carry one id, so one would replace the other's settings.
    #[error("two issuer sources share the id {0}")]
    DuplicateId(String),
    #[error(transparent)]
    Set(#[from] IssuerSetError),
}

/// One configured issuer: its id, the verifier profile it is held to, the
/// source of its signing keys, the caller kinds the operator declared for it,
/// and the audience the task grants it carries are bound to.
pub struct IssuerSource {
    id: String,
    verifier: TokenVerifierConfig,
    keys: Arc<JwksFetcher>,
    declared: DeclaredKinds,
    audience: String,
}

impl IssuerSource {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        verifier: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        declared: DeclaredKinds,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            verifier,
            keys,
            declared,
            audience: audience.into(),
        }
    }
}

/// The scopes and profiles of the deployment that hold for every issuer: what
/// each route family requires of a caller, whichever issuer signed its token.
#[derive(Clone, Debug)]
pub struct AuthorizationProfiles {
    pub reads_scope: String,
    pub explain_scope: String,
    pub appointment_read_profiles: BTreeMap<String, OperationalReadProfileConfig>,
    pub busy_import_profiles: BTreeMap<String, BusyImportProfileConfig>,
}

impl From<&OidcConfig> for AuthorizationProfiles {
    fn from(oidc: &OidcConfig) -> Self {
        Self {
            reads_scope: oidc.reads_scope.clone(),
            explain_scope: oidc.explain_scope.clone(),
            appointment_read_profiles: oidc.appointment_read_profiles.clone(),
            busy_import_profiles: oidc.busy_import_profiles.clone(),
        }
    }
}

/// What the deployment declared about one issuer entry, which a token it
/// verified is held to after verification.
struct IssuerSettings {
    /// The audience this entry's task grants are bound to.
    audience: String,
    /// The claim the entry reads scopes from, as configured.
    scope_claim: String,
    /// Whether the entry declared any assertion authority at all.
    binds_assertion_issuers: bool,
}

/// A credential the issuer set verified, resolved to its caller.
struct Authenticated {
    caller: Caller,
    scopes: Vec<String>,
    client: Option<String>,
    /// The scope claim of the entry that verified the credential.
    scope_claim: String,
}

pub struct SchedulingAuthenticator {
    peer_policy: registry_platform_httputil::PeerPolicy,
    issuers: IssuerSet,
    settings: BTreeMap<String, IssuerSettings>,
    claim_names: ClaimNames,
    reads_scope: String,
    explain_scope: String,
    appointment_read_profiles: BTreeMap<String, OperationalReadProfileConfig>,
    busy_import_profiles: BTreeMap<String, BusyImportProfileConfig>,
    /// Counts and logs every refusal the HTTP edge answers, by failed check.
    refusals: Arc<RefusalRecorder>,
}

impl SchedulingAuthenticator {
    /// The recorder the HTTP edge reports each refusal to, and whose counter
    /// the metrics listener exposes.
    #[must_use]
    pub fn refusals(&self) -> &Arc<RefusalRecorder> {
        &self.refusals
    }

    /// Whether the audit qualifies each granted principal by its token
    /// issuer: with more than one issuer entry one subject can come from two
    /// issuers, and a deployment of one entry keeps the pseudonyms it always
    /// wrote.
    #[must_use]
    pub fn qualifies_audit_principals(&self) -> bool {
        self.settings.len() > 1
    }

    /// The authenticator over `sources`, one entry per issuer. Two entries
    /// that name one issuer are refused.
    pub fn new(
        profiles: impl Into<AuthorizationProfiles>,
        sources: Vec<IssuerSource>,
    ) -> Result<Self, AuthenticatorBuildError> {
        let profiles = profiles.into();
        // The default contextual-claim profile is the closed one this product
        // speaks; validating it here keeps a future name change honest.
        let claim_names = ClaimNames::default();
        claim_names
            .validate()
            .expect("the default contextual claim names are valid");
        let mut settings = BTreeMap::new();
        let mut entries = Vec::new();
        for source in sources {
            let replaced = settings.insert(
                source.id.clone(),
                IssuerSettings {
                    audience: source.audience,
                    scope_claim: source.verifier.scope_claim.clone(),
                    binds_assertion_issuers: !source.verifier.assertion_issuers.is_empty(),
                },
            );
            // A repeated id would let the second entry's audience, scope
            // claim and assertion binding stand in for the first's.
            if replaced.is_some() {
                return Err(AuthenticatorBuildError::DuplicateId(source.id));
            }
            entries.push(IssuerEntry::new(
                source.id,
                TokenVerifier::new(source.verifier, source.keys),
                source.declared,
            ));
        }
        Ok(Self {
            peer_policy: registry_platform_httputil::PeerPolicy::RefuseDevelopmentPeer,
            issuers: IssuerSet::new(entries, ClaimNames::default())?,
            settings,
            claim_names,
            reads_scope: profiles.reads_scope,
            explain_scope: profiles.explain_scope,
            appointment_read_profiles: profiles.appointment_read_profiles,
            busy_import_profiles: profiles.busy_import_profiles,
            refusals: Arc::new(
                RefusalRecorder::new("scheduling").expect("the refusal counter is declared once"),
            ),
        })
    }

    #[must_use]
    pub fn with_peer_policy(mut self, peer_policy: registry_platform_httputil::PeerPolicy) -> Self {
        self.peer_policy = peer_policy;
        self
    }

    /// The issuer set's verdict on `token`: the entry that verified it with
    /// the caller kind settled, or the refusal with the check that failed.
    pub async fn verify(
        &self,
        token: &str,
    ) -> Result<VerifiedCaller, registry_platform_oidc::CallerRefusal> {
        self.issuers.verify(token).await
    }

    /// The profile every catalogue, availability, and owned-record read
    /// demands: the caller holds the configured reads scope.
    pub async fn authenticate_read(&self, token: &str) -> Result<Caller, AuthenticationFailure> {
        let authenticated = self.verified_caller(token).await?;
        self.require_scope(authenticated, &self.reads_scope)
    }

    /// Authenticate the one appointment-detail route. Ordinary owner reads
    /// keep the configured reads scope. An assisted manager may instead
    /// present a structurally valid task grant carrying `appointment.read`;
    /// the service still binds that action to the appointment's retained
    /// service and location under fresh online status, and for a
    /// source-managed appointment to the stored manager. For a self-booked
    /// appointment a current grant for that service and location reads it by
    /// id (accepted residual SCHEDULING-RES-01, see
    /// https://docs.registrystack.org/security/scheduling/#scheduling-res-01-a-self-booked-appointment-is-readable-by-id-within-the-granted-service-and-location).
    /// The returned admission records which of the two admitted the caller;
    /// a caller holding the reads scope is admitted by it even with a grant.
    pub async fn authenticate_appointment_detail(
        &self,
        token: &str,
    ) -> Result<(Caller, DetailAdmission), AuthenticationFailure> {
        let authenticated = self.verified_caller(token).await?;
        if authenticated
            .scopes
            .iter()
            .any(|scope| scope == &self.reads_scope)
        {
            return Ok((authenticated.caller, DetailAdmission::ReadsScope));
        }
        let caller = authenticated.caller;
        if caller.grant.as_ref().is_some_and(|grant| {
            grant
                .bounds()
                .scheduling_permissions()
                .is_some_and(|permissions| {
                    permissions.iter().any(|permission| {
                        permission
                            .actions()
                            .iter()
                            .any(|action| action == APPOINTMENT_READ_ACTION)
                    })
                })
        }) {
            return Ok((caller, DetailAdmission::Grant));
        }
        Err(
            AuthenticationFailure::from(AuthenticationError::Profile(FailedCheck::Scope))
                .declaring(
                    DeclaredScope::new(&authenticated.scope_claim)
                        .with_required_scope(&self.reads_scope),
                ),
        )
    }

    /// The profile the separately authorized explain path demands: the caller
    /// holds the explain scope, which is never the reads scope.
    pub async fn authenticate_explain(&self, token: &str) -> Result<Caller, AuthenticationFailure> {
        let authenticated = self.verified_caller(token).await?;
        self.require_scope(authenticated, &self.explain_scope)
    }

    /// Admit a verified caller holding `required`, or refuse it as a profile
    /// miss. Nothing about the refusal's answer names a scope or claim value.
    /// The values the deployment declared for the scope ride with the refusal
    /// to the operator's log line.
    fn require_scope(
        &self,
        authenticated: Authenticated,
        required: &str,
    ) -> Result<Caller, AuthenticationFailure> {
        if authenticated.scopes.iter().any(|scope| scope == required) {
            return Ok(authenticated.caller);
        }
        Err(
            AuthenticationFailure::from(AuthenticationError::Profile(FailedCheck::Scope))
                .declaring(
                    DeclaredScope::new(&authenticated.scope_claim).with_required_scope(required),
                ),
        )
    }

    /// The profile the commitments demand: no product scope, because the
    /// authority for a mutation is the task grant the service checks against
    /// the offering's service, location, and action.
    pub async fn authenticate_mutate(&self, token: &str) -> Result<Caller, AuthenticationFailure> {
        self.verified_caller(token)
            .await
            .map(|authenticated| authenticated.caller)
    }

    /// Select exactly one operator-configured busy source profile. Holding a
    /// second profile's scope does not union either source or resource set.
    pub async fn authenticate_busy_source(
        &self,
        token: &str,
        profile_selector: &str,
    ) -> Result<AuthorizedBusySource, AuthenticationFailure> {
        let authenticated = self.verified_caller(token).await?;
        let client = authenticated
            .client
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClient))?;
        let identity = BusySourceIdentity::new(
            authenticated.caller.issuer,
            authenticated.caller.subject,
            client,
        )
        .map_err(|_| AuthenticationError::Profile(FailedCheck::TokenClaims))?;
        authorize_busy_source(
            &self.busy_import_profiles,
            &authenticated.scopes,
            Some(profile_selector),
            identity,
        )
        .map_err(|error| {
            AuthenticationFailure::from(AuthenticationError::Profile(error.failed_check()))
                .declaring(self.declared_busy_scope(&authenticated.scope_claim, profile_selector))
        })
    }

    /// The configured values a source-busy scope refusal's log line names:
    /// the profile's scope, and the profile id when the deployment declares
    /// that profile.
    fn declared_busy_scope(&self, scope_claim: &str, profile_selector: &str) -> DeclaredScope {
        let declared = DeclaredScope::new(scope_claim);
        match self.busy_import_profiles.get(profile_selector) {
            Some(profile) => declared
                .with_required_scope(&profile.scope)
                .with_access_profile(profile_selector),
            None => declared,
        }
    }

    /// Verify one token and authorize exactly one opt-in operational profile
    /// for the already-normalized request. Neither the catalogue scope nor a
    /// task grant participates in this decision.
    pub async fn authenticate_operational_read(
        &self,
        token: &str,
        profile_selector: Option<&str>,
        filter: OperationalReadFilter,
        now: DateTime<Utc>,
    ) -> Result<AuthorizedOperationalRead, AuthenticationFailure> {
        let authenticated = self.verified_caller(token).await?;
        let client = authenticated
            .client
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClient))?;
        let identity = OperationalIdentity::new(
            authenticated.caller.issuer,
            authenticated.caller.subject,
            client,
        )
        .map_err(|_| AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        authorize_operational_read(
            &self.appointment_read_profiles,
            &authenticated.scopes,
            profile_selector,
            identity,
            filter,
            now,
        )
        .map_err(|_| {
            AuthenticationFailure::from(AuthenticationError::Profile(FailedCheck::AccessProfile))
        })
    }

    /// Verify one credential and resolve its caller. A present grant is bound
    /// to the verified client and the verifying entry's audience before the
    /// caller ever reaches the service.
    async fn verified_caller(&self, token: &str) -> Result<Authenticated, AuthenticationFailure> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let verified = self.verify(token).await.map_err(|refusal| {
            let mut failure = AuthenticationFailure::from(verifier_failure(&refusal.error));
            failure.remedy = refusal.remedy;
            failure
        })?;
        if refuses_development_assertion(&verified.token, self.peer_policy) {
            return Err(AuthenticationError::DevelopmentAssertion.into());
        }
        let settings = self
            .settings
            .get(&*verified.issuer_id)
            .ok_or(AuthenticationError::Refused(FailedCheck::TokenIssuer))?;
        let claims = &verified.token.claims;
        // An exchanged token names the authority whose assertion produced it.
        // The platform applies no rule while the entry's map is empty, so an
        // empty map would trust every authority the issuer federates. Refuse
        // the exchange instead: a deployment that means to accept one says
        // which authorities, and which client may present them.
        if !settings.binds_assertion_issuers && claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
            return Err(AuthenticationError::Profile(FailedCheck::TokenAssertionIssuer).into());
        }
        let actor_kind = verified
            .kind
            .kind()
            .map_or(UNSPECIFIED_ACTOR_KIND, |kind| kind.as_str());
        let grant = grant_claims(claims, &self.claim_names, unix_now()?).map_err(|error| {
            AuthenticationError::Claims(match error {
                ClaimError::Expired => FailedCheck::TaskGrantExpired,
                _ => FailedCheck::TaskGrantClaims,
            })
        })?;
        if let Some(grant) = &grant {
            grant
                .verify_context(&verified.token, &settings.audience, self.peer_policy)
                .map_err(|_| AuthenticationError::Profile(FailedCheck::TaskGrantBinding))?;
        }
        let client = verified
            .token
            .matched_client_id()
            .map_err(|_| AuthenticationError::Claims(FailedCheck::TokenClient))?
            .filter(|client| !client.is_empty())
            .map(str::to_owned);
        // A task-grant exchange preserves the subjects its source authority
        // approved in the signed `identity` object. Keep only an object-shaped value. The shared
        // binding validates its field and value bounds before any use. The
        // offline path that `unchecked-final-fifteen-minutes` selects does not
        // require this member, so absence or an older shape remains a
        // status-binding miss rather than changing bearer admission; a
        // service that lists status authorities fails that miss closed before
        // capacity is touched.
        let task_grant_subjects = grant.as_ref().and_then(|_| {
            claims
                .extra
                .get("identity")
                .cloned()
                .and_then(|value| serde_json::from_value::<BTreeMap<String, Value>>(value).ok())
        });
        // The issuer is the verifying entry's own, which the token's `iss`
        // matched exactly, so one subject from two issuers is two principals.
        let issuer = claims
            .iss
            .clone()
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        let subject = claims
            .sub
            .clone()
            .filter(|subject| !subject.is_empty())
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        let credential_exp_unix = claims
            .exp
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        Ok(Authenticated {
            caller: Caller {
                actor_kind: actor_kind.to_owned(),
                issuer,
                subject,
                credential_exp_unix,
                grant,
                task_grant_subjects,
            },
            scopes: verified.token.scopes,
            client,
            scope_claim: settings.scope_claim.clone(),
        })
    }
}

impl std::fmt::Debug for SchedulingAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SchedulingAuthenticator")
            .field("issuers", &"<redacted>")
            .field("reads_scope", &self.reads_scope)
            .field("explain_scope", &self.explain_scope)
            .field(
                "appointment_read_profile_count",
                &self.appointment_read_profiles.len(),
            )
            .finish()
    }
}

/// Why authentication refused a request. Each refusal carries the check it
/// failed, which only the operator sees: the answer to the caller is the same
/// for every check of one kind.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused(FailedCheck),
    #[error("the verified identity claims are invalid")]
    Claims(FailedCheck),
    #[error("the caller's authentication profile is not authorized for this request")]
    Profile(FailedCheck),
    #[error("production refuses task assertions issued in development")]
    DevelopmentAssertion,
    /// The verifier could not reach a verdict at all.
    #[error("the credential could not be verified because this verifier cannot answer")]
    Unavailable,
}

/// A refusal of authentication with what the deployment declared about it:
/// the scope values of a scope refusal, and the sentence that names the
/// setting a verifier refusal involves. Both are for the operator's log line
/// and never enter a response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationFailure {
    pub error: AuthenticationError,
    pub declared: Option<DeclaredScope>,
    pub remedy: Option<&'static str>,
}

impl AuthenticationFailure {
    fn declaring(mut self, declared: DeclaredScope) -> Self {
        self.declared = Some(declared);
        self
    }
}

impl From<AuthenticationError> for AuthenticationFailure {
    fn from(error: AuthenticationError) -> Self {
        Self {
            error,
            declared: None,
            remedy: None,
        }
    }
}

/// Separate a verifier outage from a bad credential.
///
/// A 401 tells a caller its credential is the problem, so it has to be
/// reserved for credentials. When the issuer's discovery document or key set
/// cannot be fetched, read, parsed or used, nothing has been learned about
/// the credential, and telling the caller to fix it would send it rotating a
/// perfectly good token through an incident that is ours. A deployment whose
/// own OIDC settings are contradictory is the same kind of failure.
fn verifier_failure(error: &OidcError) -> AuthenticationError {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk
        | OidcError::EmptyKeySet
        | OidcError::MissingIssuer
        | OidcError::ConflictingEndpointConfiguration => AuthenticationError::Unavailable,
        // Every other outcome is a judgement about the credential, including
        // an unknown `kid`: a key the issuer never published is a forgery
        // signal, not an outage, and answering 503 there would let a caller
        // probe the key set. A variant added to the platform later is read as
        // a credential refusal until it is classified here, so a new outcome
        // can never widen the door. The check the refusal records is the
        // shared verifier's own map.
        _ => AuthenticationError::Refused(error.failed_check()),
    }
}

/// The observation of now the grant's expiry is judged against, in the same
/// units the token's own `exp` carries.
fn unix_now() -> Result<u64, AuthenticationError> {
    unix_seconds(SystemTime::now())
}

/// Read one clock observation as seconds since the epoch.
///
/// A reading that cannot be taken is refused rather than substituted. Epoch
/// zero is before every `exp` a credential carries, so falling back to it
/// would pass every expiry check at once: an expired grant would keep
/// committing capacity for as long as the clock stayed unreadable, and the
/// deployment would be told nothing. Nothing has been learned about the
/// credential either, so the answer is the outage answer, not a challenge.
/// The edge counts that answer as `key-source-unavailable` because no member
/// names a clock failure. The error line above names the clock.
fn unix_seconds(observed: SystemTime) -> Result<u64, AuthenticationError> {
    observed
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| {
            tracing::error!(
                "the system clock reads before the Unix epoch; refusing to judge an expiry"
            );
            AuthenticationError::Unavailable
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{ActorKind, JwksFetcherConfig, ASSERTION_ISSUER_CLAIM};
    use serde_json::json;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ISSUER: &str = "https://task-token.test";
    const AUDIENCE: &str = "urn:registry-scheduling:test";
    const CLIENT: &str = "task-agent";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    fn profiles() -> AuthorizationProfiles {
        AuthorizationProfiles {
            reads_scope: "scheduling-read".to_owned(),
            explain_scope: "scheduling-explain".to_owned(),
            appointment_read_profiles: BTreeMap::new(),
            busy_import_profiles: BTreeMap::new(),
        }
    }

    fn profiles_with_operational_profiles() -> AuthorizationProfiles {
        let mut oidc = profiles();
        oidc.appointment_read_profiles = BTreeMap::from([
            (
                "north-desk".to_owned(),
                crate::operational::OperationalReadProfileConfig {
                    scope: "scheduling:appointments:north".to_owned(),
                    maximum_past_days: 7,
                    maximum_future_days: 31,
                    maximum_span_days: 1,
                    permissions: vec![crate::operational::OperationalReadPermissionConfig {
                        service: "registry-update".to_owned(),
                        location: "north-counter".to_owned(),
                        resources: crate::operational::OperationalResourceScope::Exact {
                            ids: vec!["station-1".to_owned()],
                        },
                    }],
                    projection: crate::operational::OperationalProjectionConfig {
                        fields: vec![crate::operational::OperationalProjectionField::Resource],
                        external_reference_products: Vec::new(),
                    },
                },
            ),
            (
                "south-desk".to_owned(),
                crate::operational::OperationalReadProfileConfig {
                    scope: "scheduling:appointments:south".to_owned(),
                    maximum_past_days: 7,
                    maximum_future_days: 31,
                    maximum_span_days: 1,
                    permissions: vec![crate::operational::OperationalReadPermissionConfig {
                        service: "registry-update".to_owned(),
                        location: "south-counter".to_owned(),
                        resources: crate::operational::OperationalResourceScope::Unrestricted {},
                    }],
                    projection: crate::operational::OperationalProjectionConfig {
                        fields: vec![crate::operational::OperationalProjectionField::Resource],
                        external_reference_products: Vec::new(),
                    },
                },
            ),
        ]);
        oidc
    }

    fn operational_filter() -> crate::operational::OperationalReadFilter {
        crate::operational::OperationalReadFilter::new(
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            None,
            crate::operational::OperationalTimeBasis::Displayed,
            Utc::now() - chrono::TimeDelta::hours(1),
            Utc::now() + chrono::TimeDelta::hours(1),
        )
        .unwrap()
    }

    fn keys() -> Arc<JwksFetcher> {
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(json!({"keys": [{
                "kty": "oct",
                "kid": "test",
                "alg": "HS256",
                "use": "sig",
                "k": URL_SAFE_NO_PAD.encode(SECRET),
            }]}))
            .unwrap(),
            JwksFetcherConfig::defaults(),
        ))
    }

    fn authenticator() -> SchedulingAuthenticator {
        authenticator_with(profiles())
    }

    /// The verifier profile of the entry every test reads: one audience, one
    /// client, the scope claim the tests sign under.
    fn verifier(
        algorithm: Algorithm,
        assertion_issuers: BTreeMap<String, Vec<String>>,
    ) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![algorithm],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("registry_scopes")
        .with_allowed_clients(vec![CLIENT.to_owned()])
        .with_assertion_issuers(assertion_issuers)
    }

    /// One issuer entry, `main`, over `keys` with no declared caller kinds.
    fn main_source(
        verifier: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        declared: DeclaredKinds,
    ) -> IssuerSource {
        IssuerSource::new("main", verifier, keys, declared, AUDIENCE)
    }

    /// Build the authenticator the way the runtime does, so the verifier and
    /// the authenticator read the same deployment settings.
    fn authenticator_with(profiles: AuthorizationProfiles) -> SchedulingAuthenticator {
        authenticator_over(profiles, keys())
    }

    /// The same deployment reading a different key source, so a test can put
    /// the issuer's key endpoint out of service without changing anything
    /// else about the caller or the profile.
    fn authenticator_over(
        profiles: AuthorizationProfiles,
        keys: Arc<JwksFetcher>,
    ) -> SchedulingAuthenticator {
        SchedulingAuthenticator::new(
            profiles,
            vec![main_source(
                verifier(Algorithm::HS256, BTreeMap::new()),
                keys,
                DeclaredKinds::None,
            )],
        )
        .unwrap()
    }

    /// Sign an access token, filling in the claims a real token always
    /// carries so a test only has to state what it varies.
    fn token(mut claims: serde_json::Value) -> String {
        let now = Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.entry("iss").or_insert(json!(ISSUER));
        object.entry("aud").or_insert(json!(AUDIENCE));
        object.entry("iat").or_insert(json!(now));
        object.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    /// The complete task-grant claim set a mutating caller carries, with the
    /// bounds the test's permission assertions read.
    fn grant_claims_value(resource: &str) -> serde_json::Value {
        let now = Utc::now().timestamp();
        json!({
            "registry_actor_kind": "agent",
            "registry_purpose": "registry-update",
            "registry_grant_id": "11111111-1111-4111-8111-111111111111",
            "registry_grant_source_issuer": "https://authority.test",
            "registry_grant_client": CLIENT,
            "registry_grant_resource": resource,
            "registry_grant_exp": now + 600,
            "registry_grant_bounds": {
                "type": "scheduling",
                "permissions": [{
                    "service": "registry-update",
                    "location": "north-counter",
                    "actions": ["hold.create", "appointment.create"],
                }],
            },
            "identity": {"subject_reference": "synthetic-subject"},
            "registry_approver": "approver-1",
        })
    }

    fn merged(scopes: &str, grant: serde_json::Value) -> serde_json::Value {
        let mut claims = json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": scopes,
            "registry_actor_kind": "service",
        });
        let object = claims.as_object_mut().unwrap();
        object.extend(
            grant
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        claims
    }

    #[tokio::test]
    async fn a_read_caller_with_the_reads_scope_authenticates_without_a_grant() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        let caller = authenticator()
            .authenticate_read(&credential)
            .await
            .expect("a standing caller holding the reads scope reads");
        assert_eq!(caller.actor_kind, "service");
        assert_eq!(caller.issuer, ISSUER);
        assert_eq!(caller.subject, "principal-1");
        assert!(caller.grant.is_none());
    }

    #[tokio::test]
    async fn appointment_detail_records_the_reads_scope_as_the_admission_when_both_are_held() {
        let mut grant = grant_claims_value(AUDIENCE);
        grant["registry_grant_bounds"]["permissions"][0]["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!(APPOINTMENT_READ_ACTION));
        let credential = token(merged("scheduling-read", grant));
        let (_, admission) = authenticator()
            .authenticate_appointment_detail(&credential)
            .await
            .expect("the reads scope admits");
        assert_eq!(admission, DetailAdmission::ReadsScope);
    }

    #[tokio::test]
    async fn appointment_detail_accepts_its_explicit_grant_without_opening_other_reads() {
        let mut grant = grant_claims_value(AUDIENCE);
        grant["registry_grant_bounds"]["permissions"][0]["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!(APPOINTMENT_READ_ACTION));
        let credential = token(merged("scheduling-explain", grant));
        let authenticator = authenticator();
        let (_, admission) = authenticator
            .authenticate_appointment_detail(&credential)
            .await
            .expect("the explicit detail action opens only the detail profile");
        assert_eq!(admission, DetailAdmission::Grant);
        assert!(matches!(
            authenticator.authenticate_read(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Profile(FailedCheck::Scope),
                ..
            })
        ));

        let without_action = token(merged("scheduling-explain", grant_claims_value(AUDIENCE)));
        assert!(matches!(
            authenticator
                .authenticate_appointment_detail(&without_action)
                .await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Profile(FailedCheck::Scope),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_read_without_the_reads_scope_is_a_profile_refusal_but_still_mutates() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "unrelated-scope",
            "registry_actor_kind": "service",
        }));
        let authenticator = authenticator();
        assert!(matches!(
            authenticator.authenticate_read(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Profile(FailedCheck::Scope),
                ..
            })
        ));
        // Mutating routes demand no product scope: their authority is the
        // task grant, checked per offering in the service.
        authenticator
            .authenticate_mutate(&credential)
            .await
            .expect("a caller without the reads scope still reaches a mutation");
    }

    #[tokio::test]
    async fn operational_authority_comes_only_from_one_selected_profile_scope() {
        let authenticator = authenticator_with(profiles_with_operational_profiles());
        let catalogue_reader = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        assert_eq!(
            authenticator
                .authenticate_operational_read(
                    &catalogue_reader,
                    None,
                    operational_filter(),
                    Utc::now(),
                )
                .await,
            Err(AuthenticationFailure::from(AuthenticationError::Profile(
                FailedCheck::AccessProfile
            )))
        );

        let grant_only = token(merged("", grant_claims_value(AUDIENCE)));
        // A grant is not a scope. With no scope and no declared kind the token
        // is an identity-only token, which the issuer set refuses before any
        // profile is consulted.
        assert!(matches!(
            authenticator
                .authenticate_operational_read(&grant_only, None, operational_filter(), Utc::now(),)
                .await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Refused(FailedCheck::ActorKind),
                ..
            })
        ));

        let two_roles = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling:appointments:north scheduling:appointments:south",
            "registry_actor_kind": "service",
        }));
        assert_eq!(
            authenticator
                .authenticate_operational_read(&two_roles, None, operational_filter(), Utc::now(),)
                .await,
            Err(AuthenticationFailure::from(AuthenticationError::Profile(
                FailedCheck::AccessProfile
            )))
        );
        let authorized = authenticator
            .authenticate_operational_read(
                &two_roles,
                Some("north-desk"),
                operational_filter(),
                Utc::now(),
            )
            .await
            .expect("the selector chooses one already-authorized role");
        assert_eq!(authorized.profile_id(), "north-desk");
    }

    #[tokio::test]
    async fn the_explain_path_demands_its_own_scope() {
        let authenticator = authenticator();
        let reader = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        assert!(matches!(
            authenticator.authenticate_explain(&reader).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Profile(FailedCheck::Scope),
                ..
            })
        ));
        let explainer = token(json!({
            "sub": "principal-2",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read scheduling-explain",
            "registry_actor_kind": "service",
        }));
        authenticator
            .authenticate_explain(&explainer)
            .await
            .expect("the explain scope opens the explain path");
    }

    #[tokio::test]
    async fn production_refuses_a_marked_token_without_grant_claims() {
        let mut claims = merged("scheduling-read", json!({}));
        let unmarked = token(claims.clone());
        authenticator().authenticate_read(&unmarked).await.unwrap();
        claims[registry_platform_oidc::POSTURE_CLAIM] = json!("development");
        let marked = token(claims);
        assert!(matches!(
            authenticator().authenticate_read(&marked).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::DevelopmentAssertion,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_complete_task_grant_is_extracted_and_bound_to_the_deployment() {
        let credential = token(merged("scheduling-read", grant_claims_value(AUDIENCE)));
        let caller = authenticator()
            .authenticate_mutate(&credential)
            .await
            .expect("a complete grant authenticates");
        let grant = caller.grant.expect("the grant is extracted");
        assert_eq!(caller.actor_kind, "agent");
        let permissions = grant
            .bounds()
            .scheduling_permissions()
            .expect("the scheduling bounds travel with the grant");
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].service(), "registry-update");
        assert_eq!(permissions[0].location(), "north-counter");
        assert!(permissions[0]
            .actions()
            .iter()
            .any(|action| action == "hold.create"));
    }

    #[tokio::test]
    async fn production_refuses_a_development_task_assertion() {
        let mut grant = grant_claims_value(AUDIENCE);
        grant["registry_posture"] = json!("development");
        let credential = token(merged("scheduling-read", grant));
        assert!(matches!(
            authenticator().authenticate_mutate(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::DevelopmentAssertion,
                ..
            })
        ));
        authenticator()
            .with_peer_policy(registry_platform_httputil::PeerPolicy::AcceptDevelopmentPeer)
            .authenticate_mutate(&credential)
            .await
            .expect("a development peer admits the same grant");
    }

    #[tokio::test]
    async fn an_offline_path_grant_need_not_carry_status_binding_members() {
        let mut grant = grant_claims_value(AUDIENCE);
        grant["registry_grant_id"] = json!("grant-1");
        grant
            .as_object_mut()
            .expect("grant claims are an object")
            .remove("identity");
        let credential = token(merged("scheduling-read", grant));
        let caller = authenticator()
            .authenticate_mutate(&credential)
            .await
            .expect("the offline grant still reaches the service");
        assert!(caller.grant.is_some());
        assert!(caller.task_grant_subjects.is_none());
    }

    #[tokio::test]
    async fn a_grant_naming_another_resource_is_a_profile_refusal() {
        let credential = token(merged(
            "scheduling-read",
            grant_claims_value("urn:registry:other-product"),
        ));
        assert!(matches!(
            authenticator().authenticate_mutate(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Profile(FailedCheck::TaskGrantBinding),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_partial_grant_is_refused_as_invalid_claims() {
        let mut grant = grant_claims_value(AUDIENCE);
        let object = grant.as_object_mut().unwrap();
        object.remove("registry_grant_exp");
        object.remove("registry_grant_client");
        let credential = token(merged("scheduling-read", grant));
        assert!(matches!(
            authenticator().authenticate_mutate(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Claims(FailedCheck::TaskGrantClaims),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn an_actor_kind_outside_the_vocabulary_is_refused() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "robot",
        }));
        assert!(matches!(
            authenticator().authenticate_read(&credential).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Refused(FailedCheck::ActorKind),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn an_exchanged_token_is_refused_until_its_authority_is_declared() {
        const AUTHORITY: &str = "https://authority.example.test";
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
            ASSERTION_ISSUER_CLAIM: AUTHORITY,
        }));
        assert!(
            matches!(
                authenticator().authenticate_read(&credential).await,
                Err(AuthenticationFailure {
                    error: AuthenticationError::Profile(FailedCheck::TokenAssertionIssuer),
                    ..
                })
            ),
            "an exchanged token was accepted by a deployment that declared no assertion authority"
        );

        let declared = || {
            SchedulingAuthenticator::new(
                profiles(),
                vec![main_source(
                    verifier(
                        Algorithm::HS256,
                        BTreeMap::from([(CLIENT.to_owned(), vec![AUTHORITY.to_owned()])]),
                    ),
                    keys(),
                    DeclaredKinds::None,
                )],
            )
            .unwrap()
        };
        declared()
            .authenticate_read(&credential)
            .await
            .expect("a declared authority's exchanged token reads");

        // The platform still refuses an authority the client may not exchange
        // from once the map is populated.
        let other = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
            ASSERTION_ISSUER_CLAIM: "https://unrelated.example.test",
        }));
        assert!(matches!(
            declared().authenticate_read(&other).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Refused(FailedCheck::TokenAssertionIssuer),
                ..
            })
        ));
    }

    #[test]
    fn an_unreadable_clock_refuses_to_judge_an_expiry_rather_than_passing_it() {
        // What the fallback reading would have meant. Epoch zero is before
        // every `exp` a credential carries, so a grant that expired an hour
        // ago still reads as live, and would keep committing capacity for as
        // long as the clock stayed unreadable.
        let names = ClaimNames::default();
        let now = Utc::now().timestamp();
        let mut expired = grant_claims_value(AUDIENCE);
        expired
            .as_object_mut()
            .unwrap()
            .insert("registry_grant_exp".to_owned(), json!(now - 3_600));
        let mut value = merged("scheduling-read", expired);
        let object = value.as_object_mut().unwrap();
        object.insert("iss".to_owned(), json!(ISSUER));
        object.insert("aud".to_owned(), json!(AUDIENCE));
        object.insert("exp".to_owned(), json!(now + 300));
        let claims: registry_platform_oidc::Claims = serde_json::from_value(value).unwrap();
        assert!(
            grant_claims(&claims, &names, 0).is_ok(),
            "epoch zero would have passed a grant that expired an hour ago"
        );
        assert!(grant_claims(&claims, &names, now as u64).is_err());

        // So a reading that cannot be taken is refused outright. The caller is
        // told to come back; it is never told its credential is good.
        assert_eq!(
            unix_seconds(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            Ok(1_700_000_000)
        );
        assert_eq!(
            unix_seconds(UNIX_EPOCH - Duration::from_secs(1)),
            Err(AuthenticationError::Unavailable)
        );
    }

    #[tokio::test]
    async fn a_key_endpoint_outage_is_unavailable_not_a_refusal() {
        // The issuer is up enough to answer, and answers that it cannot serve
        // its key set. Nothing has been learned about the credential, so
        // blaming it would send a caller holding a perfectly good token off
        // to rotate credentials during an incident on this side.
        let issuer_keys = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&issuer_keys)
            .await;
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        let during_outage = authenticator_over(
            profiles(),
            Arc::new(JwksFetcher::new_with_fetch_url_policy(
                format!("{}/jwks.json", issuer_keys.uri()),
                JwksFetcherConfig::defaults(),
                FetchUrlPolicy::https_or_loopback(),
            )),
        );
        assert!(
            matches!(
                during_outage.authenticate_read(&credential).await,
                Err(AuthenticationFailure {
                    error: AuthenticationError::Unavailable,
                    ..
                })
            ),
            "a key endpoint that cannot answer was reported as a bad credential"
        );
    }

    #[test]
    fn only_a_verifier_that_reached_no_verdict_is_unavailable() {
        for outage in [
            OidcError::HttpStatus(503),
            OidcError::InvalidUrl,
            OidcError::Parse,
            OidcError::InvalidJwk,
            OidcError::EmptyKeySet,
            OidcError::MissingIssuer,
            OidcError::ConflictingEndpointConfiguration,
        ] {
            assert_eq!(
                verifier_failure(&outage),
                AuthenticationError::Unavailable,
                "{outage} was blamed on the credential"
            );
        }
        for refusal in [
            OidcError::IssuerMismatch {
                expected: ISSUER.to_owned(),
                actual: "https://elsewhere.test".to_owned(),
            },
            OidcError::MalformedToken,
            OidcError::AlgorithmNotAllowed,
            OidcError::TokenTypeNotAllowed,
            OidcError::MissingKid,
            OidcError::KidTooLong,
            // An unknown `kid` is a key the issuer never published, which is a
            // forgery signal and not an outage. Answering 503 here would also
            // hand a caller a probe for the key set.
            OidcError::UnknownKid,
            OidcError::TokenExpired,
            OidcError::TokenNotYetValid,
            OidcError::AudienceMismatch,
            OidcError::SignatureInvalid,
            OidcError::InvalidToken,
            OidcError::InvalidTimeClaims,
            OidcError::ClientNotAllowed,
            OidcError::AssertionIssuerNotAllowed,
        ] {
            assert_eq!(
                verifier_failure(&refusal),
                AuthenticationError::Refused(refusal.failed_check()),
                "{refusal} was excused as an outage"
            );
        }
    }

    #[tokio::test]
    async fn a_credential_signed_by_an_unknown_key_is_refused() {
        let mut claims = json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": ActorKind::Service.as_str(),
        });
        let now = Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.insert("iss".to_owned(), json!(ISSUER));
        object.insert("aud".to_owned(), json!(AUDIENCE));
        object.insert("iat".to_owned(), json!(now));
        object.insert("exp".to_owned(), json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        let forged = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"another-secret-another-secret-another!"),
        )
        .unwrap();
        assert!(matches!(
            authenticator().authenticate_read(&forged).await,
            Err(AuthenticationFailure {
                error: AuthenticationError::Refused(FailedCheck::TokenSignature),
                ..
            })
        ));
    }
    #[tokio::test]
    async fn malformed_compact_tokens_are_refused_as_malformed_credentials_and_logged_value_free() {
        use registry_platform_testing::CapturedDiagnosticLogs;
        use tracing::instrument::WithSubscriber;
        let captured = CapturedDiagnosticLogs::default();
        let subscriber = captured.subscriber();
        let tokens = registry_platform_testing::malformed_access_token_fixtures();
        let auth = authenticator();
        let malformed = Some(AuthenticationError::Refused(
            FailedCheck::CredentialMalformed,
        ));
        for token in &tokens {
            assert_eq!(
                auth.authenticate_read(token)
                    .with_subscriber(subscriber.clone())
                    .await
                    .err()
                    .map(|failure| failure.error),
                malformed
            );
            assert_eq!(
                auth.authenticate_explain(token)
                    .with_subscriber(subscriber.clone())
                    .await
                    .err()
                    .map(|failure| failure.error),
                malformed
            );
            assert_eq!(
                auth.authenticate_mutate(token)
                    .with_subscriber(subscriber.clone())
                    .await
                    .err()
                    .map(|failure| failure.error),
                malformed
            );
        }
        // The refusal line is written at the HTTP edge. Whatever the
        // authenticator itself logs carries no part of a credential.
        let rendered = captured.text();
        assert!(!rendered.contains("canary"));
        for token in tokens.iter().filter(|token| !token.is_empty()) {
            assert!(
                !rendered.contains(token),
                "diagnostics must not contain credentials"
            );
        }
    }

    #[tokio::test]
    async fn separate_resource_rs256_and_es256_profiles_refuse_cross_resource_reuse() {
        for algorithm in [Algorithm::RS256, Algorithm::ES256] {
            let key = registry_platform_testing::access_token_test_key(algorithm);
            let jwks = serde_json::from_value(json!({"keys":[key.public()]})).unwrap();
            let source = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
            let auth = SchedulingAuthenticator::new(
                profiles(),
                vec![main_source(
                    verifier(algorithm, BTreeMap::new()),
                    source,
                    DeclaredKinds::None,
                )],
            )
            .unwrap();
            let now = Utc::now().timestamp();
            let claims = json!({"iss":ISSUER,"aud":AUDIENCE,"azp":CLIENT,"sub":"canary-person","registry_scopes":"scheduling-read","registry_actor_kind":"human","iat":now,"exp":now+300});
            let sign = |claims: serde_json::Value, typ: &str| {
                registry_platform_testing::sign_compact_jwt_with_key(
                    &key,
                    typ,
                    "canary-resource-key",
                    claims,
                )
            };
            registry_platform_testing::assert_resource_audience_and_token_type_rules(
                &key,
                claims.clone(),
                |token: String| {
                    let auth = &auth;
                    async move { auth.authenticate_read(&token).await }
                },
                |failure| matches!(failure.error, AuthenticationError::Refused(_)),
            )
            .await;
            // A valid symmetric JWT is outside the asymmetric production baseline.
            let token = self::token(
                json!({"azp":CLIENT,"registry_scopes":"scheduling-read","registry_actor_kind":"human"}),
            );
            assert!(matches!(
                auth.authenticate_read(&token).await,
                Err(AuthenticationFailure {
                    error: AuthenticationError::Refused(_),
                    ..
                })
            ));
            let mut wrong_actor = claims.clone();
            wrong_actor["registry_actor_kind"] = json!("canary-invalid-actor");
            let token = sign(wrong_actor, "at+jwt");
            assert!(matches!(
                auth.authenticate_read(&token).await,
                Err(AuthenticationFailure {
                    error: AuthenticationError::Refused(FailedCheck::ActorKind),
                    ..
                })
            ));
            let mut missing = claims.clone();
            missing["registry_scopes"] = json!("scheduling-other");
            let token = sign(missing, "at+jwt");
            assert!(matches!(
                auth.authenticate_read(&token).await,
                Err(AuthenticationFailure {
                    error: AuthenticationError::Profile(FailedCheck::Scope),
                    ..
                })
            ));
        }
    }

    // Helpers for the issuer-set tests.

    const PARTNER_ISSUER: &str = "https://partner.test";
    const PARTNER_AUDIENCE: &str = "urn:registry-scheduling:partner";
    const PARTNER_CLIENT: &str = "partner-agent";
    const PARTNER_SECRET: &[u8] = b"abcdefghijklmnopqrstuvwxyz012345";

    fn without(mut claims: serde_json::Value, key: &str) -> serde_json::Value {
        claims.as_object_mut().unwrap().remove(key);
        claims
    }

    fn with(
        mut claims: serde_json::Value,
        key: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        claims[key] = value;
        claims
    }

    /// Sign `claims` as `typ` with `secret`, filling in the times.
    fn signed_as(mut claims: serde_json::Value, typ: &str, secret: &[u8]) -> String {
        let now = Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.entry("iss").or_insert(json!(ISSUER));
        object.entry("aud").or_insert(json!(AUDIENCE));
        object.entry("iat").or_insert(json!(now));
        object.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some(typ.to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    fn jwt_typed(claims: serde_json::Value) -> String {
        signed_as(claims, "JWT", SECRET)
    }

    fn read_claims() -> serde_json::Value {
        json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        })
    }

    fn typed_verifier(
        access_token_type: registry_platform_config::AccessTokenType,
    ) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            registry_platform_oidc::access_token_types(access_token_type),
        )
        .with_scope_claim("registry_scopes")
        .with_allowed_clients(vec![CLIENT.to_owned()])
    }

    fn keys_for(secret: &[u8]) -> Arc<JwksFetcher> {
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(json!({"keys": [{
                "kty": "oct",
                "kid": "test",
                "alg": "HS256",
                "use": "sig",
                "k": URL_SAFE_NO_PAD.encode(secret),
            }]}))
            .unwrap(),
            JwksFetcherConfig::defaults(),
        ))
    }

    /// Two issuers, `main` and `partner`, each with its own keys, audience,
    /// scope claim and client.
    fn two_issuers() -> SchedulingAuthenticator {
        let partner = TokenVerifierConfig::access_token_profile(
            PARTNER_ISSUER,
            vec![PARTNER_AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("scp")
        .with_allowed_clients(vec![PARTNER_CLIENT.to_owned()]);
        SchedulingAuthenticator::new(
            profiles(),
            vec![
                main_source(
                    verifier(Algorithm::HS256, BTreeMap::new()),
                    keys(),
                    DeclaredKinds::None,
                ),
                IssuerSource::new(
                    "partner",
                    partner,
                    keys_for(PARTNER_SECRET),
                    DeclaredKinds::None,
                    PARTNER_AUDIENCE,
                ),
            ],
        )
        .unwrap()
    }

    fn partner_claims() -> serde_json::Value {
        json!({
            "iss": PARTNER_ISSUER,
            "aud": PARTNER_AUDIENCE,
            "sub": "principal-1",
            "azp": PARTNER_CLIENT,
            "scp": "scheduling-read",
            "registry_actor_kind": "service",
        })
    }

    fn partner_token(claims: serde_json::Value) -> String {
        signed_as(claims, "at+jwt", PARTNER_SECRET)
    }

    async fn read_refusal(credential: &str) -> AuthenticationFailure {
        authenticator()
            .authenticate_read(credential)
            .await
            .err()
            .expect("the credential was accepted")
    }

    // The access token type

    #[tokio::test]
    async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
        let refused = read_refusal(&jwt_typed(read_claims())).await;
        assert_eq!(
            refused.error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
        assert!(
            refused
                .remedy
                .is_some_and(|remedy| remedy.contains("accessTokenType")),
            "{:?}",
            refused.remedy
        );
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
        let stating = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                typed_verifier(registry_platform_config::AccessTokenType::Jwt),
                keys(),
                DeclaredKinds::None,
            )],
        )
        .unwrap();
        stating
            .authenticate_read(&jwt_typed(read_claims()))
            .await
            .expect("an entry that states accessTokenType: JWT admits a JWT-typed token");
        assert_eq!(
            stating
                .authenticate_read(&token(read_claims()))
                .await
                .err()
                .expect("JWT admits that type alone")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
    }

    #[tokio::test]
    async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
        let mut id_claims = read_claims();
        id_claims["nonce"] = json!("n-0S6_WzA2Mj");
        id_claims["at_hash"] = json!("77QmUPtjPfzWtF2AnpK9RQ");
        let id_token = jwt_typed(id_claims);
        assert_eq!(
            read_refusal(&id_token).await.error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
        let stating = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                typed_verifier(registry_platform_config::AccessTokenType::Jwt),
                keys(),
                DeclaredKinds::None,
            )],
        )
        .unwrap();
        let refused = stating
            .authenticate_read(&id_token)
            .await
            .err()
            .expect("an ID token is not an access token under JWT either");
        assert_eq!(
            refused.error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
        assert!(
            refused.remedy.is_some(),
            "the log line names what to change"
        );
    }

    // The caller kind

    #[tokio::test]
    async fn a_token_without_a_kind_authenticates_as_unspecified() {
        let caller = authenticator()
            .authenticate_read(&token(without(read_claims(), "registry_actor_kind")))
            .await
            .expect("a token that names no kind authenticates");
        assert_eq!(caller.actor_kind, UNSPECIFIED_ACTOR_KIND);
    }

    #[tokio::test]
    async fn a_declared_client_kind_admits_a_token_without_a_kind() {
        let declared = DeclaredKinds::Clients(
            [(
                CLIENT.to_owned(),
                registry_platform_oidc::ActorKind::Service,
            )]
            .into(),
        );
        let caller = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                verifier(Algorithm::HS256, BTreeMap::new()),
                keys(),
                declared,
            )],
        )
        .unwrap()
        .authenticate_read(&token(without(read_claims(), "registry_actor_kind")))
        .await
        .expect("the declared kind stands for the missing claim");
        assert_eq!(caller.actor_kind, "service");
    }

    #[tokio::test]
    async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
        let declared = DeclaredKinds::Issuer(registry_platform_oidc::ActorKind::Service);
        let human = token(with(read_claims(), "registry_actor_kind", json!("human")));
        let refused = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                verifier(Algorithm::HS256, BTreeMap::new()),
                keys(),
                declared,
            )],
        )
        .unwrap()
        .authenticate_read(&human)
        .await
        .err()
        .expect("a person's token is never served as a service");
        assert_eq!(
            refused.error,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused() {
        let stranger = token(with(read_claims(), "azp", json!("unrelated-app")));
        assert_eq!(
            read_refusal(&stranger).await.error,
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
    }

    #[tokio::test]
    async fn an_identity_only_token_is_refused_without_a_declared_kind() {
        let identity_only = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "openid profile email",
        }));
        assert_eq!(
            read_refusal(&identity_only).await.error,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
        // The operator's statement of the client's kind lets it through
        // authentication. The route still requires its scope.
        let declared = DeclaredKinds::Clients(
            [(
                CLIENT.to_owned(),
                registry_platform_oidc::ActorKind::Service,
            )]
            .into(),
        );
        let refused = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                verifier(Algorithm::HS256, BTreeMap::new()),
                keys(),
                declared,
            )],
        )
        .unwrap()
        .authenticate_read(&identity_only)
        .await
        .err()
        .expect("the route requires a scope the token lacks");
        assert_eq!(
            refused.error,
            AuthenticationError::Profile(FailedCheck::Scope)
        );
    }

    // Several issuers

    #[tokio::test]
    async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
        let auth = two_issuers();
        let main = auth
            .authenticate_read(&token(read_claims()))
            .await
            .expect("the main issuer's token authenticates");
        assert_eq!(main.issuer, ISSUER);
        let partner = auth
            .authenticate_read(&partner_token(partner_claims()))
            .await
            .expect("the partner issuer's token authenticates under its own scope claim");
        assert_eq!(partner.issuer, PARTNER_ISSUER);
        // The partner entry reads `scp`, not the main entry's claim.
        let wrong_claim = partner_token(with(
            with(partner_claims(), "scp", json!("scheduling-other")),
            "registry_scopes",
            json!("scheduling-read"),
        ));
        assert_eq!(
            auth.authenticate_read(&wrong_claim)
                .await
                .err()
                .expect("the partner entry does not read the main scope claim")
                .error,
            AuthenticationError::Profile(FailedCheck::Scope)
        );
        // The main entry's audience is not the partner's.
        let main_audience = partner_token(with(partner_claims(), "aud", json!(AUDIENCE)));
        assert_eq!(
            auth.authenticate_read(&main_audience)
                .await
                .err()
                .expect("each entry holds its own audience")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenAudience)
        );
    }

    #[tokio::test]
    async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
        let auth = two_issuers();
        let partner_signed_as_main = signed_as(partner_claims(), "at+jwt", SECRET);
        assert_eq!(
            auth.authenticate_read(&partner_signed_as_main)
                .await
                .err()
                .expect("the partner entry verifies with the partner's keys")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
        let main_signed_as_partner = signed_as(read_claims(), "at+jwt", PARTNER_SECRET);
        assert_eq!(
            auth.authenticate_read(&main_signed_as_partner)
                .await
                .err()
                .expect("the main entry verifies with the main keys")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
    }

    #[tokio::test]
    async fn a_token_from_an_unconfigured_issuer_is_refused() {
        let stranger = token(with(read_claims(), "iss", json!("https://elsewhere.test")));
        assert_eq!(
            two_issuers()
                .authenticate_read(&stranger)
                .await
                .err()
                .expect("no entry names this issuer")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenIssuer)
        );
    }

    #[test]
    fn an_authenticator_refuses_two_entries_that_name_one_issuer() {
        let error = SchedulingAuthenticator::new(
            profiles(),
            vec![
                main_source(
                    verifier(Algorithm::HS256, BTreeMap::new()),
                    keys(),
                    DeclaredKinds::None,
                ),
                IssuerSource::new(
                    "second",
                    verifier(Algorithm::HS256, BTreeMap::new()),
                    keys(),
                    DeclaredKinds::None,
                    AUDIENCE,
                ),
            ],
        )
        .expect_err("one issuer cannot be two entries");
        assert!(
            matches!(
                error,
                AuthenticatorBuildError::Set(IssuerSetError::DuplicateIss { .. })
            ),
            "{error}"
        );
    }

    #[test]
    fn audit_principals_are_qualified_by_issuer_only_with_more_than_one_entry() {
        let one = SchedulingAuthenticator::new(
            profiles(),
            vec![main_source(
                verifier(Algorithm::HS256, BTreeMap::new()),
                keys(),
                DeclaredKinds::None,
            )],
        )
        .expect("one entry");
        assert!(!one.qualifies_audit_principals());
        let two = SchedulingAuthenticator::new(
            profiles(),
            vec![
                main_source(
                    verifier(Algorithm::HS256, BTreeMap::new()),
                    keys(),
                    DeclaredKinds::None,
                ),
                IssuerSource::new(
                    "second",
                    TokenVerifierConfig::access_token_profile(
                        PARTNER_ISSUER,
                        vec![PARTNER_AUDIENCE.to_owned()],
                        vec![Algorithm::HS256],
                        vec!["at+jwt".to_owned()],
                    )
                    .with_scope_claim("scp")
                    .with_allowed_clients(vec![PARTNER_CLIENT.to_owned()]),
                    keys_for(PARTNER_SECRET),
                    DeclaredKinds::None,
                    PARTNER_AUDIENCE,
                ),
            ],
        )
        .expect("two entries");
        assert!(two.qualifies_audit_principals());
    }

    #[test]
    fn an_authenticator_refuses_two_sources_with_one_id() {
        let partner = TokenVerifierConfig::access_token_profile(
            PARTNER_ISSUER,
            vec![PARTNER_AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("scp")
        .with_allowed_clients(vec![PARTNER_CLIENT.to_owned()]);
        let error = SchedulingAuthenticator::new(
            profiles(),
            vec![
                main_source(
                    verifier(Algorithm::HS256, BTreeMap::new()),
                    keys(),
                    DeclaredKinds::None,
                ),
                IssuerSource::new(
                    "main",
                    partner,
                    keys_for(PARTNER_SECRET),
                    DeclaredKinds::None,
                    PARTNER_AUDIENCE,
                ),
            ],
        )
        .expect_err("two sources cannot share an id, or one would replace the other's settings");
        assert!(
            matches!(&error, AuthenticatorBuildError::DuplicateId(id) if id == "main"),
            "{error}"
        );
        let message = error.to_string();
        assert!(message.contains("main"), "{message}");
        assert!(!message.contains("one issuer"), "{message}");
    }

    #[tokio::test]
    async fn a_client_listed_by_one_issuer_is_refused_in_a_token_from_another() {
        let auth = two_issuers();
        let partner_naming_main_client =
            partner_token(with(partner_claims(), "azp", json!(CLIENT)));
        assert_eq!(
            auth.authenticate_read(&partner_naming_main_client)
                .await
                .err()
                .expect("the partner entry admits only its own clients")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
        let main_naming_partner_client = token(with(read_claims(), "azp", json!(PARTNER_CLIENT)));
        assert_eq!(
            auth.authenticate_read(&main_naming_partner_client)
                .await
                .err()
                .expect("the main entry admits only its own clients")
                .error,
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
    }

    #[tokio::test]
    async fn one_subject_from_two_issuers_is_two_callers() {
        let auth = two_issuers();
        let main = auth.authenticate_read(&token(read_claims())).await.unwrap();
        let partner = auth
            .authenticate_read(&partner_token(partner_claims()))
            .await
            .unwrap();
        assert_eq!(main.subject, partner.subject);
        assert_ne!(
            (&main.issuer, &main.subject),
            (&partner.issuer, &partner.subject)
        );
    }
}
