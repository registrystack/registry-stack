// SPDX-License-Identifier: Apache-2.0
//! Fixed workload binding for purpose-aware consultations.
//!
//! Consultation routes accept only a coupled [`AuthenticationResult`] produced
//! by Relay's OIDC verifier. A request cannot supply the workload, tenant,
//! registry instance, issuer, audience, client-claim selector, or required
//! scope. Those values come from one validated startup binding.

use std::fmt;

use thiserror::Error;

use crate::auth::{AuthMode, AuthenticationResult};

const MAX_DEPLOYMENT_ID_BYTES: usize = 96;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_AUDIENCE_BYTES: usize = 256;
const MAX_CLIENT_VALUE_BYTES: usize = 256;
const MAX_SCOPE_BYTES: usize = 128;
const MAX_PRINCIPAL_ID_BYTES: usize = 256;

/// A value-free reason that consultation workload configuration or proof was
/// rejected.
///
/// Runtime authentication failures deliberately collapse into
/// [`Self::AuthenticationDenied`]. Callers cannot use this error to discover
/// which verified claim was absent or different.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum WorkloadBindingError {
    /// A configured workload identifier is outside the closed v1 grammar.
    #[error("invalid consultation workload identifier")]
    InvalidWorkloadId,
    /// A configured issuer is not a bounded HTTPS issuer URL.
    #[error("invalid consultation issuer")]
    InvalidIssuer,
    /// A configured audience is not a bounded visible-ASCII value.
    #[error("invalid consultation audience")]
    InvalidAudience,
    /// A configured client value is not a bounded visible-ASCII value.
    #[error("invalid consultation client value")]
    InvalidClientValue,
    /// A client-claim selector is not exactly `azp` or `client_id`.
    #[error("invalid consultation client-claim selector")]
    InvalidClientClaimSelector,
    /// A configured scope is not one bounded RFC 6749 scope token.
    #[error("invalid consultation required scope")]
    InvalidRequiredScope,
    /// A configured principal is not one bounded service principal id.
    #[error("invalid consultation principal identifier")]
    InvalidPrincipalId,
    /// A configured tenant identifier is outside the closed v1 grammar.
    #[error("invalid consultation tenant identifier")]
    InvalidTenantId,
    /// A configured registry-instance identifier is outside the closed v1
    /// grammar.
    #[error("invalid consultation registry-instance identifier")]
    InvalidRegistryInstanceId,
    /// The coupled authentication does not prove the complete fixed binding.
    #[error("consultation workload authentication denied")]
    AuthenticationDenied,
}

fn is_deployment_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= MAX_DEPLOYMENT_ID_BYTES
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn is_visible_ascii(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
}

fn is_safe_principal_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PRINCIPAL_ID_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
}

macro_rules! deployment_id {
    ($(#[$meta:meta])* $name:ident, $error:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);

        impl $name {
            /// Return the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = WorkloadBindingError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                is_deployment_id(value)
                    .then(|| Self(value.into()))
                    .ok_or($error)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

deployment_id!(
    /// The server-configured identity of one consultation workload.
    WorkloadId,
    WorkloadBindingError::InvalidWorkloadId
);
deployment_id!(
    /// The server-configured tenant selected by a workload binding.
    TenantId,
    WorkloadBindingError::InvalidTenantId
);
deployment_id!(
    /// The server-configured Relay registry instance.
    RegistryInstanceId,
    WorkloadBindingError::InvalidRegistryInstanceId
);

/// The exact HTTPS issuer accepted for one consultation workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfiguredIssuer(Box<str>);

impl ConfiguredIssuer {
    /// Return the issuer compared with the verified `iss` claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ConfiguredIssuer {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !is_visible_ascii(value, MAX_ISSUER_BYTES) {
            return Err(WorkloadBindingError::InvalidIssuer);
        }
        let parsed = reqwest::Url::parse(value).map_err(|_| WorkloadBindingError::InvalidIssuer)?;
        let valid = parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none();
        valid
            .then(|| Self(value.into()))
            .ok_or(WorkloadBindingError::InvalidIssuer)
    }
}

/// The exact audience required in the verified token's `aud` set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfiguredAudience(Box<str>);

impl ConfiguredAudience {
    /// Return the audience used for exact membership checks.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ConfiguredAudience {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        is_visible_ascii(value, MAX_AUDIENCE_BYTES)
            .then(|| Self(value.into()))
            .ok_or(WorkloadBindingError::InvalidAudience)
    }
}

/// The one verified client claim selected by startup configuration.
///
/// There is intentionally no `Auto` variant and no default. Deployments must
/// state whether `azp` or `client_id` binds the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientClaimSelector {
    /// Match only the verified OAuth `azp` claim.
    Azp,
    /// Match only the verified OAuth `client_id` claim.
    ClientId,
}

impl ClientClaimSelector {
    /// Return the canonical configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Azp => "azp",
            Self::ClientId => "client_id",
        }
    }
}

impl TryFrom<&str> for ClientClaimSelector {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "azp" => Ok(Self::Azp),
            "client_id" => Ok(Self::ClientId),
            _ => Err(WorkloadBindingError::InvalidClientClaimSelector),
        }
    }
}

/// A bounded configured value for the selected verified client claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpectedClientValue(Box<str>);

impl ExpectedClientValue {
    /// Return the configured client value used for exact comparison.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ExpectedClientValue {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        is_visible_ascii(value, MAX_CLIENT_VALUE_BYTES)
            .then(|| Self(value.into()))
            .ok_or(WorkloadBindingError::InvalidClientValue)
    }
}

/// The explicit verified-claim/value pair that identifies one client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfiguredClientBinding {
    selector: ClientClaimSelector,
    expected: ExpectedClientValue,
}

impl ConfiguredClientBinding {
    /// Construct an explicit client binding. Both parts are already validated.
    #[must_use]
    pub const fn new(selector: ClientClaimSelector, expected: ExpectedClientValue) -> Self {
        Self { selector, expected }
    }

    /// Return the configured claim selector.
    #[must_use]
    pub const fn selector(&self) -> ClientClaimSelector {
        self.selector
    }

    /// Return the exact configured client value.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedClientValue {
        &self.expected
    }
}

/// The one Relay scope checked for a consultation profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequiredConsultationScope(Box<str>);

impl RequiredConsultationScope {
    /// Return the required scope token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for RequiredConsultationScope {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        is_scope_token(value)
            .then(|| Self(value.into()))
            .ok_or(WorkloadBindingError::InvalidRequiredScope)
    }
}

/// The exact resolved authenticated principal required for one workload.
///
/// Relay currently resolves this from verified `sub`, then `client_id`, then
/// `azp`. This binding pins the resulting principal in addition to separately
/// pinning the selected client claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfiguredPrincipalId(Box<str>);

impl ConfiguredPrincipalId {
    /// Return the principal compared with the coupled verified authentication.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ConfiguredPrincipalId {
    type Error = WorkloadBindingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        is_safe_principal_id(value)
            .then(|| Self(value.into()))
            .ok_or(WorkloadBindingError::InvalidPrincipalId)
    }
}

/// Complete fixed OIDC proof expected for one configured service workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredOidcWorkloadProof {
    issuer: ConfiguredIssuer,
    audience: ConfiguredAudience,
    client: ConfiguredClientBinding,
    principal_id: ConfiguredPrincipalId,
}

impl ConfiguredOidcWorkloadProof {
    /// Assemble the four independently validated OIDC binding facts.
    #[must_use]
    pub(crate) const fn new(
        issuer: ConfiguredIssuer,
        audience: ConfiguredAudience,
        client: ConfiguredClientBinding,
        principal_id: ConfiguredPrincipalId,
    ) -> Self {
        Self {
            issuer,
            audience,
            client,
            principal_id,
        }
    }

    #[must_use]
    pub const fn issuer(&self) -> &ConfiguredIssuer {
        &self.issuer
    }

    #[must_use]
    pub const fn audience(&self) -> &ConfiguredAudience {
        &self.audience
    }

    #[must_use]
    pub const fn client(&self) -> &ConfiguredClientBinding {
        &self.client
    }

    #[must_use]
    pub const fn principal_id(&self) -> &ConfiguredPrincipalId {
        &self.principal_id
    }

    /// Prove the fixed Notary service identity before any profile lookup.
    /// Profile-specific scope, tenant, registry, and workload checks remain in
    /// [`AuthenticatedConsultationWorkload::try_bind`].
    pub(crate) fn precheck_authentication(
        &self,
        authentication: &AuthenticationResult,
    ) -> Result<(), WorkloadBindingError> {
        require_exact_oidc_identity(authentication, self).map(|_| ())
    }
}

fn require_exact_oidc_identity<'authentication>(
    authentication: &'authentication AuthenticationResult,
    expected: &ConfiguredOidcWorkloadProof,
) -> Result<&'authentication crate::auth::VerifiedOidcIdentity, WorkloadBindingError> {
    let principal = authentication.principal();
    if principal.auth_mode != AuthMode::Oidc
        || principal.principal_id != expected.principal_id().as_str()
    {
        return Err(WorkloadBindingError::AuthenticationDenied);
    }
    let identity = authentication
        .verified_oidc()
        .ok_or(WorkloadBindingError::AuthenticationDenied)?;
    if identity.issuer() != expected.issuer().as_str()
        || !identity.has_audience(expected.audience().as_str())
    {
        return Err(WorkloadBindingError::AuthenticationDenied);
    }
    let selected_client = match expected.client().selector {
        ClientClaimSelector::Azp => identity.authorized_party(),
        ClientClaimSelector::ClientId => identity.client_id_claim(),
    };
    if selected_client != Some(expected.client().expected.as_str()) {
        return Err(WorkloadBindingError::AuthenticationDenied);
    }
    Ok(identity)
}

/// The closed role of a consultation workload.
///
/// Consultation v1 has exactly one service role. A later role requires a
/// reviewed protocol change rather than relying on a workload-id convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsultationWorkloadRole {
    /// The configured Registry Notary service.
    Notary,
    #[cfg(test)]
    Other,
}

impl ConsultationWorkloadRole {
    /// Return the stable role spelling used by configuration and audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notary => "notary",
            #[cfg(test)]
            Self::Other => "test-other",
        }
    }
}

/// Validated, fixed startup configuration for one consultation workload.
///
/// This type has no request-derived fields. A later configuration loader may
/// select one of these bindings, but callers cannot override any member through
/// a consultation path, header, or body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultationWorkloadBinding {
    role: ConsultationWorkloadRole,
    workload_id: WorkloadId,
    oidc: ConfiguredOidcWorkloadProof,
    required_scope: RequiredConsultationScope,
    tenant: TenantId,
    registry_instance: RegistryInstanceId,
}

impl ConsultationWorkloadBinding {
    /// Assemble one fixed binding from validated configuration values.
    #[must_use]
    pub(crate) const fn new(
        role: ConsultationWorkloadRole,
        workload_id: WorkloadId,
        oidc: ConfiguredOidcWorkloadProof,
        required_scope: RequiredConsultationScope,
        tenant: TenantId,
        registry_instance: RegistryInstanceId,
    ) -> Self {
        Self {
            role,
            workload_id,
            oidc,
            required_scope,
            tenant,
            registry_instance,
        }
    }

    /// Return the explicit closed service role.
    #[must_use]
    pub const fn role(&self) -> ConsultationWorkloadRole {
        self.role
    }

    /// Return the fixed workload identifier.
    #[must_use]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Return the fixed issuer.
    #[must_use]
    pub const fn issuer(&self) -> &ConfiguredIssuer {
        self.oidc.issuer()
    }

    /// Return the fixed audience.
    #[must_use]
    pub const fn audience(&self) -> &ConfiguredAudience {
        self.oidc.audience()
    }

    /// Return the explicit fixed client binding.
    #[must_use]
    pub const fn client(&self) -> &ConfiguredClientBinding {
        self.oidc.client()
    }

    /// Return the fixed verified principal.
    #[must_use]
    pub const fn principal_id(&self) -> &ConfiguredPrincipalId {
        self.oidc.principal_id()
    }

    /// Return the one required consultation scope.
    #[must_use]
    pub const fn required_scope(&self) -> &RequiredConsultationScope {
        &self.required_scope
    }

    /// Return the fixed tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Return the fixed registry instance.
    #[must_use]
    pub const fn registry_instance(&self) -> &RegistryInstanceId {
        &self.registry_instance
    }
}

/// The only authentication mode accepted by consultation v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsultationAuthMode {
    /// A bearer JWT verified by Relay's configured OIDC provider.
    OidcJwt,
}

impl ConsultationAuthMode {
    /// Return the canonical audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OidcJwt => "oidc",
        }
    }
}

/// A coupled OIDC authentication that exactly matches one fixed consultation
/// workload binding.
///
/// This type intentionally implements neither `Debug` nor serialization. It
/// retains only the fixed matched values, one bounded principal identifier,
/// and the one scope actually checked. It does not retain the token, complete
/// audience set, both client claims, or unchecked scopes.
pub struct AuthenticatedConsultationWorkload {
    role: ConsultationWorkloadRole,
    workload_id: WorkloadId,
    issuer: ConfiguredIssuer,
    audience: ConfiguredAudience,
    client_selector: ClientClaimSelector,
    client_value: ExpectedClientValue,
    principal_id: ConfiguredPrincipalId,
    checked_scope: RequiredConsultationScope,
    authentication_expires_at_unix_ms: i64,
    tenant: TenantId,
    registry_instance: RegistryInstanceId,
}

impl AuthenticatedConsultationWorkload {
    #[cfg(test)]
    pub(crate) fn for_runtime_vector_test(authentication_expires_at_unix_ms: i64) -> Self {
        Self {
            role: ConsultationWorkloadRole::Notary,
            workload_id: WorkloadId::try_from("registry-notary").unwrap(),
            issuer: ConfiguredIssuer::try_from("https://issuer.synthetic.example").unwrap(),
            audience: ConfiguredAudience::try_from("registry-relay").unwrap(),
            client_selector: ClientClaimSelector::Azp,
            client_value: ExpectedClientValue::try_from("synthetic-notary-client").unwrap(),
            principal_id: ConfiguredPrincipalId::try_from("synthetic-notary-service").unwrap(),
            checked_scope: RequiredConsultationScope::try_from("registry:consult:person-status")
                .unwrap(),
            authentication_expires_at_unix_ms,
            tenant: TenantId::try_from("synthetic-government").unwrap(),
            registry_instance: RegistryInstanceId::try_from("people-primary").unwrap(),
        }
    }

    /// Prove one fixed workload binding from a single coupled authentication
    /// result.
    ///
    /// # Errors
    ///
    /// Returns [`WorkloadBindingError::AuthenticationDenied`] for API keys,
    /// absent verified OIDC context, any exact binding mismatch, a missing
    /// required scope, or an unsafe principal identifier. The error never
    /// carries an observed claim value.
    pub(crate) fn try_bind(
        authentication: &AuthenticationResult,
        binding: &ConsultationWorkloadBinding,
    ) -> Result<Self, WorkloadBindingError> {
        let identity = require_exact_oidc_identity(authentication, &binding.oidc)?;
        if !authentication
            .principal()
            .scopes
            .contains(binding.required_scope.as_str())
        {
            return Err(WorkloadBindingError::AuthenticationDenied);
        }

        Ok(Self {
            role: binding.role,
            workload_id: binding.workload_id.clone(),
            issuer: binding.issuer().clone(),
            audience: binding.audience().clone(),
            client_selector: binding.client().selector,
            client_value: binding.client().expected.clone(),
            principal_id: binding.principal_id().clone(),
            checked_scope: binding.required_scope.clone(),
            authentication_expires_at_unix_ms: identity.expires_at_unix_ms(),
            tenant: binding.tenant.clone(),
            registry_instance: binding.registry_instance.clone(),
        })
    }

    /// Return the closed consultation authentication mode.
    #[must_use]
    pub const fn auth_mode(&self) -> ConsultationAuthMode {
        ConsultationAuthMode::OidcJwt
    }

    /// Return the exact service role fixed by the matched startup binding.
    #[must_use]
    pub const fn role(&self) -> ConsultationWorkloadRole {
        self.role
    }

    /// Narrow this generic authenticated service to the Notary-only
    /// correlation capability.
    pub(crate) fn try_as_notary(&self) -> Option<AuthenticatedNotaryWorkload<'_>> {
        match self.role {
            ConsultationWorkloadRole::Notary => Some(AuthenticatedNotaryWorkload {
                proof: AuthenticatedNotaryProof::Bound(self),
            }),
            #[cfg(test)]
            ConsultationWorkloadRole::Other => None,
        }
    }

    /// Return the fixed workload identifier.
    #[must_use]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Return the exact issuer that was checked.
    #[must_use]
    pub const fn issuer(&self) -> &ConfiguredIssuer {
        &self.issuer
    }

    /// Return the exact audience whose membership was checked.
    #[must_use]
    pub const fn audience(&self) -> &ConfiguredAudience {
        &self.audience
    }

    /// Return the claim selector explicitly used for client binding.
    #[must_use]
    pub const fn client_claim_selector(&self) -> ClientClaimSelector {
        self.client_selector
    }

    /// Return the configured client value that was checked.
    #[must_use]
    pub const fn client_value(&self) -> &ExpectedClientValue {
        &self.client_value
    }

    /// Return the bounded principal identifier from the coupled result.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        self.principal_id.as_str()
    }

    /// Iterate exactly the scopes checked by this binding.
    pub fn checked_scopes(&self) -> impl ExactSizeIterator<Item = &str> {
        std::iter::once(self.checked_scope.as_str())
    }

    /// Return the signature-verified client authentication expiry.
    #[must_use]
    pub(crate) const fn authentication_expires_at_unix_ms(&self) -> i64 {
        self.authentication_expires_at_unix_ms
    }

    /// Return the fixed tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Return the fixed registry instance.
    #[must_use]
    pub const fn registry_instance(&self) -> &RegistryInstanceId {
        &self.registry_instance
    }
}

enum AuthenticatedNotaryProof<'a> {
    Bound(&'a AuthenticatedConsultationWorkload),
    #[cfg(test)]
    WireTest,
}

/// Proof that the exact fixed Notary workload binding was authenticated.
///
/// The proof has no public constructor, implements neither `Clone`, `Debug`,
/// nor serialization, and borrows the coupled verified workload. A generic or
/// future non-Notary consultation workload cannot create it.
///
/// ```compile_fail
/// use registry_relay::consultation::AuthenticatedNotaryWorkload;
/// let _forged: AuthenticatedNotaryWorkload<'static> =
///     AuthenticatedNotaryWorkload {};
/// ```
pub struct AuthenticatedNotaryWorkload<'a> {
    proof: AuthenticatedNotaryProof<'a>,
}

impl AuthenticatedNotaryWorkload<'_> {
    /// Return the complete coupled workload proof.
    #[must_use]
    pub fn workload(&self) -> &AuthenticatedConsultationWorkload {
        match &self.proof {
            AuthenticatedNotaryProof::Bound(workload) => workload,
            #[cfg(test)]
            AuthenticatedNotaryProof::WireTest => {
                panic!("test-only Notary wire proof has no workload")
            }
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_wire_test() -> Self {
        Self {
            proof: AuthenticatedNotaryProof::WireTest,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::http::{header, HeaderMap, HeaderValue};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rand_core::OsRng;
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::auth::oidc::{static_fetcher, OidcAuth};
    use crate::auth::{AuthProvider, Principal, ScopeSet};
    use crate::config::{OidcAlgorithm, OidcConfig};

    const ISSUER: &str = "https://idp.example.test/realms/registry";
    const AUDIENCE: &str = "registry-relay";
    const REQUIRED_SCOPE: &str = "registry:consult:person-status";
    const KID: &str = "consultation-workload-test";

    fn binding(
        selector: ClientClaimSelector,
        expected_client: &str,
    ) -> ConsultationWorkloadBinding {
        binding_with_role(ConsultationWorkloadRole::Notary, selector, expected_client)
    }

    fn binding_with_role(
        role: ConsultationWorkloadRole,
        selector: ClientClaimSelector,
        expected_client: &str,
    ) -> ConsultationWorkloadBinding {
        ConsultationWorkloadBinding::new(
            role,
            WorkloadId::try_from("registry-notary").unwrap(),
            ConfiguredOidcWorkloadProof::new(
                ConfiguredIssuer::try_from(ISSUER).unwrap(),
                ConfiguredAudience::try_from(AUDIENCE).unwrap(),
                ConfiguredClientBinding::new(
                    selector,
                    ExpectedClientValue::try_from(expected_client).unwrap(),
                ),
                ConfiguredPrincipalId::try_from("notary-service").unwrap(),
            ),
            RequiredConsultationScope::try_from(REQUIRED_SCOPE).unwrap(),
            TenantId::try_from("example-government").unwrap(),
            RegistryInstanceId::try_from("people-primary").unwrap(),
        )
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn jwks(verifying: &VerifyingKey) -> JwkSet {
        let x = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
        serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": KID,
                "x": x,
            }]
        }))
        .unwrap()
    }

    fn oidc_config(issuer: &str, audiences: Vec<String>) -> OidcConfig {
        OidcConfig {
            issuer: issuer.to_string(),
            audiences,
            jwks_url: None,
            discovery_url: None,
            allow_dev_insecure_fetch_urls: false,
            allowed_algorithms: vec![OidcAlgorithm::EdDsa],
            jwks_cache_ttl: Duration::from_secs(600),
            leeway: Duration::from_secs(60),
            scope_claim: "scope".to_string(),
            scope_map: BTreeMap::new(),
            scope_object_required_keys: Vec::new(),
            allowed_clients: Vec::new(),
            allowed_token_types: vec!["JWT".to_string(), "at+jwt".to_string()],
        }
    }

    fn mint(signing: &SigningKey, claims: Map<String, Value>) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_string());
        header.typ = Some("at+jwt".to_string());
        let key =
            EncodingKey::from_ed_der(signing.to_pkcs8_der().expect("encode test key").as_bytes());
        encode(&header, &Value::Object(claims), &key).expect("mint test token")
    }

    fn claims(issuer: &str, audience: Value) -> Map<String, Value> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        Map::from_iter([
            ("iss".to_string(), Value::String(issuer.to_string())),
            ("aud".to_string(), audience),
            (
                "sub".to_string(),
                Value::String("notary-service".to_string()),
            ),
            ("iat".to_string(), Value::from(now)),
            ("exp".to_string(), Value::from(now + 300)),
            (
                "scope".to_string(),
                Value::String(format!("{REQUIRED_SCOPE} unrelated:scope")),
            ),
            ("azp".to_string(), Value::String("notary-azp".to_string())),
            (
                "client_id".to_string(),
                Value::String("notary-client-id".to_string()),
            ),
        ])
    }

    async fn authenticate(
        config: OidcConfig,
        signing: &SigningKey,
        verifying: &VerifyingKey,
        claims: Map<String, Value>,
    ) -> AuthenticationResult {
        let provider = OidcAuth::new(&config, static_fetcher(jwks(verifying)));
        let token = mint(signing, claims);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        provider
            .authenticate(&headers, "127.0.0.1".parse().unwrap())
            .await
            .expect("test OIDC authentication")
    }

    #[test]
    fn fixed_configuration_types_enforce_conservative_grammars() {
        assert!(WorkloadId::try_from("registry-notary").is_ok());
        assert_eq!(
            WorkloadId::try_from("Registry Notary"),
            Err(WorkloadBindingError::InvalidWorkloadId)
        );
        assert!(ConfiguredIssuer::try_from("https://issuer.example/realm").is_ok());
        assert_eq!(
            ConfiguredIssuer::try_from("http://issuer.example/realm"),
            Err(WorkloadBindingError::InvalidIssuer)
        );
        assert_eq!(
            ConfiguredIssuer::try_from("https://user@issuer.example/realm"),
            Err(WorkloadBindingError::InvalidIssuer)
        );
        assert_eq!(
            ConfiguredAudience::try_from("registry relay"),
            Err(WorkloadBindingError::InvalidAudience)
        );
        assert_eq!(
            RequiredConsultationScope::try_from("registry:consult person"),
            Err(WorkloadBindingError::InvalidRequiredScope)
        );
        assert_eq!(
            ClientClaimSelector::try_from("preferred"),
            Err(WorkloadBindingError::InvalidClientClaimSelector)
        );
        assert_eq!(ClientClaimSelector::Azp.as_str(), "azp");
        assert_eq!(ClientClaimSelector::ClientId.as_str(), "client_id");
        assert_eq!(
            ConfiguredPrincipalId::try_from("notary service"),
            Err(WorkloadBindingError::InvalidPrincipalId)
        );
    }

    #[test]
    fn fixed_configuration_scalars_enforce_zero_max_max_plus_one_and_unicode_bounds() {
        let deployment_max = format!("a{}", "0".repeat(MAX_DEPLOYMENT_ID_BYTES - 1));
        let deployment_too_long = format!("a{}", "0".repeat(MAX_DEPLOYMENT_ID_BYTES));
        assert!(WorkloadId::try_from(deployment_max.as_str()).is_ok());
        assert!(WorkloadId::try_from(deployment_too_long.as_str()).is_err());
        assert!(TenantId::try_from("").is_err());
        assert!(RegistryInstanceId::try_from("régistry").is_err());

        let audience_max = "a".repeat(MAX_AUDIENCE_BYTES);
        let audience_too_long = "a".repeat(MAX_AUDIENCE_BYTES + 1);
        assert!(ConfiguredAudience::try_from(audience_max.as_str()).is_ok());
        assert!(ConfiguredAudience::try_from(audience_too_long.as_str()).is_err());
        assert!(ConfiguredAudience::try_from("audience-é").is_err());

        let client_max = "c".repeat(MAX_CLIENT_VALUE_BYTES);
        let client_too_long = "c".repeat(MAX_CLIENT_VALUE_BYTES + 1);
        assert!(ExpectedClientValue::try_from(client_max.as_str()).is_ok());
        assert!(ExpectedClientValue::try_from(client_too_long.as_str()).is_err());
        assert!(ExpectedClientValue::try_from("").is_err());

        let scope_max = "s".repeat(MAX_SCOPE_BYTES);
        let scope_too_long = "s".repeat(MAX_SCOPE_BYTES + 1);
        assert!(RequiredConsultationScope::try_from(scope_max.as_str()).is_ok());
        assert!(RequiredConsultationScope::try_from(scope_too_long.as_str()).is_err());
        assert!(RequiredConsultationScope::try_from("scope-é").is_err());

        let principal_max = "p".repeat(MAX_PRINCIPAL_ID_BYTES);
        let principal_too_long = "p".repeat(MAX_PRINCIPAL_ID_BYTES + 1);
        assert!(ConfiguredPrincipalId::try_from(principal_max.as_str()).is_ok());
        assert!(ConfiguredPrincipalId::try_from(principal_too_long.as_str()).is_err());
        assert!(ConfiguredPrincipalId::try_from("principal é").is_err());
    }

    #[tokio::test]
    async fn exact_oidc_binding_retains_only_checked_scope_and_fixed_context() {
        let (signing, verifying) = keypair();
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            claims(
                ISSUER,
                json!(["another-resource", AUDIENCE, "unused-resource"]),
            ),
        )
        .await;

        let workload = AuthenticatedConsultationWorkload::try_bind(
            &authentication,
            &binding(ClientClaimSelector::Azp, "notary-azp"),
        )
        .expect("exact workload binding");

        assert_eq!(workload.auth_mode().as_str(), "oidc");
        assert_eq!(workload.role().as_str(), "notary");
        assert_eq!(workload.workload_id().as_str(), "registry-notary");
        assert_eq!(workload.issuer().as_str(), ISSUER);
        assert_eq!(workload.audience().as_str(), AUDIENCE);
        assert_eq!(workload.client_claim_selector(), ClientClaimSelector::Azp);
        assert_eq!(workload.client_value().as_str(), "notary-azp");
        assert_eq!(workload.principal_id(), "notary-service");
        assert_eq!(
            workload.checked_scopes().collect::<Vec<_>>(),
            [REQUIRED_SCOPE]
        );
        assert_eq!(workload.tenant().as_str(), "example-government");
        assert_eq!(workload.registry_instance().as_str(), "people-primary");
        let notary = workload.try_as_notary().expect("typed Notary capability");
        assert_eq!(notary.workload().principal_id(), "notary-service");
    }

    #[tokio::test]
    async fn a_non_notary_role_cannot_mint_notary_header_authority() {
        let (signing, verifying) = keypair();
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            claims(ISSUER, Value::String(AUDIENCE.to_string())),
        )
        .await;
        let workload = AuthenticatedConsultationWorkload::try_bind(
            &authentication,
            &binding_with_role(
                ConsultationWorkloadRole::Other,
                ClientClaimSelector::Azp,
                "notary-azp",
            ),
        )
        .expect("the exact OIDC facts still bind the test-only non-Notary role");
        assert_eq!(workload.role(), ConsultationWorkloadRole::Other);
        assert!(workload.try_as_notary().is_none());
    }

    #[tokio::test]
    async fn explicit_selector_resolves_conflicting_azp_and_client_id_without_preference() {
        let (signing, verifying) = keypair();
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            claims(ISSUER, Value::String(AUDIENCE.to_string())),
        )
        .await;

        assert!(AuthenticatedConsultationWorkload::try_bind(
            &authentication,
            &binding(ClientClaimSelector::Azp, "notary-azp"),
        )
        .is_ok());
        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(
                &authentication,
                &binding(ClientClaimSelector::Azp, "notary-client-id"),
            )
            .err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
        assert!(AuthenticatedConsultationWorkload::try_bind(
            &authentication,
            &binding(ClientClaimSelector::ClientId, "notary-client-id"),
        )
        .is_ok());
        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(
                &authentication,
                &binding(ClientClaimSelector::ClientId, "notary-azp"),
            )
            .err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
    }

    #[tokio::test]
    async fn every_missing_or_mismatched_verified_binding_fact_is_denied() {
        let (signing, verifying) = keypair();

        let issuer_mismatch = authenticate(
            oidc_config("https://other-issuer.example", vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            claims(
                "https://other-issuer.example",
                Value::String(AUDIENCE.to_string()),
            ),
        )
        .await;
        let audience_mismatch = authenticate(
            oidc_config(ISSUER, vec!["other-audience".to_string()]),
            &signing,
            &verifying,
            claims(ISSUER, Value::String("other-audience".to_string())),
        )
        .await;

        let mut missing_client_claims = claims(ISSUER, Value::String(AUDIENCE.to_string()));
        missing_client_claims.remove("azp");
        let missing_client = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            missing_client_claims,
        )
        .await;

        let mut missing_scope_claims = claims(ISSUER, Value::String(AUDIENCE.to_string()));
        missing_scope_claims.insert(
            "scope".to_string(),
            Value::String("other:scope".to_string()),
        );
        let missing_scope = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            missing_scope_claims,
        )
        .await;

        let expected = binding(ClientClaimSelector::Azp, "notary-azp");
        for rejected in [
            &issuer_mismatch,
            &audience_mismatch,
            &missing_client,
            &missing_scope,
        ] {
            assert_eq!(
                AuthenticatedConsultationWorkload::try_bind(rejected, &expected).err(),
                Some(WorkloadBindingError::AuthenticationDenied)
            );
        }
    }

    #[tokio::test]
    async fn fixed_identity_precheck_precedes_profile_specific_scope() {
        let (signing, verifying) = keypair();
        let mut missing_scope_claims = claims(ISSUER, Value::String(AUDIENCE.to_string()));
        missing_scope_claims.insert(
            "scope".to_string(),
            Value::String("other:scope".to_string()),
        );
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            missing_scope_claims,
        )
        .await;
        let expected = binding(ClientClaimSelector::Azp, "notary-azp");

        assert_eq!(
            expected.oidc.precheck_authentication(&authentication),
            Ok(())
        );
        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(&authentication, &expected).err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
    }

    #[test]
    fn api_key_result_cannot_prove_a_consultation_workload() {
        let authentication = AuthenticationResult::api_key(Principal {
            principal_id: "notary-service".to_string(),
            scopes: ScopeSet::from_iter([REQUIRED_SCOPE]),
            auth_mode: AuthMode::ApiKey,
        })
        .expect("consistent API-key authentication");

        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(
                &authentication,
                &binding(ClientClaimSelector::Azp, "notary-azp"),
            )
            .err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
    }

    #[tokio::test]
    async fn unsafe_principal_id_is_denied_after_genuine_oidc_verification() {
        let (signing, verifying) = keypair();
        let mut unsafe_claims = claims(ISSUER, Value::String(AUDIENCE.to_string()));
        unsafe_claims.insert(
            "sub".to_string(),
            Value::String("notary service".to_string()),
        );
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            unsafe_claims,
        )
        .await;

        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(
                &authentication,
                &binding(ClientClaimSelector::Azp, "notary-azp"),
            )
            .err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
    }

    #[tokio::test]
    async fn different_safe_principal_is_denied_after_genuine_oidc_verification() {
        let (signing, verifying) = keypair();
        let mut different_principal_claims = claims(ISSUER, Value::String(AUDIENCE.to_string()));
        different_principal_claims.insert(
            "sub".to_string(),
            Value::String("another-notary-service".to_string()),
        );
        let authentication = authenticate(
            oidc_config(ISSUER, vec![AUDIENCE.to_string()]),
            &signing,
            &verifying,
            different_principal_claims,
        )
        .await;

        assert_eq!(
            AuthenticatedConsultationWorkload::try_bind(
                &authentication,
                &binding(ClientClaimSelector::Azp, "notary-azp"),
            )
            .err(),
            Some(WorkloadBindingError::AuthenticationDenied)
        );
    }
}
