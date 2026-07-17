// SPDX-License-Identifier: Apache-2.0
//! Configuration validation errors.

#[derive(Debug, thiserror::Error)]
pub enum EvidenceConfigError {
    #[error("evidence.enabled must be true for the standalone Registry Notary")]
    EvidenceDisabled,
    #[error("at least one API key, bearer token, or OIDC authenticator must be configured")]
    NoCredentialsConfigured,
    #[error("invalid auth config: {reason}")]
    InvalidAuthConfig { reason: String },
    #[error("invalid auth.oidc config: {reason}")]
    InvalidOidcConfig { reason: String },
    #[error("invalid subject_access config: {reason}")]
    InvalidSubjectAccessConfig { reason: String },
    #[error("invalid oid4vci config: {reason}")]
    InvalidOid4vciConfig { reason: String },
    #[error("invalid auth.access_token_signing config: {reason}")]
    InvalidAccessTokenSigningConfig { reason: String },
    #[error("invalid state config: {reason}")]
    InvalidStateConfig { reason: String },
    #[error("invalid credential status config: {reason}")]
    InvalidCredentialStatusConfig { reason: String },
    #[error("invalid cel config: {reason}")]
    InvalidCelConfig { reason: String },
    #[error("invalid federation config: {reason}")]
    InvalidFederationConfig { reason: String },
    #[error("invalid server config: {reason}")]
    InvalidServerConfig { reason: String },
    #[error("invalid config_trust config: {reason}")]
    InvalidConfigTrustConfig { reason: String },
    #[error("invalid deployment config: {reason}")]
    InvalidDeploymentConfig { reason: String },
    #[error(
        "deployment.evidence.audit_ack_max_age_secs is set but deployment.evidence.audit_ack_cursor_path is not; a freshness window is meaningless with no cursor to read. Set audit_ack_cursor_path to the registry.audit.ack_cursor.v1 file the audit shipper maintains, or remove audit_ack_max_age_secs"
    )]
    AuditAckMaxAgeWithoutCursor,
    #[error(
        "deployment.evidence.audit_ack_cursor_path is set with a local file audit sink but deployment.evidence.audit_offhost_shipping is false; an ack cursor asserts observed off-host shipping that has not been declared. Set audit_offhost_shipping: true once shipping is in place, or remove audit_ack_cursor_path"
    )]
    AuditAckCursorWithoutShippingDeclared,
    #[error("invalid evidence.relay config: {reason}")]
    InvalidRelayConfig { reason: String },
    #[error("invalid evidence.variables config: {reason}")]
    InvalidRequestVariableConfig { reason: String },
    #[error("claim id must not be empty")]
    InvalidClaim,
    /// REQ-DM-CLAIM-001 requires a claim's `id` to be unique across the
    /// configuration; RS-DM-CLAIM Section 10 previously documented this as an
    /// operator responsibility the loader did not enforce.
    #[error("claim id '{claim}' is used by more than one claim; claim ids must be unique")]
    DuplicateClaimId { claim: String },
    #[error("claim '{claim}' has invalid semantics config: {reason}")]
    InvalidClaimSemantics { claim: String, reason: String },
    #[error("claim '{claim}' has invalid evidence_mode: {reason}")]
    InvalidClaimEvidenceMode { claim: String, reason: String },
    #[error("claim '{claim}' dependency closure exceeds v1 bounds ({nodes} nodes, {edges} edges)")]
    ClaimDependencyGraphTooLarge {
        claim: String,
        nodes: usize,
        edges: usize,
    },
    /// REQ-DM-CLAIM-008 requires a claim's `disclosure.default` to be a
    /// member of `disclosure.allowed`; RS-DM-CLAIM Section 10 previously
    /// documented this as unchecked at load, surfacing only when a result
    /// was rendered.
    #[error(
        "claim '{claim}' disclosure.default '{default}' is not a member of \
         disclosure.allowed ({allowed}); a claim's default disclosure mode must be one \
         it is permitted to render",
        allowed = allowed.join(", ")
    )]
    ClaimDisclosureDefaultNotAllowed {
        claim: String,
        default: String,
        allowed: Vec<String>,
    },
    #[error(
        "claim '{claim}' formats must not be empty; omit formats to use the default \
         application/vnd.registry-notary.claim-result+json representation, or list one or more response formats"
    )]
    EmptyClaimFormats { claim: String },
    #[error(
        "claim '{claim}' formats must include the canonical evaluation response format \
         application/vnd.registry-notary.claim-result+json; add it alongside any supported additional evaluation renderers"
    )]
    MissingCanonicalClaimFormat { claim: String },
    #[error(
        "claim '{claim}' has unsupported evaluation response format '{format}' in formats; \
         supported formats are application/vnd.registry-notary.claim-result+json and \
         application/ld+json; profile=\"cccev\". SD-JWT VC belongs in credential_profiles, not claim formats"
    )]
    UnsupportedClaimFormat { claim: String, format: String },
    #[error("allowed purpose must not be empty")]
    InvalidPurpose,
    #[error("concurrency.subjects must be >= 1")]
    InvalidConcurrency,
    #[error("invalid evidence.machine_quota config: {reason}")]
    InvalidMachineQuotaConfig { reason: String },
    /// Credential holder binding only works with did:jwk because holder_jwk()
    /// only implements did:jwk resolution. Restrict allowed_did_methods to
    /// ["did:jwk"] or leave it empty when holder binding is disabled.
    #[error(
        "credential profile '{profile}': holder binding is only supported with did:jwk, \
         but allowed_did_methods contains unsupported method(s): {methods}; \
         restrict allowed_did_methods to [\"did:jwk\"]",
        methods = methods.join(", ")
    )]
    UnsupportedCredentialProfileDidMethods {
        profile: String,
        methods: Vec<String>,
    },
    #[error("claim '{claim}' depends_on unknown claim '{unknown}'")]
    DependsOnUnknownClaim { claim: String, unknown: String },
    #[error(
        "depends_on cycle detected: {cycle}",
        cycle = cycle.join(" -> ")
    )]
    DependsOnCycle { cycle: Vec<String> },
    /// A credential profile with an empty `allowed_claims` would short-circuit
    /// the issuance-time claim filter (api.rs treats empty as "all claims
    /// allowed"). Reject at load time so operators must explicitly enumerate
    /// the claims a profile may bind to.
    #[error(
        "credential profile '{profile}': allowed_claims must list at least one \
         claim; an empty list would permit any claim at issuance"
    )]
    EmptyAllowedClaims { profile: String },
    /// Registry Notary currently issues only SD-JWT VC credentials using the
    /// current `application/dc+sd-jwt` media type. Reject aliases and profile
    /// labels so operator config cannot drift from the wire contract.
    #[error(
        "credential profile '{profile}': unsupported format '{format}'; \
         supported credential format is application/dc+sd-jwt"
    )]
    UnsupportedCredentialProfileFormat { profile: String, format: String },
    #[error("signing key '{key}' is invalid: {reason}")]
    InvalidSigningKeyConfig { key: String, reason: String },
    #[error("credential profile '{profile}' references unknown signing key '{key}'")]
    UnknownCredentialProfileSigningKey { profile: String, key: String },
    #[error("credential profile '{profile}' references non-active signing key '{key}'")]
    CredentialProfileSigningKeyNotActive { profile: String, key: String },
    #[error(
        "credential profile '{profile}' validity_seconds {validity_seconds} must be between 1 and {max_validity_seconds}"
    )]
    InvalidCredentialProfileValidity {
        profile: String,
        validity_seconds: i64,
        max_validity_seconds: u64,
    },
    #[error("credential profile '{profile}' issuer does not match signing key '{key}': {reason}")]
    CredentialProfileSigningKeyIssuerMismatch {
        profile: String,
        key: String,
        reason: String,
    },
}
